//! The `certificate_authorities` extension (RFC 8446 section 4.2.4). A peer lists the
//! distinguished names of the certificate authorities that it trusts. The server sends the
//! list in a CertificateRequest, and the client can send it in a ClientHello. The receiver
//! then prefers a certificate chain that leads to one of the names.
const std = @import("std");
const tls = std.crypto.tls;
const codec = @import("codec.zig");
const der = @import("../der.zig");
const CertChain = @import("../CertChain.zig");
const verify = @import("../verify.zig");

pub const extension_type: u16 = @intFromEnum(tls.ExtensionType.certificate_authorities);

/// The largest name list that the client sends in a ClientHello. The client also keeps the
/// first ClientHello at 16 KiB or less, because the SDK server and many other servers refuse a
/// larger ClientHello.
pub const max_hello_list_len = 8 << 10;

/// The largest name list that the server sends in a CertificateRequest. The message then
/// stays below 16 KiB, the limit of many TLS clients.
pub const max_request_list_len = (16 << 10) - 512;

/// The size of a buffer for a CertificateRequest with the largest name list.
pub const max_request_message_len = max_request_list_len + 512;

/// Check the body of a certificate_authorities extension and return its name list. The list
/// has at least one name, and each name is one DER `Name` with at least one relative
/// distinguished name. Any other content gives `error.DecodeError`.
pub fn parse(body: []const u8) codec.ParseError![]const u8 {
    if (body.len < 2) return error.DecodeError;
    const list_len = std.mem.readInt(u16, body[0..2], .big);
    // The list has 3 to 2^16 - 1 bytes and fills the body.
    if (list_len < 3 or list_len != body.len - 2) return error.DecodeError;
    const list = body[2..];
    var rest = list;
    while (rest.len > 0) {
        if (rest.len < 2) return error.DecodeError;
        const len = std.mem.readInt(u16, rest[0..2], .big);
        if (len == 0 or len > rest.len - 2) return error.DecodeError;
        if (!isName(rest[2..][0..len])) return error.DecodeError;
        rest = rest[2 + len ..];
    }
    return list;
}

/// True when `bytes` is exactly one DER `Name` (RFC 5280 section 4.1.2.4) with at least one
/// relative distinguished name. Each relative distinguished name has at least one attribute,
/// and each attribute has a type and a value. The name of a CA is never empty.
pub fn isName(bytes: []const u8) bool {
    const name = der.parseExact(bytes) catch return false;
    if (name.tag != der.tag_sequence or name.content.len == 0) return false;
    var rdns = name.children();
    while (rdns.next() catch return false) |rdn| {
        if (rdn.tag != der.tag_set or rdn.content.len == 0) return false;
        var attributes = rdn.children();
        while (attributes.next() catch return false) |attribute| {
            if (attribute.tag != der.tag_sequence) return false;
            var parts = attribute.children();
            const kind = (parts.next() catch return false) orelse return false;
            if (kind.tag != der.tag_oid or kind.content.len == 0) return false;
            _ = (parts.next() catch return false) orelse return false;
            if ((parts.next() catch return false) != null) return false;
        }
    }
    return true;
}

/// Iterate the names of a list that `parse` checked.
pub const Iterator = struct {
    rest: []const u8,

    pub fn init(list: []const u8) Iterator {
        return .{ .rest = list };
    }

    pub fn next(self: *Iterator) ?[]const u8 {
        if (self.rest.len < 2) return null;
        const len = std.mem.readInt(u16, self.rest[0..2], .big);
        if (len > self.rest.len - 2) return null;
        const name = self.rest[2..][0..len];
        self.rest = self.rest[2 + len ..];
        return name;
    }
};

/// True when the checked list has the DER name `name`.
pub fn contains(list: []const u8, name: []const u8) bool {
    var it: Iterator = .init(list);
    while (it.next()) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

const Names = struct { issuer: []const u8, subject: []const u8 };

/// The DER issuer name and subject name of a DER certificate, with their headers.
fn certificateNames(cert: []const u8) ?Names {
    const outer = der.parse(cert) catch return null;
    if (outer.tag != der.tag_sequence) return null;
    var top = outer.children();
    const tbs = top.require() catch return null;
    if (tbs.tag != der.tag_sequence) return null;
    var fields = tbs.children();
    var first = fields.require() catch return null;
    if (first.tag == der.tag_context_0) first = fields.require() catch return null; // the serial number
    _ = fields.require() catch return null; // the signature algorithm
    const issuer = fields.require() catch return null;
    _ = fields.require() catch return null; // the validity
    const subject = fields.require() catch return null;
    if (issuer.tag != der.tag_sequence or subject.tag != der.tag_sequence) return null;
    return .{ .issuer = issuer.raw, .subject = subject.raw };
}

/// True when the issuer of a certificate of `chain` is a name of `list`. The issuers are the
/// intermediate certificate authorities and the root of the chain.
pub fn chainMatches(chain: *const CertChain, list: []const u8) bool {
    for (chain.certs) |cert| {
        const names = certificateNames(cert) orelse continue;
        if (contains(list, names.issuer)) return true;
    }
    return false;
}

/// Iterate the subject names of the anchors of a trust policy. Only the `ca_set` and `bundle`
/// policies have anchors.
const AnchorNames = struct {
    trust: verify.Trust,
    index: usize = 0,
    bundle_it: ?@FieldType(std.crypto.Certificate.Bundle, "map").ValueIterator = null,

    fn next(self: *AnchorNames) ?[]const u8 {
        switch (self.trust) {
            .ca_set => |set| while (self.index < set.certs.items.len) {
                const cert = set.certs.items[self.index];
                self.index += 1;
                if (certificateNames(cert)) |names| return names.subject;
            },
            .bundle => |bundle| {
                if (self.bundle_it == null) self.bundle_it = bundle.map.valueIterator();
                while (self.bundle_it.?.next()) |start| {
                    if (certificateNames(bundle.bytes.items[start.*..])) |names| return names.subject;
                }
            },
            else => {},
        }
        return null;
    }
};

/// Write a certificate_authorities extension with the subject names of the anchors of
/// `trust`. The function writes nothing and returns false when the policy has no anchors, or
/// when the name list is longer than `max_list_len` bytes. The extension then does not go out
/// at all, because a part of the list can make the peer choose a wrong chain.
pub fn write(b: *codec.Builder, trust: verify.Trust, max_list_len: usize) bool {
    const start = b.len;
    b.int(u16, extension_type);
    const ext = b.beginLen(u16);
    const list = b.beginLen(u16);
    var names: AnchorNames = .{ .trust = trust };
    var count: usize = 0;
    while (names.next()) |name| {
        const list_len = b.len - list - 2;
        if (list_len + 2 + name.len > max_list_len or b.len + 2 + name.len > b.buf.len) {
            b.len = start;
            return false;
        }
        b.int(u16, @intCast(name.len));
        b.bytes(name);
        count += 1;
    }
    if (count == 0) {
        b.len = start;
        return false;
    }
    b.endLen(u16, list);
    b.endLen(u16, ext);
    return true;
}

/// A CertificateRequest with an empty context and the accepted signature schemes. With
/// `names`, it also has a certificate_authorities extension with the anchors of this policy
/// when they fit in `max_request_list_len` bytes. `buf` has `max_request_message_len` bytes.
pub fn certificateRequest(buf: []u8, schemes: []const tls.SignatureScheme, names: ?verify.Trust) []u8 {
    var b: codec.Builder = .{ .buf = buf };
    b.byte(@intFromEnum(tls.HandshakeType.certificate_request));
    const msg = b.beginLen(u24);
    b.byte(0); // certificate_request_context
    const exts = b.beginLen(u16);
    b.int(u16, @intFromEnum(tls.ExtensionType.signature_algorithms));
    const ext = b.beginLen(u16);
    const list = b.beginLen(u16);
    for (schemes) |s| b.int(u16, @intFromEnum(s));
    b.endLen(u16, list);
    b.endLen(u16, ext);
    if (names) |trust| _ = write(&b, trust, max_request_list_len);
    b.endLen(u16, exts);
    b.endLen(u24, msg);
    return b.slice();
}

// -- Tests -----------------------------------------------------------------------------------

const CaSet = @import("../CaSet.zig");

const test_name = "\x30\x1a\x31\x18\x30\x16\x06\x03\x55\x04\x03\x0c\x0fzig-sdk test CA";

fn loadCaDer(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    const pem = @import("../pem.zig");
    const text = try std.Io.Dir.cwd().readFileAlloc(io, "test/fixtures/tls/pem/ca.crt", gpa, .limited(1 << 16));
    defer gpa.free(text);
    var it: pem.Iterator = .init(text);
    return it.nextLabeled("CERTIFICATE").?.decode(gpa);
}

test "parse a name list" {
    const body = "\x00\x1e\x00\x1c" ++ test_name;
    const list = try parse(body);
    try std.testing.expect(contains(list, test_name));
    try std.testing.expect(!contains(list, test_name[0 .. test_name.len - 1]));
    var it: Iterator = .init(list);
    try std.testing.expectEqualStrings(test_name, it.next().?);
    try std.testing.expect(it.next() == null);
    // Two names.
    const two = "\x00\x3c\x00\x1c" ++ test_name ++ "\x00\x1c" ++ test_name;
    var count: usize = 0;
    var it2: Iterator = .init(try parse(two));
    while (it2.next()) |_| count += 1;
    try std.testing.expectEqual(2, count);
}

test "malformed name lists are decode errors" {
    const bad = [_][]const u8{
        "",
        "\x00",
        // An empty list, and a list shorter than the body or longer than the body.
        "\x00\x00",
        "\x00\x1d\x00\x1c" ++ test_name,
        "\x00\x1f\x00\x1c" ++ test_name,
        "\x00\x1e\x00\x1c" ++ test_name ++ "\x00",
        // A name of zero bytes, and a name longer than the list.
        "\x00\x03\x00\x00\x30",
        "\x00\x1e\x00\x1d" ++ test_name,
        // A name length without the name.
        "\x00\x20\x00\x1c" ++ test_name ++ "\x00\x05",
        // Not a SEQUENCE, an empty Name, an empty relative distinguished name, an attribute
        // without a value, an attribute with three parts, a type that is not an OID, and
        // trailing bytes after the Name.
        "\x00\x04\x00\x02\x31\x00",
        "\x00\x04\x00\x02\x30\x00",
        "\x00\x06\x00\x04\x30\x02\x31\x00",
        "\x00\x0d\x00\x0b\x30\x09\x31\x07\x30\x05\x06\x03\x55\x04\x03",
        "\x00\x11\x00\x0f\x30\x0d\x31\x0b\x30\x09\x06\x03\x55\x04\x03\x05\x00\x05\x00",
        "\x00\x0f\x00\x0d\x30\x0b\x31\x09\x30\x07\x04\x03\x55\x04\x03\x05\x00",
        "\x00\x1f\x00\x1d" ++ test_name ++ "\x00",
        // A truncated DER length.
        "\x00\x05\x00\x03\x30\x81\x80",
    };
    for (bad, 0..) |body, i| {
        errdefer std.debug.print("case {d}\n", .{i});
        try std.testing.expectError(error.DecodeError, parse(body));
    }
}

test "the names of the anchors round trip through a CertificateRequest" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const client = @import("client.zig");
    var set: CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    try set.addFile(io, "test/fixtures/tls/pem/rsa-pss.crt");
    var buf: [max_request_message_len]u8 = undefined;
    const msg = certificateRequest(&buf, &.{ .ecdsa_secp256r1_sha256, .rsa_pss_pss_sha256 }, .{ .ca_set = &set });
    try std.testing.expectEqual(msg.len - 4, std.mem.readInt(u24, msg[1..4], .big));
    const req = try client.CertificateRequest.parse(msg[4..]);
    try std.testing.expect(req.offersScheme(@intFromEnum(tls.SignatureScheme.rsa_pss_pss_sha256)));
    const list = req.authorities.?;
    try std.testing.expect(contains(list, test_name));
    const pss_name = "\x30\x22\x31\x20\x30\x1e\x06\x03\x55\x04\x03\x0c\x17zig-sdk RSA-PSS test CA";
    try std.testing.expect(contains(list, pss_name));

    // Without names, and with a policy that has no anchors.
    for ([_]?verify.Trust{ null, .self_signed, .no_verification }) |names| {
        const plain = certificateRequest(&buf, &.{.ed25519}, names);
        try std.testing.expect((try client.CertificateRequest.parse(plain[4..])).authorities == null);
    }
}

test "a name list that does not fit is left out" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const client = @import("client.zig");
    var set: CaSet = .init(gpa);
    defer set.deinit();
    const ca = try loadCaDer(gpa, io);
    defer gpa.free(ca);
    // Each copy of the CA adds 30 bytes to the list.
    const per_name = 2 + test_name.len;
    const fit = max_request_list_len / per_name;
    for (0..fit) |_| try set.addDer(ca);
    var buf: [max_request_message_len]u8 = undefined;
    const msg = certificateRequest(&buf, &.{.ed25519}, .{ .ca_set = &set });
    try std.testing.expect(msg.len < 16 << 10);
    const req = try client.CertificateRequest.parse(msg[4..]);
    try std.testing.expectEqual(fit * per_name, req.authorities.?.len);
    // One more name is too much: no names at all.
    try set.addDer(ca);
    const plain = certificateRequest(&buf, &.{.ed25519}, .{ .ca_set = &set });
    try std.testing.expect((try client.CertificateRequest.parse(plain[4..])).authorities == null);
    // A small limit in a ClientHello.
    var hello_buf: [64]u8 = undefined;
    var b: codec.Builder = .{ .buf = &hello_buf };
    try std.testing.expect(!write(&b, .{ .ca_set = &set }, max_hello_list_len));
    try std.testing.expectEqual(0, b.len);
}

test "the names of a std bundle" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    try bundle.addCertsFromFilePath(gpa, io, std.Io.Clock.real.now(io), std.Io.Dir.cwd(), "test/fixtures/tls/pem/ca.crt");
    try bundle.addCertsFromFilePath(gpa, io, std.Io.Clock.real.now(io), std.Io.Dir.cwd(), "test/fixtures/tls/pem/p256.crt");
    var buf: [256]u8 = undefined;
    var b: codec.Builder = .{ .buf = &buf };
    try std.testing.expect(write(&b, .{ .bundle = &bundle }, max_hello_list_len));
    const body = b.slice()[4..];
    const list = try parse(body);
    try std.testing.expect(contains(list, test_name));
    try std.testing.expect(contains(list, "\x30\x14\x31\x12\x30\x10\x06\x03\x55\x04\x03\x0c\x09localhost"));
    // An empty bundle has no names.
    var empty: std.crypto.Certificate.Bundle = .empty;
    b.len = 0;
    try std.testing.expect(!write(&b, .{ .bundle = &empty }, max_hello_list_len));
    try std.testing.expectEqual(0, b.len);
}

test "chains match the names of their issuers" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/chain.crt", "test/fixtures/tls/pem/chain-leaf.key");
    defer chain.deinit();
    var self_signed = try CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/p256.crt", "test/fixtures/tls/pem/p256.key");
    defer self_signed.deinit();
    const list = try parse("\x00\x1e\x00\x1c" ++ test_name);
    try std.testing.expect(chainMatches(&chain, list));
    try std.testing.expect(!chainMatches(&self_signed, list));
}
