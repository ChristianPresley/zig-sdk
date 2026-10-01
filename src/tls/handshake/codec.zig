//! Parse and build handshake messages (RFC 8446 section 4).
const std = @import("std");
const tls = std.crypto.tls;
const Decoder = tls.Decoder;
const ca_names = @import("ca_names.zig");

pub const max_message_len = 16 << 10;

pub const ParseError = error{
    /// The message is malformed: alert `decode_error`.
    DecodeError,
    /// A field has a forbidden value: alert `illegal_parameter`.
    IllegalParameter,
    /// The peer did not offer TLS 1.3: alert `protocol_version`.
    ProtocolVersion,
    /// A mandatory extension is absent: alert `missing_extension`.
    MissingExtension,
    /// The peer answered with an extension that this side did not send, or with an unknown
    /// one: alert `unsupported_extension` (RFC 8446 section 4.2).
    UnsupportedExtension,
};

/// True when `extension_type` has a name in `tls.ExtensionType`.
pub fn isKnownExtension(extension_type: u16) bool {
    for (std.enums.values(tls.ExtensionType)) |v| if (@intFromEnum(v) == extension_type) return true;
    return false;
}

pub const HandshakeType = tls.HandshakeType;

/// One bit for each of the 2^16 extension types or group code points.
pub const ExtensionSet = std.StaticBitSet(1 << 16);

/// A parsed ClientHello. Slices point into the message buffer.
pub const ClientHello = struct {
    random: [32]u8,
    session_id: []const u8,
    /// Raw big-endian `CipherSuite` list.
    cipher_suites: []const u8,
    /// Raw `NamedGroup` list.
    supported_groups: []const u8 = &.{},
    /// Raw `KeyShareEntry` list.
    key_shares: []const u8 = &.{},
    /// Raw `SignatureScheme` list.
    signature_algorithms: []const u8 = &.{},
    server_name: ?[]const u8 = null,
    /// Raw `ProtocolNameList`.
    alpn: []const u8 = &.{},
    /// The checked name list of the certificate_authorities extension (RFC 8446 section
    /// 4.2.4). Iterate it with `ca_names.Iterator`.
    certificate_authorities: ?[]const u8 = null,
    offers_tls_1_3: bool = false,
    has_key_share: bool = false,
    has_groups: bool = false,
    has_signature_algorithms: bool = false,
    has_pre_shared_key: bool = false,
    has_early_data: bool = false,
    /// The client asks for a stapled OCSP response (RFC 6066 section 8).
    status_request: bool = false,
    /// The cookie of a second ClientHello (RFC 8446 section 4.2.2).
    cookie: ?[]const u8 = null,

    pub fn parse(body: []u8) ParseError!ClientHello {
        var d: Decoder = .fromTheirSlice(body);
        d.ensure(2 + 32 + 1) catch return error.DecodeError;
        _ = d.decode(u16); // legacy_version: ignored, supported_versions decides
        var hello: ClientHello = .{ .random = d.array(32).*, .session_id = &.{}, .cipher_suites = &.{} };
        const sid_len = d.decode(u8);
        if (sid_len > 32) return error.DecodeError;
        d.ensure(sid_len + 2) catch return error.DecodeError;
        hello.session_id = d.slice(sid_len);
        const cs_len = d.decode(u16);
        if (cs_len < 2 or cs_len % 2 != 0) return error.DecodeError;
        d.ensure(cs_len + 1) catch return error.DecodeError;
        hello.cipher_suites = d.slice(cs_len);
        const comp_len = d.decode(u8);
        d.ensure(comp_len) catch return error.DecodeError;
        const compression = d.slice(comp_len);
        if (!(compression.len == 1 and compression[0] == 0)) return error.IllegalParameter;
        if (d.eof()) return error.MissingExtension;
        d.ensure(2) catch return error.DecodeError;
        const ext_len = d.decode(u16);
        var exts = d.sub(ext_len) catch return error.DecodeError;
        if (!d.eof()) return error.DecodeError;

        // Every extension type at most once (section 4.2). The set covers all 2^16 types.
        var seen: ExtensionSet = .initEmpty();
        while (!exts.eof()) {
            if (hello.has_pre_shared_key) return error.IllegalParameter; // pre_shared_key must be last
            exts.ensure(4) catch return error.DecodeError;
            const et = exts.decode(u16);
            const len = exts.decode(u16);
            var ext = exts.sub(len) catch return error.DecodeError;
            if (seen.isSet(et)) return error.IllegalParameter;
            seen.set(et);
            switch (@as(tls.ExtensionType, @enumFromInt(et))) {
                .supported_versions => {
                    ext.ensure(1) catch return error.DecodeError;
                    const list_len = ext.decode(u8);
                    if (list_len < 2 or list_len % 2 != 0) return error.DecodeError;
                    var list = ext.sub(list_len) catch return error.DecodeError;
                    while (!list.eof()) {
                        list.ensure(2) catch return error.DecodeError;
                        if (list.decode(u16) == @intFromEnum(tls.ProtocolVersion.tls_1_3)) hello.offers_tls_1_3 = true;
                    }
                },
                .supported_groups => {
                    ext.ensure(2) catch return error.DecodeError;
                    const list_len = ext.decode(u16);
                    if (list_len < 2 or list_len % 2 != 0) return error.DecodeError;
                    const list = ext.sub(list_len) catch return error.DecodeError;
                    hello.supported_groups = list.buf;
                    hello.has_groups = true;
                },
                .key_share => {
                    ext.ensure(2) catch return error.DecodeError;
                    const list_len = ext.decode(u16);
                    var list = ext.sub(list_len) catch return error.DecodeError;
                    hello.key_shares = list.buf;
                    while (!list.eof()) {
                        list.ensure(4) catch return error.DecodeError;
                        _ = list.decode(u16);
                        const klen = list.decode(u16);
                        if (klen == 0) return error.DecodeError;
                        list.ensure(klen) catch return error.DecodeError;
                        _ = list.slice(klen);
                    }
                    hello.has_key_share = true;
                },
                .signature_algorithms => {
                    ext.ensure(2) catch return error.DecodeError;
                    const list_len = ext.decode(u16);
                    if (list_len < 2 or list_len % 2 != 0) return error.DecodeError;
                    const list = ext.sub(list_len) catch return error.DecodeError;
                    hello.signature_algorithms = list.buf;
                    hello.has_signature_algorithms = true;
                },
                .server_name => {
                    ext.ensure(2) catch return error.DecodeError;
                    const list_len = ext.decode(u16);
                    var list = ext.sub(list_len) catch return error.DecodeError;
                    list.ensure(3) catch return error.DecodeError;
                    const name_type = list.decode(u8);
                    const name_len = list.decode(u16);
                    list.ensure(name_len) catch return error.DecodeError;
                    const name = list.slice(name_len);
                    if (name_type != 0) return error.IllegalParameter;
                    if (name.len == 0 or name.len > 255) return error.IllegalParameter;
                    for (name) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '.')) return error.IllegalParameter;
                    // The list has one host name. Another entry has no length that a parser can skip.
                    if (!list.eof()) return error.DecodeError;
                    hello.server_name = name;
                },
                .application_layer_protocol_negotiation => {
                    ext.ensure(2) catch return error.DecodeError;
                    const list_len = ext.decode(u16);
                    var list = ext.sub(list_len) catch return error.DecodeError;
                    hello.alpn = list.buf;
                    if (list.eof()) return error.DecodeError;
                    while (!list.eof()) {
                        list.ensure(1) catch return error.DecodeError;
                        const plen = list.decode(u8);
                        if (plen == 0) return error.IllegalParameter;
                        list.ensure(plen) catch return error.DecodeError;
                        _ = list.slice(plen);
                    }
                },
                .certificate_authorities => {
                    hello.certificate_authorities = try ca_names.parse(ext.buf);
                    continue;
                },
                .cookie => {
                    ext.ensure(2) catch return error.DecodeError;
                    const cookie_len = ext.decode(u16);
                    if (cookie_len == 0) return error.DecodeError;
                    ext.ensure(cookie_len) catch return error.DecodeError;
                    hello.cookie = ext.slice(cookie_len);
                },
                .status_request => {
                    ext.ensure(1) catch return error.DecodeError;
                    hello.status_request = ext.decode(u8) == 1; // status_type ocsp
                    // The server reads no responder ids and no request extensions.
                    continue;
                },
                // The parser does not read the body of these extensions and of unknown ones.
                .pre_shared_key => {
                    hello.has_pre_shared_key = true;
                    continue;
                },
                .early_data => {
                    hello.has_early_data = true;
                    continue;
                },
                else => continue,
            }
            // The body of a known extension ends where its structure ends.
            if (!ext.eof()) return error.DecodeError;
        }
        if (!hello.offers_tls_1_3) return error.ProtocolVersion;
        if (!hello.has_key_share or !hello.has_groups or !hello.has_signature_algorithms) return error.MissingExtension;
        try hello.checkKeyShareGroups();
        return hello;
    }

    /// Each key share is for a group in supported_groups, and no two key shares have the same
    /// group (section 4.2.8). The parser checked the layout of both lists.
    fn checkKeyShareGroups(self: *const ClientHello) ParseError!void {
        var offered: ExtensionSet = .initEmpty();
        var i: usize = 0;
        while (i + 2 <= self.supported_groups.len) : (i += 2) offered.set(std.mem.readInt(u16, self.supported_groups[i..][0..2], .big));
        i = 0;
        while (i + 4 <= self.key_shares.len) {
            const group = std.mem.readInt(u16, self.key_shares[i..][0..2], .big);
            const len = std.mem.readInt(u16, self.key_shares[i + 2 ..][0..2], .big);
            // A group that is not offered, or a second share for a group, is not in the set.
            if (!offered.isSet(group)) return error.IllegalParameter;
            offered.unset(group);
            i += 4 + @as(usize, len);
        }
    }

    pub fn offersSuite(self: *const ClientHello, id: u16) bool {
        return containsU16(self.cipher_suites, id);
    }

    pub fn offersGroup(self: *const ClientHello, id: u16) bool {
        return containsU16(self.supported_groups, id);
    }

    pub fn offersScheme(self: *const ClientHello, id: u16) bool {
        return containsU16(self.signature_algorithms, id);
    }

    /// The client's key share for `group`, if any.
    pub fn keyShare(self: *const ClientHello, group: u16) ?[]const u8 {
        var i: usize = 0;
        while (i + 4 <= self.key_shares.len) {
            const g = std.mem.readInt(u16, self.key_shares[i..][0..2], .big);
            const len = std.mem.readInt(u16, self.key_shares[i + 2 ..][0..2], .big);
            i += 4;
            if (i + len > self.key_shares.len) return null;
            if (g == group) return self.key_shares[i .. i + len];
            i += len;
        }
        return null;
    }

    pub fn offersAlpn(self: *const ClientHello, name: []const u8) bool {
        var i: usize = 0;
        while (i < self.alpn.len) {
            const len = self.alpn[i];
            i += 1;
            if (i + len > self.alpn.len) return false;
            if (std.mem.eql(u8, self.alpn[i .. i + len], name)) return true;
            i += len;
        }
        return false;
    }
};

fn containsU16(list: []const u8, id: u16) bool {
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (std.mem.readInt(u16, list[i..][0..2], .big) == id) return true;
    }
    return false;
}

/// A bounded writer for handshake messages.
pub const Builder = struct {
    buf: []u8,
    len: usize = 0,

    pub fn byte(self: *Builder, v: u8) void {
        self.buf[self.len] = v;
        self.len += 1;
    }

    pub fn int(self: *Builder, comptime T: type, v: T) void {
        const n = @divExact(@bitSizeOf(T), 8);
        std.mem.writeInt(T, self.buf[self.len..][0..n], v, .big);
        self.len += n;
    }

    pub fn bytes(self: *Builder, b: []const u8) void {
        @memcpy(self.buf[self.len..][0..b.len], b);
        self.len += b.len;
    }

    /// Reserve a length prefix of `T` bytes. Returns its position for `endLen`.
    pub fn beginLen(self: *Builder, comptime T: type) usize {
        const pos = self.len;
        self.len += @divExact(@bitSizeOf(T), 8);
        return pos;
    }

    pub fn endLen(self: *Builder, comptime T: type, pos: usize) void {
        const n = @divExact(@bitSizeOf(T), 8);
        const len = self.len - pos - n;
        std.mem.writeInt(T, self.buf[pos..][0..n], @intCast(len), .big);
    }

    pub fn slice(self: *Builder) []u8 {
        return self.buf[0..self.len];
    }
};

/// Build a ServerHello or, with `hrr`, a HelloRetryRequest.
pub fn serverHello(buf: []u8, random: [32]u8, session_id: []const u8, suite: u16, group: u16, public: []const u8, hrr: bool) []u8 {
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.server_hello));
    const msg = b.beginLen(u24);
    b.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2));
    b.bytes(&random);
    b.byte(@intCast(session_id.len));
    b.bytes(session_id);
    b.int(u16, suite);
    b.byte(0); // legacy_compression_method
    const exts = b.beginLen(u16);
    b.int(u16, @intFromEnum(tls.ExtensionType.supported_versions));
    b.int(u16, 2);
    b.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_3));
    b.int(u16, @intFromEnum(tls.ExtensionType.key_share));
    const ks = b.beginLen(u16);
    b.int(u16, group);
    if (!hrr) {
        b.int(u16, @intCast(public.len));
        b.bytes(public);
    }
    b.endLen(u16, ks);
    b.endLen(u16, exts);
    b.endLen(u24, msg);
    return b.slice();
}

/// A HelloRetryRequest (RFC 8446 section 4.1.4) with the group of the wanted key share, a
/// cookie, or both. At least one of the two must be present.
pub fn helloRetryRequest(buf: []u8, session_id: []const u8, suite: u16, group: ?u16, cookie: ?[]const u8) []u8 {
    std.debug.assert(group != null or cookie != null);
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.server_hello));
    const msg = b.beginLen(u24);
    b.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2));
    b.bytes(&tls.hello_retry_request_sequence);
    b.byte(@intCast(session_id.len));
    b.bytes(session_id);
    b.int(u16, suite);
    b.byte(0); // legacy_compression_method
    const exts = b.beginLen(u16);
    b.int(u16, @intFromEnum(tls.ExtensionType.supported_versions));
    b.int(u16, 2);
    b.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_3));
    if (group) |g| {
        b.int(u16, @intFromEnum(tls.ExtensionType.key_share));
        b.int(u16, 2);
        b.int(u16, g);
    }
    if (cookie) |value| {
        b.int(u16, @intFromEnum(tls.ExtensionType.cookie));
        const ext = b.beginLen(u16);
        b.int(u16, @intCast(value.len));
        b.bytes(value);
        b.endLen(u16, ext);
    }
    b.endLen(u16, exts);
    b.endLen(u24, msg);
    return b.slice();
}

pub fn encryptedExtensions(buf: []u8, alpn: ?[]const u8, server_name_ack: bool) []u8 {
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.encrypted_extensions));
    const msg = b.beginLen(u24);
    const exts = b.beginLen(u16);
    if (alpn) |name| {
        b.int(u16, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation));
        const ext = b.beginLen(u16);
        const list = b.beginLen(u16);
        b.byte(@intCast(name.len));
        b.bytes(name);
        b.endLen(u16, list);
        b.endLen(u16, ext);
    }
    if (server_name_ack) {
        b.int(u16, @intFromEnum(tls.ExtensionType.server_name));
        b.int(u16, 0);
    }
    b.endLen(u16, exts);
    b.endLen(u24, msg);
    return b.slice();
}

pub fn certificateVerify(buf: []u8, scheme: u16, signature: []const u8) []u8 {
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.certificate_verify));
    const msg = b.beginLen(u24);
    b.int(u16, scheme);
    b.int(u16, @intCast(signature.len));
    b.bytes(signature);
    b.endLen(u24, msg);
    return b.slice();
}

pub fn finished(buf: []u8, verify_data: []const u8) []u8 {
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.finished));
    const msg = b.beginLen(u24);
    b.bytes(verify_data);
    b.endLen(u24, msg);
    return b.slice();
}

pub fn keyUpdate(buf: []u8, request_update: bool) []u8 {
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.key_update));
    b.int(u24, 1);
    b.byte(if (request_update) 1 else 0);
    return b.slice();
}

/// The synthetic `message_hash` message that replaces the first ClientHello after a
/// HelloRetryRequest (RFC 8446 section 4.4.1).
pub fn messageHash(buf: []u8, hash: []const u8) []u8 {
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.message_hash));
    b.int(u24, @intCast(hash.len));
    b.bytes(hash);
    return b.slice();
}

pub const certificate_verify_context = " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00";
pub const client_certificate_verify_context = " " ** 64 ++ "TLS 1.3, client CertificateVerify\x00";

test "parse a minimal client hello" {
    var b: Builder = .{ .buf = try std.testing.allocator.alloc(u8, 512) };
    defer std.testing.allocator.free(b.buf);
    b.int(u16, 0x0303);
    b.bytes(&([_]u8{7} ** 32));
    b.byte(0); // session id
    b.int(u16, 4);
    b.int(u16, 0x1301);
    b.int(u16, 0x1303);
    b.byte(1);
    b.byte(0);
    const exts = b.beginLen(u16);
    // supported_versions
    b.int(u16, 43);
    b.int(u16, 3);
    b.byte(2);
    b.int(u16, 0x0304);
    // supported_groups
    b.int(u16, 10);
    b.int(u16, 4);
    b.int(u16, 2);
    b.int(u16, 0x001d);
    // signature_algorithms
    b.int(u16, 13);
    b.int(u16, 4);
    b.int(u16, 2);
    b.int(u16, 0x0403);
    // key_share
    b.int(u16, 51);
    b.int(u16, 2 + 4 + 32);
    b.int(u16, 4 + 32);
    b.int(u16, 0x001d);
    b.int(u16, 32);
    b.bytes(&([_]u8{9} ** 32));
    // server_name
    b.int(u16, 0);
    b.int(u16, 2 + 3 + 9);
    b.int(u16, 3 + 9);
    b.byte(0);
    b.int(u16, 9);
    b.bytes("localhost");
    // alpn
    b.int(u16, 16);
    b.int(u16, 2 + 3 + 9);
    b.int(u16, 3 + 9);
    b.byte(2);
    b.bytes("h2");
    b.byte(8);
    b.bytes("http/1.1");
    b.endLen(u16, exts);
    const hello = try ClientHello.parse(b.slice());
    try std.testing.expect(hello.offers_tls_1_3);
    try std.testing.expect(hello.offersSuite(0x1303));
    try std.testing.expect(!hello.offersSuite(0x1302));
    try std.testing.expect(hello.offersGroup(0x001d));
    try std.testing.expect(hello.offersScheme(0x0403));
    try std.testing.expectEqualSlices(u8, &([_]u8{9} ** 32), hello.keyShare(0x001d).?);
    try std.testing.expect(hello.keyShare(0x0017) == null);
    try std.testing.expectEqualStrings("localhost", hello.server_name.?);
    try std.testing.expect(hello.offersAlpn("http/1.1"));
    try std.testing.expect(!hello.offersAlpn("http/1.0"));

    // Without supported_versions the client speaks TLS 1.2 at most.
    const short = b.slice()[0 .. 2 + 32 + 1 + 2 + 4 + 2];
    try std.testing.expectError(error.MissingExtension, ClientHello.parse(short));
    // Truncated.
    try std.testing.expectError(error.DecodeError, ClientHello.parse(b.slice()[0..40]));
}

/// An extension for the test ClientHellos.
const TestExtension = struct { type: u16, body: []const u8 };

/// A ClientHello body with one cipher suite and the extensions `exts` in this order.
fn testHello(buf: []u8, exts: []const TestExtension) []u8 {
    var b: Builder = .{ .buf = buf };
    b.int(u16, 0x0303);
    b.bytes(&([_]u8{7} ** 32));
    b.byte(0);
    b.int(u16, 2);
    b.int(u16, 0x1301);
    b.byte(1);
    b.byte(0);
    const list = b.beginLen(u16);
    for (exts) |e| {
        b.int(u16, e.type);
        b.int(u16, @intCast(e.body.len));
        b.bytes(e.body);
    }
    b.endLen(u16, list);
    return b.slice();
}

const test_versions: TestExtension = .{ .type = 43, .body = "\x02\x03\x04" };
const test_groups: TestExtension = .{ .type = 10, .body = "\x00\x04\x00\x1d\x00\x17" };
const test_schemes: TestExtension = .{ .type = 13, .body = "\x00\x02\x04\x03" };
const test_share: TestExtension = .{ .type = 51, .body = "\x00\x24\x00\x1d\x00\x20" ++ "\x09" ** 32 };

test "a duplicate extension after many other extensions is refused" {
    var buf: [4096]u8 = undefined;
    var exts: [40]TestExtension = undefined;
    // 32 distinct unknown extensions, then the mandatory ones.
    for (exts[0..32], 0..) |*e, i| e.* = .{ .type = @intCast(0x7000 + i), .body = "" };
    exts[32..36].* = .{ test_versions, test_groups, test_schemes, test_share };
    _ = try ClientHello.parse(testHello(&buf, exts[0..36]));
    // A second key_share or supported_versions after all of them.
    exts[36] = test_share;
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(testHello(&buf, exts[0..37])));
    exts[36] = test_versions;
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(testHello(&buf, exts[0..37])));
    // A second unknown extension of the same type.
    exts[36] = exts[0];
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(testHello(&buf, exts[0..37])));
}

test "key shares must be for distinct offered groups" {
    var buf: [4096]u8 = undefined;
    var groups_buf: [2 + 2 * 20]u8 = undefined;
    var shares_buf: [2 + 20 * 5]u8 = undefined;
    // 18 distinct groups in supported_groups and one share of one byte for each.
    std.mem.writeInt(u16, groups_buf[0..2], 2 * 18, .big);
    for (0..18) |i| std.mem.writeInt(u16, groups_buf[2 + 2 * i ..][0..2], @intCast(0x0100 + i), .big);
    const groups: TestExtension = .{ .type = 10, .body = groups_buf[0 .. 2 + 2 * 18] };
    for (0..18) |i| {
        std.mem.writeInt(u16, shares_buf[2 + 5 * i ..][0..2], @intCast(0x0100 + i), .big);
        std.mem.writeInt(u16, shares_buf[2 + 5 * i + 2 ..][0..2], 1, .big);
        shares_buf[2 + 5 * i + 4] = 0x42;
    }
    std.mem.writeInt(u16, shares_buf[0..2], 5 * 18, .big);
    _ = try ClientHello.parse(testHello(&buf, &.{ test_versions, groups, test_schemes, .{ .type = 51, .body = shares_buf[0 .. 2 + 5 * 18] } }));
    // A 19th share for the first group again.
    @memcpy(shares_buf[2 + 5 * 18 ..][0..5], shares_buf[2..7]);
    std.mem.writeInt(u16, shares_buf[0..2], 5 * 19, .big);
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(testHello(&buf, &.{ test_versions, groups, test_schemes, .{ .type = 51, .body = shares_buf[0 .. 2 + 5 * 19] } })));
    // A share for a group that supported_groups does not list, before or after that list.
    const other_share: TestExtension = .{ .type = 51, .body = "\x00\x05\x00\x18\x00\x01\x42" };
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(testHello(&buf, &.{ test_versions, test_groups, test_schemes, other_share })));
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(testHello(&buf, &.{ other_share, test_versions, test_groups, test_schemes })));
}

test "trailing bytes in a known client hello extension are a decode error" {
    var buf: [4096]u8 = undefined;
    _ = try ClientHello.parse(testHello(&buf, &.{ test_versions, test_groups, test_schemes, test_share }));
    const bad = [_]TestExtension{
        .{ .type = 43, .body = "\x02\x03\x04\x00" },
        .{ .type = 10, .body = "\x00\x04\x00\x1d\x00\x17\x00" },
        .{ .type = 13, .body = "\x00\x02\x04\x03\x00" },
        .{ .type = 51, .body = "\x00\x24\x00\x1d\x00\x20" ++ "\x09" ** 32 ++ "\x00" },
        .{ .type = 0, .body = "\x00\x0c\x00\x00\x09localhost\x00" },
        .{ .type = 0, .body = "\x00\x0d\x00\x00\x09localhost\x00" },
        .{ .type = 16, .body = "\x00\x03\x02h2\x00" },
    };
    const mandatory = [_]TestExtension{ test_versions, test_groups, test_schemes, test_share };
    for (bad) |e| {
        // Replace the mandatory extension of the same type, or add the extension.
        var list: [5]TestExtension = undefined;
        var n: usize = 0;
        for (mandatory) |m| {
            if (m.type == e.type) continue;
            list[n] = m;
            n += 1;
        }
        list[n] = e;
        try std.testing.expectError(error.DecodeError, ClientHello.parse(testHello(&buf, list[0 .. n + 1])));
    }
}

test "the certificate_authorities extension of a client hello" {
    var buf: [4096]u8 = undefined;
    const name = "\x30\x1a\x31\x18\x30\x16\x06\x03\x55\x04\x03\x0c\x0fzig-sdk test CA";
    const names: TestExtension = .{ .type = 47, .body = "\x00\x1e\x00\x1c" ++ name };
    const hello = try ClientHello.parse(testHello(&buf, &.{ test_versions, test_groups, names, test_schemes, test_share }));
    try std.testing.expect(ca_names.contains(hello.certificate_authorities.?, name));
    const plain = try ClientHello.parse(testHello(&buf, &.{ test_versions, test_groups, test_schemes, test_share }));
    try std.testing.expect(plain.certificate_authorities == null);
    // A malformed list, an empty list and a second extension.
    const bad: TestExtension = .{ .type = 47, .body = "\x00\x1e\x00\x1c\x31" ++ name[1..] };
    try std.testing.expectError(error.DecodeError, ClientHello.parse(testHello(&buf, &.{ test_versions, test_groups, bad, test_schemes, test_share })));
    const empty: TestExtension = .{ .type = 47, .body = "\x00\x00" };
    try std.testing.expectError(error.DecodeError, ClientHello.parse(testHello(&buf, &.{ test_versions, test_groups, empty, test_schemes, test_share })));
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(testHello(&buf, &.{ test_versions, names, test_groups, names, test_schemes, test_share })));
}

test "server hello builder" {
    var buf: [256]u8 = undefined;
    const sh = serverHello(&buf, [_]u8{1} ** 32, "abc", 0x1301, 0x001d, &([_]u8{2} ** 32), false);
    try std.testing.expectEqual(@as(u8, 2), sh[0]);
    try std.testing.expectEqual(sh.len - 4, std.mem.readInt(u24, sh[1..4], .big));
    const hrr = serverHello(&buf, tls.hello_retry_request_sequence, "abc", 0x1301, 0x0017, &.{}, true);
    try std.testing.expect(hrr.len < sh.len);
}
