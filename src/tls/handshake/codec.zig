//! Parse and build handshake messages (RFC 8446 section 4).
const std = @import("std");
const tls = std.crypto.tls;
const Decoder = tls.Decoder;

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
};

pub const HandshakeType = tls.HandshakeType;

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
    offers_tls_1_3: bool = false,
    has_key_share: bool = false,
    has_groups: bool = false,
    has_signature_algorithms: bool = false,
    has_pre_shared_key: bool = false,
    has_early_data: bool = false,

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

        var seen: [32]u16 = undefined;
        var seen_len: usize = 0;
        while (!exts.eof()) {
            if (hello.has_pre_shared_key) return error.IllegalParameter; // pre_shared_key must be last
            exts.ensure(4) catch return error.DecodeError;
            const et = exts.decode(u16);
            const len = exts.decode(u16);
            var ext = exts.sub(len) catch return error.DecodeError;
            for (seen[0..seen_len]) |s| if (s == et) return error.IllegalParameter;
            if (seen_len < seen.len) {
                seen[seen_len] = et;
                seen_len += 1;
            }
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
                    var groups_seen: [16]u16 = undefined;
                    var n: usize = 0;
                    while (!list.eof()) {
                        list.ensure(4) catch return error.DecodeError;
                        const g = list.decode(u16);
                        const klen = list.decode(u16);
                        if (klen == 0) return error.DecodeError;
                        list.ensure(klen) catch return error.DecodeError;
                        _ = list.slice(klen);
                        for (groups_seen[0..n]) |s| if (s == g) return error.IllegalParameter;
                        if (n < groups_seen.len) {
                            groups_seen[n] = g;
                            n += 1;
                        }
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
                .pre_shared_key => hello.has_pre_shared_key = true,
                .early_data => hello.has_early_data = true,
                else => {},
            }
        }
        if (!hello.offers_tls_1_3) return error.ProtocolVersion;
        if (!hello.has_key_share or !hello.has_groups or !hello.has_signature_algorithms) return error.MissingExtension;
        return hello;
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

/// A CertificateRequest with an empty context and the accepted signature schemes.
pub fn certificateRequest(buf: []u8, schemes: []const tls.SignatureScheme) []u8 {
    var b: Builder = .{ .buf = buf };
    b.byte(@intFromEnum(HandshakeType.certificate_request));
    const msg = b.beginLen(u24);
    b.byte(0); // certificate_request_context
    const exts = b.beginLen(u16);
    b.int(u16, @intFromEnum(tls.ExtensionType.signature_algorithms));
    const ext = b.beginLen(u16);
    const list = b.beginLen(u16);
    for (schemes) |s| b.int(u16, @intFromEnum(s));
    b.endLen(u16, list);
    b.endLen(u16, ext);
    b.endLen(u16, exts);
    b.endLen(u24, msg);
    return b.slice();
}

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

test "server hello builder" {
    var buf: [256]u8 = undefined;
    const sh = serverHello(&buf, [_]u8{1} ** 32, "abc", 0x1301, 0x001d, &([_]u8{2} ** 32), false);
    try std.testing.expectEqual(@as(u8, 2), sh[0]);
    try std.testing.expectEqual(sh.len - 4, std.mem.readInt(u24, sh[1..4], .big));
    const hrr = serverHello(&buf, tls.hello_retry_request_sequence, "abc", 0x1301, 0x0017, &.{}, true);
    try std.testing.expect(hrr.len < sh.len);
}
