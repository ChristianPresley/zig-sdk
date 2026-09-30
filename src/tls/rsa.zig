//! RSA private keys for a TLS 1.3 CertificateVerify. The key signs with RSASSA-PSS (RFC 8017
//! section 8.1) with MGF1, the same hash for the mask and a salt as long as the hash (RFC 8446
//! section 4.2.3). The private operation uses the Chinese remainder theorem and the constant
//! time arithmetic of `std.crypto.ff`. The key verifies each signature before it goes out.
const std = @import("std");
const crypto = std.crypto;
const ff = crypto.ff;
const der = @import("der.zig");

pub const min_modulus_bits = 2048;
pub const max_modulus_bits = 4096;
pub const max_modulus_len = max_modulus_bits / 8;
/// The DER `RSAPublicKey` of the largest key: a sequence of the modulus and the exponent.
pub const max_public_key_len = 4 + (4 + 1 + max_modulus_len) + (2 + 4);

const Modulus = ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;
const Uint = ff.Uint(max_modulus_bits);

pub const ParseError = error{
    /// The DER structure has an error.
    InvalidEncoding,
    /// The key has more than two primes, or a modulus or an exponent out of the range.
    UnsupportedKey,
    /// The key components are inconsistent.
    InvalidKey,
};

pub const SignError = error{SigningFailed};

/// A big-endian unsigned integer without leading zero bytes.
const Int = struct {
    bytes: [max_modulus_len]u8 = @splat(0),
    len: u16 = 0,

    fn slice(self: *const Int) []const u8 {
        return self.bytes[0..self.len];
    }

    fn set(bytes: []const u8) ParseError!Int {
        if (bytes.len > max_modulus_len) return error.UnsupportedKey;
        var out: Int = .{ .len = @intCast(bytes.len) };
        @memcpy(out.bytes[0..bytes.len], bytes);
        return out;
    }
};

/// An RSA private key with the CRT components. The private exponent `d` is not kept.
pub const PrivateKey = struct {
    n: Int,
    e: Int,
    p: Int,
    q: Int,
    dp: Int,
    dq: Int,
    qinv: Int,

    /// The length of the modulus and of a signature in bytes.
    pub fn modulusLen(self: *const PrivateKey) usize {
        return self.n.len;
    }

    /// The length of the modulus in bits.
    pub fn modulusBits(self: *const PrivateKey) usize {
        return (self.n.len - 1) * 8 + (8 - @as(usize, @clz(self.n.bytes[0])));
    }

    /// The public key as DER `RSAPublicKey`, the content of a certificate
    /// `subjectPublicKey` bit string.
    pub fn publicKeyDer(self: *const PrivateKey, buf: *[max_public_key_len]u8) []const u8 {
        var body: [max_public_key_len]u8 = undefined;
        var len: usize = 0;
        len += encodeInteger(body[len..], self.n.slice());
        len += encodeInteger(body[len..], self.e.slice());
        var out_len = encodeHeader(buf, der.tag_sequence, len);
        @memcpy(buf[out_len..][0..len], body[0..len]);
        out_len += len;
        return buf[0..out_len];
    }

    /// Sign `message` with RSASSA-PSS. `Hash` is the message hash and the MGF1 hash. `salt`
    /// has the length of the hash. `out` receives `modulusLen()` bytes.
    pub fn signPss(self: *const PrivateKey, comptime Hash: type, message: []const u8, salt: *const [Hash.digest_length]u8, out: []u8) SignError![]const u8 {
        const k = self.modulusLen();
        if (out.len < k) return error.SigningFailed;
        const em_bits = self.modulusBits() - 1;
        const em_len = (em_bits + 7) / 8;
        var em: [max_modulus_len]u8 = undefined;
        defer crypto.secureZero(u8, &em);
        @memset(em[0 .. k - em_len], 0);
        emsaPssEncode(Hash, message, salt, em_bits, em[k - em_len .. k]);
        try self.privateOp(em[0..k], out[0..k]);
        // A fault in the private operation can leak the key. The public operation must give
        // the encoded message back.
        var check: [max_modulus_len]u8 = undefined;
        self.publicOp(out[0..k], check[0..k]) catch {
            crypto.secureZero(u8, out[0..k]);
            return error.SigningFailed;
        };
        if (!std.mem.eql(u8, check[0..k], em[0..k])) {
            crypto.secureZero(u8, out[0..k]);
            return error.SigningFailed;
        }
        return out[0..k];
    }

    /// `input` to the power of `d` modulo `n`, with the Chinese remainder theorem.
    fn privateOp(self: *const PrivateKey, input: []const u8, out: []u8) SignError!void {
        const n = Modulus.fromBytes(self.n.slice(), .big) catch return error.SigningFailed;
        const p = Modulus.fromBytes(self.p.slice(), .big) catch return error.SigningFailed;
        const q = Modulus.fromBytes(self.q.slice(), .big) catch return error.SigningFailed;
        const m = Uint.fromBytes(input, .big) catch return error.SigningFailed;
        var buf: [max_modulus_len]u8 = undefined;
        defer crypto.secureZero(u8, &buf);

        // s1 = m^dP mod p and s2 = m^dQ mod q.
        var s1 = p.powWithEncodedExponent(p.reduce(m), self.dp.slice(), .big) catch return error.SigningFailed;
        defer crypto.secureZero(u8, std.mem.asBytes(&s1));
        var s2 = q.powWithEncodedExponent(q.reduce(m), self.dq.slice(), .big) catch return error.SigningFailed;
        defer crypto.secureZero(u8, std.mem.asBytes(&s2));

        // h = (s1 - s2) * qInv mod p.
        const q_len = self.q.len;
        s2.toBytes(buf[0..q_len], .big) catch return error.SigningFailed;
        const s2_uint = Uint.fromBytes(buf[0..q_len], .big) catch return error.SigningFailed;
        const qinv = Fe.fromBytes(p, self.qinv.slice(), .big) catch return error.SigningFailed;
        var h = p.mul(p.sub(s1, p.reduce(s2_uint)), qinv);
        defer crypto.secureZero(u8, std.mem.asBytes(&h));

        // s = s2 + q * h. The result is smaller than n, so the arithmetic modulo n is exact.
        const p_len = self.p.len;
        h.toBytes(buf[0..p_len], .big) catch return error.SigningFailed;
        const h_n = Fe.fromBytes(n, buf[0..p_len], .big) catch return error.SigningFailed;
        const q_n = Fe.fromBytes(n, self.q.slice(), .big) catch return error.SigningFailed;
        s2.toBytes(buf[0..q_len], .big) catch return error.SigningFailed;
        const s2_n = Fe.fromBytes(n, buf[0..q_len], .big) catch return error.SigningFailed;
        var s = n.add(s2_n, n.mul(q_n, h_n));
        defer crypto.secureZero(u8, std.mem.asBytes(&s));
        s.toBytes(out, .big) catch return error.SigningFailed;
    }

    /// `input` to the power of `e` modulo `n`.
    fn publicOp(self: *const PrivateKey, input: []const u8, out: []u8) SignError!void {
        const n = Modulus.fromBytes(self.n.slice(), .big) catch return error.SigningFailed;
        const x = Fe.fromBytes(n, input, .big) catch return error.SigningFailed;
        const y = n.powWithEncodedPublicExponent(x, self.e.slice(), .big) catch return error.SigningFailed;
        y.toBytes(out, .big) catch return error.SigningFailed;
    }
};

/// Parse a PKCS#1 `RSAPrivateKey` with two primes. The modulus has 2048 to 4096 bits and the
/// public exponent is odd, at least 3 and less than 2^32. A test signature checks that the
/// components agree.
pub fn parsePkcs1(bytes: []const u8) ParseError!PrivateKey {
    const root = der.parseExact(bytes) catch return error.InvalidEncoding;
    if (root.tag != der.tag_sequence) return error.InvalidEncoding;
    var it = root.children();
    const version = (it.require() catch return error.InvalidEncoding).smallInt() catch return error.InvalidEncoding;
    if (version == 1) return error.UnsupportedKey; // more than two primes
    if (version != 0) return error.InvalidEncoding;
    var key: PrivateKey = .{
        .n = try Int.set(try integer(&it)),
        .e = .{},
        .p = .{},
        .q = .{},
        .dp = .{},
        .dq = .{},
        .qinv = .{},
    };
    errdefer crypto.secureZero(u8, std.mem.asBytes(&key));
    const e = try integer(&it);
    _ = try integer(&it); // d: the CRT components replace it
    key.p = try Int.set(try integer(&it));
    key.q = try Int.set(try integer(&it));
    key.dp = try Int.set(try integer(&it));
    key.dq = try Int.set(try integer(&it));
    key.qinv = try Int.set(try integer(&it));
    if ((it.next() catch return error.InvalidEncoding) != null) return error.InvalidEncoding;

    if (key.n.len == 0) return error.InvalidKey;
    const bits = key.modulusBits();
    if (bits < min_modulus_bits or bits > max_modulus_bits) return error.UnsupportedKey;
    if (e.len == 0 or e.len > 4) return error.UnsupportedKey;
    var e_value: u32 = 0;
    for (e) |b| e_value = (e_value << 8) | b;
    if (e_value < 3 or e_value % 2 == 0) return error.InvalidKey;
    key.e = try Int.set(e);
    try checkComponents(&key);
    return key;
}

/// Check the components. The primes divide the modulus and each CRT value is less than its
/// prime. A test value survives the private and the public operation.
fn checkComponents(key: *const PrivateKey) ParseError!void {
    for ([_]*const Int{ &key.p, &key.q, &key.dp, &key.dq, &key.qinv }) |v| if (v.len == 0) return error.InvalidKey;
    const n = Modulus.fromBytes(key.n.slice(), .big) catch return error.InvalidKey;
    const p = Modulus.fromBytes(key.p.slice(), .big) catch return error.InvalidKey;
    const q = Modulus.fromBytes(key.q.slice(), .big) catch return error.InvalidKey;
    if (p.bits() < 2 or q.bits() < 2) return error.InvalidKey;
    const n_uint = Uint.fromBytes(key.n.slice(), .big) catch return error.InvalidKey;
    if (!p.reduce(n_uint).isZero() or !q.reduce(n_uint).isZero()) return error.InvalidKey;
    _ = Fe.fromBytes(p, key.dp.slice(), .big) catch return error.InvalidKey;
    _ = Fe.fromBytes(q, key.dq.slice(), .big) catch return error.InvalidKey;
    _ = Fe.fromBytes(p, key.qinv.slice(), .big) catch return error.InvalidKey;
    _ = n;

    const k = key.modulusLen();
    var input: [max_modulus_len]u8 = @splat(0);
    // A fixed value with bits in every limb, smaller than the modulus.
    for (input[1..k], 1..) |*b, i| b.* = @truncate(i *% 0x9d);
    var sig: [max_modulus_len]u8 = undefined;
    var back: [max_modulus_len]u8 = undefined;
    key.privateOp(input[0..k], sig[0..k]) catch return error.InvalidKey;
    key.publicOp(sig[0..k], back[0..k]) catch return error.InvalidKey;
    if (!std.mem.eql(u8, input[0..k], back[0..k])) return error.InvalidKey;
}

/// The next element as a non-negative INTEGER, without leading zero bytes.
fn integer(it: *der.Iterator) ParseError![]const u8 {
    const elem = it.require() catch return error.InvalidEncoding;
    if (elem.tag != der.tag_integer or elem.content.len == 0) return error.InvalidEncoding;
    if (elem.content[0] & 0x80 != 0) return error.InvalidKey; // negative
    var v = elem.content;
    while (v.len > 0 and v[0] == 0) v = v[1..];
    return v;
}

/// EMSA-PSS-ENCODE (RFC 8017 section 9.1.1) with a salt as long as the hash. `em` has
/// ceil(`em_bits` / 8) bytes.
pub fn emsaPssEncode(comptime Hash: type, message: []const u8, salt: *const [Hash.digest_length]u8, em_bits: usize, em: []u8) void {
    const h_len = Hash.digest_length;
    const em_len = (em_bits + 7) / 8;
    std.debug.assert(em.len == em_len and em_len >= 2 * h_len + 2);
    var m_hash: [h_len]u8 = undefined;
    Hash.hash(message, &m_hash, .{});
    // H = Hash(0x00 * 8 || mHash || salt).
    var h: [h_len]u8 = undefined;
    var hasher: Hash = .init(.{});
    hasher.update(&([_]u8{0} ** 8));
    hasher.update(&m_hash);
    hasher.update(salt);
    hasher.final(&h);
    // DB = PS || 0x01 || salt, then maskedDB = DB xor MGF1(H).
    const db_len = em_len - h_len - 1;
    const db = em[0..db_len];
    @memset(db[0 .. db_len - h_len - 1], 0);
    db[db_len - h_len - 1] = 0x01;
    @memcpy(db[db_len - h_len ..], salt);
    mgf1Xor(Hash, &h, db);
    db[0] &= @as(u8, 0xff) >> @intCast(8 * em_len - em_bits);
    @memcpy(em[db_len..][0..h_len], &h);
    em[em_len - 1] = 0xbc;
}

/// XOR `out` with MGF1 (RFC 8017 appendix B.2.1) of `seed`.
fn mgf1Xor(comptime Hash: type, seed: []const u8, out: []u8) void {
    var counter: u32 = 0;
    var i: usize = 0;
    while (i < out.len) : (counter += 1) {
        var block: [Hash.digest_length]u8 = undefined;
        var hasher: Hash = .init(.{});
        hasher.update(seed);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);
        hasher.update(&c);
        hasher.final(&block);
        const n = @min(block.len, out.len - i);
        for (out[i..][0..n], block[0..n]) |*o, b| o.* ^= b;
        i += n;
    }
}

fn encodeHeader(buf: []u8, tag: u8, len: usize) usize {
    buf[0] = tag;
    if (len < 0x80) {
        buf[1] = @intCast(len);
        return 2;
    }
    if (len < 0x100) {
        buf[1] = 0x81;
        buf[2] = @intCast(len);
        return 3;
    }
    buf[1] = 0x82;
    std.mem.writeInt(u16, buf[2..4], @intCast(len), .big);
    return 4;
}

/// A minimal DER INTEGER for a non-negative value without leading zero bytes.
fn encodeInteger(buf: []u8, value: []const u8) usize {
    const pad: usize = if (value.len == 0 or value[0] & 0x80 != 0) 1 else 0;
    var len = encodeHeader(buf, der.tag_integer, value.len + pad);
    if (pad == 1) {
        buf[len] = 0;
        len += 1;
    }
    @memcpy(buf[len..][0..value.len], value);
    return len + value.len;
}

// -- Tests -----------------------------------------------------------------------------------

const pem = @import("pem.zig");

fn loadKeyDer(gpa: std.mem.Allocator, path: []const u8, label: []const u8) ![]u8 {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 16));
    defer gpa.free(text);
    var it: pem.Iterator = .init(text);
    return it.nextLabeled(label).?.decode(gpa);
}

fn verifyWithStd(comptime Hash: type, key: *const PrivateKey, message: []const u8, sig: []const u8) !void {
    const Std = crypto.Certificate.rsa;
    var pk_buf: [max_public_key_len]u8 = undefined;
    const components = try Std.PublicKey.parseDer(key.publicKeyDer(&pk_buf));
    const public_key: Std.PublicKey = try .fromBytes(components.exponent, components.modulus);
    switch (sig.len) {
        inline 256, 384, 512 => |len| try Std.PSSSignature.verify(len, sig[0..len].*, message, public_key, Hash),
        else => return error.UnsupportedModulus,
    }
}

test "RSASSA-PSS signatures verify with the std verifier" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { path: []const u8, bits: usize }{
        .{ .path = "test/fixtures/tls/pem/rsa2048-pkcs1.key", .bits = 2048 },
        .{ .path = "test/fixtures/tls/pem/rsa3072-pkcs1.key", .bits = 3072 },
    };
    for (cases) |case| {
        const bytes = try loadKeyDer(gpa, case.path, "RSA PRIVATE KEY");
        defer gpa.free(bytes);
        var key = try parsePkcs1(bytes);
        try std.testing.expectEqual(case.bits, key.modulusBits());
        var out: [max_modulus_len]u8 = undefined;
        const message = "TLS 1.3, server CertificateVerify";
        inline for (.{ crypto.hash.sha2.Sha256, crypto.hash.sha2.Sha384, crypto.hash.sha2.Sha512 }) |Hash| {
            const salt: [Hash.digest_length]u8 = @splat(0x5a);
            const sig = try key.signPss(Hash, message, &salt, &out);
            try std.testing.expectEqual(case.bits / 8, sig.len);
            try verifyWithStd(Hash, &key, message, sig);
            try std.testing.expectError(error.InvalidSignature, verifyWithStd(Hash, &key, "another message", sig));
        }
        crypto.secureZero(u8, std.mem.asBytes(&key));
    }
}

test "EMSA-PSS encoding layout" {
    const Sha256 = crypto.hash.sha2.Sha256;
    const salt: [32]u8 = @splat(7);
    var em: [256]u8 = undefined;
    // An odd bit count clears the top bits of the first byte.
    emsaPssEncode(Sha256, "abc", &salt, 2047, &em);
    try std.testing.expectEqual(0xbc, em[255]);
    try std.testing.expect(em[0] & 0x80 == 0);
    // Unmask DB and find the separator and the salt.
    var db = em[0 .. 256 - 32 - 1].*;
    mgf1Xor(Sha256, em[256 - 33 .. 255], &db);
    db[0] &= 0x7f;
    for (db[0 .. db.len - 33]) |b| try std.testing.expectEqual(0, b);
    try std.testing.expectEqual(0x01, db[db.len - 33]);
    try std.testing.expectEqualSlices(u8, &salt, db[db.len - 32 ..]);
}

/// Encode `RSAPrivateKey` from its components, for the negative tests.
fn encodePkcs1(buf: []u8, version: u8, ints: []const []const u8) []const u8 {
    var body: [8 * (max_modulus_len + 8)]u8 = undefined;
    var len: usize = 0;
    body[0] = der.tag_integer;
    body[1] = 1;
    body[2] = version;
    len = 3;
    for (ints) |v| len += encodeInteger(body[len..], v);
    var out_len = encodeHeader(buf, der.tag_sequence, len);
    @memcpy(buf[out_len..][0..len], body[0..len]);
    out_len += len;
    return buf[0..out_len];
}

test "key parsing refuses bad keys" {
    const gpa = std.testing.allocator;
    const bytes = try loadKeyDer(gpa, "test/fixtures/tls/pem/rsa2048-pkcs1.key", "RSA PRIVATE KEY");
    defer gpa.free(bytes);
    // Take the components apart.
    var ints: [8][]const u8 = undefined;
    {
        const root = try der.parseExact(bytes);
        var it = root.children();
        _ = try it.require();
        for (&ints) |*v| v.* = try integer(&it);
    }
    var buf: [8 * (max_modulus_len + 8)]u8 = undefined;
    // The fixture itself, encoded again, parses.
    _ = try parsePkcs1(encodePkcs1(&buf, 0, &ints));

    try std.testing.expectError(error.InvalidEncoding, parsePkcs1(bytes[0 .. bytes.len - 1]));
    try std.testing.expectError(error.InvalidEncoding, parsePkcs1(encodePkcs1(&buf, 0, ints[0..7])));
    try std.testing.expectError(error.UnsupportedKey, parsePkcs1(encodePkcs1(&buf, 1, &ints)));
    try std.testing.expectError(error.InvalidEncoding, parsePkcs1(encodePkcs1(&buf, 2, &ints)));

    // An even or a small exponent.
    var bad = ints;
    bad[1] = "\x01\x00\x00";
    try std.testing.expectError(error.InvalidKey, parsePkcs1(encodePkcs1(&buf, 0, &bad)));
    bad[1] = "\x01";
    try std.testing.expectError(error.InvalidKey, parsePkcs1(encodePkcs1(&buf, 0, &bad)));
    bad[1] = "\x01\x00\x00\x00\x01";
    try std.testing.expectError(error.UnsupportedKey, parsePkcs1(encodePkcs1(&buf, 0, &bad)));

    // A wrong CRT exponent, a wrong coefficient and swapped primes.
    var changed: [max_modulus_len]u8 = undefined;
    inline for (.{ 5, 6, 7 }) |index| {
        bad = ints;
        @memcpy(changed[0..ints[index].len], ints[index]);
        changed[ints[index].len - 1] ^= 0x02;
        bad[index] = changed[0..ints[index].len];
        try std.testing.expectError(error.InvalidKey, parsePkcs1(encodePkcs1(&buf, 0, &bad)));
    }
    bad = ints;
    bad[3] = ints[4];
    bad[4] = ints[3];
    try std.testing.expectError(error.InvalidKey, parsePkcs1(encodePkcs1(&buf, 0, &bad)));
    // A prime that does not divide the modulus.
    bad = ints;
    @memcpy(changed[0..ints[3].len], ints[3]);
    changed[ints[3].len - 1] ^= 0x04;
    bad[3] = changed[0..ints[3].len];
    try std.testing.expectError(error.InvalidKey, parsePkcs1(encodePkcs1(&buf, 0, &bad)));

    // A 1024-bit key is too small.
    const small = try loadKeyDer(gpa, "test/fixtures/tls/pem/rsa1024-pkcs1.key", "RSA PRIVATE KEY");
    defer gpa.free(small);
    try std.testing.expectError(error.UnsupportedKey, parsePkcs1(small));
}
