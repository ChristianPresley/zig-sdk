//! RSA private keys for JSON Web Token signatures. This file reads PKCS#1 and PKCS#8 keys and
//! signs with RSASSA-PKCS1-v1_5 and SHA-256 (the JWS algorithm RS256). The exponentiation is
//! the constant-time one of `std.crypto.ff`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../../tls/der.zig");
const Certificate = std.crypto.Certificate;
const Sha256 = std.crypto.hash.sha2.Sha256;

const max_modulus_bits = 4096;
const Modulus = std.crypto.ff.Modulus(max_modulus_bits);

const oid_rsa_encryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

/// The DER prefix of a SHA-256 `DigestInfo` (RFC 8017 section 9.2).
const digest_info_sha256 = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

pub const ParseError = error{ OutOfMemory, InvalidEncoding, UnsupportedKey, InvalidKey };
pub const SignError = error{ OutOfMemory, SigningFailed };

pub const PrivateKey = struct {
    /// The big-endian modulus without leading zero bytes.
    modulus: []const u8,
    /// The big-endian public exponent.
    public_exponent: []const u8,
    /// The big-endian private exponent.
    private_exponent: []const u8,
    /// Owns the three values above.
    storage: []u8,

    /// Parse a PKCS#8 `PrivateKeyInfo` with an RSA key, or a PKCS#1 `RSAPrivateKey`.
    pub fn parseDer(gpa: Allocator, bytes: []const u8) ParseError!PrivateKey {
        const root = der.parseExact(bytes) catch return error.InvalidEncoding;
        if (root.tag != der.tag_sequence) return error.InvalidEncoding;
        var it = root.children();
        _ = it.require() catch return error.InvalidEncoding;
        const second = it.require() catch return error.InvalidEncoding;
        if (second.tag == der.tag_sequence) {
            // PKCS#8: version, AlgorithmIdentifier, OCTET STRING with the PKCS#1 key.
            var alg = second.children();
            const oid = alg.require() catch return error.InvalidEncoding;
            if (!oid.isOid(oid_rsa_encryption)) return error.UnsupportedKey;
            const inner = (it.require() catch return error.InvalidEncoding).expect(der.tag_octet_string) catch return error.InvalidEncoding;
            return parsePkcs1(gpa, inner.content);
        }
        return parsePkcs1(gpa, bytes);
    }

    fn parsePkcs1(gpa: Allocator, bytes: []const u8) ParseError!PrivateKey {
        const root = der.parseExact(bytes) catch return error.InvalidEncoding;
        if (root.tag != der.tag_sequence) return error.InvalidEncoding;
        var it = root.children();
        const version = (it.require() catch return error.InvalidEncoding).smallInt() catch return error.InvalidEncoding;
        if (version != 0) return error.UnsupportedKey;
        const n = try unsignedInteger(&it);
        const e = try unsignedInteger(&it);
        const d = try unsignedInteger(&it);
        if (n.len * 8 < 2048 or n.len * 8 > max_modulus_bits or n[n.len - 1] & 1 == 0) return error.InvalidKey;
        if (e.len == 0 or e.len > 4 or d.len == 0 or d.len > n.len) return error.InvalidKey;
        const storage = try gpa.alloc(u8, n.len + e.len + d.len);
        @memcpy(storage[0..n.len], n);
        @memcpy(storage[n.len..][0..e.len], e);
        @memcpy(storage[n.len + e.len ..], d);
        return .{
            .modulus = storage[0..n.len],
            .public_exponent = storage[n.len..][0..e.len],
            .private_exponent = storage[n.len + e.len ..],
            .storage = storage,
        };
    }

    fn unsignedInteger(it: *der.Iterator) ParseError![]const u8 {
        const elem = (it.require() catch return error.InvalidEncoding).expect(der.tag_integer) catch return error.InvalidEncoding;
        if (elem.content.len == 0 or elem.content[0] & 0x80 != 0) return error.InvalidEncoding;
        return std.mem.trimStart(u8, elem.content, "\x00");
    }

    pub fn deinit(self: *PrivateKey, gpa: Allocator) void {
        std.crypto.secureZero(u8, self.storage);
        gpa.free(self.storage);
        self.* = undefined;
    }

    /// The length of a signature in bytes.
    pub fn signatureLength(self: *const PrivateKey) usize {
        return self.modulus.len;
    }

    /// Sign `message` with RSASSA-PKCS1-v1_5 and SHA-256. The result is in `arena`.
    pub fn signPkcs1v15Sha256(self: *const PrivateKey, arena: Allocator, message: []const u8) SignError![]u8 {
        const k = self.modulus.len;
        if (k < digest_info_sha256.len + Sha256.digest_length + 11) return error.SigningFailed;
        // EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || H (RFC 8017 section 9.2).
        const em = try arena.alloc(u8, k);
        defer std.crypto.secureZero(u8, em);
        em[0] = 0x00;
        em[1] = 0x01;
        const t_len = digest_info_sha256.len + Sha256.digest_length;
        @memset(em[2 .. k - t_len - 1], 0xff);
        em[k - t_len - 1] = 0x00;
        @memcpy(em[k - t_len ..][0..digest_info_sha256.len], &digest_info_sha256);
        Sha256.hash(message, em[k - Sha256.digest_length ..][0..Sha256.digest_length], .{});

        const n = Modulus.fromBytes(self.modulus, .big) catch return error.SigningFailed;
        const m = Modulus.Fe.fromBytes(n, em, .big) catch return error.SigningFailed;
        const s = n.powWithEncodedExponent(m, self.private_exponent, .big) catch return error.SigningFailed;
        const out = try arena.alloc(u8, k);
        s.toBytes(out, .big) catch return error.SigningFailed;

        // Check the signature with the public key before it leaves the process.
        const pk = Certificate.rsa.PublicKey.fromBytes(self.public_exponent, self.modulus) catch return error.SigningFailed;
        switch (k) {
            inline 256, 384, 512 => |len| Certificate.rsa.PKCS1v1_5Signature.verify(len, out[0..len].*, message, pk, Sha256) catch return error.SigningFailed,
            else => return error.SigningFailed,
        }
        return out;
    }
};

test "rsa key parsing refuses other keys" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.InvalidEncoding, PrivateKey.parseDer(gpa, "\x30\x00"));
    // A PKCS#8 structure with the P-256 algorithm identifier.
    const ec = "\x30\x13\x02\x01\x00\x30\x09\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x04\x03\x30\x01\x00";
    try std.testing.expectError(error.UnsupportedKey, PrivateKey.parseDer(gpa, ec));
}
