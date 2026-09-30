//! A private key for a certificate: ECDSA P-256, ECDSA P-384, Ed25519 or RSA. It loads from
//! PKCS#8, SEC1 or PKCS#1 DER. An RSA key signs only with RSA-PSS.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const der = @import("der.zig");
const pem = @import("pem.zig");
pub const rsa = @import("rsa.zig");

const PrivateKey = @This();

pub const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
pub const EcdsaP384 = crypto.sign.ecdsa.EcdsaP384Sha384;
pub const Ed25519 = crypto.sign.Ed25519;

pub const Kind = enum { ecdsa_p256, ecdsa_p384, ed25519, rsa };

key: union(Kind) {
    ecdsa_p256: EcdsaP256.KeyPair,
    ecdsa_p384: EcdsaP384.KeyPair,
    ed25519: Ed25519.KeyPair,
    rsa: rsa.PrivateKey,
},

pub const ParseError = error{
    /// The DER structure is malformed.
    InvalidEncoding,
    /// The SDK does not support the key algorithm, the curve or the RSA key size.
    UnsupportedKey,
    /// The scalar is out of range or the key pair is inconsistent.
    InvalidKey,
};

const oid_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01";
const oid_secp256r1 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const oid_secp384r1 = "\x2b\x81\x04\x00\x22";
const oid_ed25519 = "\x2b\x65\x70";
const oid_rsa_encryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

/// Parse a PKCS#8 `PrivateKeyInfo`, a SEC1 `ECPrivateKey` or a PKCS#1 `RSAPrivateKey`.
pub fn parseDer(bytes: []const u8) ParseError!PrivateKey {
    const root = der.parseExact(bytes) catch return error.InvalidEncoding;
    if (root.tag != der.tag_sequence) return error.InvalidEncoding;
    var it = root.children();
    const version = (it.require() catch return error.InvalidEncoding).smallInt() catch return error.InvalidEncoding;
    const second = it.require() catch return error.InvalidEncoding;
    if (second.tag == der.tag_sequence) {
        // PKCS#8: version, AlgorithmIdentifier, OCTET STRING privateKey.
        if (version != 0 and version != 1) return error.InvalidEncoding;
        var alg = second.children();
        const oid = alg.require() catch return error.InvalidEncoding;
        const private = (it.require() catch return error.InvalidEncoding).expect(der.tag_octet_string) catch return error.InvalidEncoding;
        if (oid.isOid(oid_ec_public_key)) {
            const curve = alg.require() catch return error.InvalidEncoding;
            return parseEcPrivateKey(private.content, curveFromOid(curve) orelse return error.UnsupportedKey);
        }
        if (oid.isOid(oid_ed25519)) {
            const inner = der.parseExact(private.content) catch return error.InvalidEncoding;
            if (inner.tag != der.tag_octet_string or inner.content.len != Ed25519.KeyPair.seed_length) return error.InvalidEncoding;
            const kp = Ed25519.KeyPair.generateDeterministic(inner.content[0..Ed25519.KeyPair.seed_length].*) catch return error.InvalidKey;
            return .{ .key = .{ .ed25519 = kp } };
        }
        if (oid.isOid(oid_rsa_encryption)) {
            // The parameters are NULL (RFC 8017 appendix A.1). Some encoders leave them out.
            if (alg.next() catch return error.InvalidEncoding) |params| {
                if (params.tag != der.tag_null or params.content.len != 0) return error.InvalidEncoding;
            }
            return .{ .key = .{ .rsa = try rsa.parsePkcs1(private.content) } };
        }
        return error.UnsupportedKey;
    }
    if (second.tag == der.tag_integer) {
        // PKCS#1 RSAPrivateKey: version, modulus, exponents and primes.
        return .{ .key = .{ .rsa = try rsa.parsePkcs1(bytes) } };
    }
    if (second.tag == der.tag_octet_string) {
        // SEC1 ECPrivateKey: version 1, privateKey, [0] parameters, [1] publicKey.
        if (version != 1) return error.InvalidEncoding;
        var curve: ?Kind = null;
        while (it.next() catch return error.InvalidEncoding) |e| {
            if (e.tag == der.tag_context_0) {
                const oid = der.parseExact(e.content) catch return error.InvalidEncoding;
                curve = curveFromOid(oid) orelse return error.UnsupportedKey;
            }
        }
        return scalarToKey(second.content, curve orelse return error.UnsupportedKey);
    }
    return error.InvalidEncoding;
}

fn parseEcPrivateKey(bytes: []const u8, curve: Kind) ParseError!PrivateKey {
    const root = der.parseExact(bytes) catch return error.InvalidEncoding;
    if (root.tag != der.tag_sequence) return error.InvalidEncoding;
    var it = root.children();
    const version = (it.require() catch return error.InvalidEncoding).smallInt() catch return error.InvalidEncoding;
    if (version != 1) return error.InvalidEncoding;
    const scalar = (it.require() catch return error.InvalidEncoding).expect(der.tag_octet_string) catch return error.InvalidEncoding;
    return scalarToKey(scalar.content, curve);
}

fn curveFromOid(elem: der.Element) ?Kind {
    if (elem.isOid(oid_secp256r1)) return .ecdsa_p256;
    if (elem.isOid(oid_secp384r1)) return .ecdsa_p384;
    return null;
}

fn scalarToKey(scalar: []const u8, curve: Kind) ParseError!PrivateKey {
    switch (curve) {
        .ecdsa_p256 => {
            if (scalar.len != EcdsaP256.SecretKey.encoded_length) return error.InvalidKey;
            const sk = EcdsaP256.SecretKey.fromBytes(scalar[0..EcdsaP256.SecretKey.encoded_length].*) catch return error.InvalidKey;
            const kp = EcdsaP256.KeyPair.fromSecretKey(sk) catch return error.InvalidKey;
            return .{ .key = .{ .ecdsa_p256 = kp } };
        },
        .ecdsa_p384 => {
            if (scalar.len != EcdsaP384.SecretKey.encoded_length) return error.InvalidKey;
            const sk = EcdsaP384.SecretKey.fromBytes(scalar[0..EcdsaP384.SecretKey.encoded_length].*) catch return error.InvalidKey;
            const kp = EcdsaP384.KeyPair.fromSecretKey(sk) catch return error.InvalidKey;
            return .{ .key = .{ .ecdsa_p384 = kp } };
        },
        .ed25519, .rsa => unreachable,
    }
}

/// Parse the first `PRIVATE KEY`, `EC PRIVATE KEY` or `RSA PRIVATE KEY` block of a PEM text.
pub fn parsePem(gpa: std.mem.Allocator, text: []const u8) (ParseError || std.mem.Allocator.Error || error{NoKeyFound})!PrivateKey {
    var it: pem.Iterator = .init(text);
    while (it.next()) |block| {
        const known = for ([_][]const u8{ "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY" }) |label| {
            if (std.mem.eql(u8, block.label, label)) break true;
        } else false;
        if (!known) continue;
        const bytes = block.decode(gpa) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidEncoding => return error.InvalidEncoding,
        };
        defer {
            crypto.secureZero(u8, bytes);
            gpa.free(bytes);
        }
        return parseDer(bytes);
    }
    return error.NoKeyFound;
}

pub fn kind(self: *const PrivateKey) Kind {
    return self.key;
}

/// The preferred TLS signature scheme of this key.
pub fn scheme(self: *const PrivateKey) tls.SignatureScheme {
    return self.schemes()[0];
}

/// The TLS signature schemes this key produces, in preference order. An RSA key never
/// produces a PKCS#1 v1.5 signature, because TLS 1.3 forbids it in a CertificateVerify.
pub fn schemes(self: *const PrivateKey) []const tls.SignatureScheme {
    return switch (self.key) {
        .ecdsa_p256 => &.{.ecdsa_secp256r1_sha256},
        .ecdsa_p384 => &.{.ecdsa_secp384r1_sha384},
        .ed25519 => &.{.ed25519},
        .rsa => &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
    };
}

/// The length of the longest public key encoding: an RSA key of 4096 bits.
pub const max_public_key_len = rsa.max_public_key_len;

/// The public key as it appears in a certificate `subjectPublicKey` bit string.
pub fn publicKeyBytes(self: *const PrivateKey, buf: *[max_public_key_len]u8) []const u8 {
    switch (self.key) {
        .ecdsa_p256 => |kp| {
            const p = kp.public_key.toUncompressedSec1();
            @memcpy(buf[0..p.len], &p);
            return buf[0..p.len];
        },
        .ecdsa_p384 => |kp| {
            const p = kp.public_key.toUncompressedSec1();
            @memcpy(buf[0..p.len], &p);
            return buf[0..p.len];
        },
        .ed25519 => |kp| {
            const p = kp.public_key.toBytes();
            @memcpy(buf[0..p.len], &p);
            return buf[0..p.len];
        },
        .rsa => |*k| return k.publicKeyDer(buf),
    }
}

/// The length of the longest signature: an RSA signature with a modulus of 4096 bits.
pub const max_signature_len: usize = @max(2 + 2 * (EcdsaP384.Signature.encoded_length / 2 + 3), rsa.max_modulus_len);

pub const SignError = error{ SigningFailed, EntropyUnavailable };

/// Sign `message` for a TLS CertificateVerify with the preferred scheme. `noise` adds
/// randomness to ECDSA and Ed25519 and gives the RSA-PSS salt.
pub fn sign(self: *const PrivateKey, message: []const u8, noise: [48]u8, out: *[max_signature_len]u8) SignError![]const u8 {
    return self.signScheme(self.scheme(), message, noise, out);
}

/// Sign `message` with `with`, one of `schemes()`. Another scheme gives `error.SigningFailed`.
pub fn signScheme(self: *const PrivateKey, with: tls.SignatureScheme, message: []const u8, noise: [48]u8, out: *[max_signature_len]u8) SignError![]const u8 {
    for (self.schemes()) |s| {
        if (s == with) break;
    } else return error.SigningFailed;
    switch (self.key) {
        .rsa => |*k| {
            // The salt is as long as the hash. SHA-512 of the noise gives enough bytes.
            var salt: [64]u8 = undefined;
            defer crypto.secureZero(u8, &salt);
            crypto.hash.sha2.Sha512.hash(&noise, &salt, .{});
            return switch (with) {
                .rsa_pss_rsae_sha256 => k.signPss(crypto.hash.sha2.Sha256, message, salt[0..32], out),
                .rsa_pss_rsae_sha384 => k.signPss(crypto.hash.sha2.Sha384, message, salt[0..48], out),
                .rsa_pss_rsae_sha512 => k.signPss(crypto.hash.sha2.Sha512, message, &salt, out),
                else => unreachable,
            };
        },
        .ecdsa_p256 => |kp| {
            const sig = kp.sign(message, noise[0..EcdsaP256.noise_length].*) catch return error.SigningFailed;
            var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
            const encoded = sig.toDer(&der_buf);
            @memcpy(out[0..encoded.len], encoded);
            return out[0..encoded.len];
        },
        .ecdsa_p384 => |kp| {
            const sig = kp.sign(message, noise[0..EcdsaP384.noise_length].*) catch return error.SigningFailed;
            var der_buf: [EcdsaP384.Signature.der_encoded_length_max]u8 = undefined;
            const encoded = sig.toDer(&der_buf);
            @memcpy(out[0..encoded.len], encoded);
            return out[0..encoded.len];
        },
        .ed25519 => |kp| {
            const sig = kp.sign(message, noise[0..Ed25519.noise_length].*) catch return error.SigningFailed;
            const bytes = sig.toBytes();
            @memcpy(out[0..bytes.len], &bytes);
            return out[0..bytes.len];
        },
    }
}

pub fn deinit(self: *PrivateKey) void {
    crypto.secureZero(u8, std.mem.asBytes(&self.key));
}

test "parse fixture keys" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { path: []const u8, kind: Kind }{
        .{ .path = "test/fixtures/tls/pem/p256.key", .kind = .ecdsa_p256 },
        .{ .path = "test/fixtures/tls/pem/p256-sec1.key", .kind = .ecdsa_p256 },
        .{ .path = "test/fixtures/tls/pem/p384.key", .kind = .ecdsa_p384 },
        .{ .path = "test/fixtures/tls/pem/ed25519.key", .kind = .ed25519 },
        .{ .path = "test/fixtures/tls/pem/rsa2048.key", .kind = .rsa },
        .{ .path = "test/fixtures/tls/pem/rsa2048-pkcs1.key", .kind = .rsa },
    };
    for (cases) |case| {
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, case.path, gpa, .limited(1 << 16));
        defer gpa.free(text);
        var key = try parsePem(gpa, text);
        defer key.deinit();
        try std.testing.expectEqual(case.kind, key.kind());
        var buf: [max_public_key_len]u8 = undefined;
        const pk = key.publicKeyBytes(&buf);
        try std.testing.expect(pk.len == 65 or pk.len == 97 or pk.len == 32 or pk.len == 270);
        var sig_buf: [max_signature_len]u8 = undefined;
        for (key.schemes()) |s| {
            const sig = try key.signScheme(s, "hello", [_]u8{1} ** 48, &sig_buf);
            try std.testing.expect(sig.len >= 64);
        }
        try std.testing.expectError(error.SigningFailed, key.signScheme(.rsa_pkcs1_sha256, "hello", [_]u8{1} ** 48, &sig_buf));
    }
    try std.testing.expectError(error.NoKeyFound, parsePem(gpa, "nothing here"));
    try std.testing.expectError(error.InvalidEncoding, parseDer("\x30\x00"));
}

test "the PKCS#1 and the PKCS#8 form of an RSA key are the same key" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const pkcs8 = try std.Io.Dir.cwd().readFileAlloc(io, "test/fixtures/tls/pem/rsa2048.key", gpa, .limited(1 << 16));
    defer gpa.free(pkcs8);
    const pkcs1 = try std.Io.Dir.cwd().readFileAlloc(io, "test/fixtures/tls/pem/rsa2048-pkcs1.key", gpa, .limited(1 << 16));
    defer gpa.free(pkcs1);
    var a = try parsePem(gpa, pkcs8);
    defer a.deinit();
    var b = try parsePem(gpa, pkcs1);
    defer b.deinit();
    var buf_a: [max_public_key_len]u8 = undefined;
    var buf_b: [max_public_key_len]u8 = undefined;
    try std.testing.expectEqualSlices(u8, a.publicKeyBytes(&buf_a), b.publicKeyBytes(&buf_b));
    try std.testing.expectEqual(tls.SignatureScheme.rsa_pss_rsae_sha256, a.scheme());
    // An RSA-PSS key (id-RSASSA-PSS) is not supported.
    const pss = try std.Io.Dir.cwd().readFileAlloc(io, "test/fixtures/tls/pem/rsa-pss.key", gpa, .limited(1 << 16));
    defer gpa.free(pss);
    try std.testing.expectError(error.UnsupportedKey, parsePem(gpa, pss));
}
