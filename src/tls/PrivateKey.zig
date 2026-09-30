//! A server private key: ECDSA P-256, ECDSA P-384 or Ed25519, loaded from PKCS#8 or SEC1
//! DER. RSA keys are not supported yet and are rejected.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const der = @import("der.zig");
const pem = @import("pem.zig");

const PrivateKey = @This();

pub const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
pub const EcdsaP384 = crypto.sign.ecdsa.EcdsaP384Sha384;
pub const Ed25519 = crypto.sign.Ed25519;

pub const Kind = enum { ecdsa_p256, ecdsa_p384, ed25519 };

key: union(Kind) {
    ecdsa_p256: EcdsaP256.KeyPair,
    ecdsa_p384: EcdsaP384.KeyPair,
    ed25519: Ed25519.KeyPair,
},

pub const ParseError = error{
    /// The DER structure is malformed.
    InvalidEncoding,
    /// The key algorithm or curve is not supported.
    UnsupportedKey,
    /// The scalar is out of range or the key pair is inconsistent.
    InvalidKey,
};

const oid_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01";
const oid_secp256r1 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const oid_secp384r1 = "\x2b\x81\x04\x00\x22";
const oid_ed25519 = "\x2b\x65\x70";

/// Parse a PKCS#8 `PrivateKeyInfo` or a SEC1 `ECPrivateKey`.
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
        return error.UnsupportedKey;
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
        .ed25519 => unreachable,
    }
}

/// Parse the first `PRIVATE KEY` or `EC PRIVATE KEY` block of a PEM text.
pub fn parsePem(gpa: std.mem.Allocator, text: []const u8) (ParseError || std.mem.Allocator.Error || error{NoKeyFound})!PrivateKey {
    var it: pem.Iterator = .init(text);
    while (it.next()) |block| {
        if (!(std.mem.eql(u8, block.label, "PRIVATE KEY") or std.mem.eql(u8, block.label, "EC PRIVATE KEY"))) continue;
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

/// The TLS signature scheme this key produces.
pub fn scheme(self: *const PrivateKey) tls.SignatureScheme {
    return switch (self.key) {
        .ecdsa_p256 => .ecdsa_secp256r1_sha256,
        .ecdsa_p384 => .ecdsa_secp384r1_sha384,
        .ed25519 => .ed25519,
    };
}

/// The public key as it appears in a certificate `subjectPublicKey` bit string.
pub fn publicKeyBytes(self: *const PrivateKey, buf: *[97]u8) []const u8 {
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
    }
}

pub const max_signature_len = 2 + 2 * (EcdsaP384.Signature.encoded_length / 2 + 3);

pub const SignError = error{ SigningFailed, EntropyUnavailable };

/// Sign `message` for a TLS CertificateVerify. `noise` adds hedging to ECDSA and Ed25519.
pub fn sign(self: *const PrivateKey, message: []const u8, noise: [48]u8, out: *[max_signature_len]u8) SignError![]const u8 {
    switch (self.key) {
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
    };
    for (cases) |case| {
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, case.path, gpa, .limited(1 << 16));
        defer gpa.free(text);
        var key = try parsePem(gpa, text);
        defer key.deinit();
        try std.testing.expectEqual(case.kind, key.kind());
        var buf: [97]u8 = undefined;
        const pk = key.publicKeyBytes(&buf);
        try std.testing.expect(pk.len == 65 or pk.len == 97 or pk.len == 32);
        var sig_buf: [max_signature_len]u8 = undefined;
        const sig = try key.sign("hello", [_]u8{1} ** 48, &sig_buf);
        try std.testing.expect(sig.len >= 64);
    }
    try std.testing.expectError(error.NoKeyFound, parsePem(gpa, "nothing here"));
    try std.testing.expectError(error.InvalidEncoding, parseDer("\x30\x00"));
}
