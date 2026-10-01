//! Certificate chain validation for the TLS client and for client certificates on the
//! server. It has the trust policies, the chain walk with CA constraints, the host name
//! check and the CertificateVerify signature check.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;
const CaSet = @import("CaSet.zig");
const pss = @import("pss.zig");
const x509 = @import("x509.zig");

/// How the SDK verifies the peer certificate.
pub const Trust = union(enum) {
    /// No verification. Only for tests: anyone can present any certificate.
    no_verification,
    /// The leaf must be self-signed and valid. This proves nothing about who holds it.
    self_signed,
    /// The leaf must equal these DER bytes.
    pinned_leaf: []const u8,
    /// The chain must lead to one of these anchors.
    ca_set: *const CaSet,
    /// The chain must lead to an anchor of this std bundle, for example the system roots.
    bundle: *const Certificate.Bundle,
};

pub const Error = error{
    /// A certificate does not parse.
    TlsCertificateInvalid,
    /// A signature in the chain is wrong, or the chain does not lead to a trusted anchor.
    TlsCertificateNotVerified,
    TlsCertificateHostMismatch,
    TlsCertificateExpired,
    TlsCertificateNotYetValid,
    /// No anchor signs the last certificate of the chain.
    TlsCertificateIssuerNotFound,
    /// An issuer in the chain is not a certificate authority.
    TlsCertificateNotCa,
};

pub const max_certs = 8;
pub const max_pub_key_len = 600;

/// The public key of the leaf, kept for the CertificateVerify check.
pub const Leaf = struct {
    algo: Certificate.Parsed.PubKeyAlgo,
    pub_key_buf: [max_pub_key_len]u8,
    pub_key_len: u16,
    /// The parameters of an id-RSASSA-PSS key. Null for other keys and for a key without
    /// parameters.
    pss: ?pss.Params = null,

    pub fn pubKey(self: *const Leaf) []const u8 {
        return self.pub_key_buf[0..self.pub_key_len];
    }
};

/// Verify a chain, leaf first, against the trust policy. When `host` is not null, the function
/// checks it against the leaf. The validity times use `now_sec`.
pub fn verifyChain(certs: []const []const u8, host: ?[]const u8, trust: Trust, now_sec: i64) Error!Leaf {
    if (certs.len == 0 or certs.len > max_certs) return error.TlsCertificateInvalid;
    const leaf_parsed = parse(certs[0]) catch return error.TlsCertificateInvalid;
    if (leaf_parsed.pubKey().len > max_pub_key_len) return error.TlsCertificateInvalid;
    var leaf: Leaf = .{ .algo = leaf_parsed.pub_key_algo, .pub_key_buf = undefined, .pub_key_len = @intCast(leaf_parsed.pubKey().len) };
    @memcpy(leaf.pub_key_buf[0..leaf.pub_key_len], leaf_parsed.pubKey());
    if (leaf.algo == .rsassa_pss) leaf.pss = pss.publicKeyParams(certs[0]) catch return error.TlsCertificateInvalid;

    switch (trust) {
        .no_verification => return leaf,
        .pinned_leaf => |pin| {
            if (!std.mem.eql(u8, pin, certs[0])) return error.TlsCertificateNotVerified;
            return leaf;
        },
        else => {},
    }
    if (host) |h| try verifyHost(certs[0], leaf_parsed, h);
    switch (trust) {
        .self_signed => {
            pss.verifyCertificate(leaf_parsed, leaf_parsed, now_sec) catch |e| return mapVerify(e);
            return leaf;
        },
        .ca_set, .bundle => {
            var current = leaf_parsed;
            var index: usize = 0;
            while (true) {
                if (findAnchor(trust, current.issuer())) |anchor| {
                    pss.verifyCertificate(current, anchor, now_sec) catch |e| return mapVerify(e);
                    try requireCa(anchor.certificate.buffer[anchor.certificate.index..], index);
                    return leaf;
                }
                index += 1;
                if (index >= certs.len) return error.TlsCertificateIssuerNotFound;
                const next = parse(certs[index]) catch return error.TlsCertificateInvalid;
                pss.verifyCertificate(current, next, now_sec) catch |e| return mapVerify(e);
                try requireCa(certs[index], index - 1);
                current = next;
            }
        },
        .no_verification, .pinned_leaf => unreachable,
    }
}

fn parse(bytes: []const u8) !Certificate.Parsed {
    // The std parser reads without bounds checks. The precheck in `pss.parseCertificate`
    // refuses what would crash it. That function also parses RSASSA-PSS signatures.
    return pss.parseCertificate(.{ .buffer = bytes, .index = 0 });
}

fn findAnchor(trust: Trust, issuer_name: []const u8) ?Certificate.Parsed {
    switch (trust) {
        .ca_set => |set| return set.findIssuer(issuer_name),
        .bundle => |bundle| {
            const index = bundle.find(issuer_name) orelse return null;
            const cert: Certificate = .{ .buffer = bundle.bytes.items, .index = index };
            return cert.parse() catch null;
        },
        else => return null,
    }
}

/// An issuer must be a certificate authority. `below` counts the intermediates it signs,
/// directly or indirectly, for the path length constraint.
fn requireCa(cert: []const u8, below: usize) Error!void {
    const bc = x509.basicConstraints(cert) catch return error.TlsCertificateInvalid;
    if (bc) |constraints| {
        if (!constraints.ca) return error.TlsCertificateNotCa;
        if (constraints.path_len) |limit| if (below > limit) return error.TlsCertificateNotCa;
    }
    const ku = x509.keyUsage(cert) catch return error.TlsCertificateInvalid;
    if (ku) |usage| if (!usage.key_cert_sign) return error.TlsCertificateNotCa;
}

fn verifyHost(cert: []const u8, parsed: Certificate.Parsed, host: []const u8) Error!void {
    if (std.Io.net.IpAddress.parse(host, 0)) |address| {
        const bytes: []const u8 = switch (address) {
            .ip4 => |a| &a.bytes,
            .ip6 => |a| &a.bytes,
        };
        const found = x509.hasIpAddress(cert, bytes) catch return error.TlsCertificateInvalid;
        if (!found) return error.TlsCertificateHostMismatch;
        return;
    } else |_| {}
    parsed.verifyHostName(host) catch |e| switch (e) {
        error.CertificateHostMismatch => return error.TlsCertificateHostMismatch,
        error.CertificateFieldHasInvalidLength => return error.TlsCertificateInvalid,
    };
}

fn mapVerify(e: Certificate.Parsed.VerifyError) Error {
    return switch (e) {
        error.CertificateExpired => error.TlsCertificateExpired,
        error.CertificateNotYetValid => error.TlsCertificateNotYetValid,
        else => error.TlsCertificateNotVerified,
    };
}

// -- CertificateVerify -------------------------------------------------------------------------

pub const SignatureError = error{ TlsBadSignatureScheme, TlsDecryptError };

/// Check a TLS 1.3 CertificateVerify signature with the leaf key.
pub fn verifySignature(leaf: *const Leaf, scheme: tls.SignatureScheme, signature: []const u8, message: []const u8) SignatureError!void {
    const pub_key = leaf.pubKey();
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            if (leaf.algo != .X9_62_id_ecPublicKey or leaf.algo.X9_62_id_ecPublicKey != .X9_62_prime256v1) return error.TlsBadSignatureScheme;
            verifyEcdsa(crypto.sign.ecdsa.EcdsaP256Sha256, pub_key, signature, message) catch return error.TlsDecryptError;
        },
        .ecdsa_secp384r1_sha384 => {
            if (leaf.algo != .X9_62_id_ecPublicKey or leaf.algo.X9_62_id_ecPublicKey != .secp384r1) return error.TlsBadSignatureScheme;
            verifyEcdsa(crypto.sign.ecdsa.EcdsaP384Sha384, pub_key, signature, message) catch return error.TlsDecryptError;
        },
        .ed25519 => {
            if (leaf.algo != .curveEd25519) return error.TlsBadSignatureScheme;
            const Ed25519 = crypto.sign.Ed25519;
            if (signature.len != Ed25519.Signature.encoded_length or pub_key.len != Ed25519.PublicKey.encoded_length) return error.TlsDecryptError;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            const key = Ed25519.PublicKey.fromBytes(pub_key[0..Ed25519.PublicKey.encoded_length].*) catch return error.TlsDecryptError;
            sig.verify(message, key) catch return error.TlsDecryptError;
        },
        inline .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => |s| {
            if (leaf.algo != .rsaEncryption) return error.TlsBadSignatureScheme;
            verifyRsaPss(s, pub_key, signature, message) catch return error.TlsDecryptError;
        },
        inline .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 => |s| {
            if (leaf.algo != .rsassa_pss) return error.TlsBadSignatureScheme;
            // Key parameters permit one hash, with a salt as long as the hash.
            if (leaf.pss) |params| if (!params.permits(s)) return error.TlsBadSignatureScheme;
            verifyRsaPss(s, pub_key, signature, message) catch return error.TlsDecryptError;
        },
        // PKCS#1 v1.5 is not allowed in a TLS 1.3 CertificateVerify.
        else => return error.TlsBadSignatureScheme,
    }
}

fn verifyEcdsa(comptime Ecdsa: type, pub_key: []const u8, signature: []const u8, message: []const u8) !void {
    const sig = try Ecdsa.Signature.fromDer(signature);
    const key = try Ecdsa.PublicKey.fromSec1(pub_key);
    try sig.verify(message, key);
}

fn verifyRsaPss(comptime scheme: tls.SignatureScheme, pub_key: []const u8, signature: []const u8, message: []const u8) !void {
    const Hash = switch (scheme) {
        .rsa_pss_rsae_sha256, .rsa_pss_pss_sha256 => crypto.hash.sha2.Sha256,
        .rsa_pss_rsae_sha384, .rsa_pss_pss_sha384 => crypto.hash.sha2.Sha384,
        .rsa_pss_rsae_sha512, .rsa_pss_pss_sha512 => crypto.hash.sha2.Sha512,
        else => unreachable,
    };
    const PublicKey = Certificate.rsa.PublicKey;
    const components = try PublicKey.parseDer(pub_key);
    switch (components.modulus.len) {
        inline 256, 384, 512 => |modulus_len| {
            if (signature.len != modulus_len) return error.InvalidSignatureLength;
            const key: PublicKey = try .fromBytes(components.exponent, components.modulus);
            const sig = Certificate.rsa.PSSSignature.fromBytes(modulus_len, signature);
            try Certificate.rsa.PSSSignature.concatVerify(modulus_len, sig, &.{message}, key, Hash);
        },
        else => return error.UnsupportedModulus,
    }
}

// -- Tests -----------------------------------------------------------------------------------

fn loadDer(gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const pem = @import("pem.zig");
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 16));
    defer gpa.free(text);
    var it: pem.Iterator = .init(text);
    return it.nextLabeled("CERTIFICATE").?.decode(gpa);
}

test "chain validation against the fixture CA" {
    const gpa = std.testing.allocator;
    const leaf = try loadDer(gpa, "test/fixtures/tls/pem/chain-leaf.crt");
    defer gpa.free(leaf);
    const ca = try loadDer(gpa, "test/fixtures/tls/pem/ca.crt");
    defer gpa.free(ca);
    const self_signed = try loadDer(gpa, "test/fixtures/tls/pem/p256.crt");
    defer gpa.free(self_signed);
    var set: CaSet = .init(gpa);
    defer set.deinit();
    try set.addDer(ca);
    const now: i64 = 1_800_000_000; // 2027-01-15, inside the validity of the fixtures

    _ = try verifyChain(&.{leaf}, "localhost", .{ .ca_set = &set }, now);
    _ = try verifyChain(&.{ leaf, ca }, "127.0.0.1", .{ .ca_set = &set }, now);
    try std.testing.expectError(error.TlsCertificateHostMismatch, verifyChain(&.{leaf}, "example.com", .{ .ca_set = &set }, now));
    try std.testing.expectError(error.TlsCertificateHostMismatch, verifyChain(&.{leaf}, "10.0.0.1", .{ .ca_set = &set }, now));
    try std.testing.expectError(error.TlsCertificateExpired, verifyChain(&.{leaf}, "localhost", .{ .ca_set = &set }, now + 400 * 365 * 86400));
    try std.testing.expectError(error.TlsCertificateNotYetValid, verifyChain(&.{leaf}, "localhost", .{ .ca_set = &set }, 0));
    // The self-signed leaf is not signed by the CA.
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, verifyChain(&.{self_signed}, "localhost", .{ .ca_set = &set }, now));
    _ = try verifyChain(&.{self_signed}, "localhost", .self_signed, now);
    try std.testing.expectError(error.TlsCertificateNotVerified, verifyChain(&.{leaf}, "localhost", .self_signed, now));
    _ = try verifyChain(&.{leaf}, null, .{ .pinned_leaf = leaf }, now);
    try std.testing.expectError(error.TlsCertificateNotVerified, verifyChain(&.{leaf}, null, .{ .pinned_leaf = ca }, now));
    // A certificate signed by a leaf that is not a CA does not verify.
    const bad = try loadDer(gpa, "test/fixtures/tls/pem/bad-chain-leaf.crt");
    defer gpa.free(bad);
    try std.testing.expectError(error.TlsCertificateNotCa, verifyChain(&.{ bad, leaf, ca }, "localhost", .{ .ca_set = &set }, now));
}

test "chains and CertificateVerify signatures with RSA-PSS keys" {
    const gpa = std.testing.allocator;
    const PrivateKey = @import("PrivateKey.zig");
    const pss_ca = try loadDer(gpa, "test/fixtures/tls/pem/rsa-pss.crt");
    defer gpa.free(pss_ca);
    const pss_leaf = try loadDer(gpa, "test/fixtures/tls/pem/rsa-pss-sha256.crt");
    defer gpa.free(pss_leaf);
    const rsa_leaf = try loadDer(gpa, "test/fixtures/tls/pem/rsa2048.crt");
    defer gpa.free(rsa_leaf);
    var set: CaSet = .init(gpa);
    defer set.deinit();
    try set.addDer(pss_ca);
    const now: i64 = 1_800_000_000;

    // RSASSA-PSS signatures in the chain: SHA-256 on the self-signed CA, SHA-384 on the leaf.
    const ca_leaf = try verifyChain(&.{pss_ca}, "localhost", .self_signed, now);
    try std.testing.expect(ca_leaf.pss == null);
    _ = try verifyChain(&.{pss_ca}, "localhost", .{ .ca_set = &set }, now);
    const leaf = try verifyChain(&.{pss_leaf}, "localhost", .{ .ca_set = &set }, now);
    try std.testing.expectEqual(pss.Params{ .hash = .sha256, .salt_len = 32 }, leaf.pss.?);
    _ = try verifyChain(&.{ pss_leaf, pss_ca }, "127.0.0.1", .{ .ca_set = &set }, now);
    try std.testing.expectError(error.TlsCertificateNotVerified, verifyChain(&.{pss_leaf}, "localhost", .self_signed, now));
    // A changed signature on the leaf.
    const tampered = try gpa.dupe(u8, pss_leaf);
    defer gpa.free(tampered);
    tampered[tampered.len - 3] ^= 0x10;
    try std.testing.expectError(error.TlsCertificateNotVerified, verifyChain(&.{tampered}, "localhost", .{ .ca_set = &set }, now));

    // CertificateVerify: the restricted leaf key accepts rsa_pss_pss_sha256 only.
    const key_text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "test/fixtures/tls/pem/rsa-pss-sha256.key", gpa, .limited(1 << 16));
    defer gpa.free(key_text);
    var key = try PrivateKey.parsePem(gpa, key_text);
    defer key.deinit();
    var sig_buf: [PrivateKey.max_signature_len]u8 = undefined;
    const message = "transcript hash";
    const sig = try key.signScheme(.rsa_pss_pss_sha256, message, [_]u8{3} ** 48, &sig_buf);
    try verifySignature(&leaf, .rsa_pss_pss_sha256, sig, message);
    try std.testing.expectError(error.TlsDecryptError, verifySignature(&leaf, .rsa_pss_pss_sha256, sig, "another hash"));
    try std.testing.expectError(error.TlsBadSignatureScheme, verifySignature(&leaf, .rsa_pss_pss_sha384, sig, message));
    try std.testing.expectError(error.TlsBadSignatureScheme, verifySignature(&leaf, .rsa_pss_rsae_sha256, sig, message));
    try std.testing.expectError(error.TlsBadSignatureScheme, verifySignature(&leaf, .rsa_pkcs1_sha256, sig, message));

    // The CA key has no parameters: each rsa_pss_pss scheme, and no rsa_pss_rsae scheme.
    const ca_key_text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "test/fixtures/tls/pem/rsa-pss.key", gpa, .limited(1 << 16));
    defer gpa.free(ca_key_text);
    var ca_key = try PrivateKey.parsePem(gpa, ca_key_text);
    defer ca_key.deinit();
    for ([_]tls.SignatureScheme{ .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 }) |s| {
        const ca_sig = try ca_key.signScheme(s, message, [_]u8{4} ** 48, &sig_buf);
        try verifySignature(&ca_leaf, s, ca_sig, message);
    }
    try std.testing.expectError(error.TlsBadSignatureScheme, verifySignature(&ca_leaf, .rsa_pss_rsae_sha256, sig, message));
    // An rsaEncryption key does not accept the rsa_pss_pss schemes.
    const rsa = try verifyChain(&.{rsa_leaf}, "localhost", .self_signed, now);
    try std.testing.expectError(error.TlsBadSignatureScheme, verifySignature(&rsa, .rsa_pss_pss_sha256, sig, message));
}
