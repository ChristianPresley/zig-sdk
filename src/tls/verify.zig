//! Certificate chain validation for the TLS client and for client certificates on the
//! server. It has the trust policies, the chain walk with CA constraints, the name
//! constraints, the host name check and the CertificateVerify signature check.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;
const CaSet = @import("CaSet.zig");
const pss = @import("pss.zig");
const der = @import("der.zig");
const name_constraints = @import("name_constraints.zig");
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
    /// The extended key usage of the leaf or of an intermediate does not permit the purpose.
    TlsCertificateWrongPurpose,
    /// A name of a certificate is outside the name constraints of a CA above it.
    TlsCertificateNameNotPermitted,
    /// A critical name constraint has a form that the SDK cannot check, and a certificate
    /// below the CA has a name of that form.
    TlsCertificateUnsupportedConstraint,
};

/// The role of the peer that presents the chain. The extended key usage of the leaf and
/// of each intermediate must permit it, or the certificate has no such extension.
pub const Purpose = enum {
    /// A TLS server: `id-kp-serverAuth`.
    server,
    /// A TLS client: `id-kp-clientAuth`.
    client,
};

pub const ChainOptions = struct {
    /// The role of the peer.
    purpose: Purpose,
    /// The name or IP address to check against the leaf. Null skips the check.
    host: ?[]const u8 = null,
    /// The time for the validity checks, in seconds since the epoch.
    now_sec: i64,
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

/// Verify a chain, leaf first, against the trust policy and the options.
pub fn verifyChain(certs: []const []const u8, trust: Trust, options: ChainOptions) Error!Leaf {
    const now_sec = options.now_sec;
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
    if (options.host) |h| try verifyHost(certs[0], h);
    try requirePurpose(certs[0], options.purpose);
    switch (trust) {
        .self_signed => {
            pss.verifyCertificate(leaf_parsed, leaf_parsed, now_sec) catch |e| return mapVerify(e);
            return leaf;
        },
        .ca_set, .bundle => {
            var current = leaf_parsed;
            var index: usize = 0;
            while (true) {
                if (try issuingAnchor(trust, current, now_sec)) |anchor| {
                    try requireCa(anchor.der, index, .anchor);
                    const path = certs[0 .. index + 1];
                    name_constraints.checkPath(path, anchor.der, options.host) catch |e| return switch (e) {
                        error.NameNotPermitted => error.TlsCertificateNameNotPermitted,
                        error.UnsupportedConstraint => error.TlsCertificateUnsupportedConstraint,
                        error.Malformed => error.TlsCertificateInvalid,
                    };
                    return leaf;
                }
                index += 1;
                if (index >= certs.len) return error.TlsCertificateIssuerNotFound;
                const next = parse(certs[index]) catch return error.TlsCertificateInvalid;
                pss.verifyCertificate(current, next, now_sec) catch |e| return mapVerify(e);
                try requireCa(certs[index], index - 1, .intermediate);
                try requirePurpose(certs[index], options.purpose);
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

/// A trust anchor: the parsed certificate and its exact DER bytes.
const Anchor = struct {
    parsed: Certificate.Parsed,
    der: []const u8,
};

/// The anchor that signs `child`: its subject is the issuer name of `child`, and its key
/// verifies the signature of `child`. A CA set can have two anchors with one name, for
/// example a root with a new key. Thus the function tries each of them. Null
/// when no anchor has the name. When anchors have the name but none verifies `child`,
/// the function returns the error of the first one.
fn issuingAnchor(trust: Trust, child: Certificate.Parsed, now_sec: i64) Error!?Anchor {
    switch (trust) {
        .ca_set => |set| {
            var first_error: ?Error = null;
            for (set.certs.items) |bytes| {
                const cert: Certificate = .{ .buffer = bytes, .index = 0 };
                const parsed = pss.parseCertificate(cert) catch continue;
                if (!std.mem.eql(u8, parsed.subject(), child.issuer())) continue;
                pss.verifyCertificate(child, parsed, now_sec) catch |e| {
                    if (first_error == null) first_error = mapVerify(e);
                    continue;
                };
                return .{ .parsed = parsed, .der = bytes };
            }
            if (first_error) |e| return e;
            return null;
        },
        .bundle => |bundle| {
            const index = bundle.find(child.issuer()) orelse return null;
            const cert: Certificate = .{ .buffer = bundle.bytes.items, .index = index };
            const parsed = pss.parseCertificate(cert) catch return null;
            const element = der.parse(bundle.bytes.items[index..]) catch return null;
            pss.verifyCertificate(child, parsed, now_sec) catch |e| return mapVerify(e);
            return .{ .parsed = parsed, .der = element.raw };
        },
        else => return null,
    }
}

const IssuerRole = enum { intermediate, anchor };

/// An issuer must be a certificate authority. `below` counts the intermediates it signs,
/// directly or indirectly, for the path length constraint. An intermediate must have
/// basic constraints with `cA` set (RFC 5280 section 6.1.4). An anchor without basic
/// constraints is good, because old version 1 roots have no extensions.
fn requireCa(cert: []const u8, below: usize, role: IssuerRole) Error!void {
    const bc = x509.basicConstraints(cert) catch return error.TlsCertificateInvalid;
    if (bc) |constraints| {
        if (!constraints.ca) return error.TlsCertificateNotCa;
        if (constraints.path_len) |limit| if (below > limit) return error.TlsCertificateNotCa;
    } else if (role == .intermediate) return error.TlsCertificateNotCa;
    const ku = x509.keyUsage(cert) catch return error.TlsCertificateInvalid;
    if (ku) |usage| if (!usage.key_cert_sign) return error.TlsCertificateNotCa;
}

/// When the certificate has an extended key usage, it must permit the purpose or every
/// purpose. The function checks the leaf and the intermediates, but not the anchor.
fn requirePurpose(cert: []const u8, purpose: Purpose) Error!void {
    const eku = (x509.extendedKeyUsage(cert) catch return error.TlsCertificateInvalid) orelse return;
    if (eku.any) return;
    const permitted = switch (purpose) {
        .server => eku.server_auth,
        .client => eku.client_auth,
    };
    if (!permitted) return error.TlsCertificateWrongPurpose;
}

/// Check the host against the subject alternative name of the leaf: an IP address against
/// an `iPAddress` entry, a DNS name against a `dNSName` entry. The common name of the
/// subject never counts. A name constraint of a CA does not cover the common name, so it
/// cannot limit that name.
fn verifyHost(cert: []const u8, host: []const u8) Error!void {
    if (std.Io.net.IpAddress.parse(host, 0)) |address| {
        const bytes: []const u8 = switch (address) {
            .ip4 => |a| &a.bytes,
            .ip6 => |a| &a.bytes,
        };
        const found = x509.hasIpAddress(cert, bytes) catch return error.TlsCertificateInvalid;
        if (!found) return error.TlsCertificateHostMismatch;
        return;
    } else |_| {}
    const found = x509.hasDnsName(cert, host) catch return error.TlsCertificateInvalid;
    if (!found) return error.TlsCertificateHostMismatch;
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

/// The test time: 2027-01-15, inside the validity of the fixtures.
const test_now: i64 = 1_800_000_000;

fn serverChain(certs: []const []const u8, host: ?[]const u8, trust: Trust, now: i64) Error!Leaf {
    return verifyChain(certs, trust, .{ .purpose = .server, .host = host, .now_sec = now });
}

fn clientChain(certs: []const []const u8, trust: Trust) Error!Leaf {
    return verifyChain(certs, trust, .{ .purpose = .client, .now_sec = test_now });
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

    _ = try serverChain(&.{leaf}, "localhost", .{ .ca_set = &set }, now);
    _ = try serverChain(&.{ leaf, ca }, "127.0.0.1", .{ .ca_set = &set }, now);
    try std.testing.expectError(error.TlsCertificateHostMismatch, serverChain(&.{leaf}, "example.com", .{ .ca_set = &set }, now));
    try std.testing.expectError(error.TlsCertificateHostMismatch, serverChain(&.{leaf}, "10.0.0.1", .{ .ca_set = &set }, now));
    try std.testing.expectError(error.TlsCertificateExpired, serverChain(&.{leaf}, "localhost", .{ .ca_set = &set }, now + 400 * 365 * 86400));
    try std.testing.expectError(error.TlsCertificateNotYetValid, serverChain(&.{leaf}, "localhost", .{ .ca_set = &set }, 0));
    // The self-signed leaf is not signed by the CA.
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, serverChain(&.{self_signed}, "localhost", .{ .ca_set = &set }, now));
    _ = try serverChain(&.{self_signed}, "localhost", .self_signed, now);
    try std.testing.expectError(error.TlsCertificateNotVerified, serverChain(&.{leaf}, "localhost", .self_signed, now));
    _ = try serverChain(&.{leaf}, null, .{ .pinned_leaf = leaf }, now);
    try std.testing.expectError(error.TlsCertificateNotVerified, serverChain(&.{leaf}, null, .{ .pinned_leaf = ca }, now));
    // A certificate signed by a leaf that is not a CA does not verify.
    const bad = try loadDer(gpa, "test/fixtures/tls/pem/bad-chain-leaf.crt");
    defer gpa.free(bad);
    try std.testing.expectError(error.TlsCertificateNotCa, serverChain(&.{ bad, leaf, ca }, "localhost", .{ .ca_set = &set }, now));
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
    const ca_leaf = try serverChain(&.{pss_ca}, "localhost", .self_signed, now);
    try std.testing.expect(ca_leaf.pss == null);
    _ = try serverChain(&.{pss_ca}, "localhost", .{ .ca_set = &set }, now);
    const leaf = try serverChain(&.{pss_leaf}, "localhost", .{ .ca_set = &set }, now);
    try std.testing.expectEqual(pss.Params{ .hash = .sha256, .salt_len = 32 }, leaf.pss.?);
    _ = try serverChain(&.{ pss_leaf, pss_ca }, "127.0.0.1", .{ .ca_set = &set }, now);
    try std.testing.expectError(error.TlsCertificateNotVerified, serverChain(&.{pss_leaf}, "localhost", .self_signed, now));
    // A changed signature on the leaf.
    const tampered = try gpa.dupe(u8, pss_leaf);
    defer gpa.free(tampered);
    tampered[tampered.len - 3] ^= 0x10;
    try std.testing.expectError(error.TlsCertificateNotVerified, serverChain(&.{tampered}, "localhost", .{ .ca_set = &set }, now));

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
    const rsa = try serverChain(&.{rsa_leaf}, "localhost", .self_signed, now);
    try std.testing.expectError(error.TlsBadSignatureScheme, verifySignature(&rsa, .rsa_pss_pss_sha256, sig, message));
}

test "the host name check ignores the common name" {
    const gpa = std.testing.allocator;
    // The CA signs this leaf. Its common name is "localhost" and it has no subject
    // alternative name.
    const cn_only = try loadDer(gpa, "test/fixtures/tls/pem/cn-only.crt");
    defer gpa.free(cn_only);
    const ca = try loadDer(gpa, "test/fixtures/tls/pem/ca.crt");
    defer gpa.free(ca);
    var set: CaSet = .init(gpa);
    defer set.deinit();
    try set.addDer(ca);
    const now: i64 = 1_800_000_000;
    try std.testing.expectError(error.TlsCertificateHostMismatch, serverChain(&.{cn_only}, "localhost", .{ .ca_set = &set }, now));
    // Without a host the chain itself is good.
    _ = try serverChain(&.{cn_only}, null, .{ .ca_set = &set }, now);
}

test "the extended key usage of the leaf and the intermediates must permit the purpose" {
    const gpa = std.testing.allocator;
    const ca = try loadDer(gpa, "test/fixtures/tls/pem/ca.crt");
    defer gpa.free(ca);
    var set: CaSet = .init(gpa);
    defer set.deinit();
    try set.addDer(ca);
    const trust: Trust = .{ .ca_set = &set };

    // serverAuth only: good for a server, not for a client.
    const server_leaf = try loadDer(gpa, "test/fixtures/tls/pem/chain-leaf.crt");
    defer gpa.free(server_leaf);
    _ = try serverChain(&.{server_leaf}, "localhost", trust, test_now);
    try std.testing.expectError(error.TlsCertificateWrongPurpose, clientChain(&.{server_leaf}, trust));
    // clientAuth only: the reverse.
    const client_leaf = try loadDer(gpa, "test/fixtures/tls/pem/client-leaf.crt");
    defer gpa.free(client_leaf);
    _ = try clientChain(&.{client_leaf}, trust);
    try std.testing.expectError(error.TlsCertificateWrongPurpose, serverChain(&.{client_leaf}, "localhost", trust, test_now));
    // anyExtendedKeyUsage permits both.
    const any_leaf = try loadDer(gpa, "test/fixtures/tls/pem/any-eku-leaf.crt");
    defer gpa.free(any_leaf);
    _ = try serverChain(&.{any_leaf}, "localhost", trust, test_now);
    _ = try clientChain(&.{any_leaf}, trust);
    // Without the extension, every purpose is good.
    const no_eku = try loadDer(gpa, "test/fixtures/tls/pem/p256.crt");
    defer gpa.free(no_eku);
    _ = try clientChain(&.{no_eku}, .self_signed);
    _ = try serverChain(&.{no_eku}, "localhost", .self_signed, test_now);
    // The leaf permits both, but the intermediate permits clientAuth only.
    const eku_ca = try loadDer(gpa, "test/fixtures/tls/pem/eku-ca.crt");
    defer gpa.free(eku_ca);
    const eku_leaf = try loadDer(gpa, "test/fixtures/tls/pem/eku-leaf.crt");
    defer gpa.free(eku_leaf);
    _ = try clientChain(&.{ eku_leaf, eku_ca }, trust);
    try std.testing.expectError(error.TlsCertificateWrongPurpose, serverChain(&.{ eku_leaf, eku_ca }, "localhost", trust, test_now));
    // The self-signed policy checks the leaf as well.
    try std.testing.expectError(error.TlsCertificateWrongPurpose, verifyChain(&.{client_leaf}, .self_signed, .{ .purpose = .server, .now_sec = test_now }));
}

test "an intermediate needs basic constraints with cA, an anchor can lack them" {
    const gpa = std.testing.allocator;
    const ca = try loadDer(gpa, "test/fixtures/tls/pem/ca.crt");
    defer gpa.free(ca);
    // no-bc-ca.crt has neither basic constraints nor key usage.
    const no_bc_ca = try loadDer(gpa, "test/fixtures/tls/pem/no-bc-ca.crt");
    defer gpa.free(no_bc_ca);
    const no_bc_leaf = try loadDer(gpa, "test/fixtures/tls/pem/no-bc-leaf.crt");
    defer gpa.free(no_bc_leaf);
    var set: CaSet = .init(gpa);
    defer set.deinit();
    try set.addDer(ca);
    try std.testing.expectError(error.TlsCertificateNotCa, serverChain(&.{ no_bc_leaf, no_bc_ca }, "localhost", .{ .ca_set = &set }, test_now));

    // As a trust anchor, the same certificate is good.
    var anchors: CaSet = .init(gpa);
    defer anchors.deinit();
    try anchors.addDer(no_bc_ca);
    _ = try serverChain(&.{no_bc_leaf}, "localhost", .{ .ca_set = &anchors }, test_now);

    // An anchor with basic constraints and cA not set is not a CA.
    const leaf = try loadDer(gpa, "test/fixtures/tls/pem/chain-leaf.crt");
    defer gpa.free(leaf);
    const bad = try loadDer(gpa, "test/fixtures/tls/pem/bad-chain-leaf.crt");
    defer gpa.free(bad);
    var leaf_anchor: CaSet = .init(gpa);
    defer leaf_anchor.deinit();
    try leaf_anchor.addDer(leaf);
    try std.testing.expectError(error.TlsCertificateNotCa, serverChain(&.{bad}, "localhost", .{ .ca_set = &leaf_anchor }, test_now));
}

test "every anchor with the issuer name gets a try" {
    const gpa = std.testing.allocator;
    const leaf = try loadDer(gpa, "test/fixtures/tls/pem/chain-leaf.crt");
    defer gpa.free(leaf);
    const ca = try loadDer(gpa, "test/fixtures/tls/pem/ca.crt");
    defer gpa.free(ca);
    // The same name as ca.crt and a different key.
    const rekeyed = try loadDer(gpa, "test/fixtures/tls/pem/ca-rekeyed.crt");
    defer gpa.free(rekeyed);
    var set: CaSet = .init(gpa);
    defer set.deinit();
    try set.addDer(rekeyed);
    try std.testing.expectError(error.TlsCertificateNotVerified, serverChain(&.{leaf}, "localhost", .{ .ca_set = &set }, test_now));
    try set.addDer(ca);
    _ = try serverChain(&.{leaf}, "localhost", .{ .ca_set = &set }, test_now);
    // The time error of the leaf comes first when no anchor verifies it.
    try std.testing.expectError(error.TlsCertificateExpired, serverChain(&.{leaf}, "localhost", .{ .ca_set = &set }, test_now + 400 * 365 * 86400));
}

/// Load each named fixture of `pem/` into `out` and return the filled part.
fn loadFixtures(gpa: std.mem.Allocator, names: []const []const u8, out: [][]u8) ![][]u8 {
    for (names, 0..) |name, i| {
        var path_buf: [96]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "test/fixtures/tls/pem/{s}.crt", .{name});
        out[i] = try loadDer(gpa, path);
    }
    return out[0..names.len];
}

fn freeFixtures(gpa: std.mem.Allocator, certs: [][]u8) void {
    for (certs) |c| gpa.free(c);
}

/// Verify the named chain against the named anchor for `host`.
fn checkFixtureChain(names: []const []const u8, anchor_name: []const u8, host: ?[]const u8) Error!void {
    const gpa = std.testing.allocator;
    var buf: [max_certs][]u8 = undefined;
    const certs = loadFixtures(gpa, names, &buf) catch return error.TlsCertificateInvalid;
    defer freeFixtures(gpa, certs);
    var anchor_buf: [1][]u8 = undefined;
    const anchor = loadFixtures(gpa, &.{anchor_name}, &anchor_buf) catch return error.TlsCertificateInvalid;
    defer freeFixtures(gpa, anchor);
    var set: CaSet = .init(gpa);
    defer set.deinit();
    set.addDer(anchor[0]) catch return error.TlsCertificateInvalid;
    var list: [max_certs][]const u8 = undefined;
    for (certs, 0..) |c, i| list[i] = c;
    _ = try serverChain(list[0..certs.len], host, .{ .ca_set = &set }, test_now);
}

test "name constraints of an intermediate limit each name form" {
    // nc-ok.crt has a permitted name of each form.
    for ([_][]const u8{ "www.example.com", "example.com", "api.example.org", "10.2.3.4", "127.0.0.1", "fd00::1" }) |host| {
        try checkFixtureChain(&.{ "nc-ok", "nc-ca" }, "nc-root", host);
    }
    const refused = [_]struct { leaf: []const u8, host: []const u8 }{
        .{ .leaf = "nc-excluded", .host = "127.0.0.1" }, // the dNSName bad.example.com is excluded
        .{ .leaf = "nc-outside", .host = "www.example.net" },
        .{ .leaf = "nc-apex", .host = "example.org" }, // .example.org permits only subdomains
        .{ .leaf = "nc-ip-excluded", .host = "www.example.com" },
        .{ .leaf = "nc-ip-outside", .host = "www.example.com" },
        .{ .leaf = "nc-dn-outside", .host = "www.example.com" },
        .{ .leaf = "nc-email-outside", .host = "www.example.com" },
        .{ .leaf = "nc-uri-outside", .host = "www.example.com" },
    };
    for (refused) |case| {
        try std.testing.expectError(error.TlsCertificateNameNotPermitted, checkFixtureChain(&.{ case.leaf, "nc-ca" }, "nc-root", case.host));
    }
    // The checks also apply without a host, for example to a client certificate.
    try std.testing.expectError(error.TlsCertificateNameNotPermitted, checkFixtureChain(&.{ "nc-outside", "nc-ca" }, "nc-root", null));
}

test "name constraints of two CAs intersect and an anchor can have them too" {
    // nc-sub-ca.crt permits only www.example.com, below nc-ca.crt.
    try checkFixtureChain(&.{ "nc-sub-ok", "nc-sub-ca", "nc-ca" }, "nc-root", "www.example.com");
    try std.testing.expectError(error.TlsCertificateNameNotPermitted, checkFixtureChain(&.{ "nc-sub-outside", "nc-sub-ca", "nc-ca" }, "nc-root", "api.example.com"));
    // The constrained CA as the trust anchor.
    try checkFixtureChain(&.{"nc-ok"}, "nc-ca", "www.example.com");
    try std.testing.expectError(error.TlsCertificateNameNotPermitted, checkFixtureChain(&.{"nc-excluded"}, "nc-ca", "127.0.0.1"));
}

test "a self-issued intermediate gets no name check, a critical unknown form fails" {
    // The subject of nc-self-ca.crt is outside the permitted directory name, but it is
    // self-issued and not the leaf.
    try checkFixtureChain(&.{ "nc-self-leaf", "nc-self-ca", "nc-ca" }, "nc-root", "www.example.com");
    // nc-rid-ca.crt constrains registered IDs and the leaf has one.
    try std.testing.expectError(error.TlsCertificateUnsupportedConstraint, checkFixtureChain(&.{ "nc-rid-leaf", "nc-rid-ca" }, "nc-root", "www.example.com"));
}
