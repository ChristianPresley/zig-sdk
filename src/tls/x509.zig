//! The X.509 extensions that chain validation needs and `std.crypto.Certificate` does not
//! expose: basic constraints, key usage and the subject alternative name (RFC 5280
//! section 4.2.1).
const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = @import("der.zig");

const oid_basic_constraints = "\x55\x1d\x13";
const oid_key_usage = "\x55\x1d\x0f";
const oid_subject_alt_name = "\x55\x1d\x11";
pub const oid_name_constraints = "\x55\x1d\x1e";
const oid_ext_key_usage = "\x55\x1d\x25";
const oid_any_ext_key_usage = "\x55\x1d\x25\x00";
const oid_kp_server_auth = "\x2b\x06\x01\x05\x05\x07\x03\x01";
const oid_kp_client_auth = "\x2b\x06\x01\x05\x05\x07\x03\x02";
const oid_kp_ocsp_signing = "\x2b\x06\x01\x05\x05\x07\x03\x09";
const oid_rsa_encryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const oid_rsassa_pss = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";
const oid_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01";

pub const PrecheckError = error{InvalidCertificate};

/// Walk the parts of a certificate that `std.crypto.Certificate.parse` and its verifiers
/// read, with bounded reads. A malformed certificate then ends in an error and never in
/// an out-of-bounds read. Call it before every use of the std parser on peer data.
pub fn precheck(bytes: []const u8) PrecheckError!void {
    precheckInner(bytes) catch return error.InvalidCertificate;
}

fn precheckInner(bytes: []const u8) der.Error!void {
    const cert = try (try der.parse(bytes)).expect(der.tag_sequence);
    var top = cert.children();
    const tbs = try (try top.require()).expect(der.tag_sequence);
    var fields = tbs.children();
    var elem = try fields.require();
    if (elem.tag == 0xa0) {
        // The version wrapper holds one small INTEGER.
        if (elem.content.len != 3) return error.InvalidLength;
        _ = try (try der.parseExact(elem.content)).expect(der.tag_integer);
        elem = try fields.require(); // serial number
    }
    _ = try fields.require(); // signature algorithm of the TBS part
    _ = try fields.require(); // issuer
    const validity = try fields.require();
    var times = validity.children();
    _ = try times.require();
    _ = try times.require();
    const subject = try fields.require();
    try precheckName(subject);
    const spki = try (try fields.require()).expect(der.tag_sequence);
    var spki_parts = spki.children();
    const algorithm = try (try spki_parts.require()).expect(der.tag_sequence);
    var algorithm_parts = algorithm.children();
    const oid = try (try algorithm_parts.require()).expect(der.tag_oid);
    if (oid.isOid(oid_ec_public_key)) _ = try algorithm_parts.require(); // the named curve
    const key = try (try spki_parts.require()).expect(der.tag_bit_string);
    const key_bytes = try key.bitString();
    if (oid.isOid(oid_rsa_encryption) or oid.isOid(oid_rsassa_pss)) {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        const rsa = try (try der.parseExact(key_bytes)).expect(der.tag_sequence);
        var rsa_parts = rsa.children();
        _ = try (try rsa_parts.require()).expect(der.tag_integer);
        _ = try (try rsa_parts.require()).expect(der.tag_integer);
    }
    // Optional unique ids and extensions. std reads the next element only when its tag
    // number is 3 (context tag [3]).
    if (try fields.next()) |next| {
        if (next.tag & 0x1f == 3) {
            const ext_list = try (try der.parse(next.content)).expect(der.tag_sequence);
            var it = ext_list.children();
            while (try it.next()) |ext| {
                var parts = ext.children();
                const ext_oid = try parts.require();
                var value = try parts.require();
                if (value.tag == 0x01) value = try parts.require();
                if (ext_oid.isOid(oid_subject_alt_name)) {
                    // The host name check walks the general names.
                    const names = try der.parse(value.content);
                    var name_it = names.children();
                    while (try name_it.next()) |_| {}
                }
            }
        }
    }
    const sig_algo = try top.require();
    var sig_algo_parts = sig_algo.children();
    _ = try sig_algo_parts.require();
    const sig = try (try top.require()).expect(der.tag_bit_string);
    _ = try sig.bitString();
}

/// A Name is a sequence of relative distinguished names, each a set of attribute pairs.
fn precheckName(name: der.Element) der.Error!void {
    var rdns = name.children();
    while (try rdns.next()) |rdn| {
        var atavs = rdn.children();
        while (try atavs.next()) |atav| {
            var parts = atav.children();
            while (try parts.next()) |_| {
                _ = try parts.require(); // every type has a value
            }
        }
    }
}

pub const BasicConstraints = struct {
    ca: bool,
    /// The maximum number of intermediate certificates below this one, when limited.
    path_len: ?u64,
};

pub const KeyUsage = struct {
    key_cert_sign: bool,
    digital_signature: bool,
    crl_sign: bool = false,
};

/// The purposes of the extended key usage extension that the SDK knows (RFC 5280
/// section 4.2.1.12). Other purposes do not change a field.
pub const ExtendedKeyUsage = struct {
    server_auth: bool = false,
    client_auth: bool = false,
    ocsp_signing: bool = false,
    /// `anyExtendedKeyUsage`: the certificate permits every purpose.
    any: bool = false,
};

/// The `extensions` sequence of a certificate, or null when the certificate has none.
fn extensions(cert: []const u8) der.Error!?der.Element {
    const outer = try (try der.parse(cert)).expect(der.tag_sequence);
    var it = outer.children();
    const tbs = try (try it.require()).expect(der.tag_sequence);
    var fields = tbs.children();
    while (try fields.next()) |field| {
        if (field.tag == 0xa3) return try (try der.parseExact(field.content)).expect(der.tag_sequence);
    }
    return null;
}

/// One extension: the content of its `OCTET STRING` and its critical flag.
pub const Extension = struct {
    value: []const u8,
    critical: bool,
};

/// Parse one `Extension` of a certificate, a CRL or an OCSP response. The `oid` field is
/// the element of the extension ID.
pub fn parseExtension(ext: der.Element) der.Error!struct { oid: der.Element, extension: Extension } {
    var parts = (try ext.expect(der.tag_sequence)).children();
    const id = try (try parts.require()).expect(der.tag_oid);
    var value = try parts.require();
    var critical = false;
    if (value.tag == 0x01) {
        if (value.content.len != 1) return error.InvalidLength;
        critical = value.content[0] != 0;
        value = try parts.require();
    }
    _ = try value.expect(der.tag_octet_string);
    if (try parts.next() != null) return error.InvalidLength;
    return .{ .oid = id, .extension = .{ .value = value.content, .critical = critical } };
}

/// The extension `oid` of a certificate, or null when absent.
pub fn findExtensionFull(cert: []const u8, oid: []const u8) der.Error!?Extension {
    const exts = (try extensions(cert)) orelse return null;
    var it = exts.children();
    while (try it.next()) |ext| {
        const parsed = try parseExtension(ext);
        if (parsed.oid.isOid(oid)) return parsed.extension;
    }
    return null;
}

/// The value of the extension `oid`, or null when absent.
fn findExtension(cert: []const u8, oid: []const u8) der.Error!?[]const u8 {
    const ext = (try findExtensionFull(cert, oid)) orelse return null;
    return ext.value;
}

/// The fields of the to-be-signed part of a certificate that the checks of the SDK read.
pub const TbsFields = struct {
    /// The `INTEGER` of the serial number.
    serial: der.Element,
    /// The `Name` of the issuer.
    issuer: der.Element,
    /// The `Name` of the subject.
    subject: der.Element,
    /// The `SubjectPublicKeyInfo`.
    spki: der.Element,
};

/// Read the fields of `TbsFields` from a DER certificate.
pub fn tbsFields(cert: []const u8) der.Error!TbsFields {
    const outer = try (try der.parse(cert)).expect(der.tag_sequence);
    var it = outer.children();
    const tbs = try (try it.require()).expect(der.tag_sequence);
    var fields = tbs.children();
    var serial = try fields.require();
    if (serial.tag == 0xa0) serial = try fields.require(); // the version
    _ = try fields.require(); // the signature algorithm
    const issuer = try (try fields.require()).expect(der.tag_sequence);
    _ = try fields.require(); // the validity
    const subject = try (try fields.require()).expect(der.tag_sequence);
    const spki = try (try fields.require()).expect(der.tag_sequence);
    return .{ .serial = try serial.expect(der.tag_integer), .issuer = issuer, .subject = subject, .spki = spki };
}

/// True when the issuer and the subject of the certificate have the same bytes.
pub fn isSelfIssued(cert: []const u8) der.Error!bool {
    const fields = try tbsFields(cert);
    return std.mem.eql(u8, fields.issuer.raw, fields.subject.raw);
}

/// The basic constraints of a certificate, or null when the extension is absent.
pub fn basicConstraints(cert: []const u8) der.Error!?BasicConstraints {
    const value = (try findExtension(cert, oid_basic_constraints)) orelse return null;
    const seq = try (try der.parseExact(value)).expect(der.tag_sequence);
    var it = seq.children();
    var result: BasicConstraints = .{ .ca = false, .path_len = null };
    var elem = try it.next();
    if (elem != null and elem.?.tag == 0x01) {
        if (elem.?.content.len != 1) return error.InvalidLength;
        result.ca = elem.?.content[0] != 0;
        elem = try it.next();
    }
    if (elem) |e| result.path_len = try e.smallInt();
    return result;
}

/// The key usage of a certificate, or null when the extension is absent.
pub fn keyUsage(cert: []const u8) der.Error!?KeyUsage {
    const value = (try findExtension(cert, oid_key_usage)) orelse return null;
    const bits = try der.parseExact(value);
    if (bits.tag != der.tag_bit_string or bits.content.len < 1) return error.UnexpectedTag;
    const first: u8 = if (bits.content.len >= 2) bits.content[1] else 0;
    return .{
        .digital_signature = first & 0x80 != 0,
        .key_cert_sign = first & 0x04 != 0,
        .crl_sign = first & 0x02 != 0,
    };
}

pub const SignatureError = error{
    /// The algorithm or the key size is not one that the SDK verifies.
    UnsupportedAlgorithm,
    /// The signature does not verify with the key.
    BadSignature,
};

const oid_sha256_rsa = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b";
const oid_sha384_rsa = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c";
const oid_sha512_rsa = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d";
const oid_ecdsa_sha256 = "\x2a\x86\x48\xce\x3d\x04\x03\x02";
const oid_ecdsa_sha384 = "\x2a\x86\x48\xce\x3d\x04\x03\x03";
const oid_ecdsa_sha512 = "\x2a\x86\x48\xce\x3d\x04\x03\x04";
const oid_ed25519 = "\x2b\x65\x70";

/// Verify the signature of a signed object, such as a CRL or an OCSP response, with the
/// public key of a certificate. `algorithm` is the `AlgorithmIdentifier` element. The SDK
/// verifies RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 or SHA-512, ECDSA on P-256 or P-384,
/// and Ed25519.
pub fn verifySignature(algorithm: der.Element, message: []const u8, signature: []const u8, signer: Certificate.Parsed) SignatureError!void {
    if (algorithm.tag != der.tag_sequence) return error.UnsupportedAlgorithm;
    var parts = algorithm.children();
    const oid = parts.require() catch return error.UnsupportedAlgorithm;
    const params = parts.next() catch return error.UnsupportedAlgorithm;
    if ((parts.next() catch return error.UnsupportedAlgorithm) != null) return error.UnsupportedAlgorithm;
    const key = signer.pubKey();
    const sha2 = std.crypto.hash.sha2;
    if (oid.isOid(oid_sha256_rsa) or oid.isOid(oid_sha384_rsa) or oid.isOid(oid_sha512_rsa)) {
        // The parameters are NULL or absent (RFC 4055 section 5).
        if (params) |p| if (p.tag != der.tag_null or p.content.len != 0) return error.UnsupportedAlgorithm;
        if (oid.isOid(oid_sha256_rsa)) return verifyRsaPkcs1(sha2.Sha256, message, signature, signer.pub_key_algo, key);
        if (oid.isOid(oid_sha384_rsa)) return verifyRsaPkcs1(sha2.Sha384, message, signature, signer.pub_key_algo, key);
        return verifyRsaPkcs1(sha2.Sha512, message, signature, signer.pub_key_algo, key);
    }
    if (params != null) return error.UnsupportedAlgorithm;
    if (oid.isOid(oid_ecdsa_sha256)) return verifyEcdsa(sha2.Sha256, message, signature, signer.pub_key_algo, key);
    if (oid.isOid(oid_ecdsa_sha384)) return verifyEcdsa(sha2.Sha384, message, signature, signer.pub_key_algo, key);
    if (oid.isOid(oid_ecdsa_sha512)) return verifyEcdsa(sha2.Sha512, message, signature, signer.pub_key_algo, key);
    if (oid.isOid(oid_ed25519)) {
        if (signer.pub_key_algo != .curveEd25519) return error.BadSignature;
        const Ed25519 = std.crypto.sign.Ed25519;
        if (signature.len != Ed25519.Signature.encoded_length or key.len != Ed25519.PublicKey.encoded_length) return error.BadSignature;
        const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
        const public = Ed25519.PublicKey.fromBytes(key[0..Ed25519.PublicKey.encoded_length].*) catch return error.BadSignature;
        sig.verify(message, public) catch return error.BadSignature;
        return;
    }
    return error.UnsupportedAlgorithm;
}

fn verifyRsaPkcs1(comptime Hash: type, message: []const u8, signature: []const u8, algo: Certificate.Parsed.PubKeyAlgo, key: []const u8) SignatureError!void {
    if (algo != .rsaEncryption) return error.BadSignature;
    const rsa = Certificate.rsa;
    const components = rsa.PublicKey.parseDer(key) catch return error.BadSignature;
    switch (components.modulus.len) {
        inline 256, 384, 512 => |modulus_len| {
            if (signature.len != modulus_len) return error.BadSignature;
            const public = rsa.PublicKey.fromBytes(components.exponent, components.modulus) catch return error.BadSignature;
            rsa.PKCS1v1_5Signature.verify(modulus_len, signature[0..modulus_len].*, message, public, Hash) catch return error.BadSignature;
        },
        else => return error.UnsupportedAlgorithm,
    }
}

fn verifyEcdsa(comptime Hash: type, message: []const u8, signature: []const u8, algo: Certificate.Parsed.PubKeyAlgo, key: []const u8) SignatureError!void {
    const curve = switch (algo) {
        .X9_62_id_ecPublicKey => |c| c,
        else => return error.BadSignature,
    };
    switch (curve) {
        inline .X9_62_prime256v1, .secp384r1 => |c| {
            const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(c.Curve(), Hash);
            const sig = Ecdsa.Signature.fromDer(signature) catch return error.BadSignature;
            const public = Ecdsa.PublicKey.fromSec1(key) catch return error.BadSignature;
            sig.verify(message, public) catch return error.BadSignature;
        },
        .secp521r1 => return error.UnsupportedAlgorithm,
    }
}

/// The extended key usage of a certificate, or null when the extension is absent.
pub fn extendedKeyUsage(cert: []const u8) der.Error!?ExtendedKeyUsage {
    const value = (try findExtension(cert, oid_ext_key_usage)) orelse return null;
    const seq = try (try der.parseExact(value)).expect(der.tag_sequence);
    var result: ExtendedKeyUsage = .{};
    var it = seq.children();
    while (try it.next()) |purpose| {
        _ = try purpose.expect(der.tag_oid);
        if (purpose.isOid(oid_kp_server_auth)) result.server_auth = true;
        if (purpose.isOid(oid_kp_client_auth)) result.client_auth = true;
        if (purpose.isOid(oid_kp_ocsp_signing)) result.ocsp_signing = true;
        if (purpose.isOid(oid_any_ext_key_usage)) result.any = true;
    }
    return result;
}

/// The `GeneralNames` sequence of the subject alternative name, or null when absent.
pub fn subjectAltNames(cert: []const u8) der.Error!?der.Element {
    const value = (try findExtension(cert, oid_subject_alt_name)) orelse return null;
    return try (try der.parseExact(value)).expect(der.tag_sequence);
}

/// True when the subject alternative name of the certificate lists this IP address.
pub fn hasIpAddress(cert: []const u8, address: []const u8) der.Error!bool {
    const names = (try subjectAltNames(cert)) orelse return false;
    var it = names.children();
    while (try it.next()) |name| {
        if (name.tag == 0x87 and std.mem.eql(u8, name.content, address)) return true;
    }
    return false;
}

/// True when a `dNSName` of the subject alternative name matches `host`. The function
/// never reads the common name of the subject (RFC 9525 section 6.3).
pub fn hasDnsName(cert: []const u8, host: []const u8) der.Error!bool {
    const names = (try subjectAltNames(cert)) orelse return false;
    var it = names.children();
    while (try it.next()) |name| {
        if (name.tag == 0x82 and matchesHostName(name.content, host)) return true;
    }
    return false;
}

/// Compare a DNS name of a certificate with a host name, without regard to case. The
/// rules of RFC 6125 section 6.4.3 apply to a wildcard. A wildcard is the complete
/// leftmost label, it matches one label, and at least two labels follow it.
pub fn matchesHostName(pattern_in: []const u8, host_in: []const u8) bool {
    const pattern = std.mem.trimEnd(u8, pattern_in, ".");
    const host = std.mem.trimEnd(u8, host_in, ".");
    if (pattern.len == 0 or host.len == 0) return false;
    if (std.mem.findScalar(u8, host, '*') != null) return false;
    if (!std.mem.startsWith(u8, pattern, "*.")) {
        if (std.mem.findScalar(u8, pattern, '*') != null) return false; // a partial wildcard
        return std.ascii.eqlIgnoreCase(pattern, host);
    }
    const suffix = pattern[2..];
    if (std.mem.findScalar(u8, suffix, '*') != null) return false;
    // Refuse "*.com": a wildcard needs two or more labels after it.
    if (!validLabels(suffix) or std.mem.findScalar(u8, suffix, '.') == null) return false;
    const dot = std.mem.findScalar(u8, host, '.') orelse return false;
    if (dot == 0) return false; // the wildcard matches one complete label, not an empty one
    return std.ascii.eqlIgnoreCase(host[dot + 1 ..], suffix);
}

/// True when `name` has no empty label.
fn validLabels(name: []const u8) bool {
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| if (label.len == 0) return false;
    return true;
}

test "host name matching follows RFC 6125 and refuses broad wildcards" {
    try std.testing.expect(matchesHostName("example.com", "example.com"));
    try std.testing.expect(matchesHostName("Example.COM", "example.com"));
    try std.testing.expect(matchesHostName("example.com.", "example.com"));
    try std.testing.expect(matchesHostName("example.com", "example.com."));
    try std.testing.expect(!matchesHostName("example.com", "www.example.com"));
    try std.testing.expect(matchesHostName("*.example.com", "www.example.com"));
    try std.testing.expect(matchesHostName("*.Example.com", "WWW.example.COM"));
    try std.testing.expect(!matchesHostName("*.example.com", "example.com"));
    try std.testing.expect(!matchesHostName("*.example.com", "a.b.example.com"));
    try std.testing.expect(!matchesHostName("*.example.com", ".example.com"));
    // Partial and inner wildcards.
    try std.testing.expect(!matchesHostName("w*.example.com", "www.example.com"));
    try std.testing.expect(!matchesHostName("*w.example.com", "www.example.com"));
    try std.testing.expect(!matchesHostName("www.*.com", "www.example.com"));
    try std.testing.expect(!matchesHostName("*.*.com", "www.example.com"));
    // Wildcards that cover a top-level domain or everything.
    try std.testing.expect(!matchesHostName("*", "localhost"));
    try std.testing.expect(!matchesHostName("*.", "localhost"));
    try std.testing.expect(!matchesHostName("*.com", "example.com"));
    try std.testing.expect(!matchesHostName("*.localhost", "a.localhost"));
    try std.testing.expect(!matchesHostName("*..com", "a..com"));
    // The host itself never has a wildcard.
    try std.testing.expect(!matchesHostName("*.example.com", "*.example.com"));
    try std.testing.expect(!matchesHostName("", ""));
    try std.testing.expect(!matchesHostName("example.com", ""));
}

test "basic constraints and key usage of the fixtures" {
    const gpa = std.testing.allocator;
    const pem = @import("pem.zig");
    const ca_text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "test/fixtures/tls/pem/ca.crt", gpa, .limited(1 << 16));
    defer gpa.free(ca_text);
    var it: pem.Iterator = .init(ca_text);
    const ca = try it.nextLabeled("CERTIFICATE").?.decode(gpa);
    defer gpa.free(ca);
    const bc = (try basicConstraints(ca)).?;
    try std.testing.expect(bc.ca);
    const ku = (try keyUsage(ca)).?;
    try std.testing.expect(ku.key_cert_sign);

    const leaf_text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "test/fixtures/tls/pem/chain-leaf.crt", gpa, .limited(1 << 16));
    defer gpa.free(leaf_text);
    var it2: pem.Iterator = .init(leaf_text);
    const leaf = try it2.nextLabeled("CERTIFICATE").?.decode(gpa);
    defer gpa.free(leaf);
    const leaf_bc = (try basicConstraints(leaf)).?;
    try std.testing.expect(!leaf_bc.ca);
    try std.testing.expect(try hasIpAddress(leaf, &.{ 127, 0, 0, 1 }));
    try std.testing.expect(!try hasIpAddress(leaf, &.{ 10, 0, 0, 1 }));
}

test "precheck accepts the fixtures and rejects truncated and empty input" {
    const gpa = std.testing.allocator;
    const pem = @import("pem.zig");
    for ([_][]const u8{ "p256.crt", "p384.crt", "ed25519.crt", "ca.crt", "chain-leaf.crt" }) |name| {
        var path_buf: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "test/fixtures/tls/pem/{s}", .{name});
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 16));
        defer gpa.free(text);
        var it: pem.Iterator = .init(text);
        const cert = try it.nextLabeled("CERTIFICATE").?.decode(gpa);
        defer gpa.free(cert);
        try precheck(cert);
        try std.testing.expectError(error.InvalidCertificate, precheck(cert[0 .. cert.len / 2]));
        try std.testing.expectError(error.InvalidCertificate, precheck(cert[0..12]));
    }
    try std.testing.expectError(error.InvalidCertificate, precheck(""));
    try std.testing.expectError(error.InvalidCertificate, precheck("\x30\x00"));
    try std.testing.expectError(error.InvalidCertificate, precheck("\x30\x03\x30\x01\x02"));
}
