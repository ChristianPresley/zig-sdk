//! RSASSA-PSS keys and certificates. This file parses the RSASSA-PSS-params of RFC 4055
//! section 3.1 and RFC 8017 appendix A.2.3. It also parses and verifies certificates with an
//! RSASSA-PSS signature, because `std.crypto.Certificate` does not know this signature
//! algorithm. The SDK supports SHA-256, SHA-384 and SHA-512 with MGF1 of the same hash.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;
const Parsed = Certificate.Parsed;
const der = @import("der.zig");
const rsa = @import("rsa.zig");
const x509 = @import("x509.zig");

/// The object identifier id-RSASSA-PSS, 1.2.840.113549.1.1.10.
pub const oid_rsassa_pss = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";
const oid_mgf1 = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08";
const oid_sha256 = "\x60\x86\x48\x01\x65\x03\x04\x02\x01";
const oid_sha384 = "\x60\x86\x48\x01\x65\x03\x04\x02\x02";
const oid_sha512 = "\x60\x86\x48\x01\x65\x03\x04\x02\x03";
const oid_common_name = "\x55\x04\x03";
const oid_subject_alt_name = "\x55\x1d\x11";

/// The hash functions of RSASSA-PSS that the SDK supports.
pub const Hash = enum {
    sha256,
    sha384,
    sha512,

    pub fn Type(comptime self: Hash) type {
        return switch (self) {
            .sha256 => crypto.hash.sha2.Sha256,
            .sha384 => crypto.hash.sha2.Sha384,
            .sha512 => crypto.hash.sha2.Sha512,
        };
    }

    pub fn digestLength(self: Hash) usize {
        return switch (self) {
            inline else => |h| h.Type().digest_length,
        };
    }

    /// The TLS 1.3 signature scheme of this hash for a key with an id-RSASSA-PSS public key.
    pub fn scheme(self: Hash) tls.SignatureScheme {
        return switch (self) {
            .sha256 => .rsa_pss_pss_sha256,
            .sha384 => .rsa_pss_pss_sha384,
            .sha512 => .rsa_pss_pss_sha512,
        };
    }

    fn fromOid(elem: der.Element) ?Hash {
        if (elem.isOid(oid_sha256)) return .sha256;
        if (elem.isOid(oid_sha384)) return .sha384;
        if (elem.isOid(oid_sha512)) return .sha512;
        return null;
    }
};

/// The parameters of an RSASSA-PSS key or signature. The MGF1 hash is always `hash`.
pub const Params = struct {
    hash: Hash,
    /// For a key, the minimum salt length. For a signature, the salt length.
    salt_len: u16,

    /// The one TLS 1.3 scheme that a key with these parameters can make. TLS 1.3 uses a salt
    /// as long as the hash (RFC 8446 section 4.2.3). Thus a longer minimum salt gives null.
    pub fn scheme(self: Params) ?tls.SignatureScheme {
        if (self.salt_len > self.hash.digestLength()) return null;
        return self.hash.scheme();
    }

    /// True when a key with these parameters can make the TLS 1.3 scheme `with`.
    pub fn permits(self: Params, with: tls.SignatureScheme) bool {
        const own = self.scheme() orelse return false;
        return own == with;
    }

    /// True when a signature with the parameters `sig` agrees with these key parameters.
    pub fn allows(self: Params, sig: Params) bool {
        return sig.hash == self.hash and sig.salt_len >= self.salt_len;
    }
};

pub const ParamsError = error{
    /// The DER structure has an error.
    InvalidEncoding,
    /// The parameters name a hash or a mask generation function that the SDK does not support.
    /// Examples are SHA-1, MGF1 with another hash than the message hash, and a trailer field
    /// other than 1.
    UnsupportedParams,
};

/// Parse `RSASSA-PSS-params`. The defaults of RFC 4055 name SHA-1, which the SDK does not
/// support. Thus parameters without a hash or without a mask generation function give
/// `error.UnsupportedParams`.
pub fn parseParams(elem: der.Element) ParamsError!Params {
    if (elem.tag != der.tag_sequence) return error.InvalidEncoding;
    var it = elem.children();
    var hash: ?Hash = null;
    var mgf_hash: ?Hash = null;
    var salt_len: u64 = 20;
    var last_tag: u8 = 0;
    while (it.next() catch return error.InvalidEncoding) |field| {
        // The fields have the tags [0] to [3], in this order and each at most once.
        if (field.tag <= last_tag) return error.InvalidEncoding;
        last_tag = field.tag;
        const inner = der.parseExact(field.content) catch return error.InvalidEncoding;
        switch (field.tag) {
            0xa0 => hash = try hashAlgorithm(inner),
            0xa1 => mgf_hash = try maskGenAlgorithm(inner),
            0xa2 => salt_len = inner.smallInt() catch return error.InvalidEncoding,
            0xa3 => {
                const trailer = inner.smallInt() catch return error.InvalidEncoding;
                if (trailer != 1) return error.UnsupportedParams;
            },
            else => return error.InvalidEncoding,
        }
    }
    const h = hash orelse return error.UnsupportedParams;
    const m = mgf_hash orelse return error.UnsupportedParams;
    if (m != h) return error.UnsupportedParams;
    if (salt_len > rsa.max_modulus_len) return error.UnsupportedParams;
    return .{ .hash = h, .salt_len = @intCast(salt_len) };
}

/// A hash `AlgorithmIdentifier` with absent or `NULL` parameters.
fn hashAlgorithm(elem: der.Element) ParamsError!Hash {
    if (elem.tag != der.tag_sequence) return error.InvalidEncoding;
    var it = elem.children();
    const oid = it.require() catch return error.InvalidEncoding;
    if (oid.tag != der.tag_oid) return error.InvalidEncoding;
    if (it.next() catch return error.InvalidEncoding) |params| {
        if (params.tag != der.tag_null or params.content.len != 0) return error.InvalidEncoding;
    }
    if ((it.next() catch return error.InvalidEncoding) != null) return error.InvalidEncoding;
    return Hash.fromOid(oid) orelse error.UnsupportedParams;
}

/// A mask generation `AlgorithmIdentifier`: MGF1 with a hash.
fn maskGenAlgorithm(elem: der.Element) ParamsError!Hash {
    if (elem.tag != der.tag_sequence) return error.InvalidEncoding;
    var it = elem.children();
    const oid = it.require() catch return error.InvalidEncoding;
    if (oid.tag != der.tag_oid) return error.InvalidEncoding;
    if (!oid.isOid(oid_mgf1)) return error.UnsupportedParams;
    const hash = try hashAlgorithm(it.require() catch return error.InvalidEncoding);
    if ((it.next() catch return error.InvalidEncoding) != null) return error.InvalidEncoding;
    return hash;
}

/// The parameters of an id-RSASSA-PSS `AlgorithmIdentifier` of a key. Null tells that the
/// parameters are absent and that the key has no restriction (RFC 4055 section 3.1).
pub fn keyParams(algorithm: der.Element) ParamsError!?Params {
    if (algorithm.tag != der.tag_sequence) return error.InvalidEncoding;
    var it = algorithm.children();
    const oid = it.require() catch return error.InvalidEncoding;
    if (!oid.isOid(oid_rsassa_pss)) return error.InvalidEncoding;
    const params = (it.next() catch return error.InvalidEncoding) orelse return null;
    if ((it.next() catch return error.InvalidEncoding) != null) return error.InvalidEncoding;
    return try parseParams(params);
}

/// The fields of a DER certificate that this file reads.
const Fields = struct {
    tbs: der.Element,
    signature_algorithm: der.Element,
    signature: der.Element,
    version: ?der.Element,
    issuer: der.Element,
    validity: der.Element,
    subject: der.Element,
    spki: der.Element,
    /// The fields after the subject public key: unique identifiers and extensions.
    rest: der.Iterator,

    fn read(bytes: []const u8) der.Error!Fields {
        const outer = try (try der.parse(bytes)).expect(der.tag_sequence);
        var top = outer.children();
        const tbs = try (try top.require()).expect(der.tag_sequence);
        const signature_algorithm = try (try top.require()).expect(der.tag_sequence);
        const signature = try (try top.require()).expect(der.tag_bit_string);
        if ((try top.next()) != null) return error.InvalidLength;
        var fields = tbs.children();
        var first = try fields.require();
        var version: ?der.Element = null;
        if (first.tag == der.tag_context_0) {
            version = first;
            first = try fields.require(); // the serial number
        }
        _ = try fields.require(); // the signature algorithm of the TBS part
        const issuer = try (try fields.require()).expect(der.tag_sequence);
        const validity = try (try fields.require()).expect(der.tag_sequence);
        const subject = try (try fields.require()).expect(der.tag_sequence);
        const spki = try (try fields.require()).expect(der.tag_sequence);
        return .{
            .tbs = tbs,
            .signature_algorithm = signature_algorithm,
            .signature = signature,
            .version = version,
            .issuer = issuer,
            .validity = validity,
            .subject = subject,
            .spki = spki,
            .rest = fields,
        };
    }
};

/// The RSASSA-PSS parameters of the signature of a DER certificate. Null tells that another
/// algorithm signs the certificate.
pub fn signatureParams(cert: []const u8) ParamsError!?Params {
    const fields = Fields.read(cert) catch return error.InvalidEncoding;
    var it = fields.signature_algorithm.children();
    const oid = it.require() catch return error.InvalidEncoding;
    if (!oid.isOid(oid_rsassa_pss)) return null;
    // A signature always has parameters (RFC 4055 section 3.1).
    const params = (it.next() catch return error.InvalidEncoding) orelse return error.InvalidEncoding;
    if ((it.next() catch return error.InvalidEncoding) != null) return error.InvalidEncoding;
    return try parseParams(params);
}

/// The RSASSA-PSS parameters of the subject public key of a DER certificate. Null tells that
/// the key has no parameters, or that it is not an id-RSASSA-PSS key.
pub fn publicKeyParams(cert: []const u8) ParamsError!?Params {
    const fields = Fields.read(cert) catch return error.InvalidEncoding;
    var it = fields.spki.children();
    const algorithm = it.require() catch return error.InvalidEncoding;
    var parts = algorithm.children();
    const oid = parts.require() catch return error.InvalidEncoding;
    if (!oid.isOid(oid_rsassa_pss)) return null;
    return keyParams(algorithm);
}

/// Parse a certificate like `std.crypto.Certificate.parse`, and also a certificate with an
/// RSASSA-PSS signature. For such a certificate, `signature_algorithm` is
/// `md2WithRSAEncryption`, which `Parsed.verify` always refuses. Use `verifyCertificate` to
/// verify it. The function runs `x509.precheck` first, because the std parser does not check
/// the bounds of its reads.
pub fn parseCertificate(cert: Certificate) Certificate.ParseError!Parsed {
    const bytes = cert.buffer[cert.index..];
    x509.precheck(bytes) catch return error.CertificateFieldHasInvalidLength;
    const signed_with_pss = (signatureParams(bytes) catch null) != null;
    if (!signed_with_pss) return cert.parse();
    return parsePssSigned(cert) catch |e| switch (e) {
        error.InvalidLength, error.Truncated, error.UnexpectedTag, error.Overflow => error.CertificateFieldHasInvalidLength,
        else => |other| other,
    };
}

/// The parser for a certificate with an RSASSA-PSS signature. It gives the same slices as the
/// std parser.
fn parsePssSigned(cert: Certificate) (Certificate.ParseError || der.Error)!Parsed {
    const base = cert.buffer;
    const fields = try Fields.read(base[cert.index..]);
    var version: Certificate.Version = .v1;
    if (fields.version) |v| version = try Certificate.parseVersion(base, stdElement(base, v));
    var times = fields.validity.children();
    const not_before = try Certificate.parseTime(cert, stdElement(base, try times.require()));
    const not_after = try Certificate.parseTime(cert, stdElement(base, try times.require()));

    var spki_parts = fields.spki.children();
    const algorithm = try (try spki_parts.require()).expect(der.tag_sequence);
    var algorithm_parts = algorithm.children();
    const algorithm_oid = try algorithm_parts.require();
    const pub_key_algo: Parsed.PubKeyAlgo = switch (try Certificate.parseAlgorithmCategory(base, stdElement(base, algorithm_oid))) {
        .rsaEncryption => .rsaEncryption,
        .rsassa_pss => .rsassa_pss,
        .curveEd25519 => .curveEd25519,
        .X9_62_id_ecPublicKey => .{ .X9_62_id_ecPublicKey = try Certificate.parseNamedCurve(base, stdElement(base, try algorithm_parts.require())) },
    };
    const pub_key = try Certificate.parseBitString(cert, stdElement(base, try spki_parts.require()));

    // The last common name of the subject, as in the std parser.
    var common_name: Certificate.der.Element.Slice = .empty;
    var rdns = fields.subject.children();
    while (try rdns.next()) |rdn| {
        var atavs = rdn.children();
        while (try atavs.next()) |atav| {
            var parts = atav.children();
            const kind = try parts.require();
            const value = try parts.require();
            if (kind.isOid(oid_common_name)) common_name = slice(base, value.content);
        }
    }

    var subject_alt_name: Certificate.der.Element.Slice = .empty;
    var rest = fields.rest;
    if (version != .v1) {
        while (try rest.next()) |field| {
            if (field.tag != 0xa3) continue;
            var exts = (try (try der.parseExact(field.content)).expect(der.tag_sequence)).children();
            while (try exts.next()) |ext| {
                var parts = ext.children();
                const id = try parts.require();
                var value = try parts.require();
                if (value.tag == 0x01) value = try parts.require(); // the critical flag
                if (id.isOid(oid_subject_alt_name)) subject_alt_name = slice(base, (try value.expect(der.tag_octet_string)).content);
            }
        }
    }

    return .{
        .certificate = cert,
        .issuer_slice = slice(base, fields.issuer.content),
        .subject_slice = slice(base, fields.subject.content),
        .common_name_slice = common_name,
        .signature_slice = try Certificate.parseBitString(cert, stdElement(base, fields.signature)),
        .signature_algorithm = .md2WithRSAEncryption,
        .pub_key_algo = pub_key_algo,
        .pub_key_slice = pub_key,
        .message_slice = slice(base, fields.tbs.raw),
        .subject_alt_name_slice = subject_alt_name,
        .validity = .{ .not_before = not_before, .not_after = not_after },
        .version = version,
    };
}

/// The position of `part` in `base`.
fn slice(base: []const u8, part: []const u8) Certificate.der.Element.Slice {
    const start: u32 = @intCast(@intFromPtr(part.ptr) - @intFromPtr(base.ptr));
    return .{ .start = start, .end = start + @as(u32, @intCast(part.len)) };
}

/// The std form of an element of `base`, for the std field parsers.
fn stdElement(base: []const u8, elem: der.Element) Certificate.der.Element {
    return .{ .identifier = @bitCast(elem.tag), .slice = slice(base, elem.content) };
}

/// Verify that `issuer` signs `subject`, like `Parsed.verify`, and also for an RSASSA-PSS
/// signature. An RSASSA-PSS signature needs an issuer key of the type rsaEncryption or
/// id-RSASSA-PSS. The parameters of an id-RSASSA-PSS key restrict the signature.
pub fn verifyCertificate(subject: Parsed, issuer: Parsed, now_sec: i64) Parsed.VerifyError!void {
    const subject_bytes = subject.certificate.buffer[subject.certificate.index..];
    const params = (signatureParams(subject_bytes) catch return error.CertificateFieldHasWrongDataType) orelse
        return subject.verify(issuer, now_sec);
    if (!std.mem.eql(u8, subject.issuer(), issuer.subject())) return error.CertificateIssuerMismatch;
    if (now_sec < subject.validity.not_before) return error.CertificateNotYetValid;
    if (now_sec > subject.validity.not_after) return error.CertificateExpired;
    switch (issuer.pub_key_algo) {
        .rsaEncryption => {},
        .rsassa_pss => {
            const issuer_bytes = issuer.certificate.buffer[issuer.certificate.index..];
            const key = publicKeyParams(issuer_bytes) catch return error.CertificatePublicKeyInvalid;
            if (key) |k| if (!k.allows(params)) return error.CertificateSignatureAlgorithmMismatch;
        },
        else => return error.CertificateSignatureAlgorithmMismatch,
    }
    const key = rsaPublicKey(issuer.pubKey()) orelse return error.CertificatePublicKeyInvalid;
    verify(params, key.modulus, key.exponent, subject.message(), subject.signature()) catch |e| return switch (e) {
        error.InvalidSignature => error.CertificateSignatureInvalid,
        error.UnsupportedKey => error.CertificateSignatureUnsupportedBitCount,
    };
}

/// Verify an RSASSA-PSS signature with the hash and the salt length of `params`.
pub fn verify(params: Params, modulus: []const u8, exponent: []const u8, message: []const u8, signature: []const u8) rsa.VerifyError!void {
    switch (params.hash) {
        inline else => |h| return rsa.verifyPss(h.Type(), modulus, exponent, message, signature, params.salt_len),
    }
}

const RsaPublicKey = struct { modulus: []const u8, exponent: []const u8 };

/// The modulus and the exponent of a DER `RSAPublicKey`, or null when it is malformed.
fn rsaPublicKey(bytes: []const u8) ?RsaPublicKey {
    const seq = der.parseExact(bytes) catch return null;
    if (seq.tag != der.tag_sequence) return null;
    var it = seq.children();
    const modulus = it.require() catch return null;
    const exponent = it.require() catch return null;
    if ((it.next() catch return null) != null) return null;
    if (modulus.tag != der.tag_integer or exponent.tag != der.tag_integer) return null;
    return .{ .modulus = modulus.content, .exponent = exponent.content };
}

// -- Tests -----------------------------------------------------------------------------------

fn loadCert(gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const pem = @import("pem.zig");
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 16));
    defer gpa.free(text);
    var it: pem.Iterator = .init(text);
    return it.nextLabeled("CERTIFICATE").?.decode(gpa);
}

/// Encode `RSASSA-PSS-params` from DER parts, for the tests.
fn encodeParams(buf: []u8, parts: []const []const u8) der.Element {
    var len: usize = 0;
    for (parts) |p| len += p.len;
    buf[0] = der.tag_sequence;
    buf[1] = @intCast(len);
    var i: usize = 2;
    for (parts) |p| {
        @memcpy(buf[i..][0..p.len], p);
        i += p.len;
    }
    return der.parseExact(buf[0..i]) catch unreachable;
}

const test_sha256 = "\xa0\x0f\x30\x0d\x06\x09" ++ oid_sha256 ++ "\x05\x00";
const test_sha384_no_null = "\xa0\x0d\x30\x0b\x06\x09" ++ oid_sha384;
const test_mgf_sha256 = "\xa1\x1c\x30\x1a\x06\x09" ++ oid_mgf1 ++ "\x30\x0d\x06\x09" ++ oid_sha256 ++ "\x05\x00";
const test_mgf_sha384 = "\xa1\x1a\x30\x18\x06\x09" ++ oid_mgf1 ++ "\x30\x0b\x06\x09" ++ oid_sha384;
const test_salt_32 = "\xa2\x03\x02\x01\x20";

test "RSASSA-PSS parameters" {
    var buf: [128]u8 = undefined;
    // SHA-256 with the default salt length 20 and the default trailer field.
    const p = try parseParams(encodeParams(&buf, &.{ test_sha256, test_mgf_sha256 }));
    try std.testing.expectEqual(Hash.sha256, p.hash);
    try std.testing.expectEqual(20, p.salt_len);
    try std.testing.expectEqual(tls.SignatureScheme.rsa_pss_pss_sha256, p.scheme().?);
    // A hash without NULL parameters, a salt length and an explicit trailer field.
    const q = try parseParams(encodeParams(&buf, &.{ test_sha384_no_null, test_mgf_sha384, "\xa2\x03\x02\x01\x40", "\xa3\x03\x02\x01\x01" }));
    try std.testing.expectEqual(Hash.sha384, q.hash);
    try std.testing.expectEqual(64, q.salt_len);
    // A minimum salt longer than the hash permits no TLS 1.3 scheme.
    try std.testing.expect(q.scheme() == null);
    try std.testing.expect(q.allows(.{ .hash = .sha384, .salt_len = 64 }));
    try std.testing.expect(!q.allows(.{ .hash = .sha384, .salt_len = 48 }));
    try std.testing.expect(!q.allows(.{ .hash = .sha256, .salt_len = 64 }));

    // The SHA-1 defaults, another MGF1 hash, another trailer field and an unknown hash.
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{})));
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{test_sha256})));
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{test_mgf_sha256})));
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{ test_sha256, test_mgf_sha384 })));
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{ test_sha256, test_mgf_sha256, "\xa3\x03\x02\x01\x02" })));
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{ "\xa0\x0b\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00", test_mgf_sha256 })));
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{ test_sha256, "\xa1\x0d\x30\x0b\x06\x09" ++ oid_sha256 })));
    try std.testing.expectError(error.UnsupportedParams, parseParams(encodeParams(&buf, &.{ test_sha256, test_mgf_sha256, "\xa2\x04\x02\x02\x02\x01" })));
    // Fields out of order, twice, with a wrong tag or with trailing bytes.
    try std.testing.expectError(error.InvalidEncoding, parseParams(encodeParams(&buf, &.{ test_mgf_sha256, test_sha256 })));
    try std.testing.expectError(error.InvalidEncoding, parseParams(encodeParams(&buf, &.{ test_sha256, test_sha256, test_mgf_sha256 })));
    try std.testing.expectError(error.InvalidEncoding, parseParams(encodeParams(&buf, &.{ test_sha256, test_mgf_sha256, "\xa4\x03\x02\x01\x01" })));
    try std.testing.expectError(error.InvalidEncoding, parseParams(encodeParams(&buf, &.{ test_sha256, test_mgf_sha256, "\xa2\x04\x02\x01\x20\x00" })));
    try std.testing.expectError(error.InvalidEncoding, parseParams(encodeParams(&buf, &.{ "\xa0\x0f\x30\x0d\x06\x09" ++ oid_sha256 ++ "\x04\x00", test_mgf_sha256 })));
    try std.testing.expectError(error.InvalidEncoding, parseParams(encodeParams(&buf, &.{ test_sha256, test_mgf_sha256, "\xa2\x03\x02\x01\x80" })));
    try std.testing.expectError(error.InvalidEncoding, parseParams(.{ .tag = der.tag_null, .content = "", .raw = "\x05\x00" }));
}

test "certificates with RSASSA-PSS signatures parse and verify" {
    const gpa = std.testing.allocator;
    const ca = try loadCert(gpa, "test/fixtures/tls/pem/rsa-pss.crt");
    defer gpa.free(ca);
    const leaf = try loadCert(gpa, "test/fixtures/tls/pem/rsa-pss-sha256.crt");
    defer gpa.free(leaf);
    const ecdsa_ca = try loadCert(gpa, "test/fixtures/tls/pem/ca.crt");
    defer gpa.free(ecdsa_ca);
    const now: i64 = 1_800_000_000;
    try x509.precheck(ca);
    try x509.precheck(leaf);

    // The std parser does not know the signature algorithm.
    const std_cert: Certificate = .{ .buffer = leaf, .index = 0 };
    try std.testing.expectError(error.CertificateHasUnrecognizedObjectId, std_cert.parse());

    const ca_parsed = try parseCertificate(.{ .buffer = ca, .index = 0 });
    const leaf_parsed = try parseCertificate(.{ .buffer = leaf, .index = 0 });
    try std.testing.expectEqual(Parsed.PubKeyAlgo.rsassa_pss, ca_parsed.pub_key_algo);
    try std.testing.expectEqualStrings("localhost", leaf_parsed.commonName());
    try std.testing.expectEqualStrings("zig-sdk RSA-PSS test CA", ca_parsed.commonName());
    try std.testing.expectEqualSlices(u8, ca_parsed.subject(), leaf_parsed.issuer());
    try leaf_parsed.verifyHostName("localhost");
    try std.testing.expectError(error.CertificateHostMismatch, leaf_parsed.verifyHostName("example.com"));

    // The signature parameters: SHA-256 and a salt of 32 bytes for the self-signed CA, SHA-384
    // and the default salt of 20 bytes for the leaf.
    try std.testing.expectEqual(Params{ .hash = .sha256, .salt_len = 32 }, (try signatureParams(ca)).?);
    try std.testing.expectEqual(Params{ .hash = .sha384, .salt_len = 20 }, (try signatureParams(leaf)).?);
    try std.testing.expect((try signatureParams(ecdsa_ca)) == null);
    // The key parameters: none for the CA, SHA-256 and at least 32 bytes of salt for the leaf.
    try std.testing.expect((try publicKeyParams(ca)) == null);
    try std.testing.expectEqual(Params{ .hash = .sha256, .salt_len = 32 }, (try publicKeyParams(leaf)).?);
    try std.testing.expect((try publicKeyParams(ecdsa_ca)) == null);

    try verifyCertificate(ca_parsed, ca_parsed, now);
    try verifyCertificate(leaf_parsed, ca_parsed, now);
    try std.testing.expectError(error.CertificateExpired, verifyCertificate(leaf_parsed, ca_parsed, now + 20 * 365 * 86400));
    try std.testing.expectError(error.CertificateNotYetValid, verifyCertificate(leaf_parsed, ca_parsed, 0));
    // The std verifier refuses the placeholder algorithm.
    try std.testing.expectError(error.CertificateSignatureAlgorithmUnsupported, leaf_parsed.verify(ca_parsed, now));
    // Another issuer: a name mismatch, and the wrong key type with the same name.
    const ecdsa_parsed = try parseCertificate(.{ .buffer = ecdsa_ca, .index = 0 });
    try std.testing.expectError(error.CertificateIssuerMismatch, verifyCertificate(leaf_parsed, ecdsa_parsed, now));
    var fake_issuer = ecdsa_parsed;
    fake_issuer.subject_slice = ca_parsed.subject_slice;
    fake_issuer.certificate = ca_parsed.certificate;
    fake_issuer.pub_key_algo = .{ .X9_62_id_ecPublicKey = .X9_62_prime256v1 };
    try std.testing.expectError(error.CertificateSignatureAlgorithmMismatch, verifyCertificate(leaf_parsed, fake_issuer, now));
    // An issuer with the restricted key of the leaf (SHA-256 only) and the name of the CA. The
    // SHA-384 signature of the leaf does not agree with the key parameters.
    var restricted = leaf_parsed;
    restricted.subject_slice = leaf_parsed.issuer_slice;
    try std.testing.expectError(error.CertificateSignatureAlgorithmMismatch, verifyCertificate(leaf_parsed, restricted, now));

    // A changed signature fails.
    const tampered = try gpa.dupe(u8, leaf);
    defer gpa.free(tampered);
    tampered[tampered.len - 10] ^= 1;
    const tampered_parsed = try parseCertificate(.{ .buffer = tampered, .index = 0 });
    try std.testing.expectError(error.CertificateSignatureInvalid, verifyCertificate(tampered_parsed, ca_parsed, now));

    // A truncated certificate does not parse, and a certificate in a larger buffer does.
    try std.testing.expectError(error.CertificateFieldHasInvalidLength, parseCertificate(.{ .buffer = leaf[0 .. leaf.len - 1], .index = 0 }));
    const both = try std.mem.concat(gpa, u8, &.{ ca, leaf });
    defer gpa.free(both);
    const second = try parseCertificate(.{ .buffer = both, .index = @intCast(ca.len) });
    try verifyCertificate(second, ca_parsed, now);
    try std.testing.expectEqualStrings("localhost", second.commonName());
}
