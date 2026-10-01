//! OCSP responses (RFC 6960) that a TLS server staples to its certificates (RFC 8446
//! section 4.4.2.1). The client checks the response offline: the SDK never asks an OCSP
//! responder.
const std = @import("std");
const Certificate = std.crypto.Certificate;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const der = @import("der.zig");
const x509 = @import("x509.zig");

/// The largest OCSP response that the server staples and that the client reads.
pub const max_response_len = 16 << 10;

/// How long a response without `nextUpdate` stays current after its `thisUpdate`: one day.
pub const default_lifetime_sec: i64 = 86400;

pub const Status = enum { good, revoked, unknown };

pub const Error = error{
    /// The response does not parse, its status is not `successful`, or its type is not
    /// the basic response.
    Malformed,
    /// No single response of the response is for the certificate.
    WrongCertificate,
    /// The signature does not verify, or the signer is not a valid responder of the issuer.
    BadSignature,
    /// The `thisUpdate` is in the future, or the response is stale.
    NotCurrent,
    /// The response has a critical extension that the SDK does not know.
    UnsupportedExtension,
};

const oid_basic_response = "\x2b\x06\x01\x05\x05\x07\x30\x01\x01";
const oid_nonce = "\x2b\x06\x01\x05\x05\x07\x30\x01\x02";
const oid_sha1 = "\x2b\x0e\x03\x02\x1a";
const oid_sha256 = "\x60\x86\x48\x01\x65\x03\x04\x02\x01";

/// Check a DER `OCSPResponse` for `cert` and return the status of the certificate.
/// `issuer` is the DER certificate of the CA that signs `cert`. The issuer itself, or a
/// delegated responder, must sign the response. A delegated responder has a certificate
/// in the response. The issuer signs it, it is valid at `now_sec`, and its extended key
/// usage has `id-kp-OCSPSigning`. The function compares the times with a tolerance of
/// `skew_sec`.
pub fn check(response: []const u8, cert: []const u8, issuer: []const u8, now_sec: i64, skew_sec: i64) Error!Status {
    if (response.len > max_response_len) return error.Malformed;
    const basic = try parseBasicResponse(response);

    // The signer: the issuer or a delegated responder.
    const issuer_parsed = parseCertificate(issuer) catch return error.Malformed;
    const issuer_fields = x509.tbsFields(issuer) catch return error.Malformed;
    const signer = if (try responderIs(basic.responder_id, issuer_fields.subject.raw, issuer_parsed.pubKey()))
        issuer_parsed
    else
        try delegatedResponder(basic, issuer_parsed, now_sec);
    x509.verifySignature(basic.algorithm, basic.tbs, basic.signature, signer) catch return error.BadSignature;

    // The single response for the certificate.
    const cert_fields = x509.tbsFields(cert) catch return error.Malformed;
    var it = basic.responses.children();
    while (it.next() catch return error.Malformed) |element| {
        const single = try parseSingleResponse(element);
        if (!try certIdMatches(single.cert_id, issuer_fields.subject.raw, issuer_parsed.pubKey(), cert_fields.serial.content)) continue;
        const valid_until = single.next_update orelse single.this_update +| default_lifetime_sec;
        if (single.this_update -| skew_sec > now_sec or now_sec > valid_until +| skew_sec) return error.NotCurrent;
        return single.status;
    }
    return error.WrongCertificate;
}

const BasicResponse = struct {
    /// The complete `ResponseData`: the signed bytes.
    tbs: []const u8,
    algorithm: der.Element,
    signature: []const u8,
    responder_id: der.Element,
    responses: der.Element,
    /// The content of `certs`, or empty.
    certs: []const u8,
};

fn parseBasicResponse(response: []const u8) Error!BasicResponse {
    return parseBasicInner(response) catch |e| switch (e) {
        error.UnsupportedExtension => error.UnsupportedExtension,
        else => error.Malformed,
    };
}

fn parseBasicInner(response: []const u8) (der.Error || error{ UnsupportedExtension, NotSuccessful })!BasicResponse {
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ... }
    const outer = try (try der.parseExact(response)).expect(der.tag_sequence);
    var top = outer.children();
    const status = try (try top.require()).expect(der.tag_enumerated);
    if (status.content.len != 1 or status.content[0] != 0) return error.NotSuccessful;
    const wrapper = try (try top.require()).expect(der.tag_context_0);
    if (try top.next() != null) return error.InvalidLength;
    var response_bytes = (try (try der.parseExact(wrapper.content)).expect(der.tag_sequence)).children();
    const response_type = try (try response_bytes.require()).expect(der.tag_oid);
    if (!response_type.isOid(oid_basic_response)) return error.UnexpectedTag;
    const octets = try (try response_bytes.require()).expect(der.tag_octet_string);
    if (try response_bytes.next() != null) return error.InvalidLength;

    // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature, certs [0] }
    const basic = try (try der.parseExact(octets.content)).expect(der.tag_sequence);
    var parts = basic.children();
    const tbs = try (try parts.require()).expect(der.tag_sequence);
    const algorithm = try (try parts.require()).expect(der.tag_sequence);
    const signature = try (try parts.require()).bitString();
    var certs: []const u8 = &.{};
    if (try parts.next()) |certs_wrapper| {
        _ = try certs_wrapper.expect(der.tag_context_0);
        certs = (try (try der.parseExact(certs_wrapper.content)).expect(der.tag_sequence)).content;
        if (try parts.next() != null) return error.InvalidLength;
    }

    // ResponseData ::= SEQUENCE { version [0], responderID, producedAt, responses, responseExtensions [1] }
    var fields = tbs.children();
    var elem = try fields.require();
    if (elem.tag == der.tag_context_0) {
        // Only version 1 exists. Its value is 0.
        if (try (try der.parseExact(elem.content)).smallInt() != 0) return error.UnexpectedTag;
        elem = try fields.require();
    }
    if (elem.tag != 0xa1 and elem.tag != 0xa2) return error.UnexpectedTag;
    const responder_id = elem;
    const produced_at = try fields.require();
    if (produced_at.tag != der.tag_generalized_time) return error.UnexpectedTag;
    _ = try produced_at.time();
    const responses = try (try fields.require()).expect(der.tag_sequence);
    if (try fields.next()) |exts| {
        if (exts.tag != der.tag_context_1) return error.UnexpectedTag;
        try checkExtensions(exts.content);
        if (try fields.next() != null) return error.InvalidLength;
    }
    return .{
        .tbs = tbs.raw,
        .algorithm = algorithm,
        .signature = signature,
        .responder_id = responder_id,
        .responses = responses,
        .certs = certs,
    };
}

/// Refuse a critical extension that the SDK does not know. The nonce is the only known one.
fn checkExtensions(wrapper: []const u8) (der.Error || error{UnsupportedExtension})!void {
    const list = try (try der.parseExact(wrapper)).expect(der.tag_sequence);
    var it = list.children();
    while (try it.next()) |ext| {
        const parsed = try x509.parseExtension(ext);
        if (parsed.extension.critical and !parsed.oid.isOid(oid_nonce)) return error.UnsupportedExtension;
    }
}

/// True when the `ResponderID` names this subject or this key (RFC 6960 section 4.2.1).
fn responderIs(responder_id: der.Element, subject: []const u8, public_key: []const u8) Error!bool {
    const inner = der.parseExact(responder_id.content) catch return error.Malformed;
    switch (responder_id.tag) {
        // byName [1] EXPLICIT Name
        0xa1 => return inner.tag == der.tag_sequence and std.mem.eql(u8, inner.raw, subject),
        // byKey [2] EXPLICIT OCTET STRING: the SHA-1 hash of the subject public key
        0xa2 => {
            if (inner.tag != der.tag_octet_string or inner.content.len != Sha1.digest_length) return error.Malformed;
            var hash: [Sha1.digest_length]u8 = undefined;
            Sha1.hash(public_key, &hash, .{});
            return std.mem.eql(u8, &hash, inner.content);
        },
        else => return error.Malformed,
    }
}

/// Find the delegated responder in the certificates of the response and check it.
fn delegatedResponder(basic: BasicResponse, issuer: Certificate.Parsed, now_sec: i64) Error!Certificate.Parsed {
    var it: der.Iterator = .{ .rest = basic.certs };
    while (it.next() catch return error.Malformed) |element| {
        const responder = parseCertificate(element.raw) catch return error.Malformed;
        const fields = x509.tbsFields(element.raw) catch return error.Malformed;
        if (!try responderIs(basic.responder_id, fields.subject.raw, responder.pubKey())) continue;
        // The issuer signs the responder, and the responder is valid now.
        responder.verify(issuer, now_sec) catch return error.BadSignature;
        const eku = (x509.extendedKeyUsage(element.raw) catch return error.Malformed) orelse return error.BadSignature;
        if (!eku.ocsp_signing) return error.BadSignature;
        const usage = x509.keyUsage(element.raw) catch return error.Malformed;
        if (usage) |ku| if (!ku.digital_signature) return error.BadSignature;
        return responder;
    }
    return error.BadSignature;
}

const SingleResponse = struct {
    cert_id: der.Element,
    status: Status,
    this_update: i64,
    next_update: ?i64,
};

fn parseSingleResponse(element: der.Element) Error!SingleResponse {
    return parseSingleInner(element) catch |e| switch (e) {
        error.UnsupportedExtension => error.UnsupportedExtension,
        else => error.Malformed,
    };
}

fn parseSingleInner(element: der.Element) (der.Error || error{UnsupportedExtension})!SingleResponse {
    var parts = (try element.expect(der.tag_sequence)).children();
    const cert_id = try (try parts.require()).expect(der.tag_sequence);
    const status_element = try parts.require();
    const status: Status = switch (status_element.tag) {
        0x80 => .good,
        0xa1 => .revoked,
        0x82 => .unknown,
        else => return error.UnexpectedTag,
    };
    if (status != .revoked and status_element.content.len != 0) return error.InvalidLength;
    const this_update = try parts.require();
    if (this_update.tag != der.tag_generalized_time) return error.UnexpectedTag;
    var result: SingleResponse = .{ .cert_id = cert_id, .status = status, .this_update = try this_update.time(), .next_update = null };
    var next = try parts.next();
    if (next != null and next.?.tag == der.tag_context_0) {
        const time = try der.parseExact(next.?.content);
        if (time.tag != der.tag_generalized_time) return error.UnexpectedTag;
        result.next_update = try time.time();
        next = try parts.next();
    }
    if (next) |exts| {
        if (exts.tag != der.tag_context_1) return error.UnexpectedTag;
        try checkExtensions(exts.content);
        if (try parts.next() != null) return error.InvalidLength;
    }
    return result;
}

/// True when the `CertID` names the certificate. The function compares the serial number
/// and the hashes of the issuer name and key, with SHA-1 or SHA-256.
fn certIdMatches(cert_id: der.Element, issuer_subject: []const u8, issuer_key: []const u8, serial: []const u8) Error!bool {
    var parts = cert_id.children();
    const algorithm = (parts.require() catch return error.Malformed).expect(der.tag_sequence) catch return error.Malformed;
    const name_hash = (parts.require() catch return error.Malformed).expect(der.tag_octet_string) catch return error.Malformed;
    const key_hash = (parts.require() catch return error.Malformed).expect(der.tag_octet_string) catch return error.Malformed;
    const number = (parts.require() catch return error.Malformed).expect(der.tag_integer) catch return error.Malformed;
    var algorithm_parts = algorithm.children();
    const oid = algorithm_parts.require() catch return error.Malformed;
    if (algorithm_parts.next() catch return error.Malformed) |params| {
        if (params.tag != der.tag_null or params.content.len != 0) return error.Malformed;
    }
    if (!std.mem.eql(u8, number.content, serial)) return false;
    if (oid.isOid(oid_sha1)) return hashesMatch(Sha1, issuer_subject, issuer_key, name_hash.content, key_hash.content);
    if (oid.isOid(oid_sha256)) return hashesMatch(Sha256, issuer_subject, issuer_key, name_hash.content, key_hash.content);
    return false;
}

fn hashesMatch(comptime Hash: type, subject: []const u8, key: []const u8, name_hash: []const u8, key_hash: []const u8) bool {
    var name_digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(subject, &name_digest, .{});
    var key_digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(key, &key_digest, .{});
    return std.mem.eql(u8, &name_digest, name_hash) and std.mem.eql(u8, &key_digest, key_hash);
}

fn parseCertificate(bytes: []const u8) !Certificate.Parsed {
    // The std parser reads without bounds checks. The precheck refuses what would crash it.
    try x509.precheck(bytes);
    return (Certificate{ .buffer = bytes, .index = 0 }).parse();
}

// -- Tests -----------------------------------------------------------------------------------

const fixture_now: i64 = 1_800_000_000;
const skew: i64 = 300;

fn readFixture(gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 16));
}

fn loadCert(gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const pem = @import("pem.zig");
    const text = try readFixture(gpa, path);
    defer gpa.free(text);
    var it: pem.Iterator = .init(text);
    return it.nextLabeled("CERTIFICATE").?.decode(gpa);
}

const Fixtures = struct {
    leaf: []u8,
    revoked: []u8,
    ca: []u8,
    root: []u8,

    fn load(gpa: std.mem.Allocator) !Fixtures {
        return .{
            .leaf = try loadCert(gpa, "test/fixtures/tls/pem/rev-leaf.crt"),
            .revoked = try loadCert(gpa, "test/fixtures/tls/pem/rev-revoked.crt"),
            .ca = try loadCert(gpa, "test/fixtures/tls/pem/rev-ca.crt"),
            .root = try loadCert(gpa, "test/fixtures/tls/pem/rev-root.crt"),
        };
    }

    fn deinit(self: *Fixtures, gpa: std.mem.Allocator) void {
        for ([_][]u8{ self.leaf, self.revoked, self.ca, self.root }) |c| gpa.free(c);
    }

    fn checkFile(self: *const Fixtures, name: []const u8, cert: []const u8, now: i64) Error!Status {
        const gpa = std.testing.allocator;
        var path_buf: [96]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "test/fixtures/tls/der/{s}.ocsp", .{name}) catch unreachable;
        const response = readFixture(gpa, path) catch return error.Malformed;
        defer gpa.free(response);
        return check(response, cert, self.ca, now, skew);
    }
};

test "OCSP responses of the issuer and of a delegated responder" {
    const gpa = std.testing.allocator;
    var f: Fixtures = try .load(gpa);
    defer f.deinit(gpa);
    // The CA signs with SHA-1 hashes in the certificate ID. The delegated responder
    // signs with SHA-256 hashes and names itself by key.
    try std.testing.expectEqual(Status.good, try f.checkFile("rev-leaf-good", f.leaf, fixture_now));
    try std.testing.expectEqual(Status.good, try f.checkFile("rev-leaf-good-delegated", f.leaf, fixture_now));
    try std.testing.expectEqual(Status.revoked, try f.checkFile("rev-revoked", f.revoked, fixture_now));
    try std.testing.expectEqual(Status.unknown, try f.checkFile("rev-leaf-unknown", f.leaf, fixture_now));
}

test "OCSP responses that the client refuses" {
    const gpa = std.testing.allocator;
    var f: Fixtures = try .load(gpa);
    defer f.deinit(gpa);
    // A response for another certificate.
    try std.testing.expectError(error.WrongCertificate, f.checkFile("rev-revoked", f.leaf, fixture_now));
    // A delegated responder without id-kp-OCSPSigning.
    try std.testing.expectError(error.BadSignature, f.checkFile("rev-leaf-noeku", f.leaf, fixture_now));
    // A stale response, and a response from the future.
    try std.testing.expectError(error.NotCurrent, f.checkFile("rev-leaf-stale", f.leaf, fixture_now));
    try std.testing.expectError(error.NotCurrent, f.checkFile("rev-leaf-good", f.leaf, 1_700_000_000));
    // The wrong issuer: the root does not sign the response of the CA.
    const response = try readFixture(gpa, "test/fixtures/tls/der/rev-leaf-good.ocsp");
    defer gpa.free(response);
    try std.testing.expectError(error.BadSignature, check(response, f.leaf, f.root, fixture_now, skew));
    // One changed bit in the signature of the response. The response also holds the
    // certificate of the CA after the signature.
    const signature = (try parseBasicResponse(response)).signature;
    response[@intFromPtr(signature.ptr) - @intFromPtr(response.ptr) + signature.len - 1] ^= 1;
    try std.testing.expectError(error.BadSignature, check(response, f.leaf, f.ca, fixture_now, skew));
    // A truncated response.
    try std.testing.expectError(error.Malformed, check(response[0 .. response.len - 1], f.leaf, f.ca, fixture_now, skew));
    // The status "tryLater" with no response bytes.
    try std.testing.expectError(error.Malformed, check("\x30\x03\x0a\x01\x03", f.leaf, f.ca, fixture_now, skew));
}
