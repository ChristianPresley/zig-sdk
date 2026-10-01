//! An X.509 certificate revocation list (RFC 5280 section 5) that the application supplies.
//! The SDK does not fetch CRLs from the network. The application loads them, for example
//! from files, and puts them in the revocation policy of a TLS client or server.
//!
//! The SDK uses complete CRLs that the CA of the certificate signs. At load time it
//! refuses a delta CRL and an indirect CRL. It also refuses a CRL with the extension
//! `issuingDistributionPoint`, and a CRL with a critical extension that it does not know.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = @import("der.zig");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");

const Crl = @This();

gpa: Allocator,
/// The DER bytes. The other slices point into them.
bytes: []u8,
/// The `Name` of the issuer, with its tag and length.
issuer: []const u8,
/// `thisUpdate` in seconds since the epoch.
this_update: i64,
/// `nextUpdate` in seconds since the epoch. RFC 5280 tells CAs to write it. The SDK
/// does not use a CRL without it.
next_update: ?i64,
/// The content of `revokedCertificates`, or empty.
revoked: []const u8,
/// The complete `tbsCertList`: the signed bytes.
tbs: []const u8,
/// The `AlgorithmIdentifier` of the signature.
algorithm: []const u8,
/// The signature without the octet of unused bits.
signature: []const u8,

pub const max_len = 16 << 20;

pub const ParseError = error{
    OutOfMemory,
    /// The bytes are not a CRL.
    InvalidCrl,
    /// A delta CRL, an indirect CRL, a CRL with `issuingDistributionPoint`, or a CRL with
    /// a critical extension that the SDK does not know.
    UnsupportedCrl,
};

/// The reason codes of RFC 5280 section 5.3.1.
pub const Reason = enum(u8) {
    unspecified = 0,
    key_compromise = 1,
    ca_compromise = 2,
    affiliation_changed = 3,
    superseded = 4,
    cessation_of_operation = 5,
    certificate_hold = 6,
    remove_from_crl = 8,
    privilege_withdrawn = 9,
    aa_compromise = 10,
    _,
};

/// One revoked certificate. The SDK refuses the certificate for each reason. The reason
/// is only for information.
pub const Entry = struct {
    revocation_time: i64,
    reason: ?Reason,
};

const oid_authority_key_id = "\x55\x1d\x23";
const oid_crl_number = "\x55\x1d\x14";
const oid_delta_crl_indicator = "\x55\x1d\x1b";
const oid_issuing_distribution_point = "\x55\x1d\x1c";
const oid_freshest_crl = "\x55\x1d\x2e";
const oid_authority_info_access = "\x2b\x06\x01\x05\x05\x07\x01\x01";
const oid_reason_code = "\x55\x1d\x15";
const oid_invalidity_date = "\x55\x1d\x18";
const oid_certificate_issuer = "\x55\x1d\x1d";

/// Parse a DER CRL. The CRL keeps a copy of the bytes.
pub fn fromDer(gpa: Allocator, bytes: []const u8) ParseError!Crl {
    if (bytes.len > max_len) return error.InvalidCrl;
    const copy = try gpa.dupe(u8, bytes);
    errdefer gpa.free(copy);
    var crl: Crl = .{
        .gpa = gpa,
        .bytes = copy,
        .issuer = undefined,
        .this_update = undefined,
        .next_update = null,
        .revoked = &.{},
        .tbs = undefined,
        .algorithm = undefined,
        .signature = undefined,
    };
    crl.parse() catch |e| return switch (e) {
        error.UnsupportedCrl => error.UnsupportedCrl,
        else => error.InvalidCrl,
    };
    return crl;
}

/// Parse the first `X509 CRL` block of a PEM text.
pub fn fromPem(gpa: Allocator, text: []const u8) ParseError!Crl {
    var it: pem.Iterator = .init(text);
    const block = it.nextLabeled("X509 CRL") orelse return error.InvalidCrl;
    const bytes = block.decode(gpa) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidEncoding => error.InvalidCrl,
    };
    defer gpa.free(bytes);
    return fromDer(gpa, bytes);
}

/// Load a CRL file in PEM or in DER.
pub fn loadFile(gpa: Allocator, io: std.Io, path: []const u8) (ParseError || std.Io.Dir.ReadFileAllocError)!Crl {
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_len));
    defer gpa.free(data);
    // A DER CRL starts with the SEQUENCE tag. A PEM CRL starts with text.
    if (data.len > 0 and data[0] == der.tag_sequence) return fromDer(gpa, data);
    return fromPem(gpa, data);
}

pub fn deinit(self: *Crl) void {
    self.gpa.free(self.bytes);
    self.* = undefined;
}

const InnerError = der.Error || error{UnsupportedCrl};

fn parse(self: *Crl) InnerError!void {
    const outer = try (try der.parseExact(self.bytes)).expect(der.tag_sequence);
    var top = outer.children();
    const tbs = try (try top.require()).expect(der.tag_sequence);
    const algorithm = try (try top.require()).expect(der.tag_sequence);
    const signature = try (try top.require()).bitString();
    if (try top.next() != null) return error.InvalidLength;

    var fields = tbs.children();
    var elem = try fields.require();
    if (elem.tag == der.tag_integer) {
        // Only version 2 has the field. The value is 1.
        if (try elem.smallInt() != 1) return error.UnexpectedTag;
        elem = try fields.require();
    }
    // The algorithm in the signed part must equal the outer one (section 5.1.1.2).
    if (!std.mem.eql(u8, elem.raw, algorithm.raw)) return error.UnexpectedTag;
    const issuer = try (try fields.require()).expect(der.tag_sequence);
    const this_update = try fields.require();
    self.this_update = try this_update.time();
    var next = try fields.next();
    if (next != null and next.?.isTime()) {
        self.next_update = try next.?.time();
        next = try fields.next();
    }
    if (next != null and next.?.tag == der.tag_sequence) {
        self.revoked = next.?.content;
        try checkEntries(next.?.content);
        next = try fields.next();
    }
    if (next) |n| {
        if (n.tag != der.tag_context_0) return error.UnexpectedTag;
        try checkCrlExtensions(n.content);
        if (try fields.next() != null) return error.InvalidLength;
    }
    self.issuer = issuer.raw;
    self.tbs = tbs.raw;
    self.algorithm = algorithm.raw;
    self.signature = signature;
}

/// The CRL extensions that the SDK knows. Each other critical extension refuses the CRL.
fn checkCrlExtensions(wrapper: []const u8) InnerError!void {
    const list = try (try der.parseExact(wrapper)).expect(der.tag_sequence);
    var it = list.children();
    while (try it.next()) |ext| {
        const parsed = try x509.parseExtension(ext);
        const oid = parsed.oid;
        // A delta CRL lists only changes, and an issuing distribution point limits the
        // scope or makes the CRL indirect. The SDK does not use either.
        if (oid.isOid(oid_delta_crl_indicator) or oid.isOid(oid_issuing_distribution_point)) return error.UnsupportedCrl;
        const known = oid.isOid(oid_authority_key_id) or oid.isOid(oid_crl_number) or
            oid.isOid(oid_freshest_crl) or oid.isOid(oid_authority_info_access);
        if (parsed.extension.critical and !known) return error.UnsupportedCrl;
    }
}

/// Check each entry: a serial number, a time and optional extensions.
fn checkEntries(content: []const u8) InnerError!void {
    var it: der.Iterator = .{ .rest = content };
    while (try it.next()) |entry| _ = try parseEntry(entry);
}

const ParsedEntry = struct {
    serial: []const u8,
    entry: Entry,
};

fn parseEntry(element: der.Element) InnerError!ParsedEntry {
    var parts = (try element.expect(der.tag_sequence)).children();
    const serial = try (try parts.require()).expect(der.tag_integer);
    if (serial.content.len == 0) return error.InvalidLength;
    const time = try (try parts.require()).time();
    var result: ParsedEntry = .{ .serial = serial.content, .entry = .{ .revocation_time = time, .reason = null } };
    if (try parts.next()) |exts| {
        var it = (try exts.expect(der.tag_sequence)).children();
        while (try it.next()) |ext| {
            const parsed = try x509.parseExtension(ext);
            if (parsed.oid.isOid(oid_reason_code)) {
                const value = try (try der.parseExact(parsed.extension.value)).expect(der.tag_enumerated);
                if (value.content.len != 1) return error.InvalidLength;
                result.entry.reason = @enumFromInt(value.content[0]);
            } else if (parsed.oid.isOid(oid_certificate_issuer)) {
                // The entry belongs to another issuer: an indirect CRL.
                return error.UnsupportedCrl;
            } else if (parsed.extension.critical and !parsed.oid.isOid(oid_invalidity_date)) {
                return error.UnsupportedCrl;
            }
        }
        if (try parts.next() != null) return error.InvalidLength;
    }
    return result;
}

/// The entry of the certificate with this serial number, or null. `serial` is the content
/// of the `INTEGER`.
pub fn find(self: *const Crl, serial: []const u8) ?Entry {
    var it: der.Iterator = .{ .rest = self.revoked };
    while (it.next() catch return null) |element| {
        const parsed = parseEntry(element) catch return null;
        if (std.mem.eql(u8, parsed.serial, serial)) return parsed.entry;
    }
    return null;
}

/// True when the CRL is valid at `now_sec`: `thisUpdate` is not in the future and
/// `nextUpdate` is not in the past. Each side has a tolerance of `skew_sec`. A CRL without
/// `nextUpdate` is never current.
pub fn isCurrent(self: *const Crl, now_sec: i64, skew_sec: i64) bool {
    const next = self.next_update orelse return false;
    return self.this_update -| skew_sec <= now_sec and now_sec <= next +| skew_sec;
}

/// True when `issuer` signs the CRL. The names must be equal and the signature must
/// verify. When the issuer has a key usage, it must permit CRL signatures. `issuer_der`
/// is the DER certificate of `issuer`.
pub fn signedBy(self: *const Crl, issuer: Certificate.Parsed, issuer_der: []const u8) bool {
    const fields = x509.tbsFields(issuer_der) catch return false;
    if (!std.mem.eql(u8, fields.subject.raw, self.issuer)) return false;
    const usage = x509.keyUsage(issuer_der) catch return false;
    if (usage) |ku| if (!ku.crl_sign) return false;
    const algorithm = der.parseExact(self.algorithm) catch return false;
    x509.verifySignature(algorithm, self.tbs, self.signature, issuer) catch return false;
    return true;
}

// -- Tests -----------------------------------------------------------------------------------

fn loadCert(gpa: Allocator, path: []const u8) ![]u8 {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 16));
    defer gpa.free(text);
    var it: pem.Iterator = .init(text);
    return it.nextLabeled("CERTIFICATE").?.decode(gpa);
}

fn parseCert(bytes: []const u8) !Certificate.Parsed {
    try x509.precheck(bytes);
    return (Certificate{ .buffer = bytes, .index = 0 }).parse();
}

const fixture_now: i64 = 1_800_000_000;

test "parse the CRL fixtures in PEM and DER" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var from_pem = try loadFile(gpa, io, "test/fixtures/tls/pem/rev-ca.crl");
    defer from_pem.deinit();
    var from_der = try loadFile(gpa, io, "test/fixtures/tls/der/rev-ca.crl");
    defer from_der.deinit();
    try std.testing.expectEqualSlices(u8, from_pem.bytes, from_der.bytes);
    const entry = from_pem.find("\x31\x02").?;
    try std.testing.expectEqual(Reason.key_compromise, entry.reason.?);
    try std.testing.expect(from_pem.find("\x31\x01") == null);
    try std.testing.expect(from_pem.isCurrent(fixture_now, 0));
    try std.testing.expect(!from_pem.isCurrent(0, 300));

    var stale = try loadFile(gpa, io, "test/fixtures/tls/pem/rev-ca-stale.crl");
    defer stale.deinit();
    try std.testing.expect(!stale.isCurrent(fixture_now, 300));

    try std.testing.expectError(error.UnsupportedCrl, loadFile(gpa, io, "test/fixtures/tls/pem/rev-ca-delta.crl"));
    try std.testing.expectError(error.UnsupportedCrl, loadFile(gpa, io, "test/fixtures/tls/pem/rev-ca-critical.crl"));
    try std.testing.expectError(error.InvalidCrl, fromPem(gpa, "no CRL here"));
    try std.testing.expectError(error.InvalidCrl, fromDer(gpa, from_der.bytes[0 .. from_der.bytes.len - 1]));
}

test "the CRL signature verifies with its issuer only" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var crl = try loadFile(gpa, io, "test/fixtures/tls/pem/rev-ca.crl");
    defer crl.deinit();
    const ca = try loadCert(gpa, "test/fixtures/tls/pem/rev-ca.crt");
    defer gpa.free(ca);
    const root = try loadCert(gpa, "test/fixtures/tls/pem/rev-root.crt");
    defer gpa.free(root);
    try std.testing.expect(crl.signedBy(try parseCert(ca), ca));
    try std.testing.expect(!crl.signedBy(try parseCert(root), root));
    // One changed bit in the signature.
    crl.bytes[crl.bytes.len - 1] ^= 1;
    try std.testing.expect(!crl.signedBy(try parseCert(ca), ca));
    // The root signs its own CRL with ECDSA.
    var root_crl = try loadFile(gpa, io, "test/fixtures/tls/pem/rev-root.crl");
    defer root_crl.deinit();
    try std.testing.expect(root_crl.signedBy(try parseCert(root), root));
}
