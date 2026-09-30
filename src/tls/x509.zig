//! The X.509 extensions that chain validation needs and `std.crypto.Certificate` does not
//! expose: basic constraints and key usage (RFC 5280 section 4.2.1).
const std = @import("std");
const der = @import("der.zig");

const oid_basic_constraints = "\x55\x1d\x13";
const oid_key_usage = "\x55\x1d\x0f";
const oid_subject_alt_name = "\x55\x1d\x11";
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

/// The value of the extension `oid`, or null when absent.
fn findExtension(cert: []const u8, oid: []const u8) der.Error!?[]const u8 {
    const exts = (try extensions(cert)) orelse return null;
    var it = exts.children();
    while (try it.next()) |ext| {
        var parts = (try ext.expect(der.tag_sequence)).children();
        const id = try (try parts.require()).expect(der.tag_oid);
        var value = try parts.require();
        if (value.tag == 0x01) value = try parts.require(); // critical BOOLEAN
        if (id.isOid(oid)) return (try value.expect(der.tag_octet_string)).content;
    }
    return null;
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
    };
}

/// True when the subject alternative name of the certificate lists this IP address.
pub fn hasIpAddress(cert: []const u8, address: []const u8) der.Error!bool {
    const value = (try findExtension(cert, oid_subject_alt_name)) orelse return false;
    const names = try (try der.parseExact(value)).expect(der.tag_sequence);
    var it = names.children();
    while (try it.next()) |name| {
        if (name.tag == 0x87 and std.mem.eql(u8, name.content, address)) return true;
    }
    return false;
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
