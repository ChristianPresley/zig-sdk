//! The X.509 extensions that chain validation needs and `std.crypto.Certificate` does not
//! expose: basic constraints and key usage (RFC 5280 section 4.2.1).
const std = @import("std");
const der = @import("der.zig");

const oid_basic_constraints = "\x55\x1d\x13";
const oid_key_usage = "\x55\x1d\x0f";
const oid_subject_alt_name = "\x55\x1d\x11";

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
