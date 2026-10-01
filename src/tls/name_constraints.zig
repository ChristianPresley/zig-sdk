//! Name constraints of CA certificates (RFC 5280 section 4.2.1.10) and their check over a
//! certification path. A CA with name constraints limits the names of every certificate
//! below it in the path. When more than one CA has constraints, each of them applies.
//!
//! The SDK checks the name forms `dNSName`, `iPAddress`, `directoryName`, `rfc822Name` and
//! `uniformResourceIdentifier`. The check fails for a name of another form when a critical
//! constraint of the CA has a subtree of that form.
const std = @import("std");
const der = @import("der.zig");
const x509 = @import("x509.zig");

pub const Error = error{
    /// A name is outside the permitted subtrees, or inside an excluded subtree.
    NameNotPermitted,
    /// A critical constraint has a name form that the SDK cannot check, and a certificate
    /// below the CA has a name of that form.
    UnsupportedConstraint,
    /// The extension or a name of a certificate does not parse.
    Malformed,
};

/// The forms of a `GeneralName` (RFC 5280 section 4.2.1.6), by the number of the context tag.
pub const Form = enum(u4) {
    other_name = 0,
    rfc822_name = 1,
    dns_name = 2,
    x400_address = 3,
    directory_name = 4,
    edi_party_name = 5,
    uri = 6,
    ip_address = 7,
    registered_id = 8,

    /// True for the forms that the SDK can compare.
    pub fn supported(self: Form) bool {
        return switch (self) {
            .rfc822_name, .dns_name, .directory_name, .uri, .ip_address => true,
            .other_name, .x400_address, .edi_party_name, .registered_id => false,
        };
    }

    fn bit(self: Form) u16 {
        return @as(u16, 1) << @intFromEnum(self);
    }
};

/// A `GeneralName`: its form and its value. The value of a `directoryName` is the content
/// of the `Name` sequence: the relative distinguished names.
pub const GeneralName = struct {
    form: Form,
    value: []const u8,

    /// Parse one `GeneralName` element of a certificate or of a constraint.
    pub fn parse(element: der.Element) Error!GeneralName {
        if (element.tag & 0xc0 != 0x80) return error.Malformed; // context-specific class
        const number = element.tag & 0x1f;
        if (number > 8) return error.Malformed;
        const form: Form = @enumFromInt(number);
        const constructed = element.tag & 0x20 != 0;
        const want_constructed = switch (form) {
            .other_name, .x400_address, .directory_name, .edi_party_name => true,
            else => false,
        };
        if (constructed != want_constructed) return error.Malformed;
        if (form == .directory_name) {
            // [4] is an explicit tag around the Name sequence.
            const name = der.parseExact(element.content) catch return error.Malformed;
            if (name.tag != der.tag_sequence) return error.Malformed;
            return .{ .form = form, .value = name.content };
        }
        return .{ .form = form, .value = element.content };
    }
};

/// The name constraints of one CA. The slices point into the certificate.
pub const NameConstraints = struct {
    /// The `GeneralSubtree` elements of `permittedSubtrees`, or empty.
    permitted: []const u8 = &.{},
    /// The `GeneralSubtree` elements of `excludedSubtrees`, or empty.
    excluded: []const u8 = &.{},
    critical: bool = true,
    /// One bit for each form that has a permitted subtree.
    permitted_forms: u16 = 0,
    /// One bit for each form that has an excluded subtree.
    excluded_forms: u16 = 0,

    /// Parse the value of the extension. The function checks each subtree: `minimum` must
    /// be zero and `maximum` must be absent (RFC 5280 section 4.2.1.10).
    pub fn parse(value: []const u8, critical: bool) Error!NameConstraints {
        var result: NameConstraints = .{ .critical = critical };
        const seq = der.parseExact(value) catch return error.Malformed;
        if (seq.tag != der.tag_sequence) return error.Malformed;
        var it = seq.children();
        var last_tag: u8 = 0;
        while (it.next() catch return error.Malformed) |part| {
            if (part.tag <= last_tag) return error.Malformed; // order and no duplicates
            last_tag = part.tag;
            switch (part.tag) {
                0xa0 => {
                    result.permitted = part.content;
                    result.permitted_forms = try checkSubtrees(part.content);
                },
                0xa1 => {
                    result.excluded = part.content;
                    result.excluded_forms = try checkSubtrees(part.content);
                },
                else => return error.Malformed,
            }
        }
        // RFC 5280 forbids an empty sequence.
        if (last_tag == 0) return error.Malformed;
        return result;
    }

    fn hasForm(self: *const NameConstraints, form: Form) bool {
        return (self.permitted_forms | self.excluded_forms) & form.bit() != 0;
    }

    /// Check one name of a certificate below the CA.
    pub fn checkName(self: *const NameConstraints, name: GeneralName) Error!void {
        if (!name.form.supported()) {
            if (self.critical and self.hasForm(name.form)) return error.UnsupportedConstraint;
            return;
        }
        if (self.excluded_forms & name.form.bit() != 0) {
            var it: SubtreeIterator = .{ .rest = self.excluded };
            while (it.next()) |base| {
                if (base.form == name.form and try within(base.form, base.value, name.value)) return error.NameNotPermitted;
            }
        }
        if (self.permitted_forms & name.form.bit() != 0) {
            var it: SubtreeIterator = .{ .rest = self.permitted };
            while (it.next()) |base| {
                if (base.form == name.form and try within(base.form, base.value, name.value)) return;
            }
            return error.NameNotPermitted;
        }
    }

    /// Check every name of `cert`: the subject, the email addresses in the subject and
    /// the subject alternative names. With `host`, the function also checks the name that
    /// the client compared with the leaf.
    pub fn checkCertificate(self: *const NameConstraints, cert: []const u8, host: ?[]const u8) Error!void {
        const fields = x509.tbsFields(cert) catch return error.Malformed;
        if (fields.subject.content.len > 0) {
            try self.checkName(.{ .form = .directory_name, .value = fields.subject.content });
        }
        var emails: EmailIterator = .{ .rdns = fields.subject.children() };
        while (try emails.next()) |email| try self.checkName(.{ .form = .rfc822_name, .value = email });
        if (x509.subjectAltNames(cert) catch return error.Malformed) |names| {
            var it = names.children();
            while (it.next() catch return error.Malformed) |element| {
                try self.checkName(try GeneralName.parse(element));
            }
        }
        if (host) |h| {
            if (std.Io.net.IpAddress.parse(h, 0)) |address| {
                const bytes: []const u8 = switch (address) {
                    .ip4 => |a| &a.bytes,
                    .ip6 => |a| &a.bytes,
                };
                try self.checkName(.{ .form = .ip_address, .value = bytes });
            } else |_| {
                try self.checkName(.{ .form = .dns_name, .value = h });
            }
        }
    }
};

/// The name constraints of a certificate, or null when it has none.
pub fn ofCertificate(cert: []const u8) Error!?NameConstraints {
    const ext = (x509.findExtensionFull(cert, x509.oid_name_constraints) catch return error.Malformed) orelse return null;
    return try NameConstraints.parse(ext.value, ext.critical);
}

/// Check the name constraints over a path. `path` holds the leaf first and then the
/// intermediates. `anchor` is the trust anchor that signs the last one. The constraints of
/// a CA apply to each certificate below it. A self-issued intermediate gets no name check
/// (RFC 5280 section 6.1.3). `host` is the name that the client compared with the leaf.
pub fn checkPath(path: []const []const u8, anchor: []const u8, host: ?[]const u8) Error!void {
    var k: usize = path.len;
    while (k >= 1) : (k -= 1) {
        const ca = if (k == path.len) anchor else path[k];
        if (try ofCertificate(ca)) |nc| {
            for (path[0..k], 0..) |cert, i| {
                if (i > 0 and (x509.isSelfIssued(cert) catch return error.Malformed)) continue;
                try nc.checkCertificate(cert, if (i == 0) host else null);
            }
        }
    }
}

/// Check the `GeneralSubtree` elements of one list and return the bits of their forms.
fn checkSubtrees(content: []const u8) Error!u16 {
    var forms: u16 = 0;
    var it: der.Iterator = .{ .rest = content };
    var count: usize = 0;
    while (it.next() catch return error.Malformed) |subtree| {
        count += 1;
        if (subtree.tag != der.tag_sequence) return error.Malformed;
        var parts = subtree.children();
        const base = GeneralName.parse(parts.require() catch return error.Malformed) catch return error.Malformed;
        if (parts.next() catch return error.Malformed) |extra| {
            // Only `minimum` with the value zero: DER leaves the default out, but some
            // encoders write it.
            if (extra.tag != 0x80 or extra.content.len != 1 or extra.content[0] != 0) return error.Malformed;
            if ((parts.next() catch return error.Malformed) != null) return error.Malformed;
        }
        switch (base.form) {
            .ip_address => if (base.value.len != 8 and base.value.len != 32) return error.Malformed,
            .directory_name => _ = try countRdns(base.value),
            .dns_name, .rfc822_name, .uri => for (base.value) |c| if (c < 0x21 or c > 0x7e) return error.Malformed,
            else => {},
        }
        forms |= base.form.bit();
    }
    if (count == 0) return error.Malformed;
    return forms;
}

/// Walks a `GeneralSubtree` list that `checkSubtrees` accepts.
const SubtreeIterator = struct {
    rest: []const u8,

    fn next(self: *SubtreeIterator) ?GeneralName {
        var it: der.Iterator = .{ .rest = self.rest };
        const subtree = (it.next() catch return null) orelse return null;
        self.rest = it.rest;
        var parts = subtree.children();
        const base = parts.require() catch return null;
        return GeneralName.parse(base) catch null;
    }
};

/// The `emailAddress` attributes of a subject. RFC 5280 section 4.2.1.10 applies the
/// `rfc822Name` constraints to them.
const EmailIterator = struct {
    rdns: der.Iterator,
    atvs: der.Iterator = .{ .rest = &.{} },

    const oid_email_address = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01";

    fn next(self: *EmailIterator) Error!?[]const u8 {
        while (true) {
            while (self.atvs.next() catch return error.Malformed) |atv| {
                var parts = atv.children();
                const oid = parts.require() catch return error.Malformed;
                const value = parts.require() catch return error.Malformed;
                if (oid.isOid(oid_email_address)) return value.content;
            }
            const rdn = (self.rdns.next() catch return error.Malformed) orelse return null;
            if (rdn.tag != der.tag_set) return error.Malformed;
            self.atvs = rdn.children();
        }
    }
};

/// True when `name` is inside the subtree `constraint` of the same form.
fn within(form: Form, constraint: []const u8, name: []const u8) Error!bool {
    return switch (form) {
        .dns_name => dnsWithin(constraint, name),
        .ip_address => ipWithin(constraint, name),
        .directory_name => directoryWithin(constraint, name),
        .rfc822_name => try emailWithin(constraint, name),
        .uri => try uriWithin(constraint, name),
        else => unreachable,
    };
}

/// A DNS constraint covers the name itself and every name with more labels on the left.
/// A constraint with a leading period covers only the names with more labels.
pub fn dnsWithin(constraint_in: []const u8, name_in: []const u8) bool {
    const constraint = trimDot(constraint_in);
    const name = trimDot(name_in);
    if (constraint.len == 0) return true;
    if (constraint[0] == '.') return name.len > constraint.len and std.ascii.endsWithIgnoreCase(name, constraint);
    if (name.len == constraint.len) return std.ascii.eqlIgnoreCase(name, constraint);
    return name.len > constraint.len and name[name.len - constraint.len - 1] == '.' and
        std.ascii.endsWithIgnoreCase(name, constraint);
}

fn trimDot(name: []const u8) []const u8 {
    return if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

/// An IP constraint is an address and a mask: 8 bytes for IPv4, 32 bytes for IPv6. An
/// address of the other family is outside.
pub fn ipWithin(constraint: []const u8, address: []const u8) bool {
    if (constraint.len != 2 * address.len) return false;
    const network = constraint[0..address.len];
    const mask = constraint[address.len..];
    for (address, network, mask) |a, n, m| if (a & m != n & m) return false;
    return true;
}

/// A directory name constraint covers each name whose first relative distinguished names
/// are equal to those of the constraint. Both values are the content of a `Name`.
pub fn directoryWithin(constraint: []const u8, name: []const u8) Error!bool {
    var c_it: der.Iterator = .{ .rest = constraint };
    var n_it: der.Iterator = .{ .rest = name };
    while (c_it.next() catch return error.Malformed) |c_rdn| {
        const n_rdn = (n_it.next() catch return error.Malformed) orelse return false;
        if (!try rdnEqual(c_rdn, n_rdn)) return false;
    }
    return true;
}

fn countRdns(name: []const u8) Error!usize {
    var it: der.Iterator = .{ .rest = name };
    var count: usize = 0;
    while (it.next() catch return error.Malformed) |rdn| {
        if (rdn.tag != der.tag_set) return error.Malformed;
        count += 1;
    }
    return count;
}

/// Two relative distinguished names are equal when they have the same attributes, in any
/// order (RFC 5280 section 7.1).
fn rdnEqual(a: der.Element, b: der.Element) Error!bool {
    if (a.tag != der.tag_set or b.tag != der.tag_set) return error.Malformed;
    var count_a: usize = 0;
    var it_a = a.children();
    while (it_a.next() catch return error.Malformed) |_| count_a += 1;
    var count_b: usize = 0;
    var it_b = b.children();
    while (it_b.next() catch return error.Malformed) |_| count_b += 1;
    if (count_a != count_b) return false;
    it_a = a.children();
    outer: while (it_a.next() catch return error.Malformed) |atv_a| {
        it_b = b.children();
        while (it_b.next() catch return error.Malformed) |atv_b| {
            if (try atvEqual(atv_a, atv_b)) continue :outer;
        }
        return false;
    }
    return true;
}

fn atvEqual(a: der.Element, b: der.Element) Error!bool {
    var parts_a = a.children();
    var parts_b = b.children();
    const type_a = parts_a.require() catch return error.Malformed;
    const value_a = parts_a.require() catch return error.Malformed;
    const type_b = parts_b.require() catch return error.Malformed;
    const value_b = parts_b.require() catch return error.Malformed;
    if (type_a.tag != der.tag_oid or type_b.tag != der.tag_oid) return error.Malformed;
    if (!std.mem.eql(u8, type_a.content, type_b.content)) return false;
    if (isText(value_a.tag) and isText(value_b.tag)) return foldedEql(value_a.content, value_b.content);
    return std.mem.eql(u8, value_a.raw, value_b.raw);
}

/// The string types that RFC 5280 section 7.1 compares without regard to the type.
fn isText(tag: u8) bool {
    return switch (tag) {
        0x0c, 0x13, 0x16, 0x1a => true, // UTF8String, PrintableString, IA5String, VisibleString
        else => false,
    };
}

/// Compare two strings without regard to ASCII case. Spaces at the start and at the end do
/// not count, and a run of spaces counts as one space.
fn foldedEql(a: []const u8, b: []const u8) bool {
    var it_a: Folded = .init(a);
    var it_b: Folded = .init(b);
    while (true) {
        const ca = it_a.next();
        const cb = it_b.next();
        if (ca == null or cb == null) return ca == null and cb == null;
        if (ca.? != cb.?) return false;
    }
}

const Folded = struct {
    text: []const u8,
    index: usize = 0,

    fn init(text: []const u8) Folded {
        return .{ .text = std.mem.trim(u8, text, " ") };
    }

    fn next(self: *Folded) ?u8 {
        if (self.index >= self.text.len) return null;
        const c = self.text[self.index];
        self.index += 1;
        if (c == ' ') {
            while (self.index < self.text.len and self.text[self.index] == ' ') self.index += 1;
        }
        return std.ascii.toLower(c);
    }
};

/// An email constraint is a mailbox (`user@host`), a host (`host`) or a domain
/// (`.domain`). The local part of a mailbox counts the case, the host does not. The
/// function cannot compare a name without `@`, so the check refuses it.
pub fn emailWithin(constraint: []const u8, name: []const u8) Error!bool {
    const at = std.mem.findScalarLast(u8, name, '@') orelse return error.NameNotPermitted;
    if (at == 0 or at + 1 == name.len) return error.NameNotPermitted;
    const host = name[at + 1 ..];
    if (constraint.len == 0) return true;
    if (std.mem.findScalarLast(u8, constraint, '@')) |c_at| {
        return std.mem.eql(u8, constraint[0..c_at], name[0..at]) and
            std.ascii.eqlIgnoreCase(constraint[c_at + 1 ..], host);
    }
    if (constraint[0] == '.') return host.len > constraint.len and std.ascii.endsWithIgnoreCase(host, constraint);
    return std.ascii.eqlIgnoreCase(host, constraint);
}

/// A URI constraint is a host (`host`) or a domain (`.domain`). It applies to the host of
/// the URI. The function cannot compare a URI without a host or with an IP address as
/// host, so the check refuses it.
pub fn uriWithin(constraint: []const u8, uri: []const u8) Error!bool {
    const host = uriHost(uri) orelse return error.NameNotPermitted;
    if (constraint.len == 0) return true;
    if (constraint[0] == '.') return host.len > constraint.len and std.ascii.endsWithIgnoreCase(host, constraint);
    return std.ascii.eqlIgnoreCase(host, constraint);
}

/// The host of a URI with an authority (RFC 3986 section 3.2.2), or null. The function
/// returns null for an IP literal.
fn uriHost(uri: []const u8) ?[]const u8 {
    const start = (std.mem.find(u8, uri, "://") orelse return null) + 3;
    var authority = uri[start..];
    if (std.mem.findAny(u8, authority, "/?#")) |end| authority = authority[0..end];
    if (std.mem.findScalarLast(u8, authority, '@')) |at| authority = authority[at + 1 ..];
    if (authority.len > 0 and authority[0] == '[') return null; // IPv6 literal
    if (std.mem.findScalarLast(u8, authority, ':')) |colon| authority = authority[0..colon];
    const host = trimDot(authority);
    if (host.len == 0) return null;
    if (std.Io.net.IpAddress.parse(host, 0)) |_| return null else |_| {}
    return host;
}

// -- Tests -----------------------------------------------------------------------------------

test "DNS name constraints" {
    try std.testing.expect(dnsWithin("example.com", "example.com"));
    try std.testing.expect(dnsWithin("example.com", "www.example.com"));
    try std.testing.expect(dnsWithin("example.com", "a.b.EXAMPLE.com"));
    try std.testing.expect(dnsWithin("Example.COM", "www.example.com."));
    try std.testing.expect(!dnsWithin("example.com", "badexample.com"));
    try std.testing.expect(!dnsWithin("example.com", "example.org"));
    try std.testing.expect(!dnsWithin("www.example.com", "example.com"));
    // The leading period: subdomains only.
    try std.testing.expect(dnsWithin(".example.com", "www.example.com"));
    try std.testing.expect(!dnsWithin(".example.com", "example.com"));
    try std.testing.expect(!dnsWithin(".example.com", "badexample.com"));
    // The empty constraint covers every name.
    try std.testing.expect(dnsWithin("", "anything.test"));
    // A wildcard name is text: it is below example.com.
    try std.testing.expect(dnsWithin("example.com", "*.example.com"));
}

test "IP address constraints" {
    const net10 = [_]u8{ 10, 0, 0, 0, 255, 0, 0, 0 };
    try std.testing.expect(ipWithin(&net10, &.{ 10, 1, 2, 3 }));
    try std.testing.expect(!ipWithin(&net10, &.{ 11, 1, 2, 3 }));
    const host = [_]u8{ 127, 0, 0, 1, 255, 255, 255, 255 };
    try std.testing.expect(ipWithin(&host, &.{ 127, 0, 0, 1 }));
    try std.testing.expect(!ipWithin(&host, &.{ 127, 0, 0, 2 }));
    var net6: [32]u8 = @splat(0);
    net6[0] = 0xfd;
    net6[16] = 0xff;
    net6[17] = 0xff;
    var inside: [16]u8 = @splat(0);
    inside[0] = 0xfd;
    inside[15] = 1;
    try std.testing.expect(ipWithin(&net6, &inside));
    inside[1] = 1;
    try std.testing.expect(!ipWithin(&net6, &inside));
    // An IPv4 address against an IPv6 constraint, and the reverse.
    try std.testing.expect(!ipWithin(&net6, &.{ 10, 1, 2, 3 }));
    try std.testing.expect(!ipWithin(&net10, &inside));
}

test "email and URI constraints" {
    try std.testing.expect(try emailWithin("example.com", "dev@example.com"));
    try std.testing.expect(try emailWithin("example.com", "dev@EXAMPLE.com"));
    try std.testing.expect(!try emailWithin("example.com", "dev@www.example.com"));
    try std.testing.expect(try emailWithin(".example.com", "dev@www.example.com"));
    try std.testing.expect(!try emailWithin(".example.com", "dev@example.com"));
    try std.testing.expect(try emailWithin("dev@example.com", "dev@Example.com"));
    try std.testing.expect(!try emailWithin("dev@example.com", "Dev@example.com"));
    try std.testing.expectError(error.NameNotPermitted, emailWithin("example.com", "no-at-sign"));

    try std.testing.expect(try uriWithin(".example.com", "https://api.example.com/mcp"));
    try std.testing.expect(try uriWithin(".example.com", "https://user@api.example.com:8443/x?y#z"));
    try std.testing.expect(!try uriWithin(".example.com", "https://example.com/"));
    try std.testing.expect(try uriWithin("example.com", "https://EXAMPLE.com/"));
    try std.testing.expect(!try uriWithin("example.com", "https://api.example.com/"));
    try std.testing.expectError(error.NameNotPermitted, uriWithin(".example.com", "urn:example:thing"));
    try std.testing.expectError(error.NameNotPermitted, uriWithin(".example.com", "https://[::1]/"));
    try std.testing.expectError(error.NameNotPermitted, uriWithin(".example.com", "https://10.1.2.3/"));
}

test "directory name constraints compare the leading relative distinguished names" {
    // SET { SEQUENCE { OID organizationName, PrintableString "Zig SD" } }
    const o_printable = "\x31\x0f\x30\x0d\x06\x03\x55\x04\x0a\x13\x06Zig SD";
    const o_utf8 = "\x31\x0f\x30\x0d\x06\x03\x55\x04\x0a\x0c\x06zig sd";
    const o_other = "\x31\x0f\x30\x0d\x06\x03\x55\x04\x0a\x0c\x06zig sx";
    const cn = "\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03www";
    try std.testing.expect(try directoryWithin(o_printable, o_printable ++ cn));
    try std.testing.expect(try directoryWithin(o_printable, o_utf8 ++ cn));
    try std.testing.expect(!try directoryWithin(o_printable, o_other ++ cn));
    try std.testing.expect(!try directoryWithin(o_printable, cn ++ o_printable));
    try std.testing.expect(!try directoryWithin(o_printable ++ cn, o_printable));
    try std.testing.expect(try directoryWithin("", cn));
    try std.testing.expect(foldedEql("  Zig   SDK ", "zig sdk"));
    try std.testing.expect(!foldedEql("zig sdk", "zigsdk"));
}

test "the extension parser refuses a maximum, a minimum other than zero and an empty list" {
    // permittedSubtrees with one dNSName "a.test".
    _ = try NameConstraints.parse("\x30\x0c\xa0\x0a\x30\x08\x82\x06a.test", true);
    // With minimum 0 written out.
    _ = try NameConstraints.parse("\x30\x0f\xa0\x0d\x30\x0b\x82\x06a.test\x80\x01\x00", true);
    try std.testing.expectError(error.Malformed, NameConstraints.parse("\x30\x0f\xa0\x0d\x30\x0b\x82\x06a.test\x80\x01\x01", true));
    try std.testing.expectError(error.Malformed, NameConstraints.parse("\x30\x0f\xa0\x0d\x30\x0b\x82\x06a.test\x81\x01\x05", true));
    try std.testing.expectError(error.Malformed, NameConstraints.parse("\x30\x00", true));
    try std.testing.expectError(error.Malformed, NameConstraints.parse("\x30\x02\xa0\x00", true));
    // An IP constraint without a mask.
    try std.testing.expectError(error.Malformed, NameConstraints.parse("\x30\x08\xa0\x06\x30\x04\x87\x02\x0a\x00", true));
    // excludedSubtrees before permittedSubtrees.
    try std.testing.expectError(error.Malformed, NameConstraints.parse("\x30\x18\xa1\x0a\x30\x08\x82\x06a.test\xa0\x0a\x30\x08\x82\x06b.test", true));
}

test "a constraint form that the SDK cannot check fails only when critical" {
    // permittedSubtrees with one registeredID 1.2.3.4.
    const value = "\x30\x09\xa0\x07\x30\x05\x88\x03\x2a\x03\x04";
    const critical = try NameConstraints.parse(value, true);
    const rid: GeneralName = .{ .form = .registered_id, .value = "\x2a\x03\x04\x05" };
    try std.testing.expectError(error.UnsupportedConstraint, critical.checkName(rid));
    const not_critical = try NameConstraints.parse(value, false);
    try not_critical.checkName(rid);
    // A DNS name is not of that form, so no constraint applies to it.
    try critical.checkName(.{ .form = .dns_name, .value = "www.example.com" });
}
