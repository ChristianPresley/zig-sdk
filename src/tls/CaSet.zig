//! A set of trust anchors for the TLS client: the certificates a server chain must lead to.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const pem = @import("pem.zig");
const pss = @import("pss.zig");
const x509 = @import("x509.zig");

const CaSet = @This();

gpa: Allocator,
/// DER certificates, each parsed once at insertion.
certs: std.ArrayList([]u8) = .empty,

pub const max_anchors = 4096;

pub const AddError = Allocator.Error || error{ InvalidCertificate, TooManyAnchors };

pub fn init(gpa: Allocator) CaSet {
    return .{ .gpa = gpa };
}

pub fn deinit(self: *CaSet) void {
    for (self.certs.items) |c| self.gpa.free(c);
    self.certs.deinit(self.gpa);
    self.* = undefined;
}

pub fn count(self: *const CaSet) usize {
    return self.certs.items.len;
}

/// Add one DER certificate. The set copies the bytes. The certificate can have an
/// RSASSA-PSS signature.
pub fn addDer(self: *CaSet, bytes: []const u8) AddError!void {
    if (self.certs.items.len >= max_anchors) return error.TooManyAnchors;
    x509.precheck(bytes) catch return error.InvalidCertificate;
    _ = pss.parseCertificate(.{ .buffer = bytes, .index = 0 }) catch return error.InvalidCertificate;
    const copy = try self.gpa.dupe(u8, bytes);
    errdefer self.gpa.free(copy);
    try self.certs.append(self.gpa, copy);
}

/// Add every `CERTIFICATE` block of a PEM text.
pub fn addPem(self: *CaSet, text: []const u8) AddError!void {
    var it: pem.Iterator = .init(text);
    var found = false;
    while (it.nextLabeled("CERTIFICATE")) |block| {
        const bytes = block.decode(self.gpa) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidEncoding => return error.InvalidCertificate,
        };
        defer self.gpa.free(bytes);
        try self.addDer(bytes);
        found = true;
    }
    if (!found) return error.InvalidCertificate;
}

/// Add the certificates of a PEM file.
pub fn addFile(self: *CaSet, io: std.Io, path: []const u8) (AddError || std.Io.Dir.ReadFileAllocError)!void {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, self.gpa, .limited(16 << 20));
    defer self.gpa.free(text);
    try self.addPem(text);
}

/// The anchor whose subject is `name`, parsed.
pub fn findIssuer(self: *const CaSet, name: []const u8) ?Certificate.Parsed {
    for (self.certs.items) |bytes| {
        const parsed = pss.parseCertificate(.{ .buffer = bytes, .index = 0 }) catch continue;
        if (std.mem.eql(u8, parsed.subject(), name)) return parsed;
    }
    return null;
}

test "load the fixture CA" {
    var set: CaSet = .init(std.testing.allocator);
    defer set.deinit();
    try set.addFile(std.testing.io, "test/fixtures/tls/pem/ca.crt");
    try std.testing.expectEqual(1, set.count());
    try std.testing.expectError(error.InvalidCertificate, set.addPem("no certificates here"));
    const leaf_text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "test/fixtures/tls/pem/chain-leaf.crt", std.testing.allocator, .limited(1 << 16));
    defer std.testing.allocator.free(leaf_text);
    var it: pem.Iterator = .init(leaf_text);
    const leaf_der = try it.nextLabeled("CERTIFICATE").?.decode(std.testing.allocator);
    defer std.testing.allocator.free(leaf_der);
    const leaf: Certificate = .{ .buffer = leaf_der, .index = 0 };
    const parsed = try leaf.parse();
    try std.testing.expect(set.findIssuer(parsed.issuer()) != null);
    try std.testing.expect(set.findIssuer(parsed.subject()) == null);
}

test "an anchor with an RSASSA-PSS signature" {
    var set: CaSet = .init(std.testing.allocator);
    defer set.deinit();
    try set.addFile(std.testing.io, "test/fixtures/tls/pem/rsa-pss.crt");
    try std.testing.expectEqual(1, set.count());
    const found = set.findIssuer(set.findIssuer("\x31\x20\x30\x1e\x06\x03\x55\x04\x03\x0c\x17zig-sdk RSA-PSS test CA").?.subject());
    try std.testing.expectEqual(std.crypto.Certificate.Parsed.PubKeyAlgo.rsassa_pss, found.?.pub_key_algo);
}
