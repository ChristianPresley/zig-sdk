//! A certificate chain with its private key, pre-encoded as a TLS 1.3 Certificate message.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = @import("der.zig");
const pem = @import("pem.zig");
const PrivateKey = @import("PrivateKey.zig");

const CertChain = @This();

gpa: Allocator,
/// DER certificates, leaf first.
certs: [][]u8,
key: PrivateKey,
/// The complete `Certificate` handshake message (type, length and body) with an empty
/// certificate request context.
handshake_message: []u8,
/// The DNS names and IP addresses of the leaf, used to answer server name indication.
leaf_common_name: []u8,

pub const max_chain_bytes = 64 << 10;
pub const max_certs = 8;

pub const Error = error{
    OutOfMemory,
    InvalidEncoding,
    NoCertificateFound,
    NoKeyFound,
    ChainTooLarge,
    /// The private key does not match the leaf certificate public key.
    KeyMismatch,
    UnsupportedKey,
    InvalidKey,
    /// The leaf certificate could not be parsed.
    InvalidCertificate,
};

/// Load a chain from PEM text: every `CERTIFICATE` block of `cert_pem` (leaf first) and the
/// first private key of `key_pem`.
pub fn fromPem(gpa: Allocator, cert_pem: []const u8, key_pem: []const u8) Error!CertChain {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |c| gpa.free(c);
        list.deinit(gpa);
    }
    var it: pem.Iterator = .init(cert_pem);
    while (it.nextLabeled("CERTIFICATE")) |block| {
        if (list.items.len == max_certs) return error.ChainTooLarge;
        const bytes = block.decode(gpa) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidEncoding => return error.InvalidEncoding,
        };
        errdefer gpa.free(bytes);
        try list.append(gpa, bytes);
    }
    if (list.items.len == 0) return error.NoCertificateFound;
    var key = PrivateKey.parsePem(gpa, key_pem) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidEncoding => return error.InvalidEncoding,
        error.UnsupportedKey => return error.UnsupportedKey,
        error.InvalidKey => return error.InvalidKey,
        error.NoKeyFound => return error.NoKeyFound,
    };
    errdefer key.deinit();
    const certs = try list.toOwnedSlice(gpa);
    errdefer {
        for (certs) |c| gpa.free(c);
        gpa.free(certs);
    }
    return fromDerOwned(gpa, certs, key);
}

/// Build a chain from owned DER certificates and a parsed key. Ownership moves to the chain.
pub fn fromDerOwned(gpa: Allocator, certs: [][]u8, key: PrivateKey) Error!CertChain {
    var total: usize = 0;
    for (certs) |c| total += c.len;
    if (total > max_chain_bytes) return error.ChainTooLarge;

    // Check that the key matches the leaf.
    const leaf: Certificate = .{ .buffer = certs[0], .index = 0 };
    const parsed = leaf.parse() catch return error.InvalidCertificate;
    var pk_buf: [97]u8 = undefined;
    const pk = key.publicKeyBytes(&pk_buf);
    if (!std.mem.eql(u8, pk, parsed.pubKey())) return error.KeyMismatch;
    const algo_ok = switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| switch (curve) {
            .X9_62_prime256v1 => key.kind() == .ecdsa_p256,
            .secp384r1 => key.kind() == .ecdsa_p384,
            else => false,
        },
        .curveEd25519 => key.kind() == .ed25519,
        else => false,
    };
    if (!algo_ok) return error.KeyMismatch;
    const common_name = try gpa.dupe(u8, parsed.commonName());
    errdefer gpa.free(common_name);

    // Encode: type(1) len(3) ctx_len(1)=0 list_len(3) { cert_len(3) cert ext_len(2)=0 }*
    const list_len = total + certs.len * 5;
    const body_len = 1 + 3 + list_len;
    const msg = try gpa.alloc(u8, 4 + body_len);
    errdefer gpa.free(msg);
    msg[0] = 0x0b; // certificate
    std.mem.writeInt(u24, msg[1..4], @intCast(body_len), .big);
    msg[4] = 0;
    std.mem.writeInt(u24, msg[5..8], @intCast(list_len), .big);
    var i: usize = 8;
    for (certs) |c| {
        std.mem.writeInt(u24, msg[i..][0..3], @intCast(c.len), .big);
        i += 3;
        @memcpy(msg[i..][0..c.len], c);
        i += c.len;
        msg[i] = 0;
        msg[i + 1] = 0;
        i += 2;
    }
    std.debug.assert(i == msg.len);
    return .{ .gpa = gpa, .certs = certs, .key = key, .handshake_message = msg, .leaf_common_name = common_name };
}

pub fn deinit(self: *CertChain) void {
    for (self.certs) |c| self.gpa.free(c);
    self.gpa.free(self.certs);
    self.gpa.free(self.handshake_message);
    self.gpa.free(self.leaf_common_name);
    self.key.deinit();
    self.* = undefined;
}

/// True when the leaf certificate names `host` (common name or subject alternative name).
pub fn matchesHost(self: *const CertChain, host: []const u8) bool {
    const leaf: Certificate = .{ .buffer = self.certs[0], .index = 0 };
    const parsed = leaf.parse() catch return false;
    parsed.verifyHostName(host) catch return false;
    return true;
}

/// Load a chain from two PEM files.
pub fn loadFiles(gpa: Allocator, io: std.Io, cert_path: []const u8, key_path: []const u8) (Error || std.Io.Dir.ReadFileAllocError)!CertChain {
    const cert_pem = try std.Io.Dir.cwd().readFileAlloc(io, cert_path, gpa, .limited(max_chain_bytes * 2));
    defer gpa.free(cert_pem);
    const key_pem = try std.Io.Dir.cwd().readFileAlloc(io, key_path, gpa, .limited(64 << 10));
    defer {
        std.crypto.secureZero(u8, key_pem);
        gpa.free(key_pem);
    }
    return fromPem(gpa, cert_pem, key_pem);
}

test "load fixture chains" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct { cert: []const u8, key: []const u8, count: usize }{
        .{ .cert = "test/fixtures/tls/pem/p256.crt", .key = "test/fixtures/tls/pem/p256.key", .count = 1 },
        .{ .cert = "test/fixtures/tls/pem/p384.crt", .key = "test/fixtures/tls/pem/p384.key", .count = 1 },
        .{ .cert = "test/fixtures/tls/pem/ed25519.crt", .key = "test/fixtures/tls/pem/ed25519.key", .count = 1 },
        .{ .cert = "test/fixtures/tls/pem/chain.crt", .key = "test/fixtures/tls/pem/chain-leaf.key", .count = 2 },
    };
    for (cases) |case| {
        var chain = try loadFiles(gpa, io, case.cert, case.key);
        defer chain.deinit();
        try std.testing.expectEqual(case.count, chain.certs.len);
        try std.testing.expectEqual(0x0b, chain.handshake_message[0]);
        try std.testing.expect(chain.matchesHost("localhost"));
        try std.testing.expect(!chain.matchesHost("example.com"));
    }
    // A key that belongs to another certificate is rejected.
    try std.testing.expectError(error.KeyMismatch, loadFiles(gpa, io, "test/fixtures/tls/pem/p256.crt", "test/fixtures/tls/pem/p384.key"));
}
