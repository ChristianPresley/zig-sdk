//! Ephemeral (EC)DHE key shares for the supported groups.
const std = @import("std");
const crypto = std.crypto;

const X25519 = crypto.dh.X25519;
const P256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = crypto.sign.ecdsa.EcdsaP384Sha384;

pub const Group = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    x25519 = 0x001d,

    pub fn fromWire(value: u16) ?Group {
        return switch (value) {
            0x0017 => .secp256r1,
            0x0018 => .secp384r1,
            0x001d => .x25519,
            else => null,
        };
    }

    pub fn wire(g: Group) u16 {
        return @intFromEnum(g);
    }
};

pub const default_groups: []const Group = &.{ .x25519, .secp256r1, .secp384r1 };

pub const max_public_len = 97;
pub const max_shared_len = 48;

pub const KeyShare = union(Group) {
    secp256r1: P256.KeyPair,
    secp384r1: P384.KeyPair,
    x25519: X25519.KeyPair,

    /// Generate a fresh key pair from secure entropy.
    pub fn generate(io: std.Io, g: Group) error{EntropyUnavailable}!KeyShare {
        var seed: [48]u8 = undefined;
        defer crypto.secureZero(u8, &seed);
        var attempts: u8 = 0;
        while (attempts < 8) : (attempts += 1) {
            io.randomSecure(&seed) catch return error.EntropyUnavailable;
            switch (g) {
                .x25519 => return .{ .x25519 = X25519.KeyPair.generateDeterministic(seed[0..32].*) catch continue },
                .secp256r1 => return .{ .secp256r1 = P256.KeyPair.generateDeterministic(seed[0..32].*) catch continue },
                .secp384r1 => return .{ .secp384r1 = P384.KeyPair.generateDeterministic(seed[0..48].*) catch continue },
            }
        }
        return error.EntropyUnavailable;
    }

    pub fn group(self: KeyShare) Group {
        return self;
    }

    /// The public key in the `KeyShareEntry.key_exchange` encoding.
    pub fn publicBytes(self: *const KeyShare, buf: *[max_public_len]u8) []const u8 {
        switch (self.*) {
            .x25519 => |kp| {
                @memcpy(buf[0..32], &kp.public_key);
                return buf[0..32];
            },
            .secp256r1 => |kp| {
                const p = kp.public_key.toUncompressedSec1();
                @memcpy(buf[0..p.len], &p);
                return buf[0..p.len];
            },
            .secp384r1 => |kp| {
                const p = kp.public_key.toUncompressedSec1();
                @memcpy(buf[0..p.len], &p);
                return buf[0..p.len];
            },
        }
    }

    pub const ExchangeError = error{
        /// The peer key has the wrong length or is not a valid point.
        IllegalParameter,
        /// The shared secret is the identity element (a low-order or invalid key).
        DecryptError,
    };

    /// Compute the shared secret with the peer's public key.
    pub fn sharedSecret(self: *const KeyShare, peer: []const u8, out: *[max_shared_len]u8) ExchangeError![]const u8 {
        switch (self.*) {
            .x25519 => |kp| {
                if (peer.len != X25519.public_length) return error.IllegalParameter;
                const s = X25519.scalarmult(kp.secret_key, peer[0..X25519.public_length].*) catch return error.DecryptError;
                @memcpy(out[0..s.len], &s);
                return out[0..s.len];
            },
            .secp256r1 => |kp| {
                if (peer.len != P256.PublicKey.uncompressed_sec1_encoded_length or peer[0] != 4) return error.IllegalParameter;
                const pk = P256.PublicKey.fromSec1(peer) catch return error.IllegalParameter;
                const m = pk.p.mul(kp.secret_key.bytes, .big) catch return error.DecryptError;
                const x = m.affineCoordinates().x.toBytes(.big);
                @memcpy(out[0..x.len], &x);
                return out[0..x.len];
            },
            .secp384r1 => |kp| {
                if (peer.len != P384.PublicKey.uncompressed_sec1_encoded_length or peer[0] != 4) return error.IllegalParameter;
                const pk = P384.PublicKey.fromSec1(peer) catch return error.IllegalParameter;
                const m = pk.p.mul(kp.secret_key.bytes, .big) catch return error.DecryptError;
                const x = m.affineCoordinates().x.toBytes(.big);
                @memcpy(out[0..x.len], &x);
                return out[0..x.len];
            },
        }
    }

    pub fn wipe(self: *KeyShare) void {
        crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

test "key agreement round trip for every group" {
    const io = std.testing.io;
    for (default_groups) |g| {
        var a = try KeyShare.generate(io, g);
        defer a.wipe();
        var b = try KeyShare.generate(io, g);
        defer b.wipe();
        var pa: [max_public_len]u8 = undefined;
        var pb: [max_public_len]u8 = undefined;
        var sa: [max_shared_len]u8 = undefined;
        var sb: [max_shared_len]u8 = undefined;
        const shared_a = try a.sharedSecret(b.publicBytes(&pb), &sa);
        const shared_b = try b.sharedSecret(a.publicBytes(&pa), &sb);
        try std.testing.expectEqualSlices(u8, shared_a, shared_b);
    }
}

test "rejects malformed and low-order peer keys" {
    const io = std.testing.io;
    var x = try KeyShare.generate(io, .x25519);
    defer x.wipe();
    var out: [max_shared_len]u8 = undefined;
    try std.testing.expectError(error.IllegalParameter, x.sharedSecret(&[_]u8{1} ** 31, &out));
    try std.testing.expectError(error.DecryptError, x.sharedSecret(&[_]u8{0} ** 32, &out));
    var p = try KeyShare.generate(io, .secp256r1);
    defer p.wipe();
    try std.testing.expectError(error.IllegalParameter, p.sharedSecret(&[_]u8{4} ++ [_]u8{1} ** 64, &out));
    try std.testing.expectError(error.IllegalParameter, p.sharedSecret(&[_]u8{2} ** 33, &out));
}
