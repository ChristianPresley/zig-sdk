//! Ephemeral key shares for the supported groups: the (EC)DHE groups and the post-quantum
//! hybrid X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem).
const std = @import("std");
const crypto = std.crypto;

const X25519 = crypto.dh.X25519;
const P256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const MLKem768 = crypto.kem.ml_kem.MLKem768;

pub const Group = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    x25519 = 0x001d,
    /// The hybrid of ML-KEM-768 and X25519. The ML-KEM part comes first in every encoding.
    x25519_mlkem768 = 0x11ec,

    pub fn fromWire(value: u16) ?Group {
        return switch (value) {
            0x0017 => .secp256r1,
            0x0018 => .secp384r1,
            0x001d => .x25519,
            0x11ec => .x25519_mlkem768,
            else => null,
        };
    }

    pub fn wire(g: Group) u16 {
        return @intFromEnum(g);
    }

    /// True for a group that has a post-quantum part.
    pub fn isHybrid(g: Group) bool {
        return g == .x25519_mlkem768;
    }
};

/// The default preference order. The hybrid group comes first.
pub const default_groups: []const Group = &.{ .x25519_mlkem768, .x25519, .secp256r1, .secp384r1 };

/// The client share of X25519MLKEM768: the ML-KEM-768 encapsulation key, then the X25519 key.
pub const hybrid_client_share_len = MLKem768.PublicKey.encoded_length + X25519.public_length;
/// The server share of X25519MLKEM768: the ML-KEM-768 ciphertext, then the X25519 key.
pub const hybrid_server_share_len = MLKem768.ciphertext_length + X25519.public_length;
pub const max_public_len: usize = @max(hybrid_client_share_len, hybrid_server_share_len);
pub const max_shared_len = MLKem768.shared_length + X25519.shared_length;

/// The client half of X25519MLKEM768.
pub const Hybrid = struct {
    mlkem: MLKem768.SecretKey,
    encapsulation_key: [MLKem768.PublicKey.encoded_length]u8,
    x25519: X25519.KeyPair,
};

pub const ExchangeError = error{
    /// The peer key has the wrong length or is not a valid key.
    IllegalParameter,
    /// The shared secret is the identity element (a low-order or invalid key).
    DecryptError,
};

pub const KeyShare = union(Group) {
    secp256r1: P256.KeyPair,
    secp384r1: P384.KeyPair,
    x25519: X25519.KeyPair,
    x25519_mlkem768: Hybrid,

    /// Generate a fresh key pair from secure entropy. This is the client side of a hybrid
    /// group and either side of an (EC)DHE group.
    pub fn generate(io: std.Io, g: Group) error{EntropyUnavailable}!KeyShare {
        var seed: [MLKem768.seed_length + X25519.seed_length]u8 = undefined;
        defer crypto.secureZero(u8, &seed);
        var attempts: u8 = 0;
        while (attempts < 8) : (attempts += 1) {
            io.randomSecure(&seed) catch return error.EntropyUnavailable;
            switch (g) {
                .x25519 => return .{ .x25519 = X25519.KeyPair.generateDeterministic(seed[0..32].*) catch continue },
                .secp256r1 => return .{ .secp256r1 = P256.KeyPair.generateDeterministic(seed[0..32].*) catch continue },
                .secp384r1 => return .{ .secp384r1 = P384.KeyPair.generateDeterministic(seed[0..48].*) catch continue },
                .x25519_mlkem768 => {
                    var kp = MLKem768.KeyPair.generateDeterministic(seed[0..MLKem768.seed_length].*) catch continue;
                    defer crypto.secureZero(u8, std.mem.asBytes(&kp));
                    const x = X25519.KeyPair.generateDeterministic(seed[MLKem768.seed_length..][0..X25519.seed_length].*) catch continue;
                    return .{ .x25519_mlkem768 = .{
                        .mlkem = kp.secret_key,
                        .encapsulation_key = kp.public_key.toBytes(),
                        .x25519 = x,
                    } };
                },
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
            .x25519_mlkem768 => |*h| {
                const ek_len = h.encapsulation_key.len;
                @memcpy(buf[0..ek_len], &h.encapsulation_key);
                @memcpy(buf[ek_len..][0..X25519.public_length], &h.x25519.public_key);
                return buf[0..hybrid_client_share_len];
            },
        }
    }

    /// Compute the shared secret with the peer's public key. For the hybrid group this is
    /// the client side: `peer` is the server share with the ML-KEM ciphertext.
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
            .x25519_mlkem768 => |*h| {
                if (peer.len != hybrid_server_share_len) return error.IllegalParameter;
                const ct = peer[0..MLKem768.ciphertext_length];
                var ss_kem = h.mlkem.decaps(ct) catch return error.DecryptError;
                defer crypto.secureZero(u8, &ss_kem);
                var ss_x = X25519.scalarmult(h.x25519.secret_key, peer[MLKem768.ciphertext_length..][0..X25519.public_length].*) catch return error.DecryptError;
                defer crypto.secureZero(u8, &ss_x);
                @memcpy(out[0..ss_kem.len], &ss_kem);
                @memcpy(out[ss_kem.len..][0..ss_x.len], &ss_x);
                return out[0..max_shared_len];
            },
        }
    }

    pub fn wipe(self: *KeyShare) void {
        crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const RespondError = ExchangeError || error{EntropyUnavailable};

/// The server answer to a client key share: the server share and the shared secret.
pub const Response = struct {
    public: []const u8,
    shared: []const u8,
};

/// Answer the client share `peer` for `g` as the server. An (EC)DHE group uses a fresh key
/// pair. The hybrid group encapsulates to the client ML-KEM key and adds a fresh X25519 key.
pub fn respond(io: std.Io, g: Group, peer: []const u8, public_out: *[max_public_len]u8, shared_out: *[max_shared_len]u8) RespondError!Response {
    if (g != .x25519_mlkem768) {
        var share = try KeyShare.generate(io, g);
        defer share.wipe();
        const shared = try share.sharedSecret(peer, shared_out);
        return .{ .public = share.publicBytes(public_out), .shared = shared };
    }
    if (peer.len != hybrid_client_share_len) return error.IllegalParameter;
    const ek_len = MLKem768.PublicKey.encoded_length;
    // The encapsulation key check of FIPS 203: every coefficient must be reduced.
    const ek = MLKem768.PublicKey.fromBytes(peer[0..ek_len]) catch return error.IllegalParameter;
    var seed: [MLKem768.encaps_seed_length + X25519.seed_length]u8 = undefined;
    defer crypto.secureZero(u8, &seed);
    var attempts: u8 = 0;
    while (attempts < 8) : (attempts += 1) {
        io.randomSecure(&seed) catch return error.EntropyUnavailable;
        var x = X25519.KeyPair.generateDeterministic(seed[MLKem768.encaps_seed_length..][0..X25519.seed_length].*) catch continue;
        defer crypto.secureZero(u8, std.mem.asBytes(&x));
        var ss_x = X25519.scalarmult(x.secret_key, peer[ek_len..][0..X25519.public_length].*) catch return error.DecryptError;
        defer crypto.secureZero(u8, &ss_x);
        var encapsulated = ek.encapsDeterministic(seed[0..MLKem768.encaps_seed_length]);
        defer crypto.secureZero(u8, &encapsulated.shared_secret);
        @memcpy(public_out[0..MLKem768.ciphertext_length], &encapsulated.ciphertext);
        @memcpy(public_out[MLKem768.ciphertext_length..][0..X25519.public_length], &x.public_key);
        @memcpy(shared_out[0..MLKem768.shared_length], &encapsulated.shared_secret);
        @memcpy(shared_out[MLKem768.shared_length..][0..X25519.shared_length], &ss_x);
        return .{ .public = public_out[0..hybrid_server_share_len], .shared = shared_out[0..max_shared_len] };
    }
    return error.EntropyUnavailable;
}

test "key agreement round trip for every group" {
    const io = std.testing.io;
    for (default_groups) |g| {
        var a = try KeyShare.generate(io, g);
        defer a.wipe();
        var pa: [max_public_len]u8 = undefined;
        var pb: [max_public_len]u8 = undefined;
        var sa: [max_shared_len]u8 = undefined;
        var sb: [max_shared_len]u8 = undefined;
        const answer = try respond(io, g, a.publicBytes(&pa), &pb, &sb);
        const shared_a = try a.sharedSecret(answer.public, &sa);
        try std.testing.expectEqualSlices(u8, answer.shared, shared_a);
    }
}

test "hybrid layout: ML-KEM first, then X25519" {
    const io = std.testing.io;
    var a = try KeyShare.generate(io, .x25519_mlkem768);
    defer a.wipe();
    var pa: [max_public_len]u8 = undefined;
    const client_share = a.publicBytes(&pa);
    try std.testing.expectEqual(1216, client_share.len);
    try std.testing.expectEqualSlices(u8, &a.x25519_mlkem768.x25519.public_key, client_share[1184..]);
    var pb: [max_public_len]u8 = undefined;
    var sb: [max_shared_len]u8 = undefined;
    const answer = try respond(io, .x25519_mlkem768, client_share, &pb, &sb);
    try std.testing.expectEqual(1120, answer.public.len);
    try std.testing.expectEqual(64, answer.shared.len);
    // The X25519 half of the secret is the plain X25519 agreement.
    const x_shared = try X25519.scalarmult(a.x25519_mlkem768.x25519.secret_key, answer.public[1088..][0..32].*);
    try std.testing.expectEqualSlices(u8, &x_shared, answer.shared[32..]);
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

    // The hybrid group checks lengths on both sides and the encapsulation key on the server.
    var h = try KeyShare.generate(io, .x25519_mlkem768);
    defer h.wipe();
    try std.testing.expectError(error.IllegalParameter, h.sharedSecret(&[_]u8{1} ** 1119, &out));
    try std.testing.expectError(error.IllegalParameter, h.sharedSecret(&[_]u8{1} ** 1216, &out));
    var pub_buf: [max_public_len]u8 = undefined;
    try std.testing.expectError(error.IllegalParameter, respond(io, .x25519_mlkem768, &[_]u8{1} ** 1215, &pub_buf, &out));
    try std.testing.expectError(error.IllegalParameter, respond(io, .x25519_mlkem768, &[_]u8{0xff} ** 1216, &pub_buf, &out));
    var hb: [max_public_len]u8 = undefined;
    var good = h.publicBytes(&hb)[0..hybrid_client_share_len].*;
    @memset(good[1184..], 0);
    try std.testing.expectError(error.DecryptError, respond(io, .x25519_mlkem768, &good, &pub_buf, &out));
    var answer_buf: [max_public_len]u8 = undefined;
    var answer_shared: [max_shared_len]u8 = undefined;
    const answer = try respond(io, .x25519_mlkem768, h.publicBytes(&hb), &answer_buf, &answer_shared);
    var low_order = answer.public[0..hybrid_server_share_len].*;
    @memset(low_order[1088..], 0);
    try std.testing.expectError(error.DecryptError, h.sharedSecret(&low_order, &out));
}
