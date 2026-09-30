//! Cipher suites, traffic keys and the TLS 1.3 key schedule (RFC 8446 section 7).
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;

/// The TLS 1.3 cipher suites this implementation supports.
pub const Suite = enum(u16) {
    AES_128_GCM_SHA256 = 0x1301,
    AES_256_GCM_SHA384 = 0x1302,
    CHACHA20_POLY1305_SHA256 = 0x1303,

    pub fn Type(comptime s: Suite) type {
        return switch (s) {
            .AES_128_GCM_SHA256 => SuiteT(crypto.aead.aes_gcm.Aes128Gcm, crypto.hash.sha2.Sha256),
            .AES_256_GCM_SHA384 => SuiteT(crypto.aead.aes_gcm.Aes256Gcm, crypto.hash.sha2.Sha384),
            .CHACHA20_POLY1305_SHA256 => SuiteT(crypto.aead.chacha_poly.ChaCha20Poly1305, crypto.hash.sha2.Sha256),
        };
    }

    pub fn fromWire(value: u16) ?Suite {
        return switch (value) {
            0x1301 => .AES_128_GCM_SHA256,
            0x1302 => .AES_256_GCM_SHA384,
            0x1303 => .CHACHA20_POLY1305_SHA256,
            else => null,
        };
    }

    pub fn wire(s: Suite) u16 {
        return @intFromEnum(s);
    }
};

/// The default server preference. ChaCha20 goes first on CPUs without AES hardware.
pub const default_suites: []const Suite = if (crypto.core.aes.has_hardware_support)
    &.{ .AES_128_GCM_SHA256, .AES_256_GCM_SHA384, .CHACHA20_POLY1305_SHA256 }
else
    &.{ .CHACHA20_POLY1305_SHA256, .AES_128_GCM_SHA256, .AES_256_GCM_SHA384 };

pub fn SuiteT(comptime AeadType: type, comptime HashType: type) type {
    return struct {
        pub const AEAD = AeadType;
        pub const Hash = HashType;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
        pub const digest_length = Hash.digest_length;
    };
}

/// Key schedule helpers for one suite.
pub fn Schedule(comptime S: type) type {
    return struct {
        pub const Secret = [S.digest_length]u8;
        const zeroes = [1]u8{0} ** S.digest_length;

        pub fn earlySecret() Secret {
            return S.Hkdf.extract(&[1]u8{0}, &zeroes);
        }

        pub fn derived(secret: Secret) Secret {
            const empty_hash = tls.emptyHash(S.Hash);
            return tls.hkdfExpandLabel(S.Hkdf, secret, "derived", &empty_hash, S.digest_length);
        }

        pub fn handshakeSecret(shared_secret: []const u8) Secret {
            return S.Hkdf.extract(&derived(earlySecret()), shared_secret);
        }

        pub fn masterSecret(handshake_secret: Secret) Secret {
            return S.Hkdf.extract(&derived(handshake_secret), &zeroes);
        }

        pub fn trafficSecret(secret: Secret, label: []const u8, transcript: Secret) Secret {
            return tls.hkdfExpandLabel(S.Hkdf, secret, label, &transcript, S.digest_length);
        }

        pub fn finishedKey(secret: Secret) [S.Hmac.key_length]u8 {
            return tls.hkdfExpandLabel(S.Hkdf, secret, "finished", "", S.Hmac.key_length);
        }

        pub fn verifyData(finished_key: [S.Hmac.key_length]u8, transcript: Secret) [S.Hmac.mac_length]u8 {
            return tls.hmac(S.Hmac, &transcript, finished_key);
        }

        pub fn updated(secret: Secret) Secret {
            return tls.hkdfExpandLabel(S.Hkdf, secret, "traffic upd", "", S.digest_length);
        }
    };
}

/// Traffic keys for one direction.
pub fn TrafficKeys(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Suite = S;
        secret: [S.digest_length]u8,
        key: [S.AEAD.key_length]u8,
        iv: [S.AEAD.nonce_length]u8,
        seq: u64 = 0,

        pub fn fromSecret(secret: [S.digest_length]u8) Self {
            return .{
                .secret = secret,
                .key = tls.hkdfExpandLabel(S.Hkdf, secret, "key", "", S.AEAD.key_length),
                .iv = tls.hkdfExpandLabel(S.Hkdf, secret, "iv", "", S.AEAD.nonce_length),
            };
        }

        /// The per-record nonce: the IV xor the big-endian sequence number.
        pub fn nonce(self: *const Self) [S.AEAD.nonce_length]u8 {
            var out = self.iv;
            const seq_bytes: [8]u8 = @bitCast(std.mem.nativeToBig(u64, self.seq));
            for (seq_bytes, 0..) |b, i| out[S.AEAD.nonce_length - 8 + i] ^= b;
            return out;
        }

        /// Rotate to the next generation (RFC 8446 section 7.2).
        pub fn update(self: *Self) void {
            const next = Schedule(S).updated(self.secret);
            crypto.secureZero(u8, &self.key);
            self.* = fromSecret(next);
        }

        pub fn wipe(self: *Self) void {
            crypto.secureZero(u8, &self.secret);
            crypto.secureZero(u8, &self.key);
            crypto.secureZero(u8, &self.iv);
        }
    };
}

/// Keys for one direction of one connection, or none while the stream is plaintext.
pub const DirectionKeys = union(enum) {
    none,
    AES_128_GCM_SHA256: TrafficKeys(Suite.Type(.AES_128_GCM_SHA256)),
    AES_256_GCM_SHA384: TrafficKeys(Suite.Type(.AES_256_GCM_SHA384)),
    CHACHA20_POLY1305_SHA256: TrafficKeys(Suite.Type(.CHACHA20_POLY1305_SHA256)),

    pub fn init(comptime suite: Suite, secret: [Suite.Type(suite).digest_length]u8) DirectionKeys {
        return @unionInit(DirectionKeys, @tagName(suite), .fromSecret(secret));
    }

    pub fn wipe(self: *DirectionKeys) void {
        switch (self.*) {
            .none => {},
            inline else => |*k| k.wipe(),
        }
        self.* = .none;
    }
};

/// A transcript hash that adds each message. The code selects its algorithm at run time.
pub const Transcript = union(enum) {
    sha256: crypto.hash.sha2.Sha256,
    sha384: crypto.hash.sha2.Sha384,

    pub fn init(comptime S: type) Transcript {
        return switch (S.digest_length) {
            32 => .{ .sha256 = .init(.{}) },
            48 => .{ .sha384 = .init(.{}) },
            else => @compileError("unsupported hash"),
        };
    }

    pub fn update(self: *Transcript, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*h| h.update(bytes),
        }
    }

    pub fn peek(self: *const Transcript, comptime S: type) [S.digest_length]u8 {
        return switch (self.*) {
            inline else => |*h| blk: {
                const d = h.peek();
                if (d.len != S.digest_length) unreachable;
                break :blk d[0..S.digest_length].*;
            },
        };
    }
};

test "traffic key nonce" {
    const S = Suite.Type(.AES_128_GCM_SHA256);
    var keys: TrafficKeys(S) = .fromSecret([_]u8{7} ** 32);
    keys.iv = [_]u8{0} ** 12;
    keys.seq = 0x0102;
    const n = keys.nonce();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2 }, &n);
}

test "key schedule matches RFC 8448 section 3 handshake secrets" {
    // RFC 8448 "Simple 1-RTT Handshake": shared secret and the client handshake traffic
    // secret derived from the ClientHello..ServerHello transcript hash.
    const S = Suite.Type(.AES_128_GCM_SHA256);
    const K = Schedule(S);
    const shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hs = K.handshakeSecret(&shared);
    try std.testing.expectEqualSlices(u8, &hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &hs);
    const transcript = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    const c_hs = K.trafficSecret(hs, "c hs traffic", transcript);
    try std.testing.expectEqualSlices(u8, &hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &c_hs);
    const s_hs = K.trafficSecret(hs, "s hs traffic", transcript);
    try std.testing.expectEqualSlices(u8, &hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &s_hs);
    const master = K.masterSecret(hs);
    try std.testing.expectEqualSlices(u8, &hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), &master);
    const keys: TrafficKeys(S) = .fromSecret(s_hs);
    try std.testing.expectEqualSlices(u8, &hex("3fce516009c21727d0f2e4e86ee403bc"), &keys.key);
    try std.testing.expectEqualSlices(u8, &hex("5d313eb2671276ee13000b30"), &keys.iv);
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
