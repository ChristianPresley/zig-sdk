//! Cipher suites, traffic keys and the TLS 1.3 key schedule (RFC 8446 section 7).
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;

/// The TLS 1.3 cipher suites this implementation supports. The two AEGIS suites of
/// draft-irtf-cfrg-aegis-aead are not in `default_suites`. To enable them, put them in the
/// `cipher_suites` option of the client or the server, or use `default_suites_with_aegis`.
pub const Suite = enum(u16) {
    AES_128_GCM_SHA256 = 0x1301,
    AES_256_GCM_SHA384 = 0x1302,
    CHACHA20_POLY1305_SHA256 = 0x1303,
    /// AEGIS-256 with a 128-bit tag and SHA-512. The key and the nonce have 32 bytes.
    AEGIS_256_SHA512 = 0x1306,
    /// AEGIS-128L with a 128-bit tag and SHA-256. The key and the nonce have 16 bytes.
    AEGIS_128L_SHA256 = 0x1307,

    pub fn Type(comptime s: Suite) type {
        return switch (s) {
            .AES_128_GCM_SHA256 => SuiteT(crypto.aead.aes_gcm.Aes128Gcm, crypto.hash.sha2.Sha256),
            .AES_256_GCM_SHA384 => SuiteT(crypto.aead.aes_gcm.Aes256Gcm, crypto.hash.sha2.Sha384),
            .CHACHA20_POLY1305_SHA256 => SuiteT(crypto.aead.chacha_poly.ChaCha20Poly1305, crypto.hash.sha2.Sha256),
            // TLS uses the variants with the 128-bit tag.
            .AEGIS_256_SHA512 => SuiteT(crypto.aead.aegis.Aegis256, crypto.hash.sha2.Sha512),
            .AEGIS_128L_SHA256 => SuiteT(crypto.aead.aegis.Aegis128L, crypto.hash.sha2.Sha256),
        };
    }

    pub fn fromWire(value: u16) ?Suite {
        return switch (value) {
            0x1301 => .AES_128_GCM_SHA256,
            0x1302 => .AES_256_GCM_SHA384,
            0x1303 => .CHACHA20_POLY1305_SHA256,
            0x1306 => .AEGIS_256_SHA512,
            0x1307 => .AEGIS_128L_SHA256,
            else => null,
        };
    }

    pub fn wire(s: Suite) u16 {
        return @intFromEnum(s);
    }

    /// True for the two AEGIS suites.
    pub fn isAegis(s: Suite) bool {
        return s == .AEGIS_128L_SHA256 or s == .AEGIS_256_SHA512;
    }
};

/// The default server preference. ChaCha20 goes first on CPUs without AES hardware. The list
/// has no AEGIS suite.
pub const default_suites: []const Suite = if (crypto.core.aes.has_hardware_support)
    &.{ .AES_128_GCM_SHA256, .AES_256_GCM_SHA384, .CHACHA20_POLY1305_SHA256 }
else
    &.{ .CHACHA20_POLY1305_SHA256, .AES_128_GCM_SHA256, .AES_256_GCM_SHA384 };

/// The default suites and the two AEGIS suites. Give this list to `cipher_suites` to enable
/// AEGIS. On CPUs with AES hardware, AEGIS-128L goes first. Else ChaCha20 goes first, because
/// AEGIS also uses the AES round function.
pub const default_suites_with_aegis: []const Suite = if (crypto.core.aes.has_hardware_support)
    &.{ .AEGIS_128L_SHA256, .AEGIS_256_SHA512, .AES_128_GCM_SHA256, .AES_256_GCM_SHA384, .CHACHA20_POLY1305_SHA256 }
else
    &.{ .CHACHA20_POLY1305_SHA256, .AEGIS_128L_SHA256, .AEGIS_256_SHA512, .AES_128_GCM_SHA256, .AES_256_GCM_SHA384 };

pub fn SuiteT(comptime AeadType: type, comptime HashType: type) type {
    // RFC 8446 section 5.3: the per-record nonce has the length of the AEAD nonce, at least
    // 8 bytes. Section 5.2: the AEAD adds 255 bytes or less.
    comptime std.debug.assert(AeadType.nonce_length >= 8);
    comptime std.debug.assert(AeadType.tag_length <= 255);
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
    AEGIS_256_SHA512: TrafficKeys(Suite.Type(.AEGIS_256_SHA512)),
    AEGIS_128L_SHA256: TrafficKeys(Suite.Type(.AEGIS_128L_SHA256)),

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
    sha512: crypto.hash.sha2.Sha512,

    pub fn init(comptime S: type) Transcript {
        return switch (S.digest_length) {
            32 => .{ .sha256 = .init(.{}) },
            48 => .{ .sha384 = .init(.{}) },
            64 => .{ .sha512 = .init(.{}) },
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

test "every suite AEAD decrypts in place" {
    // The record layer decrypts a record in place in the input buffer. This test fails when a
    // change of an AEAD in std breaks decryption into the same slice.
    const gpa = std.testing.allocator;
    const lengths = [_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4103, tls.max_ciphertext_inner_record_len + 1 };
    inline for (comptime std.enums.values(Suite)) |suite| {
        const A = Suite.Type(suite).AEAD;
        var key: [A.key_length]u8 = undefined;
        var nonce: [A.nonce_length]u8 = undefined;
        for (&key, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
        for (&nonce, 0..) |*b, i| b.* = @truncate(i *% 13 +% 2);
        const ad = "\x17\x03\x03\x00\x00";
        for (lengths) |len| {
            const plain = try gpa.alloc(u8, len);
            defer gpa.free(plain);
            for (plain, 0..) |*b, i| b.* = @truncate(i *% 31 +% 3);
            const buf = try gpa.alloc(u8, len);
            defer gpa.free(buf);
            var tag: [A.tag_length]u8 = undefined;
            A.encrypt(buf, &tag, plain, ad, nonce, key);
            try A.decrypt(buf, buf, tag, ad, nonce, key);
            try std.testing.expectEqualSlices(u8, plain, buf);
        }
    }
}

test "the default suites have no AEGIS suite" {
    for (default_suites) |s| try std.testing.expect(!s.isAegis());
    var aegis: usize = 0;
    for (default_suites_with_aegis) |s| {
        if (s.isAegis()) aegis += 1 else try std.testing.expect(std.mem.indexOfScalar(Suite, default_suites, s) != null);
    }
    try std.testing.expectEqual(2, aegis);
    try std.testing.expectEqual(default_suites.len + 2, default_suites_with_aegis.len);
    try std.testing.expectEqual(Suite.AEGIS_256_SHA512, Suite.fromWire(0x1306).?);
    try std.testing.expectEqual(Suite.AEGIS_128L_SHA256, Suite.fromWire(0x1307).?);
}

test "AEGIS traffic keys and the record nonce" {
    // RFC 8446 section 5.3: the IV has the length of the AEAD nonce, and the sequence number
    // goes into its last 8 bytes.
    inline for (.{ .{ Suite.AEGIS_128L_SHA256, 16, 32 }, .{ Suite.AEGIS_256_SHA512, 32, 64 } }) |case| {
        const S = Suite.Type(case[0]);
        try std.testing.expectEqual(case[1], S.AEAD.key_length);
        try std.testing.expectEqual(case[1], S.AEAD.nonce_length);
        try std.testing.expectEqual(16, S.AEAD.tag_length);
        try std.testing.expectEqual(case[2], S.digest_length);
        var keys: TrafficKeys(S) = .fromSecret([_]u8{9} ** S.digest_length);
        try std.testing.expectEqual(case[1], keys.key.len);
        try std.testing.expectEqual(case[1], keys.iv.len);
        keys.iv = [_]u8{0xff} ** case[1];
        keys.seq = 0x0102;
        const n = keys.nonce();
        try std.testing.expectEqualSlices(u8, &([_]u8{0xff} ** (case[1] - 2)), n[0 .. case[1] - 2]);
        try std.testing.expectEqualSlices(u8, &.{ 0xfe, 0xfd }, n[case[1] - 2 ..]);
        // A key update derives a new secret, key and IV, and starts the sequence again.
        const old_key = keys.key;
        keys.update();
        try std.testing.expectEqual(0, keys.seq);
        try std.testing.expect(!std.mem.eql(u8, &old_key, &keys.key));
        var dk = DirectionKeys.init(case[0], [_]u8{9} ** S.digest_length);
        dk.wipe();
        try std.testing.expect(dk == .none);
    }
}

test "the AEGIS suites use the AEAD with the 128-bit tag" {
    // Test vectors A.2.4 (AEGIS-128L) and A.3.4 (AEGIS-256) of draft-irtf-cfrg-aegis-aead-18.
    const m = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const ad = hex("0001020304050607");
    {
        const A = Suite.Type(.AEGIS_128L_SHA256).AEAD;
        const key = hex("10010000000000000000000000000000");
        const nonce = hex("10000200000000000000000000000000");
        var c: [m.len]u8 = undefined;
        var tag: [A.tag_length]u8 = undefined;
        A.encrypt(&c, &tag, &m, &ad, nonce, key);
        try std.testing.expectEqualSlices(u8, &hex("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84"), &c);
        try std.testing.expectEqualSlices(u8, &hex("cc6f3372f6aa1bb82388d695c3962d9a"), &tag);
    }
    {
        const A = Suite.Type(.AEGIS_256_SHA512).AEAD;
        const key = hex("1001000000000000000000000000000000000000000000000000000000000000");
        const nonce = hex("1000020000000000000000000000000000000000000000000000000000000000");
        var c: [m.len]u8 = undefined;
        var tag: [A.tag_length]u8 = undefined;
        A.encrypt(&c, &tag, &m, &ad, nonce, key);
        try std.testing.expectEqualSlices(u8, &hex("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"), &c);
        try std.testing.expectEqualSlices(u8, &hex("8d86f91ee606e9ff26a01b64ccbdd91d"), &tag);
    }
}

test "the SHA-512 transcript of AEGIS-256" {
    const S = Suite.Type(.AEGIS_256_SHA512);
    var t: Transcript = .init(S);
    try std.testing.expect(t == .sha512);
    t.update("abc");
    var want: [64]u8 = undefined;
    crypto.hash.sha2.Sha512.hash("abc", &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &t.peek(S));
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
