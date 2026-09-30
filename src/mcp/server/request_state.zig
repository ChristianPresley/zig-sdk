//! Sealed `requestState` for multi round-trip requests.
//!
//! Format: `v1.` + base64url(nonce ‖ ciphertext ‖ tag). The plaintext is
//! `{"exp":<unix seconds>,"s":<caller state>}` and the associated data binds the state to
//! the method, the target name or URI, and a principal tag.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const json = @import("../json.zig");

pub const key_length = Aes256Gcm.key_length;
pub const prefix = "v1.";

pub const Codec = struct {
    key: [key_length]u8,
    ttl_seconds: i64,

    pub fn initRandom(io: Io, ttl: Io.Duration) error{EntropyUnavailable}!Codec {
        var key: [key_length]u8 = undefined;
        io.randomSecure(&key) catch return error.EntropyUnavailable;
        return .{ .key = key, .ttl_seconds = @intCast(@divTrunc(ttl.nanoseconds, std.time.ns_per_s)) };
    }

    pub fn deinit(self: *Codec) void {
        std.crypto.secureZero(u8, &self.key);
    }

    /// Seal `state` for the request described by `aad`. Returns text owned by `arena`.
    pub fn seal(self: Codec, arena: Allocator, io: Io, associated: []const u8, state: []const u8, now_seconds: i64) (Allocator.Error || error{EntropyUnavailable})![]u8 {
        const plain = try std.fmt.allocPrint(arena, "{{\"exp\":{d},\"s\":{f}}}", .{ now_seconds + self.ttl_seconds, std.json.fmt(state, .{}) });
        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        io.randomSecure(&nonce) catch return error.EntropyUnavailable;
        const raw = try arena.alloc(u8, nonce.len + plain.len + Aes256Gcm.tag_length);
        @memcpy(raw[0..nonce.len], &nonce);
        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(raw[nonce.len .. nonce.len + plain.len], &tag, plain, associated, nonce, self.key);
        @memcpy(raw[nonce.len + plain.len ..], &tag);
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const out = try arena.alloc(u8, prefix.len + encoder.calcSize(raw.len));
        @memcpy(out[0..prefix.len], prefix);
        _ = encoder.encode(out[prefix.len..], raw);
        return out;
    }

    pub const UnsealError = error{ Invalid, Expired, OutOfMemory };

    /// Verify and decrypt `text`. Returns the caller state, owned by `arena`.
    pub fn unseal(self: Codec, arena: Allocator, associated: []const u8, text: []const u8, now_seconds: i64) UnsealError![]const u8 {
        if (!std.mem.startsWith(u8, text, prefix)) return error.Invalid;
        const body = text[prefix.len..];
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const raw_len = decoder.calcSizeForSlice(body) catch return error.Invalid;
        if (raw_len < Aes256Gcm.nonce_length + Aes256Gcm.tag_length) return error.Invalid;
        const raw = try arena.alloc(u8, raw_len);
        decoder.decode(raw, body) catch return error.Invalid;
        const nonce = raw[0..Aes256Gcm.nonce_length].*;
        const tag = raw[raw_len - Aes256Gcm.tag_length ..][0..Aes256Gcm.tag_length].*;
        const cipher = raw[Aes256Gcm.nonce_length .. raw_len - Aes256Gcm.tag_length];
        const plain = try arena.alloc(u8, cipher.len);
        Aes256Gcm.decrypt(plain, cipher, tag, associated, nonce, self.key) catch return error.Invalid;
        const Claims = struct { exp: i64, s: []const u8 };
        const tree = json.parseTree(arena, plain) catch return error.Invalid;
        const claims = json.parseValue(Claims, arena, tree) catch return error.Invalid;
        if (now_seconds > claims.exp) return error.Expired;
        return claims.s;
    }
};

/// Build the associated data for a request: method, target and principal.
pub fn aad(arena: Allocator, method: []const u8, target: []const u8, principal: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{s}\x00{s}\x00{s}", .{ method, target, principal });
}

test "seal and unseal" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var codec: Codec = .{ .key = [_]u8{7} ** key_length, .ttl_seconds = 600 };
    const ad = try aad(arena, "tools/call", "echo", "");
    const sealed = try codec.seal(arena, std.testing.io, ad, "{\"round\":1}", 1_000);
    try std.testing.expect(std.mem.startsWith(u8, sealed, "v1."));
    const back = try codec.unseal(arena, ad, sealed, 1_100);
    try std.testing.expectEqualStrings("{\"round\":1}", back);
    try std.testing.expectError(error.Expired, codec.unseal(arena, ad, sealed, 2_000));
    const other_ad = try aad(arena, "tools/call", "other", "");
    try std.testing.expectError(error.Invalid, codec.unseal(arena, other_ad, sealed, 1_100));
    const tampered = try std.fmt.allocPrint(arena, "{s}-TAMPERED", .{sealed});
    try std.testing.expectError(error.Invalid, codec.unseal(arena, ad, tampered, 1_100));
    try std.testing.expectError(error.Invalid, codec.unseal(arena, ad, "garbage", 1_100));
}
