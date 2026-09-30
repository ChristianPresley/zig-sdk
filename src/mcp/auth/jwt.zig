//! JSON Web Token verification for resource servers: compact JWS parsing, an algorithm
//! allow-list (HS256, ES256, RS256, PS256), key lookup by `kid`, and the standard claims.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const Certificate = std.crypto.Certificate;

pub const Algorithm = enum { HS256, ES256, RS256, PS256 };

/// A verification key. `kid` is optional. `alg` restricts the key to one algorithm.
pub const Key = struct {
    kid: ?[]const u8 = null,
    alg: Algorithm,
    material: union(enum) {
        /// The shared secret of HS256.
        secret: []const u8,
        /// The uncompressed SEC1 point (65 bytes) of a P-256 key.
        p256: []const u8,
        /// The big-endian modulus and exponent of an RSA key.
        rsa: struct { n: []const u8, e: []const u8 },
    },
};

pub const Claims = struct {
    issuer: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    audience: []const []const u8 = &.{},
    expires_at: ?i64 = null,
    not_before: ?i64 = null,
    issued_at: ?i64 = null,
    client_id: ?[]const u8 = null,
    scopes: []const []const u8 = &.{},
    /// The whole payload.
    payload: Value,
};

pub const VerifyError = error{
    OutOfMemory,
    Malformed,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
    Expired,
    NotYetValid,
    IssuerMismatch,
    AudienceMismatch,
};

pub const Options = struct {
    keys: []const Key,
    /// The `iss` the token must carry. Null skips the check.
    issuer: ?[]const u8 = null,
    /// A value that `aud` must contain. Null skips the check.
    audience: ?[]const u8 = null,
    /// Tolerance for `exp`, `nbf` and `iat`.
    clock_skew_seconds: i64 = 60,
};

/// Verify a compact JWS and its claims at time `now` (Unix seconds).
pub fn verify(arena: Allocator, token: []const u8, options: Options, now: i64) VerifyError!Claims {
    var parts = std.mem.splitScalar(u8, token, '.');
    const h = parts.next() orelse return error.Malformed;
    const p = parts.next() orelse return error.Malformed;
    const s = parts.next() orelse return error.Malformed;
    if (parts.next() != null) return error.Malformed;
    const header_text = decode(arena, h) catch return error.Malformed;
    const payload_text = decode(arena, p) catch return error.Malformed;
    const signature = decode(arena, s) catch return error.Malformed;
    const header = json.parseTree(arena, header_text) catch return error.Malformed;
    const payload = json.parseTree(arena, payload_text) catch return error.Malformed;
    if (header != .object or payload != .object) return error.Malformed;
    const alg_text = json.getString(header, "alg") orelse return error.Malformed;
    const alg = std.meta.stringToEnum(Algorithm, alg_text) orelse return error.UnsupportedAlgorithm;
    const kid = json.getString(header, "kid");

    // Signing input.
    const signing_input = token[0 .. h.len + 1 + p.len];
    var verified = false;
    for (options.keys) |key| {
        if (key.alg != alg) continue;
        if (kid != null and key.kid != null and !std.mem.eql(u8, kid.?, key.kid.?)) continue;
        if (kid == null and key.kid != null and options.keys.len > 1) continue;
        if (verifySignature(key, alg, signing_input, signature)) {
            verified = true;
            break;
        }
    }
    if (!verified) return if (hasKeyFor(options.keys, alg)) error.BadSignature else error.UnknownKey;

    // Claims.
    var claims: Claims = .{ .payload = payload };
    claims.issuer = json.getString(payload, "iss");
    claims.subject = json.getString(payload, "sub");
    claims.client_id = json.getString(payload, "client_id");
    claims.expires_at = intClaim(payload, "exp");
    claims.not_before = intClaim(payload, "nbf");
    claims.issued_at = intClaim(payload, "iat");
    claims.audience = try audienceList(arena, payload);
    claims.scopes = try scopeList(arena, payload);
    const skew = options.clock_skew_seconds;
    if (claims.expires_at) |exp| if (now > exp + skew) return error.Expired;
    if (claims.not_before) |nbf| if (now + skew < nbf) return error.NotYetValid;
    if (claims.issued_at) |iat| if (now + skew < iat) return error.NotYetValid;
    if (options.issuer) |want| {
        const got = claims.issuer orelse return error.IssuerMismatch;
        if (!std.mem.eql(u8, got, want)) return error.IssuerMismatch;
    }
    if (options.audience) |want| {
        var found = false;
        for (claims.audience) |a| if (std.mem.eql(u8, a, want)) {
            found = true;
        };
        if (!found) return error.AudienceMismatch;
    }
    return claims;
}

fn hasKeyFor(keys: []const Key, alg: Algorithm) bool {
    for (keys) |k| if (k.alg == alg) return true;
    return false;
}

fn verifySignature(key: Key, alg: Algorithm, input: []const u8, signature: []const u8) bool {
    switch (alg) {
        .HS256 => {
            if (key.material != .secret) return false;
            const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
            if (signature.len != Hmac.mac_length) return false;
            var mac: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&mac, input, key.material.secret);
            return std.crypto.timing_safe.eql([Hmac.mac_length]u8, mac, signature[0..Hmac.mac_length].*);
        },
        .ES256 => {
            if (key.material != .p256) return false;
            const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            if (signature.len != Ecdsa.Signature.encoded_length) return false;
            const pk = Ecdsa.PublicKey.fromSec1(key.material.p256) catch return false;
            const sig = Ecdsa.Signature.fromBytes(signature[0..Ecdsa.Signature.encoded_length].*);
            sig.verify(input, pk) catch return false;
            return true;
        },
        .RS256, .PS256 => {
            if (key.material != .rsa) return false;
            const modulus = std.mem.trimStart(u8, key.material.rsa.n, "\x00");
            const pk = Certificate.rsa.PublicKey.fromBytes(key.material.rsa.e, modulus) catch return false;
            if (signature.len != modulus.len) return false;
            const Hash = std.crypto.hash.sha2.Sha256;
            switch (modulus.len) {
                inline 256, 384, 512 => |len| {
                    const sig = signature[0..len].*;
                    if (alg == .RS256) {
                        Certificate.rsa.PKCS1v1_5Signature.verify(len, sig, input, pk, Hash) catch return false;
                    } else {
                        Certificate.rsa.PSSSignature.verify(len, sig, input, pk, Hash) catch return false;
                    }
                    return true;
                },
                else => return false,
            }
        },
    }
}

fn intClaim(payload: Value, key: []const u8) ?i64 {
    const v = payload.object.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

fn audienceList(arena: Allocator, payload: Value) Allocator.Error![]const []const u8 {
    const v = payload.object.get("aud") orelse return &.{};
    switch (v) {
        .string => |s| {
            const one = try arena.alloc([]const u8, 1);
            one[0] = s;
            return one;
        },
        .array => |a| {
            var out: std.ArrayList([]const u8) = .empty;
            for (a.items) |item| if (item == .string) try out.append(arena, item.string);
            return out.items;
        },
        else => return &.{},
    }
}

fn scopeList(arena: Allocator, payload: Value) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (payload.object.get("scope")) |v| if (v == .string) {
        var it = std.mem.tokenizeScalar(u8, v.string, ' ');
        while (it.next()) |s| try out.append(arena, s);
    };
    if (payload.object.get("scp")) |v| if (v == .array) {
        for (v.array.items) |item| if (item == .string) try out.append(arena, item.string);
    };
    return out.items;
}

fn decode(arena: Allocator, text: []const u8) ![]u8 {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const len = try dec.calcSizeForSlice(text);
    const out = try arena.alloc(u8, len);
    try dec.decode(out, text);
    return out;
}

/// Encode a base64url segment (tests and token issuers).
pub fn encodeSegment(arena: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(bytes.len));
    _ = enc.encode(out, bytes);
    return out;
}

/// Make an HS256 token for tests and simple deployments.
pub fn signHs256(arena: Allocator, payload_json: []const u8, secret: []const u8, kid: ?[]const u8) Allocator.Error![]u8 {
    const header = if (kid) |k| try std.fmt.allocPrint(arena, "{{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":{f}}}", .{std.json.fmt(k, .{})}) else try arena.dupe(u8, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    const input = try std.mem.concat(arena, u8, &.{ try encodeSegment(arena, header), ".", try encodeSegment(arena, payload_json) });
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, input, secret);
    return std.mem.concat(arena, u8, &.{ input, ".", try encodeSegment(arena, &mac) });
}

test "hs256 round trip and claims" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const secret = "test-secret-of-32-bytes-or-more!!";
    const token = try signHs256(arena, "{\"iss\":\"https://as.example\",\"sub\":\"alice\",\"aud\":[\"https://rs.example/mcp\"],\"exp\":1000,\"nbf\":900,\"scope\":\"mcp:read mcp:write\"}", secret, "k1");
    const keys = [_]Key{.{ .kid = "k1", .alg = .HS256, .material = .{ .secret = secret } }};
    const claims = try verify(arena, token, .{ .keys = &keys, .issuer = "https://as.example", .audience = "https://rs.example/mcp" }, 950);
    try std.testing.expectEqualStrings("alice", claims.subject.?);
    try std.testing.expectEqual(2, claims.scopes.len);
    try std.testing.expectError(error.Expired, verify(arena, token, .{ .keys = &keys }, 1100));
    try std.testing.expectError(error.NotYetValid, verify(arena, token, .{ .keys = &keys }, 800));
    try std.testing.expectError(error.AudienceMismatch, verify(arena, token, .{ .keys = &keys, .audience = "https://other" }, 950));
    try std.testing.expectError(error.IssuerMismatch, verify(arena, token, .{ .keys = &keys, .issuer = "https://evil" }, 950));
    const wrong = [_]Key{.{ .kid = "k1", .alg = .HS256, .material = .{ .secret = "other" } }};
    try std.testing.expectError(error.BadSignature, verify(arena, token, .{ .keys = &wrong }, 950));
    const none = [_]Key{.{ .alg = .ES256, .material = .{ .p256 = &.{} } }};
    try std.testing.expectError(error.UnknownKey, verify(arena, token, .{ .keys = &none }, 950));
    try std.testing.expectError(error.Malformed, verify(arena, "a.b", .{ .keys = &keys }, 950));
    // `none` and other algorithms are refused.
    const alg_none = try std.mem.concat(arena, u8, &.{ try encodeSegment(arena, "{\"alg\":\"none\"}"), ".", try encodeSegment(arena, "{}"), "." });
    try std.testing.expectError(error.UnsupportedAlgorithm, verify(arena, alg_none, .{ .keys = &keys }, 950));
}

test "es256 verification" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const header = try encodeSegment(arena, "{\"alg\":\"ES256\"}");
    const payload = try encodeSegment(arena, "{\"sub\":\"bob\",\"exp\":2000}");
    const input = try std.mem.concat(arena, u8, &.{ header, ".", payload });
    const sig = try kp.sign(input, null);
    const token = try std.mem.concat(arena, u8, &.{ input, ".", try encodeSegment(arena, &sig.toBytes()) });
    const point = kp.public_key.toUncompressedSec1();
    const keys = [_]Key{.{ .alg = .ES256, .material = .{ .p256 = &point } }};
    const claims = try verify(arena, token, .{ .keys = &keys }, 1000);
    try std.testing.expectEqualStrings("bob", claims.subject.?);
    // Change one character inside the signature segment to another valid base64url character.
    var tampered = try arena.dupe(u8, token);
    const sig_start = input.len + 1;
    tampered[sig_start + 3] = if (tampered[sig_start + 3] == 'A') 'B' else 'A';
    try std.testing.expectError(error.BadSignature, verify(arena, tampered, .{ .keys = &keys }, 1000));
}
