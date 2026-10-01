//! JSON Web Tokens. This file verifies compact JWS tokens with an algorithm allow-list (HS256,
//! ES256, ES384, EdDSA, RS256, PS256), finds keys by `kid`, and reads the standard claims. It
//! also reads JWK sets and signs tokens, for example client assertions.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const common = @import("common.zig");
const Certificate = std.crypto.Certificate;
const rsa = @import("../../tls/rsa.zig");
const pem = @import("../../tls/pem.zig");
const TlsPrivateKey = @import("../../tls/PrivateKey.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The JWS algorithms. `EdDSA` is Ed25519 only.
pub const Algorithm = enum { HS256, ES256, ES384, EdDSA, RS256, PS256 };

/// A verification key. `kid` is optional. `alg` restricts the key to one algorithm.
pub const Key = struct {
    kid: ?[]const u8 = null,
    alg: Algorithm,
    material: union(enum) {
        /// The shared secret of HS256.
        secret: []const u8,
        /// The uncompressed SEC1 point (65 bytes) of a P-256 key.
        p256: []const u8,
        /// The uncompressed SEC1 point (97 bytes) of a P-384 key.
        p384: []const u8,
        /// The 32-byte public key of Ed25519.
        ed25519: []const u8,
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
    /// The `jti` claim.
    jwt_id: ?[]const u8 = null,
    scopes: []const []const u8 = &.{},
    /// The whole payload.
    payload: Value,
    /// The whole JOSE header.
    header: Value = .null,
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
    /// The `typ` header is not the one that `Options.token_type` requires.
    TypeMismatch,
};

pub const Options = struct {
    keys: []const Key,
    /// The `iss` the token must carry. Null skips the check.
    issuer: ?[]const u8 = null,
    /// A value that `aud` must contain. Null skips the check. The comparison accepts an
    /// uppercase scheme and host (RFC 3986 section 6.2.2.1).
    audience: ?[]const u8 = null,
    /// The `typ` header the token must carry, for example `oauth-id-jag+jwt`. The comparison
    /// ignores case and an `application/` prefix (RFC 7515 section 4.1.9). Null skips the check.
    token_type: ?[]const u8 = null,
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
    if (options.token_type) |want| {
        const got = json.getString(header, "typ") orelse return error.TypeMismatch;
        if (!mediaTypeEql(got, want)) return error.TypeMismatch;
    }

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
    var claims: Claims = .{ .payload = payload, .header = header };
    claims.issuer = json.getString(payload, "iss");
    claims.subject = json.getString(payload, "sub");
    claims.client_id = json.getString(payload, "client_id");
    claims.jwt_id = json.getString(payload, "jti");
    claims.expires_at = intClaim(payload, "exp");
    claims.not_before = intClaim(payload, "nbf");
    claims.issued_at = intClaim(payload, "iat");
    claims.audience = try audienceList(arena, payload);
    claims.scopes = try scopeList(arena, payload);
    const skew = options.clock_skew_seconds;
    if (claims.expires_at) |exp| if (now > exp +| skew) return error.Expired;
    if (claims.not_before) |nbf| if (now +| skew < nbf) return error.NotYetValid;
    if (claims.issued_at) |iat| if (now +| skew < iat) return error.NotYetValid;
    if (options.issuer) |want| {
        const got = claims.issuer orelse return error.IssuerMismatch;
        if (!std.mem.eql(u8, got, want)) return error.IssuerMismatch;
    }
    if (options.audience) |want| {
        var found = false;
        for (claims.audience) |a| if (common.uriEql(a, want)) {
            found = true;
        };
        if (!found) return error.AudienceMismatch;
    }
    return claims;
}

/// Compare two `typ` values. The comparison ignores case and an `application/` prefix.
fn mediaTypeEql(a: []const u8, b: []const u8) bool {
    const prefix = "application/";
    const x = if (std.ascii.startsWithIgnoreCase(a, prefix)) a[prefix.len..] else a;
    const y = if (std.ascii.startsWithIgnoreCase(b, prefix)) b[prefix.len..] else b;
    return std.ascii.eqlIgnoreCase(x, y);
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
        .ES384 => {
            if (key.material != .p384) return false;
            if (signature.len != EcdsaP384.Signature.encoded_length) return false;
            const pk = EcdsaP384.PublicKey.fromSec1(key.material.p384) catch return false;
            const sig = EcdsaP384.Signature.fromBytes(signature[0..EcdsaP384.Signature.encoded_length].*);
            sig.verify(input, pk) catch return false;
            return true;
        },
        .EdDSA => {
            if (key.material != .ed25519) return false;
            if (key.material.ed25519.len != Ed25519.PublicKey.encoded_length) return false;
            if (signature.len != Ed25519.Signature.encoded_length) return false;
            const pk = Ed25519.PublicKey.fromBytes(key.material.ed25519[0..Ed25519.PublicKey.encoded_length].*) catch return false;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            sig.verifyStrict(input, pk) catch return false;
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

/// An integer claim. A float claim counts when it is in the range of `i64`, and the value is
/// the integer part. Other values give null.
fn intClaim(payload: Value, key: []const u8) ?i64 {
    const v = payload.object.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| if (std.math.isNan(f) or f < -9.0e18 or f > 9.0e18) null else @intFromFloat(f),
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

// -- Signatures ----------------------------------------------------------------------------------

/// A private key that signs tokens, for example client assertions (RFC 7523 section 2.2).
pub const SigningKey = union(enum) {
    /// The shared secret of HS256. The key does not own it.
    hs256: []const u8,
    es256: EcdsaP256.KeyPair,
    es384: EcdsaP384.KeyPair,
    eddsa: Ed25519.KeyPair,
    /// An RSA key that signs with RSASSA-PKCS1-v1_5 and SHA-256.
    rs256: rsa.PrivateKey,
    /// An RSA key that signs with RSASSA-PSS and SHA-256. `usePss` makes one from `rs256`.
    ps256: rsa.PrivateKey,

    pub const LoadError = error{ OutOfMemory, NoKeyFound, InvalidEncoding, UnsupportedKey, InvalidKey };

    pub fn algorithm(self: *const SigningKey) Algorithm {
        return switch (self.*) {
            .hs256 => .HS256,
            .es256 => .ES256,
            .es384 => .ES384,
            .eddsa => .EdDSA,
            .rs256 => .RS256,
            .ps256 => .PS256,
        };
    }

    /// Load the first private key of a PEM text: PKCS#8 (`PRIVATE KEY`), SEC1
    /// (`EC PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`). Call `deinit` to erase it.
    pub fn fromPem(gpa: Allocator, text: []const u8) LoadError!SigningKey {
        var it: pem.Iterator = .init(text);
        while (it.next()) |block| {
            const pkcs8 = std.mem.eql(u8, block.label, "PRIVATE KEY");
            const sec1 = std.mem.eql(u8, block.label, "EC PRIVATE KEY");
            const pkcs1 = std.mem.eql(u8, block.label, "RSA PRIVATE KEY");
            if (!pkcs8 and !sec1 and !pkcs1) continue;
            const bytes = try block.decode(gpa);
            defer {
                std.crypto.secureZero(u8, bytes);
                gpa.free(bytes);
            }
            return fromDer(bytes);
        }
        return error.NoKeyFound;
    }

    /// Load a private key from PKCS#8, SEC1 or PKCS#1 DER. Call `deinit` to erase it.
    pub fn fromDer(bytes: []const u8) LoadError!SigningKey {
        var key = TlsPrivateKey.parseDer(bytes) catch |err| return switch (err) {
            error.UnsupportedKey => error.UnsupportedKey,
            error.InvalidEncoding => error.InvalidEncoding,
            error.InvalidKey => error.InvalidKey,
        };
        defer key.deinit();
        return switch (key.key) {
            .ecdsa_p256 => |kp| .{ .es256 = kp },
            .ecdsa_p384 => |kp| .{ .es384 = kp },
            .ed25519 => |kp| .{ .eddsa = kp },
            .rsa => |k| .{ .rs256 = k },
        };
    }

    /// The same RSA key with the algorithm PS256 instead of RS256. Other keys do not change.
    pub fn usePss(self: SigningKey) SigningKey {
        return switch (self) {
            .rs256 => |k| .{ .ps256 = k },
            else => self,
        };
    }

    /// Erase the key material. The key owns no memory.
    pub fn deinit(self: *SigningKey) void {
        switch (self.*) {
            .hs256 => {},
            else => std.crypto.secureZero(u8, std.mem.asBytes(self)),
        }
        self.* = undefined;
    }

    /// The verification key for tokens that this key signs. `buf` holds the public point.
    pub fn verificationKey(self: *const SigningKey, buf: *[97]u8, kid: ?[]const u8) Key {
        return switch (self.*) {
            .hs256 => |s| .{ .kid = kid, .alg = .HS256, .material = .{ .secret = s } },
            .es256 => |kp| blk: {
                const p = kp.public_key.toUncompressedSec1();
                @memcpy(buf[0..p.len], &p);
                break :blk .{ .kid = kid, .alg = .ES256, .material = .{ .p256 = buf[0..p.len] } };
            },
            .es384 => |kp| blk: {
                const p = kp.public_key.toUncompressedSec1();
                @memcpy(buf[0..p.len], &p);
                break :blk .{ .kid = kid, .alg = .ES384, .material = .{ .p384 = buf[0..p.len] } };
            },
            .eddsa => |kp| blk: {
                const p = kp.public_key.toBytes();
                @memcpy(buf[0..p.len], &p);
                break :blk .{ .kid = kid, .alg = .EdDSA, .material = .{ .ed25519 = buf[0..p.len] } };
            },
            .rs256 => |*k| .{ .kid = kid, .alg = .RS256, .material = .{ .rsa = .{ .n = k.modulus(), .e = k.publicExponent() } } },
            .ps256 => |*k| .{ .kid = kid, .alg = .PS256, .material = .{ .rsa = .{ .n = k.modulus(), .e = k.publicExponent() } } },
        };
    }
};

pub const SignOptions = struct {
    /// The `kid` header. Null omits it.
    kid: ?[]const u8 = null,
    /// The `typ` header. Null omits it.
    typ: ?[]const u8 = "JWT",
};

pub const SignError = error{ OutOfMemory, SigningFailed };

/// Make a compact JWS with the payload `payload_json`. ECDSA and EdDSA signatures are
/// deterministic. The result is in `arena`.
pub fn sign(arena: Allocator, key: *const SigningKey, payload_json: []const u8, options: SignOptions) SignError![]u8 {
    var header: std.Io.Writer.Allocating = .init(arena);
    const w = &header.writer;
    w.print("{{\"alg\":\"{t}\"", .{key.algorithm()}) catch return error.OutOfMemory;
    if (options.typ) |t| w.print(",\"typ\":{f}", .{std.json.fmt(t, .{})}) catch return error.OutOfMemory;
    if (options.kid) |k| w.print(",\"kid\":{f}", .{std.json.fmt(k, .{})}) catch return error.OutOfMemory;
    w.writeByte('}') catch return error.OutOfMemory;
    const input = try std.mem.concat(arena, u8, &.{ try encodeSegment(arena, header.written()), ".", try encodeSegment(arena, payload_json) });
    const signature: []const u8 = switch (key.*) {
        .hs256 => |secret| blk: {
            var mac: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, input, secret);
            break :blk try arena.dupe(u8, &mac);
        },
        .es256 => |kp| blk: {
            const sig = kp.sign(input, null) catch return error.SigningFailed;
            break :blk try arena.dupe(u8, &sig.toBytes());
        },
        .es384 => |kp| blk: {
            const sig = kp.sign(input, null) catch return error.SigningFailed;
            break :blk try arena.dupe(u8, &sig.toBytes());
        },
        .eddsa => |kp| blk: {
            const sig = kp.sign(input, null) catch return error.SigningFailed;
            break :blk try arena.dupe(u8, &sig.toBytes());
        },
        .rs256 => |*k| blk: {
            const out = try arena.alloc(u8, k.modulusLen());
            break :blk k.signPkcs1v15(Sha256, input, out) catch return error.SigningFailed;
        },
        .ps256 => |*k| blk: {
            const out = try arena.alloc(u8, k.modulusLen());
            break :blk k.signPssDeterministic(Sha256, input, out) catch return error.SigningFailed;
        },
    };
    return std.mem.concat(arena, u8, &.{ input, ".", try encodeSegment(arena, signature) });
}

/// Decode the payload of a compact JWS without any check. Use it only to read claims of a
/// token that the client itself received, for example the `exp` of an assertion.
pub fn decodePayloadUnverified(arena: Allocator, token: []const u8) error{ OutOfMemory, Malformed }!Value {
    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next() orelse return error.Malformed;
    const p = parts.next() orelse return error.Malformed;
    const text = decode(arena, p) catch return error.Malformed;
    const tree = json.parseTree(arena, text) catch return error.Malformed;
    if (tree != .object) return error.Malformed;
    return tree;
}

/// Read an integer claim, for example `exp`, from a payload object.
pub fn integerClaim(payload: Value, key: []const u8) ?i64 {
    if (payload != .object) return null;
    return intClaim(payload, key);
}

// -- JWK sets ------------------------------------------------------------------------------------

pub const JwksError = error{ OutOfMemory, Malformed };

/// Parse a JWK set (RFC 7517 section 5) into verification keys. The parser keeps signature keys
/// of the types `EC` (P-256, P-384), `OKP` (Ed25519) and `RSA`, and skips all other keys. An RSA
/// key without `alg` gives one key for RS256 and one for PS256. The keys are in `arena`.
pub fn parseJwks(arena: Allocator, text: []const u8) JwksError![]Key {
    const tree = json.parseTree(arena, text) catch return error.Malformed;
    if (tree != .object) return error.Malformed;
    const list = tree.object.get("keys") orelse return error.Malformed;
    if (list != .array) return error.Malformed;
    var out: std.ArrayList(Key) = .empty;
    for (list.array.items) |jwk| {
        if (jwk != .object) continue;
        if (json.getString(jwk, "use")) |use| if (!std.mem.eql(u8, use, "sig")) continue;
        const kid = json.getString(jwk, "kid");
        const alg_text = json.getString(jwk, "alg");
        const alg: ?Algorithm = if (alg_text) |t| std.meta.stringToEnum(Algorithm, t) orelse continue else null;
        const kty = json.getString(jwk, "kty") orelse continue;
        if (std.mem.eql(u8, kty, "EC")) {
            const crv = json.getString(jwk, "crv") orelse continue;
            const want: Algorithm, const size: usize = if (std.mem.eql(u8, crv, "P-256")) .{ .ES256, 32 } else if (std.mem.eql(u8, crv, "P-384")) .{ .ES384, 48 } else continue;
            if (alg != null and alg.? != want) continue;
            const x = jwkBytes(arena, jwk, "x") orelse continue;
            const y = jwkBytes(arena, jwk, "y") orelse continue;
            if (x.len != size or y.len != size) continue;
            const point = try std.mem.concat(arena, u8, &.{ "\x04", x, y });
            try out.append(arena, .{ .kid = kid, .alg = want, .material = if (want == .ES256) .{ .p256 = point } else .{ .p384 = point } });
        } else if (std.mem.eql(u8, kty, "OKP")) {
            const crv = json.getString(jwk, "crv") orelse continue;
            if (!std.mem.eql(u8, crv, "Ed25519")) continue;
            if (alg != null and alg.? != .EdDSA) continue;
            const x = jwkBytes(arena, jwk, "x") orelse continue;
            if (x.len != Ed25519.PublicKey.encoded_length) continue;
            try out.append(arena, .{ .kid = kid, .alg = .EdDSA, .material = .{ .ed25519 = x } });
        } else if (std.mem.eql(u8, kty, "RSA")) {
            const n = jwkBytes(arena, jwk, "n") orelse continue;
            const e = jwkBytes(arena, jwk, "e") orelse continue;
            if (alg) |a| {
                if (a != .RS256 and a != .PS256) continue;
                try out.append(arena, .{ .kid = kid, .alg = a, .material = .{ .rsa = .{ .n = n, .e = e } } });
            } else {
                try out.append(arena, .{ .kid = kid, .alg = .RS256, .material = .{ .rsa = .{ .n = n, .e = e } } });
                try out.append(arena, .{ .kid = kid, .alg = .PS256, .material = .{ .rsa = .{ .n = n, .e = e } } });
            }
        }
    }
    return out.items;
}

fn jwkBytes(arena: Allocator, jwk: Value, name: []const u8) ?[]u8 {
    const text = json.getString(jwk, name) orelse return null;
    return decode(arena, text) catch null;
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
    // The audience comparison accepts an uppercase scheme and host, but not another path.
    _ = try verify(arena, token, .{ .keys = &keys, .audience = "HTTPS://RS.Example/mcp" }, 950);
    try std.testing.expectError(error.AudienceMismatch, verify(arena, token, .{ .keys = &keys, .audience = "https://rs.example/MCP" }, 950));
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

test "signatures round trip for every signing algorithm" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const payload = "{\"iss\":\"client-1\",\"sub\":\"client-1\",\"aud\":\"https://as.example\",\"exp\":2000}";
    const files = [_]struct { path: []const u8, alg: Algorithm }{
        .{ .path = "test/fixtures/tls/pem/p256.key", .alg = .ES256 },
        .{ .path = "test/fixtures/tls/pem/p384.key", .alg = .ES384 },
        .{ .path = "test/fixtures/tls/pem/ed25519.key", .alg = .EdDSA },
        .{ .path = "test/fixtures/jwt/rsa2048.key", .alg = .RS256 },
    };
    for (files) |f| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, f.path, gpa, .limited(1 << 16));
        defer gpa.free(text);
        var key = try SigningKey.fromPem(gpa, text);
        defer key.deinit();
        try std.testing.expectEqual(f.alg, key.algorithm());
        const token = try sign(arena, &key, payload, .{ .kid = "k1", .typ = "oauth-id-jag+jwt" });
        var buf: [97]u8 = undefined;
        const keys = [_]Key{key.verificationKey(&buf, "k1")};
        const claims = try verify(arena, token, .{ .keys = &keys, .audience = "https://as.example", .token_type = "application/OAUTH-ID-JAG+JWT" }, 1000);
        try std.testing.expectEqualStrings("client-1", claims.subject.?);
        try std.testing.expectEqualStrings("k1", json.getString(claims.header, "kid").?);
        try std.testing.expectError(error.TypeMismatch, verify(arena, token, .{ .keys = &keys, .token_type = "JWT" }, 1000));
    }
    {
        // The RSA key signs PS256 too. An RS256 key of the same modulus does not accept it.
        const text = try std.Io.Dir.cwd().readFileAlloc(io, "test/fixtures/jwt/rsa2048.key", gpa, .limited(1 << 16));
        defer gpa.free(text);
        var rs = try SigningKey.fromPem(gpa, text);
        defer rs.deinit();
        var ps = rs.usePss();
        try std.testing.expectEqual(Algorithm.PS256, ps.algorithm());
        const token = try sign(arena, &ps, payload, .{});
        var buf: [97]u8 = undefined;
        const ps_keys = [_]Key{ps.verificationKey(&buf, null)};
        _ = try verify(arena, token, .{ .keys = &ps_keys }, 1000);
        try std.testing.expectEqualStrings(token, try sign(arena, &ps, payload, .{}));
        const rs_keys = [_]Key{rs.verificationKey(&buf, null)};
        try std.testing.expectError(error.UnknownKey, verify(arena, token, .{ .keys = &rs_keys }, 1000));
    }
    var hs: SigningKey = .{ .hs256 = "a-shared-secret-of-thirty-two-b!" };
    const token = try sign(arena, &hs, payload, .{ .typ = null });
    var buf: [97]u8 = undefined;
    const keys = [_]Key{hs.verificationKey(&buf, null)};
    _ = try verify(arena, token, .{ .keys = &keys }, 1000);
    try std.testing.expectError(error.TypeMismatch, verify(arena, token, .{ .keys = &keys, .token_type = "JWT" }, 1000));
    try std.testing.expectEqual(2000, integerClaim(try decodePayloadUnverified(arena, token), "exp").?);
    try std.testing.expectError(error.NoKeyFound, SigningKey.fromPem(gpa, "no key"));
}

test "jwk set parsing" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const point = kp.public_key.toUncompressedSec1();
    const x = try encodeSegment(arena, point[1..33]);
    const y = try encodeSegment(arena, point[33..65]);
    const text = try std.fmt.allocPrint(arena,
        \\{{"keys":[
        \\{{"kty":"EC","crv":"P-256","kid":"ec1","use":"sig","x":"{s}","y":"{s}"}},
        \\{{"kty":"EC","crv":"P-256","kid":"enc","use":"enc","x":"{s}","y":"{s}"}},
        \\{{"kty":"RSA","kid":"r1","n":"AQAB","e":"AQAB"}},
        \\{{"kty":"OKP","crv":"X25519","x":"AAAA"}},
        \\{{"kty":"oct","k":"AAAA"}}
        \\]}}
    , .{ x, y, x, y });
    const keys = try parseJwks(arena, text);
    try std.testing.expectEqual(3, keys.len);
    try std.testing.expectEqualStrings("ec1", keys[0].kid.?);
    try std.testing.expectEqualSlices(u8, &point, keys[0].material.p256);
    try std.testing.expectEqual(Algorithm.RS256, keys[1].alg);
    try std.testing.expectEqual(Algorithm.PS256, keys[2].alg);
    try std.testing.expectError(error.Malformed, parseJwks(arena, "{}"));
}

test "time claims at the limits of i64 and large floats do not overflow" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const secret = "test-secret-of-32-bytes-or-more!!";
    const keys = [_]Key{.{ .alg = .HS256, .material = .{ .secret = secret } }};
    const max = try signHs256(arena, "{\"exp\":9223372036854775807,\"nbf\":-9223372036854775808,\"iat\":-9223372036854775808}", secret, null);
    _ = try verify(arena, max, .{ .keys = &keys }, 1000);
    const min = try signHs256(arena, "{\"exp\":-9223372036854775808}", secret, null);
    try std.testing.expectError(error.Expired, verify(arena, min, .{ .keys = &keys }, 1000));
    const future = try signHs256(arena, "{\"nbf\":9223372036854775807}", secret, null);
    try std.testing.expectError(error.NotYetValid, verify(arena, future, .{ .keys = &keys }, 1000));
    _ = try verify(arena, future, .{ .keys = &keys }, std.math.maxInt(i64));
    // A float outside the range of `i64` does not count as a time.
    const huge = try signHs256(arena, "{\"exp\":1e300,\"iat\":-1e300}", secret, null);
    const claims = try verify(arena, huge, .{ .keys = &keys }, 1000);
    try std.testing.expect(claims.expires_at == null and claims.issued_at == null);
    try std.testing.expectEqual(1500, integerClaim(try json.parseTree(arena, "{\"exp\":1500.7}"), "exp").?);
}
