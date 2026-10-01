//! OAuth 2.0 DPoP (RFC 9449) for the DPoP extension of MCP: access tokens that only the holder
//! of a key can use.
//!
//! The client side: `Prover` holds the key pair of the client. It makes a proof JWT for each
//! HTTP request and keeps the nonces that servers send in the `DPoP-Nonce` header. The flows of
//! the SDK send a proof with each token request. The HTTP client transport sends a proof with
//! each request that carries a DPoP-bound token.
//!
//! The server side: `verifyProof` applies the checks of RFC 9449 section 4.3. `NonceIssuer`
//! makes nonces that need no state: each nonce is an encrypted timestamp. The resource server
//! helpers use both. An authorization server of the application can use them at its token
//! endpoint. It puts the thumbprint of the proof key into the `cnf.jkt` claim of the token.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const common = @import("common.zig");
const jwt = @import("jwt.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

/// The identifier of the extension in the `extensions` capability. The draft of the extension
/// names no identifier. This value is the one that the MCP conformance suite uses.
pub const extension_id = "io.modelcontextprotocol/auth/dpop";
/// The `typ` header of a proof JWT.
pub const proof_type = "dpop+jwt";
/// The name of the request header that carries the proof.
pub const header_name = "DPoP";
/// The name of the response header that carries a nonce.
pub const nonce_header_name = "DPoP-Nonce";
/// The `token_type` of a DPoP-bound access token, and the scheme of its `Authorization` header.
pub const token_type = "DPoP";
/// The largest difference between the `iat` claim of a proof and the clock of the server. The
/// extension sets five minutes.
pub const max_proof_age_seconds: i64 = 300;
/// The algorithms that a verifier accepts by default: every asymmetric algorithm of the SDK.
pub const default_algorithms = [_]jwt.Algorithm{ .ES256, .ES384, .EdDSA, .RS256, .PS256 };

// -- Client side ---------------------------------------------------------------------------------

/// The key pair of a client and the nonces that servers gave it. One prover can serve more than
/// one flow. All functions are safe to call from more than one task.
pub const Prover = struct {
    io: Io,
    gpa: Allocator,
    key: jwt.SigningKey,
    /// The public key as a JWK object in JSON text, with the members in the order of RFC 7638.
    jwk: []u8,
    /// The JWK SHA-256 thumbprint of the public key in base64url (RFC 7638).
    jkt: []u8,
    /// The clock of the `iat` claim. Null uses the real clock.
    clock: common.Clock = null,
    lock: Io.Mutex = .init,
    /// The last nonce of each origin, for example `https://as.example`.
    nonces: std.ArrayList(Nonce) = .empty,

    const Nonce = struct { origin: []u8, value: []u8 };

    pub const InitError = error{
        OutOfMemory,
        /// The key is HS256. A proof needs an asymmetric key.
        SymmetricKey,
    };

    /// Make a prover with a copy of `key`. The key must be asymmetric. Call `deinit` to erase
    /// the copy.
    pub fn init(io: Io, gpa: Allocator, key: jwt.SigningKey) InitError!Prover {
        if (!key.algorithm().isAsymmetric()) return error.SymmetricKey;
        var self: Prover = .{ .io = io, .gpa = gpa, .key = key, .jwk = &.{}, .jkt = &.{} };
        errdefer self.key.deinit();
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const text = try jwt.publicJwk(arena, &self.key);
        const tree = json.parseTree(arena, text) catch return error.OutOfMemory;
        const thumbprint = (try jwt.jwkThumbprint(arena, tree)) orelse unreachable;
        self.jwk = try gpa.dupe(u8, text);
        errdefer gpa.free(self.jwk);
        self.jkt = try gpa.dupe(u8, thumbprint);
        return self;
    }

    /// Make a prover with a new random P-256 key (ES256).
    pub fn generate(io: Io, gpa: Allocator) (InitError || error{EntropyUnavailable})!Prover {
        const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        while (true) {
            var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            io.randomSecure(&seed) catch return error.EntropyUnavailable;
            const kp = Ecdsa.KeyPair.generateDeterministic(seed) catch continue;
            return init(io, gpa, .{ .es256 = kp });
        }
    }

    /// Erase the key and free the nonces.
    pub fn deinit(self: *Prover) void {
        for (self.nonces.items) |n| {
            self.gpa.free(n.origin);
            self.gpa.free(n.value);
        }
        self.nonces.deinit(self.gpa);
        self.gpa.free(self.jwk);
        self.gpa.free(self.jkt);
        self.key.deinit();
        self.* = undefined;
    }

    /// The algorithm of the proofs.
    pub fn algorithm(self: *const Prover) jwt.Algorithm {
        return self.key.algorithm();
    }

    pub const ProofError = error{ OutOfMemory, SigningFailed, EntropyUnavailable };

    /// Make a proof for one HTTP request (RFC 9449 section 4.2). `url` is the target URI. The
    /// `htu` claim is the URI without the query and the fragment. `access_token` adds the `ath`
    /// claim. The proof carries the last nonce of the origin of `url`, when the client has one.
    /// The proof is in `arena`.
    pub fn proof(self: *Prover, arena: Allocator, method: []const u8, url: []const u8, access_token: ?[]const u8) ProofError![]u8 {
        var jti_bytes: [16]u8 = undefined;
        self.io.randomSecure(&jti_bytes) catch return error.EntropyUnavailable;
        var aw: Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        w.print("{{\"jti\":\"{s}\",\"htm\":{f},\"htu\":{f},\"iat\":{d}", .{
            try common.base64Url(arena, &jti_bytes),
            std.json.fmt(method, .{}),
            std.json.fmt(withoutQuery(url), .{}),
            common.now(self.io, self.clock),
        }) catch return error.OutOfMemory;
        if (access_token) |t| {
            var hash: [43]u8 = undefined;
            w.print(",\"ath\":\"{s}\"", .{accessTokenHash(&hash, t)}) catch return error.OutOfMemory;
        }
        if (try self.nonceFor(arena, url)) |n| w.print(",\"nonce\":{f}", .{std.json.fmt(n, .{})}) catch return error.OutOfMemory;
        w.writeByte('}') catch return error.OutOfMemory;
        return jwt.sign(arena, &self.key, aw.written(), .{ .typ = proof_type, .jwk = self.jwk }) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.SigningFailed => error.SigningFailed,
        };
    }

    /// Keep `nonce` for the origin of `url`. The next proofs for that origin carry it. A value
    /// with characters that RFC 9449 section 8.1 does not permit has no effect.
    pub fn rememberNonce(self: *Prover, url: []const u8, nonce: []const u8) Allocator.Error!void {
        if (!validNonce(nonce)) return;
        const origin = originOf(url);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.nonces.items) |*n| if (std.ascii.eqlIgnoreCase(n.origin, origin)) {
            const copy = try self.gpa.dupe(u8, nonce);
            self.gpa.free(n.value);
            n.value = copy;
            return;
        };
        const origin_copy = try self.gpa.dupe(u8, origin);
        errdefer self.gpa.free(origin_copy);
        const value_copy = try self.gpa.dupe(u8, nonce);
        errdefer self.gpa.free(value_copy);
        try self.nonces.append(self.gpa, .{ .origin = origin_copy, .value = value_copy });
    }

    fn nonceFor(self: *Prover, arena: Allocator, url: []const u8) Allocator.Error!?[]const u8 {
        const origin = originOf(url);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.nonces.items) |n| if (std.ascii.eqlIgnoreCase(n.origin, origin)) return try arena.dupe(u8, n.value);
        return null;
    }
};

/// The `ath` claim of a proof: the SHA-256 hash of the access token in base64url.
pub fn accessTokenHash(buf: *[43]u8, access_token: []const u8) []const u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(access_token, &digest, .{});
    return std.base64.url_safe_no_pad.Encoder.encode(buf, &digest);
}

/// True for a nonce value of RFC 9449 section 8.1: one or more of the characters `%x21`,
/// `%x23-5B` and `%x5D-7E`.
pub fn validNonce(nonce: []const u8) bool {
    if (nonce.len == 0) return false;
    for (nonce) |c| {
        if (c < 0x21 or c > 0x7e or c == '"' or c == '\\') return false;
    }
    return true;
}

/// The URI without its query and its fragment.
fn withoutQuery(url: []const u8) []const u8 {
    return url[0 .. std.mem.indexOfAny(u8, url, "?#") orelse url.len];
}

/// `scheme://authority` of a URL, or the whole text when it has no `://`.
fn originOf(url: []const u8) []const u8 {
    const parts = common.splitUri(url) orelse return url;
    return url[0 .. url.len - parts.rest.len];
}

// -- Server side ---------------------------------------------------------------------------------

/// What a proof must match: the request that carries it.
pub const Expectation = struct {
    /// The HTTP method of the request, for example `POST`.
    method: []const u8,
    /// The target URI of the request. The check ignores the query and the fragment.
    uri: []const u8,
    /// The access token of the request. Null for a request without a token, for example a
    /// token request. With a token, the proof must carry its `ath`.
    access_token: ?[]const u8 = null,
    /// The `jkt` of the `cnf` claim of the access token. Null skips the check.
    jkt: ?[]const u8 = null,
};

/// Records the `jti` values of proofs to refuse a replay (RFC 9449 section 11.1).
pub const ReplayCheck = struct {
    userdata: ?*anyopaque = null,
    /// Return true when the store already has the pair of `jkt` and `jti`. Otherwise record the
    /// pair until `expires_at` in Unix seconds.
    seen: *const fn (userdata: ?*anyopaque, jkt: []const u8, jti: []const u8, expires_at: i64) bool,
};

pub const VerifyOptions = struct {
    /// The algorithms that the verifier accepts. Only asymmetric algorithms have an effect.
    algorithms: []const jwt.Algorithm = &default_algorithms,
    /// The largest difference between the `iat` claim and the clock.
    max_age_seconds: i64 = max_proof_age_seconds,
    /// Require a nonce from this issuer. Null accepts a proof without a nonce.
    nonce: ?*const NonceIssuer = null,
    /// Refuse a `jti` that the store saw before. Null skips the check. Without it, the age
    /// limit is the replay protection.
    replay: ?ReplayCheck = null,
};

pub const VerifyError = error{
    OutOfMemory,
    /// The proof is not a compact JWS, or a required claim is missing or has the wrong type.
    Malformed,
    /// The `typ` header is not `dpop+jwt`.
    TypeMismatch,
    /// The `alg` header is not an accepted asymmetric algorithm.
    UnsupportedAlgorithm,
    /// The `jwk` header is missing, has a private member, or does not fit the algorithm.
    BadKey,
    BadSignature,
    /// The `htm` claim is not the method of the request.
    MethodMismatch,
    /// The `htu` claim is not the target URI of the request.
    UriMismatch,
    /// The `iat` claim is outside the accepted window.
    Stale,
    /// The `ath` claim is missing or is not the hash of the access token.
    TokenHashMismatch,
    /// The thumbprint of the proof key is not the `cnf.jkt` of the access token.
    KeyMismatch,
    /// The proof has no nonce, or its nonce is not valid. Answer with a new nonce.
    UseNonce,
    /// The replay check saw the `jti` before.
    Replayed,
};

/// What a valid proof tells. The slices point into `arena`.
pub const Proof = struct {
    /// The JWK SHA-256 thumbprint of the proof key. An authorization server puts it into the
    /// `cnf.jkt` claim of a DPoP-bound token.
    jkt: []const u8,
    jti: []const u8,
    issued_at: i64,
    nonce: ?[]const u8 = null,
};

/// Check a proof JWT against the request that carries it, at `now` in Unix seconds (RFC 9449
/// section 4.3). The caller makes sure that the request has exactly one `DPoP` header.
pub fn verifyProof(arena: Allocator, proof: []const u8, expect: Expectation, options: VerifyOptions, now: i64) VerifyError!Proof {
    var parts = std.mem.splitScalar(u8, proof, '.');
    const header_text = decodeSegment(arena, parts.next() orelse return error.Malformed) catch |e| return mapDecode(e);
    const header = json.parseTree(arena, header_text) catch return error.Malformed;
    if (header != .object) return error.Malformed;
    const typ = json.getString(header, "typ") orelse return error.TypeMismatch;
    if (!std.ascii.eqlIgnoreCase(typ, proof_type) and !std.ascii.eqlIgnoreCase(typ, "application/" ++ proof_type)) return error.TypeMismatch;
    const alg_text = json.getString(header, "alg") orelse return error.UnsupportedAlgorithm;
    const alg = std.meta.stringToEnum(jwt.Algorithm, alg_text) orelse return error.UnsupportedAlgorithm;
    if (!alg.isAsymmetric()) return error.UnsupportedAlgorithm;
    for (options.algorithms) |a| {
        if (a == alg) break;
    } else return error.UnsupportedAlgorithm;
    const jwk = header.object.get("jwk") orelse return error.BadKey;
    if (jwk != .object or jwt.jwkHasPrivateMembers(jwk)) return error.BadKey;
    var key = (try jwt.parseJwk(arena, jwk, alg)) orelse return error.BadKey;
    key.kid = null;

    const claims = jwt.verify(arena, proof, .{ .keys = &.{key}, .clock_skew_seconds = options.max_age_seconds }, now) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Malformed => error.Malformed,
        error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
        error.UnknownKey, error.BadSignature => error.BadSignature,
        error.Expired, error.NotYetValid => error.Stale,
        error.IssuerMismatch, error.AudienceMismatch, error.TypeMismatch => error.Malformed,
    };
    const payload = claims.payload;
    const jti = claims.jwt_id orelse return error.Malformed;
    if (jti.len == 0) return error.Malformed;
    const htm = json.getString(payload, "htm") orelse return error.Malformed;
    const htu = json.getString(payload, "htu") orelse return error.Malformed;
    const iat = claims.issued_at orelse return error.Malformed;
    if (!std.mem.eql(u8, htm, expect.method)) return error.MethodMismatch;
    if (!try sameTargetUri(arena, htu, expect.uri)) return error.UriMismatch;
    if (now -| iat > options.max_age_seconds or iat -| now > options.max_age_seconds) return error.Stale;
    if (expect.access_token) |token| {
        const ath = json.getString(payload, "ath") orelse return error.TokenHashMismatch;
        var buf: [43]u8 = undefined;
        if (!std.mem.eql(u8, ath, accessTokenHash(&buf, token))) return error.TokenHashMismatch;
    }
    const jkt = (try jwt.jwkThumbprint(arena, jwk)) orelse return error.BadKey;
    if (expect.jkt) |want| if (!std.mem.eql(u8, want, jkt)) return error.KeyMismatch;
    const nonce = json.getString(payload, "nonce");
    if (options.nonce) |issuer| {
        const n = nonce orelse return error.UseNonce;
        if (!issuer.check(n, now)) return error.UseNonce;
    }
    if (options.replay) |r| if (r.seen(r.userdata, jkt, jti, iat +| options.max_age_seconds)) return error.Replayed;
    return .{ .jkt = jkt, .jti = jti, .issued_at = iat, .nonce = nonce };
}

fn mapDecode(err: anyerror) VerifyError {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.Malformed;
}

fn decodeSegment(arena: Allocator, text: []const u8) ![]u8 {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const out = try arena.alloc(u8, try dec.calcSizeForSlice(text));
    try dec.decode(out, text);
    return out;
}

/// Compare two target URIs after the normalization of RFC 3986 section 6.2.2 and 6.2.3. The
/// case of the scheme and the host, a default port and an empty path do not count. The
/// comparison ignores the query and the fragment.
pub fn sameTargetUri(arena: Allocator, a: []const u8, b: []const u8) Allocator.Error!bool {
    const x = try normalizeUri(arena, a) orelse return false;
    const y = try normalizeUri(arena, b) orelse return false;
    return std.mem.eql(u8, x, y);
}

/// The normal form of an `http` or `https` URI without the query and the fragment, or null for
/// another URI. The scheme and the host are in lowercase, the default port is gone, and an empty
/// path is `/`. The text is in `arena`.
pub fn normalizeUri(arena: Allocator, uri: []const u8) Allocator.Error!?[]u8 {
    const parts = common.splitUri(withoutQuery(uri)) orelse return null;
    const https = std.ascii.eqlIgnoreCase(parts.scheme, "https");
    if (!https and !std.ascii.eqlIgnoreCase(parts.scheme, "http")) return null;
    if (parts.userinfo.len > 0) return null;
    var host_port = parts.host_port;
    const default_port: []const u8 = if (https) ":443" else ":80";
    if (std.mem.endsWith(u8, host_port, default_port)) host_port = host_port[0 .. host_port.len - default_port.len];
    if (host_port.len > 0 and host_port[host_port.len - 1] == ':') host_port = host_port[0 .. host_port.len - 1];
    const path = if (parts.rest.len == 0) "/" else parts.rest;
    const out = try std.mem.concat(arena, u8, &.{ if (https) "https" else "http", "://", host_port, path });
    _ = std.ascii.lowerString(out[0 .. out.len - path.len], out[0 .. out.len - path.len]);
    return out;
}

/// Makes and checks nonces without state (RFC 9449 section 8 and 9). A nonce is an encrypted
/// timestamp: XChaCha20-Poly1305 with a random 24-byte nonce of the cipher. A server that gives
/// a nonce and requires it in each proof limits the time in which a stolen proof is usable.
/// All servers that share the key accept the nonces of each other.
pub const NonceIssuer = struct {
    key: [Aead.key_length]u8,
    /// A nonce is valid for this number of seconds after the server made it.
    lifetime_seconds: i64 = max_proof_age_seconds,

    const label = "mcp-dpop-nonce-v1";
    const plain_len = 8;
    const raw_len = Aead.nonce_length + plain_len + Aead.tag_length;
    /// The length of a nonce in base64url.
    pub const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw_len);

    /// An issuer with a random key.
    pub fn init(io: Io) error{EntropyUnavailable}!NonceIssuer {
        var self: NonceIssuer = .{ .key = undefined };
        io.randomSecure(&self.key) catch return error.EntropyUnavailable;
        return self;
    }

    /// Make a nonce for the time `now` in Unix seconds.
    pub fn issue(self: *const NonceIssuer, io: Io, buf: *[encoded_len]u8, now: i64) error{EntropyUnavailable}![]const u8 {
        var raw: [raw_len]u8 = undefined;
        const npub = raw[0..Aead.nonce_length];
        io.randomSecure(npub) catch return error.EntropyUnavailable;
        var plain: [plain_len]u8 = undefined;
        std.mem.writeInt(i64, &plain, now, .big);
        const cipher = raw[Aead.nonce_length..][0..plain_len];
        const tag = raw[Aead.nonce_length + plain_len ..][0..Aead.tag_length];
        Aead.encrypt(cipher, tag, &plain, label, npub.*, self.key);
        return std.base64.url_safe_no_pad.Encoder.encode(buf, &raw);
    }

    /// True when `nonce` comes from this issuer and is not older than the lifetime at `now`. A
    /// nonce from the future is valid only within 60 seconds of clock difference.
    pub fn check(self: *const NonceIssuer, nonce: []const u8, now: i64) bool {
        if (nonce.len != encoded_len) return false;
        var raw: [raw_len]u8 = undefined;
        std.base64.url_safe_no_pad.Decoder.decode(&raw, nonce) catch return false;
        var plain: [plain_len]u8 = undefined;
        Aead.decrypt(&plain, raw[Aead.nonce_length..][0..plain_len], raw[Aead.nonce_length + plain_len ..][0..Aead.tag_length].*, label, raw[0..Aead.nonce_length].*, self.key) catch return false;
        const made = std.mem.readInt(i64, &plain, .big);
        return made <= now + 60 and now - made <= self.lifetime_seconds;
    }
};

/// The `error_description` for a failed proof check.
pub fn describe(err: VerifyError) []const u8 {
    return switch (err) {
        error.OutOfMemory => "The server is out of memory",
        error.Malformed => "The DPoP proof is malformed or lacks a required claim",
        error.TypeMismatch => "The DPoP proof typ header is not dpop+jwt",
        error.UnsupportedAlgorithm => "The DPoP proof algorithm is not accepted",
        error.BadKey => "The DPoP proof jwk header is not a valid public key",
        error.BadSignature => "The DPoP proof signature is not valid",
        error.MethodMismatch => "The DPoP proof htm claim is not the request method",
        error.UriMismatch => "The DPoP proof htu claim is not the request URI",
        error.Stale => "The DPoP proof iat claim is outside the accepted window",
        error.TokenHashMismatch => "The DPoP proof ath claim is not the hash of the access token",
        error.KeyMismatch => "The DPoP proof key is not the key of the access token",
        error.UseNonce => "The server requires a DPoP nonce",
        error.Replayed => "The DPoP proof was used before",
    };
}

test "a proof verifies and binds to the token" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var prover: Prover = try .init(io, std.testing.allocator, .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{11} ** 32) });
    defer prover.deinit();
    prover.clock = fixedClock;
    try std.testing.expectEqual(43, prover.jkt.len);

    const p = try prover.proof(arena, "POST", "https://MCP.example.com:443/mcp?x=1#f", "token-1");
    const ok = try verifyProof(arena, p, .{ .method = "POST", .uri = "https://mcp.example.com/mcp", .access_token = "token-1", .jkt = prover.jkt }, .{}, 1_000_100);
    try std.testing.expectEqualStrings(prover.jkt, ok.jkt);
    try std.testing.expectEqual(1_000_000, ok.issued_at);
    const header = try json.parseTree(arena, try decodeSegment(arena, p[0..std.mem.indexOfScalar(u8, p, '.').?]));
    try std.testing.expectEqualStrings("dpop+jwt", json.getString(header, "typ").?);
    try std.testing.expectEqualStrings("ES256", json.getString(header, "alg").?);
    const payload = try jwt.decodePayloadUnverified(arena, p);
    try std.testing.expectEqualStrings("https://MCP.example.com:443/mcp", json.getString(payload, "htu").?);

    // Each proof has a new `jti`.
    const p2 = try prover.proof(arena, "POST", "https://mcp.example.com/mcp", "token-1");
    const ok2 = try verifyProof(arena, p2, .{ .method = "POST", .uri = "https://mcp.example.com/mcp", .access_token = "token-1" }, .{}, 1_000_000);
    try std.testing.expect(!std.mem.eql(u8, ok.jti, ok2.jti));

    const E = Expectation;
    try std.testing.expectError(error.MethodMismatch, verifyProof(arena, p, E{ .method = "GET", .uri = "https://mcp.example.com/mcp", .access_token = "token-1" }, .{}, 1_000_000));
    try std.testing.expectError(error.UriMismatch, verifyProof(arena, p, E{ .method = "POST", .uri = "https://mcp.example.com/other", .access_token = "token-1" }, .{}, 1_000_000));
    try std.testing.expectError(error.UriMismatch, verifyProof(arena, p, E{ .method = "POST", .uri = "http://mcp.example.com/mcp", .access_token = "token-1" }, .{}, 1_000_000));
    try std.testing.expectError(error.TokenHashMismatch, verifyProof(arena, p, E{ .method = "POST", .uri = "https://mcp.example.com/mcp", .access_token = "token-2" }, .{}, 1_000_000));
    try std.testing.expectError(error.KeyMismatch, verifyProof(arena, p, E{ .method = "POST", .uri = "https://mcp.example.com/mcp", .access_token = "token-1", .jkt = "other" }, .{}, 1_000_000));
    try std.testing.expectError(error.Stale, verifyProof(arena, p, E{ .method = "POST", .uri = "https://mcp.example.com/mcp" }, .{}, 1_000_301));
    try std.testing.expectError(error.Stale, verifyProof(arena, p, E{ .method = "POST", .uri = "https://mcp.example.com/mcp" }, .{}, 999_699));
    try std.testing.expectError(error.UnsupportedAlgorithm, verifyProof(arena, p, E{ .method = "POST", .uri = "https://mcp.example.com/mcp" }, .{ .algorithms = &.{.EdDSA} }, 1_000_000));

    // A proof without a token has no `ath`, and a token request accepts it.
    const bare = try prover.proof(arena, "POST", "https://as.example/token", null);
    _ = try verifyProof(arena, bare, .{ .method = "POST", .uri = "https://as.example/token" }, .{}, 1_000_000);
    try std.testing.expectError(error.TokenHashMismatch, verifyProof(arena, bare, .{ .method = "POST", .uri = "https://as.example/token", .access_token = "t" }, .{}, 1_000_000));

    // A changed signature fails.
    var tampered = try arena.dupe(u8, p);
    const at = std.mem.lastIndexOfScalar(u8, tampered, '.').? + 4;
    tampered[at] = if (tampered[at] == 'A') 'B' else 'A';
    try std.testing.expectError(error.BadSignature, verifyProof(arena, tampered, .{ .method = "POST", .uri = "https://mcp.example.com/mcp" }, .{}, 1_000_000));
}

test "proof headers that the verifier refuses" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const key: jwt.SigningKey = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{12} ** 32) };
    const jwk = try jwt.publicJwk(arena, &key);
    const claims = "{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://h/t\",\"iat\":1000}";
    const expect: Expectation = .{ .method = "POST", .uri = "https://h/t" };
    _ = try verifyProof(arena, try jwt.sign(arena, &key, claims, .{ .typ = proof_type, .jwk = jwk }), expect, .{}, 1000);
    try std.testing.expectError(error.TypeMismatch, verifyProof(arena, try jwt.sign(arena, &key, claims, .{ .jwk = jwk }), expect, .{}, 1000));
    try std.testing.expectError(error.BadKey, verifyProof(arena, try jwt.sign(arena, &key, claims, .{ .typ = proof_type }), expect, .{}, 1000));
    // A private key in the `jwk` header.
    const private = try std.fmt.allocPrint(arena, "{s},\"d\":\"AAAA\"}}", .{jwk[0 .. jwk.len - 1]});
    try std.testing.expectError(error.BadKey, verifyProof(arena, try jwt.sign(arena, &key, claims, .{ .typ = proof_type, .jwk = private }), expect, .{}, 1000));
    // Another key in the `jwk` header than the key that signed.
    const other: jwt.SigningKey = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{13} ** 32) };
    try std.testing.expectError(error.BadSignature, verifyProof(arena, try jwt.sign(arena, &key, claims, .{ .typ = proof_type, .jwk = try jwt.publicJwk(arena, &other) }), expect, .{}, 1000));
    // HS256 and missing claims.
    const hs: jwt.SigningKey = .{ .hs256 = "a-shared-secret-of-thirty-two-b!" };
    try std.testing.expectError(error.UnsupportedAlgorithm, verifyProof(arena, try jwt.sign(arena, &hs, claims, .{ .typ = proof_type, .jwk = jwk }), expect, .{}, 1000));
    try std.testing.expectError(error.Malformed, verifyProof(arena, try jwt.sign(arena, &key, "{\"htm\":\"POST\",\"htu\":\"https://h/t\",\"iat\":1000}", .{ .typ = proof_type, .jwk = jwk }), expect, .{}, 1000));
    try std.testing.expectError(error.Malformed, verifyProof(arena, try jwt.sign(arena, &key, "{\"jti\":\"j\",\"htu\":\"https://h/t\",\"iat\":1000}", .{ .typ = proof_type, .jwk = jwk }), expect, .{}, 1000));
    try std.testing.expectError(error.Malformed, verifyProof(arena, "not-a-jwt", expect, .{}, 1000));
    // The header `{}` has no `typ`.
    try std.testing.expectError(error.TypeMismatch, verifyProof(arena, "e30", expect, .{}, 1000));
}

test "every asymmetric key type makes a proof" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{ "test/fixtures/tls/pem/p256.key", "test/fixtures/tls/pem/p384.key", "test/fixtures/tls/pem/ed25519.key", "test/fixtures/jwt/rsa2048.key" }) |path| {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 16));
        defer gpa.free(text);
        var prover: Prover = try .init(io, gpa, try jwt.SigningKey.fromPem(gpa, text));
        defer prover.deinit();
        const p = try prover.proof(arena, "POST", "https://mcp.example/mcp", "t");
        const now = common.now(io, null);
        const ok = try verifyProof(arena, p, .{ .method = "POST", .uri = "https://mcp.example/mcp", .access_token = "t", .jkt = prover.jkt }, .{}, now);
        try std.testing.expectEqualStrings(prover.jkt, ok.jkt);
    }
    const rsa_text = try std.Io.Dir.cwd().readFileAlloc(io, "test/fixtures/jwt/rsa2048.key", gpa, .limited(1 << 16));
    defer gpa.free(rsa_text);
    var pss: Prover = try .init(io, gpa, (try jwt.SigningKey.fromPem(gpa, rsa_text)).usePss());
    defer pss.deinit();
    try std.testing.expectEqual(jwt.Algorithm.PS256, pss.algorithm());
    _ = try verifyProof(arena, try pss.proof(arena, "GET", "https://h/", null), .{ .method = "GET", .uri = "https://h" }, .{}, common.now(io, null));
    try std.testing.expectError(error.SymmetricKey, Prover.init(io, gpa, .{ .hs256 = "secret" }));
}

test "the JWK thumbprint of RFC 7638" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The example of RFC 7638 section 3.1.
    const example =
        \\{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}
    ;
    const tp = (try jwt.jwkThumbprint(arena, try json.parseTree(arena, example))).?;
    try std.testing.expectEqualStrings("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", tp);
    try std.testing.expect((try jwt.jwkThumbprint(arena, try json.parseTree(arena, "{\"kty\":\"oct\",\"k\":\"AA\"}"))) == null);
}

test "nonces: the issuer accepts its own nonces within the lifetime" {
    const io = std.testing.io;
    const issuer: NonceIssuer = try .init(io);
    var buf: [NonceIssuer.encoded_len]u8 = undefined;
    const n = try issuer.issue(io, &buf, 5000);
    try std.testing.expect(validNonce(n));
    try std.testing.expect(issuer.check(n, 5000));
    try std.testing.expect(issuer.check(n, 5300));
    try std.testing.expect(!issuer.check(n, 5301));
    try std.testing.expect(!issuer.check(n, 4900));
    const other: NonceIssuer = try .init(io);
    try std.testing.expect(!other.check(n, 5000));
    var bad = buf;
    bad[10] = if (bad[10] == 'A') 'B' else 'A';
    try std.testing.expect(!issuer.check(&bad, 5000));
    try std.testing.expect(!issuer.check("short", 5000));

    // A proof must carry a nonce of the issuer.
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var prover: Prover = try .init(io, std.testing.allocator, .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{14} ** 32) });
    defer prover.deinit();
    prover.clock = fixedClock;
    const expect: Expectation = .{ .method = "POST", .uri = "https://rs.example/mcp" };
    const without = try prover.proof(arena, "POST", "https://rs.example/mcp", null);
    try std.testing.expectError(error.UseNonce, verifyProof(arena, without, expect, .{ .nonce = &issuer }, 1_000_000));
    const fresh = try issuer.issue(io, &buf, 1_000_000);
    try prover.rememberNonce("https://RS.example/other", fresh);
    try prover.rememberNonce("https://as.example/token", "as-nonce");
    try prover.rememberNonce("https://rs.example/mcp", "bad nonce with spaces");
    const with = try prover.proof(arena, "POST", "https://rs.example/mcp", null);
    const ok = try verifyProof(arena, with, expect, .{ .nonce = &issuer }, 1_000_010);
    try std.testing.expectEqualStrings(fresh, ok.nonce.?);
    // The same nonce from an issuer with a shorter lifetime: the proof is fresh, the nonce is not.
    const short: NonceIssuer = .{ .key = issuer.key, .lifetime_seconds = 100 };
    try std.testing.expectError(error.UseNonce, verifyProof(arena, with, expect, .{ .nonce = &short }, 1_000_150));
    const as_proof = try prover.proof(arena, "POST", "https://as.example/token", null);
    try std.testing.expectEqualStrings("as-nonce", json.getString(try jwt.decodePayloadUnverified(arena, as_proof), "nonce").?);
}

test "the replay check refuses a second use of a proof" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var prover: Prover = try .init(std.testing.io, std.testing.allocator, .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{15} ** 32) });
    defer prover.deinit();
    prover.clock = fixedClock;
    const Store = struct {
        last: ?[]const u8 = null,
        fn seen(userdata: ?*anyopaque, jkt: []const u8, jti: []const u8, expires_at: i64) bool {
            _ = jkt;
            _ = expires_at;
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.last) |l| if (std.mem.eql(u8, l, jti)) return true;
            self.last = jti;
            return false;
        }
    };
    var store: Store = .{};
    const options: VerifyOptions = .{ .replay = .{ .userdata = &store, .seen = Store.seen } };
    const p = try prover.proof(arena, "POST", "https://h/mcp", null);
    _ = try verifyProof(arena, p, .{ .method = "POST", .uri = "https://h/mcp" }, options, 1_000_000);
    try std.testing.expectError(error.Replayed, verifyProof(arena, p, .{ .method = "POST", .uri = "https://h/mcp" }, options, 1_000_000));
}

test "target URI normalization" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expect(try sameTargetUri(arena, "HTTPS://Example.COM:443/a?b#c", "https://example.com/a"));
    try std.testing.expect(try sameTargetUri(arena, "http://example.com:80", "http://example.com/"));
    try std.testing.expect(try sameTargetUri(arena, "http://127.0.0.1:8080/mcp", "http://127.0.0.1:8080/mcp"));
    try std.testing.expect(!try sameTargetUri(arena, "http://example.com:8080/", "http://example.com/"));
    try std.testing.expect(!try sameTargetUri(arena, "https://example.com/A", "https://example.com/a"));
    try std.testing.expect(!try sameTargetUri(arena, "https://u@example.com/a", "https://example.com/a"));
    try std.testing.expect(!try sameTargetUri(arena, "ftp://example.com/a", "ftp://example.com/a"));
    try std.testing.expectEqualStrings("https://[::1]:8443/mcp", (try normalizeUri(arena, "HTTPS://[::1]:8443/mcp")).?);
}

fn fixedClock() i64 {
    return 1_000_000;
}
