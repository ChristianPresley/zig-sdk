//! The resource server side of MCP authorization: protected resource metadata, bearer token
//! checks and the `WWW-Authenticate` challenges the specification mandates. With a DPoP policy,
//! the server also accepts DPoP-bound tokens and checks their proofs (RFC 9449).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const dpop = @import("dpop.zig");
const jwt_mod = @import("jwt.zig");

/// Who the token stands for. Handlers read it through the request context.
pub const Principal = struct {
    /// The issuer of the token, the `iss` claim of a JWT.
    issuer: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    scopes: []const []const u8 = &.{},
    expires_at: ?i64 = null,
    /// The `jkt` of the `cnf` claim: the JWK thumbprint of the DPoP key of the token (RFC
    /// 9449 section 6). Null for a token without a binding. A verifier that reads tokens
    /// with `cnf` must set it, else the server cannot refuse a bound token with the Bearer scheme.
    confirmation: ?[]const u8 = null,
    /// All claims, for application checks.
    claims: ?Value = null,
};

pub const VerifyError = error{ InvalidToken, OutOfMemory };

/// Turns a bearer token into a principal.
pub const TokenVerifier = struct {
    ptr: *anyopaque,
    verify: *const fn (ptr: *anyopaque, arena: Allocator, token: []const u8) VerifyError!Principal,

    pub fn call(self: TokenVerifier, arena: Allocator, token: []const u8) VerifyError!Principal {
        return self.verify(self.ptr, arena, token);
    }
};

/// A broader scope and the narrower scopes that it implies.
pub const ScopeRule = struct {
    scope: []const u8,
    implies: []const []const u8,
};

/// True when `held` has `needed`, or a scope that implies `needed` through the rules of
/// `hierarchy`. An implication can use more than one rule.
pub fn scopeSatisfied(hierarchy: []const ScopeRule, held: []const []const u8, needed: []const u8) bool {
    return scopeFound(hierarchy, held, needed, hierarchy.len);
}

fn scopeFound(hierarchy: []const ScopeRule, held: []const []const u8, needed: []const u8, depth: usize) bool {
    for (held) |have| if (std.mem.eql(u8, have, needed)) return true;
    if (depth == 0) return false;
    for (hierarchy) |rule| {
        for (rule.implies) |narrow| if (std.mem.eql(u8, narrow, needed)) {
            if (scopeFound(hierarchy, held, rule.scope, depth - 1)) return true;
        };
    }
    return false;
}

/// The answer to a rejected request.
pub const Challenge = struct {
    status: u16,
    www_authenticate: []const u8,
    /// A second `WWW-Authenticate` header: the DPoP challenge, when the server accepts both
    /// schemes and the request had no token.
    www_authenticate_extra: ?[]const u8 = null,
    /// The `DPoP-Nonce` header, for the error `use_dpop_nonce`.
    dpop_nonce: ?[]const u8 = null,
    body: []const u8,

    /// The response headers of the challenge, without `content-type`.
    pub fn headers(self: *const Challenge, buf: *[3]std.http.Header) []std.http.Header {
        var n: usize = 0;
        buf[n] = .{ .name = "www-authenticate", .value = self.www_authenticate };
        n += 1;
        if (self.www_authenticate_extra) |w| {
            buf[n] = .{ .name = "www-authenticate", .value = w };
            n += 1;
        }
        if (self.dpop_nonce) |v| {
            buf[n] = .{ .name = "dpop-nonce", .value = v };
            n += 1;
        }
        return buf[0..n];
    }
};

/// How the resource server accepts DPoP-bound tokens (RFC 9449 and the DPoP extension of MCP).
pub const DpopPolicy = struct {
    /// Refuse bearer tokens. Without it, the server accepts both schemes.
    required: bool = false,
    /// The checks of each proof. Set `verify.nonce` to require a nonce of the server in each
    /// proof. Set `verify.replay` to refuse a proof that the server saw before.
    verify: dpop.VerifyOptions = .{},
    /// The source of random bytes for new nonces.
    io: Io,
    /// The clock of the proof checks. Null uses the real clock of `io`.
    clock: ?*const fn () i64 = null,

    fn now(self: *const DpopPolicy) i64 {
        if (self.clock) |f| return f();
        return Io.Clock.Timestamp.now(self.io, .real).raw.toSeconds();
    }

    /// The `algs` of the DPoP challenge and of the metadata.
    fn algorithms(self: *const DpopPolicy) []const jwt_mod.Algorithm {
        return self.verify.algorithms;
    }
};

/// The parts of an HTTP request that the authorization needs.
pub const Request = struct {
    /// The `Authorization` header.
    authorization: ?[]const u8 = null,
    /// The values of the `DPoP` headers. A request with a DPoP-bound token must have exactly one.
    dpop: []const []const u8 = &.{},
    /// The HTTP method, for the `htm` claim of a proof.
    method: []const u8 = "POST",
};

const Scheme = enum { bearer, dpop };

pub const Decision = union(enum) {
    ok: Principal,
    challenge: Challenge,
};

pub const ResourceServer = struct {
    /// The canonical URI of the MCP endpoint, for example `https://host/mcp`.
    resource: []const u8,
    /// The URL of the protected resource metadata document that challenges advertise.
    resource_metadata_url: []const u8,
    authorization_servers: []const []const u8,
    scopes_supported: []const []const u8 = &.{},
    /// Scopes every request needs.
    required_scopes: []const []const u8 = &.{},
    /// Broader scopes and the narrower scopes that they imply. A token with a broader scope
    /// satisfies a need for each scope that it implies.
    scope_hierarchy: []const ScopeRule = &.{},
    verifier: TokenVerifier,
    /// Accept DPoP-bound tokens with this policy. Null accepts bearer tokens only. The `htu` of
    /// each proof must be `resource`, so `resource` must be the URI that clients send requests to.
    dpop: ?*const DpopPolicy = null,

    /// True when the principal has the scope `needed`, or a broader scope that implies it.
    /// Handlers can call it for the scopes of one operation.
    pub fn hasScope(self: *const ResourceServer, principal: *const Principal, needed: []const u8) bool {
        return scopeSatisfied(self.scope_hierarchy, principal.scopes, needed);
    }

    /// The metadata document (RFC 9728).
    pub fn metadataJson(self: *const ResourceServer, arena: Allocator) Allocator.Error![]u8 {
        var aw: std.Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        w.print("{{\"resource\":{f},\"authorization_servers\":[", .{std.json.fmt(self.resource, .{})}) catch return error.OutOfMemory;
        for (self.authorization_servers, 0..) |as, i| {
            if (i > 0) w.writeByte(',') catch return error.OutOfMemory;
            w.print("{f}", .{std.json.fmt(as, .{})}) catch return error.OutOfMemory;
        }
        w.writeAll("],\"bearer_methods_supported\":[\"header\"]") catch return error.OutOfMemory;
        if (self.dpop) |policy| {
            // RFC 9728 section 2.
            w.writeAll(",\"dpop_signing_alg_values_supported\":[") catch return error.OutOfMemory;
            var first = true;
            for (policy.algorithms()) |a| {
                if (!a.isAsymmetric()) continue;
                w.print("{s}\"{t}\"", .{ if (first) "" else ",", a }) catch return error.OutOfMemory;
                first = false;
            }
            w.writeByte(']') catch return error.OutOfMemory;
            if (policy.required) w.writeAll(",\"dpop_bound_access_tokens_required\":true") catch return error.OutOfMemory;
        }
        if (self.scopes_supported.len > 0) {
            w.writeAll(",\"scopes_supported\":[") catch return error.OutOfMemory;
            for (self.scopes_supported, 0..) |s, i| {
                if (i > 0) w.writeByte(',') catch return error.OutOfMemory;
                w.print("{f}", .{std.json.fmt(s, .{})}) catch return error.OutOfMemory;
            }
            w.writeByte(']') catch return error.OutOfMemory;
        }
        w.writeByte('}') catch return error.OutOfMemory;
        return aw.toOwnedSlice();
    }

    /// Decide about one request from its `Authorization` header. A DPoP-bound token needs
    /// `authorizeRequest`, which also gets the `DPoP` header.
    pub fn authorize(self: *const ResourceServer, arena: Allocator, authorization: ?[]const u8) Allocator.Error!Decision {
        return self.authorizeRequest(arena, .{ .authorization = authorization });
    }

    /// Decide about one request from its `Authorization` and `DPoP` headers.
    pub fn authorizeRequest(self: *const ResourceServer, arena: Allocator, req: Request) Allocator.Error!Decision {
        // Without a token, the server names each scheme that it accepts.
        const header = req.authorization orelse return .{ .challenge = try self.challengeAll(arena) };
        const scheme: Scheme = if (startsWithScheme(header, "Bearer")) .bearer else if (startsWithScheme(header, "DPoP")) .dpop else {
            return .{ .challenge = try self.challenge(arena, self.primaryScheme(), 400, "invalid_request", "The Authorization header must carry a bearer token or a DPoP-bound token") };
        };
        if (scheme == .dpop and self.dpop == null) {
            return .{ .challenge = try self.challenge(arena, .bearer, 400, "invalid_request", "The server accepts bearer tokens only") };
        }
        if (scheme == .bearer) if (self.dpop) |policy| if (policy.required) {
            return .{ .challenge = try self.challenge(arena, .dpop, 401, "invalid_token", "The server accepts DPoP-bound tokens only") };
        };
        const token = std.mem.trim(u8, header[std.mem.indexOfScalar(u8, header, ' ').? + 1 ..], " \t");
        if (token.len == 0) return .{ .challenge = try self.challenge(arena, scheme, 400, "invalid_request", "The access token is empty") };
        if (scheme == .dpop and req.dpop.len != 1) {
            return .{ .challenge = try self.challenge(arena, .dpop, 401, "invalid_dpop_proof", "The request must have exactly one DPoP header") };
        }
        const principal = self.verifier.call(arena, token) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidToken => return .{ .challenge = try self.challenge(arena, scheme, 401, "invalid_token", "The access token is not valid") },
        };
        switch (scheme) {
            // RFC 9449 section 7.2: a DPoP-bound token never counts as a bearer token.
            .bearer => if (principal.confirmation != null) {
                return .{ .challenge = try self.challenge(arena, if (self.dpop != null) .dpop else .bearer, 401, "invalid_token", "The access token is DPoP-bound and needs the DPoP scheme") };
            },
            .dpop => {
                const policy = self.dpop.?;
                const jkt = principal.confirmation orelse {
                    return .{ .challenge = try self.challenge(arena, .dpop, 401, "invalid_token", "The access token is not DPoP-bound") };
                };
                _ = dpop.verifyProof(arena, req.dpop[0], .{
                    .method = req.method,
                    .uri = self.resource,
                    .access_token = token,
                    .jkt = jkt,
                }, policy.verify, policy.now()) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.UseNonce => return .{ .challenge = try self.nonceChallenge(arena, policy) },
                    else => return .{ .challenge = try self.challenge(arena, .dpop, 401, "invalid_dpop_proof", dpop.describe(e)) },
                };
            },
        }
        for (self.required_scopes) |needed| {
            if (!self.hasScope(&principal, needed)) return .{ .challenge = try self.challenge(arena, scheme, 403, "insufficient_scope", "The token lacks a required scope") };
        }
        return .{ .ok = principal };
    }

    /// A `401` challenge with the error `invalid_token`, for a transport that refuses a token
    /// after its own check. `dpop_scheme` selects the `DPoP` challenge. The WebSocket server
    /// uses it for a token that expired before the upgrade.
    pub fn invalidToken(self: *const ResourceServer, arena: Allocator, dpop_scheme: bool, description: []const u8) Allocator.Error!Challenge {
        return self.challenge(arena, if (dpop_scheme) .dpop else .bearer, 401, "invalid_token", description);
    }

    /// The scheme of a challenge that is not for one scheme.
    fn primaryScheme(self: *const ResourceServer) Scheme {
        const policy = self.dpop orelse return .bearer;
        return if (policy.required) .dpop else .bearer;
    }

    /// A `401` without an error that names each accepted scheme.
    fn challengeAll(self: *const ResourceServer, arena: Allocator) Allocator.Error!Challenge {
        var c = try self.challenge(arena, self.primaryScheme(), 401, null, null);
        if (self.dpop) |policy| if (!policy.required) {
            c.www_authenticate_extra = try self.challengeValue(arena, .dpop, null, null);
        };
        return c;
    }

    /// A `401` with the error `use_dpop_nonce` and a new nonce (RFC 9449 section 9).
    fn nonceChallenge(self: *const ResourceServer, arena: Allocator, policy: *const DpopPolicy) Allocator.Error!Challenge {
        var c = try self.challenge(arena, .dpop, 401, "use_dpop_nonce", "The server requires a DPoP nonce");
        if (policy.verify.nonce) |issuer| {
            const buf = try arena.create([dpop.NonceIssuer.encoded_len]u8);
            c.dpop_nonce = issuer.issue(policy.io, buf, policy.now()) catch null;
        }
        return c;
    }

    fn challenge(self: *const ResourceServer, arena: Allocator, scheme: Scheme, status: u16, err: ?[]const u8, description: ?[]const u8) Allocator.Error!Challenge {
        const body = try std.fmt.allocPrint(arena, "{{\"error\":{f},\"error_description\":{f}}}", .{ std.json.fmt(err orelse "unauthorized", .{}), std.json.fmt(description orelse "Authorization is required", .{}) });
        return .{ .status = status, .www_authenticate = try self.challengeValue(arena, scheme, err, description), .body = body };
    }

    fn challengeValue(self: *const ResourceServer, arena: Allocator, scheme: Scheme, err: ?[]const u8, description: ?[]const u8) Allocator.Error![]const u8 {
        var aw: std.Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        w.writeAll(if (scheme == .dpop) "DPoP" else "Bearer") catch return error.OutOfMemory;
        var first = true;
        if (err) |e| {
            w.print(" error=\"{s}\"", .{e}) catch return error.OutOfMemory;
            first = false;
        }
        if (description) |d| {
            w.print("{s} error_description=\"{s}\"", .{ if (first) "" else ",", d }) catch return error.OutOfMemory;
            first = false;
        }
        w.print("{s} resource_metadata=\"{s}\"", .{ if (first) "" else ",", self.resource_metadata_url }) catch return error.OutOfMemory;
        if (self.required_scopes.len > 0) {
            w.writeAll(", scope=\"") catch return error.OutOfMemory;
            for (self.required_scopes, 0..) |s, i| {
                if (i > 0) w.writeByte(' ') catch return error.OutOfMemory;
                w.writeAll(s) catch return error.OutOfMemory;
            }
            w.writeByte('"') catch return error.OutOfMemory;
        }
        if (scheme == .dpop) if (self.dpop) |policy| {
            w.writeAll(", algs=\"") catch return error.OutOfMemory;
            var first_alg = true;
            for (policy.algorithms()) |a| {
                if (!a.isAsymmetric()) continue;
                w.print("{s}{t}", .{ if (first_alg) "" else " ", a }) catch return error.OutOfMemory;
                first_alg = false;
            }
            w.writeByte('"') catch return error.OutOfMemory;
        };
        return aw.toOwnedSlice();
    }
};

/// A verifier for JSON Web Tokens with a static key set.
pub const JwtVerifier = struct {
    options: @import("jwt.zig").Options,
    /// The clock for the time claims.
    clock: union(enum) {
        /// The real clock of this `Io`.
        io: std.Io,
        /// A function that returns Unix seconds (tests).
        fixed: *const fn () i64,
    },

    fn now(self: *const JwtVerifier) i64 {
        return switch (self.clock) {
            .io => |io| std.Io.Clock.Timestamp.now(io, .real).raw.toSeconds(),
            .fixed => |f| f(),
        };
    }

    pub fn verifier(self: *JwtVerifier) TokenVerifier {
        return .{ .ptr = self, .verify = verify };
    }

    fn verify(ptr: *anyopaque, arena: Allocator, token: []const u8) VerifyError!Principal {
        const self: *JwtVerifier = @ptrCast(@alignCast(ptr));
        const jwt = @import("jwt.zig");
        const claims = jwt.verify(arena, token, self.options, self.now()) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidToken,
        };
        return .{
            .issuer = claims.issuer,
            .subject = claims.subject,
            .client_id = claims.client_id,
            .scopes = claims.scopes,
            .expires_at = claims.expires_at,
            .confirmation = confirmationOf(claims.payload),
            .claims = claims.payload,
        };
    }
};

/// The `jkt` member of the `cnf` claim (RFC 9449 section 6.1), or null.
pub fn confirmationOf(payload: Value) ?[]const u8 {
    if (payload != .object) return null;
    const cnf = payload.object.get("cnf") orelse return null;
    return json.getString(cnf, "jkt");
}

/// True when `header` starts with `scheme` and a space. The comparison ignores case.
fn startsWithScheme(header: []const u8, scheme: []const u8) bool {
    return header.len > scheme.len and std.ascii.eqlIgnoreCase(header[0..scheme.len], scheme) and header[scheme.len] == ' ';
}

test "challenges and decisions" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const jwt = @import("jwt.zig");
    const secret = "resource-server-test-secret-32b!";
    const keys = [_]jwt.Key{.{ .alg = .HS256, .material = .{ .secret = secret } }};
    var jv: JwtVerifier = .{ .options = .{ .keys = &keys, .audience = "https://rs.example/mcp" }, .clock = .{ .fixed = fixedNow } };
    const rs: ResourceServer = .{
        .resource = "https://rs.example/mcp",
        .resource_metadata_url = "https://rs.example/.well-known/oauth-protected-resource/mcp",
        .authorization_servers = &.{"https://as.example"},
        .scopes_supported = &.{ "mcp:read", "mcp:write" },
        .required_scopes = &.{"mcp:read"},
        .verifier = jv.verifier(),
    };
    const doc = try rs.metadataJson(arena);
    try std.testing.expectEqualStrings("{\"resource\":\"https://rs.example/mcp\",\"authorization_servers\":[\"https://as.example\"],\"bearer_methods_supported\":[\"header\"],\"scopes_supported\":[\"mcp:read\",\"mcp:write\"]}", doc);

    const none = try rs.authorize(arena, null);
    try std.testing.expectEqual(401, none.challenge.status);
    try std.testing.expectEqualStrings("Bearer resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:read\"", none.challenge.www_authenticate);
    const basic = try rs.authorize(arena, "Basic abc");
    try std.testing.expectEqual(400, basic.challenge.status);
    const bad = try rs.authorize(arena, "Bearer not.a.jwt");
    try std.testing.expectEqual(401, bad.challenge.status);
    try std.testing.expect(std.mem.startsWith(u8, bad.challenge.www_authenticate, "Bearer error=\"invalid_token\""));
    const low = try jwt.signHs256(arena, "{\"sub\":\"eve\",\"aud\":\"https://rs.example/mcp\",\"exp\":2000,\"scope\":\"mcp:write\"}", secret, null);
    const scope = try rs.authorize(arena, try std.mem.concat(arena, u8, &.{ "Bearer ", low }));
    try std.testing.expectEqual(403, scope.challenge.status);
    try std.testing.expect(std.mem.indexOf(u8, scope.challenge.www_authenticate, "insufficient_scope") != null);
    const good = try jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"https://rs.example/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}", secret, null);
    const ok = try rs.authorize(arena, try std.mem.concat(arena, u8, &.{ "Bearer ", good }));
    try std.testing.expectEqualStrings("alice", ok.ok.subject.?);
    const wrong_aud = try jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"https://other\",\"exp\":2000,\"scope\":\"mcp:read\"}", secret, null);
    const rejected = try rs.authorize(arena, try std.mem.concat(arena, u8, &.{ "Bearer ", wrong_aud }));
    try std.testing.expectEqual(401, rejected.challenge.status);
    // The audience check accepts an uppercase scheme and host.
    const upper_aud = try jwt.signHs256(arena, "{\"iss\":\"https://as.example\",\"sub\":\"alice\",\"aud\":\"HTTPS://RS.EXAMPLE/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}", secret, null);
    const upper = try rs.authorize(arena, try std.mem.concat(arena, u8, &.{ "Bearer ", upper_aud }));
    try std.testing.expectEqualStrings("alice", upper.ok.subject.?);
    try std.testing.expectEqualStrings("https://as.example", upper.ok.issuer.?);
}

test "scope hierarchy" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const jwt = @import("jwt.zig");
    const secret = "resource-server-test-secret-32b!";
    const keys = [_]jwt.Key{.{ .alg = .HS256, .material = .{ .secret = secret } }};
    var jv: JwtVerifier = .{ .options = .{ .keys = &keys, .audience = "https://rs.example/mcp" }, .clock = .{ .fixed = fixedNow } };
    const hierarchy = [_]ScopeRule{
        .{ .scope = "mcp:admin", .implies = &.{"mcp:write"} },
        .{ .scope = "mcp:write", .implies = &.{"mcp:read"} },
    };
    const rs: ResourceServer = .{
        .resource = "https://rs.example/mcp",
        .resource_metadata_url = "https://rs.example/.well-known/oauth-protected-resource/mcp",
        .authorization_servers = &.{"https://as.example"},
        .required_scopes = &.{"mcp:read"},
        .scope_hierarchy = &hierarchy,
        .verifier = jv.verifier(),
    };
    // A broader scope satisfies the required narrower scope, also through two rules.
    for ([_][]const u8{ "mcp:read", "mcp:write", "mcp:admin" }) |scope| {
        const payload = try std.fmt.allocPrint(arena, "{{\"sub\":\"alice\",\"aud\":\"https://rs.example/mcp\",\"exp\":2000,\"scope\":\"{s}\"}}", .{scope});
        const token = try jwt.signHs256(arena, payload, secret, null);
        const decision = try rs.authorize(arena, try std.mem.concat(arena, u8, &.{ "Bearer ", token }));
        try std.testing.expectEqualStrings("alice", decision.ok.subject.?);
    }
    // A narrower scope does not satisfy a broader one, and unrelated scopes do not count.
    const other = try jwt.signHs256(arena, "{\"sub\":\"eve\",\"aud\":\"https://rs.example/mcp\",\"exp\":2000,\"scope\":\"files:read\"}", secret, null);
    try std.testing.expectEqual(403, (try rs.authorize(arena, try std.mem.concat(arena, u8, &.{ "Bearer ", other }))).challenge.status);
    const reader: Principal = .{ .scopes = &.{"mcp:read"} };
    try std.testing.expect(rs.hasScope(&reader, "mcp:read"));
    try std.testing.expect(!rs.hasScope(&reader, "mcp:write"));
    const admin: Principal = .{ .scopes = &.{"mcp:admin"} };
    try std.testing.expect(rs.hasScope(&admin, "mcp:read"));
    try std.testing.expect(!rs.hasScope(&admin, "mcp:delete"));
    // A cycle in the rules ends.
    const cycle = [_]ScopeRule{ .{ .scope = "a", .implies = &.{"b"} }, .{ .scope = "b", .implies = &.{"a"} } };
    try std.testing.expect(!scopeSatisfied(&cycle, &.{"c"}, "a"));
    try std.testing.expect(scopeSatisfied(&cycle, &.{"b"}, "a"));
}

test "DPoP: bound tokens, proofs, nonces and the downgrade to bearer" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    const jwt = @import("jwt.zig");
    const secret = "resource-server-test-secret-32b!";
    const keys = [_]jwt.Key{.{ .alg = .HS256, .material = .{ .secret = secret } }};
    var jv: JwtVerifier = .{ .options = .{ .keys = &keys, .audience = "https://rs.example/mcp" }, .clock = .{ .fixed = fixedNow } };
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var prover: dpop.Prover = try .init(io, std.testing.allocator, .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{31} ** 32) });
    defer prover.deinit();
    prover.clock = fixedNow;
    const issuer: dpop.NonceIssuer = try .init(io);
    var policy: DpopPolicy = .{ .io = io, .clock = fixedNow };
    var rs: ResourceServer = .{
        .resource = "https://rs.example/mcp",
        .resource_metadata_url = "https://rs.example/.well-known/oauth-protected-resource/mcp",
        .authorization_servers = &.{"https://as.example"},
        .verifier = jv.verifier(),
        .dpop = &policy,
    };
    const bound_payload = try std.fmt.allocPrint(arena, "{{\"sub\":\"alice\",\"aud\":\"https://rs.example/mcp\",\"exp\":2000,\"cnf\":{{\"jkt\":\"{s}\"}}}}", .{prover.jkt});
    const bound = try jwt.signHs256(arena, bound_payload, secret, null);
    const plain = try jwt.signHs256(arena, "{\"sub\":\"bob\",\"aud\":\"https://rs.example/mcp\",\"exp\":2000}", secret, null);
    const dpop_auth = try std.mem.concat(arena, u8, &.{ "DPoP ", bound });

    // The metadata names the proof algorithms.
    const doc = try json.parseTree(arena, try rs.metadataJson(arena));
    try std.testing.expect(doc.object.get("dpop_signing_alg_values_supported") != null);
    try std.testing.expect(doc.object.get("dpop_bound_access_tokens_required") == null);

    // Without a token, both schemes appear.
    const none = (try rs.authorizeRequest(arena, .{})).challenge;
    try std.testing.expect(std.mem.startsWith(u8, none.www_authenticate, "Bearer "));
    try std.testing.expect(std.mem.startsWith(u8, none.www_authenticate_extra.?, "DPoP resource_metadata="));
    try std.testing.expect(std.mem.indexOf(u8, none.www_authenticate_extra.?, "algs=\"ES256 ES384 EdDSA RS256 PS256\"") != null);

    // A good proof.
    const proof = try prover.proof(arena, "POST", "https://rs.example/mcp", bound);
    const ok = try rs.authorizeRequest(arena, .{ .authorization = dpop_auth, .dpop = &.{proof} });
    try std.testing.expectEqualStrings("alice", ok.ok.subject.?);
    try std.testing.expectEqualStrings(prover.jkt, ok.ok.confirmation.?);

    // The bound token as a bearer token: refused.
    const downgrade = (try rs.authorizeRequest(arena, .{ .authorization = try std.mem.concat(arena, u8, &.{ "Bearer ", bound }) })).challenge;
    try std.testing.expectEqual(401, downgrade.status);
    try std.testing.expect(std.mem.startsWith(u8, downgrade.www_authenticate, "DPoP error=\"invalid_token\""));
    // A token without a binding is still a good bearer token.
    try std.testing.expectEqualStrings("bob", (try rs.authorizeRequest(arena, .{ .authorization = try std.mem.concat(arena, u8, &.{ "Bearer ", plain }) })).ok.subject.?);
    // A token without a binding with the DPoP scheme: refused.
    const plain_proof = try prover.proof(arena, "POST", "https://rs.example/mcp", plain);
    const unbound = (try rs.authorizeRequest(arena, .{ .authorization = try std.mem.concat(arena, u8, &.{ "DPoP ", plain }), .dpop = &.{plain_proof} })).challenge;
    try std.testing.expect(std.mem.indexOf(u8, unbound.www_authenticate, "invalid_token") != null);

    // A missing proof, two proofs, a proof for another URI and a proof of another key.
    const missing = (try rs.authorizeRequest(arena, .{ .authorization = dpop_auth })).challenge;
    try std.testing.expect(std.mem.indexOf(u8, missing.www_authenticate, "invalid_dpop_proof") != null);
    const two = (try rs.authorizeRequest(arena, .{ .authorization = dpop_auth, .dpop = &.{ proof, proof } })).challenge;
    try std.testing.expect(std.mem.indexOf(u8, two.www_authenticate, "invalid_dpop_proof") != null);
    const wrong_uri = try prover.proof(arena, "POST", "https://rs.example/other", bound);
    try std.testing.expect(std.mem.indexOf(u8, (try rs.authorizeRequest(arena, .{ .authorization = dpop_auth, .dpop = &.{wrong_uri} })).challenge.www_authenticate, "invalid_dpop_proof") != null);
    var thief: dpop.Prover = try .init(io, std.testing.allocator, .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{32} ** 32) });
    defer thief.deinit();
    thief.clock = fixedNow;
    const stolen = try thief.proof(arena, "POST", "https://rs.example/mcp", bound);
    try std.testing.expect(std.mem.indexOf(u8, (try rs.authorizeRequest(arena, .{ .authorization = dpop_auth, .dpop = &.{stolen} })).challenge.www_authenticate, "invalid_dpop_proof") != null);

    // With a nonce: the first proof gets `use_dpop_nonce` and a nonce, the next proof works.
    policy.verify.nonce = &issuer;
    const challenge = (try rs.authorizeRequest(arena, .{ .authorization = dpop_auth, .dpop = &.{proof} })).challenge;
    try std.testing.expectEqual(401, challenge.status);
    try std.testing.expect(std.mem.startsWith(u8, challenge.www_authenticate, "DPoP error=\"use_dpop_nonce\""));
    var buf: [3]std.http.Header = undefined;
    const hs = challenge.headers(&buf);
    try std.testing.expectEqual(2, hs.len);
    try std.testing.expectEqualStrings("dpop-nonce", hs[1].name);
    try prover.rememberNonce("https://rs.example/mcp", challenge.dpop_nonce.?);
    const with_nonce = try prover.proof(arena, "POST", "https://rs.example/mcp", bound);
    try std.testing.expectEqualStrings("alice", (try rs.authorizeRequest(arena, .{ .authorization = dpop_auth, .dpop = &.{with_nonce} })).ok.subject.?);

    // DPoP only: bearer tokens get a DPoP challenge.
    policy.required = true;
    const only = (try rs.authorizeRequest(arena, .{ .authorization = try std.mem.concat(arena, u8, &.{ "Bearer ", plain }) })).challenge;
    try std.testing.expect(std.mem.startsWith(u8, only.www_authenticate, "DPoP error=\"invalid_token\""));
    const required_none = (try rs.authorizeRequest(arena, .{})).challenge;
    try std.testing.expect(std.mem.startsWith(u8, required_none.www_authenticate, "DPoP "));
    try std.testing.expect(required_none.www_authenticate_extra == null);
    const required_doc = try json.parseTree(arena, try rs.metadataJson(arena));
    try std.testing.expect(required_doc.object.get("dpop_bound_access_tokens_required").?.bool);

    // A server without DPoP refuses the scheme and a bound bearer token.
    rs.dpop = null;
    try std.testing.expectEqual(400, (try rs.authorizeRequest(arena, .{ .authorization = dpop_auth, .dpop = &.{proof} })).challenge.status);
    try std.testing.expectEqual(401, (try rs.authorize(arena, try std.mem.concat(arena, u8, &.{ "Bearer ", bound }))).challenge.status);
}

fn fixedNow() i64 {
    return 1500;
}
