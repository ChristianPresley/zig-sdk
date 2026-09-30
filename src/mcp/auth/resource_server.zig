//! The resource server side of MCP authorization: protected resource metadata, bearer token
//! checks and the `WWW-Authenticate` challenges the specification mandates.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");

/// Who the token stands for. Handlers read it through the request context.
pub const Principal = struct {
    /// The issuer of the token, the `iss` claim of a JWT.
    issuer: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    scopes: []const []const u8 = &.{},
    expires_at: ?i64 = null,
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
    body: []const u8,
};

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

    /// Decide about one request from its `Authorization` header.
    pub fn authorize(self: *const ResourceServer, arena: Allocator, authorization: ?[]const u8) Allocator.Error!Decision {
        const header = authorization orelse return .{ .challenge = try self.challenge(arena, 401, null, null) };
        if (header.len < 7 or !std.ascii.eqlIgnoreCase(header[0..7], "Bearer ")) {
            return .{ .challenge = try self.challenge(arena, 400, "invalid_request", "The Authorization header must carry a bearer token") };
        }
        const token = std.mem.trim(u8, header[7..], " \t");
        if (token.len == 0) return .{ .challenge = try self.challenge(arena, 400, "invalid_request", "The bearer token is empty") };
        const principal = self.verifier.call(arena, token) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidToken => return .{ .challenge = try self.challenge(arena, 401, "invalid_token", "The access token is not valid") },
        };
        for (self.required_scopes) |needed| {
            if (!self.hasScope(&principal, needed)) return .{ .challenge = try self.challenge(arena, 403, "insufficient_scope", "The token lacks a required scope") };
        }
        return .{ .ok = principal };
    }

    fn challenge(self: *const ResourceServer, arena: Allocator, status: u16, err: ?[]const u8, description: ?[]const u8) Allocator.Error!Challenge {
        var aw: std.Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        w.writeAll("Bearer") catch return error.OutOfMemory;
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
        const body = try std.fmt.allocPrint(arena, "{{\"error\":{f},\"error_description\":{f}}}", .{ std.json.fmt(err orelse "unauthorized", .{}), std.json.fmt(description orelse "Authorization is required", .{}) });
        return .{ .status = status, .www_authenticate = try aw.toOwnedSlice(), .body = body };
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
            .claims = claims.payload,
        };
    }
};

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

fn fixedNow() i64 {
    return 1500;
}
