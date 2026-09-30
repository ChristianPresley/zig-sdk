//! Tests for the rules of the authorization page of the specification.
//! A mock authorization server and resource server records the requests of the OAuth client.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const mcp = @import("../../mcp.zig");
const json = mcp.json;
const types = mcp.types;
const OAuthClient = mcp.auth.OAuthClient;
const resource_server = mcp.auth.resource_server;
const jwt = mcp.auth.jwt;

// -- The mock authorization server and MCP endpoint ---------------------------------------------

const Entry = struct {
    method: http.Method,
    target: []u8,
    authorization: ?[]u8,
    body: []u8,

    fn path(self: Entry) []const u8 {
        const end = std.mem.indexOfScalar(u8, self.target, '?') orelse self.target.len;
        return self.target[0..end];
    }

    fn query(self: Entry) []const u8 {
        const start = std.mem.indexOfScalar(u8, self.target, '?') orelse return "";
        return self.target[start + 1 ..];
    }
};

/// One HTTP server that plays the protected resource metadata host, the authorization server
/// and the MCP endpoint. It answers every request with `connection: close` and records it.
const Mock = struct {
    gpa: Allocator,
    io: Io,
    listener: Io.net.Server = undefined,
    stopping: std.atomic.Value(bool) = .init(false),
    future: Io.Future(void) = undefined,
    base: []u8 = &.{},
    lock: Io.Mutex = .init,
    entries: std.ArrayList(Entry) = .empty,
    tokens_issued: u32 = 0,

    // Behaviour.
    /// Extra parameters of the `WWW-Authenticate` challenge of the MCP endpoint.
    challenge_extra: []const u8 = "",
    /// Extra members of the protected resource metadata document.
    prm_extra: []const u8 = "",
    /// Extra members of the authorization server metadata document.
    as_extra: []const u8 = "",
    /// The `iss` of the authorization response. Null sends the real issuer.
    iss: ?[]const u8 = null,
    /// Answer the authorization request with an error response.
    deny: bool = false,

    fn start(self: *Mock) !void {
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.listener = try address.listen(self.io, .{ .reuse_address = true });
        self.base = try std.fmt.allocPrint(self.gpa, "http://127.0.0.1:{d}", .{self.listener.socket.address.getPort()});
        self.future = try self.io.concurrent(acceptLoop, .{self});
    }

    fn stop(self: *Mock) void {
        mcp.util.wake.cancelAcceptLoop(self.io, &self.future, self.listener.socket.address, &self.stopping);
        self.listener.deinit(self.io);
        for (self.entries.items) |e| {
            self.gpa.free(e.target);
            if (e.authorization) |a| self.gpa.free(a);
            self.gpa.free(e.body);
        }
        self.entries.deinit(self.gpa);
        self.gpa.free(self.base);
    }

    fn acceptLoop(self: *Mock) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch |e| switch (e) {
                error.Canceled => return,
                else => continue,
            };
            defer stream.close(self.io);
            if (self.stopping.load(.acquire)) return;
            self.handle(stream) catch {};
        }
    }

    fn record(self: *Mock, method: http.Method, target: []const u8, authorization: ?[]const u8, body: []const u8) !void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        try self.entries.append(self.gpa, .{
            .method = method,
            .target = try self.gpa.dupe(u8, target),
            .authorization = if (authorization) |a| try self.gpa.dupe(u8, a) else null,
            .body = try self.gpa.dupe(u8, body),
        });
    }

    /// The recorded requests to `path`, in order. The caller frees the slice.
    fn requests(self: *Mock, arena: Allocator, path: []const u8) ![]Entry {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        var out: std.ArrayList(Entry) = .empty;
        for (self.entries.items) |e| if (std.mem.eql(u8, e.path(), path)) try out.append(arena, e);
        return out.items;
    }

    fn allRequests(self: *Mock, arena: Allocator) ![]Entry {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        return arena.dupe(Entry, self.entries.items);
    }

    fn handle(self: *Mock, stream: Io.net.Stream) !void {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [16 * 1024]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        var writer = stream.writer(self.io, &write_buf);
        var server: http.Server = .init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        const method = request.head.method;
        const target = try arena.dupe(u8, request.head.target);
        var authorization: ?[]const u8 = null;
        var it = request.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
            authorization = try arena.dupe(u8, h.value);
        };
        var body_buf: [4096]u8 = undefined;
        const body = try request.readerExpectNone(&body_buf).allocRemaining(arena, .limited(1 << 20));
        try self.record(method, target, authorization, body);

        const path = (Entry{ .method = method, .target = target, .authorization = null, .body = &.{} }).path();
        const json_type: []const http.Header = &.{.{ .name = "content-type", .value = "application/json" }};
        if (std.mem.eql(u8, path, "/.well-known/oauth-protected-resource/mcp")) {
            const doc = try std.fmt.allocPrint(arena, "{{\"resource\":\"{s}/mcp\",\"authorization_servers\":[\"{s}\"]{s}}}", .{ self.base, self.base, self.prm_extra });
            return request.respond(doc, .{ .keep_alive = false, .extra_headers = json_type });
        }
        if (std.mem.eql(u8, path, "/.well-known/oauth-authorization-server")) {
            const doc = try std.fmt.allocPrint(arena,
                \\{{"issuer":"{s}","authorization_endpoint":"{s}/authorize","token_endpoint":"{s}/token","registration_endpoint":"{s}/register","response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"]{s}}}
            , .{ self.base, self.base, self.base, self.base, self.as_extra });
            return request.respond(doc, .{ .keep_alive = false, .extra_headers = json_type });
        }
        if (std.mem.eql(u8, path, "/register")) {
            return request.respond("{\"client_id\":\"dyn-client\",\"token_endpoint_auth_method\":\"none\"}", .{ .status = .created, .keep_alive = false, .extra_headers = json_type });
        }
        if (std.mem.eql(u8, path, "/authorize")) {
            const q = (Entry{ .method = method, .target = target, .authorization = null, .body = &.{} }).query();
            const redirect_uri = (try formValue(arena, q, "redirect_uri")) orelse "";
            const state = (try formValue(arena, q, "state")) orelse "";
            var aw: Io.Writer.Allocating = .init(arena);
            try aw.writer.writeAll(redirect_uri);
            try aw.writer.writeAll(if (self.deny) "?error=access_denied&error_description=Denied" else "?code=code-1");
            try aw.writer.writeAll("&state=");
            try formEncode(&aw.writer, state);
            try aw.writer.writeAll("&iss=");
            try formEncode(&aw.writer, self.iss orelse self.base);
            return request.respond("", .{ .status = .found, .keep_alive = false, .extra_headers = &.{.{ .name = "location", .value = aw.written() }} });
        }
        if (std.mem.eql(u8, path, "/token")) {
            self.lock.lockUncancelable(self.io);
            self.tokens_issued += 1;
            const n = self.tokens_issued;
            self.lock.unlock(self.io);
            // No `refresh_token`: the authorization server decides not to issue one.
            const doc = try std.fmt.allocPrint(arena, "{{\"access_token\":\"tok-{d}\",\"token_type\":\"Bearer\",\"expires_in\":3600}}", .{n});
            return request.respond(doc, .{ .keep_alive = false, .extra_headers = json_type });
        }
        if (std.mem.eql(u8, path, "/mcp")) {
            self.lock.lockUncancelable(self.io);
            const n = self.tokens_issued;
            self.lock.unlock(self.io);
            const expected = try std.fmt.allocPrint(arena, "Bearer tok-{d}", .{n});
            if (n == 0 or authorization == null or !std.mem.eql(u8, authorization.?, expected)) {
                const www = try std.fmt.allocPrint(arena, "Bearer resource_metadata=\"{s}/.well-known/oauth-protected-resource/mcp\"{s}", .{ self.base, self.challenge_extra });
                return request.respond("{\"error\":\"invalid_token\"}", .{ .status = .unauthorized, .keep_alive = false, .extra_headers = &.{ .{ .name = "www-authenticate", .value = www }, .{ .name = "content-type", .value = "application/json" } } });
            }
            const tree = try json.parseTree(arena, body);
            const id = tree.object.get("id").?.integer;
            const rpc_method = json.getString(tree, "method") orelse "";
            const result = if (std.mem.eql(u8, rpc_method, "tools/list"))
                "{\"tools\":[{\"name\":\"t\",\"inputSchema\":{\"type\":\"object\"}}],\"resultType\":\"complete\"}"
            else
                "{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],\"resultType\":\"complete\"}";
            const doc = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{s}}}", .{ id, result });
            return request.respond(doc, .{ .keep_alive = false, .extra_headers = json_type });
        }
        return request.respond("Not Found", .{ .status = .not_found, .keep_alive = false });
    }

    fn serverUrl(self: *Mock, arena: Allocator) ![]u8 {
        return std.mem.concat(arena, u8, &.{ self.base, "/mcp" });
    }

    /// The `WWW-Authenticate` value of a first 401 answer, with extra parameters.
    fn challenge(self: *Mock, arena: Allocator, extra: []const u8) ![]u8 {
        return std.fmt.allocPrint(arena, "Bearer resource_metadata=\"{s}/.well-known/oauth-protected-resource/mcp\"{s}", .{ self.base, extra });
    }
};

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

fn formEncode(w: *Io.Writer, value: []const u8) !void {
    for (value) |c| {
        if (isUnreserved(c)) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
}

/// The decoded value of `key` in a form encoded text, or null.
fn formValue(arena: Allocator, text: []const u8, key: []const u8) !?[]const u8 {
    var it = std.mem.splitScalar(u8, text, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        if (!std.mem.eql(u8, pair[0..eq], key)) continue;
        const buf = try arena.dupe(u8, if (eq < pair.len) pair[eq + 1 ..] else "");
        for (buf) |*c| if (c.* == '+') {
            c.* = ' ';
        };
        return std.Uri.percentDecodeInPlace(buf);
    }
    return null;
}

// -- Client side --------------------------------------------------------------------------------

test "oauth client sends the token in the authorization header of every request and never in the query" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io };
    try mock.start();
    defer mock.stop();

    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true });
    defer oauth.deinit();
    const transport = try mcp.transport.HttpClient.init(io, gpa, .{ .url = try mock.serverUrl(arena), .auth = &oauth });
    defer transport.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(transport.transport());

    _ = try client.listTools(arena, null, .{});
    _ = try client.callTool(arena, "t", null, .{});
    _ = try client.callTool(arena, "t", null, .{});

    // One authorization, then every MCP request carries the token in the header.
    try std.testing.expectEqual(@as(usize, 1), (try mock.requests(arena, "/token")).len);
    const posts = try mock.requests(arena, "/mcp");
    try std.testing.expectEqual(@as(usize, 4), posts.len);
    try std.testing.expect(posts[0].authorization == null);
    for (posts[1..]) |p| try std.testing.expectEqualStrings("Bearer tok-1", p.authorization.?);
    // No request of the client carries the token in its target.
    for (try mock.allRequests(arena)) |e| {
        try std.testing.expect(std.mem.indexOf(u8, e.target, "tok-") == null);
        if (std.mem.eql(u8, e.path(), "/mcp")) try std.testing.expectEqualStrings("/mcp", e.target);
    }
}

test "oauth client sends the canonical server uri as resource in the authorization and token requests" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The authorization server metadata does not say that it supports resource indicators.
    var mock: Mock = .{ .gpa = gpa, .io = io };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true });
    defer oauth.deinit();

    const server_url = try mock.serverUrl(arena);
    const token = try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1);
    try std.testing.expectEqualStrings("tok-1", token);

    const authz = try mock.requests(arena, "/authorize");
    try std.testing.expectEqual(@as(usize, 1), authz.len);
    try std.testing.expectEqualStrings(server_url, (try formValue(arena, authz[0].query(), "resource")).?);
    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(@as(usize, 1), tok.len);
    try std.testing.expectEqualStrings(server_url, (try formValue(arena, tok[0].body, "resource")).?);
}

test "oauth client requests exactly the challenged scopes whatever their relation to scopes_supported" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The challenge is neither a subset nor a superset of `scopes_supported`.
    var mock: Mock = .{ .gpa = gpa, .io = io, .prm_extra = ",\"scopes_supported\":[\"files:read\",\"files:list\"]" };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .want_refresh_token = false });
    defer oauth.deinit();

    _ = try oauth.handleChallenge(arena, try mock.serverUrl(arena), 401, try mock.challenge(arena, ", scope=\"files:read admin:all\""), 1);
    const authz = try mock.requests(arena, "/authorize");
    try std.testing.expectEqual(@as(usize, 1), authz.len);
    try std.testing.expectEqualStrings("files:read admin:all", (try formValue(arena, authz[0].query(), "scope")).?);
}

test "oauth client registers the refresh_token grant and does not require a refresh token" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .as_extra = ",\"scopes_supported\":[\"mcp:basic\",\"offline_access\"]" };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .registration = .dynamic, .want_refresh_token = true });
    defer oauth.deinit();

    const token = try oauth.handleChallenge(arena, try mock.serverUrl(arena), 401, try mock.challenge(arena, ", scope=\"mcp:basic\""), 1);
    // The token response has no refresh token and the flow still succeeds.
    try std.testing.expectEqualStrings("tok-1", token);
    try std.testing.expectEqualStrings("tok-1", oauth.currentToken().?);

    const reg = try mock.requests(arena, "/register");
    try std.testing.expectEqual(@as(usize, 1), reg.len);
    const doc = try json.parseTree(arena, reg[0].body);
    var has_refresh = false;
    for (doc.object.get("grant_types").?.array.items) |g| {
        if (std.mem.eql(u8, g.string, "refresh_token")) has_refresh = true;
    }
    try std.testing.expect(has_refresh);
    // The authorization server lists `offline_access`, so the client asks for it.
    const authz = try mock.requests(arena, "/authorize");
    try std.testing.expectEqualStrings("mcp:basic offline_access", (try formValue(arena, authz[0].query(), "scope")).?);
}

test "oauth client rejects a wrong or normalized iss before it contacts the token endpoint" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io };
    try mock.start();
    defer mock.stop();
    const port = mock.listener.socket.address.getPort();
    // A foreign issuer, then values that match only after normalization.
    const variants = [_][]const u8{
        "https://evil.example",
        try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/", .{port}),
        try std.fmt.allocPrint(arena, "HTTP://127.0.0.1:{d}", .{port}),
        // "%31" is "1": the value matches only after percent-encoding normalization.
        try std.fmt.allocPrint(arena, "http://%3127.0.0.1:{d}", .{port}),
    };
    for (variants) |iss| {
        mock.iss = iss;
        var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true });
        defer oauth.deinit();
        try std.testing.expectError(error.IssMismatch, oauth.handleChallenge(arena, try mock.serverUrl(arena), 401, try mock.challenge(arena, ""), 1));
        try std.testing.expect(oauth.currentToken() == null);
    }
    try std.testing.expectEqual(@as(usize, variants.len), (try mock.requests(arena, "/authorize")).len);
    try std.testing.expectEqual(@as(usize, 0), (try mock.requests(arena, "/token")).len);
}

test "oauth client does not act on an error response whose iss does not match" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .deny = true, .iss = "https://evil.example" };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true });
    defer oauth.deinit();

    // The client gives only a generic failure. It does not surface the error fields.
    try std.testing.expectError(error.AuthorizationFailed, oauth.handleChallenge(arena, try mock.serverUrl(arena), 401, try mock.challenge(arena, ""), 1));
    try std.testing.expect(oauth.currentToken() == null);
    try std.testing.expectEqual(@as(usize, 0), (try mock.requests(arena, "/token")).len);
}

test "oauth client refuses authorization server endpoints without https" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = false });
    defer oauth.deinit();

    try std.testing.expectError(error.InsecureEndpoint, oauth.handleChallenge(arena, try mock.serverUrl(arena), 401, try mock.challenge(arena, ""), 1));
    try std.testing.expectEqual(@as(usize, 0), (try mock.requests(arena, "/register")).len);
    try std.testing.expectEqual(@as(usize, 0), (try mock.requests(arena, "/authorize")).len);
    try std.testing.expectEqual(@as(usize, 0), (try mock.requests(arena, "/token")).len);
}

// -- Server side --------------------------------------------------------------------------------

/// Accepts the token "read-only" with the scope `files:read`.
fn stubVerify(ptr: *anyopaque, arena: Allocator, token: []const u8) resource_server.VerifyError!resource_server.Principal {
    _ = ptr;
    _ = arena;
    if (std.mem.eql(u8, token, "read-only")) return .{ .subject = "alice", .scopes = &.{"files:read"} };
    return error.InvalidToken;
}

test "resource server challenges insufficient scope with 403 and all required scopes at once" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dummy: u8 = 0;
    const rs: resource_server.ResourceServer = .{
        .resource = "https://mcp.example.com/mcp",
        .resource_metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        .authorization_servers = &.{"https://as.example.com"},
        .required_scopes = &.{ "files:read", "files:write" },
        .verifier = .{ .ptr = &dummy, .verify = stubVerify },
    };

    // Two scopes are missing or present in part: one challenge names both.
    const low = try rs.authorize(arena, "Bearer read-only");
    try std.testing.expectEqual(@as(u16, 403), low.challenge.status);
    try std.testing.expectEqualStrings(
        "Bearer error=\"insufficient_scope\", error_description=\"The token lacks a required scope\", resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\", scope=\"files:read files:write\"",
        low.challenge.www_authenticate,
    );
    const body = try json.parseTree(arena, low.challenge.body);
    try std.testing.expectEqualStrings("insufficient_scope", json.getString(body, "error").?);

    // The 401 challenges name the same scope set.
    const none = try rs.authorize(arena, null);
    try std.testing.expectEqual(@as(u16, 401), none.challenge.status);
    try std.testing.expectEqualStrings("Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\", scope=\"files:read files:write\"", none.challenge.www_authenticate);
    const bad = try rs.authorize(arena, "Bearer forged");
    try std.testing.expectEqual(@as(u16, 401), bad.challenge.status);
    try std.testing.expect(std.mem.indexOf(u8, bad.challenge.www_authenticate, "error=\"invalid_token\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, bad.challenge.www_authenticate, "scope=\"files:read files:write\""));
}

const secret = "g3a-auth-test-secret-with-32-bytes!!";

fn fixedNow() i64 {
    return 1000;
}

fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const p = ctx.principal() orelse return error.NoPrincipal;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{p.subject orelse "?"}) };
}

const ServerFixture = struct {
    server: mcp.Server,
    keys: [1]jwt.Key,
    jv: mcp.auth.JwtVerifier,
    rs: mcp.auth.ResourceServer,
    transport: mcp.transport.http.Server,
    future: Io.Future(void),
    client: http.Client,
    base: []u8,

    fn start(self: *ServerFixture) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "g3a-auth", .version = "1" } });
        try self.server.addToolJson(.{ .name = "whoami" }, whoami);
        self.keys = .{.{ .alg = .HS256, .material = .{ .secret = secret } }};
        self.jv = .{ .options = .{ .keys = &self.keys, .audience = "http://127.0.0.1/mcp" }, .clock = .{ .fixed = fixedNow } };
        self.rs = .{
            .resource = "http://127.0.0.1/mcp",
            .resource_metadata_url = "http://127.0.0.1/.well-known/oauth-protected-resource/mcp",
            .authorization_servers = &.{"http://127.0.0.1:9/as"},
            .verifier = self.jv.verifier(),
        };
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .auth = &self.rs });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        self.client = .{ .allocator = gpa, .io = io };
        self.base = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}", .{self.transport.bound_port});
    }

    fn serveIgnoringErrors(t: *mcp.transport.http.Server) void {
        t.serve() catch {};
    }

    fn stop(self: *ServerFixture) void {
        const io = std.testing.io;
        self.client.deinit();
        self.transport.shutdown();
        self.future.await(io);
        self.transport.deinit();
        self.server.deinit();
        std.testing.allocator.free(self.base);
    }

    fn post(self: *ServerFixture, arena: Allocator, target: []const u8, body: []const u8, extra: []const http.Header) !http.Status {
        const url = try std.mem.concat(arena, u8, &.{ self.base, target });
        var req = try self.client.request(.POST, try std.Uri.parse(url), .{
            .redirect_behavior = .unhandled,
            .extra_headers = extra,
            .keep_alive = false,
            .headers = .{ .content_type = .{ .override = "application/json" }, .accept_encoding = .{ .override = "identity" } },
        });
        defer req.deinit();
        try req.sendBodyComplete(try arena.dupe(u8, body));
        var redirect_buf: [256]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);
        const status = response.head.status;
        var transfer: [4096]u8 = undefined;
        _ = try response.reader(&transfer).allocRemaining(arena, .limited(1 << 20));
        return status;
    }
};

const call_whoami = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"whoami\"}}";
const std_headers = [_]http.Header{
    .{ .name = "accept", .value = "application/json, text/event-stream" },
    .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
    .{ .name = "mcp-method", .value = "tools/call" },
    .{ .name = "mcp-name", .value = "whoami" },
};

test "http server does not accept an access token in the query string" {
    var f: ServerFixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const good = try jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000}", secret, null);

    const in_query = try f.post(arena, try std.mem.concat(arena, u8, &.{ "/mcp?access_token=", good }), call_whoami, &std_headers);
    try std.testing.expectEqual(http.Status.unauthorized, in_query);
    const in_header = try f.post(arena, "/mcp", call_whoami, &(std_headers ++ [_]http.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", good }) }}));
    try std.testing.expectEqual(http.Status.ok, in_header);
}
