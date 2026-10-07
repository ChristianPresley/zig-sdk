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
    /// The `DPoP` header of the request.
    dpop: ?[]u8 = null,

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
    /// Issue a refresh token with each grant.
    refresh: bool = false,
    /// Give a new refresh token with each refresh, and make the old one invalid.
    rotate: bool = true,
    /// Refuse each refresh with `invalid_grant`.
    refuse_refresh: bool = false,
    /// Refuse each token request with `invalid_client`.
    refuse_client: bool = false,
    /// The `expires_in` of each token.
    expires_in: i64 = 3600,
    /// The valid refresh token is `ref-{refresh_serial}`. Zero: none is valid.
    refresh_serial: u32 = 0,
    /// The authorization server of the protected resource metadata. Null names this mock.
    authorization_server: ?[]const u8 = null,
    /// Runs in the task of the mock before it answers a token request. A test uses it to act as
    /// another client while a request of the client under test is on its way.
    on_token: ?Hook = null,

    const Hook = struct {
        ctx: *anyopaque,
        run: *const fn (ctx: *anyopaque, mock: *Mock) void,
    };

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
            if (e.dpop) |d| self.gpa.free(d);
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

    fn record(self: *Mock, method: http.Method, target: []const u8, authorization: ?[]const u8, proof: ?[]const u8, body: []const u8) !void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        try self.entries.append(self.gpa, .{
            .method = method,
            .target = try self.gpa.dupe(u8, target),
            .authorization = if (authorization) |a| try self.gpa.dupe(u8, a) else null,
            .dpop = if (proof) |d| try self.gpa.dupe(u8, d) else null,
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
        var proof: ?[]const u8 = null;
        var it = request.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "authorization")) authorization = try arena.dupe(u8, h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "dpop")) proof = try arena.dupe(u8, h.value);
        }
        var body_buf: [4096]u8 = undefined;
        const body = try request.readerExpectNone(&body_buf).allocRemaining(arena, .limited(1 << 20));
        try self.record(method, target, authorization, proof, body);

        const path = (Entry{ .method = method, .target = target, .authorization = null, .body = &.{} }).path();
        const json_type: []const http.Header = &.{.{ .name = "content-type", .value = "application/json" }};
        if (std.mem.eql(u8, path, "/.well-known/oauth-protected-resource/mcp")) {
            const doc = try std.fmt.allocPrint(arena, "{{\"resource\":\"{s}/mcp\",\"authorization_servers\":[\"{s}\"]{s}}}", .{ self.base, self.authorization_server orelse self.base, self.prm_extra });
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
            if (self.on_token) |hook| hook.run(hook.ctx, self);
            const grant = (try formValue(arena, body, "grant_type")) orelse "";
            const refreshing = std.mem.eql(u8, grant, "refresh_token");
            if (self.refuse_client) return request.respond("{\"error\":\"invalid_client\"}", .{ .status = .unauthorized, .keep_alive = false, .extra_headers = json_type });
            self.lock.lockUncancelable(self.io);
            if (refreshing) {
                const want = try std.fmt.allocPrint(arena, "ref-{d}", .{self.refresh_serial});
                const got = (try formValue(arena, body, "refresh_token")) orelse "";
                if (self.refuse_refresh or self.refresh_serial == 0 or !std.mem.eql(u8, got, want)) {
                    self.lock.unlock(self.io);
                    return request.respond("{\"error\":\"invalid_grant\"}", .{ .status = .bad_request, .keep_alive = false, .extra_headers = json_type });
                }
            }
            const new_refresh = self.refresh and (!refreshing or self.rotate);
            if (new_refresh) self.refresh_serial += 1;
            self.tokens_issued += 1;
            const n = self.tokens_issued;
            const r = self.refresh_serial;
            self.lock.unlock(self.io);
            // Without `refresh`, the token has no `refresh_token`: the authorization server
            // decides not to issue one.
            const refresh_field = if (new_refresh) try std.fmt.allocPrint(arena, ",\"refresh_token\":\"ref-{d}\"", .{r}) else "";
            const doc = try std.fmt.allocPrint(arena, "{{\"access_token\":\"tok-{d}\",\"token_type\":\"{s}\",\"expires_in\":{d}{s}}}", .{ n, if (proof != null) "DPoP" else "Bearer", self.expires_in, refresh_field });
            return request.respond(doc, .{ .keep_alive = false, .extra_headers = json_type });
        }
        if (std.mem.eql(u8, path, "/mcp")) {
            self.lock.lockUncancelable(self.io);
            const n = self.tokens_issued;
            self.lock.unlock(self.io);
            const expected = try std.fmt.allocPrint(arena, " tok-{d}", .{n});
            const scheme_ok = authorization != null and (std.mem.startsWith(u8, authorization.?, "Bearer ") or std.mem.startsWith(u8, authorization.?, "DPoP "));
            if (n == 0 or !scheme_ok or !std.mem.endsWith(u8, authorization.?, expected)) {
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

// -- Refresh tokens -----------------------------------------------------------------------------

/// The clock of the refresh tests, in Unix seconds. A test moves it forward.
var test_time: i64 = 1_000_000;

fn testNow() i64 {
    return test_time;
}

fn grantOf(arena: Allocator, entry: Entry) ![]const u8 {
    return (try formValue(arena, entry.body, "grant_type")) orelse "";
}

test "oauth client refreshes the access token before it expires and keeps the rotated refresh token" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    test_time = 1_000_000;
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .clock = testNow });
    defer oauth.deinit();
    const server_url = try mock.serverUrl(arena);
    const transport = try mcp.transport.HttpClient.init(io, gpa, .{ .url = server_url, .auth = &oauth });
    defer transport.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(transport.transport());

    _ = try client.callTool(arena, "t", null, .{});
    try std.testing.expectEqualStrings("ref-1", oauth.refresh_token.?);
    try std.testing.expectEqual(test_time + 3600, oauth.expires_at.?);
    // 30 seconds before the expiry is within the margin of 60 seconds. The next request gets a
    // new token first.
    test_time += 3600 - 30;
    _ = try client.callTool(arena, "t", null, .{});
    test_time += 3600 - 30;
    _ = try client.callTool(arena, "t", null, .{});

    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(3, tok.len);
    try std.testing.expectEqual(1, (try mock.requests(arena, "/authorize")).len);
    try std.testing.expectEqualStrings("authorization_code", try grantOf(arena, tok[0]));
    for (tok[1..], [_][]const u8{ "ref-1", "ref-2" }) |t, want| {
        try std.testing.expectEqualStrings("refresh_token", try grantOf(arena, t));
        try std.testing.expectEqualStrings(want, (try formValue(arena, t.body, "refresh_token")).?);
        try std.testing.expectEqualStrings(server_url, (try formValue(arena, t.body, "resource")).?);
        try std.testing.expectEqualStrings("dyn-client", (try formValue(arena, t.body, "client_id")).?);
    }
    // Each rotation replaced the refresh token, and each request used the newest access token.
    try std.testing.expectEqualStrings("ref-3", oauth.refresh_token.?);
    const posts = try mock.requests(arena, "/mcp");
    try std.testing.expectEqual(4, posts.len);
    try std.testing.expectEqualStrings("Bearer tok-3", posts[3].authorization.?);
}

test "oauth client runs the authorization code flow when the server refuses the refresh token" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true });
    defer oauth.deinit();
    const server_url = try mock.serverUrl(arena);

    try std.testing.expectEqualStrings("tok-1", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    // The server revokes the grant. The next challenge tries the refresh token, then the code flow.
    mock.refuse_refresh = true;
    try std.testing.expectEqualStrings("tok-2", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ", error=\"invalid_token\""), 1));

    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(3, tok.len);
    try std.testing.expectEqualStrings("refresh_token", try grantOf(arena, tok[1]));
    try std.testing.expectEqualStrings("authorization_code", try grantOf(arena, tok[2]));
    try std.testing.expectEqual(2, (try mock.requests(arena, "/authorize")).len);
    // The registration stays, and the new grant has its own refresh token.
    try std.testing.expectEqual(1, (try mock.requests(arena, "/register")).len);
    try std.testing.expectEqualStrings("ref-2", oauth.refresh_token.?);
    const failure = (try oauth.lastFailure(arena)).?;
    try std.testing.expectEqual(OAuthClient.Failure.Step.refresh, failure.step);
    try std.testing.expectEqualStrings("invalid_grant", failure.code.?);
}

test "oauth client does not use the refresh token for a step-up" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true });
    defer oauth.deinit();
    const server_url = try mock.serverUrl(arena);

    _ = try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ", scope=\"files:read\""), 1);
    _ = try oauth.handleChallenge(arena, server_url, 403, try mock.challenge(arena, ", error=\"insufficient_scope\", scope=\"files:write\""), 1);
    for (try mock.requests(arena, "/token")) |t| try std.testing.expectEqualStrings("authorization_code", try grantOf(arena, t));
    const authz = try mock.requests(arena, "/authorize");
    try std.testing.expectEqual(2, authz.len);
    try std.testing.expectEqualStrings("files:read files:write", (try formValue(arena, authz[1].query(), "scope")).?);
}

test "oauth client never asks for a wider scope with a refresh token" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true });
    defer oauth.deinit();
    const server_url = try mock.serverUrl(arena);

    _ = try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ", scope=\"files:read\""), 1);
    // A 401 that names more scopes is not a step-up. The refresh asks for the granted scope only.
    _ = try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ", error=\"invalid_token\", scope=\"files:read files:write\""), 1);
    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(2, tok.len);
    try std.testing.expectEqualStrings("refresh_token", try grantOf(arena, tok[1]));
    try std.testing.expectEqualStrings("files:read", (try formValue(arena, tok[1].body, "scope")).?);
    try std.testing.expectEqual(1, (try mock.requests(arena, "/authorize")).len);
    try std.testing.expectEqual(1, oauth.granted_scopes.items.len);
}

test "oauth client sends a DPoP proof with the refresh token" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var prover: mcp.auth.DpopProver = try .generate(io, gpa);
    defer prover.deinit();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .dpop = &prover });
    defer oauth.deinit();
    const server_url = try mock.serverUrl(arena);

    _ = try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1);
    try std.testing.expect(oauth.token_dpop);
    try std.testing.expectEqualStrings("tok-2", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ", error=\"invalid_token\""), 1));
    try std.testing.expect(oauth.token_dpop);

    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(2, tok.len);
    try std.testing.expectEqualStrings("refresh_token", try grantOf(arena, tok[1]));
    const token_url = try std.mem.concat(arena, u8, &.{ mock.base, "/token" });
    const time = Io.Clock.Timestamp.now(io, .real).raw.toSeconds();
    for (tok) |t| {
        const proof = try mcp.auth.dpop.verifyProof(arena, t.dpop.?, .{ .method = "POST", .uri = token_url }, .{}, time);
        try std.testing.expectEqualStrings(prover.jkt, proof.jkt);
    }
}

// -- Token storage ------------------------------------------------------------------------------

/// The storage key of the dynamic registration of a client with the default options.
fn dynamicKey(arena: Allocator, issuer: []const u8, resource: []const u8) !mcp.auth.token_storage.Key {
    const options: OAuthClient.Options = .{};
    return .{ .issuer = issuer, .resource = resource, .client = try std.fmt.allocPrint(arena, "dynamic {s} {s}", .{ options.client_name, options.redirect_uri }) };
}

test "oauth client keeps its record in a file storage, and a second client needs no new authorization" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/tokens", .{tmp.sub_path});
    const file_key = [_]u8{0x5a} ** 32;
    const server_url = try mock.serverUrl(arena);
    test_time = 1_000_000;

    {
        var files: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
        defer files.deinit();
        var first: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files.storage(), .clock = testNow });
        defer first.deinit();
        try std.testing.expectEqualStrings("tok-1", try first.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    }

    // A new storage and a new client, as in a new process. The client loads the record at the
    // first challenge and sends the stored token without registration, authorization or token
    // request.
    {
        var files: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
        defer files.deinit();
        var second: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files.storage(), .clock = testNow });
        defer second.deinit();
        const transport = try mcp.transport.HttpClient.init(io, gpa, .{ .url = server_url, .auth = &second });
        defer transport.deinit();
        var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
        defer client.deinit();
        client.connect(transport.transport());
        _ = try client.callTool(arena, "t", null, .{});
    }
    try std.testing.expectEqual(1, (try mock.requests(arena, "/register")).len);
    try std.testing.expectEqual(1, (try mock.requests(arena, "/authorize")).len);
    try std.testing.expectEqual(1, (try mock.requests(arena, "/token")).len);
    const posts = try mock.requests(arena, "/mcp");
    try std.testing.expectEqualStrings("Bearer tok-1", posts[posts.len - 1].authorization.?);

    // After the expiry, a third client refreshes the stored token. The user sees no browser.
    test_time += 7200;
    var files: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer files.deinit();
    {
        var third: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files.storage(), .clock = testNow });
        defer third.deinit();
        try std.testing.expectEqualStrings("tok-2", try third.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    }
    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(2, tok.len);
    try std.testing.expectEqualStrings("refresh_token", try grantOf(arena, tok[1]));
    try std.testing.expectEqual(1, (try mock.requests(arena, "/authorize")).len);
    // The record has the rotated refresh token and the registration.
    var record = (try files.storage().load(gpa, try dynamicKey(arena, mock.base, server_url))).?;
    defer record.deinit(gpa);
    try std.testing.expectEqualStrings("tok-2", record.access_token.?);
    try std.testing.expectEqualStrings("ref-2", record.refresh_token.?);
    try std.testing.expectEqualStrings("dyn-client", record.registration.?.client_id);
    try std.testing.expectEqual(test_time + 3600, record.expires_at.?);
}

test "oauth client deletes the stored record when the issuer changes or the server refuses the client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var other: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try other.start();
    defer other.stop();
    var memory: mcp.auth.MemoryTokenStorage = .init(io, gpa);
    defer memory.deinit();
    const storage = memory.storage();
    const server_url = try mock.serverUrl(arena);
    const first_key = try dynamicKey(arena, mock.base, server_url);
    const second_key = try dynamicKey(arena, other.base, server_url);

    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = storage });
    defer oauth.deinit();
    _ = try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1);
    try std.testing.expect(try hasRecord(storage, first_key));

    // The protected resource names another authorization server. The record of the old one goes.
    mock.authorization_server = other.base;
    _ = try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1);
    try std.testing.expect(!try hasRecord(storage, first_key));
    try std.testing.expect(try hasRecord(storage, second_key));
    try std.testing.expectEqual(1, (try other.requests(arena, "/register")).len);

    // The new authorization server refuses the client for the refresh and the code exchange.
    other.refuse_client = true;
    try std.testing.expectError(error.TokenRequestFailed, oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    try std.testing.expect(!try hasRecord(storage, second_key));
    try std.testing.expectEqual(0, memory.count());
    // The client registered again after the refusal of the refresh.
    try std.testing.expectEqual(2, (try other.requests(arena, "/register")).len);
}

fn hasRecord(storage: mcp.auth.TokenStorage, key: mcp.auth.token_storage.Key) !bool {
    var record = (try storage.load(std.testing.allocator, key)) orelse return false;
    record.deinit(std.testing.allocator);
    return true;
}

test "oauth client skips stored tokens of another DPoP key and keeps the registration" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var memory: mcp.auth.MemoryTokenStorage = .init(io, gpa);
    defer memory.deinit();
    const server_url = try mock.serverUrl(arena);

    var old_key: mcp.auth.DpopProver = try .generate(io, gpa);
    defer old_key.deinit();
    {
        var first: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = memory.storage(), .dpop = &old_key });
        defer first.deinit();
        _ = try first.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1);
        try std.testing.expect(first.token_dpop);
    }
    var record = (try memory.storage().load(gpa, try dynamicKey(arena, mock.base, server_url))).?;
    try std.testing.expect(record.dpop_bound);
    try std.testing.expectEqualStrings(old_key.jkt, record.dpop_jkt.?);
    record.deinit(gpa);

    // A new key cannot use the bound tokens. The client authorizes again with the stored client.
    var new_key: mcp.auth.DpopProver = try .generate(io, gpa);
    defer new_key.deinit();
    var second: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = memory.storage(), .dpop = &new_key });
    defer second.deinit();
    try std.testing.expectEqualStrings("tok-2", try second.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    try std.testing.expectEqual(1, (try mock.requests(arena, "/register")).len);
    try std.testing.expectEqual(2, (try mock.requests(arena, "/authorize")).len);
    for (try mock.requests(arena, "/token")) |t| try std.testing.expectEqualStrings("authorization_code", try grantOf(arena, t));
}

test "oauth clients that share a file storage use the tokens that the other client refreshed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/tokens", .{tmp.sub_path});
    const file_key = [_]u8{0x5b} ** 32;
    const server_url = try mock.serverUrl(arena);
    test_time = 1_000_000;

    // Two processes with one token directory, for example two windows of an application.
    var files_a: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer files_a.deinit();
    var files_b: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer files_b.deinit();
    var a: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files_a.storage(), .clock = testNow });
    defer a.deinit();
    var b: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files_b.storage(), .clock = testNow });
    defer b.deinit();
    try std.testing.expectEqualStrings("tok-1", try a.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    try std.testing.expectEqualStrings("tok-1", try b.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));

    // Both tokens expire. A refreshes first, and the server rotates the refresh token. At its
    // next challenge, B reads the record of A and sends no token request.
    test_time += 7200;
    const expired = try mock.challenge(arena, ", error=\"invalid_token\"");
    try std.testing.expectEqualStrings("tok-2", try a.handleChallenge(arena, server_url, 401, expired, 1));
    try std.testing.expectEqualStrings("tok-2", try b.handleChallenge(arena, server_url, 401, expired, 1));
    try std.testing.expectEqual(2, (try mock.requests(arena, "/token")).len);

    // Before a request, A refreshes again. Later B needs a token, and the token of A in the
    // record expired too. Thus B refreshes with the refresh token of A. Then A takes the token
    // of B.
    test_time += 7200;
    try std.testing.expectEqualStrings("tok-3", a.provider().token(arena).?);
    test_time += 7200;
    try std.testing.expectEqualStrings("tok-4", b.provider().token(arena).?);
    try std.testing.expectEqualStrings("tok-4", a.provider().token(arena).?);

    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(4, tok.len);
    for (tok[1..], [_][]const u8{ "ref-1", "ref-2", "ref-3" }) |t, want| {
        try std.testing.expectEqualStrings("refresh_token", try grantOf(arena, t));
        try std.testing.expectEqualStrings(want, (try formValue(arena, t.body, "refresh_token")).?);
    }
    // The server refused no refresh token, and the user saw the browser one time.
    try std.testing.expectEqual(1, (try mock.requests(arena, "/authorize")).len);
    try std.testing.expect((try a.lastFailure(arena)) == null);
    try std.testing.expect((try b.lastFailure(arena)) == null);
    var record = (try files_a.storage().load(gpa, try dynamicKey(arena, mock.base, server_url))).?;
    defer record.deinit(gpa);
    try std.testing.expectEqualStrings("tok-4", record.access_token.?);
    try std.testing.expectEqualStrings("ref-4", record.refresh_token.?);
}

/// Acts as another process with the same storage. Before the mock answers the next token
/// request, it rotates the refresh token at the mock and writes new tokens to the storage.
const Rotation = struct {
    storage: mcp.auth.TokenStorage,
    key: mcp.auth.token_storage.Key,
    access_token: []const u8,
    expires_at: i64,
    /// The DPoP key of the tokens of the other process. Null for bearer tokens.
    dpop_jkt: ?[]const u8 = null,
    armed: std.atomic.Value(bool) = .init(true),
    saved: std.atomic.Value(bool) = .init(false),
    refresh_buf: [16]u8 = undefined,

    fn hook(self: *Rotation) Mock.Hook {
        return .{ .ctx = self, .run = run };
    }

    fn run(ctx: *anyopaque, mock: *Mock) void {
        const self: *Rotation = @ptrCast(@alignCast(ctx));
        if (!self.armed.swap(false, .acq_rel)) return;
        mock.lock.lockUncancelable(mock.io);
        mock.refresh_serial += 1;
        const serial = mock.refresh_serial;
        mock.lock.unlock(mock.io);
        const refresh_token = std.fmt.bufPrint(&self.refresh_buf, "ref-{d}", .{serial}) catch unreachable;
        self.storage.save(std.testing.allocator, self.key, .{
            .registration = .{ .client_id = "dyn-client" },
            .access_token = self.access_token,
            .expires_at = self.expires_at,
            .refresh_token = refresh_token,
            .dpop_bound = self.dpop_jkt != null,
            .dpop_jkt = self.dpop_jkt,
        }) catch return;
        self.saved.store(true, .release);
    }
};

test "oauth client takes the tokens of another process that rotated the refresh token during the refresh" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/tokens", .{tmp.sub_path});
    const file_key = [_]u8{0x5c} ** 32;
    const server_url = try mock.serverUrl(arena);
    const key = try dynamicKey(arena, mock.base, server_url);
    test_time = 1_000_000;
    var files: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer files.deinit();
    var other: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer other.deinit();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files.storage(), .clock = testNow });
    defer oauth.deinit();
    try std.testing.expectEqualStrings("tok-1", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    const expired = try mock.challenge(arena, ", error=\"invalid_token\"");

    // The other process refreshes while the request of the client is on its way. The server
    // refuses the old refresh token of the client. The client takes the new token from the
    // record, and the record stays as the other process wrote it.
    test_time += 7200;
    var rotation: Rotation = .{ .storage = other.storage(), .key = key, .access_token = "tok-other", .expires_at = test_time + 3600 };
    mock.on_token = rotation.hook();
    try std.testing.expectEqualStrings("tok-other", try oauth.handleChallenge(arena, server_url, 401, expired, 1));
    try std.testing.expect(rotation.saved.load(.acquire));
    try std.testing.expectEqualStrings("ref-2", oauth.refresh_token.?);
    {
        var record = (try files.storage().load(gpa, key)).?;
        defer record.deinit(gpa);
        try std.testing.expectEqualStrings("tok-other", record.access_token.?);
        try std.testing.expectEqualStrings("ref-2", record.refresh_token.?);
    }

    // Again, but the new token of the other process expires within the refresh margin. The
    // client sends one more refresh with the new refresh token.
    test_time += 7200;
    rotation.access_token = "tok-other-2";
    rotation.expires_at = test_time + 30;
    rotation.armed.store(true, .release);
    try std.testing.expectEqualStrings("tok-2", try oauth.handleChallenge(arena, server_url, 401, expired, 1));

    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(4, tok.len);
    for (tok[1..], [_][]const u8{ "ref-1", "ref-2", "ref-3" }) |t, want| {
        try std.testing.expectEqualStrings(want, (try formValue(arena, t.body, "refresh_token")).?);
    }
    try std.testing.expectEqual(1, (try mock.requests(arena, "/authorize")).len);
    var record = (try files.storage().load(gpa, key)).?;
    defer record.deinit(gpa);
    try std.testing.expectEqualStrings("tok-2", record.access_token.?);
    try std.testing.expectEqualStrings("ref-4", record.refresh_token.?);
}

test "oauth client removes refused tokens from the storage only when no other client changed the record" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/tokens", .{tmp.sub_path});
    const file_key = [_]u8{0x5d} ** 32;
    const server_url = try mock.serverUrl(arena);
    const key = try dynamicKey(arena, mock.base, server_url);
    test_time = 1_000_000;
    var files: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer files.deinit();
    var other: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer other.deinit();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files.storage(), .clock = testNow });
    defer oauth.deinit();
    try std.testing.expectEqualStrings("tok-1", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));

    // The server revokes the grant before a request. The record keeps the registration
    // without the refused tokens.
    test_time += 7200;
    mock.refuse_refresh = true;
    try std.testing.expect(oauth.provider().token(arena) == null);
    {
        var record = (try files.storage().load(gpa, key)).?;
        defer record.deinit(gpa);
        try std.testing.expectEqualStrings("dyn-client", record.registration.?.client_id);
        try std.testing.expect(record.access_token == null and record.refresh_token == null);
    }

    // A new grant. Then another process with another DPoP key refreshes during the refresh of
    // the client. The client cannot use the tokens of that record, and does not write over it.
    mock.refuse_refresh = false;
    try std.testing.expectEqualStrings("tok-2", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));
    test_time += 7200;
    var rotation: Rotation = .{ .storage = other.storage(), .key = key, .access_token = "tok-other", .expires_at = test_time + 3600, .dpop_jkt = "jkt-of-another-key" };
    mock.on_token = rotation.hook();
    try std.testing.expect(oauth.provider().token(arena) == null);
    try std.testing.expect(rotation.saved.load(.acquire));
    try std.testing.expect(oauth.currentToken() == null);
    var record = (try files.storage().load(gpa, key)).?;
    defer record.deinit(gpa);
    try std.testing.expectEqualStrings("tok-other", record.access_token.?);
    try std.testing.expectEqualStrings("ref-3", record.refresh_token.?);
    try std.testing.expectEqualStrings("jkt-of-another-key", record.dpop_jkt.?);
}

test "oauth client keeps its registration and refresh token when a record of another client ID has tokens of another DPoP key" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mock: Mock = .{ .gpa = gpa, .io = io, .refresh = true };
    try mock.start();
    defer mock.stop();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/tokens", .{tmp.sub_path});
    const file_key = [_]u8{0x5e} ** 32;
    const server_url = try mock.serverUrl(arena);
    const key = try dynamicKey(arena, mock.base, server_url);
    test_time = 1_000_000;
    var files: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer files.deinit();
    var other: mcp.auth.FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = file_key });
    defer other.deinit();
    var oauth: OAuthClient = .init(io, gpa, .{ .allow_http = true, .storage = files.storage(), .clock = testNow });
    defer oauth.deinit();
    try std.testing.expectEqualStrings("tok-1", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ""), 1));

    // Another process with its own registration and its own DPoP key writes its record. The
    // client cannot use these tokens. Before a request, it refreshes with its own refresh token
    // and its own client ID.
    test_time += 7200;
    try other.storage().save(gpa, key, .{ .registration = .{ .client_id = "other-client" }, .access_token = "tok-other", .expires_at = test_time + 3600, .refresh_token = "ref-other", .dpop_bound = true, .dpop_jkt = "jkt-of-another-key" });
    try std.testing.expectEqualStrings("tok-2", oauth.provider().token(arena) orelse "");
    try std.testing.expectEqualStrings("dyn-client", oauth.registration.?.client_id);

    // The same at a challenge.
    test_time += 7200;
    try other.storage().save(gpa, key, .{ .registration = .{ .client_id = "other-client" }, .access_token = "tok-other-2", .expires_at = test_time + 3600, .refresh_token = "ref-other-2", .dpop_bound = true, .dpop_jkt = "jkt-of-another-key" });
    try std.testing.expectEqualStrings("tok-3", try oauth.handleChallenge(arena, server_url, 401, try mock.challenge(arena, ", error=\"invalid_token\""), 1));
    try std.testing.expectEqualStrings("dyn-client", oauth.registration.?.client_id);

    const tok = try mock.requests(arena, "/token");
    try std.testing.expectEqual(3, tok.len);
    for (tok[1..], [_][]const u8{ "ref-1", "ref-2" }) |t, want| {
        try std.testing.expectEqualStrings("refresh_token", try grantOf(arena, t));
        try std.testing.expectEqualStrings(want, (try formValue(arena, t.body, "refresh_token")).?);
        try std.testing.expectEqualStrings("dyn-client", (try formValue(arena, t.body, "client_id")).?);
    }
    try std.testing.expectEqual(1, (try mock.requests(arena, "/register")).len);
    try std.testing.expectEqual(1, (try mock.requests(arena, "/authorize")).len);
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
