//! The HTTP server as an OAuth 2.1 resource server: metadata, challenges and principals.
const std = @import("std");
const Io = std.Io;
const http = std.http;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const json = mcp.json;
const types = mcp.types;
const HttpServer = mcp.transport.http.Server;
const jwt = mcp.auth.jwt;

const secret = "http-auth-test-secret-with-32-bytes!";
const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;

fn fixedNow() i64 {
    return 1000;
}

/// Answers with the subject of the principal.
fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const p = ctx.principal() orelse return error.NoPrincipal;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{p.subject orelse "?"}) };
}

/// Asks for a name in the first round and greets in the second round.
fn askName(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content orelse .null, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s} from {s}", .{ name, ctx.request_state orelse "-" }) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    try ir.setStateFmt("{{\"asked\":{f}}}", .{std.json.fmt(ctx.principal().?.subject orelse "", .{})});
    return .{ .input_required = ir };
}

const Fixture = struct {
    server: mcp.Server,
    keys: [1]jwt.Key,
    jv: mcp.auth.JwtVerifier,
    rs: mcp.auth.ResourceServer,
    transport: HttpServer,
    future: Io.Future(void),
    client: http.Client,
    base: []u8,

    fn start(self: *Fixture) !void {
        return self.startWith(.{ .info = .{ .name = "auth-test", .version = "1" } });
    }

    fn startWith(self: *Fixture, options: mcp.Server.Options) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, options);
        try self.server.addToolJson(.{ .name = "whoami" }, whoami);
        try self.server.addToolJson(.{ .name = "ask" }, askName);
        self.keys = .{.{ .alg = .HS256, .material = .{ .secret = secret } }};
        self.jv = .{ .options = .{ .keys = &self.keys, .audience = "http://127.0.0.1/mcp" }, .clock = .{ .fixed = fixedNow } };
        self.rs = .{
            .resource = "http://127.0.0.1/mcp",
            .resource_metadata_url = "http://127.0.0.1/.well-known/oauth-protected-resource/mcp",
            .authorization_servers = &.{"http://127.0.0.1:9/as"},
            .required_scopes = &.{"mcp:read"},
            .verifier = self.jv.verifier(),
        };
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .auth = &self.rs });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        self.client = .{ .allocator = gpa, .io = io };
        self.base = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}", .{self.transport.bound_port});
    }

    fn serveIgnoringErrors(t: *HttpServer) void {
        t.serve() catch {};
    }

    fn stop(self: *Fixture) void {
        const io = std.testing.io;
        self.client.deinit();
        self.transport.shutdown();
        self.future.await(io);
        self.transport.deinit();
        self.server.deinit();
        std.testing.allocator.free(self.base);
    }

    const Reply = struct { status: http.Status, body: []u8, www_authenticate: ?[]u8, retry_after: ?[]u8 = null };

    fn send(self: *Fixture, arena: std.mem.Allocator, method: http.Method, path: []const u8, body: ?[]const u8, extra: []const http.Header) !Reply {
        const url = try std.mem.concat(arena, u8, &.{ self.base, path });
        var req = try self.client.request(method, try std.Uri.parse(url), .{
            .redirect_behavior = .unhandled,
            .extra_headers = extra,
            .headers = .{ .content_type = if (body != null) .{ .override = "application/json" } else .default, .accept_encoding = .{ .override = "identity" } },
        });
        defer req.deinit();
        if (body) |b| try req.sendBodyComplete(try arena.dupe(u8, b)) else try req.sendBodiless();
        var redirect_buf: [256]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);
        var www: ?[]u8 = null;
        var retry_after: ?[]u8 = null;
        var it = response.head.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) www = try arena.dupe(u8, h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "retry-after")) retry_after = try arena.dupe(u8, h.value);
        }
        const status = response.head.status;
        var transfer: [4096]u8 = undefined;
        const text = try response.reader(&transfer).allocRemaining(arena, .limited(1 << 20));
        return .{ .status = status, .body = text, .www_authenticate = www, .retry_after = retry_after };
    }
};

const call_whoami = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++ meta_none ++ ",\"name\":\"whoami\"}}";
const std_headers = [_]http.Header{
    .{ .name = "accept", .value = "application/json, text/event-stream" },
    .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
    .{ .name = "mcp-method", .value = "tools/call" },
    .{ .name = "mcp-name", .value = "whoami" },
};

test "resource server: metadata, challenges and the principal" {
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The metadata document.
    const prm = try f.send(arena, .GET, "/.well-known/oauth-protected-resource/mcp", null, &.{});
    try std.testing.expectEqual(http.Status.ok, prm.status);
    const doc = try json.parseTree(arena, prm.body);
    try std.testing.expectEqualStrings("http://127.0.0.1/mcp", doc.object.get("resource").?.string);

    // No token: 401 with the challenge.
    const none = try f.send(arena, .POST, "/mcp", call_whoami, &std_headers);
    try std.testing.expectEqual(http.Status.unauthorized, none.status);
    try std.testing.expect(std.mem.indexOf(u8, none.www_authenticate.?, "resource_metadata=\"http://127.0.0.1/.well-known/oauth-protected-resource/mcp\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, none.www_authenticate.?, "scope=\"mcp:read\"") != null);

    // A token without the scope: 403.
    const weak = try jwt.signHs256(arena, "{\"sub\":\"eve\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:write\"}", secret, null);
    const forbidden = try f.send(arena, .POST, "/mcp", call_whoami, &(std_headers ++ [_]http.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", weak }) }}));
    try std.testing.expectEqual(http.Status.forbidden, forbidden.status);
    try std.testing.expect(std.mem.indexOf(u8, forbidden.www_authenticate.?, "insufficient_scope") != null);

    // A valid token: the handler sees the principal.
    const good = try jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}", secret, null);
    const ok = try f.send(arena, .POST, "/mcp", call_whoami, &(std_headers ++ [_]http.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", good }) }}));
    try std.testing.expectEqual(http.Status.ok, ok.status);
    const tree = try json.parseTree(arena, ok.body);
    try std.testing.expectEqualStrings("alice", tree.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);

    // An expired token: 401 invalid_token.
    const expired = try jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":10,\"scope\":\"mcp:read\"}", secret, null);
    const stale = try f.send(arena, .POST, "/mcp", call_whoami, &(std_headers ++ [_]http.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", expired }) }}));
    try std.testing.expectEqual(http.Status.unauthorized, stale.status);
    try std.testing.expect(std.mem.indexOf(u8, stale.www_authenticate.?, "invalid_token") != null);
}

const meta_elicit =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}
;
const ask_headers = [_]http.Header{
    .{ .name = "accept", .value = "application/json, text/event-stream" },
    .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
    .{ .name = "mcp-method", .value = "tools/call" },
    .{ .name = "mcp-name", .value = "ask" },
};

/// Call the tool `ask` with the token for `claims`. `state` is the sealed state of the round
/// before, or null for the first round. Checks the HTTP status and returns the parsed response.
fn callAsk(f: *Fixture, arena: std.mem.Allocator, claims: []const u8, state: ?[]const u8, status: http.Status) !Value {
    const token = try jwt.signHs256(arena, claims, secret, null);
    const retry = if (state) |s|
        try std.fmt.allocPrint(arena, ",\"inputResponses\":{{\"user_name\":{{\"action\":\"accept\",\"content\":{{\"name\":\"Ann\"}}}}}},\"requestState\":\"{s}\"", .{s})
    else
        "";
    const body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{{s},\"name\":\"ask\",\"arguments\":{{}}{s}}}}}", .{ meta_elicit, retry });
    const reply = try f.send(arena, .POST, "/mcp", body, &(ask_headers ++ [_]http.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", token }) }}));
    try std.testing.expectEqual(status, reply.status);
    return json.parseTree(arena, reply.body);
}

test "resource server: sealed request state opens only for the principal that it was sealed for" {
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const alice = "{\"iss\":\"https://as.example\",\"sub\":\"alice\",\"client_id\":\"app\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}";
    const first = try callAsk(&f, arena, alice, null, .ok);
    const result = first.object.get("result").?;
    try std.testing.expectEqualStrings("input_required", result.object.get("resultType").?.string);
    const state = result.object.get("requestState").?.string;

    // Another subject, another issuer or another client cannot use the state. The HTTP
    // server sends the invalid params error with status 400.
    const others = [_][]const u8{
        "{\"iss\":\"https://as.example\",\"sub\":\"bob\",\"client_id\":\"app\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}",
        "{\"iss\":\"https://other.example\",\"sub\":\"alice\",\"client_id\":\"app\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}",
        "{\"iss\":\"https://as.example\",\"sub\":\"alice\",\"client_id\":\"other-app\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}",
    };
    for (others) |claims| {
        const reply = try callAsk(&f, arena, claims, state, .bad_request);
        try std.testing.expect(reply.object.get("result") == null);
        const err = reply.object.get("error").?;
        try std.testing.expectEqual(@as(i64, -32602), err.object.get("code").?.integer);
        try std.testing.expectEqualStrings("invalid_request_state", err.object.get("data").?.object.get("reason").?.string);
    }

    // The same principal, with a new token, completes the request.
    const again = "{\"iss\":\"https://as.example\",\"sub\":\"alice\",\"client_id\":\"app\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":1900,\"scope\":\"mcp:read\"}";
    const done = try callAsk(&f, arena, again, state, .ok);
    const text = done.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string;
    try std.testing.expectEqualStrings("hello Ann from {\"asked\":\"alice\"}", text);
}

/// The time of the rate limits of the HTTP test, in nanoseconds. The test moves it.
var rate_now_ns: i64 = 0;

fn rateNow() i64 {
    return rate_now_ns;
}

test "resource server: rate limits keep principals apart and answer 429 with Retry-After" {
    rate_now_ns = 0;
    var options: mcp.Server.Options = .{ .info = .{ .name = "auth-test", .version = "1" }, .rate_limit_clock = rateNow };
    options.limits.rate_limits.tool_calls = .{ .count = 1, .period = .fromMilliseconds(2500) };
    var f: Fixture = undefined;
    try f.startWith(options);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const alice = try jwt.signHs256(arena, "{\"iss\":\"https://as.example\",\"sub\":\"alice\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}", secret, null);
    const bob = try jwt.signHs256(arena, "{\"iss\":\"https://as.example\",\"sub\":\"bob\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000,\"scope\":\"mcp:read\"}", secret, null);
    const as_alice = std_headers ++ [_]http.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", alice }) }};
    const as_bob = std_headers ++ [_]http.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", bob }) }};

    const first = try f.send(arena, .POST, "/mcp", call_whoami, &as_alice);
    try std.testing.expectEqual(http.Status.ok, first.status);
    try std.testing.expect(first.retry_after == null);

    // The second call of the same principal: 429, `Retry-After` in whole seconds, and the
    // JSON-RPC error with the time in milliseconds.
    const second = try f.send(arena, .POST, "/mcp", call_whoami, &as_alice);
    try std.testing.expectEqual(http.Status.too_many_requests, second.status);
    try std.testing.expectEqualStrings("3", second.retry_after.?);
    const tree = try json.parseTree(arena, second.body);
    try std.testing.expectEqual(@as(i64, 1), tree.object.get("id").?.integer);
    const err = tree.object.get("error").?;
    try std.testing.expectEqual(@as(i64, -31429), err.object.get("code").?.integer);
    try std.testing.expectEqual(@as(i64, 2500), err.object.get("data").?.object.get("retryAfterMs").?.integer);

    // Another principal on the same address has its own bucket.
    const other = try f.send(arena, .POST, "/mcp", call_whoami, &as_bob);
    try std.testing.expectEqual(http.Status.ok, other.status);
    const who = try json.parseTree(arena, other.body);
    try std.testing.expectEqualStrings("bob", who.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);

    // After the refill time, the first principal can call again.
    rate_now_ns += 2500 * std.time.ns_per_ms;
    const later = try f.send(arena, .POST, "/mcp", call_whoami, &as_alice);
    try std.testing.expectEqual(http.Status.ok, later.status);
    try std.testing.expectEqual(1, f.server.rateLimitStats(std.testing.io).tool_calls_refused);
}
