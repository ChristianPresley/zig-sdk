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
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "auth-test", .version = "1" } });
        try self.server.addToolJson(.{ .name = "whoami" }, whoami);
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

    const Reply = struct { status: http.Status, body: []u8, www_authenticate: ?[]u8 };

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
        var it = response.head.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) {
            www = try arena.dupe(u8, h.value);
        };
        const status = response.head.status;
        var transfer: [4096]u8 = undefined;
        const text = try response.reader(&transfer).allocRemaining(arena, .limited(1 << 20));
        return .{ .status = status, .body = text, .www_authenticate = www };
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
