//! Loopback tests for the Streamable HTTP server through `std.http.Client`.
const std = @import("std");
const Io = std.Io;
const http = std.http;
const mcp = @import("../../mcp.zig");
const json = mcp.json;
const types = mcp.types;
const HttpServer = mcp.transport.http.Server;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(0, 100, null);
    try ctx.progress(50, 100, null);
    try ctx.progress(100, 100, null);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

const HeaderArgs = struct {
    region: []const u8,
    priority: i64,
    pub const json_schema = .{ .fields = .{ .region = .{ .header = "Region" }, .priority = .{ .header = "Priority" } } };
};

fn echoHeaders(ctx: *mcp.RequestContext, args: HeaderArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}/{d}", .{ args.region, args.priority }) };
}

const Fixture = struct {
    server: mcp.Server,
    transport: HttpServer,
    future: Io.Future(void),
    client: http.Client,
    base: []u8,

    fn start(self: *Fixture, mode: mcp.transport.http.ResponseMode) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "http-test", .version = "1" } });
        try self.server.addTool(.{ .name = "add" }, add);
        try self.server.addTool(.{ .name = "test_headers" }, echoHeaders);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .response_mode = mode });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        self.client = .{ .allocator = gpa, .io = io };
        self.base = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/mcp", .{self.transport.bound_port});
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

    const Reply = struct { status: http.Status, body: []u8 };

    fn post(self: *Fixture, gpa: std.mem.Allocator, body: []const u8, extra: []const http.Header) !Reply {
        var aw: Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        const result = try self.client.fetch(.{
            .location = .{ .url = self.base },
            .method = .POST,
            .payload = body,
            .headers = .{ .content_type = .{ .override = "application/json" }, .accept_encoding = .{ .override = "identity" } },
            .extra_headers = extra,
            .response_writer = &aw.writer,
        });
        return .{ .status = result.status, .body = try aw.toOwnedSlice() };
    }
};

fn request(gpa: std.mem.Allocator, id: i64, method: []const u8, extra: []const u8) ![]u8 {
    const sep: []const u8 = if (extra.len > 0) "," else "";
    return std.fmt.allocPrint(gpa, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta_none, sep, extra });
}

const std_headers = [_]http.Header{
    .{ .name = "accept", .value = "application/json, text/event-stream" },
    .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
};

test "http ladder and json responses" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.auto);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Discover in JSON mode.
    {
        const body = try request(arena, 1, "server/discover", "");
        const reply = try f.post(arena, body, &(std_headers ++ [_]http.Header{.{ .name = "mcp-method", .value = "server/discover" }}));
        try std.testing.expectEqual(http.Status.ok, reply.status);
        const tree = try json.parseTree(arena, reply.body);
        try std.testing.expectEqualStrings("2026-07-28", tree.object.get("result").?.object.get("supportedVersions").?.array.items[0].string);
    }
    // Missing protocol version header -> 400 + -32020.
    {
        const body = try request(arena, 2, "server/discover", "");
        const reply = try f.post(arena, body, &.{ .{ .name = "accept", .value = "application/json, text/event-stream" }, .{ .name = "mcp-method", .value = "server/discover" } });
        try std.testing.expectEqual(http.Status.bad_request, reply.status);
        const tree = try json.parseTree(arena, reply.body);
        try std.testing.expectEqual(@as(i64, -32020), tree.object.get("error").?.object.get("code").?.integer);
        try std.testing.expectEqual(@as(i64, 2), tree.object.get("id").?.integer);
    }
    // Header and body versions differ -> -32020; unsupported version -> -32022.
    {
        const body = try request(arena, 3, "server/discover", "");
        const reply = try f.post(arena, body, &.{ .{ .name = "accept", .value = "application/json, text/event-stream" }, .{ .name = "mcp-protocol-version", .value = "v999.0.0" }, .{ .name = "mcp-method", .value = "server/discover" } });
        try std.testing.expectEqual(http.Status.bad_request, reply.status);
        const tree = try json.parseTree(arena, reply.body);
        try std.testing.expectEqual(@as(i64, -32020), tree.object.get("error").?.object.get("code").?.integer);
        const body2 = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"server/discover\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"v999.0.0\",\"io.modelcontextprotocol/clientCapabilities\":{{}}}}}}}}", .{});
        const reply2 = try f.post(arena, body2, &.{ .{ .name = "accept", .value = "application/json, text/event-stream" }, .{ .name = "mcp-protocol-version", .value = "v999.0.0" }, .{ .name = "mcp-method", .value = "server/discover" } });
        try std.testing.expectEqual(http.Status.bad_request, reply2.status);
        const tree2 = try json.parseTree(arena, reply2.body);
        try std.testing.expectEqual(@as(i64, -32022), tree2.object.get("error").?.object.get("code").?.integer);
        try std.testing.expectEqualStrings("v999.0.0", tree2.object.get("error").?.object.get("data").?.object.get("requested").?.string);
    }
    // Unknown method -> 404 + -32601; removed method too.
    {
        const body = try request(arena, 5, "ping", "");
        const reply = try f.post(arena, body, &(std_headers ++ [_]http.Header{.{ .name = "mcp-method", .value = "ping" }}));
        try std.testing.expectEqual(http.Status.not_found, reply.status);
        const tree = try json.parseTree(arena, reply.body);
        try std.testing.expectEqual(@as(i64, -32601), tree.object.get("error").?.object.get("code").?.integer);
    }
    // Missing _meta -> 400 + -32602.
    {
        const body = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"server/discover\",\"params\":{}}";
        const reply = try f.post(arena, body, &(std_headers ++ [_]http.Header{.{ .name = "mcp-method", .value = "server/discover" }}));
        try std.testing.expectEqual(http.Status.bad_request, reply.status);
        const tree = try json.parseTree(arena, reply.body);
        try std.testing.expectEqual(@as(i64, -32602), tree.object.get("error").?.object.get("code").?.integer);
    }
    // Notification -> 202.
    {
        const body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}";
        const reply = try f.post(arena, body, &std_headers);
        try std.testing.expectEqual(http.Status.accepted, reply.status);
    }
    // Invalid Origin -> 403.
    {
        const body = try request(arena, 7, "server/discover", "");
        const reply = try f.post(arena, body, &(std_headers ++ [_]http.Header{ .{ .name = "mcp-method", .value = "server/discover" }, .{ .name = "origin", .value = "http://evil.example.com" } }));
        try std.testing.expectEqual(http.Status.forbidden, reply.status);
    }
    // Parse error -> 400 + -32700 with null id.
    {
        const reply = try f.post(arena, "{not json", &std_headers);
        try std.testing.expectEqual(http.Status.bad_request, reply.status);
        const tree = try json.parseTree(arena, reply.body);
        try std.testing.expectEqual(@as(i64, -32700), tree.object.get("error").?.object.get("code").?.integer);
    }
    // GET -> 405 with Allow.
    {
        var aw: Io.Writer.Allocating = .init(arena);
        const result = try f.client.fetch(.{ .location = .{ .url = f.base }, .method = .GET, .response_writer = &aw.writer });
        try std.testing.expectEqual(http.Status.method_not_allowed, result.status);
    }
    // Mcp-Param headers: mirrored values must match; a mismatch is -32020.
    {
        const body = try request(arena, 8, "tools/call", "\"name\":\"test_headers\",\"arguments\":{\"region\":\"us-west1\",\"priority\":42}");
        const ok = try f.post(arena, body, &(std_headers ++ [_]http.Header{ .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = "test_headers" }, .{ .name = "mcp-param-region", .value = "us-west1" }, .{ .name = "mcp-param-priority", .value = "42" } }));
        try std.testing.expectEqual(http.Status.ok, ok.status);
        const tree = try json.parseTree(arena, ok.body);
        try std.testing.expectEqualStrings("us-west1/42", tree.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
        const bad = try f.post(arena, body, &(std_headers ++ [_]http.Header{ .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = "test_headers" }, .{ .name = "mcp-param-region", .value = "eu-west1" }, .{ .name = "mcp-param-priority", .value = "42" } }));
        try std.testing.expectEqual(http.Status.bad_request, bad.status);
        const missing = try f.post(arena, body, &(std_headers ++ [_]http.Header{ .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = "test_headers" } }));
        try std.testing.expectEqual(http.Status.bad_request, missing.status);
    }
}

test "http sse response with progress notifications" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.auto);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{{}},\"progressToken\":\"progress-test-1\"}},\"name\":\"add\",\"arguments\":{{\"a\":1,\"b\":2}}}}}}", .{});
    const reply = try f.post(arena, body, &(std_headers ++ [_]http.Header{ .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = "add" } }));
    try std.testing.expectEqual(http.Status.ok, reply.status);
    // The body is an SSE stream: three progress events then the response.
    var parser: mcp.transport.sse.Parser = .init(gpa);
    defer parser.deinit();
    try parser.feed(reply.body);
    var events: usize = 0;
    var last_progress: f64 = -1;
    var got_result = false;
    while (parser.next()) |e| {
        defer parser.release(e);
        events += 1;
        const tree = try json.parseTree(arena, e.data);
        if (tree.object.get("method")) |m| {
            try std.testing.expectEqualStrings("notifications/progress", m.string);
            const p = tree.object.get("params").?;
            try std.testing.expectEqualStrings("progress-test-1", p.object.get("progressToken").?.string);
            const value: f64 = switch (p.object.get("progress").?) {
                .integer => |i| @floatFromInt(i),
                .float => |x| x,
                else => unreachable,
            };
            try std.testing.expect(value > last_progress);
            last_progress = value;
        } else {
            try std.testing.expect(!got_result);
            got_result = true;
            try std.testing.expectEqualStrings("3", tree.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
        }
    }
    try std.testing.expectEqual(4, events);
    try std.testing.expect(got_result);
}
