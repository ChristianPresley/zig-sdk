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
        try self.startWith(mode, .{});
    }

    fn startWith(self: *Fixture, mode: mcp.transport.http.ResponseMode, limits: mcp.Limits) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "http-test", .version = "1" }, .limits = limits });
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

// -- Limits -------------------------------------------------------------------------------------

/// A raw TCP peer that writes bytes and reads all bytes until the server closes.
const Raw = struct {
    stream: Io.net.Stream,
    read_buf: [4096]u8 = undefined,
    write_buf: [4096]u8 = undefined,
    reader: Io.net.Stream.Reader = undefined,
    writer: Io.net.Stream.Writer = undefined,

    fn open(gpa: std.mem.Allocator, port: u16) !*Raw {
        const io = std.testing.io;
        const raw = try gpa.create(Raw);
        errdefer gpa.destroy(raw);
        const address = try Io.net.IpAddress.parse("127.0.0.1", port);
        raw.* = .{ .stream = try address.connect(io, .{ .mode = .stream }) };
        raw.reader = raw.stream.reader(io, &raw.read_buf);
        raw.writer = raw.stream.writer(io, &raw.write_buf);
        return raw;
    }

    fn close(raw: *Raw, gpa: std.mem.Allocator) void {
        raw.stream.close(std.testing.io);
        gpa.destroy(raw);
    }

    fn send(raw: *Raw, bytes: []const u8) !void {
        try raw.writer.interface.writeAll(bytes);
        try raw.writer.interface.flush();
    }

    /// One response with a `content-length` body: its head and its body.
    fn readResponse(raw: *Raw, arena: std.mem.Allocator) ![]u8 {
        const r = &raw.reader.interface;
        var all: std.ArrayList(u8) = .empty;
        while (!std.mem.endsWith(u8, all.items, "\r\n\r\n")) try all.append(arena, try r.takeByte());
        var lines = std.mem.splitSequence(u8, all.items, "\r\n");
        const length = while (lines.next()) |line| {
            const colon = std.mem.findScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) break try std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " "), 10);
        } else return error.NoContentLength;
        const head_len = all.items.len;
        try all.resize(arena, head_len + length);
        try r.readSliceAll(all.items[head_len..]);
        return all.items;
    }

    /// All bytes until the end of the connection. A reset also ends the read.
    fn readToEnd(raw: *Raw, arena: std.mem.Allocator) ![]u8 {
        var all: std.ArrayList(u8) = .empty;
        const r = &raw.reader.interface;
        while (true) {
            r.fillMore() catch break;
            try all.appendSlice(arena, r.buffered());
            r.tossBuffered();
        }
        try all.appendSlice(arena, r.buffered());
        r.tossBuffered();
        return all.items;
    }
};

const discover_body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{" ++ meta_none ++ "}}";

fn discoverRequest(arena: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\nmcp-protocol-version: 2026-07-28\r\nmcp-method: server/discover\r\ncontent-length: {d}\r\n\r\n{s}", .{ discover_body.len, discover_body });
}

fn countResponses(bytes: []const u8) usize {
    return std.mem.count(u8, bytes, "HTTP/1.1 ");
}

test "http limits: a request head that does not arrive in head_timeout gets 408" {
    const gpa = std.testing.allocator;
    var limits: mcp.Limits = .{};
    limits.http.head_timeout = .fromMilliseconds(200);
    var f: Fixture = undefined;
    try f.startWith(.auto, limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A slow client sends a part of the head and then nothing.
    {
        const raw = try Raw.open(gpa, f.transport.bound_port);
        defer raw.close(gpa);
        try raw.send("POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\n");
        const reply = try raw.readToEnd(arena);
        try std.testing.expect(std.mem.startsWith(u8, reply, "HTTP/1.1 408 "));
        try std.testing.expectEqual(1, countResponses(reply));
    }
    // A client that sends no byte also gets 408 after the time limit.
    {
        const raw = try Raw.open(gpa, f.transport.bound_port);
        defer raw.close(gpa);
        try std.testing.expect(std.mem.startsWith(u8, try raw.readToEnd(arena), "HTTP/1.1 408 "));
    }
    // A complete request in time gets its response.
    const reply = try f.post(arena, discover_body, &(std_headers ++ [_]http.Header{.{ .name = "mcp-method", .value = "server/discover" }}));
    try std.testing.expectEqual(http.Status.ok, reply.status);
}

test "http limits: the server closes a keep-alive connection after idle_timeout without a response" {
    const gpa = std.testing.allocator;
    var limits: mcp.Limits = .{};
    limits.http.idle_timeout = .fromMilliseconds(300);
    var f: Fixture = undefined;
    try f.startWith(.json, limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // After a request, the connection waits for the next request.
    {
        const raw = try Raw.open(gpa, f.transport.bound_port);
        defer raw.close(gpa);
        try raw.send(try discoverRequest(arena));
        const bytes = try raw.readToEnd(arena);
        try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 "));
        // The end of the connection is the only sign of the idle timeout.
        try std.testing.expectEqual(1, countResponses(bytes));
    }
    // A notification gets 202 and takes another path to the next request.
    {
        const raw = try Raw.open(gpa, f.transport.bound_port);
        defer raw.close(gpa);
        const note = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}";
        try raw.send(try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: {d}\r\n\r\n{s}", .{ note.len, note }));
        const bytes = try raw.readToEnd(arena);
        try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 202 "));
        try std.testing.expectEqual(1, countResponses(bytes));
    }
    // A second request before the limit uses the same connection. It goes out when the first
    // response arrived, thus the wait between them is far below the limit. Before, the test
    // slept 100 ms after the first request, and a slow computer slept more than the limit.
    {
        const raw = try Raw.open(gpa, f.transport.bound_port);
        defer raw.close(gpa);
        const request_bytes = try discoverRequest(arena);
        try raw.send(request_bytes);
        try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
        try raw.send(request_bytes);
        const rest = try raw.readToEnd(arena);
        try std.testing.expect(std.mem.startsWith(u8, rest, "HTTP/1.1 200 "));
        try std.testing.expectEqual(1, countResponses(rest));
    }
}

test "http limits: a request body that does not arrive in idle_timeout gets 408" {
    const gpa = std.testing.allocator;
    var limits: mcp.Limits = .{};
    limits.http.idle_timeout = .fromMilliseconds(300);
    var f: Fixture = undefined;
    try f.startWith(.json, limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = try Raw.open(gpa, f.transport.bound_port);
    defer raw.close(gpa);
    try raw.send("POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: 100\r\n\r\n{\"jsonrpc\"");
    const bytes = try raw.readToEnd(arena);
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 408 "));
    try std.testing.expectEqual(1, countResponses(bytes));
}

test "http shutdown ends a connection that sends nothing, also without time limits" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var limits: mcp.Limits = .{};
    limits.http.head_timeout = .zero;
    limits.http.idle_timeout = .zero;
    var f: Fixture = undefined;
    try f.startWith(.json, limits);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // One silent connection, and one that waits for its next request.
    const silent = try Raw.open(gpa, f.transport.bound_port);
    defer silent.close(gpa);
    const idle = try Raw.open(gpa, f.transport.bound_port);
    defer idle.close(gpa);
    try idle.send(try discoverRequest(arena));
    var head: [12]u8 = undefined;
    try idle.reader.interface.readSliceAll(&head);
    try std.testing.expectEqualStrings("HTTP/1.1 200", &head);
    // Without time limits, the connections stay open.
    try io.sleep(.fromMilliseconds(200), .awake);

    // The peers do not close their side. The shutdown must not wait for them.
    const started = Io.Timestamp.now(io, .awake);
    f.stop();
    const took = started.durationTo(Io.Timestamp.now(io, .awake));
    try std.testing.expect(took.nanoseconds < 5 * std.time.ns_per_s);
    try std.testing.expectEqual(0, countResponses(try silent.readToEnd(arena)));
}

test "http limits: a message deeper than json_max_depth gets -32700" {
    const gpa = std.testing.allocator;
    var limits: mcp.Limits = .{};
    limits.json_max_depth = 8;
    var f: Fixture = undefined;
    try f.startWith(.json, limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const headers = std_headers ++ [_]http.Header{ .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = "add" } };
    // The message object, `params`, `arguments` and six arrays: nine levels.
    const deep = try request(arena, 1, "tools/call", "\"name\":\"add\",\"arguments\":{\"a\":[[[[[[1]]]]]],\"b\":1}");
    const reply = try f.post(arena, deep, &headers);
    try std.testing.expectEqual(http.Status.bad_request, reply.status);
    const tree = try json.parseTree(arena, reply.body);
    try std.testing.expectEqual(@as(i64, -32700), tree.object.get("error").?.object.get("code").?.integer);
    try std.testing.expect(tree.object.get("id").? == .null);
    // The message object, `params` and `_meta` with the client capabilities: four levels.
    const ok = try request(arena, 2, "tools/call", "\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}");
    const answer = try f.post(arena, ok, &headers);
    try std.testing.expectEqual(http.Status.ok, answer.status);
}
