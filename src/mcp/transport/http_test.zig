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

const NoArgs = struct {};

/// The size of the text of `big_text`: larger than the socket buffers on loopback.
const big_text_len = 8 << 20;

fn bigText(ctx: *mcp.RequestContext, args: NoArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const text = try ctx.arena.alloc(u8, big_text_len);
    @memset(text, 'x');
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{text}) };
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
        try self.server.addTool(.{ .name = "big_text", .quick = true }, bigText);
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
    // The version check comes before the other header checks: a 2025-11-25 client sends the
    // version header but no Mcp-Method and no _meta -> 400 + -32022 with data.supported.
    {
        const body = "{\"jsonrpc\":\"2.0\",\"id\":40,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"old\",\"version\":\"1\"}}}";
        const reply = try f.post(arena, body, &.{ .{ .name = "accept", .value = "application/json, text/event-stream" }, .{ .name = "mcp-protocol-version", .value = "2025-11-25" } });
        try std.testing.expectEqual(http.Status.bad_request, reply.status);
        const err = (try json.parseTree(arena, reply.body)).object.get("error").?.object;
        try std.testing.expectEqual(@as(i64, -32022), err.get("code").?.integer);
        try std.testing.expectEqualStrings("2025-11-25", err.get("data").?.object.get("requested").?.string);
        try std.testing.expectEqualStrings("2026-07-28", err.get("data").?.object.get("supported").?.array.items[0].string);
        // A different revision and a wrong Mcp-Method -> -32022 too.
        const old_list = "{\"jsonrpc\":\"2.0\",\"id\":41,\"method\":\"tools/list\",\"params\":{}}";
        const reply2 = try f.post(arena, old_list, &.{ .{ .name = "accept", .value = "application/json, text/event-stream" }, .{ .name = "mcp-protocol-version", .value = "2025-11-25" }, .{ .name = "mcp-method", .value = "prompts/list" } });
        try std.testing.expectEqual(@as(i64, -32022), (try json.parseTree(arena, reply2.body)).object.get("error").?.object.get("code").?.integer);
        // The supported version without Mcp-Method stays -32020.
        const reply3 = try f.post(arena, try request(arena, 42, "tools/list", ""), &std_headers);
        try std.testing.expectEqual(http.Status.bad_request, reply3.status);
        try std.testing.expectEqual(@as(i64, -32020), (try json.parseTree(arena, reply3.body)).object.get("error").?.object.get("code").?.integer);
        // A different revision in the header and the supported one in _meta stays -32020.
        const reply4 = try f.post(arena, try request(arena, 43, "tools/list", ""), &.{ .{ .name = "accept", .value = "application/json, text/event-stream" }, .{ .name = "mcp-protocol-version", .value = "2025-11-25" } });
        try std.testing.expectEqual(@as(i64, -32020), (try json.parseTree(arena, reply4.body)).object.get("error").?.object.get("code").?.integer);
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
        raw.* = .{ .stream = try mcp.util.loopback.connect(io, address) };
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

test "http limits: an idle_timeout that passes while the connection goes to the parker frees the connection one time" {
    const gpa = std.testing.allocator;
    var limits: mcp.Limits = .{};
    // After each response, the supervisor cancels the task of the connection while the task
    // gives the connection to the parker. Only one of them must end the task, and the parker
    // must free the connection only after the cancel.
    limits.http.idle_timeout = .fromMilliseconds(1);
    var f: Fixture = undefined;
    try f.startWith(.json, limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const request_bytes = try discoverRequest(arena);

    for (0..200) |i| {
        const raw = try Raw.open(gpa, f.transport.bound_port);
        defer raw.close(gpa);
        try raw.send(request_bytes);
        // The body of the request also has `idle_timeout`. On a slow computer the time limit
        // can pass before the server reads it: then the server closes the connection without
        // a response, or sends 408.
        const response = raw.readResponse(arena) catch |e| switch (e) {
            error.EndOfStream, error.ReadFailed => continue,
            else => return e,
        };
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 ") or std.mem.startsWith(u8, response, "HTTP/1.1 408 "));
        // Half of the clients close at once: the task closes the connection. The other half
        // wait: the connection parks, and the parker closes it.
        if (i % 2 == 0) _ = try raw.readToEnd(arena);
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

/// Send one `server/discover` request on a new connection, read the status line and close
/// the connection.
fn discoverOnce(gpa: std.mem.Allocator, port: u16) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const raw = try Raw.open(gpa, port);
    defer raw.close(gpa);
    try raw.send(try discoverRequest(arena_state.allocator()));
    var head: [12]u8 = undefined;
    try raw.reader.interface.readSliceAll(&head);
    try std.testing.expectEqualStrings("HTTP/1.1 200", &head);
}

test "http server ends serve at a cancel without a shutdown" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.json);
    defer {
        f.client.deinit();
        f.transport.deinit();
        f.server.deinit();
        gpa.free(f.base);
    }
    const served = discoverOnce(gpa, f.transport.bound_port);
    // No `shutdown`. Only the cancel can end `serve`.
    f.future.cancel(std.testing.io);
    try served;
    try std.testing.expect(f.transport.closing.load(.acquire));
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

/// Wait until the parker of `t` holds `count` connections, for at most two seconds.
fn waitHeld(t: *HttpServer, count: usize) !void {
    const io = std.testing.io;
    var waited: usize = 0;
    while (t.parker.held.load(.acquire) != count) : (waited += 1) {
        if (waited > 2000) return error.ParkerCountNotReached;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
}

test "http parker: an idle keep-alive connection holds no task, resumes on the next request and ends with the peer" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.json);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = try Raw.open(gpa, f.transport.bound_port);
    const request_bytes = try discoverRequest(arena);
    try raw.send(request_bytes);
    try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
    // After the response, the parker owns the connection and no task does.
    try waitHeld(&f.transport, 1);
    f.transport.connections_lock.lockUncancelable(std.testing.io);
    const with_task = f.transport.connections.items.len;
    f.transport.connections_lock.unlock(std.testing.io);
    try std.testing.expectEqual(0, with_task);
    // The next request wakes the connection, and it parks again.
    try raw.send(request_bytes);
    try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
    try waitHeld(&f.transport, 1);
    // The close by the peer frees the parked connection without a task.
    raw.close(gpa);
    try waitHeld(&f.transport, 0);
}

test "http parker: quick requests stay on the task of the connection, and a close during the wait ends it" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.json);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const request_bytes = try discoverRequest(arena);

    // On POSIX systems the task waits for the next request after a response. Each request
    // here comes at once, while the task waits, or later from the parker.
    for (0..3) |_| {
        const raw = try Raw.open(gpa, f.transport.bound_port);
        for (0..20) |_| {
            try raw.send(request_bytes);
            try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
        }
        // The close comes while the task waits for the next request.
        raw.close(gpa);
    }
    const io = std.testing.io;
    var waited: usize = 0;
    while (true) : (waited += 1) {
        f.transport.connections_lock.lockUncancelable(io);
        const with_task = f.transport.connections.items.len;
        f.transport.connections_lock.unlock(io);
        if (with_task == 0 and f.transport.parker.held.load(.acquire) == 0) break;
        if (waited > 2000) return error.ConnectionsNotEnded;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
}

fn bigTextRequest(arena: std.mem.Allocator, id: i64) ![]u8 {
    const body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"tools/call\",\"params\":{{{s},\"name\":\"big_text\",\"arguments\":{{}}}}}}", .{ id, meta_none });
    return std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\nmcp-protocol-version: 2026-07-28\r\nmcp-method: tools/call\r\nmcp-name: big_text\r\ncontent-length: {d}\r\n\r\n{s}", .{ body.len, body });
}

test "http parker: a quick request of a parked connection, with a response that the client reads late" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.json);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = try Raw.open(gpa, f.transport.bound_port);
    try raw.send(try discoverRequest(arena));
    try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
    try waitHeld(&f.transport, 1);
    // On Linux and Windows the parker runs this quick call itself. The response is larger than the socket
    // buffers, and the client reads it only later: the task of the connection sends the rest.
    try raw.send(try bigTextRequest(arena, 2));
    try io.sleep(.fromMilliseconds(100), .awake);
    const big = try raw.readResponse(arena);
    try std.testing.expect(std.mem.startsWith(u8, big, "HTTP/1.1 200 "));
    try std.testing.expect(big.len > big_text_len);
    try std.testing.expect(std.mem.endsWith(u8, big, "}"));
    // The connection carries the next requests.
    for (0..3) |_| {
        try waitHeld(&f.transport, 1);
        try raw.send(try discoverRequest(arena));
        try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
    }
    raw.close(gpa);
    try waitHeld(&f.transport, 0);
}

test "http parker: a quick request head with a huge Content-Length gets 413, and the server keeps serving" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.json);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = try Raw.open(gpa, f.transport.bound_port);
    defer raw.close(gpa);
    try raw.send(try discoverRequest(arena));
    try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
    try waitHeld(&f.transport, 1);
    // The parker looks at this head. The sum of its length and the body length overflows.
    try raw.send("POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\nmcp-protocol-version: 2026-07-28\r\nmcp-method: server/discover\r\ncontent-length: 18446744073709551615\r\n\r\n");
    try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 413 "));
    const other = try Raw.open(gpa, f.transport.bound_port);
    defer other.close(gpa);
    try other.send(try discoverRequest(arena));
    try std.testing.expect(std.mem.startsWith(u8, try other.readResponse(arena), "HTTP/1.1 200 "));
}

test "http parker: the cap of the worker tasks queues connections and serves them in turn" {
    const gpa = std.testing.allocator;
    var limits: mcp.Limits = .{};
    limits.http.max_in_flight = 1;
    var f: Fixture = undefined;
    try f.startWith(.json, limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var raws: [3]*Raw = undefined;
    for (&raws) |*r| r.* = try Raw.open(gpa, f.transport.bound_port);
    defer for (raws) |r| r.close(gpa);
    const request_bytes = try discoverRequest(arena);
    // Three requests at once share one worker task: each connection parks after its response,
    // and the next queued connection gets the task.
    for (raws) |r| try r.send(request_bytes);
    for (raws) |r| try std.testing.expect(std.mem.startsWith(u8, try r.readResponse(arena), "HTTP/1.1 200 "));
    for (raws) |r| try r.send(request_bytes);
    for (raws) |r| try std.testing.expect(std.mem.startsWith(u8, try r.readResponse(arena), "HTTP/1.1 200 "));
    try waitHeld(&f.transport, 3);
}

test "http limits: at max_connections a new connection closes the idle connection that waited longest" {
    const gpa = std.testing.allocator;
    var limits: mcp.Limits = .{};
    limits.http.max_connections = 2;
    var f: Fixture = undefined;
    try f.startWith(.json, limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const request_bytes = try discoverRequest(arena);
    const oldest = try Raw.open(gpa, f.transport.bound_port);
    defer oldest.close(gpa);
    try oldest.send(request_bytes);
    try std.testing.expect(std.mem.startsWith(u8, try oldest.readResponse(arena), "HTTP/1.1 200 "));
    try waitHeld(&f.transport, 1);
    const newer = try Raw.open(gpa, f.transport.bound_port);
    defer newer.close(gpa);
    try newer.send(request_bytes);
    try std.testing.expect(std.mem.startsWith(u8, try newer.readResponse(arena), "HTTP/1.1 200 "));
    try waitHeld(&f.transport, 2);
    // Both permits are in use. A third connection gets its response without a wait for the
    // idle time limit, and the server closes the oldest idle connection.
    const io = std.testing.io;
    const started = Io.Timestamp.now(io, .awake);
    const third = try Raw.open(gpa, f.transport.bound_port);
    defer third.close(gpa);
    try third.send(request_bytes);
    try std.testing.expect(std.mem.startsWith(u8, try third.readResponse(arena), "HTTP/1.1 200 "));
    const took = started.durationTo(Io.Timestamp.now(io, .awake));
    try std.testing.expect(took.nanoseconds < 5 * std.time.ns_per_s);
    try std.testing.expectEqual(0, (try oldest.readToEnd(arena)).len);
    // The newer idle connection stays open and carries one more request.
    try newer.send(request_bytes);
    try std.testing.expect(std.mem.startsWith(u8, try newer.readResponse(arena), "HTTP/1.1 200 "));
}

test "http sse response: the connection carries the next request" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.auto);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const body = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{},\"progressToken\":\"p\"},\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}}}";
    const call = try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\nmcp-protocol-version: 2026-07-28\r\nmcp-method: tools/call\r\nmcp-name: add\r\ncontent-length: {d}\r\n\r\n{s}", .{ body.len, body });
    const raw = try Raw.open(gpa, f.transport.bound_port);
    defer raw.close(gpa);
    try raw.send(call);
    // The SSE stream has a chunked body. Read up to its last chunk.
    const r = &raw.reader.interface;
    var all: std.ArrayList(u8) = .empty;
    while (!std.mem.endsWith(u8, all.items, "\r\n0\r\n\r\n")) try all.append(arena, try r.takeByte());
    try std.testing.expect(std.mem.startsWith(u8, all.items, "HTTP/1.1 200 "));
    try std.testing.expect(std.mem.find(u8, all.items, "text/event-stream") != null);
    try std.testing.expect(std.ascii.findIgnoreCase(all.items, "connection: close") == null);
    try std.testing.expect(std.mem.find(u8, all.items, "notifications/progress") != null);
    // The same connection carries the next request.
    try raw.send(try discoverRequest(arena));
    try std.testing.expect(std.mem.startsWith(u8, try raw.readResponse(arena), "HTTP/1.1 200 "));
}
