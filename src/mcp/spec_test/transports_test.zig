//! Tests for the transport requirements of the specification: the stdio binding and the
//! Streamable HTTP binding, on the server side and on the client side.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const http = std.http;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const json = mcp.json;
const types = mcp.types;
const Client = mcp.Client;
const HttpServer = mcp.transport.http.Server;
const http1 = mcp.transport.http1;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;
const meta_elicit =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}
;
const meta_progress =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":"tick"}
;

fn request(arena: std.mem.Allocator, id: i64, method: []const u8, meta: []const u8, extra: []const u8) ![]u8 {
    const sep: []const u8 = if (extra.len > 0) "," else "";
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta, sep, extra });
}

// -- Tools -------------------------------------------------------------------------------------

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(1, 2, null);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

fn multiline(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "first line\nsecond line\r\n", .{}) };
}

fn askName(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content orelse .null, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "Name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

/// Set when a handler saw the cancellation of its request.
var saw_cancel: std.atomic.Value(bool) = .init(false);

/// Waits for the cancellation of its request, then stops.
fn waitForCancel(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        ctx.checkCancel() catch |e| {
            saw_cancel.store(true, .release);
            return e;
        };
        try ctx.io.sleep(.fromMilliseconds(5), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "not cancelled", .{}) };
}

/// Set when `pollCancel` started.
var poll_started: std.atomic.Value(bool) = .init(false);
/// Set when `pollCancel` saw the cancellation.
var poll_cancelled: std.atomic.Value(bool) = .init(false);

/// Polls for the cancellation and writes nothing, at most five seconds.
fn pollCancel(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    poll_started.store(true, .release);
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        ctx.checkCancel() catch |e| {
            poll_cancelled.store(true, .release);
            return e;
        };
        try ctx.io.sleep(.fromMilliseconds(5), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "not cancelled", .{}) };
}

/// Sends progress until a send fails because the stream is gone.
fn ticker(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        ctx.progress(@floatFromInt(i), null, null) catch |e| {
            if (e == error.Canceled) saw_cancel.store(true, .release);
            return e;
        };
        try ctx.io.sleep(.fromMilliseconds(10), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "done", .{}) };
}

const HeaderArgs = struct {
    region: []const u8,
    priority: i64,
    pub const json_schema = .{ .fields = .{ .region = .{ .header = "Region" }, .priority = .{ .header = "Priority" } } };
};

fn echoHeaders(ctx: *mcp.RequestContext, args: HeaderArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}/{d}", .{ args.region, args.priority }) };
}

const OptionalArgs = struct {
    region: ?[]const u8 = null,
    verbose: ?bool = null,
    pub const json_schema = .{ .fields = .{ .region = .{ .header = "Region" }, .verbose = .{ .header = "Verbose" } } };
};

fn echoOptional(ctx: *mcp.RequestContext, args: OptionalArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{args.region orelse "none"}) };
}

fn echoNested(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "nested", .{}) };
}

const nested_schema =
    \\{"type":"object","properties":{"target":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}},"count":{"type":"integer","x-mcp-header":"Count"}}}
;

fn readStatic(ctx: *mcp.RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "static" } };
    return .{ .complete = .{ .contents = contents } };
}

fn initServer(server: *mcp.Server) !void {
    server.* = try mcp.Server.init(std.testing.allocator, std.testing.io, .{ .info = .{ .name = "g2", .version = "1" }, .mrtr = .{ .elicitation = true } });
    errdefer server.deinit();
    try server.addTool(.{ .name = "add" }, add);
    try server.addToolJson(.{ .name = "multiline" }, multiline);
    try server.addToolJson(.{ .name = "ask_name" }, askName);
    try server.addToolJson(.{ .name = "wait_for_cancel" }, waitForCancel);
    try server.addToolJson(.{ .name = "ticker" }, ticker);
    try server.addToolJson(.{ .name = "poll_cancel" }, pollCancel);
    try server.addTool(.{ .name = "test_headers" }, echoHeaders);
    try server.addTool(.{ .name = "optional_headers" }, echoOptional);
    try server.addToolJson(.{ .name = "nested_headers", .input_schema = nested_schema }, echoNested);
    try server.addResource(.{ .uri = "test://static", .name = "static" }, readStatic);
}

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

// -- stdio server ------------------------------------------------------------------------------

/// Run the stdio server over `input` and return what it wrote.
fn runStdio(server: *mcp.Server, input: []const u8, out: *Io.Writer.Allocating) !void {
    var reader: Io.Reader = .fixed(input);
    var transport: mcp.transport.stdio.Server = .init(std.testing.io, std.testing.allocator, server, &out.writer);
    defer transport.deinit();
    // `run` returns when the input ends, after the requests in flight are done.
    try transport.run(&reader);
}

/// Split the output of the stdio server into lines and parse each one as one message.
fn parseLines(arena: std.mem.Allocator, output: []const u8) ![]mcp.jsonrpc.Message {
    var list: std.ArrayList(mcp.jsonrpc.Message) = .empty;
    try std.testing.expect(output.len > 0);
    // Every message ends with a newline, and there is no text after the last one.
    try std.testing.expectEqual(@as(u8, '\n'), output[output.len - 1]);
    var it = std.mem.splitScalar(u8, output[0 .. output.len - 1], '\n');
    while (it.next()) |line| {
        try std.testing.expect(line.len > 0);
        try std.testing.expect(std.unicode.utf8ValidateSlice(line));
        const tree = try json.parseTree(arena, line);
        try std.testing.expectEqualStrings("2.0", tree.object.get("jsonrpc").?.string);
        try list.append(arena, try mcp.jsonrpc.Message.parse(arena, line));
    }
    return list.items;
}

fn responseFor(arena: std.mem.Allocator, output: []const u8, id: i64) !?Value {
    var it = std.mem.splitScalar(u8, output, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const tree = try json.parseTree(arena, line);
        const got = tree.object.get("id") orelse continue;
        if (got == .integer and got.integer == id) return tree;
    }
    return null;
}

test "stdio server writes one valid JSON-RPC message per line and never a request" {
    const gpa = std.testing.allocator;
    var server: mcp.Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var input: std.ArrayList(u8) = .empty;
    for ([_][]const u8{
        try request(arena, 1, "server/discover", meta_none, ""),
        try request(arena, 2, "tools/call", meta_none, "\"name\":\"multiline\""),
        try request(arena, 3, "tools/call", meta_elicit, "\"name\":\"ask_name\""),
        try request(arena, 4, "tools/call", meta_progress, "\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}"),
        "\xff\xfe{\"jsonrpc\":\"2.0\"}",
        "{not json",
    }) |line| {
        try input.appendSlice(arena, line);
        try input.append(arena, '\n');
    }
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try runStdio(&server, input.items, &out);

    const messages = try parseLines(arena, out.written());
    var responses: usize = 0;
    var errors_null_id: usize = 0;
    var notifications: usize = 0;
    for (messages) |m| switch (m) {
        .request => return error.TestUnexpectedResult,
        .response => responses += 1,
        .error_response => |e| {
            try std.testing.expect(e.id == null);
            try std.testing.expectEqual(@as(i64, -32700), e.code);
            errors_null_id += 1;
        },
        .notification => |n| {
            try std.testing.expectEqualStrings("notifications/progress", n.method);
            notifications += 1;
        },
    };
    try std.testing.expectEqual(4, responses);
    // The invalid UTF-8 line and the broken JSON line are parse errors.
    try std.testing.expectEqual(2, errors_null_id);
    try std.testing.expectEqual(1, notifications);

    // The newlines of the tool text travel escaped inside the one line.
    const text = (try responseFor(arena, out.written(), 2)).?;
    try std.testing.expectEqualStrings("first line\nsecond line\r\n", text.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
    // The server asks for input inside a result, not with a request of its own.
    const ask = (try responseFor(arena, out.written(), 3)).?;
    try std.testing.expectEqualStrings("input_required", ask.object.get("result").?.object.get("resultType").?.string);
}

test "stdio server answers a message deeper than limits.json_max_depth with a parse error" {
    const gpa = std.testing.allocator;
    var server: mcp.Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const max_depth = server.options.limits.json_max_depth;

    // The message object, `params` and `arguments` are three levels of the depth.
    const ok_args = try std.fmt.allocPrint(arena, "\"name\":\"multiline\",\"arguments\":{{\"a\":{s}}}", .{try json.nestedArrays(arena, max_depth - 3)});
    const deep_args = try std.fmt.allocPrint(arena, "\"name\":\"multiline\",\"arguments\":{{\"a\":{s}}}", .{try json.nestedArrays(arena, max_depth - 2)});
    // Far too deep for the stack of a recursive parser or serializer.
    const huge = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"x\":{s}}}}}", .{try json.nestedArrays(arena, 1 << 20)});
    const input = try std.mem.concat(arena, u8, &.{
        try request(arena, 1, "tools/call", meta_none, ok_args),   "\n",
        try request(arena, 2, "tools/call", meta_none, deep_args), "\n",
        huge,                                                      "\n",
    });
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try runStdio(&server, input, &out);

    // The message at the limit gets an answer with its id.
    try std.testing.expect(try responseFor(arena, out.written(), 1) != null);
    var parse_errors: usize = 0;
    for (try parseLines(arena, out.written())) |m| switch (m) {
        .error_response => |e| if (e.code == -32700) {
            try std.testing.expect(e.id == null);
            parse_errors += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(2, parse_errors);
}

test "stdio server answers valid JSON that is not a message with Invalid Request and the id" {
    const gpa = std.testing.allocator;
    var server: mcp.Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Each line is valid JSON but not a JSON-RPC message. The server recovers the id.
    const input = "{\"jsonrpc\":\"2.0\",\"id\":8}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":\"s-9\",\"params\":{}}\n" ++
        "[1,2]\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"server/discover\",\"params\":{" ++ meta_none ++ "}}\n";
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try runStdio(&server, input, &out);

    const messages = try parseLines(arena, out.written());
    try std.testing.expectEqual(4, messages.len);
    try std.testing.expectEqual(@as(i64, 8), messages[0].error_response.id.?.integer);
    try std.testing.expectEqual(@as(i64, -32600), messages[0].error_response.code);
    try std.testing.expectEqualStrings("s-9", messages[1].error_response.id.?.string);
    try std.testing.expectEqual(@as(i64, -32600), messages[1].error_response.code);
    try std.testing.expect(messages[2].error_response.id == null);
    // The server still serves the next request.
    try std.testing.expectEqual(@as(i64, 10), messages[3].response.id.integer);
}

test "stdio server sends nothing more for a request that the client cancelled" {
    const gpa = std.testing.allocator;
    var server: mcp.Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    saw_cancel.store(false, .release);

    const input = try std.mem.concat(arena, u8, &.{
        try request(arena, 7, "tools/call", meta_progress, "\"name\":\"wait_for_cancel\""),
        "\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":7,\"reason\":\"user\"}}\n",
        try request(arena, 8, "server/discover", meta_none, ""),
        "\n",
    });
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try runStdio(&server, input, &out);

    try std.testing.expect(saw_cancel.load(.acquire));
    try std.testing.expect((try responseFor(arena, out.written(), 8)) != null);
    // No response and no notification for request 7.
    try std.testing.expect((try responseFor(arena, out.written(), 7)) == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "notifications/progress") == null);
}

// -- Streamable HTTP server --------------------------------------------------------------------

const Fixture = struct {
    server: mcp.Server,
    transport: HttpServer,
    future: Io.Future(void),
    host: []u8,

    fn start(self: *Fixture) !void {
        const io = std.testing.io;
        try initServer(&self.server);
        errdefer self.server.deinit();
        self.transport = .init(io, std.testing.allocator, &self.server, .{ .port = 0 });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        self.host = try std.fmt.allocPrint(std.testing.allocator, "127.0.0.1:{d}", .{self.transport.bound_port});
    }

    fn serveIgnoringErrors(t: *HttpServer) void {
        t.serve() catch {};
    }

    fn stop(self: *Fixture) void {
        self.transport.shutdown();
        self.future.await(std.testing.io);
        self.transport.deinit();
        self.server.deinit();
        std.testing.allocator.free(self.host);
    }

    const Reply = struct {
        status: u16,
        /// The raw response head, with the status line.
        head: []const u8,
        body: []const u8,

        fn header(self: Reply, name: []const u8) ?[]const u8 {
            var it: http.HeaderIterator = .init(self.head);
            while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
            return null;
        }

        fn tree(self: Reply, arena: std.mem.Allocator) !Value {
            return json.parseTree(arena, self.body);
        }
    };

    /// Send one request with exactly the given headers on a new connection.
    fn send(self: *Fixture, arena: std.mem.Allocator, method: []const u8, headers: []const http.Header, body: []const u8) !Reply {
        const conn = try http1.Connection.open(std.testing.io, std.testing.allocator, "127.0.0.1", self.transport.bound_port, null);
        defer conn.close();
        // A raw head: these tests send bytes that `Connection.send` refuses, such as DEL.
        const w = conn.writer;
        try w.print("{s} /mcp HTTP/1.1\r\nhost: {s}\r\nconnection: close\r\n", .{ method, self.host });
        if (body.len > 0 or !std.mem.eql(u8, method, "GET")) try w.print("content-length: {d}\r\n", .{body.len});
        for (headers) |h| try w.print("{s}: {s}\r\n", .{ h.name, h.value });
        try w.writeAll("\r\n");
        try w.writeAll(body);
        try conn.flush();
        const response = try conn.receiveHead();
        const head = try arena.dupe(u8, response.bytes);
        const status: u16 = @intFromEnum(response.head.status);
        const reader = conn.bodyReader(&response);
        const reply_body = try reader.allocRemaining(arena, .limited(1 << 20));
        return .{ .status = status, .head = head, .body = reply_body };
    }

    /// POST with the standard headers plus `extra`.
    fn post(self: *Fixture, arena: std.mem.Allocator, extra: []const http.Header, body: []const u8) !Reply {
        var headers: std.ArrayList(http.Header) = .empty;
        try headers.appendSlice(arena, &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "accept", .value = "application/json, text/event-stream" },
        });
        try headers.appendSlice(arena, extra);
        return self.send(arena, "POST", headers.items, body);
    }
};

const version_header: http.Header = .{ .name = "mcp-protocol-version", .value = "2026-07-28" };

fn callHeaders(comptime name: []const u8, comptime params: []const http.Header) []const http.Header {
    return &([_]http.Header{ version_header, .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = name } } ++ params[0..params.len].*);
}

/// Expect `400 Bad Request` with the `-32020` error for the request id.
fn expectHeaderMismatch(arena: std.mem.Allocator, reply: Fixture.Reply, id: i64) !void {
    try std.testing.expectEqual(@as(u16, 400), reply.status);
    const tree = try reply.tree(arena);
    try std.testing.expectEqual(@as(i64, -32020), errorCode(tree).?);
    try std.testing.expectEqual(id, tree.object.get("id").?.integer);
}

test "streamable http server requires Mcp-Method and Mcp-Name and compares them with the body" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const call = try request(arena, 1, "tools/call", meta_none, "\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}");

    // All headers present and equal to the body.
    const ok = try f.post(arena, callHeaders("add", &.{}), call);
    try std.testing.expectEqual(@as(u16, 200), ok.status);
    // Mcp-Method is missing, differs, or differs only in case (values are case-sensitive).
    try expectHeaderMismatch(arena, try f.post(arena, &.{ version_header, .{ .name = "mcp-name", .value = "add" } }, call), 1);
    try expectHeaderMismatch(arena, try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "tools/list" }, .{ .name = "mcp-name", .value = "add" } }, call), 1);
    try expectHeaderMismatch(arena, try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "Tools/Call" }, .{ .name = "mcp-name", .value = "add" } }, call), 1);
    // Mcp-Name is missing or differs from params.name.
    try expectHeaderMismatch(arena, try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "tools/call" } }, call), 1);
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("multiline", &.{}), call), 1);
    // For resources/read, Mcp-Name mirrors params.uri.
    const read = try request(arena, 2, "resources/read", meta_none, "\"uri\":\"test://static\"");
    const read_ok = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "resources/read" }, .{ .name = "mcp-name", .value = "test://static" } }, read);
    try std.testing.expectEqual(@as(u16, 200), read_ok.status);
    try expectHeaderMismatch(arena, try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "resources/read" }, .{ .name = "mcp-name", .value = "test://other" } }, read), 2);
    try expectHeaderMismatch(arena, try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "resources/read" } }, read), 2);
}

test "streamable http server matches header names without regard to case" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const call = try request(arena, 3, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"us-west1\",\"priority\":42}");
    const reply = try f.send(arena, "POST", &.{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "ACCEPT", .value = "application/json, text/event-stream" },
        .{ .name = "MCP-PROTOCOL-VERSION", .value = "2026-07-28" },
        .{ .name = "MCP-Method", .value = "tools/call" },
        .{ .name = "mCP-nAME", .value = "test_headers" },
        .{ .name = "MCP-PARAM-REGION", .value = "us-west1" },
        .{ .name = "Mcp-Param-priority", .value = "42" },
    }, call);
    try std.testing.expectEqual(@as(u16, 200), reply.status);
    const tree = try reply.tree(arena);
    try std.testing.expectEqualStrings("us-west1/42", tree.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
}

test "streamable http server decodes base64 header values before it compares them" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const encode = mcp.transport.envelope.encodeValue;

    // Mcp-Name in the sentinel form, and a non-ASCII parameter in the sentinel form.
    const call = try request(arena, 4, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"Gr\u{fc}\u{df}e \",\"priority\":7}");
    const name_b64 = "=?base64?dGVzdF9oZWFkZXJz?=";
    const region_b64 = try encode(arena, "Gr\u{fc}\u{df}e ");
    try std.testing.expect(std.mem.startsWith(u8, region_b64, "=?base64?"));
    const ok = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = name_b64 }, .{ .name = "mcp-param-region", .value = region_b64 }, .{ .name = "mcp-param-priority", .value = "7" } }, call);
    try std.testing.expectEqual(@as(u16, 200), ok.status);
    const tree = try ok.tree(arena);
    try std.testing.expectEqualStrings("Gr\u{fc}\u{df}e /7", tree.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);

    // The markers are case-sensitive: an upper-case marker is a plain value, so it does not match.
    const plain = try request(arena, 5, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"us-west1\",\"priority\":7}");
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "=?BASE64?dXMtd2VzdDE=?=" }, .{ .name = "mcp-param-priority", .value = "7" } }), plain), 5);
    // The lower-case form of the same value matches.
    const lower = try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "=?base64?dXMtd2VzdDE=?=" }, .{ .name = "mcp-param-priority", .value = "7" } }), plain);
    try std.testing.expectEqual(@as(u16, 200), lower.status);
    // A sentinel with a broken base64 body is rejected.
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "=?base64?dXMtd2VzdDE?=" }, .{ .name = "mcp-param-priority", .value = "7" } }), plain), 5);
    // An integer header compares by number.
    const numeric = try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "us-west1" }, .{ .name = "mcp-param-priority", .value = "7.0" } }), plain);
    try std.testing.expectEqual(@as(u16, 200), numeric.status);
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "us-west1" }, .{ .name = "mcp-param-priority", .value = "8" } }), plain), 5);
}

test "streamable http server expects Mcp-Param headers only for values in the body" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A null value and an absent value need no header.
    const with_null = try request(arena, 6, "tools/call", meta_none, "\"name\":\"optional_headers\",\"arguments\":{\"region\":null}");
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("optional_headers", &.{}), with_null)).status);
    const absent = try request(arena, 7, "tools/call", meta_none, "\"name\":\"optional_headers\",\"arguments\":{}");
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("optional_headers", &.{}), absent)).status);
    // A value in the body without its header is rejected.
    const with_value = try request(arena, 8, "tools/call", meta_none, "\"name\":\"optional_headers\",\"arguments\":{\"verbose\":true}");
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("optional_headers", &.{}), with_value), 8);
    // A header without a value in the body is rejected too.
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("optional_headers", &.{.{ .name = "mcp-param-region", .value = "eu" }}), absent), 7);
    // With the header, the value must match.
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("optional_headers", &.{.{ .name = "mcp-param-verbose", .value = "true" }}), with_value)).status);
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("optional_headers", &.{.{ .name = "mcp-param-verbose", .value = "false" }}), with_value), 8);
}

test "streamable http server reads Mcp-Param values at the nested property path" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const full = try request(arena, 11, "tools/call", meta_none, "\"name\":\"nested_headers\",\"arguments\":{\"target\":{\"region\":\"eu\"},\"count\":3}");
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("nested_headers", &.{ .{ .name = "mcp-param-region", .value = "eu" }, .{ .name = "mcp-param-count", .value = "3" } }), full)).status);
    // The nested value needs its header, and the header must match the nested value.
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("nested_headers", &.{.{ .name = "mcp-param-count", .value = "3" }}), full), 11);
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("nested_headers", &.{ .{ .name = "mcp-param-region", .value = "us" }, .{ .name = "mcp-param-count", .value = "3" } }), full), 11);
    // Without a value at the path, the server expects no header.
    const no_target = try request(arena, 12, "tools/call", meta_none, "\"name\":\"nested_headers\",\"arguments\":{\"count\":3}");
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("nested_headers", &.{.{ .name = "mcp-param-count", .value = "3" }}), no_target)).status);
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("nested_headers", &.{ .{ .name = "mcp-param-region", .value = "eu" }, .{ .name = "mcp-param-count", .value = "3" } }), no_target), 12);
    const null_region = try request(arena, 13, "tools/call", meta_none, "\"name\":\"nested_headers\",\"arguments\":{\"target\":{\"region\":null}}");
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("nested_headers", &.{}), null_region)).status);
    // A property with the same name at the root is not the annotated property.
    const root_region = try request(arena, 14, "tools/call", meta_none, "\"name\":\"nested_headers\",\"arguments\":{\"region\":\"eu\"}");
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("nested_headers", &.{}), root_region)).status);
}

test "streamable http server rejects invalid characters and unsafe integers in mirrored headers" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const encode = mcp.transport.envelope.encodeValue;

    // Raw non-ASCII bytes and control characters are invalid, also when they equal the body.
    const greeting = try request(arena, 21, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"Gr\u{fc}\u{df}e\",\"priority\":7}");
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "Gr\u{fc}\u{df}e" }, .{ .name = "mcp-param-priority", .value = "7" } }), greeting), 21);
    const greeting_b64 = try encode(arena, "Gr\u{fc}\u{df}e");
    const greeting_ok = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "tools/call" }, .{ .name = "mcp-name", .value = "test_headers" }, .{ .name = "mcp-param-region", .value = greeting_b64 }, .{ .name = "mcp-param-priority", .value = "7" } }, greeting);
    try std.testing.expectEqual(@as(u16, 200), greeting_ok.status);
    const delete = try request(arena, 22, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"a\\u007fb\",\"priority\":7}");
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "a\x7fb" }, .{ .name = "mcp-param-priority", .value = "7" } }), delete), 22);
    // The same rule applies to Mcp-Name.
    const uri = "test://\u{fc}ber";
    const read = try request(arena, 23, "resources/read", meta_none, "\"uri\":\"" ++ uri ++ "\"");
    try expectHeaderMismatch(arena, try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "resources/read" }, .{ .name = "mcp-name", .value = uri } }, read), 23);
    const read_encoded = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "resources/read" }, .{ .name = "mcp-name", .value = try encode(arena, uri) } }, read);
    try std.testing.expect(errorCode(try read_encoded.tree(arena)) != -32020);

    // A mirrored integer must be in the safe range of JavaScript.
    const largest = try request(arena, 24, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"eu\",\"priority\":9007199254740991}");
    try std.testing.expectEqual(@as(u16, 200), (try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "eu" }, .{ .name = "mcp-param-priority", .value = "9007199254740991" } }), largest)).status);
    const too_large = try request(arena, 25, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"eu\",\"priority\":9007199254740992}");
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "eu" }, .{ .name = "mcp-param-priority", .value = "9007199254740992" } }), too_large), 25);
    const too_small = try request(arena, 26, "tools/call", meta_none, "\"name\":\"test_headers\",\"arguments\":{\"region\":\"eu\",\"priority\":-9007199254740992}");
    try expectHeaderMismatch(arena, try f.post(arena, callHeaders("test_headers", &.{ .{ .name = "mcp-param-region", .value = "eu" }, .{ .name = "mcp-param-priority", .value = "-9007199254740992" } }), too_small), 26);
}

test "streamable http server answers notifications with 202 and rejects bodies it cannot accept" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // An accepted notification: 202 with no body.
    const note = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}";
    const accepted = try f.post(arena, &.{version_header}, note);
    try std.testing.expectEqual(@as(u16, 202), accepted.status);
    try std.testing.expectEqual(0, accepted.body.len);
    // A notification the server cannot accept: an HTTP error status and an error without an id.
    const malformed = try f.post(arena, &.{version_header}, "{\"jsonrpc\":\"1.0\",\"method\":\"notifications/cancelled\"}");
    try std.testing.expectEqual(@as(u16, 400), malformed.status);
    const malformed_tree = try malformed.tree(arena);
    try std.testing.expectEqual(@as(i64, -32600), errorCode(malformed_tree).?);
    try std.testing.expect(malformed_tree.object.get("id").? == .null);
    // A body must be one request or one notification: a batch and a response are rejected.
    const batch = try f.post(arena, &.{version_header}, try std.fmt.allocPrint(arena, "[{s}]", .{note}));
    try std.testing.expectEqual(@as(u16, 400), batch.status);
    const response = try f.post(arena, &.{version_header}, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    try std.testing.expectEqual(@as(u16, 400), response.status);
    try std.testing.expectEqual(@as(i64, -32600), errorCode(try response.tree(arena)).?);
    // A body that is not UTF-8 is a parse error.
    const not_utf8 = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "server/discover" } }, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"server/discover\",\"params\":{\"x\":\"\xff\xfe\"}}");
    try std.testing.expectEqual(@as(u16, 400), not_utf8.status);
    try std.testing.expectEqual(@as(i64, -32700), errorCode(try not_utf8.tree(arena)).?);
}

test "streamable http server rejects a foreign Origin with 403 and an error that has no id" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const discover = try request(arena, 10, "server/discover", meta_none, "");
    const disc_headers = [_]http.Header{ version_header, .{ .name = "mcp-method", .value = "server/discover" } };

    const foreign = try f.post(arena, &(disc_headers ++ [_]http.Header{.{ .name = "origin", .value = "http://evil.example" }}), discover);
    try std.testing.expectEqual(@as(u16, 403), foreign.status);
    const tree = try foreign.tree(arena);
    try std.testing.expect(errorCode(tree) != null);
    try std.testing.expect(tree.object.get("id").? == .null);
    // A notification with a foreign Origin is refused too.
    const note = try f.post(arena, &.{ version_header, .{ .name = "origin", .value = "http://evil.example" } }, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}");
    try std.testing.expectEqual(@as(u16, 403), note.status);
    // A loopback Origin is accepted.
    const local = try f.post(arena, &(disc_headers ++ [_]http.Header{.{ .name = "origin", .value = "http://localhost:6274" }}), discover);
    try std.testing.expectEqual(@as(u16, 200), local.status);
    // The default bind address is the loopback interface.
    const defaults: mcp.transport.http.Options = .{};
    try std.testing.expectEqualStrings("127.0.0.1", defaults.address);
}

test "streamable http server answers with JSON or with an SSE stream that the response ends" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "server/discover" } }, try request(arena, 11, "server/discover", meta_none, ""));
    try std.testing.expectEqual(@as(u16, 200), disc.status);
    try std.testing.expect(std.mem.startsWith(u8, disc.header("content-type").?, "application/json"));
    _ = try disc.tree(arena);

    // With a progress token the reply is an SSE stream: progress first, then the response.
    const sum = try f.post(arena, callHeaders("add", &.{}), try request(arena, 12, "tools/call", meta_progress, "\"name\":\"add\",\"arguments\":{\"a\":2,\"b\":3}"));
    try std.testing.expectEqual(@as(u16, 200), sum.status);
    try std.testing.expect(std.mem.startsWith(u8, sum.header("content-type").?, "text/event-stream"));
    try std.testing.expectEqualStrings("no", sum.header("x-accel-buffering").?);
    var parser: mcp.transport.sse.Parser = .init(gpa);
    defer parser.deinit();
    try parser.feed(sum.body);
    var kinds: std.ArrayList(u8) = .empty;
    while (parser.next()) |e| {
        defer parser.release(e);
        const msg = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, e.data));
        switch (msg) {
            .notification => |n| {
                try std.testing.expectEqualStrings("notifications/progress", n.method);
                try std.testing.expectEqualStrings("tick", n.params.?.object.get("progressToken").?.string);
                try kinds.append(arena, 'n');
            },
            .response => |r| {
                try std.testing.expectEqual(@as(i64, 12), r.id.integer);
                try kinds.append(arena, 'r');
            },
            else => return error.TestUnexpectedResult,
        }
    }
    // The stream ended with the response: nothing follows it.
    try std.testing.expectEqualStrings("nr", kinds.items);
}

test "streamable http server answers legacy traffic without sessions" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const get = try f.send(arena, "GET", &.{.{ .name = "accept", .value = "text/event-stream" }}, "");
    try std.testing.expectEqual(@as(u16, 405), get.status);
    const delete = try f.send(arena, "DELETE", &.{.{ .name = "mcp-session-id", .value = "abc" }}, "");
    try std.testing.expectEqual(@as(u16, 405), delete.status);
    // A session id and a Last-Event-ID are ignored, and no session id comes back.
    const disc = try f.post(arena, &.{
        version_header,
        .{ .name = "mcp-method", .value = "server/discover" },
        .{ .name = "mcp-session-id", .value = "abc" },
        .{ .name = "last-event-id", .value = "42" },
    }, try request(arena, 13, "server/discover", meta_none, ""));
    try std.testing.expectEqual(@as(u16, 200), disc.status);
    try std.testing.expect(disc.header("mcp-session-id") == null);
    try std.testing.expect((try disc.tree(arena)).object.get("result") != null);
}

test "streamable http server treats a closed SSE stream as the cancellation of the request" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    saw_cancel.store(false, .release);

    {
        const conn = try http1.Connection.open(io, gpa, "127.0.0.1", f.transport.bound_port, null);
        defer conn.close();
        const body = try request(arena, 14, "tools/call", meta_progress, "\"name\":\"ticker\"");
        try conn.send("POST", "/mcp", f.host, &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "accept", .value = "application/json, text/event-stream" },
            version_header,
            .{ .name = "mcp-method", .value = "tools/call" },
            .{ .name = "mcp-name", .value = "ticker" },
        }, body);
        const response = try conn.receiveHead();
        try std.testing.expectEqual(http.Status.ok, response.head.status);
        // Read the first event, then close the stream.
        var first: [16]u8 = undefined;
        try conn.bodyReader(&response).readSliceAll(&first);
    }
    var spins: usize = 0;
    while (!saw_cancel.load(.acquire) and spins < 300) : (spins += 1) try io.sleep(.fromMilliseconds(10), .awake);
    try std.testing.expect(saw_cancel.load(.acquire));
    // The server still serves new requests.
    const disc = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "server/discover" } }, try request(arena, 15, "server/discover", meta_none, ""));
    try std.testing.expectEqual(@as(u16, 200), disc.status);
}

fn waitFlag(flag: *const std.atomic.Value(bool)) !void {
    var spins: usize = 0;
    while (!flag.load(.acquire)) : (spins += 1) {
        if (spins > 500) return error.TestTimeout;
        try std.testing.io.sleep(.fromMilliseconds(10), .awake);
    }
}

test "streamable http server cancels a handler that only polls when the client disconnects" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    poll_started.store(false, .release);
    poll_cancelled.store(false, .release);

    {
        // Without a progress token the handler writes nothing before its response.
        const conn = try http1.Connection.open(io, gpa, "127.0.0.1", f.transport.bound_port, null);
        defer conn.close();
        const body = try request(arena, 21, "tools/call", meta_none, "\"name\":\"poll_cancel\"");
        try conn.send("POST", "/mcp", f.host, &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "accept", .value = "application/json, text/event-stream" },
            version_header,
            .{ .name = "mcp-method", .value = "tools/call" },
            .{ .name = "mcp-name", .value = "poll_cancel" },
        }, body);
        try waitFlag(&poll_started);
    }
    // The connection is closed. The server cancels the request at once, not at a write.
    try waitFlag(&poll_cancelled);
    const disc = try f.post(arena, &.{ version_header, .{ .name = "mcp-method", .value = "server/discover" } }, try request(arena, 22, "server/discover", meta_none, ""));
    try std.testing.expectEqual(@as(u16, 200), disc.status);
}

test "streamable http server ends an idle listen stream when the client disconnects" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        const conn = try http1.Connection.open(io, gpa, "127.0.0.1", f.transport.bound_port, null);
        defer conn.close();
        const body = try request(arena, 23, "subscriptions/listen", meta_none, "\"notifications\":{\"toolsListChanged\":true}");
        try conn.send("POST", "/mcp", f.host, &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "accept", .value = "application/json, text/event-stream" },
            version_header,
            .{ .name = "mcp-method", .value = "subscriptions/listen" },
        }, body);
        const response = try conn.receiveHead();
        try std.testing.expectEqual(http.Status.ok, response.head.status);
        // The acknowledgement is on the stream. After it the stream is idle.
        var first: [16]u8 = undefined;
        try conn.bodyReader(&response).readSliceAll(&first);
        f.server.subscriptions_lock.lockUncancelable(io);
        const open = f.server.subscriptions.items.len;
        f.server.subscriptions_lock.unlock(io);
        try std.testing.expectEqual(1, open);
    }
    // No event and no keepalive comes before the check: only the disconnect ends the stream.
    var spins: usize = 0;
    while (true) : (spins += 1) {
        f.server.subscriptions_lock.lockUncancelable(io);
        const open = f.server.subscriptions.items.len;
        f.server.subscriptions_lock.unlock(io);
        if (open == 0) break;
        if (spins > 500) return error.TestTimeout;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

// -- Streamable HTTP client --------------------------------------------------------------------

/// One HTTP request as the capture server received it.
const Captured = struct {
    method: []const u8,
    target: []const u8,
    headers: []const http.Header,
    body: []const u8,

    fn header(self: Captured, name: []const u8) ?[]const u8 {
        for (self.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    fn paramHeaderCount(self: Captured) usize {
        var n: usize = 0;
        for (self.headers) |h| {
            if (h.name.len >= 10 and std.ascii.eqlIgnoreCase(h.name[0..10], "mcp-param-")) n += 1;
        }
        return n;
    }
};

const capture_tools =
    \\{"tools":[
    \\{"name":"hdr","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"count":{"type":"integer","x-mcp-header":"Count"},"flag":{"type":"boolean","x-mcp-header":"Flag"},"note":{"type":"string","x-mcp-header":"Note"},"query":{"type":"string"}}}},
    \\{"name":"bad_empty","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":""}}}},
    \\{"name":"bad_number","inputSchema":{"type":"object","properties":{"v":{"type":"number","x-mcp-header":"V"}}}},
    \\{"name":"ask","inputSchema":{"type":"object"}}
    \\],"resultType":"complete"}
;

/// A plain HTTP server that records every request and answers like an MCP server. It
/// accepts one request per connection.
const Capture = struct {
    arena_state: std.heap.ArenaAllocator,
    listener: Io.net.Server,
    stopping: std.atomic.Value(bool) = .init(false),
    port: u16,
    connections: usize = 0,
    requests: std.ArrayList(Captured) = .empty,
    future: Io.Future(void),
    /// With `refresh`, the tool schemas change after the first `tools/list` and tool calls
    /// without the `Mcp-Param-Region` header get a `-32020` error.
    mode: enum { fixed, refresh } = .fixed,
    lists: usize = 0,

    fn start(self: *Capture) !void {
        const io = std.testing.io;
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.* = .{ .arena_state = .init(std.testing.allocator), .listener = try address.listen(io, .{}), .port = 0, .future = undefined };
        self.port = self.listener.socket.address.getPort();
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    fn stop(self: *Capture) void {
        const io = std.testing.io;
        mcp.util.wake.cancelAcceptLoop(io, &self.future, self.listener.socket.address, &self.stopping);
        self.listener.deinit(io);
        self.arena_state.deinit();
    }

    fn acceptLoop(self: *Capture) void {
        const io = std.testing.io;
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(io) catch return;
            defer stream.close(io);
            if (self.stopping.load(.acquire)) return;
            self.connections += 1;
            self.serveOne(stream) catch {};
        }
    }

    fn serveOne(self: *Capture, stream: Io.net.Stream) !void {
        const io = std.testing.io;
        const arena = self.arena_state.allocator();
        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [16 * 1024]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        var writer = stream.writer(io, &write_buf);
        var server: http.Server = .init(&reader.interface, &writer.interface);
        var req = try server.receiveHead();
        var headers: std.ArrayList(http.Header) = .empty;
        var it = req.iterateHeaders();
        while (it.next()) |h| try headers.append(arena, .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) });
        const method = try arena.dupe(u8, @tagName(req.head.method));
        const target = try arena.dupe(u8, req.head.target);
        if (req.head.transfer_encoding == .none and req.head.content_length == null) req.head.content_length = 0;
        var body_buf: [4096]u8 = undefined;
        const body = try req.readerExpectNone(&body_buf).allocRemaining(arena, .limited(1 << 20));
        try self.requests.append(arena, .{ .method = method, .target = target, .headers = headers.items, .body = body });
        const reply = try self.replyFor(arena, body, headers.items);
        // The header name is in upper case: the client must match it without regard to case.
        try req.respond(reply.body, .{ .status = reply.status, .keep_alive = false, .extra_headers = &.{.{ .name = "CONTENT-TYPE", .value = "application/json" }} });
    }

    const Reply = struct { status: http.Status = .ok, body: []const u8 };

    fn replyFor(self: *Capture, arena: std.mem.Allocator, body: []const u8, headers: []const http.Header) !Reply {
        const tree = try json.parseTree(arena, body);
        const id = tree.object.get("id").?.integer;
        const method = json.getString(tree, "method").?;
        const params = tree.object.get("params").?;
        if (self.mode == .refresh) {
            if (std.mem.eql(u8, method, "tools/list")) {
                self.lists += 1;
                const tools = if (self.lists == 1) refresh_tools_before else refresh_tools_after;
                return .{ .body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{s}}}", .{ id, tools }) };
            }
            if (std.mem.eql(u8, method, "tools/call")) {
                var mirrored = false;
                for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "mcp-param-region")) {
                    mirrored = true;
                };
                if (!mirrored or std.mem.eql(u8, json.getString(params, "name").?, "never")) {
                    return .{ .status = .bad_request, .body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"error\":{{\"code\":-32020,\"message\":\"Header mismatch: the Mcp-Param-Region header is missing\"}}}}", .{id}) };
                }
            }
        }
        const result: []const u8 = if (std.mem.eql(u8, method, "server/discover"))
            "{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{\"tools\":{},\"resources\":{}}}"
        else if (std.mem.eql(u8, method, "tools/list"))
            capture_tools
        else if (std.mem.eql(u8, method, "resources/read"))
            "{\"resultType\":\"complete\",\"contents\":[{\"uri\":\"file:///x\",\"text\":\"x\"}]}"
        else if (std.mem.eql(u8, json.getString(params, "name") orelse "", "ask") and params.object.get("inputResponses") == null)
            "{\"resultType\":\"input_required\",\"inputRequests\":{\"user_name\":{\"method\":\"elicitation/create\",\"params\":{\"mode\":\"form\",\"message\":\"Name?\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}}}}}}}"
        else
            "{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}";
        return .{ .body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{s}}}", .{ id, result }) };
    }
};

const refresh_tools_before =
    \\{"resultType":"complete","tools":[
    \\{"name":"late","inputSchema":{"type":"object","properties":{"target":{"type":"object","properties":{"region":{"type":"string"}}}}}},
    \\{"name":"never","inputSchema":{"type":"object"}}]}
;

const refresh_tools_after =
    \\{"resultType":"complete","tools":[
    \\{"name":"late","inputSchema":{"type":"object","properties":{"target":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}}}},
    \\{"name":"never","inputSchema":{"type":"object"}}]}
;

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Bob\"}") };
}

/// The base64 sentinel form of `value`, computed without the SDK.
fn sentinel(arena: std.mem.Allocator, value: []const u8) ![]const u8 {
    const encoder = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, encoder.calcSize(value.len));
    return std.mem.concat(arena, u8, &.{ "=?base64?", encoder.encode(out, value), "?=" });
}

test "streamable http client sends every message as a new POST with Accept and the metadata headers" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var capture: Capture = undefined;
    try capture.start();
    defer capture.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/mcp", .{capture.port});
    const transport = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url });
    defer transport.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "g2", .version = "1" }, .capabilities = .{ .elicitation = .{} }, .hooks = .{ .elicit_form = answerForm } });
    defer client.deinit();
    client.connect(transport.transport());

    _ = try client.discover(arena, .{});
    _ = try client.readResource(arena, "file:///x", .{});
    // The server asks for input: the client answers with a new request, never with a response.
    const hello = try client.callTool(arena, "ask", null, .{});
    try std.testing.expectEqualStrings("ok", hello.content[0].text.text);

    try std.testing.expectEqual(4, capture.requests.items.len);
    // One connection per message.
    try std.testing.expectEqual(4, capture.connections);
    var ids: [4]i64 = undefined;
    for (capture.requests.items, 0..) |r, i| {
        try std.testing.expectEqualStrings("POST", r.method);
        try std.testing.expectEqualStrings("/mcp", r.target);
        const accept = r.header("accept").?;
        try std.testing.expect(std.mem.indexOf(u8, accept, "application/json") != null);
        try std.testing.expect(std.mem.indexOf(u8, accept, "text/event-stream") != null);
        // The body is one JSON-RPC request.
        const msg = try mcp.jsonrpc.Message.parse(arena, r.body);
        try std.testing.expect(msg == .request);
        ids[i] = msg.request.id.integer;
        // The mirrored headers equal the body.
        const version = r.header("mcp-protocol-version").?;
        try std.testing.expectEqualStrings("2026-07-28", version);
        const meta = msg.request.params.?.object.get("_meta").?;
        try std.testing.expectEqualStrings(version, json.getString(meta, "io.modelcontextprotocol/protocolVersion").?);
        try std.testing.expectEqualStrings(msg.request.method, r.header("mcp-method").?);
    }
    try std.testing.expectEqualStrings("file:///x", capture.requests.items[1].header("mcp-name").?);
    try std.testing.expectEqualStrings("ask", capture.requests.items[2].header("mcp-name").?);
    // The retry is a new request with a new id and the answers.
    try std.testing.expect(ids[2] != ids[3]);
    const retry = try json.parseTree(arena, capture.requests.items[3].body);
    try std.testing.expect(retry.object.get("params").?.object.get("inputResponses") != null);
}

test "streamable http client mirrors x-mcp-header parameters with the value encoding" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var capture: Capture = undefined;
    try capture.start();
    defer capture.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/mcp", .{capture.port});
    const transport = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url });
    defer transport.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "g2", .version = "1" } });
    defer client.deinit();
    client.connect(transport.transport());

    // The log messages for the removed tools are expected here.
    const level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = level;
    // Tools with invalid annotations are not in the list.
    const tools = try client.listTools(arena, null, .{});
    try std.testing.expectEqual(2, tools.tools.len);
    try std.testing.expectEqualStrings("hdr", tools.tools[0].name);
    try std.testing.expectEqualStrings("ask", tools.tools[1].name);

    _ = try client.callTool(arena, "hdr", try json.parseTree(arena, "{\"region\":\"us-west1\",\"count\":42,\"flag\":true,\"note\":\"Gr\u{fc}\u{df}e\",\"query\":\"q\"}"), .{});
    _ = try client.callTool(arena, "hdr", try json.parseTree(arena, "{\"region\":null,\"note\":\"=?base64?abc?=\"}"), .{});
    _ = try client.callTool(arena, "hdr", try json.parseTree(arena, "{\"region\":\" padded \",\"note\":\"line1\\nline2\",\"count\":-7,\"flag\":false}"), .{});
    const uri = "file:///tmp/\u{fc}ber.txt";
    _ = try client.readResource(arena, uri, .{});

    const reqs = capture.requests.items;
    try std.testing.expectEqual(5, reqs.len);
    // Plain values travel as they are, integers in decimal and booleans in lower case.
    const first = reqs[1];
    try std.testing.expectEqualStrings("tools/call", first.header("mcp-method").?);
    try std.testing.expectEqualStrings("hdr", first.header("mcp-name").?);
    try std.testing.expectEqualStrings("us-west1", first.header("mcp-param-region").?);
    try std.testing.expectEqualStrings("42", first.header("mcp-param-count").?);
    try std.testing.expectEqualStrings("true", first.header("mcp-param-flag").?);
    // Non-ASCII text uses the base64 sentinel with lower-case markers.
    try std.testing.expectEqualStrings(try sentinel(arena, "Gr\u{fc}\u{df}e"), first.header("mcp-param-note").?);
    // A parameter without an annotation is not mirrored.
    try std.testing.expectEqual(4, first.paramHeaderCount());
    // A null value and an absent value have no header. A plain value in the sentinel shape is encoded.
    const second = reqs[2];
    try std.testing.expect(second.header("mcp-param-region") == null);
    try std.testing.expect(second.header("mcp-param-count") == null);
    try std.testing.expect(second.header("mcp-param-flag") == null);
    try std.testing.expectEqualStrings(try sentinel(arena, "=?base64?abc?="), second.header("mcp-param-note").?);
    try std.testing.expectEqual(1, second.paramHeaderCount());
    // Leading or trailing spaces and control characters need the sentinel.
    const third = reqs[3];
    try std.testing.expectEqualStrings(try sentinel(arena, " padded "), third.header("mcp-param-region").?);
    try std.testing.expectEqualStrings(try sentinel(arena, "line1\nline2"), third.header("mcp-param-note").?);
    try std.testing.expectEqualStrings("-7", third.header("mcp-param-count").?);
    try std.testing.expectEqualStrings("false", third.header("mcp-param-flag").?);
    // Mcp-Name uses the same encoding for a URI that is not plain ASCII.
    try std.testing.expectEqualStrings("resources/read", reqs[4].header("mcp-method").?);
    try std.testing.expectEqualStrings(try sentinel(arena, uri), reqs[4].header("mcp-name").?);
}

test "streamable http client refuses to mirror an integer outside the safe range" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var capture: Capture = undefined;
    try capture.start();
    defer capture.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/mcp", .{capture.port});
    const transport = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url });
    defer transport.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "g2", .version = "1" } });
    defer client.deinit();
    client.connect(transport.transport());
    const level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = level;
    _ = try client.listTools(arena, null, .{});

    // The client does not send the call.
    try std.testing.expectError(error.InvalidRequest, client.callTool(arena, "hdr", try json.parseTree(arena, "{\"count\":9007199254740992}"), .{}));
    try std.testing.expectError(error.InvalidRequest, client.callTool(arena, "hdr", try json.parseTree(arena, "{\"count\":-9007199254740992}"), .{}));
    try std.testing.expectEqual(1, capture.requests.items.len);
    _ = try client.callTool(arena, "hdr", try json.parseTree(arena, "{\"count\":-9007199254740991}"), .{});
    try std.testing.expectEqual(2, capture.requests.items.len);
    try std.testing.expectEqualStrings("-9007199254740991", capture.requests.items[1].header("mcp-param-count").?);
}

test "streamable http client refreshes tools/list and retries once after a header mismatch" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var capture: Capture = undefined;
    try capture.start();
    defer capture.stop();
    capture.mode = .refresh;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/mcp", .{capture.port});
    const transport = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url });
    defer transport.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "g2", .version = "1" } });
    defer client.deinit();
    client.connect(transport.transport());

    // The first list has no annotation. The server then adds one to the schema of "late".
    _ = try client.listTools(arena, null, .{});
    const args = try json.parseTree(arena, "{\"target\":{\"region\":\"eu\"}}");
    const done = try client.callTool(arena, "late", args, .{});
    try std.testing.expectEqualStrings("ok", done.content[0].text.text);
    const reqs = capture.requests.items;
    try std.testing.expectEqual(4, reqs.len);
    try std.testing.expectEqualStrings("tools/call", reqs[1].header("mcp-method").?);
    try std.testing.expect(reqs[1].header("mcp-param-region") == null);
    try std.testing.expectEqualStrings("tools/list", reqs[2].header("mcp-method").?);
    // The retry is the same call with a new id and the header from the new schema.
    try std.testing.expectEqualStrings("tools/call", reqs[3].header("mcp-method").?);
    try std.testing.expectEqualStrings("eu", reqs[3].header("mcp-param-region").?);
    const first = try json.parseTree(arena, reqs[1].body);
    const retry = try json.parseTree(arena, reqs[3].body);
    try std.testing.expect(first.object.get("id").?.integer != retry.object.get("id").?.integer);

    // The client retries only one time. Then the caller gets the -32020 error.
    var diag: Client.Diagnostics = .{};
    try std.testing.expectError(error.Rpc, client.callTool(arena, "never", args, .{ .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32020), diag.rpc_error.?.code);
    try std.testing.expectEqual(7, capture.requests.items.len);
    try std.testing.expectEqualStrings("tools/call", capture.requests.items[4].header("mcp-method").?);
    try std.testing.expectEqualStrings("tools/list", capture.requests.items[5].header("mcp-method").?);
    try std.testing.expectEqualStrings("tools/call", capture.requests.items[6].header("mcp-method").?);
}

test "client header map removes tools whose x-mcp-header annotations are invalid" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var map: mcp.transport.tool_headers.Map = .init(gpa, std.testing.io);
    defer map.deinit();

    const frame =
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[
        \\{"name":"valid","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"n":{"type":"integer","x-mcp-header":"N"},"b":{"type":"boolean","x-mcp-header":"B"}}}},
        \\{"name":"empty","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":""}}}},
        \\{"name":"space","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"My Region"}}}},
        \\{"name":"colon","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region:Primary"}}}},
        \\{"name":"non_ascii","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"R\u00e9gion"}}}},
        \\{"name":"tab","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region\t1"}}}},
        \\{"name":"line_feed","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region\n1"}}}},
        \\{"name":"carriage_return","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region\r1"}}}},
        \\{"name":"same_case","inputSchema":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Region"},"b":{"type":"string","x-mcp-header":"Region"}}}},
        \\{"name":"other_case","inputSchema":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"MyField"},"b":{"type":"string","x-mcp-header":"myfield"}}}},
        \\{"name":"object","inputSchema":{"type":"object","properties":{"v":{"type":"object","x-mcp-header":"V"}}}},
        \\{"name":"array","inputSchema":{"type":"object","properties":{"v":{"type":"array","items":{"type":"string"},"x-mcp-header":"V"}}}},
        \\{"name":"null","inputSchema":{"type":"object","properties":{"v":{"type":"null","x-mcp-header":"V"}}}},
        \\{"name":"number","inputSchema":{"type":"object","properties":{"v":{"type":"number","x-mcp-header":"V"}}}},
        \\{"name":"plain","inputSchema":{"type":"object"}}
        \\]}}
    ;
    // The log messages for the removed tools are expected here.
    const level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = level;
    const rewritten = (try map.learn(arena, frame)).?;
    const tree = try json.parseTree(arena, rewritten);
    const kept = tree.object.get("result").?.object.get("tools").?.array.items;
    try std.testing.expectEqual(2, kept.len);
    try std.testing.expectEqualStrings("valid", kept[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("plain", kept[1].object.get("name").?.string);

    // The kept tool mirrors its annotated parameters.
    var headers: std.ArrayList(http.Header) = .empty;
    try map.appendParamHeaders(arena, &headers, "valid", try json.parseTree(arena, "{\"region\":\"eu\",\"n\":3,\"b\":false,\"other\":\"x\"}"), false);
    try std.testing.expectEqual(3, headers.items.len);
}

// -- stdio client ------------------------------------------------------------------------------

fn exampleServerPath() []const u8 {
    return if (builtin.os.tag == .windows) "zig-out/bin/stdio_server.exe" else "zig-out/bin/stdio_server";
}

fn elapsedMs(io: Io, start: Io.Clock.Timestamp) i64 {
    const ns = start.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    return @intCast(@divTrunc(ns, std.time.ns_per_ms));
}

/// A child that copies its standard input into the file `capture.jsonl` in its current
/// directory. It exits at the end of the input.
const capture_argv: []const []const u8 = if (builtin.os.tag == .windows)
    &.{ "cmd.exe", "/d", "/c", "findstr", "/R", ".", ">", "capture.jsonl" }
else
    &.{ "/bin/sh", "-c", "cat > capture.jsonl; exit 0" };

/// A child that ignores its standard input and runs for 30 seconds.
const stubborn_argv: []const []const u8 = if (builtin.os.tag == .windows)
    &.{ "cmd.exe", "/d", "/c", "ping", "-n", "30", "127.0.0.1", ">", "nul" }
else
    &.{ "/bin/sh", "-c", "sleep 30; exit 0" };

test "stdio client writes only requests and notifications, one per line, and cancels with a notification" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        const proc = mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = capture_argv, .cwd = .{ .dir = tmp.dir } }) catch return error.SkipZigTest;
        defer proc.deinit();
        var client: Client = .init(gpa, io, .{ .info = .{ .name = "g2", .version = "1" } });
        defer client.deinit();
        client.connect(proc.transport());

        // A request the caller cancels, and a request that times out.
        var token: mcp.transport.CancelToken = .{};
        token.cancel(io, "user");
        try std.testing.expectError(error.Canceled, client.callTool(arena, "add", .{ .a = 1, .b = 2 }, .{ .cancel = &token }));
        try std.testing.expectError(error.Timeout, client.discover(arena, .{ .timeout = .fromMilliseconds(100) }));
        // Shutdown: the client closes the input of the child and waits for it to exit.
        const start = Io.Clock.Timestamp.now(io, .awake);
        proc.close();
        try std.testing.expect(elapsedMs(io, start) < 2000);
    }

    const data = try tmp.dir.readFileAlloc(io, "capture.jsonl", arena, .limited(1 << 20));
    var lines: std.ArrayList(mcp.jsonrpc.Message) = .empty;
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        try lines.append(arena, try mcp.jsonrpc.Message.parse(arena, line));
    }
    try std.testing.expectEqual(4, lines.items.len);
    const kinds = [_]std.meta.Tag(mcp.jsonrpc.Message){ .request, .notification, .request, .notification };
    for (lines.items, kinds) |m, k| try std.testing.expectEqual(k, std.meta.activeTag(m));
    // Each cancellation names the request before it.
    for ([_]usize{ 0, 2 }) |i| {
        const req = lines.items[i].request;
        const note = lines.items[i + 1].notification;
        try std.testing.expectEqualStrings("notifications/cancelled", note.method);
        const params = note.params.?;
        try std.testing.expectEqual(req.id.integer, params.object.get("requestId").?.integer);
    }
    try std.testing.expectEqualStrings("tools/call", lines.items[0].request.method);
    try std.testing.expectEqualStrings("user", lines.items[1].notification.params.?.object.get("reason").?.string);
    try std.testing.expectEqualStrings("server/discover", lines.items[2].request.method);
    try std.testing.expectEqualStrings("timeout", lines.items[3].notification.params.?.object.get("reason").?.string);
}

test "stdio client close lets the server exit at the end of its input" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    Io.Dir.cwd().access(io, exampleServerPath(), .{}) catch return error.SkipZigTest;
    var limits: mcp.Limits = .{};
    limits.shutdown_grace = .fromSeconds(20);
    const proc = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = &.{exampleServerPath()}, .limits = limits });
    defer proc.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "g2", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    _ = try client.discover(arena_state.allocator(), .{ .timeout = .fromSeconds(20) });

    // `close` signals nothing before the grace period ends. An earlier return means the
    // server exited by itself when its input closed.
    const start = Io.Clock.Timestamp.now(io, .awake);
    proc.close();
    try std.testing.expect(elapsedMs(io, start) < 20_000);
}

test "stdio client terminates a server that does not exit after its input closed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var limits: mcp.Limits = .{};
    limits.shutdown_grace = .fromMilliseconds(100);
    const proc = mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = stubborn_argv, .limits = limits }) catch return error.SkipZigTest;
    defer proc.deinit();
    const start = Io.Clock.Timestamp.now(io, .awake);
    proc.close();
    const ms = elapsedMs(io, start);
    // The client waited for the grace period, then ended the process long before it would exit.
    try std.testing.expect(ms >= 100);
    try std.testing.expect(ms < 10_000);
}

const ListenRecorder = struct {
    acked: std.atomic.Value(bool) = .init(false),
    subscription_id: std.atomic.Value(i64) = .init(-1),
    unrouted: std.atomic.Value(u32) = .init(0),

    fn onListen(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *ListenRecorder = @ptrCast(@alignCast(userdata.?));
        if (!std.mem.eql(u8, method, "notifications/subscriptions/acknowledged")) return;
        const p = params orelse return;
        const m = p.object.get("_meta") orelse return;
        const sid = m.object.get("io.modelcontextprotocol/subscriptionId") orelse return;
        if (sid == .integer) self.subscription_id.store(sid.integer, .release);
        self.acked.store(true, .release);
    }

    fn onUnrouted(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        _ = method;
        _ = params;
        const self: *ListenRecorder = @ptrCast(@alignCast(userdata.?));
        _ = self.unrouted.fetchAdd(1, .monotonic);
    }
};

const ListenJob = struct {
    client: *Client,
    recorder: *ListenRecorder,
    token: mcp.transport.CancelToken = .{},
    result: anyerror!void = {},

    fn run(job: *ListenJob) void {
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const params = json.parseTree(arena, "{\"notifications\":{\"toolsListChanged\":true}}") catch |e| {
            job.result = e;
            return;
        };
        _ = job.client.requestAs(arena, types.SubscriptionsListenResult, "subscriptions/listen", params, .{
            .cancel = &job.token,
            .on_notification = ListenRecorder.onListen,
            .userdata = job.recorder,
        }) catch |e| {
            job.result = e;
            return;
        };
    }
};

test "stdio client routes listen notifications to their request by the subscription id" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    Io.Dir.cwd().access(io, exampleServerPath(), .{}) catch return error.SkipZigTest;
    var recorder: ListenRecorder = .{};
    const proc = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = &.{exampleServerPath()}, .on_notification = ListenRecorder.onUnrouted, .userdata = &recorder });
    defer proc.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "g2", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());

    var job: ListenJob = .{ .client = &client, .recorder = &recorder };
    var future = try io.concurrent(ListenJob.run, .{&job});
    var spins: usize = 0;
    while (!recorder.acked.load(.acquire) and spins < 1000) : (spins += 1) try io.sleep(.fromMilliseconds(10), .awake);
    const acked = recorder.acked.load(.acquire);
    job.token.cancel(io, "done");
    future.await(io);
    try std.testing.expect(acked);
    // The acknowledgement reached the listen request, not the catch-all handler.
    try std.testing.expectEqual(@as(i64, 1), recorder.subscription_id.load(.acquire));
    try std.testing.expectEqual(0, recorder.unrouted.load(.monotonic));
    try std.testing.expectError(error.Canceled, job.result);
}
