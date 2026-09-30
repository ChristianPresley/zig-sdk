//! Tests for the base protocol page, the version page and the discovery page of the specification.
//! They check the message rules, the per-request metadata and the version negotiation.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const mcp = @import("../../mcp.zig");
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const types = mcp.types;
const json = mcp.json;
const Harness = mcp.transport.memory.Harness;
const Transport = mcp.transport.Transport;
const errors = mcp.protocol.errors;
const meta = mcp.protocol.meta;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;
const meta_all =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{"sampling":{},"elicitation":{},"roots":{}}}
;

// -- Server fixtures ----------------------------------------------------------------------------

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(1, 2, "adding");
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

fn plain(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "ok", .{}) };
}

fn askName(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content orelse .null, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn readStatic(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "static text" } };
    return .{ .complete = .{ .contents = contents } };
}

fn getPrompt(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    _ = args;
    const messages = try ctx.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = "hi" } } };
    return .{ .complete = .{ .messages = messages } };
}

fn complete(ctx: *RequestContext, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion {
    _ = params;
    const values = try ctx.arena.alloc([]const u8, 1);
    values[0] = "alpha";
    return .{ .values = values };
}

fn registerAll(server: *Server) !void {
    try server.addTool(.{ .name = "add" }, add);
    try server.addToolJson(.{ .name = "needs_sampling", .requires_client = .{ .sampling = .{} } }, plain);
    try server.addToolJson(.{ .name = "ask_name" }, askName);
    try server.addResource(.{ .uri = "test://static", .name = "static" }, readStatic);
    try server.addPrompt(.{ .name = "greet" }, getPrompt);
    server.setCompletionHandler(complete);
}

const Fixture = struct {
    server: Server,
    harness: Harness,
    arena_state: std.heap.ArenaAllocator,

    fn init(self: *Fixture) !void {
        const gpa = std.testing.allocator;
        self.arena_state = .init(gpa);
        self.server = try Server.init(gpa, std.testing.io, .{ .info = .{ .name = "g1", .version = "1.2.3" } });
        try registerAll(&self.server);
        self.harness = .init(std.testing.io, gpa, &self.server);
    }

    fn deinit(self: *Fixture) void {
        self.harness.deinit();
        self.server.deinit();
        self.arena_state.deinit();
    }

    fn arena(self: *Fixture) Allocator {
        return self.arena_state.allocator();
    }

    /// Send one raw frame and return the parsed last output frame.
    fn raw(self: *Fixture, frame: []const u8) !Value {
        self.harness.clear();
        try self.harness.send(frame);
        try std.testing.expect(self.harness.finished);
        return json.parseTree(self.arena(), self.harness.last().?);
    }

    /// Send a request with an integer id.
    fn call(self: *Fixture, id: i64, method: []const u8, meta_text: []const u8, extra: []const u8) !Value {
        const sep: []const u8 = if (extra.len > 0) "," else "";
        const frame = try std.fmt.allocPrint(self.arena(), "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta_text, sep, extra });
        return self.raw(frame);
    }
};

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

// -- Messages -----------------------------------------------------------------------------------

test "a result response echoes a string or an integer request id" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();

    const by_string = try f.raw("{\"jsonrpc\":\"2.0\",\"id\":\"req-abc\",\"method\":\"tools/list\",\"params\":{" ++ meta_none ++ "}}");
    try std.testing.expectEqualStrings("req-abc", by_string.object.get("id").?.string);
    try std.testing.expect(by_string.object.get("result") != null);

    const by_int = try f.call(4242, "server/discover", meta_none, "");
    try std.testing.expectEqual(@as(i64, 4242), by_int.object.get("id").?.integer);
    try std.testing.expect(by_int.object.get("result") != null);
}

/// The methods and params that the fixture server answers with a result.
const result_calls = [_]struct { method: []const u8, extra: []const u8, result_type: []const u8 }{
    .{ .method = "server/discover", .extra = "", .result_type = "complete" },
    .{ .method = "tools/list", .extra = "", .result_type = "complete" },
    .{ .method = "tools/call", .extra = "\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}", .result_type = "complete" },
    .{ .method = "tools/call", .extra = "\"name\":\"ask_name\",\"arguments\":{}", .result_type = "input_required" },
    .{ .method = "resources/list", .extra = "", .result_type = "complete" },
    .{ .method = "resources/templates/list", .extra = "", .result_type = "complete" },
    .{ .method = "resources/read", .extra = "\"uri\":\"test://static\"", .result_type = "complete" },
    .{ .method = "prompts/list", .extra = "", .result_type = "complete" },
    .{ .method = "prompts/get", .extra = "\"name\":\"greet\"", .result_type = "complete" },
    .{ .method = "completion/complete", .extra = "\"ref\":{\"type\":\"ref/prompt\",\"name\":\"greet\"},\"argument\":{\"name\":\"x\",\"value\":\"a\"}", .result_type = "complete" },
};

test "every result of the server is a JSON-RPC 2.0 result object with a resultType" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    for (result_calls, 0..) |c, i| {
        const v = try f.call(@intCast(i + 1), c.method, meta_all, c.extra);
        try std.testing.expectEqualStrings("2.0", v.object.get("jsonrpc").?.string);
        try std.testing.expect(v.object.get("error") == null);
        const r = v.object.get("result").?;
        try std.testing.expect(r == .object);
        try std.testing.expectEqualStrings(c.result_type, r.object.get("resultType").?.string);
    }
}

test "every result of the server names the server in _meta" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    for (result_calls, 0..) |c, i| {
        const v = try f.call(@intCast(i + 1), c.method, meta_all, c.extra);
        const info = v.object.get("result").?.object.get("_meta").?.object.get(meta.key_server_info).?;
        try std.testing.expectEqualStrings("g1", info.object.get("name").?.string);
        try std.testing.expectEqualStrings("1.2.3", info.object.get("version").?.string);
    }
}

test "error responses echo the id and carry an integer code and a string message" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();

    const unknown = try f.raw("{\"jsonrpc\":\"2.0\",\"id\":\"e-1\",\"method\":\"unknown/method\",\"params\":{" ++ meta_none ++ "}}");
    try std.testing.expectEqualStrings("2.0", unknown.object.get("jsonrpc").?.string);
    try std.testing.expectEqualStrings("e-1", unknown.object.get("id").?.string);
    try std.testing.expect(unknown.object.get("result") == null);
    const e = unknown.object.get("error").?;
    try std.testing.expect(e.object.get("code").? == .integer);
    try std.testing.expectEqual(@as(i64, -32601), e.object.get("code").?.integer);
    try std.testing.expect(e.object.get("message").? == .string);
    try std.testing.expect(e.object.get("message").?.string.len > 0);

    const invalid = try f.call(77, "tools/call", meta_none, "\"name\":\"nope\"");
    try std.testing.expectEqual(@as(i64, 77), invalid.object.get("id").?.integer);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(invalid).?);

    // The parser accepts only an integer code and a string message.
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Message = mcp.jsonrpc.Message;
    try std.testing.expectError(error.Invalid, Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1.5,\"message\":\"x\"}}"));
    try std.testing.expectError(error.Invalid, Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":\"-32600\",\"message\":\"x\"}}"));
    try std.testing.expectError(error.Invalid, Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600}}"));
}

test "notifications from the server carry no id" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const meta_progress =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":"p1"}
    ;
    _ = try f.call(1, "tools/call", meta_progress, "\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}");
    try std.testing.expectEqual(2, f.harness.out.items.len);
    const note = try json.parseTree(f.arena(), f.harness.out.items[0]);
    try std.testing.expectEqualStrings("notifications/progress", note.object.get("method").?.string);
    try std.testing.expect(note.object.get("id") == null);
}

test "the server sends no response to a notification" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    f.harness.clear();
    try f.harness.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}");
    try f.harness.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}");
    try std.testing.expectEqual(0, f.harness.out.items.len);
    try std.testing.expect(!f.harness.finished);
}

test "no error code of the SDK is in the legacy sub-range" {
    inline for (@typeInfo(errors.Code).@"enum".fields) |field| {
        const code: i64 = field.value;
        try std.testing.expect(!(code <= -32000 and code >= -32019));
        try std.testing.expect(errors.Code.isEmittable(code));
    }
}

// -- Statelessness and per-request metadata -----------------------------------------------------

test "the server takes capabilities from each request and not from the connection" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    // The first request on the link needs no handshake.
    const first = try f.call(1, "tools/call", meta_all, "\"name\":\"needs_sampling\",\"arguments\":{}");
    try std.testing.expect(errorCode(first) == null);
    // A later request without the capability is rejected, even on the same link.
    const second = try f.call(2, "tools/call", meta_none, "\"name\":\"needs_sampling\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(second).?);
    const required = second.object.get("error").?.object.get("data").?.object.get("requiredCapabilities").?;
    try std.testing.expect(required.object.get("sampling") != null);
    // A request that declares it again succeeds.
    const third = try f.call(3, "tools/call", meta_all, "\"name\":\"needs_sampling\",\"arguments\":{}");
    try std.testing.expect(errorCode(third) == null);
}

test "a request with a missing or malformed required _meta field is rejected with -32602" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const cases = [_][]const u8{
        // No protocol version.
        "\"_meta\":{\"io.modelcontextprotocol/clientCapabilities\":{}}",
        // No client capabilities.
        "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}",
        // No _meta.
        "\"cursor\":\"x\"",
        // Reserved keys with values of the wrong type.
        "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":20260728,\"io.modelcontextprotocol/clientCapabilities\":{}}",
        "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":\"all\"}",
        "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{},\"io.modelcontextprotocol/clientInfo\":\"t\"}",
        "\"_meta\":[]",
    };
    for (cases, 0..) |c, i| {
        const v = try f.call(@intCast(i + 1), "tools/list", c, "");
        try std.testing.expectEqual(@as(i64, -32602), errorCode(v).?);
        try std.testing.expectEqual(@as(i64, @intCast(i + 1)), v.object.get("id").?.integer);
    }
}

test "clientInfo does not change the response of the server" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const a = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"a\",\"version\":\"1\"},\"io.modelcontextprotocol/clientCapabilities\":{}}";
    const b = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"other-client\",\"version\":\"9.9\"},\"io.modelcontextprotocol/clientCapabilities\":{}}";
    const methods_to_check = [_]struct { method: []const u8, extra: []const u8 }{
        .{ .method = "server/discover", .extra = "" },
        .{ .method = "tools/list", .extra = "" },
        .{ .method = "tools/call", .extra = "\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}" },
    };
    for (methods_to_check) |m| {
        _ = try f.call(1, m.method, a, m.extra);
        const first = try f.arena().dupe(u8, f.harness.last().?);
        _ = try f.call(1, m.method, b, m.extra);
        try std.testing.expectEqualStrings(first, f.harness.last().?);
    }
}

// -- Versioning ---------------------------------------------------------------------------------

test "a legacy initialize request gets the supported versions" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const v = try f.raw("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"old\",\"version\":\"1\"}}}");
    const e = v.object.get("error").?;
    try std.testing.expect(std.mem.indexOf(u8, e.object.get("message").?.string, "2026-07-28") != null);
    const versions = e.object.get("data").?.object.get("supportedVersions").?.array.items;
    try std.testing.expectEqual(1, versions.len);
    try std.testing.expectEqualStrings("2026-07-28", versions[0].string);
}

test "extension identifiers follow the _meta key rules with a prefix" {
    try meta.validateKey(mcp.tasks.extension_id);
    try std.testing.expect(std.mem.indexOfScalar(u8, mcp.tasks.extension_id, '/') != null);
    try std.testing.expect(meta.isReservedPrefix(mcp.tasks.extension_id));
}

// -- _meta key names ----------------------------------------------------------------------------

test "meta key labels and names follow the grammar" {
    // Labels start with a letter and end with a letter or a digit.
    try meta.validateKey("a-b.c1/x");
    try std.testing.expectError(error.InvalidPrefix, meta.validateKey("a-/x"));
    try std.testing.expectError(error.InvalidPrefix, meta.validateKey("ab.1c/x"));
    try std.testing.expectError(error.InvalidPrefix, meta.validateKey("ab.c_d/x"));
    // Names start and end with an alphanumeric character.
    try meta.validateKey("com.example/a");
    try meta.validateKey("com.example/my-key_v.2");
    try std.testing.expectError(error.InvalidName, meta.validateKey("com.example/key-"));
    try std.testing.expectError(error.InvalidName, meta.validateKey("com.example/_key"));
    try std.testing.expectError(error.InvalidName, meta.validateKey("com.example/a b"));
}

// -- JSON Schema --------------------------------------------------------------------------------

test "tool registration checks the schema dialect and the schema" {
    const gpa = std.testing.allocator;
    var server = try Server.init(gpa, std.testing.io, .{ .info = .{ .name = "g1", .version = "1" } });
    defer server.deinit();
    // The explicit 2020-12 dialect is accepted.
    try server.addToolJson(.{ .name = "explicit", .input_schema = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":\"object\"}" }, plain);
    // Another dialect is an error that names the dialect problem.
    try std.testing.expectError(error.UnsupportedDialect, server.addToolJson(.{ .name = "draft7", .input_schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"type\":\"object\"}" }, plain));
    try std.testing.expectError(error.UnsupportedDialect, server.addToolJson(.{ .name = "draft7out", .output_schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\"}" }, plain));
    // A schema that is not valid 2020-12 is rejected.
    try std.testing.expectError(error.InvalidSchema, server.addToolJson(.{ .name = "badtype", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"int\"}}}" }, plain));
    try std.testing.expectError(error.InvalidSchema, server.addToolJson(.{ .name = "badref", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"$ref\":\"#/$defs/missing\"}}}" }, plain));
}

// -- stdio server -------------------------------------------------------------------------------

/// Run the stdio server over `input` and return every output frame, parsed.
fn runStdio(arena: Allocator, input: []const u8) ![]Value {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(gpa, io, .{ .info = .{ .name = "g1", .version = "1" } });
    defer server.deinit();
    try registerAll(&server);
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var transport: mcp.transport.stdio.Server = .init(io, gpa, &server, &out.writer);
    defer transport.deinit();
    var in: Io.Reader = .fixed(input);
    try transport.run(&in);
    var frames: std.ArrayList(Value) = .empty;
    var it = std.mem.splitScalar(u8, out.written(), '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try frames.append(arena, try json.parseTree(arena, line));
    }
    return frames.items;
}

fn frameWithId(frames: []const Value, id: Value) ?Value {
    for (frames) |fr| {
        const fid = fr.object.get("id") orelse continue;
        if (std.meta.activeTag(fid) != std.meta.activeTag(id)) continue;
        switch (id) {
            .integer => |i| if (fid.integer == i) return fr,
            .string => |s| if (std.mem.eql(u8, fid.string, s)) return fr,
            else => {},
        }
    }
    return null;
}

test "stdio server answers a parse error with -32700 and a null id" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const frames = try runStdio(arena_state.allocator(), "{not json\n");
    try std.testing.expectEqual(1, frames.len);
    try std.testing.expectEqualStrings("2.0", frames[0].object.get("jsonrpc").?.string);
    try std.testing.expect(frames[0].object.get("id").? == .null);
    try std.testing.expectEqual(@as(i64, -32700), errorCode(frames[0]).?);
}

test "stdio server rejects a request id that is null or not an integer" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const input =
        \\{"jsonrpc":"2.0","id":null,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
        \\{"jsonrpc":"2.0","id":1.5,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
        \\{"jsonrpc":"2.0","id":true,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
        \\
    ;
    const frames = try runStdio(arena_state.allocator(), input);
    try std.testing.expectEqual(3, frames.len);
    for (frames) |fr| {
        try std.testing.expectEqual(@as(i64, -32600), errorCode(fr).?);
        try std.testing.expect(fr.object.get("id").? == .null);
        try std.testing.expect(fr.object.get("result") == null);
    }
}

test "stdio server echoes each request id and sends nothing for notifications" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const input =
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}
        \\{"jsonrpc":"2.0","id":"s-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
        \\{"jsonrpc":"2.0","id":7,"method":"unknown/x","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
        \\
    ;
    // A valid JSON line that is not a JSON-RPC message (for example {"jsonrpc":"2.0","id":8})
    // is not in this input: stdio.Server.run frees the line before recoverId reads it.
    const frames = try runStdio(arena_state.allocator(), input);
    // Two requests, two responses. The notifications get none.
    try std.testing.expectEqual(2, frames.len);
    const ok = frameWithId(frames, .{ .string = "s-1" }).?;
    try std.testing.expectEqualStrings("complete", ok.object.get("result").?.object.get("resultType").?.string);
    const unknown = frameWithId(frames, .{ .integer = 7 }).?;
    try std.testing.expectEqual(@as(i64, -32601), errorCode(unknown).?);
}

// -- Streamable HTTP server ---------------------------------------------------------------------

const HttpFixture = struct {
    server: Server,
    transport: mcp.transport.http.Server,
    future: Io.Future(void),
    client: http.Client,
    base: []u8,

    fn start(self: *HttpFixture) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try Server.init(gpa, io, .{ .info = .{ .name = "g1-http", .version = "1" } });
        try self.server.addToolJson(.{ .name = "needs_sampling", .requires_client = .{ .sampling = .{} } }, plain);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .response_mode = .auto });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        self.client = .{ .allocator = gpa, .io = io };
        self.base = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/mcp", .{self.transport.bound_port});
    }

    fn serveIgnoringErrors(t: *mcp.transport.http.Server) void {
        t.serve() catch {};
    }

    fn stop(self: *HttpFixture) void {
        const io = std.testing.io;
        self.client.deinit();
        self.transport.shutdown();
        self.future.await(io);
        self.transport.deinit();
        self.server.deinit();
        std.testing.allocator.free(self.base);
    }

    const Reply = struct { status: http.Status, body: []u8 };

    fn post(self: *HttpFixture, gpa: Allocator, body: []const u8, extra: []const http.Header) !Reply {
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

test "http server answers a missing client capability with 400 and -32021" {
    const gpa = std.testing.allocator;
    var f: HttpFixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const body = "{\"jsonrpc\":\"2.0\",\"id\":31,\"method\":\"tools/call\",\"params\":{" ++ meta_none ++ ",\"name\":\"needs_sampling\",\"arguments\":{}}}";
    const reply = try f.post(arena, body, &.{
        .{ .name = "accept", .value = "application/json, text/event-stream" },
        .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
        .{ .name = "mcp-method", .value = "tools/call" },
        .{ .name = "mcp-name", .value = "needs_sampling" },
    });
    try std.testing.expectEqual(http.Status.bad_request, reply.status);
    const tree = try json.parseTree(arena, reply.body);
    try std.testing.expectEqual(@as(i64, 31), tree.object.get("id").?.integer);
    try std.testing.expectEqual(@as(i64, -32021), errorCode(tree).?);
    const required = tree.object.get("error").?.object.get("data").?.object.get("requiredCapabilities").?;
    try std.testing.expect(required.object.get("sampling") != null);
}

test "http server names the supported versions when a legacy client sends initialize" {
    const gpa = std.testing.allocator;
    var f: HttpFixture = undefined;
    try f.start();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"old\",\"version\":\"1\"}}}";
    const reply = try f.post(arena, body, &.{.{ .name = "accept", .value = "application/json, text/event-stream" }});
    try std.testing.expectEqual(http.Status.bad_request, reply.status);
    const tree = try json.parseTree(arena, reply.body);
    try std.testing.expectEqual(@as(i64, -32022), errorCode(tree).?);
    const e = tree.object.get("error").?;
    try std.testing.expect(std.mem.indexOf(u8, e.object.get("message").?.string, "2026-07-28") != null);
    try std.testing.expectEqualStrings("2026-07-28", e.object.get("data").?.object.get("supported").?.array.items[0].string);
}

// -- Client -------------------------------------------------------------------------------------

/// A client transport that records every request frame and forwards it to another transport.
const Recording = struct {
    inner: Transport.ClientTransport,
    arena: Allocator,
    frames: std.ArrayList([]const u8) = .empty,

    fn transport(self: *Recording) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .memory, .exchange = exchange, .notify = notify };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Recording = @ptrCast(@alignCast(ptr));
        try self.frames.append(self.arena, try self.arena.dupe(u8, ex.frame));
        return self.inner.exchange(io, ex);
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const self: *Recording = @ptrCast(@alignCast(ptr));
        return self.inner.notify(io, frame);
    }
};

/// A client transport that answers each request with the next canned reply. A reply is the
/// `"result":...` or `"error":...` member of the response. The transport adds the request id.
const Canned = struct {
    arena: Allocator,
    replies: []const []const u8,
    next: usize = 0,
    frames: std.ArrayList([]const u8) = .empty,

    fn transport(self: *Canned) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .memory, .exchange = exchange, .notify = notify };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Canned = @ptrCast(@alignCast(ptr));
        try self.frames.append(self.arena, try self.arena.dupe(u8, ex.frame));
        if (self.next >= self.replies.len) return error.Closed;
        const reply = self.replies[self.next];
        self.next += 1;
        const id_text = try json.writeAlloc(self.arena, ex.id);
        const frame = try std.fmt.allocPrint(self.arena, "{{\"jsonrpc\":\"2.0\",\"id\":{s},{s}}}", .{ id_text, reply });
        ex.sink.deliver(io, frame) catch return error.InvalidFrame;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = ptr;
        _ = io;
        _ = frame;
    }
};

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Alice\"}") };
}

test "client request ids are unique and carry the required _meta fields" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var server = try Server.init(gpa, io, .{ .info = .{ .name = "g1", .version = "1" } });
    defer server.deinit();
    try registerAll(&server);
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var recording: Recording = .{ .inner = link.transport(), .arena = arena };
    var client: Client = .init(gpa, io, .{
        .info = .{ .name = "cli", .version = "3" },
        .capabilities = .{ .elicitation = .{} },
        .hooks = .{ .elicit_form = answerForm },
    });
    defer client.deinit();
    client.connect(recording.transport());

    _ = try client.discover(arena, .{});
    _ = try client.listTools(arena, null, .{});
    const greeting = try client.callTool(arena, "ask_name", null, .{});
    try std.testing.expectEqualStrings("hello Alice", greeting.content[0].text.text);
    _ = try client.readResource(arena, "test://static", .{});

    // Four calls, and the multi round-trip call took two requests.
    try std.testing.expectEqual(5, recording.frames.items.len);
    var ids: std.ArrayList(i64) = .empty;
    for (recording.frames.items) |frame| {
        const tree = try json.parseTree(arena, frame);
        try std.testing.expectEqualStrings("2.0", tree.object.get("jsonrpc").?.string);
        const id = tree.object.get("id").?;
        try std.testing.expect(id == .integer);
        for (ids.items) |seen| try std.testing.expect(seen != id.integer);
        try ids.append(arena, id.integer);
        const m = tree.object.get("params").?.object.get("_meta").?;
        try std.testing.expectEqualStrings("2026-07-28", m.object.get(meta.key_protocol_version).?.string);
        try std.testing.expect(m.object.get(meta.key_client_capabilities).? == .object);
        try std.testing.expectEqualStrings("cli", m.object.get(meta.key_client_info).?.object.get("name").?.string);
    }
}

test "client treats a result without resultType as complete" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var canned: Canned = .{ .arena = arena, .replies = &.{"\"result\":{\"tools\":[{\"name\":\"t\",\"inputSchema\":{\"type\":\"object\"}}]}"} };
    var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(canned.transport());
    var diag: Client.Diagnostics = .{};
    const tools = try client.listTools(arena, null, .{ .diagnostics = &diag });
    try std.testing.expectEqual(1, tools.tools.len);
    try std.testing.expect(diag.result_type_absent);
}

test "client rejects a result with an unknown resultType" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var canned: Canned = .{ .arena = arena, .replies = &.{
        "\"result\":{\"resultType\":\"bogus\",\"tools\":[]}",
        "\"result\":{\"resultType\":\"Complete\",\"content\":[]}",
    } };
    var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(canned.transport());
    try std.testing.expectError(error.InvalidResponse, client.listTools(arena, null, .{}));
    try std.testing.expectError(error.InvalidResponse, client.callTool(arena, "t", null, .{}));
}

test "client accepts the task result type only for a declared extension" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const task_reply = "\"result\":{\"resultType\":\"task\",\"taskId\":\"t1\",\"status\":\"working\",\"createdAt\":\"2026-07-28T00:00:00Z\",\"lastUpdatedAt\":\"2026-07-28T00:00:00Z\",\"ttlMs\":1000}";

    // Without the extension a task result is invalid.
    {
        var canned: Canned = .{ .arena = arena, .replies = &.{task_reply} };
        var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
        defer client.deinit();
        client.connect(canned.transport());
        try std.testing.expectError(error.InvalidResponse, client.callToolOrTask(arena, "t", null, .{}));
    }
    // With the extension a tools/call can become a task, but no other method can.
    {
        const caps_tree = try json.parseTree(arena, "{\"extensions\":{\"io.modelcontextprotocol/tasks\":{}}}");
        var canned: Canned = .{ .arena = arena, .replies = &.{ task_reply, task_reply } };
        var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" }, .capabilities = try json.parseValue(types.ClientCapabilities, arena, caps_tree) });
        defer client.deinit();
        client.connect(canned.transport());
        const outcome = try client.callToolOrTask(arena, "t", null, .{});
        try std.testing.expectEqualStrings("t1", outcome.task.taskId);
        try std.testing.expectError(error.InvalidResponse, client.listTools(arena, null, .{}));
    }
}

test "client surfaces legacy and implementation-defined error codes as errors" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var canned: Canned = .{ .arena = arena, .replies = &.{
        "\"error\":{\"code\":-32002,\"message\":\"Resource not found\",\"data\":{\"uri\":\"test://x\"}}",
        "\"error\":{\"code\":-32001,\"message\":\"Legacy\"}",
    } };
    var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(canned.transport());

    var diag: Client.Diagnostics = .{};
    try std.testing.expectError(error.Rpc, client.readResource(arena, "test://x", .{ .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32002), diag.rpc_error.?.code);
    try std.testing.expectEqualStrings("test://x", diag.rpc_error.?.data.?.object.get("uri").?.string);
    diag = .{};
    try std.testing.expectError(error.Rpc, client.listTools(arena, null, .{ .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32001), diag.rpc_error.?.code);
    // No code made the client retry.
    try std.testing.expectEqual(2, canned.frames.items.len);
}

test "client retries once when the server lists its version and fails otherwise" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        var canned: Canned = .{ .arena = arena, .replies = &.{
            "\"error\":{\"code\":-32022,\"message\":\"Unsupported protocol version\",\"data\":{\"supported\":[\"2025-11-25\",\"2026-07-28\"],\"requested\":\"2026-07-28\"}}",
            "\"result\":{\"resultType\":\"complete\",\"tools\":[]}",
        } };
        var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
        defer client.deinit();
        client.connect(canned.transport());
        _ = try client.listTools(arena, null, .{});
        try std.testing.expectEqual(2, canned.frames.items.len);
        const first = try json.parseTree(arena, canned.frames.items[0]);
        const second = try json.parseTree(arena, canned.frames.items[1]);
        try std.testing.expect(first.object.get("id").?.integer != second.object.get("id").?.integer);
        const version = second.object.get("params").?.object.get("_meta").?.object.get(meta.key_protocol_version).?.string;
        try std.testing.expectEqualStrings("2026-07-28", version);
    }
    {
        var canned: Canned = .{ .arena = arena, .replies = &.{
            "\"error\":{\"code\":-32022,\"message\":\"Unsupported protocol version\",\"data\":{\"supported\":[\"2025-11-25\"],\"requested\":\"2026-07-28\"}}",
            "\"result\":{\"resultType\":\"complete\",\"tools\":[]}",
        } };
        var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
        defer client.deinit();
        client.connect(canned.transport());
        var diag: Client.Diagnostics = .{};
        try std.testing.expectError(error.Rpc, client.listTools(arena, null, .{ .diagnostics = &diag }));
        try std.testing.expectEqual(@as(i64, -32022), diag.rpc_error.?.code);
        try std.testing.expectEqual(1, canned.frames.items.len);
    }
}
