//! Behavioural tests for the server engine over the in-memory harness.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const Server = mcp.Server;
const RequestContext = mcp.RequestContext;
const types = mcp.types;
const json = mcp.json;
const Harness = mcp.transport.memory.Harness;
const Transport = mcp.transport.Transport;

const meta_all =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{"sampling":{},"elicitation":{},"roots":{}}}
;
const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;

fn request(arena: std.mem.Allocator, id: i64, method: []const u8, meta: []const u8, extra: []const u8) ![]u8 {
    const sep: []const u8 = if (extra.len > 0) "," else "";
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta, sep, extra });
}

const AddArgs = struct {
    a: i64,
    b: i64,
    pub const json_schema = .{ .description = "Add two integers." };
};

fn add(ctx: *RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(1, 2, "adding");
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

fn boom(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = ctx;
    _ = args;
    return error.Boom;
}

fn askName(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const round = (try ctx.state(struct { round: u32 })) orelse return error.MissingState;
        if (resp.action != .accept) return .{ .complete = try types.CallToolResult.text(ctx.arena, "declined", .{}) };
        const name = json.getString(resp.content.?, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s} (round {d})", .{ name, round.round }) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    try ir.setStateFmt("{{\"round\":{d}}}", .{1});
    return .{ .input_required = ir };
}

fn needsSampling(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "ok", .{}) };
}

/// Echoes `structuredContent` from the `shape` argument to exercise output validation.
fn shape(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    const sc = args.object.get("shape") orelse return error.NoShape;
    const blocks = try ctx.arena.alloc(types.ContentBlock, 1);
    blocks[0] = .{ .text = .{ .text = "shape" } };
    return .{ .complete = .{ .content = blocks, .structuredContent = sc } };
}

fn readStatic(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "static text" } };
    return .{ .complete = .{ .contents = contents } };
}

fn readTemplate(ctx: *RequestContext, uri: []const u8, vars: []const mcp.UriTemplate.Variable) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "application/json", .text = try std.fmt.allocPrint(ctx.arena, "{{\"id\":\"{s}\"}}", .{vars[0].value}) } };
    return .{ .complete = .{ .contents = contents } };
}

fn getPrompt(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    const arg1 = if (args) |a| a.map.get("arg1") orelse "none" else "none";
    const messages = try ctx.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = try std.fmt.allocPrint(ctx.arena, "arg1={s}", .{arg1}) } } };
    return .{ .complete = .{ .messages = messages } };
}

fn complete(ctx: *RequestContext, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion {
    _ = params;
    const values = try ctx.arena.alloc([]const u8, 2);
    values[0] = "alpha";
    values[1] = "beta";
    return .{ .values = values };
}

const Fixture = struct {
    server: Server,
    harness: Harness,
    arena_state: std.heap.ArenaAllocator,

    fn init(self: *Fixture, options: Server.Options) !void {
        const gpa = std.testing.allocator;
        self.arena_state = .init(gpa);
        self.server = try Server.init(gpa, std.testing.io, options);
        try self.server.addTool(.{ .name = "add", .description = "Adds" }, add);
        try self.server.addToolJson(.{ .name = "boom" }, boom);
        try self.server.addToolJson(.{ .name = "ask_name" }, askName);
        try self.server.addToolJson(.{ .name = "needs_sampling", .requires_client = .{ .sampling = .{} } }, needsSampling);
        try self.server.addToolJson(.{
            .name = "shape",
            .input_schema = "{\"type\":\"object\",\"properties\":{\"shape\":{\"type\":\"object\"},\"count\":{\"type\":\"integer\",\"minimum\":1}},\"required\":[\"shape\"]}",
            .output_schema = "{\"type\":\"object\",\"properties\":{\"sides\":{\"type\":\"integer\"}},\"required\":[\"sides\"]}",
        }, shape);
        try self.server.addResource(.{ .uri = "test://static-text", .name = "static", .mime_type = "text/plain" }, readStatic);
        try self.server.addResourceTemplate(.{ .uri_template = "test://template/{id}/data", .name = "tpl" }, readTemplate);
        try self.server.addPrompt(.{ .name = "test_prompt", .arguments = &.{.{ .name = "arg1", .required = true }} }, getPrompt);
        self.server.setCompletionHandler(complete);
        self.harness = .init(std.testing.io, gpa, &self.server);
    }

    fn deinit(self: *Fixture) void {
        self.harness.deinit();
        self.server.deinit();
        self.arena_state.deinit();
    }

    fn arena(self: *Fixture) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// Send a request and return the parsed last frame.
    fn call(self: *Fixture, id: i64, method: []const u8, meta: []const u8, extra: []const u8) !Value {
        self.harness.clear();
        try self.harness.send(try request(self.arena(), id, method, meta, extra));
        try std.testing.expect(self.harness.finished);
        return json.parseTree(self.arena(), self.harness.last().?);
    }
};

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

fn result(v: Value) Value {
    return v.object.get("result").?;
}

test "discover and ladder errors" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "test", .version = "0.1.0" }, .instructions = "hi" });
    defer f.deinit();

    const disc = try f.call(1, "server/discover", meta_none, "");
    const r = result(disc);
    try std.testing.expectEqualStrings("complete", r.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("2026-07-28", r.object.get("supportedVersions").?.array.items[0].string);
    try std.testing.expect(r.object.get("capabilities").?.object.get("tools") != null);
    try std.testing.expectEqual(@as(i64, 0), r.object.get("ttlMs").?.integer);
    try std.testing.expectEqualStrings("private", r.object.get("cacheScope").?.string);
    try std.testing.expectEqualStrings("test", r.object.get("_meta").?.object.get("io.modelcontextprotocol/serverInfo").?.object.get("name").?.string);
    try std.testing.expectEqualStrings("hi", r.object.get("instructions").?.string);

    // Missing _meta entirely.
    var v = try f.call(2, "server/discover", "\"x\":1", "");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(v).?);
    // Missing clientCapabilities.
    v = try f.call(3, "server/discover", "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}", "");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(v).?);
    // clientInfo is optional.
    v = try f.call(4, "server/discover", meta_none, "");
    try std.testing.expect(errorCode(v) == null);
    // Unsupported version.
    v = try f.call(5, "server/discover", "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"v999.0.0\",\"io.modelcontextprotocol/clientCapabilities\":{}}", "");
    try std.testing.expectEqual(@as(i64, -32022), errorCode(v).?);
    const data = v.object.get("error").?.object.get("data").?;
    try std.testing.expectEqualStrings("v999.0.0", data.object.get("requested").?.string);
    try std.testing.expectEqualStrings("2026-07-28", data.object.get("supported").?.array.items[0].string);
    // Legacy handshake and removed methods.
    v = try f.call(6, "initialize", "\"protocolVersion\":\"2025-11-25\"", "");
    try std.testing.expectEqual(@as(i64, -32601), errorCode(v).?);
    try std.testing.expect(v.object.get("error").?.object.get("data").?.object.get("supportedVersions") != null);
    v = try f.call(7, "ping", meta_none, "");
    try std.testing.expectEqual(@as(i64, -32601), errorCode(v).?);
    v = try f.call(8, "unknown/method", meta_none, "");
    try std.testing.expectEqual(@as(i64, -32601), errorCode(v).?);
    try std.testing.expectEqual(@as(i64, 8), v.object.get("id").?.integer);
}

test "tools list and call" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "test", .version = "0.1.0" } });
    defer f.deinit();

    const list = result(try f.call(1, "tools/list", meta_none, ""));
    const tools = list.object.get("tools").?.array.items;
    try std.testing.expectEqual(5, tools.len);
    try std.testing.expectEqualStrings("add", tools[0].object.get("name").?.string);
    const schema = tools[0].object.get("inputSchema").?;
    try std.testing.expectEqualStrings("object", schema.object.get("type").?.string);
    try std.testing.expect(schema.object.get("properties").?.object.get("a") != null);
    try std.testing.expect(list.object.get("ttlMs") != null);

    // Call with arguments, progress token set.
    const meta_progress =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":"p1"}
    ;
    const v = try f.call(2, "tools/call", meta_progress, "\"name\":\"add\",\"arguments\":{\"a\":2,\"b\":3}");
    try std.testing.expectEqualStrings("5", result(v).object.get("content").?.array.items[0].object.get("text").?.string);
    // The progress notification came first.
    try std.testing.expectEqual(2, f.harness.out.items.len);
    const note = try json.parseTree(f.arena(), f.harness.out.items[0]);
    try std.testing.expectEqualStrings("notifications/progress", note.object.get("method").?.string);
    try std.testing.expectEqualStrings("p1", note.object.get("params").?.object.get("progressToken").?.string);

    // Invalid arguments become a tool error result by default.
    const bad = result(try f.call(3, "tools/call", meta_none, "\"name\":\"add\",\"arguments\":{\"a\":\"x\"}"));
    try std.testing.expect(bad.object.get("isError").?.bool);
    // A handler failure is a tool error, not a protocol error.
    const failed = result(try f.call(4, "tools/call", meta_none, "\"name\":\"boom\""));
    try std.testing.expect(failed.object.get("isError").?.bool);
    // Unknown tool.
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(5, "tools/call", meta_none, "\"name\":\"nope\"")).?);
    // Missing client capability declared at registration.
    const missing = try f.call(6, "tools/call", meta_none, "\"name\":\"needs_sampling\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(missing).?);
    try std.testing.expect(missing.object.get("error").?.object.get("data").?.object.get("requiredCapabilities").?.object.get("sampling") != null);
    try std.testing.expect(errorCode(try f.call(7, "tools/call", meta_all, "\"name\":\"needs_sampling\",\"arguments\":{}")) == null);
}

test "tool schemas validate arguments and structured output" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "test", .version = "0.1.0" } });
    defer f.deinit();

    // Valid arguments and valid structured output.
    const ok = result(try f.call(1, "tools/call", meta_none, "\"name\":\"shape\",\"arguments\":{\"shape\":{\"sides\":3},\"count\":2}"));
    try std.testing.expect(ok.object.get("isError") == null);
    try std.testing.expectEqual(3, ok.object.get("structuredContent").?.object.get("sides").?.integer);
    // A schema violation in the arguments is a tool error with the location.
    const bad = result(try f.call(2, "tools/call", meta_none, "\"name\":\"shape\",\"arguments\":{\"shape\":{\"sides\":3},\"count\":0}"));
    try std.testing.expect(bad.object.get("isError").?.bool);
    const text = bad.object.get("content").?.array.items[0].object.get("text").?.string;
    try std.testing.expect(std.mem.indexOf(u8, text, "/count") != null);
    // A missing required argument.
    const missing = result(try f.call(3, "tools/call", meta_none, "\"name\":\"shape\",\"arguments\":{}"));
    try std.testing.expect(missing.object.get("isError").?.bool);
    // Structured output that does not match the output schema is a server error.
    const wrong = try f.call(4, "tools/call", meta_none, "\"name\":\"shape\",\"arguments\":{\"shape\":{\"sides\":\"three\"}}");
    try std.testing.expectEqual(@as(i64, -32603), errorCode(wrong).?);

    // The rpc_error policy turns argument violations into -32602.
    var g: Fixture = undefined;
    try g.init(.{ .info = .{ .name = "test", .version = "0.1.0" }, .invalid_args_policy = .rpc_error });
    defer g.deinit();
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try g.call(5, "tools/call", meta_none, "\"name\":\"shape\",\"arguments\":{}")).?);

    // The `pattern` keyword validates string arguments.
    try g.server.addToolJson(.{ .name = "code", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"pattern\":\"^[A-Z]{3}$\"}}}" }, boom);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try g.call(6, "tools/call", meta_none, "\"name\":\"code\",\"arguments\":{\"a\":\"abc\"}")).?);
    try std.testing.expect(errorCode(try g.call(7, "tools/call", meta_none, "\"name\":\"code\",\"arguments\":{\"a\":\"ABC\"}")) == null);
    // `unevaluatedProperties` rejects the names that no other keyword evaluated.
    try g.server.addToolJson(.{ .name = "strict", .input_schema = "{\"type\":\"object\",\"allOf\":[{\"properties\":{\"a\":{\"type\":\"string\"}}}],\"unevaluatedProperties\":false}" }, boom);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try g.call(8, "tools/call", meta_none, "\"name\":\"strict\",\"arguments\":{\"a\":\"x\",\"b\":1}")).?);
    try std.testing.expect(errorCode(try g.call(9, "tools/call", meta_none, "\"name\":\"strict\",\"arguments\":{\"a\":\"x\"}")) == null);
    // Registration rejects `$schema` outside the root of a resource, regular expression
    // features that the engine does not support, invalid regular expressions, remote
    // references and bad header annotations.
    try std.testing.expectError(error.UnsupportedKeyword, g.server.addToolJson(.{ .name = "u", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}}}" }, boom));
    try std.testing.expectError(error.UnsupportedKeyword, g.server.addToolJson(.{ .name = "p", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"pattern\":\"^(?=a)\"}}}" }, boom));
    try std.testing.expectError(error.InvalidSchema, g.server.addToolJson(.{ .name = "q", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"pattern\":\"^(a\"}}}" }, boom));
    try std.testing.expectError(error.RemoteRef, g.server.addToolJson(.{ .name = "r", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"$ref\":\"https://example.com/x\"}}}" }, boom));
    try std.testing.expectError(error.InvalidHeaderAnnotation, g.server.addToolJson(.{ .name = "h", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"object\",\"x-mcp-header\":\"A\"}}}" }, boom));
    try std.testing.expectError(error.InvalidHeaderAnnotation, g.server.addToolJson(.{ .name = "h2", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"x-mcp-header\":\"A\"},\"b\":{\"type\":\"string\",\"x-mcp-header\":\"a\"}}}" }, boom));
    // Opting in ignores the regular expressions that the engine does not support.
    var h: Fixture = undefined;
    try h.init(.{ .info = .{ .name = "test", .version = "0.1.0" }, .allow_unsupported_schema_keywords = true });
    defer h.deinit();
    try h.server.addToolJson(.{ .name = "p", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"pattern\":\"^(?=a)\"}}}" }, boom);
}

test "multi round-trip request with sealed state" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "test", .version = "0.1.0" } });
    defer f.deinit();

    const first = result(try f.call(1, "tools/call", meta_all, "\"name\":\"ask_name\",\"arguments\":{}"));
    try std.testing.expectEqualStrings("input_required", first.object.get("resultType").?.string);
    const req = first.object.get("inputRequests").?.object.get("user_name").?;
    try std.testing.expectEqualStrings("elicitation/create", req.object.get("method").?.string);
    const state = first.object.get("requestState").?.string;
    try std.testing.expect(std.mem.startsWith(u8, state, "v1."));
    try std.testing.expect(first.object.get("ttlMs") == null);

    const retry = try std.fmt.allocPrint(f.arena(), "\"name\":\"ask_name\",\"arguments\":{{}},\"inputResponses\":{{\"user_name\":{{\"action\":\"accept\",\"content\":{{\"name\":\"Alice\"}}}}}},\"requestState\":\"{s}\"", .{state});
    const second = result(try f.call(2, "tools/call", meta_all, retry));
    try std.testing.expectEqualStrings("complete", second.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("hello Alice (round 1)", second.object.get("content").?.array.items[0].object.get("text").?.string);

    const tampered = try std.fmt.allocPrint(f.arena(), "\"name\":\"ask_name\",\"arguments\":{{}},\"inputResponses\":{{\"user_name\":{{\"action\":\"accept\",\"content\":{{\"name\":\"Alice\"}}}}}},\"requestState\":\"{s}-TAMPERED\"", .{state});
    const bad = try f.call(3, "tools/call", meta_all, tampered);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(bad).?);
    try std.testing.expectEqualStrings("invalid_request_state", bad.object.get("error").?.object.get("data").?.object.get("reason").?.string);

    // A client without the elicitation capability gets -32021 instead of an input request.
    const no_caps = try f.call(4, "tools/call", meta_none, "\"name\":\"ask_name\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_caps).?);
}

test "uri template limits: template length at registration and URI length at match" {
    var options: Server.Options = .{ .info = .{ .name = "test", .version = "0.1.0" } };
    options.limits.uri_template.max_uri_bytes = 32;
    var f: Fixture = undefined;
    try f.init(options);
    defer f.deinit();

    // The fixture template "test://template/{id}/data" matches a URI of 32 bytes or less.
    const short = result(try f.call(1, "resources/read", meta_none, "\"uri\":\"test://template/12345/data\""));
    try std.testing.expectEqualStrings("{\"id\":\"12345\"}", short.object.get("contents").?.array.items[0].object.get("text").?.string);
    // A longer URI matches no template: the resource is not found.
    const long = try f.call(2, "resources/read", meta_none, "\"uri\":\"test://template/123456789012345/data\"");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(long).?);

    // A template longer than the limit fails at registration.
    var small: Server.Options = .{ .info = .{ .name = "test", .version = "0.1.0" } };
    small.limits.uri_template.max_template_bytes = 16;
    var server = try Server.init(std.testing.allocator, std.testing.io, small);
    defer server.deinit();
    try std.testing.expectError(error.InvalidUriTemplate, server.addResourceTemplate(.{ .uri_template = "test://template/{id}/data", .name = "tpl" }, readTemplate));
    try server.addResourceTemplate(.{ .uri_template = "t://{id}", .name = "ok" }, readTemplate);
}

test "resources, templates, prompts, completion" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "test", .version = "0.1.0" } });
    defer f.deinit();

    const list = result(try f.call(1, "resources/list", meta_none, ""));
    try std.testing.expectEqual(1, list.object.get("resources").?.array.items.len);
    const tlist = result(try f.call(2, "resources/templates/list", meta_none, ""));
    try std.testing.expectEqualStrings("test://template/{id}/data", tlist.object.get("resourceTemplates").?.array.items[0].object.get("uriTemplate").?.string);

    const read = result(try f.call(3, "resources/read", meta_none, "\"uri\":\"test://static-text\""));
    try std.testing.expectEqualStrings("static text", read.object.get("contents").?.array.items[0].object.get("text").?.string);
    try std.testing.expect(read.object.get("cacheScope") != null);
    const tread = result(try f.call(4, "resources/read", meta_none, "\"uri\":\"test://template/123/data\""));
    try std.testing.expectEqualStrings("{\"id\":\"123\"}", tread.object.get("contents").?.array.items[0].object.get("text").?.string);
    const missing = try f.call(5, "resources/read", meta_none, "\"uri\":\"test://nope\"");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(missing).?);
    try std.testing.expectEqualStrings("test://nope", missing.object.get("error").?.object.get("data").?.object.get("uri").?.string);

    const plist = result(try f.call(6, "prompts/list", meta_none, ""));
    try std.testing.expectEqualStrings("test_prompt", plist.object.get("prompts").?.array.items[0].object.get("name").?.string);
    const pget = result(try f.call(7, "prompts/get", meta_none, "\"name\":\"test_prompt\",\"arguments\":{\"arg1\":\"v1\"}"));
    try std.testing.expectEqualStrings("arg1=v1", pget.object.get("messages").?.array.items[0].object.get("content").?.object.get("text").?.string);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(8, "prompts/get", meta_none, "\"name\":\"test_prompt\"")).?);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(9, "prompts/get", meta_none, "\"name\":\"nope\"")).?);

    const comp = result(try f.call(10, "completion/complete", meta_none, "\"ref\":{\"type\":\"ref/prompt\",\"name\":\"test_prompt\"},\"argument\":{\"name\":\"arg1\",\"value\":\"a\"}"));
    try std.testing.expectEqual(2, comp.object.get("completion").?.object.get("values").?.array.items.len);
}

test "pagination" {
    var f: Fixture = undefined;
    var options: Server.Options = .{ .info = .{ .name = "test", .version = "0.1.0" } };
    options.limits.page_size = 3;
    try f.init(options);
    defer f.deinit();

    const page1 = result(try f.call(1, "tools/list", meta_none, ""));
    try std.testing.expectEqual(3, page1.object.get("tools").?.array.items.len);
    const cursor = page1.object.get("nextCursor").?.string;
    const page2 = result(try f.call(2, "tools/list", meta_none, try std.fmt.allocPrint(f.arena(), "\"cursor\":\"{s}\"", .{cursor})));
    try std.testing.expectEqual(2, page2.object.get("tools").?.array.items.len);
    try std.testing.expect(page2.object.get("nextCursor") == null);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(3, "tools/list", meta_none, "\"cursor\":\"garbage!\"")).?);
}

test "subscriptions listen stream" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "test", .version = "0.1.0" } });
    defer f.deinit();
    const io = std.testing.io;

    var token: Transport.CancelToken = .{};
    const frame = try request(f.arena(), 9, "subscriptions/listen", meta_none, "\"notifications\":{\"toolsListChanged\":true,\"promptsListChanged\":false}");
    var future = try io.concurrent(Harness.sendWithToken, .{ &f.harness, frame, &token });

    // Wait for the acknowledgement.
    var spins: usize = 0;
    while (f.harness.out.items.len == 0 and spins < 200) : (spins += 1) try io.sleep(.fromMilliseconds(5), .awake);
    try std.testing.expect(f.harness.out.items.len >= 1);
    const ack = try json.parseTree(f.arena(), f.harness.out.items[0]);
    try std.testing.expectEqualStrings("notifications/subscriptions/acknowledged", ack.object.get("method").?.string);
    const ack_params = ack.object.get("params").?;
    try std.testing.expectEqual(@as(i64, 9), ack_params.object.get("_meta").?.object.get("io.modelcontextprotocol/subscriptionId").?.integer);
    try std.testing.expect(ack_params.object.get("notifications").?.object.get("toolsListChanged").?.bool);

    // A tools change is delivered with the subscription id; a prompts change is not.
    f.server.notifyToolsListChanged(io);
    f.server.notifyPromptsListChanged(io);
    spins = 0;
    while (f.harness.out.items.len < 2 and spins < 200) : (spins += 1) try io.sleep(.fromMilliseconds(5), .awake);
    try std.testing.expectEqual(2, f.harness.out.items.len);
    const note = try json.parseTree(f.arena(), f.harness.out.items[1]);
    try std.testing.expectEqualStrings("notifications/tools/list_changed", note.object.get("method").?.string);
    try std.testing.expectEqual(@as(i64, 9), note.object.get("params").?.object.get("_meta").?.object.get("io.modelcontextprotocol/subscriptionId").?.integer);

    // Server-initiated teardown ends with a completion result carrying the subscription id.
    f.server.shutdownSubscriptions(io);
    try future.await(io);
    try std.testing.expect(f.harness.finished);
    const last = try json.parseTree(f.arena(), f.harness.last().?);
    try std.testing.expectEqualStrings("complete", result(last).object.get("resultType").?.string);
    try std.testing.expectEqual(@as(i64, 9), result(last).object.get("_meta").?.object.get("io.modelcontextprotocol/subscriptionId").?.integer);
}

test "a listen filter above limits.max_filter_bytes gets -32603 and no stream" {
    var f: Fixture = undefined;
    var options: Server.Options = .{ .info = .{ .name = "test", .version = "0.1.0" } };
    options.limits.max_filter_bytes = 64;
    try f.init(options);
    defer f.deinit();
    // The filter has 79 bytes as compact JSON.
    const big = "\"notifications\":{\"resourceSubscriptions\":[\"file:///a/long/path/one\",\"file:///a/long/path/two\"]}";
    const reply = try f.call(11, "subscriptions/listen", meta_none, big);
    try std.testing.expectEqual(@as(i64, -32603), errorCode(reply).?);
    try std.testing.expectEqualStrings("Subscription filter too large", reply.object.get("error").?.object.get("message").?.string);
    // The error is the only frame: there is no acknowledgment.
    try std.testing.expectEqual(1, f.harness.out.items.len);
}

test "client-cancelled listen stream gets no response" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "test", .version = "0.1.0" } });
    defer f.deinit();
    const io = std.testing.io;
    var token: Transport.CancelToken = .{};
    const frame = try request(f.arena(), 10, "subscriptions/listen", meta_none, "\"notifications\":{\"toolsListChanged\":true}");
    var future = try io.concurrent(Harness.sendWithToken, .{ &f.harness, frame, &token });
    var spins: usize = 0;
    while (f.harness.out.items.len == 0 and spins < 200) : (spins += 1) try io.sleep(.fromMilliseconds(5), .awake);
    token.cancel(io, "client cancelled");
    try future.await(io);
    try std.testing.expectEqual(1, f.harness.out.items.len);
    try std.testing.expect(f.harness.finished);
}

// -- Order of the acknowledgment and the events -------------------------------------------------

const ack_method = "notifications/subscriptions/acknowledged";
const event_method = "notifications/tools/list_changed";
const tools_listen = "\"notifications\":{\"toolsListChanged\":true}";

fn listChangedServer() !Server {
    return Server.init(std.testing.allocator, std.testing.io, .{
        .info = .{ .name = "test", .version = "0.1.0" },
        .capabilities = .{ .tools = .{ .listChanged = true } },
    });
}

/// Wait until `event` is set, at most `ms` milliseconds. Returns false when the time ends
/// first.
fn waitEvent(event: *Io.Event, ms: i64) bool {
    const io = std.testing.io;
    const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = .fromMilliseconds(ms), .clock = .awake });
    while (!event.isSet()) {
        // A wait can also end early without the event. Then wait again until the deadline.
        event.waitTimeout(io, .{ .deadline = deadline }) catch |e| switch (e) {
            error.Timeout => if (Io.Clock.Timestamp.now(io, .awake).durationTo(deadline).raw.nanoseconds <= 0) return event.isSet(),
            error.Canceled => return event.isSet(),
        };
    }
    return true;
}

/// A listen stream that holds its acknowledgment until `release` is set, and records the
/// order of its frames.
const GatedStream = struct {
    release: Io.Event = .unset,
    ack_started: Io.Event = .unset,
    got_event: Io.Event = .unset,
    lock: Io.Mutex = .init,
    order: [4]Kind = undefined,
    count: usize = 0,

    const Kind = enum { ack, event, other };

    fn responder(self: *GatedStream) Transport.Responder {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.Responder.VTable = .{ .notify = notify, .finish = notify, .abort = abort };

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const self: *GatedStream = @ptrCast(@alignCast(ptr));
        const kind: Kind = if (std.mem.find(u8, frame, ack_method) != null) .ack else if (std.mem.find(u8, frame, event_method) != null) .event else .other;
        if (kind == .ack) {
            self.ack_started.set(io);
            try self.release.wait(io);
        }
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        if (self.count < self.order.len) self.order[self.count] = kind;
        self.count += 1;
        if (kind == .event) self.got_event.set(io);
    }

    fn abort(ptr: *anyopaque, io: Io) void {
        _ = ptr;
        _ = io;
    }

    fn serve(self: *GatedStream, server: *Server, token: *Transport.CancelToken) void {
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const text = request(arena, 1, "subscriptions/listen", meta_none, tools_listen) catch return;
        const msg = mcp.jsonrpc.Message.parse(arena, text) catch return;
        server.handle(std.testing.io, .{ .kind = .memory, .arena = arena, .message = msg, .responder = self.responder(), .cancel = token });
    }
};

test "an event that the server publishes during the acknowledgment goes out after it" {
    const io = std.testing.io;
    var server = try listChangedServer();
    defer server.deinit();
    var stream: GatedStream = .{};
    var token: Transport.CancelToken = .{};
    var listen = try io.concurrent(GatedStream.serve, .{ &stream, &server, &token });
    var listen_done = false;
    defer if (!listen_done) {
        stream.release.set(io);
        token.cancel(io, "done");
        listen.await(io);
    };
    try std.testing.expect(waitEvent(&stream.ack_started, 4000));

    // The subscription is visible to publish, but its acknowledgment is not out. The event
    // waits for it. Without the order, the event arrives in this time.
    var publish = try io.concurrent(Server.notifyToolsListChanged, .{ &server, io });
    const early = waitEvent(&stream.got_event, 200);
    stream.release.set(io);
    const delivered = waitEvent(&stream.got_event, 4000);
    publish.await(io);
    token.cancel(io, "done");
    listen.await(io);
    listen_done = true;

    try std.testing.expect(!early);
    try std.testing.expect(delivered);
    try std.testing.expectEqual(2, stream.count);
    try std.testing.expectEqual(GatedStream.Kind.ack, stream.order[0]);
    try std.testing.expectEqual(GatedStream.Kind.event, stream.order[1]);
}

/// Publishes `notifications/tools/list_changed` until `stop` is true.
const Publisher = struct {
    server: *Server,
    stop: std.atomic.Value(bool) = .init(false),
    /// While true, the publisher publishes nothing. A loop of publications holds the lock of
    /// the subscriptions most of the time, thus a listen stream then ends slowly.
    paused: std.atomic.Value(bool) = .init(false),

    fn run(self: *Publisher) void {
        while (!self.stop.load(.acquire)) {
            if (!self.paused.load(.acquire)) self.server.notifyToolsListChanged(std.testing.io);
        }
    }

    fn halt(self: *Publisher, future: *Io.Future(void)) void {
        self.stop.store(true, .release);
        future.await(std.testing.io);
    }
};

/// The listen streams that each stress test opens one after the other.
const order_rounds = 200;

/// One listen stream over the memory link. It counts its events and the events that arrive
/// before its acknowledgment.
const LinkListen = struct {
    client: *mcp.Client,
    token: Transport.CancelToken = .{},
    acked: Io.Event = .unset,
    events: std.atomic.Value(u32) = .init(0),
    early: std.atomic.Value(u32) = .init(0),

    fn onNotification(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        _ = params;
        const self: *LinkListen = @ptrCast(@alignCast(userdata.?));
        if (std.mem.eql(u8, method, ack_method)) {
            self.acked.set(std.testing.io);
        } else if (std.mem.eql(u8, method, event_method)) {
            if (!self.acked.isSet()) _ = self.early.fetchAdd(1, .monotonic);
            _ = self.events.fetchAdd(1, .monotonic);
        }
    }

    fn run(self: *LinkListen) void {
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const filter: types.SubscriptionsListenRequestParams = .{
            ._meta = .{ .@"io.modelcontextprotocol/protocolVersion" = "2026-07-28", .@"io.modelcontextprotocol/clientCapabilities" = .{} },
            .notifications = .{ .toolsListChanged = true },
        };
        _ = self.client.listen(arena_state.allocator(), filter, .{
            .cancel = &self.token,
            .retry = .never,
            .on_notification = onNotification,
            .userdata = self,
        }) catch {};
    }
};

test "a publish that races new listen streams over the memory link never gets to the client before the acknowledgment" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server = try listChangedServer();
    defer server.deinit();
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(link.transport());

    var publisher: Publisher = .{ .server = &server };
    var publishing = try io.concurrent(Publisher.run, .{&publisher});
    var halted = false;
    defer if (!halted) publisher.halt(&publishing);

    var events: u32 = 0;
    var early: u32 = 0;
    for (0..order_rounds) |_| {
        var job: LinkListen = .{ .client = &client };
        publisher.paused.store(false, .release);
        var future = try io.concurrent(LinkListen.run, .{&job});
        const acked = waitEvent(&job.acked, 4000);
        publisher.paused.store(true, .release);
        job.token.cancel(io, "done");
        future.await(io);
        try std.testing.expect(acked);
        events += job.events.load(.monotonic);
        early += job.early.load(.monotonic);
    }
    publisher.halt(&publishing);
    halted = true;
    try std.testing.expectEqual(0, early);
    // The publisher raced the streams.
    try std.testing.expect(events > 0);
}

/// The output of a stdio server. It reads each line when the transport flushes it, thus in
/// the order of the writes. For each subscription id, it counts the events before the
/// acknowledgment.
const StdioOrder = struct {
    writer: Io.Writer,
    /// The start of a line that the next flush ends.
    line: std.ArrayList(u8) = .empty,
    acked: [order_rounds + 1]bool = @splat(false),
    /// The highest subscription id with an acknowledgment.
    last_ack: std.atomic.Value(usize) = .init(0),
    /// Set at each acknowledgment.
    ack_event: Io.Event = .unset,
    events: u32 = 0,
    early: u32 = 0,

    fn init(buffer: []u8) StdioOrder {
        return .{ .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn deinit(self: *StdioOrder) void {
        self.line.deinit(std.testing.allocator);
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *StdioOrder = @fieldParentPtr("writer", w);
        self.take(w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var count: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            self.take(bytes) catch return error.WriteFailed;
            count += bytes.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| self.take(last) catch return error.WriteFailed;
        return count + last.len * splat;
    }

    fn take(self: *StdioOrder, bytes: []const u8) !void {
        var rest = bytes;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
            try self.line.appendSlice(std.testing.allocator, rest[0..end]);
            try self.record(self.line.items);
            self.line.clearRetainingCapacity();
            rest = rest[end + 1 ..];
        }
        try self.line.appendSlice(std.testing.allocator, rest);
    }

    fn record(self: *StdioOrder, line: []const u8) !void {
        var buf: [4096]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const frame = try json.parseTree(fba.allocator(), line);
        const method = json.getString(frame, "method") orelse return;
        const params = frame.object.get("params") orelse return;
        const meta = params.object.get("_meta") orelse return;
        const sid = meta.object.get("io.modelcontextprotocol/subscriptionId") orelse return;
        const index: usize = @intCast(sid.integer);
        if (std.mem.eql(u8, method, ack_method)) {
            self.acked[index] = true;
            self.last_ack.store(@max(index, self.last_ack.load(.monotonic)), .release);
            self.ack_event.set(std.testing.io);
        } else if (std.mem.eql(u8, method, event_method)) {
            self.events += 1;
            if (!self.acked[index]) self.early += 1;
        }
    }

    /// Wait until the stream `id` has its acknowledgment, at most four seconds.
    fn awaitAck(self: *StdioOrder, id: usize) bool {
        while (self.last_ack.load(.acquire) < id) {
            if (!waitEvent(&self.ack_event, 4000)) return false;
            // Only this task waits for the event.
            self.ack_event.reset();
        }
        return true;
    }
};

test "a publish that races new listen streams over stdio never writes an event before the acknowledgment" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server = try listChangedServer();
    defer server.deinit();
    var buffer: [8192]u8 = undefined;
    var order: StdioOrder = .init(&buffer);
    defer order.deinit();
    var transport: mcp.transport.stdio.Server = .init(io, gpa, &server, &order.writer);
    defer transport.deinit();
    var drained = false;
    defer if (!drained) {
        transport.stopAdmission();
        transport.cancelAll("done", false);
        transport.awaitInFlight(.fromSeconds(10));
    };

    var publisher: Publisher = .{ .server = &server };
    var publishing = try io.concurrent(Publisher.run, .{&publisher});
    var halted = false;
    defer if (!halted) publisher.halt(&publishing);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (1..order_rounds + 1) |id| {
        try transport.receive(try request(arena, @intCast(id), "subscriptions/listen", meta_none, tools_listen));
        try std.testing.expect(order.awaitAck(id));
        try transport.receive(try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":{d},\"reason\":\"done\"}}}}", .{id}));
    }
    publisher.halt(&publishing);
    halted = true;
    transport.stopAdmission();
    transport.cancelAll("done", false);
    transport.awaitInFlight(.fromSeconds(10));
    drained = true;

    // No task writes now.
    try std.testing.expectEqual(0, order.early);
    // The publisher raced the streams.
    try std.testing.expect(order.events > 0);
}

// -- Tasks extension --------------------------------------------------------------------------

const meta_tasks =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{},"extensions":{"io.modelcontextprotocol/tasks":{}}}}
;

const SlowArgs = struct { ms: i64 = 0 };

fn slowTool(ctx: *RequestContext, args: SlowArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    if (!ctx.inTask()) return .start_task;
    var left = args.ms;
    while (left > 0) : (left -= 10) {
        try ctx.checkCancel();
        try ctx.io.sleep(.fromMilliseconds(10), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "slept {d} ms", .{args.ms}) };
}

fn askTask(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (!ctx.inTask()) return .start_task;
    if (try ctx.elicitResponse("user_name")) |r| {
        const name = json.getString(r.content orelse .null, "name") orelse "nobody";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "task greets {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "Name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn failTask(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (!ctx.inTask()) return .start_task;
    return ctx.setError(mcp.protocol.errors.internalError("boom"));
}

const TaskFixture = struct {
    base: Fixture,
    next_id: i64 = 100,

    fn init(self: *TaskFixture) !void {
        self.* = .{ .base = undefined };
        try self.base.init(.{ .info = .{ .name = "test", .version = "0.1.0" }, .tasks = .{ .poll_interval_ms = 10 } });
        try self.base.server.addTool(.{ .name = "slow", .task_support = .optional }, slowTool);
        try self.base.server.addToolJson(.{ .name = "ask_task", .task_support = .required }, askTask);
        try self.base.server.addToolJson(.{ .name = "fail_task", .task_support = .optional }, failTask);
    }

    fn deinit(self: *TaskFixture) void {
        self.base.deinit();
    }

    fn call(self: *TaskFixture, method: []const u8, meta: []const u8, extra: []const u8) !Value {
        self.next_id += 1;
        return self.base.call(self.next_id, method, meta, extra);
    }

    fn get(self: *TaskFixture, task_id: []const u8) !Value {
        const extra = try std.fmt.allocPrint(self.base.arena(), "\"taskId\":\"{s}\"", .{task_id});
        return result(try self.call("tasks/get", meta_tasks, extra));
    }

    /// Poll `tasks/get` until the task has the wanted status.
    fn waitFor(self: *TaskFixture, task_id: []const u8, status: []const u8) !Value {
        var tries: usize = 0;
        while (tries < 500) : (tries += 1) {
            const r = try self.get(task_id);
            if (std.mem.eql(u8, r.object.get("status").?.string, status)) return r;
            try std.testing.io.sleep(.fromMilliseconds(10), .awake);
        }
        return error.TaskTimeout;
    }
};

fn taskId(v: Value) []const u8 {
    return result(v).object.get("taskId").?.string;
}

test "tasks extension: gate, sync fallback and lifecycle" {
    var f: TaskFixture = undefined;
    try f.init();
    defer f.deinit();

    // The extension is advertised.
    const disc = result(try f.call("server/discover", meta_none, ""));
    const ext = disc.object.get("capabilities").?.object.get("extensions").?;
    try std.testing.expect(ext.object.get(mcp.tasks.extension_id) != null);

    // Without the extension: task methods are gated, optional tools run at once, required tools fail.
    const gated = try f.call("tasks/get", meta_none, "\"taskId\":\"x\"");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(gated).?);
    const sync = result(try f.call("tools/call", meta_all, "\"name\":\"slow\",\"arguments\":{\"ms\":0}"));
    try std.testing.expectEqualStrings("complete", sync.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("slept 0 ms", sync.object.get("content").?.array.items[0].object.get("text").?.string);
    const required = try f.call("tools/call", meta_all, "\"name\":\"ask_task\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(required).?);
    const removed = try f.call("tasks/list", meta_tasks, "");
    try std.testing.expectEqual(@as(i64, -32601), errorCode(removed).?);
    const unknown = try f.call("tasks/get", meta_tasks, "\"taskId\":\"nope\"");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(unknown).?);

    // With the extension: a task is created, then completes.
    const created = try f.call("tools/call", meta_tasks, "\"name\":\"slow\",\"arguments\":{\"ms\":30}");
    const cr = result(created);
    try std.testing.expectEqualStrings("task", cr.object.get("resultType").?.string);
    try std.testing.expect(cr.object.get("requestState") == null);
    try std.testing.expect(cr.object.get("content") == null);
    try std.testing.expectEqual(@as(i64, 10), cr.object.get("pollIntervalMs").?.integer);
    const done = try f.waitFor(taskId(created), "completed");
    try std.testing.expectEqualStrings("complete", done.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("slept 30 ms", done.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
    try std.testing.expect(done.object.get("error") == null);

    // A protocol error makes the task fail with the error object.
    const failing = try f.call("tools/call", meta_tasks, "\"name\":\"fail_task\",\"arguments\":{}");
    const failed = try f.waitFor(taskId(failing), "failed");
    try std.testing.expectEqual(@as(i64, -32603), failed.object.get("error").?.object.get("code").?.integer);
    try std.testing.expect(failed.object.get("result") == null);

    // Cancel a running task; a second cancel is an idempotent ack.
    const long = try f.call("tools/call", meta_tasks, "\"name\":\"slow\",\"arguments\":{\"ms\":60000}");
    const cancel_extra = try std.fmt.allocPrint(f.base.arena(), "\"taskId\":\"{s}\"", .{taskId(long)});
    const ack = result(try f.call("tasks/cancel", meta_tasks, cancel_extra));
    try std.testing.expectEqualStrings("complete", ack.object.get("resultType").?.string);
    try std.testing.expect(ack.object.get("taskId") == null);
    _ = try f.waitFor(taskId(long), "cancelled");
    const ack2 = result(try f.call("tasks/cancel", meta_tasks, cancel_extra));
    try std.testing.expectEqualStrings("complete", ack2.object.get("resultType").?.string);
}

/// Logs three messages. With the Tasks extension, it logs them in a task.
fn logTask(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (!ctx.inTask()) return .start_task;
    for (0..3) |i| try ctx.logText(.info, "task", "step {d}", .{i});
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "logged", .{}) };
}

test "a task in the background sends no log messages and takes no log tokens" {
    const meta_tasks_debug =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}},"io.modelcontextprotocol/logLevel":"debug"}
    ;
    const meta_debug =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/logLevel":"debug"}
    ;
    var options: Server.Options = .{ .info = .{ .name = "test", .version = "0.1.0" }, .tasks = .{ .poll_interval_ms = 10 }, .capabilities = .{ .logging = .{ .object = .empty } } };
    options.limits.rate_limits.log_messages = .{ .count = 1, .period = .fromSeconds(3600) };
    var f: TaskFixture = .{ .base = undefined };
    try f.base.init(options);
    defer f.deinit();
    try f.base.server.addToolJson(.{ .name = "log_task", .task_support = .optional }, logTask);

    const created = try f.call("tools/call", meta_tasks_debug, "\"name\":\"log_task\",\"arguments\":{}");
    _ = try f.waitFor(taskId(created), "completed");
    try std.testing.expectEqual(0, f.base.server.rateLimitStats(std.testing.io).log_messages_dropped);

    // Without the extension, the task runs inside the request and logs on its stream. The
    // background task took no token, thus the first message goes out.
    const v = try f.call("tools/call", meta_debug, "\"name\":\"log_task\",\"arguments\":{}");
    try std.testing.expectEqualStrings("logged", result(v).object.get("content").?.array.items[0].object.get("text").?.string);
    var messages: usize = 0;
    for (f.base.harness.out.items) |frame| {
        const note = try json.parseTree(f.base.arena(), frame);
        const m = note.object.get("method") orelse continue;
        if (!std.mem.eql(u8, m.string, "notifications/message")) continue;
        messages += 1;
        try std.testing.expectEqualStrings("step 0", note.object.get("params").?.object.get("data").?.string);
    }
    try std.testing.expectEqual(1, messages);
    try std.testing.expectEqual(2, f.base.server.rateLimitStats(std.testing.io).log_messages_dropped);
}

test "tasks extension: input required inside a task" {
    var f: TaskFixture = undefined;
    try f.init();
    defer f.deinit();

    const created = try f.call("tools/call", meta_tasks, "\"name\":\"ask_task\",\"arguments\":{}");
    try std.testing.expectEqualStrings("task", result(created).object.get("resultType").?.string);
    const id = taskId(created);
    const parked = try f.waitFor(id, "input_required");
    const req = parked.object.get("inputRequests").?.object.get("user_name").?;
    try std.testing.expectEqualStrings("elicitation/create", req.object.get("method").?.string);

    const update = try std.fmt.allocPrint(f.base.arena(), "\"taskId\":\"{s}\",\"inputResponses\":{{\"user_name\":{{\"action\":\"accept\",\"content\":{{\"name\":\"Alice\"}}}}}}", .{id});
    const ack = result(try f.call("tasks/update", meta_tasks, update));
    try std.testing.expectEqualStrings("complete", ack.object.get("resultType").?.string);
    const done = try f.waitFor(id, "completed");
    try std.testing.expect(done.object.get("inputRequests") == null);
    try std.testing.expectEqualStrings("task greets Alice", done.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
}
