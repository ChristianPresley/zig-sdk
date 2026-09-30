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

    // Registration rejects unsupported keywords, remote references and bad header annotations.
    try std.testing.expectError(error.UnsupportedKeyword, g.server.addToolJson(.{ .name = "p", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"pattern\":\"^a\"}}}" }, boom));
    try std.testing.expectError(error.RemoteRef, g.server.addToolJson(.{ .name = "r", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"$ref\":\"https://example.com/x\"}}}" }, boom));
    try std.testing.expectError(error.InvalidHeaderAnnotation, g.server.addToolJson(.{ .name = "h", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"object\",\"x-mcp-header\":\"A\"}}}" }, boom));
    try std.testing.expectError(error.InvalidHeaderAnnotation, g.server.addToolJson(.{ .name = "h2", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"x-mcp-header\":\"A\"},\"b\":{\"type\":\"string\",\"x-mcp-header\":\"a\"}}}" }, boom));
    // Opting in keeps unsupported keywords as annotations.
    var h: Fixture = undefined;
    try h.init(.{ .info = .{ .name = "test", .version = "0.1.0" }, .allow_unsupported_schema_keywords = true });
    defer h.deinit();
    try h.server.addToolJson(.{ .name = "p", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"pattern\":\"^a\"}}}" }, boom);
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
