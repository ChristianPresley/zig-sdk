//! Tests for the tools, prompts and resources pages of the MCP specification.
//! Each test checks one group of server or client obligations through the public API.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const types = mcp.types;
const json = mcp.json;
const Harness = mcp.transport.memory.Harness;
const Transport = mcp.transport.Transport;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;
const meta_elicit =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}
;

const info: types.Implementation = .{ .name = "spec", .version = "1" };

fn request(arena: std.mem.Allocator, id: i64, method: []const u8, meta: []const u8, extra: []const u8) ![]u8 {
    const sep: []const u8 = if (extra.len > 0) "," else "";
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta, sep, extra });
}

// Send one request on a harness and return the parsed last frame.
fn call(h: *Harness, arena: std.mem.Allocator, id: i64, method: []const u8, meta: []const u8, extra: []const u8) !Value {
    h.clear();
    try h.send(try request(arena, id, method, meta, extra));
    try std.testing.expect(h.finished);
    return json.parseTree(arena, try arena.dupe(u8, h.last().?));
}

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

fn result(v: Value) Value {
    return v.object.get("result").?;
}

fn absent(v: Value, key: []const u8) bool {
    const x = v.object.get(key) orelse return true;
    return x == .null;
}

// -- Handlers ----------------------------------------------------------------------------------

fn okTool(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "ok", .{}) };
}

fn simplePrompt(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    _ = args;
    const messages = try ctx.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = "hello" } } };
    return .{ .complete = .{ .messages = messages } };
}

fn readText(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "text" } };
    return .{ .complete = .{ .contents = contents } };
}

fn readTwo(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 2);
    contents[0] = .{ .text = .{ .uri = "test://dir/a.txt", .mimeType = "text/plain", .text = "a" } };
    contents[1] = .{ .blob = .{ .uri = "test://dir/b.bin", .mimeType = "application/octet-stream", .blob = "AAEC" } };
    _ = uri;
    return .{ .complete = .{ .contents = contents } };
}

fn readEmpty(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    _ = ctx;
    _ = uri;
    return .{ .complete = .{ .contents = &.{} } };
}

fn readFails(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    _ = ctx;
    _ = uri;
    return error.DiskFailure;
}

fn readAsks(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    if (try ctx.elicitResponse("password")) |resp| {
        const word = json.getString(resp.content.?, "password") orelse "?";
        const contents = try ctx.arena.alloc(types.ResourceContents, 1);
        contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = try std.fmt.allocPrint(ctx.arena, "unlocked with {s}", .{word}) } };
        return .{ .complete = .{ .contents = contents } };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("password", "Password?", try mcp.InputRequired.stringSchema(ctx.arena, "password", null, true));
    return .{ .input_required = ir };
}

fn promptFails(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    _ = ctx;
    _ = args;
    return error.TemplateMissing;
}

fn promptAsks(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    _ = args;
    if (try ctx.elicitResponse("topic")) |resp| {
        const topic = json.getString(resp.content.?, "topic") orelse "?";
        const messages = try ctx.arena.alloc(types.PromptMessage, 1);
        messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = try std.fmt.allocPrint(ctx.arena, "write about {s}", .{topic}) } } };
        return .{ .complete = .{ .messages = messages } };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("topic", "Topic?", try mcp.InputRequired.stringSchema(ctx.arena, "topic", null, true));
    return .{ .input_required = ir };
}

fn promptWithLinks(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    _ = args;
    const messages = try ctx.arena.alloc(types.PromptMessage, 2);
    messages[0] = .{ .role = .user, .content = .{ .resource_link = .{ .name = "main.rs", .uri = "file:///project/src/main.rs", .mimeType = "text/x-rust" } } };
    messages[1] = .{ .role = .user, .content = .{ .resource = .{ .resource = .{ .text = .{ .uri = "resource://example", .mimeType = "text/plain", .text = "Resource content" } } } } };
    return .{ .complete = .{ .messages = messages } };
}

fn toolWithLinks(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const blocks = try ctx.arena.alloc(types.ContentBlock, 2);
    blocks[0] = .{ .resource_link = .{ .name = "main.rs", .uri = "file:///project/src/main.rs", .mimeType = "text/x-rust" } };
    blocks[1] = .{ .resource = .{ .resource = .{ .blob = .{ .uri = "file:///project/logo.png", .mimeType = "image/png", .blob = "iVBORw0KGgo=" } } } };
    return .{ .complete = .{ .content = blocks } };
}

// Returns structured content, a plain text result or a tool error, as `mode` tells.
fn weather(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    const mode = json.getString(args, "mode") orelse "structured";
    if (std.mem.eql(u8, mode, "structured")) {
        return .{ .complete = .{ .content = &.{}, .structuredContent = try json.parseTree(ctx.arena, "{\"temperature\":21}") } };
    }
    if (std.mem.eql(u8, mode, "text_only")) {
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "21 degrees", .{}) };
    }
    return .{ .complete = try types.CallToolResult.err(ctx.arena, "sensor offline", .{}) };
}

var seen_ids: [8]i64 = undefined;
var seen_count: usize = 0;

// Records the JSON-RPC id of every round, then asks for a name once.
fn recordIds(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (seen_count < seen_ids.len) {
        seen_ids[seen_count] = switch (ctx.id) {
            .integer => |i| i,
            else => -1,
        };
        seen_count += 1;
    }
    if (try ctx.elicitResponse("name")) |_| return .{ .complete = try types.CallToolResult.text(ctx.arena, "done", .{}) };
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("name", "Name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Alice\"}") };
}

// A server with two tools, two prompts and two resources.
fn populate(server: *Server) !void {
    try server.addToolJson(.{ .name = "alpha" }, okTool);
    try server.addToolJson(.{ .name = "beta" }, okTool);
    try server.addPrompt(.{ .name = "first" }, simplePrompt);
    try server.addPrompt(.{ .name = "second" }, simplePrompt);
    try server.addResource(.{ .uri = "test://one", .name = "one" }, readText);
    try server.addResource(.{ .uri = "test://two", .name = "two" }, readText);
}

// -- Tests -------------------------------------------------------------------------------------

test "registering tools, prompts and resources declares their capabilities in discover" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    var h: Harness = .init(std.testing.io, gpa, &server);
    defer h.deinit();

    // Nothing registered: no capability, and the gated methods do not exist.
    const empty = result(try call(&h, arena, 1, "server/discover", meta_none, "")).object.get("capabilities").?;
    try std.testing.expect(absent(empty, "tools"));
    try std.testing.expect(absent(empty, "prompts"));
    try std.testing.expect(absent(empty, "resources"));
    try std.testing.expectEqual(@as(i64, -32601), errorCode(try call(&h, arena, 2, "tools/list", meta_none, "")).?);
    try std.testing.expectEqual(@as(i64, -32601), errorCode(try call(&h, arena, 3, "prompts/list", meta_none, "")).?);
    try std.testing.expectEqual(@as(i64, -32601), errorCode(try call(&h, arena, 4, "prompts/get", meta_none, "\"name\":\"first\"")).?);
    try std.testing.expectEqual(@as(i64, -32601), errorCode(try call(&h, arena, 5, "resources/read", meta_none, "\"uri\":\"test://one\"")).?);

    // Registration declares each capability with list change support.
    try populate(&server);
    const caps = result(try call(&h, arena, 6, "server/discover", meta_none, "")).object.get("capabilities").?;
    try std.testing.expect(caps.object.get("tools").?.object.get("listChanged").?.bool);
    try std.testing.expect(caps.object.get("prompts").?.object.get("listChanged").?.bool);
    const res_caps = caps.object.get("resources").?;
    try std.testing.expect(res_caps.object.get("listChanged").?.bool);
    try std.testing.expect(res_caps.object.get("subscribe").?.bool);
    try std.testing.expect(errorCode(try call(&h, arena, 7, "prompts/list", meta_none, "")) == null);
    try std.testing.expect(errorCode(try call(&h, arena, 8, "resources/list", meta_none, "")) == null);
}

test "list results are the same on every connection, in the same order, after other requests" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    try populate(&server);
    // Two harnesses are two independent connections to one server.
    var a: Harness = .init(std.testing.io, gpa, &server);
    defer a.deinit();
    var b: Harness = .init(std.testing.io, gpa, &server);
    defer b.deinit();

    const lists = [_]struct { method: []const u8, field: []const u8 }{
        .{ .method = "tools/list", .field = "tools" },
        .{ .method = "prompts/list", .field = "prompts" },
        .{ .method = "resources/list", .field = "resources" },
    };
    var before: [lists.len][]const u8 = undefined;
    for (lists, 0..) |l, i| {
        before[i] = try json.writeAlloc(arena, result(try call(&a, arena, 1, l.method, meta_none, "")).object.get(l.field).?);
    }
    const tools = result(try call(&a, arena, 2, "tools/list", meta_none, "")).object.get("tools").?.array.items;
    try std.testing.expectEqualStrings("alpha", tools[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("beta", tools[1].object.get("name").?.string);

    // Other requests on the second connection change nothing.
    _ = try call(&b, arena, 3, "tools/call", meta_none, "\"name\":\"alpha\",\"arguments\":{}");
    _ = try call(&b, arena, 4, "prompts/get", meta_none, "\"name\":\"first\"");
    _ = try call(&b, arena, 5, "resources/read", meta_none, "\"uri\":\"test://one\"");
    _ = try call(&b, arena, 6, "tools/call", meta_none, "\"name\":\"missing\"");

    for (lists, 0..) |l, i| {
        const on_b = try json.writeAlloc(arena, result(try call(&b, arena, 7, l.method, meta_none, "")).object.get(l.field).?);
        try std.testing.expectEqualStrings(before[i], on_b);
        const again = try json.writeAlloc(arena, result(try call(&a, arena, 8, l.method, meta_none, "")).object.get(l.field).?);
        try std.testing.expectEqualStrings(before[i], again);
    }
}

test "list changes reach listen streams that asked for them and lists show only available items" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, io, .{ .info = info });
    defer server.deinit();
    try populate(&server);
    var stream: Harness = .init(io, gpa, &server);
    defer stream.deinit();
    var other: Harness = .init(io, gpa, &server);
    defer other.deinit();

    var token: Transport.CancelToken = .{};
    const frame = try request(arena, 50, "subscriptions/listen", meta_none, "\"notifications\":{\"toolsListChanged\":true,\"promptsListChanged\":true,\"resourcesListChanged\":true}");
    var future = try io.concurrent(Harness.sendWithToken, .{ &stream, frame, &token });
    var spins: usize = 0;
    while (stream.out.items.len == 0 and spins < 200) : (spins += 1) try io.sleep(.fromMilliseconds(5), .awake);
    try std.testing.expectEqual(1, stream.out.items.len);

    // Disabling a tool and a prompt publishes the changes. The application announces resource changes.
    try std.testing.expect(server.setToolEnabled(io, "beta", false));
    try std.testing.expect(server.setPromptEnabled(io, "second", false));
    server.notifyResourcesListChanged(io);
    try std.testing.expectEqual(4, stream.out.items.len);
    const expected = [_][]const u8{ "notifications/tools/list_changed", "notifications/prompts/list_changed", "notifications/resources/list_changed" };
    for (expected, 1..) |method, i| {
        const note = try json.parseTree(arena, try arena.dupe(u8, stream.out.items[i]));
        try std.testing.expectEqualStrings(method, note.object.get("method").?.string);
        try std.testing.expectEqual(@as(i64, 50), note.object.get("params").?.object.get("_meta").?.object.get("io.modelcontextprotocol/subscriptionId").?.integer);
    }

    // The lists now hold only the available items, and a disabled tool cannot be called.
    const tools = result(try call(&other, arena, 51, "tools/list", meta_none, "")).object.get("tools").?.array.items;
    try std.testing.expectEqual(1, tools.len);
    try std.testing.expectEqualStrings("alpha", tools[0].object.get("name").?.string);
    const prompts = result(try call(&other, arena, 52, "prompts/list", meta_none, "")).object.get("prompts").?.array.items;
    try std.testing.expectEqual(1, prompts.len);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try call(&other, arena, 53, "tools/call", meta_none, "\"name\":\"beta\"")).?);

    server.shutdownSubscriptions(io);
    try future.await(io);
    try std.testing.expect(stream.finished);
}

test "tool names follow the length, character, case and uniqueness rules" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    var h: Harness = .init(std.testing.io, gpa, &server);
    defer h.deinit();

    // Length from 1 to 128 characters.
    try std.testing.expectError(error.InvalidToolName, server.addToolJson(.{ .name = "" }, okTool));
    try std.testing.expectError(error.InvalidToolName, server.addToolJson(.{ .name = "a" ** 129 }, okTool));
    try server.addToolJson(.{ .name = "a" ** 128 }, okTool);
    try server.addToolJson(.{ .name = "x" }, okTool);
    // Only ASCII letters, digits, underscore, hyphen and dot.
    for ([_][]const u8{ "get user", "get,user", "get/user", "get:user", "get@user", "caf\xc3\xa9", "tab\tname" }) |bad| {
        try std.testing.expectError(error.InvalidToolName, server.addToolJson(.{ .name = bad }, okTool));
    }
    for ([_][]const u8{ "getUser", "DATA_EXPORT_v2", "admin.tools.list", "get-user" }) |good| {
        try server.addToolJson(.{ .name = good }, okTool);
    }
    // Unique within the server, and case-sensitive.
    try std.testing.expectError(error.DuplicateName, server.addToolJson(.{ .name = "getUser" }, okTool));
    try server.addToolJson(.{ .name = "GetUser" }, okTool);
    try std.testing.expect(errorCode(try call(&h, arena, 1, "tools/call", meta_none, "\"name\":\"getUser\"")) == null);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try call(&h, arena, 2, "tools/call", meta_none, "\"name\":\"GETUSER\"")).?);
}

test "a tool input schema must be a valid JSON Schema object" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    var h: Harness = .init(std.testing.io, gpa, &server);
    defer h.deinit();

    try std.testing.expectError(error.SchemaNotObject, server.addToolJson(.{ .name = "n1", .input_schema = "null" }, okTool));
    try std.testing.expectError(error.SchemaNotObject, server.addToolJson(.{ .name = "n2", .input_schema = "[]" }, okTool));
    try std.testing.expectError(error.SchemaNotObject, server.addToolJson(.{ .name = "n3", .input_schema = "{\"type\":\"string\"}" }, okTool));
    try std.testing.expectError(error.InvalidSchema, server.addToolJson(.{ .name = "n4", .input_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"int\"}}}" }, okTool));
    try std.testing.expectError(error.InvalidSchema, server.addToolJson(.{ .name = "n5", .input_schema = "{\"type\":" }, okTool));
    try std.testing.expectError(error.SchemaNotObject, server.addToolJson(.{ .name = "n6", .output_schema = "null" }, okTool));

    // A tool without parameters gets an object schema, never null.
    try server.addToolJson(.{ .name = "no_params" }, okTool);
    const tools = result(try call(&h, arena, 1, "tools/list", meta_none, "")).object.get("tools").?.array.items;
    try std.testing.expectEqual(1, tools.len);
    const schema = tools[0].object.get("inputSchema").?;
    try std.testing.expect(schema == .object);
    try std.testing.expectEqualStrings("object", schema.object.get("type").?.string);
}

test "x-mcp-header annotations that break the constraints are rejected at registration" {
    const gpa = std.testing.allocator;
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();

    const bad_schemas = [_][]const u8{
        // Empty.
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":""}}}
        ,
        // Not a token: space, colon, non-ASCII.
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"My Region"}}}
        ,
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region:Primary"}}}
        ,
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"R\u00e9gion"}}}
        ,
        // Control characters: CR, LF and tab.
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region\r\nX-Evil: 1"}}}
        ,
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region\n"}}}
        ,
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"Region\t1"}}}
        ,
        // Not unique, also when the case differs.
        \\{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Region"},"b":{"type":"string","x-mcp-header":"Region"}}}
        ,
        \\{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"MyField"},"b":{"type":"integer","x-mcp-header":"myfield"}}}
        ,
        // Not a primitive type.
        \\{"type":"object","properties":{"v":{"type":"number","x-mcp-header":"V"}}}
        ,
        \\{"type":"object","properties":{"v":{"type":"object","x-mcp-header":"V"}}}
        ,
        \\{"type":"object","properties":{"v":{"type":"array","items":{"type":"string"},"x-mcp-header":"V"}}}
        ,
        \\{"type":"object","properties":{"v":{"type":"null","x-mcp-header":"V"}}}
        ,
        // Not a string.
        \\{"type":"object","properties":{"v":{"type":"string","x-mcp-header":7}}}
        ,
    };
    for (bad_schemas, 0..) |schema, i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "bad_{d}", .{i});
        try std.testing.expectError(error.InvalidHeaderAnnotation, server.addToolJson(.{ .name = name, .input_schema = schema }, okTool));
    }
    // Token characters on string, integer and boolean parameters are accepted.
    try server.addToolJson(.{
        .name = "good",
        .input_schema =
        \\{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"priority":{"type":"integer","x-mcp-header":"X-Priority_1"},"verbose":{"type":"boolean","x-mcp-header":"Verbose!#$%&'*+.^`|~"}}}
        ,
    }, okTool);
}

test "the client drops tools with invalid x-mcp-header annotations from tools/list" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var map: mcp.transport.tool_headers.Map = .init(gpa, std.testing.io);
    defer map.deinit();

    const frame =
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[
        \\{"name":"valid_tool","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}},
        \\{"name":"invalid_empty","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":""}}}},
        \\{"name":"invalid_space","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"My Region"}}}},
        \\{"name":"invalid_crlf","inputSchema":{"type":"object","properties":{"v":{"type":"string","x-mcp-header":"A\r\nB"}}}},
        \\{"name":"invalid_duplicate","inputSchema":{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"X"},"b":{"type":"string","x-mcp-header":"x"}}}},
        \\{"name":"invalid_number","inputSchema":{"type":"object","properties":{"v":{"type":"number","x-mcp-header":"V"}}}},
        \\{"name":"plain_tool","inputSchema":{"type":"object"}}
        \\]}}
    ;
    const rewritten = (try map.learn(arena, frame)) orelse return error.TestExpectedRewrite;
    const tree = try json.parseTree(arena, rewritten);
    const tools = result(tree).object.get("tools").?.array.items;
    try std.testing.expectEqual(2, tools.len);
    try std.testing.expectEqualStrings("valid_tool", tools[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("plain_tool", tools[1].object.get("name").?.string);

    // The valid tool keeps its header binding. The rejected tools have none.
    var headers: std.ArrayList(mcp.transport.tool_headers.Header) = .empty;
    const args = try json.parseTree(arena, "{\"region\":\"us-west1\",\"v\":\"x\"}");
    try map.appendParamHeaders(arena, &headers, "valid_tool", args, false);
    try std.testing.expectEqual(1, headers.items.len);
    try std.testing.expectEqualStrings("mcp-param-Region", headers.items[0].name);
    try std.testing.expectEqualStrings("us-west1", headers.items[0].value);
    try map.appendParamHeaders(arena, &headers, "invalid_empty", args, false);
    try std.testing.expectEqual(1, headers.items.len);

    // A list with only valid tools is passed on unchanged.
    const clean =
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[{"name":"valid_tool","inputSchema":{"type":"object"}}]}}
    ;
    try std.testing.expect((try map.learn(arena, clean)) == null);
}

test "structured content is mirrored into a text block and must match the output schema" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    try server.addToolJson(.{
        .name = "weather",
        .input_schema = "{\"type\":\"object\",\"properties\":{\"mode\":{\"type\":\"string\"}}}",
        .output_schema = "{\"type\":\"object\",\"properties\":{\"temperature\":{\"type\":\"integer\"}},\"required\":[\"temperature\"]}",
    }, weather);
    var h: Harness = .init(std.testing.io, gpa, &server);
    defer h.deinit();

    // The handler gave no text block: the serialized JSON is added as one.
    const ok = result(try call(&h, arena, 1, "tools/call", meta_none, "\"name\":\"weather\",\"arguments\":{\"mode\":\"structured\"}"));
    try std.testing.expectEqual(21, ok.object.get("structuredContent").?.object.get("temperature").?.integer);
    const content = ok.object.get("content").?.array.items;
    try std.testing.expectEqual(1, content.len);
    try std.testing.expectEqualStrings("text", content[0].object.get("type").?.string);
    const mirrored = try json.parseTree(arena, content[0].object.get("text").?.string);
    try std.testing.expectEqual(21, mirrored.object.get("temperature").?.integer);

    // A result without structured content breaks the output schema: a server error.
    try std.testing.expectEqual(@as(i64, -32603), errorCode(try call(&h, arena, 2, "tools/call", meta_none, "\"name\":\"weather\",\"arguments\":{\"mode\":\"text_only\"}")).?);
    // A tool execution error needs no structured content.
    const failed = result(try call(&h, arena, 3, "tools/call", meta_none, "\"name\":\"weather\",\"arguments\":{\"mode\":\"error\"}"));
    try std.testing.expect(failed.object.get("isError").?.bool);
}

test "tool and prompt results carry resource links and embedded resources" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    try server.addToolJson(.{ .name = "links" }, toolWithLinks);
    try server.addPrompt(.{ .name = "links" }, promptWithLinks);
    var h: Harness = .init(std.testing.io, gpa, &server);
    defer h.deinit();

    const tool = result(try call(&h, arena, 1, "tools/call", meta_none, "\"name\":\"links\"")).object.get("content").?.array.items;
    try std.testing.expectEqualStrings("resource_link", tool[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("file:///project/src/main.rs", tool[0].object.get("uri").?.string);
    try std.testing.expectEqualStrings("resource", tool[1].object.get("type").?.string);
    const blob = tool[1].object.get("resource").?;
    try std.testing.expectEqualStrings("file:///project/logo.png", blob.object.get("uri").?.string);
    try std.testing.expectEqualStrings("image/png", blob.object.get("mimeType").?.string);
    try std.testing.expectEqualStrings("iVBORw0KGgo=", blob.object.get("blob").?.string);

    const messages = result(try call(&h, arena, 2, "prompts/get", meta_none, "\"name\":\"links\"")).object.get("messages").?.array.items;
    const link = messages[0].object.get("content").?;
    try std.testing.expectEqualStrings("resource_link", link.object.get("type").?.string);
    try std.testing.expectEqualStrings("text/x-rust", link.object.get("mimeType").?.string);
    const embedded = messages[1].object.get("content").?;
    try std.testing.expectEqualStrings("resource", embedded.object.get("type").?.string);
    try std.testing.expectEqualStrings("resource://example", embedded.object.get("resource").?.object.get("uri").?.string);
    try std.testing.expectEqualStrings("Resource content", embedded.object.get("resource").?.object.get("text").?.string);
}

test "prompts/get validates arguments, reports handler failures and supports input required" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    try server.addPrompt(.{ .name = "review", .arguments = &.{.{ .name = "code", .required = true }} }, simplePrompt);
    try server.addPrompt(.{ .name = "broken" }, promptFails);
    try server.addPrompt(.{ .name = "ask" }, promptAsks);
    var h: Harness = .init(std.testing.io, gpa, &server);
    defer h.deinit();

    // Invalid name, missing required argument and an argument that is not a string: -32602.
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try call(&h, arena, 1, "prompts/get", meta_none, "\"name\":\"nope\"")).?);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try call(&h, arena, 2, "prompts/get", meta_none, "\"name\":\"review\",\"arguments\":{}")).?);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try call(&h, arena, 3, "prompts/get", meta_none, "\"name\":\"review\",\"arguments\":{\"code\":5}")).?);
    try std.testing.expect(errorCode(try call(&h, arena, 4, "prompts/get", meta_none, "\"name\":\"review\",\"arguments\":{\"code\":\"x\"}")) == null);
    // A handler failure is an internal error.
    try std.testing.expectEqual(@as(i64, -32603), errorCode(try call(&h, arena, 5, "prompts/get", meta_none, "\"name\":\"broken\"")).?);

    // Input required, then the complete prompt on the retry.
    const first = result(try call(&h, arena, 6, "prompts/get", meta_elicit, "\"name\":\"ask\""));
    try std.testing.expectEqualStrings("input_required", first.object.get("resultType").?.string);
    try std.testing.expect(first.object.get("inputRequests").?.object.get("topic") != null);
    const second = result(try call(&h, arena, 7, "prompts/get", meta_elicit, "\"name\":\"ask\",\"inputResponses\":{\"topic\":{\"action\":\"accept\",\"content\":{\"topic\":\"zig\"}}}"));
    try std.testing.expectEqualStrings("complete", second.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("write about zig", second.object.get("messages").?.array.items[0].object.get("content").?.object.get("text").?.string);
}

test "resources/read returns several contents, never empty contents, and reports failures" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, std.testing.io, .{ .info = info });
    defer server.deinit();
    try server.addResource(.{ .uri = "test://dir", .name = "dir", .mime_type = "inode/directory" }, readTwo);
    try server.addResource(.{ .uri = "test://empty", .name = "empty" }, readEmpty);
    try server.addResource(.{ .uri = "test://broken", .name = "broken" }, readFails);
    try server.addResource(.{ .uri = "test://locked", .name = "locked" }, readAsks);
    var h: Harness = .init(std.testing.io, gpa, &server);
    defer h.deinit();

    // Several contents for one read.
    const dir = result(try call(&h, arena, 1, "resources/read", meta_none, "\"uri\":\"test://dir\"")).object.get("contents").?.array.items;
    try std.testing.expectEqual(2, dir.len);
    try std.testing.expectEqualStrings("a", dir[0].object.get("text").?.string);
    try std.testing.expectEqualStrings("AAEC", dir[1].object.get("blob").?.string);

    // Empty contents from a handler become "not found", not an empty array.
    const empty = try call(&h, arena, 2, "resources/read", meta_none, "\"uri\":\"test://empty\"");
    try std.testing.expect(empty.object.get("result") == null);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(empty).?);
    try std.testing.expectEqualStrings("test://empty", empty.object.get("error").?.object.get("data").?.object.get("uri").?.string);
    // An unknown URI is also -32602 without a result.
    const missing = try call(&h, arena, 3, "resources/read", meta_none, "\"uri\":\"test://missing\"");
    try std.testing.expect(missing.object.get("result") == null);
    try std.testing.expectEqual(@as(i64, -32602), errorCode(missing).?);
    // A handler failure is an internal error.
    try std.testing.expectEqual(@as(i64, -32603), errorCode(try call(&h, arena, 4, "resources/read", meta_none, "\"uri\":\"test://broken\"")).?);

    // Input required, then the contents on the retry.
    const first = result(try call(&h, arena, 5, "resources/read", meta_elicit, "\"uri\":\"test://locked\""));
    try std.testing.expectEqualStrings("input_required", first.object.get("resultType").?.string);
    try std.testing.expect(first.object.get("inputRequests").?.object.get("password") != null);
    const second = result(try call(&h, arena, 6, "resources/read", meta_elicit, "\"uri\":\"test://locked\",\"inputResponses\":{\"password\":{\"action\":\"accept\",\"content\":{\"password\":\"open\"}}}"));
    try std.testing.expectEqualStrings("unlocked with open", second.object.get("contents").?.array.items[0].object.get("text").?.string);
}

test "the client retries an input required request with a new JSON-RPC id" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, io, .{ .info = info });
    defer server.deinit();
    try server.addToolJson(.{ .name = "record" }, recordIds);
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var client: Client = .init(gpa, io, .{
        .info = info,
        .capabilities = .{ .elicitation = .{} },
        .hooks = .{ .elicit_form = answerForm },
    });
    defer client.deinit();
    client.connect(link.transport());

    seen_count = 0;
    const done = try client.callTool(arena, "record", null, .{});
    try std.testing.expectEqualStrings("done", done.content[0].text.text);
    try std.testing.expectEqual(2, seen_count);
    try std.testing.expect(seen_ids[0] != seen_ids[1]);
}

test "the client pages through a long prompt list with the cursor" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var options: Server.Options = .{ .info = info };
    options.limits.page_size = 2;
    var server = try Server.init(gpa, io, options);
    defer server.deinit();
    const names = [_][]const u8{ "p1", "p2", "p3", "p4", "p5" };
    for (names) |n| try server.addPrompt(.{ .name = n }, simplePrompt);
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var client: Client = .init(gpa, io, .{ .info = info });
    defer client.deinit();
    client.connect(link.transport());

    var seen: usize = 0;
    var pages: usize = 0;
    var cursor: ?[]const u8 = null;
    while (true) {
        const page = try client.listPrompts(arena, cursor, .{});
        pages += 1;
        for (page.prompts) |p| {
            try std.testing.expectEqualStrings(names[seen], p.name);
            seen += 1;
        }
        cursor = page.nextCursor orelse break;
    }
    try std.testing.expectEqual(names.len, seen);
    try std.testing.expectEqual(3, pages);
}
