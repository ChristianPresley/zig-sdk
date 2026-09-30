//! Tests for the client pages of the specification: elicitation, roots and sampling.
//! The tests use the in-memory link and a scripted client transport.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const Transport = mcp.transport.Transport;
const Harness = mcp.transport.memory.Harness;
const types = mcp.types;
const json = mcp.json;

// -- Server handlers ----------------------------------------------------------------------------

fn askForm(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("name")) |resp| return .{ .complete = try types.CallToolResult.text(ctx.arena, "form {t}", .{resp.action}) };
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("name", "Name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn askUrl(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("link")) |resp| return .{ .complete = try types.CallToolResult.text(ctx.arena, "url {t}", .{resp.action}) };
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitUrl("link", "Open the page to connect.", "https://example.com/connect");
    return .{ .input_required = ir };
}

fn userMessage(ctx: *RequestContext, text: []const u8) ![]const types.SamplingMessage {
    const messages = try ctx.arena.alloc(types.SamplingMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .single = .{ .text = .{ .text = text } } } };
    return messages;
}

fn askSample(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.sampleResponse("reply")) |resp| return .{ .complete = try types.CallToolResult.text(ctx.arena, "model {s}", .{resp.model}) };
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.sample("reply", .{ .messages = try userMessage(ctx, "hi"), .maxTokens = 10 });
    return .{ .input_required = ir };
}

fn askSampleTools(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.sampleResponse("weather")) |resp| return .{ .complete = try types.CallToolResult.text(ctx.arena, "model {s}", .{resp.model}) };
    const tools = try ctx.arena.alloc(types.Tool, 1);
    tools[0] = .{ .name = "get_weather", .inputSchema = try json.parseTree(ctx.arena, "{\"type\":\"object\"}") };
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.sample("weather", .{ .messages = try userMessage(ctx, "What is the weather?"), .maxTokens = 100, .tools = tools });
    return .{ .input_required = ir };
}

fn askRoots(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.rootsResponse("roots")) |resp| return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d} roots", .{resp.roots.len}) };
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.listRoots("roots");
    return .{ .input_required = ir };
}

var loop_calls: u32 = 0;

/// Asks for input on every round and never completes.
fn endless(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    loop_calls += 1;
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("again", "Again?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn initServer(server: *Server) !void {
    server.* = try Server.init(std.testing.allocator, std.testing.io, .{
        .info = .{ .name = "srv", .version = "1" },
        .mrtr = .{ .elicitation = true, .sampling = true, .sampling_tools = true, .roots = true },
    });
    errdefer server.deinit();
    try server.addToolJson(.{ .name = "ask_form" }, askForm);
    try server.addToolJson(.{ .name = "ask_url" }, askUrl);
    try server.addToolJson(.{ .name = "ask_sample" }, askSample);
    try server.addToolJson(.{ .name = "ask_sample_tools" }, askSampleTools);
    try server.addToolJson(.{ .name = "ask_roots" }, askRoots);
    try server.addToolJson(.{ .name = "endless" }, endless);
}

// -- Raw server calls through the harness -------------------------------------------------------

fn metaWith(arena: std.mem.Allocator, caps: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{s}}}", .{caps});
}

/// Call a tool with the given client capabilities and return the parsed response frame.
fn rawCall(h: *Harness, arena: std.mem.Allocator, id: i64, caps: []const u8, extra: []const u8) !Value {
    h.clear();
    const text = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"tools/call\",\"params\":{{{s},{s}}}}}", .{ id, try metaWith(arena, caps), extra });
    try h.send(text);
    try std.testing.expect(h.finished);
    return json.parseTree(arena, h.last().?);
}

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

fn requiredCaps(v: Value) Value {
    return v.object.get("error").?.object.get("data").?.object.get("requiredCapabilities").?;
}

fn result(v: Value) Value {
    return v.object.get("result").?;
}

// -- Client transports --------------------------------------------------------------------------

/// Wraps a client transport and keeps a copy of every request frame.
const Recording = struct {
    inner: Transport.ClientTransport,
    frames: std.ArrayList([]u8) = .empty,

    fn transport(self: *Recording) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn deinit(self: *Recording) void {
        for (self.frames.items) |f| std.testing.allocator.free(f);
        self.frames.deinit(std.testing.allocator);
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .memory, .exchange = exchange, .notify = notify };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Recording = @ptrCast(@alignCast(ptr));
        const copy = try std.testing.allocator.dupe(u8, ex.frame);
        errdefer std.testing.allocator.free(copy);
        try self.frames.append(std.testing.allocator, copy);
        return self.inner.exchange(io, ex);
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const self: *Recording = @ptrCast(@alignCast(ptr));
        return self.inner.notify(io, frame);
    }
};

/// Answers each request with the next scripted result. The last result repeats.
const Scripted = struct {
    results: []const []const u8,
    exchanges: usize = 0,

    fn transport(self: *Scripted) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .memory, .exchange = exchange, .notify = notify };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Scripted = @ptrCast(@alignCast(ptr));
        const body = self.results[@min(self.exchanges, self.results.len - 1)];
        self.exchanges += 1;
        var buf: [2048]u8 = undefined;
        const frame = std.fmt.bufPrint(&buf, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{s}}}", .{ ex.id.integer, body }) catch return error.OutOfMemory;
        ex.sink.deliver(io, frame) catch return error.InvalidFrame;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = ptr;
        _ = io;
        _ = frame;
    }
};

const complete_text =
    \\{"resultType":"complete","content":[{"type":"text","text":"done"}]}
;

// -- Client hooks -------------------------------------------------------------------------------

/// Records the hook calls of one client.
const Calls = struct {
    form: u32 = 0,
    url: u32 = 0,
    sample: u32 = 0,
    form_message: []const u8 = "",
    /// The root URI that `listRoots` returns.
    root_uri: []const u8 = "file:///workspace",
};

fn calls(ctx: *Client.HookContext) *Calls {
    return @ptrCast(@alignCast(ctx.userdata.?));
}

fn acceptForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    const c = calls(ctx);
    c.form += 1;
    c.form_message = try ctx.arena.dupe(u8, params.message);
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Alice\"}") };
}

fn acceptUrl(ctx: *Client.HookContext, params: types.ElicitRequestURLParams) anyerror!types.ElicitResult {
    _ = params;
    calls(ctx).url += 1;
    return .{ .action = .accept };
}

fn sample(ctx: *Client.HookContext, params: types.CreateMessageRequestParams) anyerror!types.CreateMessageResult {
    _ = params;
    calls(ctx).sample += 1;
    return .{ .role = .assistant, .content = .{ .single = .{ .text = .{ .text = "hello" } } }, .model = "test-model" };
}

fn listRoots(ctx: *Client.HookContext) anyerror![]const types.Root {
    const roots = try ctx.arena.alloc(types.Root, 1);
    roots[0] = .{ .uri = calls(ctx).root_uri };
    return roots;
}

const all_hooks: Client.Hooks = .{ .elicit_form = acceptForm, .elicit_url = acceptUrl, .sample = sample, .list_roots = listRoots };

// -- Tests --------------------------------------------------------------------------------------

test "client declares elicitation, sampling and roots in _meta on every round" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var rec: Recording = .{ .inner = link.transport() };
    defer rec.deinit();
    var c: Calls = .{};
    var hooks = all_hooks;
    hooks.userdata = &c;
    var client: Client = .init(gpa, io, .{
        .info = .{ .name = "cli", .version = "1" },
        .capabilities = .{ .elicitation = .{}, .sampling = .{}, .roots = .{} },
        .hooks = hooks,
    });
    defer client.deinit();
    client.connect(rec.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const r = try client.callTool(arena, "ask_form", null, .{});
    try std.testing.expectEqualStrings("form accept", r.content[0].text.text);
    _ = try client.listTools(arena, null, .{});
    // Two rounds of the tool call and one list request.
    try std.testing.expectEqual(3, rec.frames.items.len);
    for (rec.frames.items) |frame| {
        const v = try json.parseTree(arena, frame);
        const caps = v.object.get("params").?.object.get("_meta").?.object.get("io.modelcontextprotocol/clientCapabilities").?;
        try std.testing.expect(caps.object.get("elicitation") != null);
        try std.testing.expect(caps.object.get("sampling") != null);
        try std.testing.expect(caps.object.get("roots") != null);
    }
    // The retry is a new request that carries the answer.
    const retry = try json.parseTree(arena, rec.frames.items[1]);
    try std.testing.expect(retry.object.get("params").?.object.get("inputResponses").?.object.get("name") != null);
}

test "an empty elicitation capability declares form mode only" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const empty: types.ClientCapabilities = .{ .elicitation = .{} };
    try std.testing.expect(empty.hasElicitation(.form));
    try std.testing.expect(!empty.hasElicitation(.url));
    const out = try json.writeAlloc(arena, empty);
    try std.testing.expectEqualStrings("{\"elicitation\":{}}", out);

    const url_only = try json.parseValue(types.ClientCapabilities, arena, try json.parseTree(arena, "{\"elicitation\":{\"url\":{}}}"));
    try std.testing.expect(url_only.hasElicitation(.url));
    try std.testing.expect(!url_only.hasElicitation(.form));
    const both = try json.parseValue(types.ClientCapabilities, arena, try json.parseTree(arena, "{\"elicitation\":{\"form\":{},\"url\":{}}}"));
    try std.testing.expect(both.hasElicitation(.url) and both.hasElicitation(.form));
    const none: types.ClientCapabilities = .{};
    try std.testing.expect(!none.hasElicitation(.form) and !none.hasElicitation(.url));
}

test "server sends an elicitation mode only when the client declared it" {
    var server: Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var h: Harness = .init(std.testing.io, std.testing.allocator, &server);
    defer h.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A form-only client gets -32021 instead of a URL request.
    const no_url = try rawCall(&h, arena, 1, "{\"elicitation\":{}}", "\"name\":\"ask_url\"");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_url).?);
    try std.testing.expect(requiredCaps(no_url).object.get("elicitation").?.object.get("url") != null);
    const url = result(try rawCall(&h, arena, 2, "{\"elicitation\":{\"url\":{}}}", "\"name\":\"ask_url\""));
    try std.testing.expectEqualStrings("input_required", url.object.get("resultType").?.string);
    const params = url.object.get("inputRequests").?.object.get("link").?.object.get("params").?;
    try std.testing.expectEqualStrings("url", params.object.get("mode").?.string);
    try std.testing.expectEqualStrings("https://example.com/connect", params.object.get("url").?.string);

    // A URL-only client gets -32021 instead of a form request.
    const no_form = try rawCall(&h, arena, 3, "{\"elicitation\":{\"url\":{}}}", "\"name\":\"ask_form\"");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_form).?);
    try std.testing.expect(requiredCaps(no_form).object.get("elicitation").?.object.get("form") != null);
    const form = result(try rawCall(&h, arena, 4, "{\"elicitation\":{}}", "\"name\":\"ask_form\""));
    try std.testing.expectEqualStrings("input_required", form.object.get("resultType").?.string);
}

test "server sends tool-enabled sampling only to clients that declared sampling.tools" {
    var server: Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var h: Harness = .init(std.testing.io, std.testing.allocator, &server);
    defer h.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const no_tools = try rawCall(&h, arena, 1, "{\"sampling\":{}}", "\"name\":\"ask_sample_tools\"");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_tools).?);
    try std.testing.expect(requiredCaps(no_tools).object.get("sampling").?.object.get("tools") != null);

    const with_tools = result(try rawCall(&h, arena, 2, "{\"sampling\":{\"tools\":{}}}", "\"name\":\"ask_sample_tools\""));
    try std.testing.expectEqualStrings("input_required", with_tools.object.get("resultType").?.string);
    const req = with_tools.object.get("inputRequests").?.object.get("weather").?;
    try std.testing.expectEqualStrings("sampling/createMessage", req.object.get("method").?.string);
    try std.testing.expectEqualStrings("get_weather", req.object.get("params").?.object.get("tools").?.array.items[0].object.get("name").?.string);

    // Plain sampling needs the sampling capability.
    const no_sampling = try rawCall(&h, arena, 3, "{}", "\"name\":\"ask_sample\"");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_sampling).?);
    try std.testing.expect(requiredCaps(no_sampling).object.get("sampling") != null);
    const plain = result(try rawCall(&h, arena, 4, "{\"sampling\":{}}", "\"name\":\"ask_sample\""));
    try std.testing.expectEqualStrings("input_required", plain.object.get("resultType").?.string);
}

test "server asks for roots only when the client declared the roots capability" {
    var server: Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var h: Harness = .init(std.testing.io, std.testing.allocator, &server);
    defer h.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const missing = try rawCall(&h, arena, 1, "{\"elicitation\":{},\"sampling\":{}}", "\"name\":\"ask_roots\"");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(missing).?);
    try std.testing.expect(requiredCaps(missing).object.get("roots") != null);
    const ok = result(try rawCall(&h, arena, 2, "{\"roots\":{}}", "\"name\":\"ask_roots\""));
    try std.testing.expectEqualStrings("roots/list", ok.object.get("inputRequests").?.object.get("roots").?.object.get("method").?.string);
}

test "elicitation requests without the required parameters do not parse" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const P = types.ElicitRequestParams;

    // Valid requests: form mode with and without `mode`, and URL mode.
    const explicit_form = try json.parseValue(P, arena, try json.parseTree(arena,
        \\{"mode":"form","message":"Name?","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}}
    ));
    try std.testing.expect(explicit_form == .form);
    const implicit_form = try json.parseValue(P, arena, try json.parseTree(arena,
        \\{"message":"Name?","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}}
    ));
    try std.testing.expect(implicit_form == .form);
    const url = try json.parseValue(P, arena, try json.parseTree(arena,
        \\{"mode":"url","message":"Connect","url":"https://example.com/connect"}
    ));
    try std.testing.expect(url == .url);
    try std.testing.expectEqualStrings("https://example.com/connect", url.url.url);

    const invalid = [_][]const u8{
        // No message.
        \\{"mode":"form","requestedSchema":{"type":"object","properties":{}}}
        ,
        \\{"mode":"url","url":"https://example.com/connect"}
        ,
        // Form mode without requestedSchema.
        \\{"mode":"form","message":"Name?"}
        ,
        \\{"message":"Name?"}
        ,
        // URL mode without url.
        \\{"mode":"url","message":"Connect"}
        ,
        // An unknown mode.
        \\{"mode":"voice","message":"Say it"}
        ,
    };
    for (invalid) |text| {
        const tree = try json.parseTree(arena, text);
        try std.testing.expect(std.meta.isError(json.parseValue(P, arena, tree)));
    }
}

test "client treats an elicitation request without mode as form mode" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const modeless =
        \\{"resultType":"input_required","inputRequests":{"q":{"method":"elicitation/create","params":{"message":"Name?","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}}}}}
    ;

    // A form client answers it with the form hook.
    var script: Scripted = .{ .results = &.{ modeless, complete_text } };
    var c: Calls = .{};
    var hooks = all_hooks;
    hooks.userdata = &c;
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .capabilities = .{ .elicitation = .{} }, .hooks = hooks });
    defer client.deinit();
    client.connect(script.transport());
    const r = try client.callTool(arena, "t", null, .{});
    try std.testing.expectEqualStrings("done", r.content[0].text.text);
    try std.testing.expectEqual(1, c.form);
    try std.testing.expectEqual(0, c.url);
    try std.testing.expectEqualStrings("Name?", c.form_message);

    // A URL-only client refuses it as an undeclared form request.
    var script2: Scripted = .{ .results = &.{ modeless, complete_text } };
    var c2: Calls = .{};
    var hooks2 = all_hooks;
    hooks2.userdata = &c2;
    const url_only = try json.parseValue(types.ClientCapabilities, arena, try json.parseTree(arena, "{\"elicitation\":{\"url\":{}}}"));
    var client2: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .capabilities = url_only, .hooks = hooks2 });
    defer client2.deinit();
    client2.connect(script2.transport());
    try std.testing.expectError(error.UndeclaredInputRequest, client2.callTool(arena, "t", null, .{}));
    try std.testing.expectEqual(0, c2.form);
}

test "client refuses a URL elicitation when it declared form mode only" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{ .results = &.{
        \\{"resultType":"input_required","inputRequests":{"link":{"method":"elicitation/create","params":{"mode":"url","message":"Connect","url":"https://example.com/connect"}}}}
        ,
        complete_text,
    } };
    var c: Calls = .{};
    var hooks = all_hooks;
    hooks.userdata = &c;
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .capabilities = .{ .elicitation = .{} }, .hooks = hooks });
    defer client.deinit();
    client.connect(script.transport());
    try std.testing.expectError(error.UndeclaredInputRequest, client.callTool(arena, "t", null, .{}));
    try std.testing.expectEqual(0, c.url);
    try std.testing.expectEqual(1, script.exchanges);
}

test "client sends only file URIs as roots" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var c: Calls = .{};
    var hooks = all_hooks;
    hooks.userdata = &c;
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .capabilities = .{ .roots = .{} }, .hooks = hooks });
    defer client.deinit();
    client.connect(link.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ok = try client.callTool(arena, "ask_roots", null, .{});
    try std.testing.expectEqualStrings("1 roots", ok.content[0].text.text);
    // A hook that returns a root with another scheme fails the request.
    c.root_uri = "https://example.com/repo";
    try std.testing.expectError(error.HookFailed, client.callTool(arena, "ask_roots", null, .{}));
}

test "sampling messages need a user or assistant role and content" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const M = types.SamplingMessage;

    const user = try json.parseValue(M, arena, try json.parseTree(arena, "{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"hi\"}}"));
    try std.testing.expectEqual(types.Role.user, user.role);
    const assistant = try json.parseValue(M, arena, try json.parseTree(arena, "{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"a\"},{\"type\":\"text\",\"text\":\"b\"}]}"));
    try std.testing.expectEqual(2, assistant.content.list.len);

    const invalid = [_][]const u8{
        "{\"role\":\"system\",\"content\":{\"type\":\"text\",\"text\":\"hi\"}}",
        "{\"content\":{\"type\":\"text\",\"text\":\"hi\"}}",
        "{\"role\":\"user\"}",
    };
    for (invalid) |text| {
        const tree = try json.parseTree(arena, text);
        try std.testing.expect(std.meta.isError(json.parseValue(M, arena, tree)));
    }

    // The client refuses a sampling request with an invalid message and does not call the hook.
    const gpa = std.testing.allocator;
    var script: Scripted = .{ .results = &.{
        \\{"resultType":"input_required","inputRequests":{"s":{"method":"sampling/createMessage","params":{"messages":[{"role":"system","content":{"type":"text","text":"hi"}}],"maxTokens":10}}}}
        ,
        complete_text,
    } };
    var c: Calls = .{};
    var hooks = all_hooks;
    hooks.userdata = &c;
    var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" }, .capabilities = .{ .sampling = .{} }, .hooks = hooks });
    defer client.deinit();
    client.connect(script.transport());
    try std.testing.expectError(error.InvalidResponse, client.callTool(arena, "t", null, .{}));
    try std.testing.expectEqual(0, c.sample);
}

test "server rejects a sampling response with an invalid message" {
    var server: Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var h: Harness = .init(std.testing.io, std.testing.allocator, &server);
    defer h.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bad = try rawCall(&h, arena, 1, "{\"sampling\":{}}",
        \\"name":"ask_sample","inputResponses":{"reply":{"role":"system","content":{"type":"text","text":"x"},"model":"m"}}
    );
    try std.testing.expectEqual(@as(i64, -32602), errorCode(bad).?);
    const good = result(try rawCall(&h, arena, 2, "{\"sampling\":{}}",
        \\"name":"ask_sample","inputResponses":{"reply":{"role":"assistant","content":{"type":"text","text":"x"},"model":"m1"}}
    ));
    try std.testing.expectEqualStrings("model m1", good.object.get("content").?.array.items[0].object.get("text").?.string);
}

test "sampling results accept the standard and custom stop reasons" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const reasons = [_][]const u8{ "endTurn", "stopSequence", "maxTokens", "toolUse", "providerSpecificReason" };
    for (reasons) |reason| {
        const text = try std.fmt.allocPrint(arena, "{{\"role\":\"assistant\",\"content\":{{\"type\":\"text\",\"text\":\"x\"}},\"model\":\"m\",\"stopReason\":\"{s}\"}}", .{reason});
        const r = try json.parseValue(types.CreateMessageResult, arena, try json.parseTree(arena, text));
        try std.testing.expectEqualStrings(reason, r.stopReason.?);
        // The value survives serialization unchanged.
        const out = try json.writeAlloc(arena, r);
        try std.testing.expect(std.mem.indexOf(u8, out, reason) != null);
    }
}

test "client stops a multi round-trip request after the round limit" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: Server = undefined;
    try initServer(&server);
    defer server.deinit();
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var c: Calls = .{};
    var hooks = all_hooks;
    hooks.userdata = &c;
    var client: Client = .init(gpa, io, .{
        .info = .{ .name = "cli", .version = "1" },
        .capabilities = .{ .elicitation = .{} },
        .hooks = hooks,
        .limits = .{ .mrtr_max_rounds_client = 3 },
    });
    defer client.deinit();
    client.connect(link.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    loop_calls = 0;
    try std.testing.expectError(error.TooManyRounds, client.callTool(arena, "endless", null, .{}));
    try std.testing.expectEqual(3, loop_calls);
    try std.testing.expectEqual(3, c.form);
}
