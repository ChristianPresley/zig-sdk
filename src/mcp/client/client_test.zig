//! Client behaviour over the in-memory link to a server.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const types = mcp.types;
const json = mcp.json;

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(1, 2, "adding");
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

fn askName(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        if (resp.action != .accept) return .{ .complete = try types.CallToolResult.text(ctx.arena, "declined", .{}) };
        const name = json.getString(resp.content.?, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    try ir.setStateFmt("{{\"round\":{d}}}", .{1});
    return .{ .input_required = ir };
}

fn everything(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (ctx.hasAllResponses(&.{ "name", "greeting", "roots" })) {
        const roots = (try ctx.rootsResponse("roots")).?;
        const greeting = (try ctx.sampleResponse("greeting")).?;
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d} roots, model {s}", .{ roots.roots.len, greeting.model }) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("name", "Name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    const messages = try ctx.arena.alloc(types.SamplingMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .single = .{ .text = .{ .text = "hi" } } } };
    try ir.sample("greeting", .{ .messages = messages, .maxTokens = 10 });
    try ir.listRoots("roots");
    return .{ .input_required = ir };
}

fn readStatic(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "static text" } };
    return .{ .complete = .{ .contents = contents } };
}

const Fixture = struct {
    server: Server,
    link: mcp.transport.memory.ClientLink,
    client: Client,

    fn init(self: *Fixture, options: Client.Options) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try Server.init(gpa, io, .{ .info = .{ .name = "srv", .version = "1" }, .mrtr = .{ .elicitation = true, .sampling = true, .roots = true } });
        try self.server.addTool(.{ .name = "add" }, add);
        try self.server.addToolJson(.{ .name = "ask_name" }, askName);
        try self.server.addToolJson(.{ .name = "everything" }, everything);
        try self.server.addResource(.{ .uri = "test://static", .name = "static" }, readStatic);
        self.link = .init(io, gpa, &self.server);
        self.client = .init(gpa, io, options);
        self.client.connect(self.link.transport());
    }

    fn deinit(self: *Fixture) void {
        self.client.deinit();
        self.server.deinit();
    }
};

const Recorder = struct {
    progress: u32 = 0,
    fn onProgress(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
        const self: *Recorder = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.progress += 1;
    }
};

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    const content = try json.parseTree(ctx.arena, "{\"name\":\"Alice\"}");
    return .{ .action = .accept, .content = content };
}

fn answerSample(ctx: *Client.HookContext, params: types.CreateMessageRequestParams) anyerror!types.CreateMessageResult {
    _ = ctx;
    _ = params;
    return .{ .role = .assistant, .content = .{ .single = .{ .text = .{ .text = "hello" } } }, .model = "test-model" };
}

fn listRoots(ctx: *Client.HookContext) anyerror![]const types.Root {
    const roots = try ctx.arena.alloc(types.Root, 2);
    roots[0] = .{ .uri = "file:///a" };
    roots[1] = .{ .uri = "file:///b" };
    return roots;
}

test "discover, list and call through the memory link" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "cli", .version = "1" } });
    defer f.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try f.client.discover(arena, .{});
    try std.testing.expectEqualStrings("2026-07-28", disc.supportedVersions[0]);
    const tools = try f.client.listTools(arena, null, .{});
    try std.testing.expectEqual(3, tools.tools.len);

    var rec: Recorder = .{};
    const result = try f.client.callTool(arena, "add", .{ .a = 2, .b = 3 }, .{ .on_progress = Recorder.onProgress, .userdata = &rec });
    try std.testing.expectEqualStrings("5", result.content[0].text.text);
    try std.testing.expectEqual(1, rec.progress);

    const res = try f.client.readResource(arena, "test://static", .{});
    try std.testing.expectEqualStrings("static text", res.contents[0].text.text);

    // An unknown tool is a JSON-RPC error with diagnostics.
    var diag: Client.Diagnostics = .{};
    try std.testing.expectError(error.Rpc, f.client.callTool(arena, "nope", null, .{ .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
}

test "multi round-trip requests are driven by the hooks" {
    var f: Fixture = undefined;
    try f.init(.{
        .info = .{ .name = "cli", .version = "1" },
        .capabilities = .{ .elicitation = .{}, .sampling = .{}, .roots = .{} },
        .hooks = .{ .elicit_form = answerForm, .sample = answerSample, .list_roots = listRoots },
    });
    defer f.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const one = try f.client.callTool(arena, "ask_name", null, .{});
    try std.testing.expectEqualStrings("hello Alice", one.content[0].text.text);
    const all = try f.client.callTool(arena, "everything", null, .{});
    try std.testing.expectEqualStrings("2 roots, model test-model", all.content[0].text.text);

    // The raw result is returned when the caller wants to drive the rounds itself.
    const raw = try f.client.request(arena, .@"tools/call", try json.parseTree(arena, "{\"name\":\"ask_name\"}"), .{ .allow_input_required = true });
    try std.testing.expect(raw.input_required != null);
    try std.testing.expect(raw.input_required.?.inputRequests.?.map.get("user_name") != null);
}

test "undeclared input kinds are rejected on the client" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "cli", .version = "1" }, .capabilities = .{ .elicitation = .{} }, .hooks = .{ .elicit_form = answerForm } });
    defer f.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The server declared sampling and roots as MRTR kinds but this client did not: the
    // server only asks for what the client declared, so the tool cannot finish.
    var diag: Client.Diagnostics = .{};
    const r = f.client.callTool(arena, "everything", null, .{ .diagnostics = &diag });
    try std.testing.expect(r == error.Rpc or r == error.UndeclaredInputRequest);
}
