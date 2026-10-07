//! Client behavior over the in-memory link to a server.
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

fn slowTask(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (!ctx.inTask()) return .start_task;
    try ctx.io.sleep(.fromMilliseconds(20), .awake);
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content.?, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "task hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

/// Reports the `_meta` entries that reached the server: the log level, `traceparent` and
/// `com.example/x`.
fn inspectMeta(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const m = ctx.params.?.object.get("_meta").?;
    const level = if (ctx.meta.log_level) |l| @tagName(l) else "none";
    const trace = json.getString(m, "traceparent") orelse "none";
    const vendor = json.getString(m, "com.example/x") orelse "none";
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s} {s} {s}", .{ level, trace, vendor }) };
}

var read_count: std.atomic.Value(u32) = .init(0);

fn readCounted(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    _ = read_count.fetchAdd(1, .monotonic);
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "counted" } };
    return .{ .complete = .{ .contents = contents } };
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
        self.server = try Server.init(gpa, io, .{ .info = .{ .name = "srv", .version = "1" }, .mrtr = .{ .elicitation = true, .sampling = true, .roots = true }, .tasks = .{ .poll_interval_ms = 10 }, .cache = .{ .reads = .{ .ttl_ms = 60_000 } } });
        try self.server.addTool(.{ .name = "add" }, add);
        try self.server.addToolJson(.{ .name = "slow_task", .task_support = .optional }, slowTask);
        try self.server.addToolJson(.{ .name = "ask_name" }, askName);
        try self.server.addToolJson(.{ .name = "everything" }, everything);
        try self.server.addToolJson(.{ .name = "inspect_meta" }, inspectMeta);
        try self.server.addResource(.{ .uri = "test://static", .name = "static" }, readStatic);
        try self.server.addResource(.{ .uri = "test://counted", .name = "counted" }, readCounted);
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
    try std.testing.expectEqual(5, tools.tools.len);

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

test "a per-request log level replaces the log level of the client" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "cli", .version = "1" } });
    defer f.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Without a client log level, the request sends its own level only.
    const none = try f.client.callTool(arena, "inspect_meta", null, .{});
    try std.testing.expectEqualStrings("none none none", none.content[0].text.text);
    const own = try f.client.callTool(arena, "inspect_meta", null, .{ .log_level = .debug });
    try std.testing.expectEqualStrings("debug none none", own.content[0].text.text);

    // With a client log level, the request level replaces it for that request only.
    f.client.options.log_level = .warning;
    const client_level = try f.client.callTool(arena, "inspect_meta", null, .{});
    try std.testing.expectEqualStrings("warning none none", client_level.content[0].text.text);
    const replaced = try f.client.callTool(arena, "inspect_meta", null, .{ .log_level = .info });
    try std.testing.expectEqualStrings("info none none", replaced.content[0].text.text);
}

test "extra _meta entries reach the server and SDK-owned keys fail the request" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "cli", .version = "1" } });
    defer f.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Trace context, a vendor key and an extension key under the reserved prefix pass.
    const traceparent = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01";
    var extra: std.json.ObjectMap = .empty;
    try extra.put(arena, "traceparent", .{ .string = traceparent });
    try extra.put(arena, "tracestate", .{ .string = "congo=t61rcWkgMzE" });
    try extra.put(arena, "com.example/x", .{ .string = "y" });
    try extra.put(arena, "io.modelcontextprotocol/example", .{ .object = .empty });
    const seen = try f.client.callTool(arena, "inspect_meta", null, .{ .meta = extra, .log_level = .notice });
    try std.testing.expectEqualStrings("notice " ++ traceparent ++ " y", seen.content[0].text.text);

    // The progress token of the SDK stays in place next to the extra entries.
    var rec: Recorder = .{};
    const sum = try f.client.callTool(arena, "add", .{ .a = 1, .b = 2 }, .{ .meta = extra, .on_progress = Recorder.onProgress, .userdata = &rec });
    try std.testing.expectEqualStrings("3", sum.content[0].text.text);
    try std.testing.expectEqual(1, rec.progress);

    // A key that the SDK owns, or a key that breaks the grammar, fails the request before
    // the client sends it.
    read_count.store(0, .monotonic);
    const refused = [_][]const u8{
        "io.modelcontextprotocol/logLevel",
        "progressToken",
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientInfo",
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/subscriptionId",
        "bad key",
        "com.example/",
        "1com.example/x",
    };
    for (refused) |key| {
        var bad: std.json.ObjectMap = .empty;
        try bad.put(arena, "traceparent", .{ .string = traceparent });
        try bad.put(arena, key, .{ .string = "debug" });
        try std.testing.expectError(error.InvalidMeta, f.client.callTool(arena, "inspect_meta", null, .{ .meta = bad }));
        try std.testing.expectError(error.InvalidMeta, f.client.readResource(arena, "test://counted", .{ .meta = bad }));
    }
    try std.testing.expectEqual(0, read_count.load(.monotonic));
}

fn exampleServerPath() []const u8 {
    return if (@import("builtin").os.tag == .windows) "zig-out/bin/stdio_server.exe" else "zig-out/bin/stdio_server";
}

test "stdio client drives the example server process" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // The build installs the example before the tests run.
    Io.Dir.cwd().access(io, exampleServerPath(), .{}) catch return error.SkipZigTest;
    const proc = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = &.{exampleServerPath()} });
    defer proc.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try client.discover(arena, .{ .timeout = .fromSeconds(20) });
    try std.testing.expect(disc.capabilities.tools != null);
    var rec: Recorder = .{};
    const sum = try client.callTool(arena, "add", .{ .a = 40, .b = 2 }, .{ .timeout = .fromSeconds(20), .on_progress = Recorder.onProgress, .userdata = &rec });
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);
    try std.testing.expectEqual(0, rec.progress);
    const prompts = try client.listPrompts(arena, null, .{ .timeout = .fromSeconds(20) });
    try std.testing.expect(prompts.prompts.len >= 1);
    var diag: Client.Diagnostics = .{};
    try std.testing.expectError(error.Rpc, client.callTool(arena, "missing", null, .{ .timeout = .fromSeconds(20), .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
}

/// End the server process behind the client's back, as a crash would.
fn crashChild(proc: *mcp.transport.stdio.Client) void {
    if (@import("builtin").os.tag == .windows) {
        _ = std.os.windows.ntdll.NtTerminateProcess(proc.child.id.?, @enumFromInt(9));
    } else {
        std.posix.kill(proc.child.id.?, .KILL) catch {};
    }
}

test "stdio client restarts a crashed server and the client re-issues the request" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    Io.Dir.cwd().access(io, exampleServerPath(), .{}) catch return error.SkipZigTest;
    const proc = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = &.{exampleServerPath()}, .max_restarts = 1 });
    defer proc.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try client.discover(arena, .{ .timeout = .fromSeconds(20) });
    crashChild(proc);
    // The reader sees the end of the stream and spawns the server again. `server/discover`
    // is idempotent, so a lost request is re-issued to the new process.
    const disc = try client.discover(arena, .{ .timeout = .fromSeconds(20) });
    try std.testing.expect(disc.capabilities.tools != null);
    try std.testing.expectEqual(1, proc.restartCount());
    // A second crash exceeds the limit: the stream stays closed.
    crashChild(proc);
    try std.testing.expectError(error.Closed, client.discover(arena, .{ .timeout = .fromSeconds(20), .retry = .never }));
}

test "stdio client spawns and closes without requests" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    Io.Dir.cwd().access(io, exampleServerPath(), .{}) catch return error.SkipZigTest;
    const proc = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = &.{exampleServerPath()} });
    proc.deinit();
}

test "tasks are awaited and their input requests answered" {
    var f: Fixture = undefined;
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const caps = try json.parseTree(arena, "{\"elicitation\":{},\"extensions\":{\"io.modelcontextprotocol/tasks\":{}}}");
    try f.init(.{
        .info = .{ .name = "cli", .version = "1" },
        .capabilities = try json.parseValue(types.ClientCapabilities, arena, caps),
        .hooks = .{ .elicit_form = answerForm },
    });
    defer f.deinit();

    // `callTool` hides the task: it polls, answers the elicitation and returns the tool result.
    const hidden = try f.client.callTool(arena, "slow_task", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("task hello Alice", hidden.content[0].text.text);

    // `callToolOrTask` returns the task record; the caller drives it.
    const outcome = try f.client.callToolOrTask(arena, "slow_task", null, .{});
    try std.testing.expect(outcome == .task);
    try std.testing.expectEqualStrings("working", outcome.task.status);
    const done = try f.client.awaitTask(arena, outcome.task.taskId, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("completed", done.status);
    const result = try Client.taskResult(arena, done);
    try std.testing.expectEqualStrings("task hello Alice", result.content[0].text.text);

    // Cancellation ends the wait with `error.TaskCancelled`.
    const second = try f.client.callToolOrTask(arena, "slow_task", null, .{});
    try f.client.cancelTask(arena, second.task.taskId, .{});
    try std.testing.expectError(error.TaskCancelled, f.client.awaitTask(arena, second.task.taskId, .{ .timeout = .fromSeconds(10) }));
}

test "a task result without the extension is invalid" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "cli", .version = "1" }, .capabilities = .{ .elicitation = .{} }, .hooks = .{ .elicit_form = answerForm } });
    defer f.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The server runs the tool at once because the client did not declare the extension.
    const direct = try f.client.callTool(arena, "slow_task", null, .{});
    try std.testing.expectEqualStrings("task hello Alice", direct.content[0].text.text);
}

test "the result cache serves reads with a lifetime until invalidated" {
    var f: Fixture = undefined;
    try f.init(.{ .info = .{ .name = "cli", .version = "1" }, .cache = .{ .enabled = true } });
    defer f.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    read_count.store(0, .monotonic);

    _ = try f.client.readResource(arena, "test://counted", .{});
    _ = try f.client.readResource(arena, "test://counted", .{});
    try std.testing.expectEqual(1, read_count.load(.monotonic));
    // Bypass and refresh reach the server; a plain read is served from the cache again.
    _ = try f.client.readResource(arena, "test://counted", .{ .cache_mode = .bypass });
    try std.testing.expectEqual(2, read_count.load(.monotonic));
    _ = try f.client.readResource(arena, "test://counted", .{ .cache_mode = .refresh });
    try std.testing.expectEqual(3, read_count.load(.monotonic));
    _ = try f.client.readResource(arena, "test://counted", .{});
    try std.testing.expectEqual(3, read_count.load(.monotonic));
    f.client.invalidateCache();
    _ = try f.client.readResource(arena, "test://counted", .{});
    try std.testing.expectEqual(4, read_count.load(.monotonic));
    // Every read carries the lifetime hint of the server; discovery carries none.
    _ = try f.client.readResource(arena, "test://static", .{});
    try std.testing.expectEqual(2, f.client.cache.count());
    _ = try f.client.discover(arena, .{});
    try std.testing.expectEqual(2, f.client.cache.count());
}
