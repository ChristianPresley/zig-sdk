//! Client behavior over the in-memory link to a server.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const Transport = mcp.transport.Transport;
const types = mcp.types;
const json = mcp.json;
const router = @import("../transport/router.zig");

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
    // the client sends it. The specification allows an empty name after a prefix, thus the
    // list does not have such a key.
    read_count.store(0, .monotonic);
    const refused = [_][]const u8{
        "io.modelcontextprotocol/logLevel",
        "progressToken",
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientInfo",
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/subscriptionId",
        "bad key",
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

// -- The memory of notifications ----------------------------------------------------------------

/// A client transport that gives the same frames to each request. `{id}` in a frame becomes
/// the id of the request. A callback can give more frames to the request in progress.
const Scripted = struct {
    frames: []const []const u8,
    in_flight: ?*Transport.Exchange = null,

    fn transport(self: *Scripted) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .memory, .exchange = exchange, .notify = notify };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Scripted = @ptrCast(@alignCast(ptr));
        self.in_flight = ex;
        defer self.in_flight = null;
        for (self.frames) |template| try self.give(io, template);
    }

    /// Give one frame to the request in progress.
    fn give(self: *Scripted, io: Io, template: []const u8) Transport.ExchangeError!void {
        const ex = self.in_flight.?;
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const id = try std.fmt.allocPrint(arena, "{d}", .{ex.id.integer});
        const frame = try std.mem.replaceOwned(u8, arena, template, "{id}", id);
        ex.deliver(io, frame) catch return error.InvalidFrame;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = ptr;
        _ = io;
        _ = frame;
    }
};

/// Fills memory with 0xaa before it gives the memory back to `child`. A read of freed memory
/// then gives other bytes.
const Poisoning = struct {
    child: std.mem.Allocator,

    fn allocator(self: *Poisoning) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Poisoning = @ptrCast(@alignCast(ptr));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Poisoning = @ptrCast(@alignCast(ptr));
        if (new_len < memory.len) @memset(memory[new_len..], 0xaa);
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        // The caller copies the memory and frees the old memory.
        return null;
    }

    fn free(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Poisoning = @ptrCast(@alignCast(ptr));
        @memset(memory, 0xaa);
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

test "a response that the check of the top-level keys does not find stays valid after the exchange" {
    // A top-level key with an escape sequence is too long for the buffer of the scanner, and a
    // nested "method" key makes the fallback check give "not a response". The collector
    // parses the frame into its scratch memory first.
    const head = "{\"jsonrpc\":\"2.0\",\"id\":";
    const tail = ",\"\\u006b" ++ "k" ** 80 ++ "\":0,\"result\":{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"kept\"}],\"structuredContent\":{\"method\":\"get\"}}}";
    const response = head ++ "{id}" ++ tail;
    // The first request of a client has the id 1.
    try std.testing.expect(!router.frameIsResponse(head ++ "1" ++ tail));
    var scripted: Scripted = .{ .frames = &.{
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":{id},\"progress\":1}}",
        response,
    } };
    // The scratch memory of the client comes from `gpa`. Freed memory changes its bytes.
    var poisoning: Poisoning = .{ .child = std.testing.allocator };
    var client: Client = .init(poisoning.allocator(), std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(scripted.transport());
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();

    const result = try client.callTool(arena_state.allocator(), "t", null, .{});
    try std.testing.expectEqualStrings("kept", result.content[0].text.text);
    try std.testing.expectEqualStrings("get", json.getString(result.structuredContent.?, "method").?);
}

/// Counts the `test/hostile` notifications that reach `RequestOptions.on_notification`.
const HostileCounter = struct {
    count: usize = 0,

    fn onNotification(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *HostileCounter = @ptrCast(@alignCast(userdata.?));
        _ = params;
        if (std.mem.eql(u8, method, "test/hostile")) self.count += 1;
    }
};

/// Give `count` copies of `notification` and then the response to the first request of a new
/// client. Return the capacity of the request arena after the call.
fn arenaAfterNotifications(notification: []const u8, count: usize) !usize {
    const gpa = std.testing.allocator;
    const frames = try gpa.alloc([]const u8, count + 1);
    defer gpa.free(frames);
    @memset(frames[0..count], notification);
    frames[count] = "{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{\"resultType\":\"complete\",\"content\":[]}}";
    var scripted: Scripted = .{ .frames = frames };
    var client: Client = .init(gpa, std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(scripted.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    var counter: HostileCounter = .{};
    _ = try client.callTool(arena_state.allocator(), "t", null, .{ .on_notification = HostileCounter.onNotification, .userdata = &counter });
    try std.testing.expectEqual(count, counter.count);
    return arena_state.queryCapacity();
}

test "a notification that the fallback check takes for a response does not make the request arena larger" {
    // A top-level key with an escape sequence is too long for the buffer of the scanner, the
    // "method" key has an escape sequence, and a value has the text "error". The fallback
    // check of the router takes the frame for a response.
    const head = "{\"jsonrpc\":\"2.0\",\"\\u0078" ++ "x" ** 80 ++ "\":0,\"\\u006dethod\":\"test/hostile\",\"params\":{\"progressToken\":";
    const tail = ",\"note\":\"error\"}}";
    try std.testing.expect(router.frameIsResponse(head ++ "1" ++ tail));
    const short = try arenaAfterNotifications(head ++ "{id}" ++ tail, 10);
    const long = try arenaAfterNotifications(head ++ "{id}" ++ tail, 2_000);
    try std.testing.expectEqual(short, long);
}

/// Gives two more frames from the callback of the first notification. Then it checks that
/// the parameters of the first notification did not change.
const Nested = struct {
    scripted: *Scripted,
    first_intact: bool = false,
    nested_seen: u32 = 0,

    fn onNotification(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *Nested = @ptrCast(@alignCast(userdata.?));
        if (!std.mem.eql(u8, method, "test/first")) {
            const text = json.getString(params.?, "text").?;
            if (std.mem.startsWith(u8, text, "nested ")) self.nested_seen += 1;
            return;
        }
        const nested = "{\"jsonrpc\":\"2.0\",\"method\":\"test/nested\",\"params\":{\"progressToken\":{id},\"text\":\"nested " ++ "n" ** 200 ++ "\"}}";
        self.scripted.give(std.testing.io, nested) catch return;
        self.scripted.give(std.testing.io, nested) catch return;
        const text = json.getString(params.?, "text") orelse "";
        self.first_intact = std.mem.eql(u8, method, "test/first") and std.mem.eql(u8, text, "first frame");
    }
};

test "a frame that a callback gives during another frame does not overwrite the parameters of that frame" {
    var scripted: Scripted = .{ .frames = &.{
        "{\"jsonrpc\":\"2.0\",\"method\":\"test/first\",\"params\":{\"progressToken\":{id},\"text\":\"first frame\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{\"resultType\":\"complete\",\"content\":[]}}",
    } };
    var nested: Nested = .{ .scripted = &scripted };
    // The scratch memory of the client comes from `gpa`. Freed memory changes its bytes.
    var poisoning: Poisoning = .{ .child = std.testing.allocator };
    var client: Client = .init(poisoning.allocator(), std.testing.io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(scripted.transport());
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();

    _ = try client.callTool(arena_state.allocator(), "t", null, .{ .on_notification = Nested.onNotification, .userdata = &nested });
    try std.testing.expectEqual(2, nested.nested_seen);
    try std.testing.expect(nested.first_intact);
}

const listen_uri = "test://counted";

/// Counts the acknowledgments and the `notifications/resources/updated` for `listen_uri`.
const UpdateCounter = struct {
    acks: std.atomic.Value(u32) = .init(0),
    updates: std.atomic.Value(u32) = .init(0),
    /// The callback waits this time before it counts an update.
    delay: ?Io.Duration = null,

    fn onNotification(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *UpdateCounter = @ptrCast(@alignCast(userdata.?));
        if (std.mem.eql(u8, method, "notifications/subscriptions/acknowledged")) {
            _ = self.acks.fetchAdd(1, .release);
            return;
        }
        if (!std.mem.eql(u8, method, "notifications/resources/updated")) return;
        const uri = json.getString(params orelse return, "uri") orelse return;
        if (self.delay) |d| std.testing.io.sleep(d, .awake) catch {};
        if (std.mem.eql(u8, uri, listen_uri)) _ = self.updates.fetchAdd(1, .release);
    }
};

/// Wait until `value` is `at_least` or more, at most 20 seconds.
fn awaitCount(value: *const std.atomic.Value(u32), at_least: u32) !void {
    var spins: usize = 0;
    while (value.load(.acquire) < at_least) : (spins += 1) {
        if (spins > 4000) return error.TestTimeout;
        try std.testing.io.sleep(.fromMilliseconds(5), .awake);
    }
}

/// One listen stream for `listen_uri` in its own task. The job owns the request arena, thus
/// the test can read its capacity.
const ListenJob = struct {
    client: *Client,
    counter: *UpdateCounter,
    arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator),
    token: Transport.CancelToken = .{},
    result: ?Client.RequestError = null,
    inline_notifications: bool = false,

    fn run(job: *ListenJob) void {
        const filter: types.SubscriptionsListenRequestParams = .{
            ._meta = .{ .@"io.modelcontextprotocol/protocolVersion" = "2026-07-28", .@"io.modelcontextprotocol/clientCapabilities" = .{} },
            .notifications = .{ .resourceSubscriptions = &.{listen_uri} },
        };
        _ = job.client.listen(job.arena_state.allocator(), filter, .{
            .cancel = &job.token,
            .retry = .never,
            .on_notification = UpdateCounter.onNotification,
            .userdata = job.counter,
            .inline_notifications = job.inline_notifications,
        }) catch |e| {
            job.result = e;
        };
    }

    /// Cancel the stream and wait for the end of its task.
    fn stop(job: *ListenJob, future: *Io.Future(void)) void {
        job.token.cancel(std.testing.io, "done");
        future.await(std.testing.io);
    }
};

test "a long listen stream over the memory link does not make the request arena larger" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(gpa, io, .{ .info = .{ .name = "srv", .version = "1" }, .capabilities = .{ .resources = .{ .subscribe = true } } });
    defer server.deinit();
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(link.transport());

    var counter: UpdateCounter = .{};
    var job: ListenJob = .{ .client = &client, .counter = &counter };
    defer job.arena_state.deinit();
    var future = try io.concurrent(ListenJob.run, .{&job});
    var stopped = false;
    defer if (!stopped) job.stop(&future);
    try awaitCount(&counter.acks, 1);
    // The server gives each event to the client on this task, thus the client has the event
    // when the call returns. The subscription is visible to publish before the
    // acknowledgment, thus the first event after it arrives.
    server.notifyResourceUpdated(io, listen_uri);
    try std.testing.expectEqual(1, counter.updates.load(.acquire));
    for (0..100) |_| server.notifyResourceUpdated(io, listen_uri);
    const updates = counter.updates.load(.acquire);
    const capacity = job.arena_state.queryCapacity();
    for (0..10_000) |_| server.notifyResourceUpdated(io, listen_uri);
    try std.testing.expectEqual(updates + 10_000, counter.updates.load(.acquire));
    try std.testing.expectEqual(capacity, job.arena_state.queryCapacity());

    job.stop(&future);
    stopped = true;
    try std.testing.expectEqual(error.Canceled, job.result.?);
}

/// A child that reads one line, writes the file `events.jsonl` of its current directory to
/// its standard output, and then reads one more line.
const replay_argv: []const []const u8 = if (builtin.os.tag == .windows)
    &.{ "cmd.exe", "/d", "/c", "set", "/p", "line=&type", "events.jsonl&set", "/p", "line=" }
else
    &.{ "/bin/sh", "-c", "read -r line; cat events.jsonl; read -r line; exit 0" };

/// Replay an acknowledgment and `count` events for the first request of a new client over
/// stdio. Return the capacity of the request arena of the listen stream after the last event.
fn replayListen(dir: Io.Dir, count: u32) !usize {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    // The first request of a client has the id 1, thus the subscription id is 1.
    try text.appendSlice(gpa, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":1},\"notifications\":{\"resourceSubscriptions\":[\"" ++ listen_uri ++ "\"]}}}\n");
    for (0..count) |_| try text.appendSlice(gpa, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":1},\"uri\":\"" ++ listen_uri ++ "\"}}\n");
    try dir.writeFile(io, .{ .sub_path = "events.jsonl", .data = text.items });

    const proc = mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = replay_argv, .cwd = .{ .dir = dir } }) catch return error.SkipZigTest;
    defer proc.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());

    var counter: UpdateCounter = .{};
    var job: ListenJob = .{ .client = &client, .counter = &counter };
    defer job.arena_state.deinit();
    var future = try io.concurrent(ListenJob.run, .{&job});
    var stopped = false;
    defer if (!stopped) job.stop(&future);
    try awaitCount(&counter.updates, count);
    const capacity = job.arena_state.queryCapacity();
    try std.testing.expectEqual(1, counter.acks.load(.acquire));

    job.stop(&future);
    stopped = true;
    try std.testing.expectEqual(error.Canceled, job.result.?);
    try std.testing.expectEqual(count, counter.updates.load(.acquire));
    return capacity;
}

test "a long listen stream over stdio does not make the request arena larger" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const short = try replayListen(tmp.dir, 100);
    const long = try replayListen(tmp.dir, 10_000);
    try std.testing.expectEqual(short, long);
}

/// Counts the log messages that reach the `on_notification` spawn option of the stdio client
/// and the `on_log` option of a request.
const LogPaths = struct {
    transport: std.atomic.Value(u32) = .init(0),
    request: u32 = 0,

    fn onTransport(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *LogPaths = @ptrCast(@alignCast(userdata.?));
        _ = params;
        if (std.mem.eql(u8, method, "notifications/message")) _ = self.transport.fetchAdd(1, .release);
    }

    fn onLog(userdata: ?*anyopaque, params: types.LoggingMessageNotificationParams) void {
        const self: *LogPaths = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.request += 1;
    }
};

test "a log message during a request reaches the on_notification spawn option of the stdio client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // The server writes a log message and then the response of the first request (id 1).
    try tmp.dir.writeFile(io, .{ .sub_path = "events.jsonl", .data = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"working\"}}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"content\":[]}}\n" });

    // The spawn option is in place before the reader task starts.
    var paths: LogPaths = .{};
    const proc = mcp.transport.stdio.Client.spawn(io, gpa, .{
        .argv = replay_argv,
        .cwd = .{ .dir = tmp.dir },
        .on_notification = LogPaths.onTransport,
        .userdata = &paths,
    }) catch return error.SkipZigTest;
    defer proc.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    _ = try client.callTool(arena_state.allocator(), "t", null, .{ .log_level = .info, .on_log = LogPaths.onLog, .userdata = &paths });
    // The reader task gave the log message to the spawn option before it routed the response.
    try std.testing.expectEqual(1, paths.transport.load(.acquire));
    try std.testing.expectEqual(0, paths.request);
}

// -- Notifications on the reader task -----------------------------------------------------------

/// A child that answers two lines. After the first line it writes the file `ack.jsonl` of its
/// current directory, and after the second line the file `events.jsonl`. Then it reads one
/// more line.
const replay_twice_argv: []const []const u8 = if (builtin.os.tag == .windows)
    &.{ "cmd.exe", "/d", "/c", "set", "/p", "line=&type", "ack.jsonl&set", "/p", "line=&type", "events.jsonl&set", "/p", "line=" }
else
    &.{ "/bin/sh", "-c", "read -r line; cat ack.jsonl; read -r line; cat events.jsonl; read -r line; exit 0" };

test "an inline listen event reaches its callback before the response that the server wrote after it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // The listen stream is the first request of the client (id 1), the tool call the second
    // (id 2). The server writes an event of the stream and then the response of the call.
    try tmp.dir.writeFile(io, .{ .sub_path = "ack.jsonl", .data = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":1},\"notifications\":{\"resourceSubscriptions\":[\"" ++ listen_uri ++ "\"]}}}\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "events.jsonl", .data = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":1},\"uri\":\"" ++ listen_uri ++ "\"}}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"complete\",\"content\":[]}}\n" });

    const proc = mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = replay_twice_argv, .cwd = .{ .dir = tmp.dir } }) catch return error.SkipZigTest;
    defer proc.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());

    // The callback of the event is slow. Without the option, the response of the call can get
    // to its caller first.
    var counter: UpdateCounter = .{ .delay = .fromMilliseconds(50) };
    var job: ListenJob = .{ .client = &client, .counter = &counter, .inline_notifications = true };
    defer job.arena_state.deinit();
    var future = try io.concurrent(ListenJob.run, .{&job});
    var stopped = false;
    defer if (!stopped) job.stop(&future);
    try awaitCount(&counter.acks, 1);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    _ = try client.callTool(arena_state.allocator(), "t", null, .{});
    // The reader task routed the response after the callback of the event returned.
    try std.testing.expectEqual(1, counter.updates.load(.acquire));

    job.stop(&future);
    stopped = true;
    try std.testing.expectEqual(error.Canceled, job.result.?);
}

/// Counts the exchanges that reach the inner transport.
const Counting = struct {
    inner: Transport.ClientTransport,
    exchanges: u32 = 0,

    fn transport(self: *Counting) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .stdio, .exchange = exchange, .notify = notify };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        self.exchanges += 1;
        return self.inner.exchange(io, ex);
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const self: *Counting = @ptrCast(@alignCast(ptr));
        return self.inner.notify(io, frame);
    }
};

/// Records the thread of each progress callback.
const ProgressThread = struct {
    calls: u32 = 0,
    thread: ?std.Thread.Id = null,

    fn onProgress(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
        const self: *ProgressThread = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.calls += 1;
        self.thread = std.Thread.getCurrentId();
    }
};

/// A child that reads one line, writes the file `events.jsonl` of its current directory and
/// exits.
const replay_and_exit_argv: []const []const u8 = if (builtin.os.tag == .windows)
    &.{ "cmd.exe", "/d", "/c", "set", "/p", "line=&type", "events.jsonl" }
else
    &.{ "/bin/sh", "-c", "read -r line; cat events.jsonl; exit 0" };

test "a request that got an inline notification does not retry a lost stream" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // The server writes progress for the first request (id 1) and then exits.
    try tmp.dir.writeFile(io, .{ .sub_path = "events.jsonl", .data = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1}}\n" });

    const proc = mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = replay_and_exit_argv, .cwd = .{ .dir = tmp.dir } }) catch return error.SkipZigTest;
    defer proc.deinit();
    var counting: Counting = .{ .inner = proc.transport() };
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(counting.transport());

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var progress: ProgressThread = .{};
    // `tools/list` is idempotent. The client re-issues it after a lost stream only when no
    // frame arrived.
    try std.testing.expectError(error.Closed, client.listTools(arena_state.allocator(), null, .{
        .inline_notifications = true,
        .on_progress = ProgressThread.onProgress,
        .userdata = &progress,
    }));
    try std.testing.expectEqual(1, counting.exchanges);
    try std.testing.expectEqual(1, progress.calls);
    // The reader task of the transport called the callback, not the task of the request.
    try std.testing.expect(progress.thread.? != std.Thread.getCurrentId());
}

// -- Frames that the client cannot read ---------------------------------------------------------

/// A child that reads one line and writes the file `events.jsonl` of its current directory to
/// its standard output. Then it writes the next line of its input to the file `next.txt`.
const record_argv: []const []const u8 = if (builtin.os.tag == .windows)
    &.{ "cmd.exe", "/d", "/v:on", "/c", "set", "/p", "line=&type", "events.jsonl&set", "/p", "line=&echo", "!line!>next.txt" }
else
    &.{ "/bin/sh", "-c", "read -r line; cat events.jsonl; read -r line; printf '%s\\n' \"$line\" > next.txt" };

test "a frame that the stdio client cannot read makes its request fail at once" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // The answers of a server to the first request (id 1).
    const answers = [_][]const u8{
        // A line over `max_line_bytes`. The id comes after the result, as some servers write it.
        "{\"jsonrpc\":\"2.0\",\"result\":{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"" ++ "x" ** 8192 ++ "\"}]},\"id\":1}\n",
        // An error response with a null id, while the request is the only one in flight.
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}\n",
        // A line that is not valid UTF-8.
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"\xff\"}]}}\n",
    };
    var limits: mcp.Limits = .{};
    limits.stdio.max_line_bytes = 1024;
    // The long line is longer than the buffer. Thus the framer reads its tail in parts.
    limits.stdio.read_buffer = 512;
    for (answers) |answer| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(io, .{ .sub_path = "events.jsonl", .data = answer });
        const proc = mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = record_argv, .cwd = .{ .dir = tmp.dir }, .limits = limits }) catch return error.SkipZigTest;
        defer proc.deinit();
        var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .limits = limits });
        defer client.deinit();
        client.connect(proc.transport());

        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        // Before, the router dropped the frame, and the request waited until its timeout.
        const start = Io.Clock.Timestamp.now(io, .awake);
        try std.testing.expectError(error.InvalidResponse, client.callTool(arena_state.allocator(), "t", null, .{ .timeout = .fromSeconds(30) }));
        try std.testing.expect(start.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds < std.time.ns_per_s * 20);
        try std.testing.expectEqual(1, proc.router.dropped_frames.load(.monotonic));

        // The server can still run the request, thus the client cancels it.
        proc.close();
        const next = try tmp.dir.readFileAlloc(io, "next.txt", gpa, .limited(4096));
        defer gpa.free(next);
        try std.testing.expect(std.mem.find(u8, next, "\"method\":\"notifications/cancelled\"") != null);
        try std.testing.expect(std.mem.find(u8, next, "\"requestId\":1,\"reason\":\"invalid frame\"") != null);
    }
}
