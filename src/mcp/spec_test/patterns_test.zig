//! Tests for the message patterns of the specification. They cover cancellation, multi round-trip
//! requests, progress and subscriptions.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const types = mcp.types;
const json = mcp.json;
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const Harness = mcp.transport.memory.Harness;
const Transport = mcp.transport.Transport;
const StdioServer = mcp.transport.stdio.Server;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;
const meta_elicit =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}
;
const meta_all =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"sampling":{},"elicitation":{},"roots":{}}}
;

fn request(arena: Allocator, id: i64, method: []const u8, meta: []const u8, extra: []const u8) ![]u8 {
    const sep: []const u8 = if (extra.len > 0) "," else "";
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta, sep, extra });
}

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

fn result(v: Value) Value {
    return v.object.get("result").?;
}

fn methodOf(v: Value) ?[]const u8 {
    const m = v.object.get("method") orelse return null;
    return m.string;
}

fn number(v: Value) f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |x| x,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch unreachable,
        else => unreachable,
    };
}

fn waitUntil(flag: *const std.atomic.Value(bool)) !void {
    var spins: usize = 0;
    while (!flag.load(.acquire)) : (spins += 1) {
        if (spins > 2000) return error.TestTimeout;
        try std.testing.io.sleep(.fromMilliseconds(5), .awake);
    }
}

// -- Handlers ---------------------------------------------------------------------------------

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

const Probe = struct {
    saw_cancel: std.atomic.Value(bool) = .init(false),
};

/// Runs until the client cancels the request, at most five seconds.
fn waitForCancel(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const probe: *Probe = @ptrCast(@alignCast(ctx.userdata.?));
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        ctx.checkCancel() catch |e| {
            probe.saw_cancel.store(true, .release);
            return e;
        };
        try ctx.io.sleep(.fromMilliseconds(5), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "not cancelled", .{}) };
}

/// Sends progress until a write fails, at most four seconds.
fn ticker(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const probe: *Probe = @ptrCast(@alignCast(ctx.userdata.?));
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        ctx.progress(@floatFromInt(i), null, null) catch |e| {
            probe.saw_cancel.store(true, .release);
            return e;
        };
        try ctx.io.sleep(.fromMilliseconds(10), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "never stopped", .{}) };
}

fn askName(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content orelse .null, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    try ir.setStateFmt("{{\"round\":{d}}}", .{1});
    return .{ .input_required = ir };
}

fn emptyInput(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .input_required = mcp.InputRequired.init(ctx.arena) };
}

fn askSampling(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var ir: mcp.InputRequired = .init(ctx.arena);
    const messages = try ctx.arena.alloc(types.SamplingMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .single = .{ .text = .{ .text = "hi" } } } };
    try ir.sample("greeting", .{ .messages = messages, .maxTokens = 10 });
    return .{ .input_required = ir };
}

fn askRoots(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.listRoots("roots");
    return .{ .input_required = ir };
}

fn readAsk(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    if (try ctx.elicitResponse("confirm")) |_| {
        const contents = try ctx.arena.alloc(types.ResourceContents, 1);
        contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "confirmed" } };
        return .{ .complete = .{ .contents = contents } };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("confirm", "Read it?", try mcp.InputRequired.stringSchema(ctx.arena, "ok", null, false));
    return .{ .input_required = ir };
}

fn promptAsk(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    _ = args;
    if (try ctx.elicitResponse("topic")) |_| {
        const messages = try ctx.arena.alloc(types.PromptMessage, 1);
        messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = "topic received" } } };
        return .{ .complete = .{ .messages = messages } };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("topic", "Topic?", try mcp.InputRequired.stringSchema(ctx.arena, "topic", null, true));
    return .{ .input_required = ir };
}

fn reportProgress(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    try ctx.progress(0.5, 1.0, "half way");
    try ctx.progress(0.75, null, null);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "done", .{}) };
}

fn floodProgress(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var i: usize = 0;
    while (i < 100) : (i += 1) try ctx.progress(@floatFromInt(i), null, null);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "flooded", .{}) };
}

fn register(server: *Server, probe: *Probe) !void {
    try server.addTool(.{ .name = "add" }, add);
    try server.addToolJson(.{ .name = "wait_for_cancel", .userdata = probe }, waitForCancel);
    try server.addToolJson(.{ .name = "ticker", .userdata = probe }, ticker);
    try server.addToolJson(.{ .name = "ask_a" }, askName);
    try server.addToolJson(.{ .name = "ask_b" }, askName);
    try server.addToolJson(.{ .name = "empty_input" }, emptyInput);
    try server.addToolJson(.{ .name = "ask_sampling" }, askSampling);
    try server.addToolJson(.{ .name = "ask_roots" }, askRoots);
    try server.addToolJson(.{ .name = "report_progress" }, reportProgress);
    try server.addToolJson(.{ .name = "flood_progress" }, floodProgress);
    try server.addResource(.{ .uri = "test://ask", .name = "ask" }, readAsk);
    try server.addPrompt(.{ .name = "ask_prompt" }, promptAsk);
}

// -- In-memory fixture ------------------------------------------------------------------------

const Fixture = struct {
    server: Server,
    harness: Harness,
    probe: Probe = .{},
    arena_state: std.heap.ArenaAllocator,

    fn init(self: *Fixture, options: Server.Options) !void {
        const gpa = std.testing.allocator;
        self.probe = .{};
        self.arena_state = .init(gpa);
        self.server = try Server.init(gpa, std.testing.io, options);
        try register(&self.server, &self.probe);
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

    /// Send a request and return the parsed last frame.
    fn call(self: *Fixture, id: i64, method: []const u8, meta: []const u8, extra: []const u8) !Value {
        self.harness.clear();
        try self.harness.send(try request(self.arena(), id, method, meta, extra));
        try std.testing.expect(self.harness.finished);
        return json.parseTree(self.arena(), self.harness.last().?);
    }

    fn frame(self: *Fixture, index: usize) !Value {
        return json.parseTree(self.arena(), self.harness.out.items[index]);
    }
};

const default_options: Server.Options = .{ .info = .{ .name = "patterns", .version = "1" } };

// -- Cancellation -----------------------------------------------------------------------------

test "a client-cancelled listen stream frees its subscription and gets no response" {
    var f: Fixture = undefined;
    try f.init(default_options);
    defer f.deinit();
    const io = std.testing.io;

    var token: Transport.CancelToken = .{};
    const frame = try request(f.arena(), 3, "subscriptions/listen", meta_none, "\"notifications\":{\"toolsListChanged\":true}");
    var future = try io.concurrent(Harness.sendWithToken, .{ &f.harness, frame, &token });
    var spins: usize = 0;
    while (f.harness.out.items.len == 0 and spins < 400) : (spins += 1) try io.sleep(.fromMilliseconds(5), .awake);
    {
        f.server.subscriptions_lock.lockUncancelable(io);
        defer f.server.subscriptions_lock.unlock(io);
        try std.testing.expectEqual(1, f.server.subscriptions.items.len);
    }
    token.cancel(io, "client cancelled");
    try future.await(io);
    // Only the acknowledgement went out, and the subscription is gone.
    try std.testing.expectEqual(1, f.harness.out.items.len);
    try std.testing.expectEqualStrings("notifications/subscriptions/acknowledged", methodOf(try f.frame(0)).?);
    try std.testing.expectEqual(0, f.server.subscriptions.items.len);
    // A later event reaches nobody.
    f.server.notifyToolsListChanged(io);
    try std.testing.expectEqual(1, f.harness.out.items.len);
}

// -- Multi round-trip requests ----------------------------------------------------------------

test "input required results are allowed on tools/call, resources/read and prompts/get" {
    var f: Fixture = undefined;
    try f.init(default_options);
    defer f.deinit();

    const tool = result(try f.call(1, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{}"));
    try std.testing.expectEqualStrings("input_required", tool.object.get("resultType").?.string);

    const read = result(try f.call(2, "resources/read", meta_elicit, "\"uri\":\"test://ask\""));
    try std.testing.expectEqualStrings("input_required", read.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("elicitation/create", read.object.get("inputRequests").?.object.get("confirm").?.object.get("method").?.string);
    const read_done = result(try f.call(3, "resources/read", meta_elicit, "\"uri\":\"test://ask\",\"inputResponses\":{\"confirm\":{\"action\":\"accept\",\"content\":{\"ok\":\"yes\"}}}"));
    try std.testing.expectEqualStrings("complete", read_done.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("confirmed", read_done.object.get("contents").?.array.items[0].object.get("text").?.string);

    const prompt = result(try f.call(4, "prompts/get", meta_elicit, "\"name\":\"ask_prompt\""));
    try std.testing.expectEqualStrings("input_required", prompt.object.get("resultType").?.string);
    try std.testing.expect(prompt.object.get("inputRequests").?.object.get("topic") != null);
    const prompt_done = result(try f.call(5, "prompts/get", meta_elicit, "\"name\":\"ask_prompt\",\"inputResponses\":{\"topic\":{\"action\":\"accept\",\"content\":{\"topic\":\"zig\"}}}"));
    try std.testing.expectEqualStrings("complete", prompt_done.object.get("resultType").?.string);
}

test "an input required result without input requests or request state is an internal error" {
    var f: Fixture = undefined;
    try f.init(default_options);
    defer f.deinit();
    const v = try f.call(1, "tools/call", meta_all, "\"name\":\"empty_input\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32603), errorCode(v).?);
    try std.testing.expect(v.object.get("result") == null);
}

test "sealed request state is bound to the tool that issued it and expires" {
    var f: Fixture = undefined;
    try f.init(default_options);
    defer f.deinit();

    const first = result(try f.call(1, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{}"));
    const state = first.object.get("requestState").?.string;
    const answer = "\"inputResponses\":{\"user_name\":{\"action\":\"accept\",\"content\":{\"name\":\"Ann\"}}}";
    // The same tool accepts the state.
    const same = result(try f.call(2, "tools/call", meta_elicit, try std.fmt.allocPrint(f.arena(), "\"name\":\"ask_a\",\"arguments\":{{}},{s},\"requestState\":\"{s}\"", .{ answer, state })));
    try std.testing.expectEqualStrings("hello Ann", same.object.get("content").?.array.items[0].object.get("text").?.string);
    // Another tool rejects it.
    const other = try f.call(3, "tools/call", meta_elicit, try std.fmt.allocPrint(f.arena(), "\"name\":\"ask_b\",\"arguments\":{{}},{s},\"requestState\":\"{s}\"", .{ answer, state }));
    try std.testing.expectEqual(@as(i64, -32602), errorCode(other).?);
    try std.testing.expectEqualStrings("invalid_request_state", other.object.get("error").?.object.get("data").?.object.get("reason").?.string);
    // A state that is not sealed by this server is rejected too.
    const forged = try f.call(4, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{},\"requestState\":\"{\\\"round\\\":1}\"");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(forged).?);

    // With a lifetime in the past, every state has expired on the retry.
    var options = default_options;
    options.limits.request_state_ttl = .fromSeconds(-1);
    var g: Fixture = undefined;
    try g.init(options);
    defer g.deinit();
    const round1 = result(try g.call(5, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{}"));
    const stale = round1.object.get("requestState").?.string;
    const expired = try g.call(6, "tools/call", meta_elicit, try std.fmt.allocPrint(g.arena(), "\"name\":\"ask_a\",\"arguments\":{{}},{s},\"requestState\":\"{s}\"", .{ answer, stale }));
    try std.testing.expectEqual(@as(i64, -32602), errorCode(expired).?);
}

test "input responses are validated and unknown keys are ignored" {
    var f: Fixture = undefined;
    try f.init(default_options);
    defer f.deinit();

    // A response of the wrong shape is a JSON-RPC error, not a result.
    const wrong = try f.call(1, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{},\"inputResponses\":{\"user_name\":12345}");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(wrong).?);
    // `inputResponses` itself must be an object.
    const not_object = try f.call(2, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{},\"inputResponses\":5");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(not_object).?);
    // Keys the server did not ask for are ignored.
    const extra = result(try f.call(3, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{},\"inputResponses\":{\"user_name\":{\"action\":\"accept\",\"content\":{\"name\":\"Bo\"}},\"unknown_key\":{\"x\":1},\"other\":7}"));
    try std.testing.expectEqualStrings("complete", extra.object.get("resultType").?.string);
    try std.testing.expectEqualStrings("hello Bo", extra.object.get("content").?.array.items[0].object.get("text").?.string);
    // A retry without the needed response gets a new input request, not an error.
    const missing = result(try f.call(4, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{},\"inputResponses\":{\"wrong_key\":{\"action\":\"accept\"}}"));
    try std.testing.expectEqualStrings("input_required", missing.object.get("resultType").?.string);
}

test "input requests need the client capability for their kind" {
    var options = default_options;
    options.mrtr = .{ .elicitation = true, .sampling = true, .roots = true };
    var f: Fixture = undefined;
    try f.init(options);
    defer f.deinit();

    const no_sampling = try f.call(1, "tools/call", meta_elicit, "\"name\":\"ask_sampling\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_sampling).?);
    try std.testing.expect(no_sampling.object.get("error").?.object.get("data").?.object.get("requiredCapabilities").?.object.get("sampling") != null);
    const no_roots = try f.call(2, "tools/call", meta_elicit, "\"name\":\"ask_roots\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_roots).?);
    const no_elicitation = try f.call(3, "tools/call", meta_none, "\"name\":\"ask_a\",\"arguments\":{}");
    try std.testing.expectEqual(@as(i64, -32021), errorCode(no_elicitation).?);

    const sampling = result(try f.call(4, "tools/call", meta_all, "\"name\":\"ask_sampling\",\"arguments\":{}"));
    try std.testing.expectEqualStrings("sampling/createMessage", sampling.object.get("inputRequests").?.object.get("greeting").?.object.get("method").?.string);
    const roots = result(try f.call(5, "tools/call", meta_all, "\"name\":\"ask_roots\",\"arguments\":{}"));
    try std.testing.expectEqualStrings("roots/list", roots.object.get("inputRequests").?.object.get("roots").?.object.get("method").?.string);

    // A kind the server did not enable is never sent, even to a capable client.
    var g: Fixture = undefined;
    try g.init(default_options);
    defer g.deinit();
    try std.testing.expectEqual(@as(i64, -32603), errorCode(try g.call(6, "tools/call", meta_all, "\"name\":\"ask_sampling\",\"arguments\":{}")).?);
}

// -- Progress ---------------------------------------------------------------------------------

test "progress notifications carry the token, the value, an optional total and an optional message" {
    var f: Fixture = undefined;
    try f.init(default_options);
    defer f.deinit();
    const meta_token =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":"tok-1"}
    ;
    const done = try f.call(1, "tools/call", meta_token, "\"name\":\"report_progress\",\"arguments\":{}");
    try std.testing.expectEqualStrings("done", result(done).object.get("content").?.array.items[0].object.get("text").?.string);
    try std.testing.expectEqual(3, f.harness.out.items.len);

    const first = (try f.frame(0)).object.get("params").?;
    try std.testing.expectEqualStrings("notifications/progress", methodOf(try f.frame(0)).?);
    try std.testing.expectEqualStrings("tok-1", first.object.get("progressToken").?.string);
    try std.testing.expectEqual(@as(f64, 0.5), number(first.object.get("progress").?));
    try std.testing.expectEqual(@as(f64, 1.0), number(first.object.get("total").?));
    try std.testing.expectEqualStrings("half way", first.object.get("message").?.string);

    const second = (try f.frame(1)).object.get("params").?;
    try std.testing.expectEqualStrings("tok-1", second.object.get("progressToken").?.string);
    try std.testing.expectEqual(@as(f64, 0.75), number(second.object.get("progress").?));
    try std.testing.expect(second.object.get("total") == null);
    try std.testing.expect(second.object.get("message") == null);
    // The response is the last frame.
    try std.testing.expect((try f.frame(2)).object.get("result") != null);
}

test "progress needs a progress token of string or integer type" {
    var f: Fixture = undefined;
    try f.init(default_options);
    defer f.deinit();

    // Without a token the server sends no progress.
    _ = try f.call(1, "tools/call", meta_none, "\"name\":\"report_progress\",\"arguments\":{}");
    try std.testing.expectEqual(1, f.harness.out.items.len);

    // An integer token is echoed as an integer.
    const meta_int =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":7}
    ;
    _ = try f.call(2, "tools/call", meta_int, "\"name\":\"report_progress\",\"arguments\":{}");
    try std.testing.expectEqual(3, f.harness.out.items.len);
    try std.testing.expectEqual(@as(i64, 7), (try f.frame(0)).object.get("params").?.object.get("progressToken").?.integer);

    // Other token types are invalid params.
    const meta_float =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":1.5}
    ;
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(3, "tools/call", meta_float, "\"name\":\"report_progress\",\"arguments\":{}")).?);
    const meta_bool =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":true}
    ;
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(4, "tools/call", meta_bool, "\"name\":\"report_progress\",\"arguments\":{}")).?);
    try std.testing.expectEqual(1, f.harness.out.items.len);
}

test "progress notifications of one request are capped" {
    var options = default_options;
    options.limits.max_progress_rate_per_s = 1;
    var f: Fixture = undefined;
    try f.init(options);
    defer f.deinit();
    const meta_token =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":"flood"}
    ;
    const done = try f.call(1, "tools/call", meta_token, "\"name\":\"flood_progress\",\"arguments\":{}");
    try std.testing.expectEqualStrings("flooded", result(done).object.get("content").?.array.items[0].object.get("text").?.string);
    // 60 progress notifications (one per second for a minute), then the response.
    try std.testing.expectEqual(61, f.harness.out.items.len);
}

// -- stdio server -----------------------------------------------------------------------------

/// A stdin substitute. It releases each line only after the server wrote enough frames.
const Script = struct {
    reader: Io.Reader,
    steps: []const Step,
    index: usize = 0,
    transport: *StdioServer,
    out: *Io.Writer.Allocating,

    const Step = struct {
        /// Release the line once the output holds this many frames.
        after_frames: usize = 0,
        line: []const u8,
    };

    fn init(buffer: []u8, transport: *StdioServer, out: *Io.Writer.Allocating, steps: []const Step) Script {
        return .{
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .steps = steps,
            .transport = transport,
            .out = out,
        };
    }

    fn frames(self: *Script) usize {
        const io = std.testing.io;
        self.transport.out_lock.lockUncancelable(io);
        defer self.transport.out_lock.unlock(io);
        return std.mem.count(u8, self.out.written(), "\n");
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        const self: *Script = @alignCast(@fieldParentPtr("reader", r));
        if (self.index == self.steps.len) return error.EndOfStream;
        const step = self.steps[self.index];
        var spins: usize = 0;
        while (self.frames() < step.after_frames and spins < 2000) : (spins += 1) {
            std.testing.io.sleep(.fromMilliseconds(5), .awake) catch return error.ReadFailed;
        }
        // The buffer is large enough for every script; the line goes behind the buffered data.
        std.debug.assert(r.buffer.len - r.end > step.line.len);
        @memcpy(r.buffer[r.end..][0..step.line.len], step.line);
        r.end += step.line.len;
        r.buffer[r.end] = '\n';
        r.end += 1;
        self.index += 1;
        return 0;
    }
};

/// Serve `server` over the stdio transport until the script ends. Returns the parsed frames.
fn runStdio(arena: Allocator, server: *Server, steps: []const Script.Step) ![]Value {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var aw: Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var transport: StdioServer = .init(io, gpa, server, &aw.writer);
    defer transport.deinit();
    var buffer: [16 * 1024]u8 = undefined;
    var script: Script = .init(&buffer, &transport, &aw, steps);
    try transport.run(&script.reader);
    // Every request slot was released.
    try std.testing.expectEqual(0, transport.in_flight.items.len);
    var out: std.ArrayList(Value) = .empty;
    var it = std.mem.splitScalar(u8, aw.written(), '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try out.append(arena, try json.parseTree(arena, line));
    }
    return out.items;
}

fn idOf(v: Value) ?i64 {
    const id = v.object.get("id") orelse return null;
    return if (id == .integer) id.integer else null;
}

test "stdio server stops a cancelled request and ignores invalid cancellations" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var probe: Probe = .{};
    var server = try Server.init(gpa, std.testing.io, default_options);
    defer server.deinit();
    try register(&server, &probe);

    const frames = try runStdio(arena, &server, &.{
        .{ .line = try request(arena, 1, "tools/call", meta_none, "\"name\":\"wait_for_cancel\",\"arguments\":{}") },
        .{ .line = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1,\"reason\":\"user\"}}" },
        // An unknown id and malformed notifications are ignored.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":99}}" },
        .{ .line = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{}}" },
        .{ .line = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}" },
        .{ .line = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":{\"x\":1}}}" },
        // A request that completes, then a late cancellation for it.
        .{ .line = try request(arena, 2, "tools/call", meta_none, "\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":2}") },
        .{ .after_frames = 1, .line = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}" },
    });
    try std.testing.expect(probe.saw_cancel.load(.acquire));
    // The only frame is the response to request 2. The cancelled request got no response.
    try std.testing.expectEqual(1, frames.len);
    try std.testing.expectEqual(@as(i64, 2), idOf(frames[0]).?);
    try std.testing.expectEqualStrings("3", result(frames[0]).object.get("content").?.array.items[0].object.get("text").?.string);
}

test "stdio server ends a listen stream with a result and then notifications/cancelled" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var probe: Probe = .{};
    var server = try Server.init(gpa, std.testing.io, default_options);
    defer server.deinit();
    try register(&server, &probe);

    const frames = try runStdio(arena, &server, &.{
        .{ .line = try request(arena, 7, "subscriptions/listen", meta_none, "\"notifications\":{\"toolsListChanged\":true}") },
        .{ .after_frames = 1, .line = try request(arena, 8, "tools/call", meta_none, "\"name\":\"add\",\"arguments\":{\"a\":2,\"b\":2}") },
        .{ .after_frames = 2, .line = try request(arena, 9, "tools/call", meta_elicit, "\"name\":\"ask_a\",\"arguments\":{}") },
        // The end of the script closes stdin once the three answers are out.
        .{ .after_frames = 3, .line = "" },
    });

    try std.testing.expectEqual(5, frames.len);
    try std.testing.expectEqualStrings("notifications/subscriptions/acknowledged", methodOf(frames[0]).?);
    try std.testing.expectEqual(@as(i64, 8), idOf(frames[1]).?);
    try std.testing.expectEqual(@as(i64, 9), idOf(frames[2]).?);
    try std.testing.expectEqualStrings("input_required", result(frames[2]).object.get("resultType").?.string);
    // Graceful teardown: the listen result, then one cancellation that names the listen request.
    try std.testing.expectEqual(@as(i64, 7), idOf(frames[3]).?);
    try std.testing.expectEqualStrings("complete", result(frames[3]).object.get("resultType").?.string);
    try std.testing.expectEqual(@as(i64, 7), result(frames[3]).object.get("_meta").?.object.get("io.modelcontextprotocol/subscriptionId").?.integer);
    try std.testing.expectEqualStrings("notifications/cancelled", methodOf(frames[4]).?);
    try std.testing.expectEqual(@as(i64, 7), frames[4].object.get("params").?.object.get("requestId").?.integer);

    var cancellations: usize = 0;
    for (frames) |v| {
        // The server never sends a request: a frame has a method or an id, not both.
        try std.testing.expect(!(v.object.get("method") != null and v.object.get("id") != null));
        if (methodOf(v)) |m| if (std.mem.eql(u8, m, "notifications/cancelled")) {
            cancellations += 1;
        };
    }
    try std.testing.expectEqual(1, cancellations);
}

// -- Client over a scripted transport ---------------------------------------------------------

/// A client transport that records each request and answers from a list of results.
const FakeServer = struct {
    arena: Allocator,
    /// The `result` of each round, as JSON text. The fake server sends a text that starts with `!` without a change.
    replies: []const []const u8,
    requests: std.ArrayList(Value) = .empty,
    hook_calls: *const u32,
    /// The hook count when each request arrived.
    hook_calls_seen: std.ArrayList(u32) = .empty,

    fn transport(self: *FakeServer) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .memory, .exchange = exchange, .notify = notify };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *FakeServer = @ptrCast(@alignCast(ptr));
        const round = self.requests.items.len;
        const tree = json.parseTree(self.arena, ex.frame) catch return error.InvalidFrame;
        try self.requests.append(self.arena, tree);
        try self.hook_calls_seen.append(self.arena, self.hook_calls.*);
        const id = tree.object.get("id").?.integer;
        // A late response for an earlier request comes first. The client must ignore it.
        const stale = std.fmt.allocPrint(self.arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{{\"resultType\":\"complete\",\"content\":[{{\"type\":\"text\",\"text\":\"stale\"}}]}}}}", .{id + 1000}) catch return error.OutOfMemory;
        ex.sink.deliver(io, stale) catch return error.InvalidFrame;
        const reply = self.replies[round];
        const frame = if (reply[0] == '!')
            reply[1..]
        else
            std.fmt.allocPrint(self.arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{s}}}", .{ id, reply }) catch return error.OutOfMemory;
        ex.sink.deliver(io, frame) catch return error.InvalidFrame;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = ptr;
        _ = io;
        _ = frame;
    }

    fn params(self: *FakeServer, round: usize) Value {
        return self.requests.items[round].object.get("params").?;
    }
};

fn countingForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    const calls: *u32 = @ptrCast(@alignCast(ctx.userdata.?));
    calls.* += 1;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Alice\"}") };
}

const done_reply = "{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}";
const elicit_request = "{\"k1\":{\"method\":\"elicitation/create\",\"params\":{\"mode\":\"form\",\"message\":\"Name?\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}}}}}}";

fn testClient(calls: *u32) Client {
    return .init(std.testing.allocator, std.testing.io, .{
        .info = .{ .name = "cli", .version = "1" },
        .capabilities = .{ .elicitation = .{} },
        .hooks = .{ .elicit_form = countingForm, .userdata = calls },
    });
}

test "client retries an input required result with a new id, the exact state and the constructed inputs" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var calls: u32 = 0;
    const opaque_state = "opaque \\\"state\\\" {not json} v1.";
    var fake: FakeServer = .{
        .arena = arena,
        .hook_calls = &calls,
        .replies = &.{
            "{\"resultType\":\"input_required\",\"inputRequests\":" ++ elicit_request ++ ",\"requestState\":\"" ++ opaque_state ++ "\"}",
            done_reply,
        },
    };
    var client = testClient(&calls);
    defer client.deinit();
    client.connect(fake.transport());

    const r = try client.callTool(arena, "t", null, .{});
    // The stale response for another id was ignored.
    try std.testing.expectEqualStrings("done", r.content[0].text.text);
    try std.testing.expectEqual(2, fake.requests.items.len);

    // The hook built the input before the retry went out.
    try std.testing.expectEqual(@as(u32, 0), fake.hook_calls_seen.items[0]);
    try std.testing.expectEqual(@as(u32, 1), fake.hook_calls_seen.items[1]);
    const retry = fake.params(1);
    try std.testing.expectEqualStrings("accept", retry.object.get("inputResponses").?.object.get("k1").?.object.get("action").?.string);
    // The state comes back byte for byte.
    try std.testing.expectEqualStrings("opaque \"state\" {not json} v1.", retry.object.get("requestState").?.string);
    try std.testing.expect(fake.params(0).object.get("requestState") == null);
    try std.testing.expect(fake.params(0).object.get("inputResponses") == null);

    // The retry is an independent request: a new id, the full _meta, and a fresh progress token.
    const id0 = fake.requests.items[0].object.get("id").?.integer;
    const id1 = fake.requests.items[1].object.get("id").?.integer;
    try std.testing.expect(id0 != id1);
    for (0..2) |i| {
        const meta = fake.params(i).object.get("_meta").?;
        try std.testing.expectEqualStrings("2026-07-28", meta.object.get("io.modelcontextprotocol/protocolVersion").?.string);
        try std.testing.expect(meta.object.get("io.modelcontextprotocol/clientCapabilities") != null);
        try std.testing.expectEqual(fake.requests.items[i].object.get("id").?.integer, meta.object.get("progressToken").?.integer);
    }
}

test "client omits requestState on the retry when the server sent none" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var calls: u32 = 0;
    var fake: FakeServer = .{
        .arena = arena,
        .hook_calls = &calls,
        .replies = &.{
            "{\"resultType\":\"input_required\",\"inputRequests\":" ++ elicit_request ++ "}",
            done_reply,
        },
    };
    var client = testClient(&calls);
    defer client.deinit();
    client.connect(fake.transport());
    _ = try client.callTool(arena, "t", null, .{});
    try std.testing.expectEqual(2, fake.requests.items.len);
    try std.testing.expect(fake.params(1).object.get("requestState") == null);
    try std.testing.expect(fake.params(1).object.get("inputResponses").?.object.get("k1") != null);
}

test "client retries at once when the server sent only request state" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var calls: u32 = 0;
    var fake: FakeServer = .{
        .arena = arena,
        .hook_calls = &calls,
        .replies = &.{ "{\"resultType\":\"input_required\",\"requestState\":\"s-1\"}", done_reply },
    };
    var client = testClient(&calls);
    defer client.deinit();
    client.connect(fake.transport());
    _ = try client.callTool(arena, "t", null, .{});
    try std.testing.expectEqual(@as(u32, 0), calls);
    try std.testing.expectEqualStrings("s-1", fake.params(1).object.get("requestState").?.string);
}

test "client rejects server requests and input required results on other methods" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var calls: u32 = 0;

    // A JSON-RPC request from the server is a protocol violation.
    var requesting: FakeServer = .{
        .arena = arena,
        .hook_calls = &calls,
        .replies = &.{"!{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"elicitation/create\",\"params\":{}}"},
    };
    var client = testClient(&calls);
    defer client.deinit();
    client.connect(requesting.transport());
    try std.testing.expectError(error.InvalidResponse, client.callTool(arena, "t", null, .{ .retry = .never }));
    try std.testing.expectEqual(@as(u32, 0), calls);

    // `tools/list` cannot answer with an input required result.
    var listing: FakeServer = .{
        .arena = arena,
        .hook_calls = &calls,
        .replies = &.{"{\"resultType\":\"input_required\",\"inputRequests\":" ++ elicit_request ++ "}"},
    };
    client.connect(listing.transport());
    try std.testing.expectError(error.InvalidResponse, client.listTools(arena, null, .{}));
    try std.testing.expectEqual(1, listing.requests.items.len);
    try std.testing.expectEqual(@as(u32, 0), calls);
}

// -- stdio client against the example server process ------------------------------------------

fn exampleServerPath() []const u8 {
    return if (@import("builtin").os.tag == .windows) "zig-out/bin/stdio_server.exe" else "zig-out/bin/stdio_server";
}

/// Records the `notifications/cancelled` that belong to no request in flight.
const Orphans = struct {
    lock: Io.Mutex = .init,
    ids: [8]i64 = undefined,
    count: usize = 0,

    fn record(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *Orphans = @ptrCast(@alignCast(userdata.?));
        if (!std.mem.eql(u8, method, "notifications/cancelled")) return;
        const p = params orelse return;
        const id = p.object.get("requestId") orelse return;
        if (id != .integer) return;
        self.lock.lockUncancelable(std.testing.io);
        defer self.lock.unlock(std.testing.io);
        if (self.count < self.ids.len) {
            self.ids[self.count] = id.integer;
            self.count += 1;
        }
    }

    fn has(self: *Orphans, id: i64) bool {
        self.lock.lockUncancelable(std.testing.io);
        defer self.lock.unlock(std.testing.io);
        for (self.ids[0..self.count]) |x| if (x == id) return true;
        return false;
    }
};

/// One listen stream run in its own task.
const Listener = struct {
    client: *Client,
    token: Transport.CancelToken = .{},
    timeout: ?Io.Duration = null,
    acked: std.atomic.Value(bool) = .init(false),
    /// The subscription id of the acknowledgment.
    subscription_id: i64 = -1,
    /// Acknowledgments that carried another subscription id.
    foreign: u32 = 0,
    outcome: ?Client.RequestError = null,

    fn onNotification(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *Listener = @ptrCast(@alignCast(userdata.?));
        if (!std.mem.eql(u8, method, "notifications/subscriptions/acknowledged")) return;
        const sid = params.?.object.get("_meta").?.object.get("io.modelcontextprotocol/subscriptionId").?.integer;
        if (self.subscription_id != -1 and self.subscription_id != sid) self.foreign += 1;
        self.subscription_id = sid;
        self.acked.store(true, .release);
    }

    fn run(self: *Listener) void {
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const filter: types.SubscriptionsListenRequestParams = .{
            ._meta = .{ .@"io.modelcontextprotocol/protocolVersion" = "2026-07-28", .@"io.modelcontextprotocol/clientCapabilities" = .{} },
            .notifications = .{ .toolsListChanged = true },
        };
        _ = self.client.listen(arena_state.allocator(), filter, .{
            .cancel = &self.token,
            .timeout = self.timeout,
            .retry = .never,
            .on_notification = onNotification,
            .userdata = self,
        }) catch |e| {
            self.outcome = e;
        };
    }
};

test "stdio client cancels requests with notifications/cancelled and keeps listen streams apart" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // The build installs the example before the tests run.
    Io.Dir.cwd().access(io, exampleServerPath(), .{}) catch return error.SkipZigTest;
    const proc = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = &.{exampleServerPath()} });
    defer proc.deinit();
    var orphans: Orphans = .{};
    proc.on_notification = Orphans.record;
    proc.userdata = &orphans;
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(proc.transport());

    // Stream A is cancelled by the caller, stream C times out, stream B stays open.
    var a: Listener = .{ .client = &client };
    var fa = try io.concurrent(Listener.run, .{&a});
    try waitUntil(&a.acked);
    var b: Listener = .{ .client = &client };
    var fb = try io.concurrent(Listener.run, .{&b});
    try waitUntil(&b.acked);
    var c: Listener = .{ .client = &client, .timeout = .fromMilliseconds(500) };
    var fc = try io.concurrent(Listener.run, .{&c});
    try waitUntil(&c.acked);

    a.token.cancel(io, "user cancelled");
    fa.await(io);
    try std.testing.expectEqual(error.Canceled, a.outcome.?);
    fc.await(io);
    try std.testing.expectEqual(error.Timeout, c.outcome.?);
    // Each stream saw only its own acknowledgement.
    try std.testing.expect(a.subscription_id != b.subscription_id and b.subscription_id != c.subscription_id);
    try std.testing.expectEqual(0, a.foreign + b.foreign + c.foreign);

    // Let the server process the two cancellations, then close its stdin. The server ends the
    // remaining stream and names it in a notifications/cancelled. A and C are already gone.
    try io.sleep(.fromMilliseconds(200), .awake);
    proc.close();
    fb.await(io);
    try std.testing.expect(orphans.has(b.subscription_id));
    try std.testing.expect(!orphans.has(a.subscription_id));
    try std.testing.expect(!orphans.has(c.subscription_id));
}

// -- Streamable HTTP --------------------------------------------------------------------------

test "http server stops a handler that writes after the client disconnects" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var probe: Probe = .{};
    var server = try Server.init(gpa, io, default_options);
    defer server.deinit();
    try register(&server, &probe);
    var transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = 0 });
    try transport.bind();
    const Serve = struct {
        fn run(t: *mcp.transport.http.Server) void {
            t.serve() catch {};
        }
    };
    var serving = try io.concurrent(Serve.run, .{&transport});
    defer {
        transport.shutdown();
        serving.await(io);
        transport.deinit();
    }

    const address = try Io.net.IpAddress.parse("127.0.0.1", transport.bound_port);
    const stream = try address.connect(io, .{ .mode = .stream });
    var closed = false;
    defer if (!closed) stream.close(io);
    const body =
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":"t"},"name":"ticker","arguments":{}}}
    ;
    var out_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &out_buf);
    try writer.interface.print("POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: application/json, text/event-stream\r\ncontent-type: application/json\r\nmcp-protocol-version: 2026-07-28\r\nmcp-method: tools/call\r\nmcp-name: ticker\r\ncontent-length: {d}\r\n\r\n{s}", .{ body.len, body });
    try writer.interface.flush();
    // Read until the first progress event arrived, then drop the connection.
    var in_buf: [4096]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(gpa);
    while (std.mem.indexOf(u8, seen.items, "notifications/progress") == null) {
        const chunk = try reader.interface.peekGreedy(1);
        try seen.appendSlice(gpa, chunk);
        reader.interface.toss(chunk.len);
    }
    try std.testing.expect(std.mem.startsWith(u8, seen.items, "HTTP/1.1 200"));
    stream.close(io);
    closed = true;
    // The next write fails and the handler stops.
    try waitUntil(&probe.saw_cancel);
}
