//! Loopback tests for the WebSocket transport: the SDK server, the SDK client and a raw peer
//! that writes frames by hand.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const types = mcp.types;
const json = mcp.json;
const websocket = mcp.transport.websocket;
const ws = websocket.frame;
const Client = mcp.Client;
const jwt = mcp.auth.jwt;

const gpa = std.testing.allocator;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;

// -- Handlers -----------------------------------------------------------------------------------

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(0, 2, null);
    try ctx.progress(1, 2, null);
    try ctx.progress(2, 2, null);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

var started: std.atomic.Value(u32) = .init(0);
var cancelled: std.atomic.Value(u32) = .init(0);
var closed_by_peer: std.atomic.Value(u32) = .init(0);

fn resetCounters() void {
    started.store(0, .release);
    cancelled.store(0, .release);
    closed_by_peer.store(0, .release);
}

/// Wait for the cancellation of the request, at most ten seconds.
fn waitCancel(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    _ = started.fetchAdd(1, .acq_rel);
    ctx.cancel.event.waitTimeout(ctx.io, .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } }) catch {};
    if (!ctx.isCancelled()) return .{ .complete = try types.CallToolResult.text(ctx.arena, "not cancelled", .{}) };
    _ = cancelled.fetchAdd(1, .acq_rel);
    if (ctx.cancel.reason) |r| {
        if (std.mem.eql(u8, r, mcp.transport.stdio.Server.connection_closed_reason)) _ = closed_by_peer.fetchAdd(1, .acq_rel);
    }
    return error.Canceled;
}

/// Sends five progress notifications, 20 milliseconds apart, then completes.
fn pulse(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        try ctx.progress(@floatFromInt(i), 5, null);
        try ctx.io.sleep(.fromMilliseconds(20), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "pulsed", .{}) };
}

/// Asks for a name in the first round and greets in the second round.
fn askName(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content orelse .null, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

/// Answers with the subject of the principal.
fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const p = ctx.principal() orelse return .{ .complete = try types.CallToolResult.text(ctx.arena, "nobody", .{}) };
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{p.subject orelse "?"}) };
}

fn readHello(ctx: *mcp.RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "hello over websocket" } };
    return .{ .complete = .{ .contents = contents } };
}

fn greetPrompt(ctx: *mcp.RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    const name = if (args) |a| a.map.get("name") orelse "world" else "world";
    const messages = try ctx.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = try std.fmt.allocPrint(ctx.arena, "Greet {s}", .{name}) } } };
    return .{ .complete = .{ .messages = messages } };
}

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Ann\"}") };
}

/// Wait until `counter` reaches `want`, at most ten seconds.
fn awaitCount(counter: *std.atomic.Value(u32), want: u32) !void {
    const io = std.testing.io;
    var waited: u32 = 0;
    while (counter.load(.acquire) < want) : (waited += 1) {
        if (waited > 1000) return error.TestTimeout;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

/// Wait until `cond` gives true, at most ten seconds.
fn awaitTrue(context: anytype, comptime cond: fn (@TypeOf(context)) bool) !void {
    const io = std.testing.io;
    var waited: u32 = 0;
    while (!cond(context)) : (waited += 1) {
        if (waited > 1000) return error.TestTimeout;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

// -- Fixture ------------------------------------------------------------------------------------

const Fixture = struct {
    server: mcp.Server,
    transport: websocket.Server,
    future: Io.Future(void),
    halted: bool = false,
    url_buf: [64]u8 = undefined,

    fn start(self: *Fixture, limits: mcp.Limits, options: websocket.Options) !void {
        const io = std.testing.io;
        self.halted = false;
        self.server = try mcp.Server.init(gpa, io, .{
            .info = .{ .name = "websocket-test", .version = "1" },
            .capabilities = .{
                .tools = .{ .listChanged = true },
                .resources = .{ .listChanged = true },
                .prompts = .{ .listChanged = true },
            },
            .mrtr = .{ .elicitation = true },
            .limits = limits,
        });
        errdefer self.server.deinit();
        try self.server.addTool(.{ .name = "add" }, add);
        try self.server.addToolJson(.{ .name = "wait_cancel" }, waitCancel);
        try self.server.addToolJson(.{ .name = "pulse" }, pulse);
        try self.server.addToolJson(.{ .name = "ask" }, askName);
        try self.server.addToolJson(.{ .name = "whoami" }, whoami);
        try self.server.addResource(.{ .uri = "test://hello", .name = "hello", .mime_type = "text/plain" }, readHello);
        try self.server.addPrompt(.{ .name = "greet", .description = "Greets", .arguments = &.{.{ .name = "name", .required = false }} }, greetPrompt);
        var opts = options;
        opts.port = 0;
        self.transport = .init(io, gpa, &self.server, opts);
        errdefer self.transport.deinit();
        try self.transport.bind();
    }

    /// Start the accept loop. The tests with authorization set the resource server first.
    fn run(self: *Fixture) !void {
        self.future = try std.testing.io.concurrent(serveIgnoringErrors, .{&self.transport});
    }

    fn serveIgnoringErrors(t: *websocket.Server) void {
        t.serve() catch {};
    }

    fn halt(self: *Fixture) void {
        if (self.halted) return;
        self.halted = true;
        self.transport.shutdown();
        self.future.await(std.testing.io);
    }

    fn stop(self: *Fixture) void {
        self.halt();
        self.transport.deinit();
        self.server.deinit();
    }

    fn port(self: *const Fixture) u16 {
        return self.transport.bound_port;
    }

    fn url(self: *Fixture, scheme: []const u8) []const u8 {
        return std.fmt.bufPrint(&self.url_buf, "{s}://127.0.0.1:{d}/mcp", .{ scheme, self.port() }) catch unreachable;
    }
};

const Connected = struct {
    transport: *websocket.Client,
    client: Client,

    fn open(self: *Connected, options: websocket.ClientOptions) !void {
        self.transport = try websocket.Client.init(std.testing.io, gpa, options);
        self.client = .init(gpa, std.testing.io, .{
            .info = .{ .name = "ws-client", .version = "1" },
            .capabilities = .{ .elicitation = .{} },
            .hooks = .{ .elicit_form = answerForm },
        });
        self.client.connect(self.transport.transport());
    }

    fn close(self: *Connected) void {
        self.client.deinit();
        self.transport.deinit();
    }
};

// -- Raw peer -----------------------------------------------------------------------------------

/// A client that writes the upgrade and the frames by hand.
const Raw = struct {
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    frames: ws.Reader,
    masks: ws.MaskSource,
    read_buf: [64 * 1024]u8,
    write_buf: [16 * 1024]u8,

    const Reply = struct {
        status: u16,
        head: []const u8,

        /// The value of the first header with `name`, or null.
        fn header(self: Reply, name: []const u8) ?[]const u8 {
            var it = std.mem.splitSequence(u8, self.head, "\r\n");
            _ = it.next();
            while (it.next()) |line| {
                const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
                if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " \t");
            }
            return null;
        }
    };

    fn open(port: u16) !*Raw {
        const io = std.testing.io;
        const raw = try gpa.create(Raw);
        errdefer gpa.destroy(raw);
        const address = try Io.net.IpAddress.parse("127.0.0.1", port);
        raw.stream = try address.connect(io, .{ .mode = .stream });
        raw.reader = raw.stream.reader(io, &raw.read_buf);
        raw.writer = raw.stream.writer(io, &raw.write_buf);
        raw.frames = .{ .in = &raw.reader.interface, .gpa = gpa, .role = .client, .max_frame_bytes = 1 << 24, .max_message_bytes = 1 << 24 };
        raw.masks = try .init(io);
        return raw;
    }

    fn close(raw: *Raw) void {
        raw.frames.deinit();
        raw.stream.close(std.testing.io);
        gpa.destroy(raw);
    }

    /// Write `request` and read the head of the response.
    fn exchangeHead(raw: *Raw, arena: std.mem.Allocator, request: []const u8) !Reply {
        try raw.writer.interface.writeAll(request);
        try raw.writer.interface.flush();
        var hr: std.http.Reader = .{ .in = &raw.reader.interface, .interface = undefined, .state = .ready, .max_head_len = 16 << 10 };
        const bytes = try hr.receiveHead();
        const head = try arena.dupe(u8, bytes);
        return .{ .status = try std.fmt.parseInt(u16, head[9..12], 10), .head = head };
    }

    /// An upgrade request with the key of RFC 6455 section 1.3. `lines` replaces the standard
    /// lines when it is not null. `extra` adds lines.
    fn upgrade(raw: *Raw, arena: std.mem.Allocator, lines: ?[]const u8, extra: []const u8) !Reply {
        const standard = "host: 127.0.0.1\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\nsec-websocket-protocol: mcp\r\n";
        const request = try std.fmt.allocPrint(arena, "GET /mcp HTTP/1.1\r\n{s}{s}\r\n", .{ lines orelse standard, extra });
        return raw.exchangeHead(arena, request);
    }

    fn send(raw: *Raw, fin: bool, opcode: ws.Opcode, payload: []const u8, masked: bool) !void {
        try ws.writeFrame(&raw.writer.interface, fin, opcode, payload, if (masked) raw.masks.next() else null);
        try raw.writer.interface.flush();
    }

    fn sendText(raw: *Raw, text: []const u8) !void {
        try raw.send(true, .text, text, true);
    }

    fn sendBytes(raw: *Raw, bytes: []const u8) !void {
        try raw.writer.interface.writeAll(bytes);
        try raw.writer.interface.flush();
    }

    fn next(raw: *Raw) !ws.Event {
        return raw.frames.next();
    }

    /// Read until a close frame and check its code. Then answer it, as a client does.
    fn expectClose(raw: *Raw, code: u16) !void {
        while (true) {
            switch (try raw.next()) {
                .close => |c| {
                    try std.testing.expectEqual(code, c.code.?);
                    var buf: [ws.max_control_payload]u8 = undefined;
                    raw.send(true, .close, ws.closePayload(&buf, @enumFromInt(code), ""), true) catch {};
                    return;
                },
                else => {},
            }
        }
    }

    /// Read until the server ends the TCP connection.
    fn expectEnd(raw: *Raw) !void {
        _ = raw.reader.interface.discardRemaining() catch {};
    }

    /// Read text messages until the one with the id `id`.
    fn awaitResponse(raw: *Raw, arena: std.mem.Allocator, id: i64) !mcp.jsonrpc.Message {
        while (true) {
            switch (try raw.next()) {
                .text => |t| {
                    const msg = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, t));
                    switch (msg) {
                        .response => |r| if (r.id.eql(.{ .integer = id })) return msg,
                        .error_response => |e| if (e.id) |eid| if (eid.eql(.{ .integer = id })) return msg,
                        else => {},
                    }
                },
                else => {},
            }
        }
    }
};

fn listRequest(arena: std.mem.Allocator, id: i64) ![]const u8 {
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"tools/list\",\"params\":{s}}}", .{ id, "{" ++ meta_none ++ "}" });
}

// -- The MCP client over the WebSocket client ---------------------------------------------------

test "websocket: discover, tools with progress, resources, prompts and a multi round-trip request" {
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    try c.open(.{ .url = f.url("ws") });
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try c.client.discover(arena, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("2026-07-28", disc.supportedVersions[0]);
    const tools = try c.client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqual(5, tools.tools.len);

    const Progress = struct {
        var count: u32 = 0;
        fn on(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
            _ = userdata;
            _ = params;
            count += 1;
        }
    };
    const sum = try c.client.callTool(arena, "add", .{ .a = 40, .b = 2 }, .{ .timeout = .fromSeconds(10), .on_progress = Progress.on });
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);
    try std.testing.expectEqual(3, Progress.count);

    const resources = try c.client.listResources(arena, null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqual(1, resources.resources.len);
    const read = try c.client.readResource(arena, "test://hello", .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("hello over websocket", read.contents[0].text.text);

    const prompts = try c.client.listPrompts(arena, null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqual(1, prompts.prompts.len);
    const prompt = try c.client.getPrompt(arena, "greet", .{ .name = "Zig" }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("Greet Zig", prompt.messages[0].content.text.text);

    // The multi round-trip request is a second request with the answer on the same connection.
    const greeted = try c.client.callTool(arena, "ask", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("hello Ann", greeted.content[0].text.text);

    // A handler without authorization sees no principal.
    const who = try c.client.callTool(arena, "whoami", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("nobody", who.content[0].text.text);
    try std.testing.expectEqual(1, f.transport.connectionCount());
}

test "websocket: a timeout sends notifications/cancelled and the connection stays open" {
    resetCounters();
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    try c.open(.{ .url = f.url("ws") });
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try std.testing.expectError(error.Timeout, c.client.callTool(arena, "wait_cancel", null, .{ .timeout = .fromMilliseconds(300) }));
    try awaitCount(&cancelled, 1);
    try std.testing.expectEqual(0, closed_by_peer.load(.acquire));

    // A cancel token of the caller also sends `notifications/cancelled`.
    const Job = struct {
        client: *Client,
        token: mcp.transport.CancelToken = .{},
        result: ?Client.RequestError = null,
        fn run(job: *@This()) void {
            var a: std.heap.ArenaAllocator = .init(gpa);
            defer a.deinit();
            _ = job.client.callTool(a.allocator(), "wait_cancel", null, .{ .timeout = .fromSeconds(20), .cancel = &job.token }) catch |e| {
                job.result = e;
            };
        }
    };
    var job: Job = .{ .client = &c.client };
    var future = try std.testing.io.concurrent(Job.run, .{&job});
    try awaitCount(&started, 2);
    job.token.cancel(std.testing.io, "user");
    future.await(std.testing.io);
    try std.testing.expectEqual(error.Canceled, job.result.?);
    try awaitCount(&cancelled, 2);

    const again = try c.client.callTool(arena, "add", .{ .a = 1, .b = 2 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("3", again.content[0].text.text);
    try std.testing.expectEqual(1, f.transport.connectionCount());
}

/// One `pulse` call that records the progress tokens it receives.
const PulseJob = struct {
    client: *Client,
    tokens: [16]i64 = undefined,
    count: usize = 0,
    ok: bool = false,

    fn onProgress(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
        const job: *PulseJob = @ptrCast(@alignCast(userdata.?));
        if (job.count == job.tokens.len) return;
        job.tokens[job.count] = switch (params.progressToken) {
            .integer => |i| i,
            else => -1,
        };
        job.count += 1;
    }

    fn run(job: *PulseJob) void {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const result = job.client.callTool(arena_state.allocator(), "pulse", null, .{ .timeout = .fromSeconds(10), .on_progress = onProgress, .userdata = job }) catch return;
        job.ok = std.mem.eql(u8, "pulsed", result.content[0].text.text);
    }
};

test "websocket: concurrent requests share one connection and get their own progress" {
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    try c.open(.{ .url = f.url("ws") });
    defer c.close();

    var jobs: [4]PulseJob = undefined;
    for (&jobs) |*j| j.* = .{ .client = &c.client };
    var group: Io.Group = .init;
    for (&jobs) |*j| try group.concurrent(io, PulseJob.run, .{j});
    try group.await(io);
    for (jobs, 0..) |job, i| {
        try std.testing.expect(job.ok);
        try std.testing.expectEqual(5, job.count);
        for (job.tokens[0..job.count]) |token| try std.testing.expectEqual(job.tokens[0], token);
        for (jobs[i + 1 ..]) |other| try std.testing.expect(other.tokens[0] != job.tokens[0]);
    }
    // All requests went on one connection.
    try std.testing.expectEqual(1, f.transport.connectionCount());
}

/// Counts the progress callbacks of one request and records whether one of them ran on the
/// thread of the caller.
const InlineProgress = struct {
    caller: std.Thread.Id,
    calls: u32 = 0,
    on_caller: bool = false,

    fn onProgress(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
        const self: *InlineProgress = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.calls += 1;
        if (std.Thread.getCurrentId() == self.caller) self.on_caller = true;
    }
};

test "websocket: the client calls the progress callback of an inline request on the reader task" {
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    try c.open(.{ .url = f.url("ws") });
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    var progress: InlineProgress = .{ .caller = std.Thread.getCurrentId() };
    const result = try c.client.callTool(arena_state.allocator(), "pulse", null, .{
        .timeout = .fromSeconds(10),
        .inline_notifications = true,
        .on_progress = InlineProgress.onProgress,
        .userdata = &progress,
    });
    try std.testing.expectEqualStrings("pulsed", result.content[0].text.text);
    // The five callbacks ran before the call returned, and the reader task of the connection
    // ran them. Without the option, the task of the request runs them.
    try std.testing.expectEqual(5, progress.calls);
    try std.testing.expect(!progress.on_caller);
}

const Recorder = struct {
    events: std.atomic.Value(u32) = .init(0),
    acked: std.atomic.Value(bool) = .init(false),

    fn onNotification(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *Recorder = @ptrCast(@alignCast(userdata.?));
        _ = params;
        if (std.mem.eql(u8, method, "notifications/subscriptions/acknowledged")) self.acked.store(true, .release);
        if (std.mem.eql(u8, method, "notifications/tools/list_changed")) _ = self.events.fetchAdd(1, .monotonic);
    }

    fn isAcked(self: *Recorder) bool {
        return self.acked.load(.acquire);
    }

    fn hasEvent(self: *Recorder) bool {
        return self.events.load(.acquire) > 0;
    }
};

const ListenJob = struct {
    client: *Client,
    rec: *Recorder,
    token: mcp.transport.CancelToken = .{},
    result: ?Client.RequestError = null,

    fn run(job: *ListenJob) void {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const filter: types.SubscriptionsListenRequestParams = .{
            ._meta = .{ .@"io.modelcontextprotocol/protocolVersion" = "2026-07-28", .@"io.modelcontextprotocol/clientCapabilities" = .{} },
            .notifications = .{ .toolsListChanged = true },
        };
        _ = job.client.listen(arena_state.allocator(), filter, .{
            .cancel = &job.token,
            .retry = .never,
            .on_notification = Recorder.onNotification,
            .userdata = job.rec,
        }) catch |e| {
            job.result = e;
        };
    }
};

test "websocket: a listen stream delivers events until the client cancels it" {
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    try c.open(.{ .url = f.url("ws") });
    defer c.close();

    var rec: Recorder = .{};
    var job: ListenJob = .{ .client = &c.client, .rec = &rec };
    var future = try io.concurrent(ListenJob.run, .{&job});
    try awaitTrue(&rec, Recorder.isAcked);
    _ = f.server.setToolEnabled(io, "whoami", false);
    try awaitTrue(&rec, Recorder.hasEvent);
    // Other requests run on the connection while the stream is open.
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const tools = try c.client.listTools(arena_state.allocator(), null, .{ .timeout = .fromSeconds(10), .cache_mode = .bypass });
    try std.testing.expectEqual(4, tools.tools.len);
    job.token.cancel(io, "done");
    future.await(io);
    try std.testing.expectEqual(error.Canceled, job.result.?);
}

test "websocket: shutdown ends a listen stream with its result, then closes with 1001" {
    resetCounters();
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = try Raw.open(f.port());
    defer raw.close();
    try std.testing.expectEqual(101, (try raw.upgrade(arena, null, "")).status);
    try raw.sendText("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"subscriptions/listen\",\"params\":{\"notifications\":{\"toolsListChanged\":true}," ++ meta_none ++ "}}");
    const ack = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, (try raw.next()).text));
    try std.testing.expectEqualStrings("notifications/subscriptions/acknowledged", ack.notification.method);
    try raw.sendText("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"wait_cancel\"," ++ meta_none ++ "}}");
    try awaitCount(&started, 1);

    var halting = try std.testing.io.concurrent(Fixture.halt, .{&f});
    defer halting.await(std.testing.io);
    // The listen stream ends with its result and `notifications/cancelled`. The other request
    // ends without a response. Then the close frame comes.
    const result = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, (try raw.next()).text));
    try std.testing.expect(result.response.id.eql(.{ .integer = 1 }));
    const note = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, (try raw.next()).text));
    try std.testing.expectEqualStrings("notifications/cancelled", note.notification.method);
    try raw.expectClose(1001);
    try raw.expectEnd();
    try std.testing.expectEqual(1, cancelled.load(.acquire));
}

test "websocket server cancels the requests of a closed connection" {
    resetCounters();
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const raw = try Raw.open(f.port());
    try std.testing.expectEqual(101, (try raw.upgrade(arena_state.allocator(), null, "")).status);
    try raw.sendText("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"wait_cancel\"," ++ meta_none ++ "}}");
    try awaitCount(&started, 1);
    raw.close();
    try awaitCount(&closed_by_peer, 1);
}

test "websocket: the client closes with 1000 and connects again after a lost connection" {
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    try c.open(.{ .url = f.url("ws") });
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try c.transport.connect();
    try std.testing.expect(c.transport.isConnected());
    _ = try c.client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    // The connection goes away without a close frame. The next request connects again.
    c.transport.dropConnection();
    try std.testing.expect(!c.transport.isConnected());
    const sum = try c.client.callTool(arena, "add", .{ .a = 2, .b = 3 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("5", sum.content[0].text.text);
    try std.testing.expect(c.transport.isConnected());

    // A clean close: the server answers the close frame and ends the connection.
    c.transport.close();
    try std.testing.expectError(error.Closed, c.client.callTool(arena, "add", .{ .a = 2, .b = 3 }, .{ .timeout = .fromSeconds(10) }));
    try awaitTrue(&f.transport, noConnections);
}

// -- Protocol rules on the raw peer -------------------------------------------------------------

/// Open a connection with the standard upgrade, send `bytes` and expect a close frame with
/// `code`.
fn expectViolation(f: *Fixture, bytes: []const u8, code: u16) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const raw = try Raw.open(f.port());
    defer raw.close();
    try std.testing.expectEqual(101, (try raw.upgrade(arena_state.allocator(), null, "")).status);
    try raw.sendBytes(bytes);
    try raw.expectClose(code);
    try raw.expectEnd();
}

/// A masked frame with the mask 0 0 0 0, so the payload stays readable.
fn maskedFrame(comptime b0: u8, comptime payload: []const u8) []const u8 {
    const len: u8 = @intCast(payload.len);
    return &[_]u8{ b0, 0x80 | len, 0, 0, 0, 0 } ++ payload;
}

test "websocket server closes with the code of each protocol violation" {
    var limits: mcp.Limits = .{};
    limits.websocket.max_frame_bytes = 600;
    limits.websocket.max_message_bytes = 1000;
    var f: Fixture = undefined;
    try f.start(limits, .{});
    try f.run();
    defer f.stop();

    // A frame without a mask.
    try expectViolation(&f, &.{ 0x81, 0x02, '{', '}' }, 1002);
    // A binary message.
    try expectViolation(&f, comptime maskedFrame(0x82, "ab"), 1003);
    // Invalid UTF-8 in a text message.
    try expectViolation(&f, comptime maskedFrame(0x81, "\xc3\x28"), 1007);
    // A reserved bit, a reserved opcode, a fragmented ping and a continuation without a start.
    try expectViolation(&f, comptime maskedFrame(0xC1, "{}"), 1002);
    try expectViolation(&f, comptime maskedFrame(0x83, "{}"), 1002);
    try expectViolation(&f, comptime maskedFrame(0x09, ""), 1002);
    try expectViolation(&f, comptime maskedFrame(0x80, "{}"), 1002);
    // A close frame with a code that a peer cannot send.
    try expectViolation(&f, comptime maskedFrame(0x88, "\x03\xed"), 1002);

    // A frame above `max_frame_bytes`, and fragments above `max_message_bytes`.
    var w: Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    try ws.writeFrame(&w.writer, true, .text, "x" ** 700, .{ 1, 2, 3, 4 });
    try expectViolation(&f, w.written(), 1009);
    w.clearRetainingCapacity();
    try ws.writeFrame(&w.writer, false, .text, "x" ** 500, .{ 1, 2, 3, 4 });
    try ws.writeFrame(&w.writer, true, .continuation, "x" ** 600, .{ 1, 2, 3, 4 });
    try expectViolation(&f, w.written(), 1009);
}

test "websocket server answers a ping, joins fragments and echoes the close code" {
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const raw = try Raw.open(f.port());
    defer raw.close();
    const reply = try raw.upgrade(arena, null, "");
    try std.testing.expectEqual(101, reply.status);
    // RFC 6455 section 1.3: the accept key of the sample key.
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", reply.header("sec-websocket-accept").?);
    try std.testing.expectEqualStrings("mcp", reply.header("sec-websocket-protocol").?);
    try std.testing.expect(reply.header("sec-websocket-extensions") == null);

    try raw.send(true, .ping, "are you there", true);
    try std.testing.expectEqualStrings("are you there", (try raw.next()).pong);

    // A request in three fragments with a ping between them.
    const request = try listRequest(arena, 7);
    try raw.send(false, .text, request[0..10], true);
    try raw.send(true, .ping, "", true);
    try raw.send(false, .continuation, request[10..20], true);
    try raw.send(true, .continuation, request[20..], true);
    try std.testing.expectEqualStrings("", (try raw.next()).pong);
    const msg = try raw.awaitResponse(arena, 7);
    try std.testing.expect(msg == .response);

    // A message that is not JSON-RPC gets an error response, and the connection stays open.
    try raw.sendText("{\"jsonrpc\":\"2.0\",\"id\":8}");
    const invalid = try raw.awaitResponse(arena, 8);
    try std.testing.expectEqual(@as(i64, -32600), invalid.error_response.code);
    try raw.sendText("not json");
    const parse_error = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, (try raw.next()).text));
    try std.testing.expectEqual(@as(i64, -32700), parse_error.error_response.code);

    // The server answers a close frame with the same code and ends the connection.
    var buf: [ws.max_control_payload]u8 = undefined;
    try raw.send(true, .close, ws.closePayload(&buf, @enumFromInt(4000), "bye"), true);
    const answer = (try raw.next()).close;
    try std.testing.expectEqual(4000, answer.code.?);
    try raw.expectEnd();
}

test "websocket server refuses an upgrade that breaks a rule" {
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const Case = struct { lines: []const u8, status: u16 };
    const cases = [_]Case{
        // No subprotocol, and a list without `mcp`.
        .{ .lines = "host: 127.0.0.1\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n", .status = 400 },
        .{ .lines = "host: 127.0.0.1\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\nsec-websocket-protocol: chat, mcp-v2\r\n", .status = 400 },
        // Another version of the protocol.
        .{ .lines = "host: 127.0.0.1\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 8\r\nsec-websocket-protocol: mcp\r\n", .status = 426 },
        // A key that is not 16 bytes in base64.
        .{ .lines = "host: 127.0.0.1\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: c2hvcnQ=\r\nsec-websocket-version: 13\r\nsec-websocket-protocol: mcp\r\n", .status = 400 },
        // No `Connection: Upgrade`, and no `Upgrade` header.
        .{ .lines = "host: 127.0.0.1\r\nupgrade: websocket\r\nconnection: keep-alive\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\nsec-websocket-protocol: mcp\r\n", .status = 400 },
        .{ .lines = "host: 127.0.0.1\r\n", .status = 426 },
        // No Host, and a Host that is not loopback.
        .{ .lines = "upgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\nsec-websocket-protocol: mcp\r\n", .status = 400 },
        .{ .lines = "host: evil.example\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\nsec-websocket-protocol: mcp\r\n", .status = 403 },
    };
    for (cases) |case| {
        const raw = try Raw.open(f.port());
        defer raw.close();
        const reply = try raw.upgrade(arena, case.lines, "");
        try std.testing.expectEqual(case.status, reply.status);
        if (case.status == 426) try std.testing.expectEqualStrings("13", reply.header("sec-websocket-version").?);
    }

    // DNS rebinding protection: a foreign origin gets 403, a loopback origin passes.
    {
        const raw = try Raw.open(f.port());
        defer raw.close();
        try std.testing.expectEqual(403, (try raw.upgrade(arena, null, "origin: https://evil.example\r\n")).status);
    }
    {
        const raw = try Raw.open(f.port());
        defer raw.close();
        try std.testing.expectEqual(101, (try raw.upgrade(arena, null, "origin: http://localhost:5173\r\n")).status);
    }
    // Another path, another method.
    {
        const raw = try Raw.open(f.port());
        defer raw.close();
        try std.testing.expectEqual(404, (try raw.exchangeHead(arena, "GET /other HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")).status);
    }
    {
        const raw = try Raw.open(f.port());
        defer raw.close();
        const reply = try raw.exchangeHead(arena, "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n");
        try std.testing.expectEqual(405, reply.status);
        try std.testing.expectEqualStrings("GET", reply.header("allow").?);
    }
}

test "websocket client refuses a server that is not a WebSocket server" {
    // A plain HTTP server answers the upgrade with 405. The client reports the status.
    const io = std.testing.io;
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "http", .version = "1" } });
    defer server.deinit();
    var http_transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = 0 });
    defer http_transport.deinit();
    try http_transport.bind();
    const Serve = struct {
        fn run(t: *mcp.transport.http.Server) void {
            t.serve() catch {};
        }
    };
    var serving = try io.concurrent(Serve.run, .{&http_transport});
    defer {
        http_transport.shutdown();
        serving.await(io);
    }
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "ws://127.0.0.1:{d}/mcp", .{http_transport.bound_port});
    const t = try websocket.Client.init(io, gpa, .{ .url = url });
    defer t.deinit();
    try std.testing.expectError(error.HttpStatus, t.connect());
    try std.testing.expectEqual(405, t.last_status.load(.acquire));
}

// -- Limits -------------------------------------------------------------------------------------

test "websocket limits: connections, requests in flight and the handshake time" {
    resetCounters();
    var limits: mcp.Limits = .{};
    limits.websocket.max_connections = 2;
    limits.websocket.max_in_flight_requests = 1;
    limits.websocket.handshake_timeout = .fromMilliseconds(200);
    var f: Fixture = undefined;
    try f.start(limits, .{});
    try f.run();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The handshake timeout closes a connection that sends no upgrade request.
    {
        const silent = try Raw.open(f.port());
        defer silent.close();
        try silent.expectEnd();
    }
    try awaitTrue(&f.transport, noConnections);

    const first = try Raw.open(f.port());
    defer first.close();
    try std.testing.expectEqual(101, (try first.upgrade(arena, null, "")).status);
    // A second request above the limit of one in flight gets -32603 at once.
    try first.sendText("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"wait_cancel\"," ++ meta_none ++ "}}");
    try awaitCount(&started, 1);
    try first.sendText(try listRequest(arena, 2));
    const refused = try first.awaitResponse(arena, 2);
    try std.testing.expectEqual(@as(i64, -32603), refused.error_response.code);
    try std.testing.expectEqualStrings(mcp.transport.stdio.Server.too_many_requests_message, refused.error_response.message);
    // The cancellation of the first request still arrives, and frees the place.
    try first.sendText("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}");
    try awaitCount(&cancelled, 1);
    var tries: u32 = 0;
    while (true) : (tries += 1) {
        try first.sendText(try listRequest(arena, 100 + tries));
        const msg = try first.awaitResponse(arena, 100 + tries);
        if (msg == .response) break;
        if (tries > 100) return error.TestTimeout;
        try std.testing.io.sleep(.fromMilliseconds(10), .awake);
    }

    // The limit of two connections: the third connection ends at once.
    const second = try Raw.open(f.port());
    defer second.close();
    try std.testing.expectEqual(101, (try second.upgrade(arena, null, "")).status);
    const third = try Raw.open(f.port());
    defer third.close();
    if (third.upgrade(arena, null, "")) |_| return error.TestUnexpectedResult else |_| {}
}

test "websocket rate limits: the connections of one IP address share the bucket of the address" {
    resetCounters();
    var limits: mcp.Limits = .{};
    limits.rate_limits.tool_calls = .{ .count = 1, .period = .fromSeconds(3600) };
    var f: Fixture = undefined;
    try f.start(limits, .{});
    try f.run();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const first = try Raw.open(f.port());
    defer first.close();
    try std.testing.expectEqual(101, (try first.upgrade(arena, null, "")).status);
    try first.sendText("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":1}," ++ meta_none ++ "}}");
    try std.testing.expect((try first.awaitResponse(arena, 1)) == .response);

    // A new connection from the same address does not get a new bucket.
    const second = try Raw.open(f.port());
    defer second.close();
    try std.testing.expectEqual(101, (try second.upgrade(arena, null, "")).status);
    try second.sendText("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"add\",\"arguments\":{\"a\":1,\"b\":1}," ++ meta_none ++ "}}");
    const refused = try second.awaitResponse(arena, 2);
    try std.testing.expectEqual(@as(i64, -31429), refused.error_response.code);
}

fn noConnections(t: *websocket.Server) bool {
    return t.connectionCount() == 0;
}

test "websocket limits: the server sends pings and closes an idle connection with 1001" {
    var limits: mcp.Limits = .{};
    limits.websocket.ping_interval = .fromMilliseconds(100);
    limits.websocket.idle_timeout = .fromMilliseconds(400);
    var f: Fixture = undefined;
    try f.start(limits, .{});
    try f.run();
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const raw = try Raw.open(f.port());
    defer raw.close();
    try std.testing.expectEqual(101, (try raw.upgrade(arena_state.allocator(), null, "")).status);
    // The peer does not answer the pings. The server pings, then closes.
    var pings: u32 = 0;
    while (true) {
        switch (try raw.next()) {
            .ping => pings += 1,
            .close => |c| {
                try std.testing.expectEqual(1001, c.code.?);
                try raw.send(true, .close, "\x03\xe9", true);
                break;
            },
            else => {},
        }
    }
    try std.testing.expect(pings >= 2);
    try raw.expectEnd();
}

test "websocket client answers pings, so the connection does not become idle" {
    var limits: mcp.Limits = .{};
    limits.websocket.ping_interval = .fromMilliseconds(50);
    limits.websocket.idle_timeout = .fromMilliseconds(300);
    var f: Fixture = undefined;
    try f.start(limits, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    // The client sends no pings of its own: the pings of the server keep the connection.
    var client_limits: mcp.Limits = .{};
    client_limits.websocket.ping_interval = .zero;
    try c.open(.{ .url = f.url("ws"), .limits = client_limits });
    defer c.close();
    try c.transport.connect();
    try std.testing.io.sleep(.fromMilliseconds(800), .awake);
    try std.testing.expect(c.transport.isConnected());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    _ = try c.client.listTools(arena_state.allocator(), null, .{ .timeout = .fromSeconds(10) });
}

test "websocket client closes with 1009 when a message is above its limit" {
    var f: Fixture = undefined;
    try f.start(.{}, .{});
    try f.run();
    defer f.stop();
    var c: Connected = undefined;
    var limits: mcp.Limits = .{};
    limits.websocket.max_message_bytes = 64;
    limits.websocket.max_frame_bytes = 64;
    try c.open(.{ .url = f.url("ws"), .limits = limits });
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    // The tools/list result is larger than 64 bytes. The client closes the connection.
    try std.testing.expectError(error.Closed, c.client.listTools(arena_state.allocator(), null, .{ .timeout = .fromSeconds(10), .retry = .never }));
}

// -- TLS ----------------------------------------------------------------------------------------

test "websocket over TLS (wss) with the SDK TLS server and client" {
    const io = std.testing.io;
    var chain = try mcp.tls.CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/chain.crt", "test/fixtures/tls/pem/chain-leaf.key");
    defer chain.deinit();
    const chains = [_]*const mcp.tls.CertChain{&chain};
    const tls_server = try mcp.tls.Server.init(.{ .chains = &chains, .alpn = &.{"http/1.1"} });
    var f: Fixture = undefined;
    try f.start(.{}, .{ .tls = &tls_server });
    try f.run();
    defer f.stop();
    var set: mcp.tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");

    var c: Connected = undefined;
    try c.open(.{ .url = f.url("wss"), .tls = .{ .trust = .{ .ca_set = &set }, .server_name = "localhost" } });
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const disc = try c.client.discover(arena, .{ .timeout = .fromSeconds(10) });
    try std.testing.expect(disc.capabilities.tools != null);
    const sum = try c.client.callTool(arena, "add", .{ .a = 20, .b = 22 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);
    const greeted = try c.client.callTool(arena, "ask", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("hello Ann", greeted.content[0].text.text);

    // A client that does not trust the certificate gets no connection.
    const untrusted = try websocket.Client.init(io, gpa, .{ .url = f.url("wss"), .tls = .{ .trust = .self_signed } });
    defer untrusted.deinit();
    try std.testing.expectError(error.TlsFailed, untrusted.connect());
}

// -- Authorization ------------------------------------------------------------------------------

const secret = "websocket-test-secret-with-32-bytes";

/// The clock of the token checks.
var auth_now: std.atomic.Value(i64) = .init(1000);

fn authClock() i64 {
    return auth_now.load(.acquire);
}

const AuthFixture = struct {
    base: Fixture,
    keys: [1]jwt.Key,
    jv: mcp.auth.JwtVerifier,
    rs: mcp.auth.ResourceServer,
    resource: []u8,
    metadata_url: []u8,

    fn start(self: *AuthFixture, policy: ?*const mcp.auth.DpopPolicy) !void {
        auth_now.store(1000, .release);
        try self.base.start(.{}, .{ .auth = &self.rs, .clock = authClock });
        // The resource is the http form of the WebSocket URL, with the bound port.
        self.resource = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/mcp", .{self.base.port()});
        self.metadata_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/.well-known/oauth-protected-resource/mcp", .{self.base.port()});
        self.keys = .{.{ .alg = .HS256, .material = .{ .secret = secret } }};
        self.jv = .{ .options = .{ .keys = &self.keys, .audience = self.resource }, .clock = .{ .fixed = authClock } };
        self.rs = .{
            .resource = self.resource,
            .resource_metadata_url = self.metadata_url,
            .authorization_servers = &.{"http://127.0.0.1:9/as"},
            .required_scopes = &.{"mcp:read"},
            .verifier = self.jv.verifier(),
            .dpop = policy,
        };
        try self.base.run();
    }

    fn stop(self: *AuthFixture) void {
        self.base.stop();
        gpa.free(self.resource);
        gpa.free(self.metadata_url);
    }

    fn token(self: *AuthFixture, arena: std.mem.Allocator, subject: []const u8, exp: i64, extra: []const u8) ![]const u8 {
        const claims = try std.fmt.allocPrint(arena, "{{\"sub\":\"{s}\",\"aud\":\"{s}\",\"exp\":{d},\"scope\":\"mcp:read\"{s}}}", .{ subject, self.resource, exp, extra });
        return jwt.signHs256(arena, claims, secret, null);
    }
};

/// An authorization provider for the tests. It has no token before the first challenge. With
/// a prover, it gives DPoP proofs.
const TestProvider = struct {
    tokens: []const []const u8,
    /// Which token comes next. Each challenge moves to the next token.
    index: usize = 0,
    has_token: bool = false,
    challenges: u32 = 0,
    nonces: u32 = 0,
    url_ok: bool = true,
    expected_url: []const u8 = "",
    prover: ?*mcp.auth.DpopProver = null,

    fn provider(self: *TestProvider) mcp.auth.Provider {
        return .{ .ptr = self, .vtable = if (self.prover != null) &dpop_vtable else &bearer_vtable };
    }

    const bearer_vtable: mcp.auth.Provider.VTable = .{ .token = token, .handle_challenge = challenge };
    const dpop_vtable: mcp.auth.Provider.VTable = .{ .token = token, .handle_challenge = challenge, .credentials = credentials, .dpop_nonce = nonce };

    fn current(self: *TestProvider) ?[]const u8 {
        if (!self.has_token) return null;
        return self.tokens[@min(self.index, self.tokens.len - 1)];
    }

    fn token(ptr: *anyopaque, arena: std.mem.Allocator) ?[]const u8 {
        const self: *TestProvider = @ptrCast(@alignCast(ptr));
        const t = self.current() orelse return null;
        return arena.dupe(u8, t) catch null;
    }

    fn challenge(ptr: *anyopaque, arena: std.mem.Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void {
        _ = arena;
        _ = status;
        _ = www_authenticate;
        const self: *TestProvider = @ptrCast(@alignCast(ptr));
        if (attempt > 2) return error.TooManyAttempts;
        if (!std.mem.eql(u8, server_url, self.expected_url)) self.url_ok = false;
        self.challenges += 1;
        if (self.has_token) self.index += 1;
        self.has_token = true;
    }

    fn credentials(ptr: *anyopaque, arena: std.mem.Allocator, method: []const u8, url: []const u8) ?mcp.auth.common.Credentials {
        const self: *TestProvider = @ptrCast(@alignCast(ptr));
        const t = self.current() orelse return null;
        if (!std.mem.eql(u8, method, "GET") or !std.mem.eql(u8, url, self.expected_url)) self.url_ok = false;
        const proof = self.prover.?.proof(arena, method, url, t) catch return null;
        return .{ .scheme = .dpop, .token = arena.dupe(u8, t) catch return null, .proof = proof };
    }

    fn nonce(ptr: *anyopaque, url: []const u8, value: []const u8) void {
        const self: *TestProvider = @ptrCast(@alignCast(ptr));
        self.nonces += 1;
        self.prover.?.rememberNonce(url, value) catch {};
    }
};

test "websocket authorization: challenge at the upgrade, metadata and the principal" {
    var f: AuthFixture = undefined;
    try f.start(null);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The protected resource metadata on the listener of the WebSocket server.
    {
        const raw = try Raw.open(f.base.port());
        defer raw.close();
        const reply = try raw.exchangeHead(arena, "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        try std.testing.expectEqual(200, reply.status);
        const body = try raw.reader.interface.allocRemaining(arena, .limited(1 << 16));
        const doc = try json.parseTree(arena, body);
        try std.testing.expectEqualStrings(f.resource, doc.object.get("resource").?.string);
    }
    // No token: 401 with the challenge, before the upgrade.
    {
        const raw = try Raw.open(f.base.port());
        defer raw.close();
        const reply = try raw.upgrade(arena, null, "");
        try std.testing.expectEqual(401, reply.status);
        const www = reply.header("www-authenticate").?;
        try std.testing.expect(std.mem.indexOf(u8, www, f.metadata_url) != null);
        try std.testing.expect(std.mem.indexOf(u8, www, "scope=\"mcp:read\"") != null);
    }
    // A token without the scope: 403.
    {
        const weak = try jwt.signHs256(arena, try std.fmt.allocPrint(arena, "{{\"sub\":\"eve\",\"aud\":\"{s}\",\"exp\":2000,\"scope\":\"mcp:write\"}}", .{f.resource}), secret, null);
        const raw = try Raw.open(f.base.port());
        defer raw.close();
        const reply = try raw.upgrade(arena, null, try std.fmt.allocPrint(arena, "authorization: Bearer {s}\r\n", .{weak}));
        try std.testing.expectEqual(403, reply.status);
    }

    // A valid token in a static header: the handler sees the principal.
    const good = try f.token(arena, "alice", 2000, "");
    const auth_header = try std.mem.concat(arena, u8, &.{ "Bearer ", good });
    {
        var c: Connected = undefined;
        try c.open(.{ .url = f.base.url("ws"), .extra_headers = &.{.{ .name = "authorization", .value = auth_header }} });
        defer c.close();
        const who = try c.client.callTool(arena, "whoami", null, .{ .timeout = .fromSeconds(10) });
        try std.testing.expectEqualStrings("alice", who.content[0].text.text);
    }

    // Without a token the client reports the status of the refused upgrade.
    {
        var c: Connected = undefined;
        try c.open(.{ .url = f.base.url("ws") });
        defer c.close();
        try std.testing.expectError(error.InvalidResponse, c.client.callTool(arena, "whoami", null, .{ .timeout = .fromSeconds(10) }));
        try std.testing.expectEqual(401, c.transport.last_status.load(.acquire));
    }

    // A provider: the 401 runs its challenge flow with the http form of the URL, then the
    // client connects again with the token.
    {
        var provider: TestProvider = .{ .tokens = &.{good}, .expected_url = f.resource };
        var c: Connected = undefined;
        try c.open(.{ .url = f.base.url("ws"), .auth_provider = provider.provider() });
        defer c.close();
        const who = try c.client.callTool(arena, "whoami", null, .{ .timeout = .fromSeconds(10) });
        try std.testing.expectEqualStrings("alice", who.content[0].text.text);
        try std.testing.expectEqual(1, provider.challenges);
        try std.testing.expect(provider.url_ok);
    }
}

test "websocket authorization: the server closes with 1008 when the token expires" {
    var f: AuthFixture = undefined;
    try f.start(null);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A raw peer sees the close code.
    const first = try f.token(arena, "alice", 2000, "");
    const raw = try Raw.open(f.base.port());
    defer raw.close();
    try std.testing.expectEqual(101, (try raw.upgrade(arena, null, try std.fmt.allocPrint(arena, "authorization: Bearer {s}\r\n", .{first}))).status);

    // The provider gets a new token for the second connection.
    const second = try f.token(arena, "bob", 3000, "");
    var provider: TestProvider = .{ .tokens = &.{ first, second }, .expected_url = f.resource };
    var c: Connected = undefined;
    try c.open(.{ .url = f.base.url("ws"), .auth_provider = provider.provider() });
    defer c.close();
    const before = try c.client.callTool(arena, "whoami", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("alice", before.content[0].text.text);

    // The token of the first connection expires at 2000.
    auth_now.store(2001, .release);
    try raw.expectClose(1008);
    try awaitTrue(c.transport, struct {
        fn gone(t: *websocket.Client) bool {
            return !t.isConnected();
        }
    }.gone);
    // The token of the provider expired: the upgrade gets 401, and the challenge gives the
    // next token.
    const after = try c.client.callTool(arena, "whoami", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("bob", after.content[0].text.text);
}

test "websocket authorization: a DPoP-bound token with a nonce, method GET and the http form of the URL" {
    const io = std.testing.io;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var prover: mcp.auth.DpopProver = try .init(io, gpa, .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{41} ** 32) });
    defer prover.deinit();
    prover.clock = authClock;
    const issuer: mcp.auth.dpop.NonceIssuer = try .init(io);
    const policy: mcp.auth.DpopPolicy = .{ .required = true, .io = io, .clock = authClock, .verify = .{ .nonce = &issuer } };
    var f: AuthFixture = undefined;
    try f.start(&policy);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bound = try f.token(arena, "carol", 2000, try std.fmt.allocPrint(arena, ",\"cnf\":{{\"jkt\":\"{s}\"}}", .{prover.jkt}));
    var provider: TestProvider = .{ .tokens = &.{bound}, .expected_url = f.resource, .prover = &prover };
    var c: Connected = undefined;
    try c.open(.{ .url = f.base.url("ws"), .auth_provider = provider.provider() });
    defer c.close();
    // The first upgrade has no token (401), the second has a proof without the nonce
    // (use_dpop_nonce), the third has the nonce of the server.
    const who = try c.client.callTool(arena, "whoami", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("carol", who.content[0].text.text);
    try std.testing.expectEqual(1, provider.challenges);
    try std.testing.expect(provider.nonces >= 1);
    try std.testing.expect(provider.url_ok);

    // A bound token as a bearer token gets a DPoP challenge.
    const raw = try Raw.open(f.base.port());
    defer raw.close();
    const reply = try raw.upgrade(arena, null, try std.fmt.allocPrint(arena, "authorization: Bearer {s}\r\n", .{bound}));
    try std.testing.expectEqual(401, reply.status);
    try std.testing.expect(std.mem.startsWith(u8, reply.header("www-authenticate").?, "DPoP "));
}
