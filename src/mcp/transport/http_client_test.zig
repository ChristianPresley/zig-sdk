//! The MCP client over the Streamable HTTP client transport against the loopback server.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const json = mcp.json;
const types = mcp.types;
const Client = mcp.Client;
const HttpServer = mcp.transport.http.Server;
const HttpClient = mcp.transport.HttpClient;

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(0, 100, null);
    try ctx.progress(50, 100, null);
    try ctx.progress(100, 100, null);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

const HeaderArgs = struct {
    region: []const u8,
    priority: i64,
    pub const json_schema = .{ .fields = .{ .region = .{ .header = "Region" }, .priority = .{ .header = "Priority" } } };
};

fn echoHeaders(ctx: *mcp.RequestContext, args: HeaderArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}/{d}", .{ args.region, args.priority }) };
}

fn askName(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content.?, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "Name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn slow(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    try ctx.io.sleep(.fromMilliseconds(1500), .awake);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "late", .{}) };
}

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Bob\"}") };
}

const ChattyArgs = struct { frames: u32 };

// Sends `frames` progress notifications and `frames` log messages, then a short result.
fn chatty(ctx: *mcp.RequestContext, args: ChattyArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    const total: f64 = @floatFromInt(args.frames);
    for (0..args.frames) |i| {
        try ctx.progress(@floatFromInt(i), total, null);
        try ctx.logText(.info, "chatty", "frame {d}", .{i});
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "done", .{}) };
}

const BigArgs = struct { bytes: u32, progress: bool };

// A result with a text of `bytes` bytes. With `progress`, one progress notification comes
// first, thus the server answers with an SSE stream and not with a JSON body.
fn big(ctx: *mcp.RequestContext, args: BigArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    if (args.progress) try ctx.progress(0, null, null);
    const text = try ctx.arena.alloc(u8, args.bytes);
    @memset(text, 'x');
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{text}) };
}

/// The settings that differ between the tests.
const Setup = struct {
    /// `HttpClient.Options.max_response_bytes`.
    max_response_bytes: usize = 4 << 20,
    /// The limits of the server and of the client.
    limits: mcp.Limits = .{},
};

const Fixture = struct {
    server: mcp.Server,
    transport: HttpServer,
    future: Io.Future(void),
    http: *HttpClient,
    client: Client,

    fn start(self: *Fixture, path: []const u8) !void {
        try self.startWith(path, .{});
    }

    fn startWith(self: *Fixture, path: []const u8, setup: Setup) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, .{
            .info = .{ .name = "http-test", .version = "1" },
            .mrtr = .{ .elicitation = true },
            .capabilities = .{ .logging = .{ .object = .empty } },
            .limits = setup.limits,
        });
        try self.server.addTool(.{ .name = "add" }, add);
        try self.server.addTool(.{ .name = "test_headers" }, echoHeaders);
        try self.server.addToolJson(.{ .name = "ask_name" }, askName);
        try self.server.addToolJson(.{ .name = "slow" }, slow);
        try self.server.addTool(.{ .name = "chatty" }, chatty);
        try self.server.addTool(.{ .name = "big" }, big);
        try self.server.addResource(.{ .uri = "test://big", .name = "big" }, readBig);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0 });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        var url_buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ self.transport.bound_port, path });
        self.http = try HttpClient.init(io, gpa, .{ .url = url, .max_response_bytes = setup.max_response_bytes });
        self.client = .init(gpa, io, .{
            .info = .{ .name = "cli", .version = "1" },
            .capabilities = .{ .elicitation = .{} },
            .hooks = .{ .elicit_form = answerForm },
            .limits = setup.limits,
        });
        self.client.connect(self.http.transport());
    }

    fn serveIgnoringErrors(t: *HttpServer) void {
        t.serve() catch {};
    }

    fn stop(self: *Fixture) void {
        const io = std.testing.io;
        self.client.deinit();
        self.http.deinit();
        self.transport.shutdown();
        self.future.await(io);
        self.transport.deinit();
        self.server.deinit();
    }
};

const Recorder = struct {
    progress: u32 = 0,
    logs: u32 = 0,
    fn onProgress(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
        const self: *Recorder = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.progress += 1;
    }
    fn onLog(userdata: ?*anyopaque, params: types.LoggingMessageNotificationParams) void {
        const self: *Recorder = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.logs += 1;
    }
};

test "http client: json, sse, header mirroring and mrtr" {
    var f: Fixture = undefined;
    try f.start("/mcp");
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try f.client.discover(arena, .{});
    try std.testing.expectEqualStrings("2026-07-28", disc.supportedVersions[0]);

    var rec: Recorder = .{};
    const sum = try f.client.callTool(arena, "add", .{ .a = 2, .b = 3 }, .{ .on_progress = Recorder.onProgress, .userdata = &rec });
    try std.testing.expectEqualStrings("5", sum.content[0].text.text);
    try std.testing.expectEqual(3, rec.progress);

    // Without the annotations learned from tools/list the server rejects the call with
    // -32020. The client then reads tools/list and retries the call with the headers.
    var diag: Client.Diagnostics = .{};
    const first = try f.client.callTool(arena, "test_headers", .{ .region = "us west", .priority = 7 }, .{ .diagnostics = &diag });
    try std.testing.expectEqualStrings("us west/7", first.content[0].text.text);
    try std.testing.expect(diag.rpc_error == null);
    // After tools/list the headers are mirrored, including the base64 sentinel for the space.
    const tools = try f.client.listTools(arena, null, .{});
    try std.testing.expectEqual(6, tools.tools.len);
    const echoed = try f.client.callTool(arena, "test_headers", .{ .region = "us west", .priority = 7 }, .{});
    try std.testing.expectEqualStrings("us west/7", echoed.content[0].text.text);

    // Multi round-trip over HTTP.
    const hello = try f.client.callTool(arena, "ask_name", null, .{});
    try std.testing.expectEqualStrings("hello Bob", hello.content[0].text.text);

    // A timeout cancels the request.
    try std.testing.expectError(error.Timeout, f.client.callTool(arena, "slow", null, .{ .timeout = .fromMilliseconds(200) }));
}

test "http client: an SSE response with more than max_response_bytes of small events succeeds" {
    var limits: mcp.Limits = .{};
    limits.max_progress_rate_per_s = 1000;
    var f: Fixture = undefined;
    try f.startWith("/mcp", .{ .max_response_bytes = 4 << 10, .limits = limits });
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    // Each progress notification and each log message has more than 80 bytes. Thus the 400
    // events have more than 32000 bytes, more than seven times the limit.
    var rec: Recorder = .{};
    const result = try f.client.callTool(arena_state.allocator(), "chatty", .{ .frames = 200 }, .{
        .on_progress = Recorder.onProgress,
        .on_log = Recorder.onLog,
        .userdata = &rec,
        .log_level = .info,
    });
    try std.testing.expectEqualStrings("done", result.content[0].text.text);
    try std.testing.expectEqual(200, rec.progress);
    try std.testing.expectEqual(200, rec.logs);
}

const FrameCounter = struct {
    frames: u32 = 0,
    fn onFrame(ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void {
        _ = io;
        _ = frame;
        const self: *FrameCounter = @ptrCast(@alignCast(ptr));
        self.frames += 1;
    }
};

test "http client: one SSE event or a JSON body over max_response_bytes ends the exchange with error.InvalidFrame" {
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.startWith("/mcp", .{ .max_response_bytes = 4 << 10 });
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const transport = f.http.transport();
    // The result has 8192 bytes of text, two times the limit. With `progress` it is the
    // second event of an SSE stream. Without `progress` it is a JSON body.
    for ([_]bool{ true, false }) |progress| {
        const frame = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{{s},\"name\":\"big\",\"arguments\":{{\"bytes\":8192,\"progress\":{s}}}}}}}", .{ meta_progress, if (progress) "true" else "false" });
        const tree = try json.parseTree(arena, frame);
        var counter: FrameCounter = .{};
        var token: mcp.transport.CancelToken = .{};
        var ex: mcp.transport.Transport.Exchange = .{
            .frame = frame,
            .id = .{ .integer = 1 },
            .method = "tools/call",
            .params = tree.object.get("params"),
            .sink = .{ .ptr = &counter, .on_frame = FrameCounter.onFrame },
            .cancel = &token,
        };
        try std.testing.expectError(error.InvalidFrame, transport.exchange(io, &ex));
        // The progress notification before the large event gets to the sink.
        try std.testing.expectEqual(@as(u32, if (progress) 1 else 0), counter.frames);
    }
    try std.testing.expectError(error.InvalidResponse, f.client.callTool(arena, "big", .{ .bytes = 8192, .progress = true }, .{}));
}

var big_reads: std.atomic.Value(u32) = .init(0);

fn readBig(ctx: *mcp.RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    _ = big_reads.fetchAdd(1, .monotonic);
    const text = try ctx.arena.alloc(u8, 8192);
    @memset(text, 'x');
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = text } };
    return .{ .complete = .{ .contents = contents } };
}

test "http client: the client does not send an idempotent request again after a JSON body over max_response_bytes" {
    var f: Fixture = undefined;
    try f.startWith("/mcp", .{ .max_response_bytes = 4 << 10 });
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    // `resources/read` is idempotent, and no frame arrived. Before, the client took the
    // overflow for a lost stream and sent the request four times.
    big_reads.store(0, .monotonic);
    try std.testing.expectError(error.InvalidResponse, f.client.readResource(arena_state.allocator(), "test://big", .{}));
    try std.testing.expectEqual(1, big_reads.load(.monotonic));
}

const meta_progress =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":1}
;

test "http client: a wrong path is an http status without a message" {
    var f: Fixture = undefined;
    try f.start("/nope");
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.InvalidResponse, f.client.discover(arena_state.allocator(), .{}));
}

const listen_filter = "{\"notifications\":{\"toolsListChanged\":true}}";

test "http client: a listen stream without its acknowledgment in listen_ack_timeout ends with error.Timeout" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // The kernel completes the connection, but nobody answers the request.
    var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var silent = try address.listen(io, .{});
    defer silent.deinit(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/mcp", .{silent.socket.address.getPort()});
    const http = try HttpClient.init(io, gpa, .{ .url = url });
    defer http.deinit();
    var limits: mcp.Limits = .{};
    limits.listen_ack_timeout = .fromMilliseconds(200);
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .limits = limits });
    defer client.deinit();
    client.connect(http.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const filter = try json.parseTree(arena, listen_filter);
    try std.testing.expectError(error.Timeout, client.request(arena, .@"subscriptions/listen", filter, .{}));
}

fn listenUntilCanceled(client: *Client, arena: std.mem.Allocator, token: *mcp.transport.CancelToken) Client.RequestError!void {
    const filter = json.parseTree(arena, listen_filter) catch return error.OutOfMemory;
    _ = try client.request(arena, .@"subscriptions/listen", filter, .{ .cancel = token });
}

test "http client: the acknowledgment stops listen_ack_timeout, and the stream stays open" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start("/mcp");
    defer f.stop();
    f.client.options.limits.listen_ack_timeout = .fromMilliseconds(200);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var token: mcp.transport.CancelToken = .{};
    var future = try io.concurrent(listenUntilCanceled, .{ &f.client, arena_state.allocator(), &token });
    try io.sleep(.fromMilliseconds(600), .awake);
    token.cancel(io, "test done");
    try std.testing.expectError(error.Canceled, future.await(io));
}
