//! The MCP client and server over the gRPC transport, on a loopback socket.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("mcp");
const types = mcp.types;
const json = mcp.json;
const Client = mcp.Client;
const grpc_server = @import("transport/grpc_server.zig");
const grpc_client = @import("transport/grpc_client.zig");
const socket_opts = mcp.transport.socket_opts;
const Connection = @import("http2/Connection.zig");
const connection_test = @import("http2/connection_test.zig");
const ErrorCode = @import("http2/frame.zig").ErrorCode;
const lpm = @import("grpc/lpm.zig");
const messages = @import("protobuf/messages.zig");

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

/// Set when the slow tool stops at a cancel.
var slow_cancelled: std.atomic.Value(bool) = .init(false);

fn slow(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var waited: u32 = 0;
    while (waited < 5000) : (waited += 20) {
        ctx.checkCancel() catch |e| {
            slow_cancelled.store(true, .release);
            return e;
        };
        try ctx.io.sleep(.fromMilliseconds(20), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "late", .{}) };
}

/// The text of the quick tool `big`: larger than the flow control window of the client.
const big_len = 100_000;

fn big(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const text = try ctx.arena.alloc(u8, big_len);
    @memset(text, 'x');
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{text}) };
}

/// A quick tool that takes some time without a wait. The read task gives such calls to the
/// workers of the connection.
/// A quick tool that sends an event to the listen streams.
fn touch(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    ctx.server.notifyToolsListChanged(ctx.io);
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "touched", .{}) };
}

fn spin(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const start = Io.Timestamp.now(ctx.io, .awake);
    while (start.durationTo(Io.Timestamp.now(ctx.io, .awake)).nanoseconds < 300 * std.time.ns_per_us) {}
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "spun", .{}) };
}

fn hidden(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "hidden", .{}) };
}

const nested_schema =
    \\{"type":"object","properties":{"target":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}},"count":{"type":"integer","x-mcp-header":"Count"}}}
;

fn echoNested(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    const target = args.object.get("target") orelse Value.null;
    const region = if (target == .object) json.getString(target, "region") orelse "-" else "-";
    const count = if (args.object.get("count")) |c| c.integer else 0;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}/{d}", .{ region, count }) };
}

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Bob\"}") };
}

const Fixture = struct {
    server: mcp.Server,
    transport: grpc_server.Server,
    future: Io.Future(void),
    /// Set when `serve` returns.
    served: Io.Event,
    channel: *grpc_client.Channel,
    client: Client,

    fn start(self: *Fixture, server_tls: ?*const mcp.tls.Server, client_tls: ?mcp.transport.http1.TlsSetup) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, .{
            .info = .{ .name = "grpc-test", .version = "1" },
            .capabilities = .{ .tools = .{ .listChanged = true } },
            .mrtr = .{ .elicitation = true },
        });
        errdefer self.server.deinit();
        try self.server.addTool(.{ .name = "add" }, add);
        try self.server.addTool(.{ .name = "test_headers" }, echoHeaders);
        try self.server.addToolJson(.{ .name = "ask_name" }, askName);
        try self.server.addToolJson(.{ .name = "slow" }, slow);
        try self.server.addToolJson(.{ .name = "hidden" }, hidden);
        try self.server.addToolJson(.{ .name = "big", .quick = true }, big);
        try self.server.addToolJson(.{ .name = "spin", .quick = true }, spin);
        try self.server.addToolJson(.{ .name = "touch", .quick = true }, touch);
        try self.server.addToolJson(.{ .name = "nested_headers", .input_schema = nested_schema }, echoNested);
        _ = self.server.setToolEnabled(io, "hidden", false);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .tls = server_tls });
        try self.transport.bind();
        self.served = .unset;
        self.future = try io.concurrent(serveIgnoringErrors, .{self});
        self.channel = try grpc_client.Channel.init(io, gpa, .{ .host = "127.0.0.1", .port = self.transport.bound_port, .tls = client_tls });
        self.client = .init(gpa, io, .{
            .info = .{ .name = "cli", .version = "1" },
            .capabilities = .{ .elicitation = .{} },
            .hooks = .{ .elicit_form = answerForm },
        });
        self.client.connect(self.channel.transport());
    }

    fn serveIgnoringErrors(self: *Fixture) void {
        defer self.served.set(std.testing.io);
        self.transport.serve() catch {};
    }

    fn stop(self: *Fixture) void {
        const io = std.testing.io;
        self.client.deinit();
        self.channel.deinit();
        self.transport.shutdown();
        // After `wait_limit`, the cancel stops the connections of the server.
        connection_test.waitSet(io, &self.served) catch {};
        self.future.cancel(io);
        self.transport.deinit();
        self.server.deinit();
    }
};

const Recorder = struct {
    progress: u32 = 0,
    events: std.atomic.Value(u32) = .init(0),
    acked: std.atomic.Value(bool) = .init(false),

    fn onProgress(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
        const self: *Recorder = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.progress += 1;
    }

    fn onNotification(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
        const self: *Recorder = @ptrCast(@alignCast(userdata.?));
        _ = params;
        if (std.mem.eql(u8, method, "notifications/subscriptions/acknowledged")) self.acked.store(true, .release);
        if (std.mem.eql(u8, method, "notifications/tools/list_changed")) _ = self.events.fetchAdd(1, .monotonic);
    }
};

test "grpc: discover, tools, progress, header mirroring, mrtr and errors" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try f.client.discover(arena, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("2026-07-28", disc.supportedVersions[0]);
    const tools = try f.client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqual(8, tools.tools.len);

    var rec: Recorder = .{};
    const sum = try f.client.callTool(arena, "add", .{ .a = 40, .b = 2 }, .{ .timeout = .fromSeconds(10), .on_progress = Recorder.onProgress, .userdata = &rec });
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);
    try std.testing.expectEqual(3, rec.progress);

    // The annotated parameters are mirrored as metadata; the server verifies the mirror.
    const echoed = try f.client.callTool(arena, "test_headers", .{ .region = "eu", .priority = 7 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("eu/7", echoed.content[0].text.text);

    const greeted = try f.client.callTool(arena, "ask_name", null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("hello Bob", greeted.content[0].text.text);

    var diag: Client.Diagnostics = .{};
    try std.testing.expectError(error.Rpc, f.client.callTool(arena, "nope", null, .{ .timeout = .fromSeconds(10), .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
    // An unknown method gets a JSON-RPC error response message, then `grpc-status: 0`.
    try std.testing.expectError(error.Rpc, f.client.requestAs(arena, types.EmptyResult, "nope/method", .{ .object = .empty }, .{ .timeout = .fromSeconds(10), .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32601), diag.rpc_error.?.code);

    // A timeout cancels the call with a reset; the server handler stops.
    slow_cancelled.store(false, .release);
    try std.testing.expectError(error.Timeout, f.client.callTool(arena, "slow", null, .{ .timeout = .fromMilliseconds(300) }));
    try connection_test.waitFlag(std.testing.io, &slow_cancelled);
    // The channel is still usable afterwards.
    const again = try f.client.callTool(arena, "add", .{ .a = 1, .b = 1 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("2", again.content[0].text.text);
}

const ListenJob = struct {
    fixture: *Fixture,
    rec: *Recorder,
    token: mcp.transport.CancelToken = .{},
    result: anyerror!void = {},

    fn run(job: *ListenJob) void {
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const params = json.parseTree(arena, "{\"notifications\":{\"toolsListChanged\":true}}") catch |e| {
            job.result = e;
            return;
        };
        _ = job.fixture.client.requestAs(arena, types.SubscriptionsListenResult, "subscriptions/listen", params, .{
            .cancel = &job.token,
            .on_notification = Recorder.onNotification,
            .userdata = job.rec,
        }) catch |e| {
            job.result = e;
            return;
        };
    }
};

test "grpc: a listen stream delivers events until the client cancels" {
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    var rec: Recorder = .{};
    var job: ListenJob = .{ .fixture = &f, .rec = &rec };
    var future = try io.concurrent(ListenJob.run, .{&job});

    var spins: usize = 0;
    while (!rec.acked.load(.acquire) and spins < 500) : (spins += 1) try io.sleep(.fromMilliseconds(10), .awake);
    try std.testing.expect(rec.acked.load(.acquire));
    _ = f.server.setToolEnabled(io, "hidden", true);
    spins = 0;
    while (rec.events.load(.monotonic) == 0 and spins < 500) : (spins += 1) try io.sleep(.fromMilliseconds(10), .awake);
    try std.testing.expect(rec.events.load(.monotonic) >= 1);
    job.token.cancel(io, "done");
    future.await(io);
    try std.testing.expectError(error.Canceled, job.result);
}

test "grpc: the server and the client set TCP_NODELAY" {
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    // After the call, the server tracks the connection.
    _ = try f.client.discover(arena_state.allocator(), .{ .timeout = .fromSeconds(10) });

    const client_socket = blk: {
        f.channel.lock.lockUncancelable(io);
        defer f.channel.lock.unlock(io);
        break :blk f.channel.link.?.stream.socket;
    };
    try std.testing.expect(try socket_opts.getNoDelay(io, client_socket));

    // The connection stays open until the end of the test, thus its place stays valid.
    const server_socket = blk: {
        try std.testing.expectEqual(1, f.transport.connection_count.load(.seq_cst));
        for (f.transport.connections) |*place| if (place.load(.seq_cst)) |c| break :blk c.stream.socket;
        return error.TestUnexpectedResult;
    };
    try std.testing.expect(try socket_opts.getNoDelay(io, server_socket));
}

test "grpc: a cancel without a shutdown ends serve" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer {
        f.transport.deinit();
        f.server.deinit();
    }
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const discovered = f.client.discover(arena_state.allocator(), .{ .timeout = .fromSeconds(10) });
    f.client.deinit();
    f.channel.deinit();
    // No `shutdown`. Only the cancel can end `serve`.
    f.future.cancel(std.testing.io);
    try std.testing.expect(f.served.isSet());
    try std.testing.expectEqualStrings("2026-07-28", (try discovered).supportedVersions[0]);
    try std.testing.expect(f.transport.closing.load(.acquire));
}

test "grpc over TLS with ALPN h2" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try mcp.tls.CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/p256.crt", "test/fixtures/tls/pem/p256.key");
    defer chain.deinit();
    const chains = [_]*const mcp.tls.CertChain{&chain};
    const tls_server = try mcp.tls.Server.init(.{ .chains = &chains, .alpn = &.{"h2"} });
    var f: Fixture = undefined;
    try f.start(&tls_server, .{ .trust = .self_signed });
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sum = try f.client.callTool(arena, "add", .{ .a = 2, .b = 3 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("5", sum.content[0].text.text);
    try std.testing.expectEqualStrings("h2", f.channel.alpn().?);
}

/// A raw HTTP/2 call to the server, for the paths the SDK client never takes.
const RawCall = struct {
    status: []const u8,
    grpc_status: ?[]const u8,
    error_code: ?[]const u8,
    error_bin: ?[]const u8,
    /// The bytes of the response messages.
    message_bytes: usize = 0,
};

/// How `rawCallWith` sends the request message.
const RawOptions = struct {
    /// Send the message only after the complete response and the reset of the server
    /// arrived. The server answers some calls before it reads the message.
    after_answer: bool = false,
    /// The receive window of each stream of the client.
    initial_window_size: u32 = 1 << 20,
};

fn rawCall(gpa: std.mem.Allocator, io: Io, port: u16, path: []const u8, content_type: []const u8, metadata: []const Connection.Header, body: []const u8) !RawCall {
    return rawCallWith(gpa, io, port, path, content_type, metadata, body, .{});
}

fn rawCallWith(gpa: std.mem.Allocator, io: Io, port: u16, path: []const u8, content_type: []const u8, metadata: []const Connection.Header, body: []const u8, options: RawOptions) !RawCall {
    const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    const stream = try mcp.util.loopback.connect(io, address);
    defer stream.close(io);
    const in_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(in_buf);
    const out_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(out_buf);
    var reader = stream.reader(io, in_buf);
    var writer = stream.writer(io, out_buf);
    const conn = try Connection.init(gpa, io, &reader.interface, &writer.interface, .{ .role = .client, .initial_window_size = options.initial_window_size });
    defer conn.deinit();
    try conn.handshake();
    var run_task: connection_test.RunTask = .{};
    try run_task.start(io, conn);
    defer {
        conn.shutdown();
        stream.shutdown(io, .send) catch {};
        run_task.finish(io);
    }
    const h2 = try conn.openStream();
    defer h2.close();
    // The reset of the watchdog ends each wait on the stream after `wait_limit`.
    var watchdog: connection_test.Watchdog = .{ .stream = h2 };
    try watchdog.start(io);
    const result = rawExchange(gpa, io, h2, path, content_type, metadata, body, options);
    watchdog.finish(io) catch |err| {
        if (result) |r| freeRaw(gpa, r) else |_| {}
        return err;
    };
    return result;
}

fn rawExchange(gpa: std.mem.Allocator, io: Io, h2: *Connection.Stream, path: []const u8, content_type: []const u8, metadata: []const Connection.Header, body: []const u8, options: RawOptions) !RawCall {
    var headers: std.ArrayList(Connection.Header) = .empty;
    defer headers.deinit(gpa);
    try headers.appendSlice(gpa, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = content_type },
        .{ .name = "te", .value = "trailers" },
    });
    try headers.appendSlice(gpa, metadata);
    try h2.sendHeaders(headers.items, false);
    if (options.after_answer) {
        try std.testing.expectEqual(@as(?ErrorCode, .no_error), try connection_test.waitAnswer(io, h2));
    }
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try messages.encodeJsonRpcMessage(gpa, &msg, body);
    try lpm.write(h2, gpa, msg.items, true);
    const response = try h2.waitHeaders();
    var result: RawCall = .{
        .status = try gpa.dupe(u8, Connection.findHeader(response, ":status") orelse ""),
        .grpc_status = null,
        .error_code = null,
        .error_bin = null,
    };
    errdefer freeRaw(gpa, result);
    var source = response;
    if (Connection.findHeader(response, "grpc-status") == null) {
        while (try lpm.read(h2, gpa, 1 << 20)) |payload| {
            result.message_bytes += payload.len;
            gpa.free(payload);
        }
        source = try h2.waitEnd();
    }
    if (Connection.findHeader(source, "grpc-status")) |v| result.grpc_status = try gpa.dupe(u8, v);
    if (Connection.findHeader(source, grpc_server.header_error_code)) |v| result.error_code = try gpa.dupe(u8, v);
    if (Connection.findHeader(source, grpc_server.header_error_bin)) |v| result.error_bin = try gpa.dupe(u8, v);
    return result;
}

fn freeRaw(gpa: std.mem.Allocator, r: RawCall) void {
    gpa.free(r.status);
    if (r.grpc_status) |v| gpa.free(v);
    if (r.error_code) |v| gpa.free(v);
    if (r.error_bin) |v| gpa.free(v);
}

test "grpc: nested header parameters, the safe integer range and one retry after a header mismatch" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const args = try json.parseTree(arena, "{\"target\":{\"region\":\"eu\"},\"count\":3}");

    // The client does not know the annotations yet: the server rejects the call with -32020.
    // The client then reads tools/list and retries with the nested value in the metadata.
    var diag: Client.Diagnostics = .{};
    const done = try f.client.callTool(arena, "nested_headers", args, .{ .timeout = .fromSeconds(10), .diagnostics = &diag });
    try std.testing.expectEqualStrings("eu/3", done.content[0].text.text);
    try std.testing.expect(diag.rpc_error == null);

    // An integer outside the safe range of JavaScript does not go into the metadata.
    try std.testing.expectError(error.InvalidRequest, f.client.callTool(arena, "nested_headers", try json.parseTree(arena, "{\"count\":9007199254740992}"), .{ .timeout = .fromSeconds(10) }));

    // The server rejects raw non-ASCII bytes in mirrored metadata, also when they equal the body.
    const body = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"nested_headers\",\"arguments\":{\"target\":{\"region\":\"\u{fc}\"}}}}";
    const common = [_]Connection.Header{
        .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
        .{ .name = "mcp-method", .value = "tools/call" },
        .{ .name = "mcp-name", .value = "nested_headers" },
    };
    const raw = try rawCall(gpa, io, f.transport.bound_port, grpc_server.call_path, "application/grpc", &(common ++ [_]Connection.Header{.{ .name = "mcp-param-region", .value = "\u{fc}" }}), body);
    defer freeRaw(gpa, raw);
    try std.testing.expectEqualStrings("-32020", raw.error_code.?);
    const encoded = try rawCall(gpa, io, f.transport.bound_port, grpc_server.call_path, "application/grpc", &(common ++ [_]Connection.Header{.{ .name = "mcp-param-region", .value = "=?base64?w7w=?=" }}), body);
    defer freeRaw(gpa, encoded);
    try std.testing.expectEqualStrings("0", encoded.grpc_status.?);
}

test "grpc: unknown path, wrong content type and missing metadata" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    const port = f.transport.bound_port;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}";

    const unknown = try rawCall(gpa, io, port, "/other.Service/Call", "application/grpc", &.{}, body);
    defer freeRaw(gpa, unknown);
    try std.testing.expectEqualStrings("200", unknown.status);
    try std.testing.expectEqualStrings("12", unknown.grpc_status.?);

    const wrong_type = try rawCall(gpa, io, port, grpc_server.call_path, "text/plain", &.{}, body);
    defer freeRaw(gpa, wrong_type);
    try std.testing.expectEqualStrings("415", wrong_type.status);

    // No mcp-method metadata: a header mismatch travels in the trailers.
    const missing = try rawCall(gpa, io, port, grpc_server.call_path, "application/grpc", &.{.{ .name = "mcp-protocol-version", .value = "2026-07-28" }}, body);
    defer freeRaw(gpa, missing);
    try std.testing.expectEqualStrings("3", missing.grpc_status.?);
    try std.testing.expectEqualStrings("-32020", missing.error_code.?);
    const decoder = std.base64.standard.Decoder;
    const frame = try gpa.alloc(u8, try decoder.calcSizeForSlice(missing.error_bin.?));
    defer gpa.free(frame);
    try decoder.decode(frame, missing.error_bin.?);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const tree = try json.parseTree(arena_state.allocator(), frame);
    try std.testing.expectEqual(@as(i64, -32020), tree.object.get("error").?.object.get("code").?.integer);
    try std.testing.expectEqual(@as(i64, 1), tree.object.get("id").?.integer);

    // Another revision without mcp-method and without _meta: the version check comes first,
    // so the answer is -32022, not a header mismatch.
    const old_body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}";
    const old = try rawCall(gpa, io, port, grpc_server.call_path, "application/grpc", &.{.{ .name = "mcp-protocol-version", .value = "2025-11-25" }}, old_body);
    defer freeRaw(gpa, old);
    try std.testing.expectEqualStrings("-32022", old.error_code.?);
    // Another revision in the metadata and the supported one in _meta stays -32020.
    const disagree = try rawCall(gpa, io, port, grpc_server.call_path, "application/grpc", &.{ .{ .name = "mcp-protocol-version", .value = "2025-11-25" }, .{ .name = "mcp-method", .value = "server/discover" } }, body);
    defer freeRaw(gpa, disagree);
    try std.testing.expectEqualStrings("-32020", disagree.error_code.?);

    // The full metadata works from a foreign client too.
    const good = try rawCall(gpa, io, port, grpc_server.call_path, "application/grpc", &.{ .{ .name = "mcp-protocol-version", .value = "2026-07-28" }, .{ .name = "mcp-method", .value = "server/discover" } }, body);
    defer freeRaw(gpa, good);
    try std.testing.expectEqualStrings("0", good.grpc_status.?);
}

test "grpc: a response before the request message stays readable after the reset" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    const port = f.transport.bound_port;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}";

    // The server answers these calls from the headers, and then resets the stream with
    // NO_ERROR (RFC 9113 section 8.1). The client sends the message after the reset. The
    // send does not fail and the client reads the response. Before, the server sent CANCEL
    // and the send failed with `error.StreamReset`.
    const unknown = try rawCallWith(gpa, io, port, "/other.Service/Call", "application/grpc", &.{}, body, .{ .after_answer = true });
    defer freeRaw(gpa, unknown);
    try std.testing.expectEqualStrings("200", unknown.status);
    try std.testing.expectEqualStrings("12", unknown.grpc_status.?);

    const wrong_type = try rawCallWith(gpa, io, port, grpc_server.call_path, "text/plain", &.{}, body, .{ .after_answer = true });
    defer freeRaw(gpa, wrong_type);
    try std.testing.expectEqualStrings("415", wrong_type.status);
}

/// Bind a gRPC server, accept one connection and close it on the server side first. The port
/// of the server then has a connection in `TIME_WAIT`. Then bind a second server to the same
/// port at once. Returns true when the second bind succeeds.
fn rebindAfterTimeWait(reuse_address: bool) !bool {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "rebind", .version = "1" } });
    defer server.deinit();
    var first: grpc_server.Server = .init(io, gpa, &server, .{ .port = 0, .reuse_address = reuse_address });
    try first.bind();
    const port = first.bound_port;
    {
        defer first.deinit();
        var client = try mcp.util.loopback.connect(io, try Io.net.IpAddress.parse("127.0.0.1", port));
        var accepted = try first.listener.?.accept(io);
        // The side that closes first keeps the connection in TIME_WAIT.
        accepted.close(io);
        var buf: [16]u8 = undefined;
        var reader = client.reader(io, &buf);
        _ = reader.interface.peekByte() catch {};
        client.close(io);
    }
    var second: grpc_server.Server = .init(io, gpa, &server, .{ .port = port, .reuse_address = reuse_address });
    defer second.deinit();
    second.bind() catch |e| switch (e) {
        error.AddressInUse => return false,
        else => return e,
    };
    return true;
}

test "grpc: reuse_address binds the port again while a connection of the port is in TIME_WAIT" {
    try std.testing.expect(try rebindAfterTimeWait(true));
    // Without the option, Linux refuses the second bind. Windows does not keep a listen port
    // for a connection in TIME_WAIT, thus the second bind succeeds there also without it.
    const without = try rebindAfterTimeWait(false);
    switch (builtin.os.tag) {
        .linux => try std.testing.expect(!without),
        .windows => try std.testing.expect(without),
        else => {},
    }
}

fn callParams(comptime tool: []const u8) []const u8 {
    return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"" ++ tool ++ "\",\"arguments\":{}}}";
}

fn callMetadata(comptime tool: []const u8) [3]Connection.Header {
    return .{
        .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
        .{ .name = "mcp-method", .value = "tools/call" },
        .{ .name = "mcp-name", .value = tool },
    };
}

test "grpc: a quick call with a response larger than the window of the client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    // The read task cannot wait for the credit of the client, thus a task sends the rest.
    const r = try rawCallWith(gpa, io, f.transport.bound_port, grpc_server.call_path, "application/grpc", &callMetadata("big"), callParams("big"), .{ .initial_window_size = 16 << 10 });
    defer freeRaw(gpa, r);
    try std.testing.expectEqualStrings("0", r.grpc_status.?);
    try std.testing.expect(r.message_bytes > big_len);
}

test "grpc: a burst of quick calls on one connection that the read task and the workers run" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    const address = Io.net.IpAddress.parse("127.0.0.1", f.transport.bound_port) catch unreachable;
    const stream = try mcp.util.loopback.connect(io, address);
    defer stream.close(io);
    const in_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(in_buf);
    const out_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(out_buf);
    var reader = stream.reader(io, in_buf);
    var writer = stream.writer(io, out_buf);
    const conn = try Connection.init(gpa, io, &reader.interface, &writer.interface, .{ .role = .client });
    defer conn.deinit();
    try conn.handshake();
    var run_task: connection_test.RunTask = .{};
    try run_task.start(io, conn);
    defer {
        conn.shutdown();
        stream.shutdown(io, .send) catch {};
        run_task.finish(io);
    }
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try messages.encodeJsonRpcMessage(gpa, &msg, callParams("spin"));
    const headers = [_]Connection.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = grpc_server.call_path },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = "grpc-timeout", .value = "10S" },
    } ++ callMetadata("spin");
    // The calls go out in one write: the frames of a corked stream stay in the buffer.
    const count = 32;
    var streams: [count]*Connection.Stream = undefined;
    var opened: usize = 0;
    defer for (streams[0..opened]) |s| s.close();
    for (&streams, 0..) |*s, i| {
        s.* = try conn.openStream();
        opened += 1;
        s.*.cork();
        try s.*.sendHeaders(&headers, false);
        try lpm.write(s.*, gpa, msg.items, true);
        if (i == count - 1) try s.*.uncork();
    }
    for (streams) |s| {
        var watchdog: connection_test.Watchdog = .{ .stream = s };
        try watchdog.start(io);
        const response = s.waitHeaders();
        var got: usize = 0;
        while (lpm.read(s, gpa, 1 << 20) catch null) |payload| {
            got += payload.len;
            gpa.free(payload);
        }
        const trailers = s.waitEnd();
        try watchdog.finish(io);
        try std.testing.expectEqualStrings("200", Connection.findHeader(try response, ":status").?);
        try std.testing.expectEqualStrings("0", Connection.findHeader(try trailers, "grpc-status").?);
        try std.testing.expect(got > 0);
    }
}

test "grpc: a quick call that sends an event to a listen stream without credit on the same connection" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    const address = Io.net.IpAddress.parse("127.0.0.1", f.transport.bound_port) catch unreachable;
    const stream = try mcp.util.loopback.connect(io, address);
    defer stream.close(io);
    const in_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(in_buf);
    const out_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(out_buf);
    var reader = stream.reader(io, in_buf);
    var writer = stream.writer(io, out_buf);
    // A small window for each stream. The test does not read the listen stream, thus its
    // window stays empty after the first event.
    const conn = try Connection.init(gpa, io, &reader.interface, &writer.interface, .{ .role = .client, .initial_window_size = 64 });
    defer conn.deinit();
    try conn.handshake();
    var run_task: connection_test.RunTask = .{};
    try run_task.start(io, conn);
    defer {
        conn.shutdown();
        stream.shutdown(io, .send) catch {};
        run_task.finish(io);
    }

    const listen_body = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"notifications\":{\"toolsListChanged\":true}}}";
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try messages.encodeJsonRpcMessage(gpa, &msg, listen_body);
    const listen = try conn.openStream();
    defer listen.close();
    var listen_watchdog: connection_test.Watchdog = .{ .stream = listen };
    try listen_watchdog.start(io);
    defer listen_watchdog.finish(io) catch {};
    try listen.sendHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = grpc_server.call_path },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
        .{ .name = "mcp-method", .value = "subscriptions/listen" },
    }, false);
    try lpm.write(listen, gpa, msg.items, true);
    // The headers go out with the acknowledgment.
    _ = try listen.waitHeaders();
    try io.sleep(.fromMilliseconds(50), .awake);

    // Before, the first event made the read task wait for credit on the listen stream, and
    // only the read task reads that credit: the connection stopped.
    for (0..10) |_| {
        const h2 = try conn.openStream();
        defer h2.close();
        var watchdog: connection_test.Watchdog = .{ .stream = h2 };
        try watchdog.start(io);
        const r = rawExchange(gpa, io, h2, grpc_server.call_path, "application/grpc", &callMetadata("touch"), callParams("touch"), .{});
        watchdog.finish(io) catch |err| {
            if (r) |c| freeRaw(gpa, c) else |_| {}
            return err;
        };
        const call = try r;
        defer freeRaw(gpa, call);
        try std.testing.expectEqualStrings("0", call.grpc_status.?);
    }
    listen.cancel();
}

/// Wait until the server has at least `want` parked connections, at most 10 s.
fn waitParked(f: *Fixture, want: usize) !void {
    const io = std.testing.io;
    var waited: u32 = 0;
    while (waited < 10_000) : (waited += 10) {
        if (f.transport.parker.parked_count.load(.acquire) >= want) return;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.Timeout;
}

test "grpc: an idle connection parks without a task and continues at the next call" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Calls in a fast sequence: the read task reads at once after each call. When the calls
    // stop, the parker sends a PING, and the connection parks after the answer.
    for (0..20) |_| _ = try f.client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    try waitParked(&f, 1);
    // A parked connection gets a new task for the next call.
    const tools = try f.client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqual(8, tools.tools.len);
    try waitParked(&f, 1);
    // `stop` ends the parked connection.
}

/// A client connection that makes one call and stays open.
const IdleClient = struct {
    stream: Io.net.Stream = undefined,
    in_buf: [16 << 10]u8 = undefined,
    out_buf: [16 << 10]u8 = undefined,
    reader: Io.net.Stream.Reader = undefined,
    writer: Io.net.Stream.Writer = undefined,
    conn: *Connection = undefined,
    run_task: connection_test.RunTask = .{},
    ok: bool = false,

    fn open(c: *IdleClient, io: Io, port: u16) !void {
        const gpa = std.testing.allocator;
        c.stream = try mcp.util.loopback.connect(io, Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable);
        c.reader = c.stream.reader(io, &c.in_buf);
        c.writer = c.stream.writer(io, &c.out_buf);
        c.conn = try Connection.init(gpa, io, &c.reader.interface, &c.writer.interface, .{ .role = .client });
        try c.conn.handshake();
        try c.run_task.start(io, c.conn);
    }

    fn call(c: *IdleClient, io: Io) void {
        const gpa = std.testing.allocator;
        const h2 = c.conn.openStream() catch return;
        defer h2.close();
        const r = rawExchange(gpa, io, h2, grpc_server.call_path, "application/grpc", &callMetadata("big"), callParams("big"), .{}) catch return;
        defer freeRaw(gpa, r);
        c.ok = r.grpc_status != null and std.mem.eql(u8, r.grpc_status.?, "0");
    }

    fn close(c: *IdleClient, io: Io) void {
        c.conn.shutdown();
        c.stream.shutdown(io, .send) catch {};
        c.run_task.finish(io);
        c.conn.deinit();
        c.stream.close(io);
    }
};

test "grpc: many clients that make one call at the same time all park" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    const count = 24;
    const clients = try gpa.alloc(IdleClient, count);
    defer gpa.free(clients);
    var opened: usize = 0;
    defer for (clients[0..opened]) |*c| c.close(io);
    for (clients) |*c| {
        c.* = .{};
        try c.open(io, f.transport.bound_port);
        opened += 1;
    }
    // The calls come at the same time. The runners of the parker serve them.
    var group: Io.Group = .init;
    for (clients) |*c| try group.concurrent(io, IdleClient.call, .{ c, io });
    try group.await(io);
    for (clients) |c| try std.testing.expect(c.ok);
    // The new connections park.
    try waitParked(&f, count);
}

test "grpc: clients that send a part of the preface or of a frame and stop do not hold the runners" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    // One more stalled client than the parker has runs. Half of them stop in the preface,
    // the others after the preface and half of a frame header.
    const count = f.transport.parker.max_runs + 1;
    const stalled = try gpa.alloc(Io.net.Stream, count);
    defer gpa.free(stalled);
    var opened: usize = 0;
    defer for (stalled[0..opened]) |s| s.close(io);
    const address = Io.net.IpAddress.parse("127.0.0.1", f.transport.bound_port) catch unreachable;
    for (stalled, 0..) |*s, i| {
        s.* = try mcp.util.loopback.connect(io, address);
        opened += 1;
        var buf: [64]u8 = undefined;
        var w = s.writer(io, &buf);
        if (i % 2 == 0) {
            try w.interface.writeAll(frame_preface[0..10]);
        } else {
            try w.interface.writeAll(frame_preface);
            try w.interface.writeAll(&.{ 0, 0, 4 });
        }
        try w.interface.flush();
    }
    try io.sleep(.fromMilliseconds(100), .awake);
    // A call of another client still gets a runner.
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const tools = try f.client.listTools(arena_state.allocator(), null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqual(8, tools.tools.len);
}

const frame_preface = @import("http2/frame.zig").preface;

/// A task that writes to the socket of a connection of the server until a write waits. The
/// client reads nothing, thus the buffers of the socket fill. `sent` counts the writes.
fn Filler(comptime C: type) type {
    return struct {
        fn run(conn: *C, sent: *std.atomic.Value(u64)) void {
            const io = std.testing.io;
            var buf: [256]u8 = undefined;
            var w = conn.stream.writer(io, &buf);
            const chunk: [16 << 10]u8 = @splat(0);
            while (true) {
                w.interface.writeAll(&chunk) catch return;
                w.interface.flush() catch return;
                _ = sent.fetchAdd(1, .monotonic);
            }
        }
    };
}

test "grpc: the shutdown ends a connection whose GOAWAY waits for a client that does not read" {
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(null, null);
    defer f.stop();
    // A client that sends the preface and its settings, and then reads nothing.
    const address = Io.net.IpAddress.parse("127.0.0.1", f.transport.bound_port) catch unreachable;
    const raw = try mcp.util.loopback.connect(io, address);
    defer raw.close(io);
    var buf: [64]u8 = undefined;
    var w = raw.writer(io, &buf);
    try w.interface.writeAll(frame_preface);
    try w.interface.writeAll(&.{ 0, 0, 0, 4, 0, 0, 0, 0, 0 });
    try w.interface.flush();
    try waitParked(&f, 1);
    const conn = blk: {
        for (f.transport.connections) |*place| if (place.load(.seq_cst)) |c| if (c.h2_ready.load(.seq_cst)) break :blk c;
        return error.TestUnexpectedResult;
    };
    // Fill the buffers of the socket until a write waits, then stop that write. The next
    // write of the server, the `GOAWAY` of the shutdown, waits too.
    var sent: std.atomic.Value(u64) = .init(0);
    var filler = try io.concurrent(Filler(@TypeOf(conn.*)).run, .{ conn, &sent });
    var last: u64 = 0;
    var still: u32 = 0;
    var rounds: u32 = 0;
    while (still < 5 and rounds < 400) : (rounds += 1) {
        try io.sleep(.fromMilliseconds(50), .awake);
        const now = sent.load(.monotonic);
        still = if (now == last) still + 1 else 0;
        last = now;
    }
    filler.cancel(io);
    try std.testing.expect(still >= 5);
    // The shutdown cancels the waiting `GOAWAY` after a short time, and `serve` returns.
    f.transport.shutdown();
    try connection_test.waitSet(io, &f.served);
}
