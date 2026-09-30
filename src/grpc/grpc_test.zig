//! The MCP client and server over the gRPC transport, on a loopback socket.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("mcp");
const types = mcp.types;
const json = mcp.json;
const Client = mcp.Client;
const grpc_server = @import("transport/grpc_server.zig");
const grpc_client = @import("transport/grpc_client.zig");
const Connection = @import("http2/Connection.zig");
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

fn slow(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var waited: u32 = 0;
    while (waited < 5000) : (waited += 20) {
        try ctx.checkCancel();
        try ctx.io.sleep(.fromMilliseconds(20), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "late", .{}) };
}

fn hidden(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "hidden", .{}) };
}

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Bob\"}") };
}

const Fixture = struct {
    server: mcp.Server,
    transport: grpc_server.Server,
    future: Io.Future(void),
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
        _ = self.server.setToolEnabled(io, "hidden", false);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .tls = server_tls });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        self.channel = try grpc_client.Channel.init(io, gpa, .{ .host = "127.0.0.1", .port = self.transport.bound_port, .tls = client_tls });
        self.client = .init(gpa, io, .{
            .info = .{ .name = "cli", .version = "1" },
            .capabilities = .{ .elicitation = .{} },
            .hooks = .{ .elicit_form = answerForm },
        });
        self.client.connect(self.channel.transport());
    }

    fn serveIgnoringErrors(t: *grpc_server.Server) void {
        t.serve() catch {};
    }

    fn stop(self: *Fixture) void {
        const io = std.testing.io;
        self.client.deinit();
        self.channel.deinit();
        self.transport.shutdown();
        self.future.await(io);
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
    try std.testing.expectEqual(4, tools.tools.len);

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
    // An unknown method ends the call in the trailers; the client still sees the error.
    try std.testing.expectError(error.Rpc, f.client.requestAs(arena, types.EmptyResult, "nope/method", .{ .object = .empty }, .{ .timeout = .fromSeconds(10), .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32601), diag.rpc_error.?.code);

    // A timeout cancels the call with a reset; the server handler stops.
    try std.testing.expectError(error.Timeout, f.client.callTool(arena, "slow", null, .{ .timeout = .fromMilliseconds(300) }));
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
};

fn rawCall(gpa: std.mem.Allocator, io: Io, port: u16, path: []const u8, content_type: []const u8, metadata: []const Connection.Header, body: []const u8) !RawCall {
    const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    const stream = try address.connect(io, .{ .mode = .stream });
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
    var run_future = try io.concurrent(Connection.run, .{conn});
    defer {
        conn.shutdown();
        stream.shutdown(io, .send) catch {};
        run_future.await(io);
    }
    const h2 = try conn.openStream();
    defer h2.close();
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
    var source = response;
    if (Connection.findHeader(response, "grpc-status") == null) {
        while (try lpm.read(h2, gpa, 1 << 20)) |payload| gpa.free(payload);
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

    // The full metadata works from a foreign client too.
    const good = try rawCall(gpa, io, port, grpc_server.call_path, "application/grpc", &.{ .{ .name = "mcp-protocol-version", .value = "2026-07-28" }, .{ .name = "mcp-method", .value = "server/discover" } }, body);
    defer freeRaw(gpa, good);
    try std.testing.expectEqualStrings("0", good.grpc_status.?);
}
