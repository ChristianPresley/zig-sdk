//! Loopback tests for the Unix socket transport: a server and clients on a socket in a
//! temporary directory.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const types = mcp.types;
const unix = mcp.transport.unix;
const Client = mcp.Client;

const gpa = std.testing.allocator;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

var started: std.atomic.Value(u32) = .init(0);
var cancelled: std.atomic.Value(u32) = .init(0);
var closed_by_peer: std.atomic.Value(u32) = .init(0);

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

fn resetCounters() void {
    started.store(0, .release);
    cancelled.store(0, .release);
    closed_by_peer.store(0, .release);
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

const Fixture = struct {
    tmp: std.testing.TmpDir,
    path: []u8,
    server: mcp.Server,
    transport: unix.Server,
    future: Io.Future(void),
    halted: bool = false,

    fn start(self: *Fixture, limits: mcp.Limits) !void {
        const io = std.testing.io;
        self.halted = false;
        self.tmp = std.testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        self.path = try socketPath(&self.tmp, "mcp.sock");
        errdefer gpa.free(self.path);
        self.server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "unix-test", .version = "1" }, .limits = limits });
        errdefer self.server.deinit();
        try self.server.addTool(.{ .name = "add" }, add);
        try self.server.addTool(.{ .name = "wait_cancel" }, waitCancel);
        try self.server.addTool(.{ .name = "pulse" }, pulse);
        self.transport = .init(io, gpa, &self.server, .{ .path = self.path });
        errdefer self.transport.deinit();
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
    }

    fn serveIgnoringErrors(t: *unix.Server) void {
        t.serve() catch {};
    }

    /// Shut the server down and wait for `serve` to return.
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
        gpa.free(self.path);
        self.tmp.cleanup();
    }

    /// A raw connection for tests that write frames by hand.
    fn rawConnect(self: *Fixture) !Io.net.Stream {
        const abs = try absolutePath(self.path);
        defer gpa.free(abs);
        const address = try Io.net.UnixAddress.init(abs);
        return address.connect(std.testing.io);
    }
};

/// A path in the private directory `run` of the temporary directory. The server refuses a
/// directory that other accounts can write to. The path stays relative, because POSIX limits
/// the socket path to 108 bytes.
fn socketPath(tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    const dir = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/run", .{tmp.sub_path});
    defer gpa.free(dir);
    try unix.createPrivateDirectory(std.testing.io, dir);
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, name });
}

/// Windows connects to absolute socket paths only.
fn absolutePath(path: []const u8) ![]u8 {
    if (builtin.os.tag != .windows) return gpa.dupe(u8, path);
    const cwd = try std.process.currentPathAlloc(std.testing.io, gpa);
    defer gpa.free(cwd);
    return std.fs.path.resolve(gpa, &.{ cwd, path });
}

fn connectClient(path: []const u8, transport: **unix.Client, client: *Client) !void {
    transport.* = try unix.Client.connect(std.testing.io, gpa, .{ .path = path });
    client.* = .init(gpa, std.testing.io, .{ .info = .{ .name = "unix-client", .version = "1" } });
    client.connect(transport.*.transport());
}

test "unix socket client lists, calls and cancels over the socket" {
    if (!unix.supported) return error.SkipZigTest;
    resetCounters();
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var t: *unix.Client = undefined;
    var client: Client = undefined;
    try connectClient(f.path, &t, &client);
    defer t.deinit();
    defer client.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try client.discover(arena, .{ .timeout = .fromSeconds(10) });
    try std.testing.expect(disc.capabilities.tools != null);
    const tools = try client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqual(3, tools.tools.len);
    const sum = try client.callTool(arena, "add", .{ .a = 40, .b = 2 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);

    // The timeout sends `notifications/cancelled`, and the handler sees the cancellation.
    try std.testing.expectError(error.Timeout, client.callTool(arena, "wait_cancel", null, .{ .timeout = .fromMilliseconds(300) }));
    try awaitCount(&cancelled, 1);
    try std.testing.expectEqual(0, closed_by_peer.load(.acquire));

    // The connection stays usable after the cancellation.
    const again = try client.callTool(arena, "add", .{ .a = 1, .b = 2 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("3", again.content[0].text.text);
}

test "unix socket server cancels the requests of a closed connection" {
    if (!unix.supported) return error.SkipZigTest;
    resetCounters();
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    const stream = try f.rawConnect();
    var write_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"wait_cancel\"," ++ meta_none ++ "}}\n");
    try writer.interface.flush();
    try awaitCount(&started, 1);
    stream.close(io);
    try awaitCount(&closed_by_peer, 1);
}

test "unix socket server gives each connection its own rate limit bucket" {
    if (!unix.supported) return error.SkipZigTest;
    var limits: mcp.Limits = .{};
    limits.rate_limits.tool_calls = .{ .count = 1, .period = .fromSeconds(3600) };
    var f: Fixture = undefined;
    try f.start(limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var transports: [2]*unix.Client = undefined;
    var clients: [2]Client = undefined;
    var connected: usize = 0;
    defer for (0..connected) |i| {
        clients[i].deinit();
        transports[i].deinit();
    };
    for (0..2) |i| {
        try connectClient(f.path, &transports[i], &clients[i]);
        connected += 1;
    }

    const sum = try clients[0].callTool(arena, "add", .{ .a = 1, .b = 1 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("2", sum.content[0].text.text);
    var diagnostics: Client.Diagnostics = .{};
    try std.testing.expectError(error.Rpc, clients[0].callTool(arena, "add", .{ .a = 1, .b = 1 }, .{ .timeout = .fromSeconds(10), .diagnostics = &diagnostics }));
    try std.testing.expectEqual(@as(i64, -31429), diagnostics.rpc_error.?.code);
    // The second connection has its own bucket.
    const other = try clients[1].callTool(arena, "add", .{ .a = 2, .b = 2 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("4", other.content[0].text.text);
}

const Job = struct {
    client: *Client,
    a: i64,
    ok: bool = false,

    fn run(job: *Job) void {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const result = job.client.callTool(arena_state.allocator(), "add", .{ .a = job.a, .b = 1 }, .{ .timeout = .fromSeconds(10) }) catch return;
        var buf: [32]u8 = undefined;
        const want = std.fmt.bufPrint(&buf, "{d}", .{job.a + 1}) catch return;
        job.ok = std.mem.eql(u8, want, result.content[0].text.text);
    }
};

test "unix socket server serves several clients at once" {
    if (!unix.supported) return error.SkipZigTest;
    resetCounters();
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();

    const n = 4;
    var transports: [n]*unix.Client = undefined;
    var clients: [n]Client = undefined;
    var connected: usize = 0;
    defer for (0..connected) |i| {
        clients[i].deinit();
        transports[i].deinit();
    };
    for (0..n) |i| {
        try connectClient(f.path, &transports[i], &clients[i]);
        connected += 1;
    }

    // Every client calls a tool at the same time.
    var jobs: [n]Job = undefined;
    for (&jobs, 0..) |*job, i| job.* = .{ .client = &clients[i], .a = @intCast(i * 10) };
    var group: Io.Group = .init;
    for (&jobs) |*job| try group.concurrent(io, Job.run, .{job});
    try group.await(io);
    for (jobs) |job| try std.testing.expect(job.ok);
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

test "unix socket client routes the progress of concurrent requests by token" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var t: *unix.Client = undefined;
    var client: Client = undefined;
    try connectClient(f.path, &t, &client);
    defer t.deinit();
    defer client.deinit();

    // Two calls share the connection and run at the same time.
    var jobs = [_]PulseJob{ .{ .client = &client }, .{ .client = &client } };
    var first = try io.concurrent(PulseJob.run, .{&jobs[0]});
    var second = try io.concurrent(PulseJob.run, .{&jobs[1]});
    first.await(io);
    second.await(io);
    // Each call got the five notifications of its own token, and the tokens differ.
    for (jobs) |job| {
        try std.testing.expect(job.ok);
        try std.testing.expectEqual(5, job.count);
        for (job.tokens[0..job.count]) |token| try std.testing.expectEqual(job.tokens[0], token);
    }
    try std.testing.expect(jobs[0].tokens[0] != jobs[1].tokens[0]);
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

test "unix socket client calls the progress callback of an inline request on the reader task" {
    if (!unix.supported) return error.SkipZigTest;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var t: *unix.Client = undefined;
    var client: Client = undefined;
    try connectClient(f.path, &t, &client);
    defer t.deinit();
    defer client.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    var progress: InlineProgress = .{ .caller = std.Thread.getCurrentId() };
    const result = try client.callTool(arena_state.allocator(), "pulse", null, .{
        .timeout = .fromSeconds(10),
        .inline_notifications = true,
        .on_progress = InlineProgress.onProgress,
        .userdata = &progress,
    });
    try std.testing.expectEqualStrings("pulsed", result.content[0].text.text);
    // The five callbacks ran before the call returned, and the reader task of the transport
    // ran them. Without the option, the task of the request runs them.
    try std.testing.expectEqual(5, progress.calls);
    try std.testing.expect(!progress.on_caller);
}

test "unix socket server drops an oversize line and keeps the connection" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var limits: mcp.Limits = .{};
    limits.stdio.max_line_bytes = 512;
    limits.stdio.read_buffer = 256;
    var f: Fixture = undefined;
    try f.start(limits);
    defer f.stop();
    const stream = try f.rawConnect();
    defer stream.close(io);
    var write_buf: [4096]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"pad\":\"" ++ "x" ** 2000 ++ "\"}}\n");
    try writer.interface.writeAll("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{" ++ meta_none ++ "}}\n");
    try writer.interface.flush();
    var read_buf: [64 * 1024]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    const line = try reader.interface.takeDelimiterExclusive('\n');
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const msg = try mcp.jsonrpc.Message.parse(arena_state.allocator(), line);
    try std.testing.expect(msg == .response);
    try std.testing.expect(msg.response.id.eql(.{ .integer = 2 }));
}

test "unix socket server answers valid JSON that is not a message with the recovered id" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    const stream = try f.rawConnect();
    defer stream.close(io);
    var write_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll("{\"jsonrpc\":\"2.0\",\"id\":8}\n");
    try writer.interface.writeAll("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\",\"params\":{" ++ meta_none ++ "}}\n");
    try writer.interface.flush();
    var read_buf: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const first = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, try reader.interface.takeDelimiterExclusive('\n')));
    reader.interface.toss(1);
    try std.testing.expect(first == .error_response);
    try std.testing.expect(first.error_response.id.?.eql(.{ .integer = 8 }));
    try std.testing.expectEqual(@as(i64, -32600), first.error_response.code);
    // The connection stays usable.
    const second = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, try reader.interface.takeDelimiterExclusive('\n')));
    try std.testing.expect(second == .response);
    try std.testing.expect(second.response.id.eql(.{ .integer = 9 }));
}

test "unix socket limit on connections closes the extra connection" {
    if (!unix.supported) return error.SkipZigTest;
    var limits: mcp.Limits = .{};
    limits.unix_socket.max_connections = 1;
    var f: Fixture = undefined;
    try f.start(limits);
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var first_t: *unix.Client = undefined;
    var first: Client = undefined;
    try connectClient(f.path, &first_t, &first);
    _ = try first.listTools(arena, null, .{ .timeout = .fromSeconds(10) });

    var second_t: *unix.Client = undefined;
    var second: Client = undefined;
    try connectClient(f.path, &second_t, &second);
    // The server closes the extra connection. The reader of the client sees the end.
    const io = std.testing.io;
    var waited: u32 = 0;
    while (!second_t.reader_done.load(.acquire)) : (waited += 1) {
        if (waited > 1000) return error.TestTimeout;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    try std.testing.expectError(error.Closed, second.listTools(arena, null, .{ .timeout = .fromSeconds(10) }));
    second.deinit();
    second_t.deinit();

    // A free place admits the next connection.
    first.deinit();
    first_t.deinit();
    try awaitNoConnections(&f);
    var third_t: *unix.Client = undefined;
    var third: Client = undefined;
    try connectClient(f.path, &third_t, &third);
    defer third_t.deinit();
    defer third.deinit();
    _ = try third.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
}

/// Wait until the server has no open connection, at most ten seconds.
fn awaitNoConnections(f: *Fixture) !void {
    const io = std.testing.io;
    var waited: u32 = 0;
    while (true) : (waited += 1) {
        f.transport.connections_lock.lockUncancelable(io);
        const open = f.transport.connections.items.len;
        f.transport.connections_lock.unlock(io);
        if (open == 0) return;
        if (waited > 1000) return error.TestTimeout;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

/// Wait until `flag` is true, at most ten seconds. The loop yields the thread, because a sleep
/// on Windows lasts at least about 15 milliseconds.
fn spinUntil(flag: *const std.atomic.Value(bool)) !void {
    const io = std.testing.io;
    const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = .fromSeconds(10), .clock = .awake });
    while (!flag.load(.acquire)) {
        if (Io.Clock.Timestamp.now(io, .awake).durationTo(deadline).raw.nanoseconds <= 0) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

// On Windows, a receive on a Unix socket that starts at about the same time as the close of
// the peer can stay pending. The next two tests make many such closes. Without the poll of
// `windows_afunix.zig`, some connections never see their close.

test "unix socket server sees the close of each peer that closes after an answer" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    const peers = 500;
    var limits: mcp.Limits = .{};
    limits.unix_socket.max_connections = peers;
    limits.stdio.read_buffer = 4096;
    var f: Fixture = undefined;
    try f.start(limits);
    defer f.stop();
    // The read task of the server writes the error for a line that is not JSON. Then it
    // starts the next receive. The peer closes its connection when it has the fourth error.
    for (0..peers) |_| {
        const stream = try f.rawConnect();
        defer stream.close(io);
        var write_buf: [64]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        var read_buf: [1024]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        for (0..4) |_| {
            try writer.interface.writeAll("x\n");
            try writer.interface.flush();
            _ = try reader.interface.takeDelimiterInclusive('\n');
        }
    }
    try awaitNoConnections(&f);
}

/// A server that reads one frame of each client, answers it with a notification and closes
/// the connection. Before the close it waits for a short time, a different time for each
/// connection. Thus some closes come while the reader task of the client starts its next
/// receive.
const AnswerAndClose = struct {
    path: []u8,
    listener: Io.net.Server,
    future: Io.Future(void),
    stopping: std.atomic.Value(bool),
    served: u64,

    fn start(self: *AnswerAndClose, path: []const u8) !void {
        const io = std.testing.io;
        self.path = try absolutePath(path);
        errdefer gpa.free(self.path);
        self.listener = try (try Io.net.UnixAddress.init(self.path)).listen(io, .{});
        errdefer self.listener.deinit(io);
        self.stopping = .init(false);
        self.served = 0;
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    fn stop(self: *AnswerAndClose) void {
        const io = std.testing.io;
        mcp.util.wake.cancelUnixAcceptLoop(io, &self.future, self.path, &self.stopping);
        self.listener.deinit(io);
        gpa.free(self.path);
    }

    fn acceptLoop(self: *AnswerAndClose) void {
        const io = std.testing.io;
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(io) catch |e| switch (e) {
                error.Canceled => return,
                else => continue,
            };
            defer stream.close(io);
            if (self.stopping.load(.acquire)) return;
            self.answer(stream) catch {};
        }
    }

    fn answer(self: *AnswerAndClose, stream: Io.net.Stream) !void {
        const io = std.testing.io;
        var read_buf: [256]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        _ = try reader.interface.takeDelimiterInclusive('\n');
        var write_buf: [256]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        try writer.interface.writeAll("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"bye\"}}\n");
        try writer.interface.flush();
        // Wait 0 to 59 microseconds.
        const start_time = Io.Clock.Timestamp.now(io, .awake);
        const wait_ns: i96 = @intCast(self.served % 60 * std.time.ns_per_us);
        while (start_time.durationTo(Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds < wait_ns) {}
        self.served += 1;
    }
};

test "unix socket client sees the close of each server that closes after an answer" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try socketPath(&tmp, "close.sock");
    defer gpa.free(path);
    var server: AnswerAndClose = undefined;
    try server.start(path);
    defer server.stop();
    var limits: mcp.Limits = .{};
    limits.stdio.read_buffer = 4096;
    for (0..1000) |_| {
        const t = try unix.Client.connect(io, gpa, .{ .path = path, .limits = limits });
        defer t.deinit();
        try t.transport().notify(io, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}");
        // The reader task gets the notification and then the end of the stream.
        try spinUntil(&t.reader_done);
    }
}

test "unix socket server refuses a path that is not a socket" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try socketPath(&tmp, "mcp.sock");
    defer gpa.free(path);
    try tmp.dir.writeFile(io, .{ .sub_path = "run/mcp.sock", .data = "keep me" });
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "unix-test", .version = "1" } });
    defer server.deinit();
    var transport: unix.Server = .init(io, gpa, &server, .{ .path = path });
    defer transport.deinit();
    try std.testing.expectError(error.PathNotSocket, transport.bind());
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("keep me", try tmp.dir.readFile(io, "run/mcp.sock", &buf));
}

test "unix socket server refuses a live socket, replaces a stale one and removes its own" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "unix-test", .version = "1" } });
    defer server.deinit();

    // A second server on the path of a live server fails.
    {
        var other: unix.Server = .init(io, gpa, &server, .{ .path = f.path });
        defer other.deinit();
        try std.testing.expectError(error.AddressInUse, other.bind());
    }

    // A socket file without a listener is stale. A new server removes it and binds.
    const stale = try socketPath(&f.tmp, "stale.sock");
    defer gpa.free(stale);
    {
        const abs = try absolutePath(stale);
        defer gpa.free(abs);
        const address = try Io.net.UnixAddress.init(abs);
        var listener = try address.listen(io, .{});
        listener.deinit(io);
    }
    {
        var replaced: unix.Server = .init(io, gpa, &server, .{ .path = stale });
        defer replaced.deinit();
        try replaced.bind();
    }
    // `deinit` removed the socket file.
    try std.testing.expectError(error.FileNotFound, f.tmp.dir.statFile(io, "run/stale.sock", .{ .follow_symlinks = false }));

    // `serve` removes the socket file at shutdown.
    f.halt();
    try std.testing.expectError(error.FileNotFound, f.tmp.dir.statFile(io, "run/mcp.sock", .{ .follow_symlinks = false }));
}

const WaitJob = struct {
    client: *Client,
    result: ?Client.RequestError = null,

    fn run(job: *WaitJob) void {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        _ = job.client.callTool(arena_state.allocator(), "wait_cancel", null, .{ .timeout = .fromSeconds(20), .retry = .never }) catch |e| {
            job.result = e;
        };
    }
};

test "unix socket shutdown ends listen streams and cancels requests in flight" {
    if (!unix.supported) return error.SkipZigTest;
    resetCounters();
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A raw peer opens a listen stream and gets the acknowledgement.
    const stream = try f.rawConnect();
    defer stream.close(io);
    var write_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"subscriptions/listen\",\"params\":{\"notifications\":{\"toolsListChanged\":true}," ++ meta_none ++ "}}\n");
    try writer.interface.flush();
    var read_buf: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    const ack = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, try reader.interface.takeDelimiterExclusive('\n')));
    reader.interface.toss(1);
    try std.testing.expect(ack == .notification);

    // A client waits in a request.
    var t: *unix.Client = undefined;
    var client: Client = undefined;
    try connectClient(f.path, &t, &client);
    defer t.deinit();
    defer client.deinit();
    var job: WaitJob = .{ .client = &client };
    var job_future = try io.concurrent(WaitJob.run, .{&job});
    try awaitCount(&started, 1);

    f.halt();
    job_future.await(io);
    try std.testing.expectEqual(error.Closed, job.result.?);
    try std.testing.expectEqual(1, cancelled.load(.acquire));

    // The listen stream ends with its result and then `notifications/cancelled`.
    const result = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, try reader.interface.takeDelimiterExclusive('\n')));
    reader.interface.toss(1);
    try std.testing.expect(result == .response);
    try std.testing.expect(result.response.id.eql(.{ .integer = 1 }));
    const note = try mcp.jsonrpc.Message.parse(arena, try arena.dupe(u8, try reader.interface.takeDelimiterExclusive('\n')));
    try std.testing.expect(note == .notification);
    try std.testing.expectEqualStrings("notifications/cancelled", note.notification.method);
    try std.testing.expectError(error.FileNotFound, f.tmp.dir.statFile(io, "run/mcp.sock", .{ .follow_symlinks = false }));
}

/// A path in the temporary directory, relative like `socketPath`.
fn tmpPath(tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

/// Bind a server on `name` in the directory `dir` of `tmp` and return the result.
fn tryBind(tmp: *std.testing.TmpDir, dir: []const u8, mode: u32) !void {
    const io = std.testing.io;
    const path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/{s}/mcp.sock", .{ tmp.sub_path, dir });
    defer gpa.free(path);
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "unix-test", .version = "1" } });
    defer server.deinit();
    var transport: unix.Server = .init(io, gpa, &server, .{ .path = path, .mode = mode });
    defer transport.deinit();
    try transport.bind();
}

test "createPrivateDirectory accepts a private directory that exists" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpPath(&tmp, "private");
    defer gpa.free(dir);
    try unix.createPrivateDirectory(io, dir);
    try unix.createPrivateDirectory(io, dir);
    try tryBind(&tmp, "private", 0o600);
}

test "unix socket server leaves only the socket in its directory" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    // `bind` created the socket in a temporary directory and moved it. That directory is gone.
    var dir = try f.tmp.dir.openDir(io, "run", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    var count: usize = 0;
    while (try it.next(io)) |entry| : (count += 1) try std.testing.expectEqualStrings("mcp.sock", entry.name);
    try std.testing.expectEqual(1, count);
    try smoke(f.path);
}

/// Connect to the server at `path`, to show that the moved socket accepts connections.
fn smoke(path: []const u8) !void {
    const io = std.testing.io;
    const abs = try absolutePath(path);
    defer gpa.free(abs);
    const stream = try (try Io.net.UnixAddress.init(abs)).connect(io);
    stream.close(io);
}

// The access tests of the socket file are different on POSIX and on Windows. Each target
// compiles only its own tests, so no target reports a skipped test.
comptime {
    if (unix.supported) _ = if (builtin.os.tag == .windows) windows_access_tests else posix_access_tests;
}

const posix_access_tests = struct {
    test "unix socket file has mode 0600 on POSIX" {
        const io = std.testing.io;
        var f: Fixture = undefined;
        try f.start(.{});
        defer f.stop();
        const st = try f.tmp.dir.statFile(io, "run/mcp.sock", .{ .follow_symlinks = false });
        try std.testing.expectEqual(Io.File.Kind.unix_domain_socket, st.kind);
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
    }

    fn makeDir(tmp: *std.testing.TmpDir, name: []const u8, mode: std.posix.mode_t) !void {
        const io = std.testing.io;
        try tmp.dir.createDir(io, name, .fromMode(0o700));
        // The umask removes bits at creation, so set the mode after it.
        try tmp.dir.setFilePermissions(io, name, .fromMode(mode), .{});
    }

    test "createPrivateDirectory gives mode 0700 on POSIX" {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const dir = try tmpPath(&tmp, "private");
        defer gpa.free(dir);
        try unix.createPrivateDirectory(io, dir);
        const st = try tmp.dir.statFile(io, "private", .{});
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), st.permissions.toMode() & 0o7777);
    }

    test "unix socket server refuses a directory that others can write to on POSIX" {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try makeDir(&tmp, "open", 0o777);
        try std.testing.expectError(error.DirectoryNotPrivate, tryBind(&tmp, "open", 0o600));
        try std.testing.expectError(error.DirectoryNotPrivate, tryBind(&tmp, "open", 0o666));
        // The sticky bit does not help: another account can put a socket at the path before
        // the server starts.
        try makeDir(&tmp, "sticky", 0o1777);
        try std.testing.expectError(error.DirectoryNotPrivate, tryBind(&tmp, "sticky", 0o600));
        // The group can write only when the mode gives the group access to the socket.
        try makeDir(&tmp, "group", 0o770);
        try std.testing.expectError(error.DirectoryNotPrivate, tryBind(&tmp, "group", 0o600));
        try tryBind(&tmp, "group", 0o660);
        // An existing directory that is not private is not accepted as private.
        const open = try tmpPath(&tmp, "open");
        defer gpa.free(open);
        try std.testing.expectError(error.DirectoryNotPrivate, unix.createPrivateDirectory(io, open));
    }

    test "unix socket server refuses a directory with a parent that others can rename it in" {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try makeDir(&tmp, "parent", 0o777);
        try tmp.dir.createDir(io, "parent/run", .fromMode(0o700));
        try std.testing.expectError(error.DirectoryNotPrivate, tryBind(&tmp, "parent/run", 0o600));
        // With the sticky bit, other accounts cannot rename a directory that they do not own.
        try tmp.dir.setFilePermissions(io, "parent", .fromMode(0o1777), .{});
        try tryBind(&tmp, "parent/run", 0o600);
    }
};

const windows_access_tests = struct {
    const windows_acl = @import("windows_acl.zig");

    test "unix socket file allows only the owner on Windows" {
        const io = std.testing.io;
        var f: Fixture = undefined;
        try f.start(.{});
        defer f.stop();
        const path = f.transport.path.?;
        const report = try windows_acl.inspect(path);
        try std.testing.expect(report.protected);
        try std.testing.expectEqual(1, report.ace_count);
        try std.testing.expect(report.only_current_user);
        // Windows checks the list when a client connects: the owner connects, and without the
        // data rights nobody connects. The owner keeps the right to delete, so the server
        // removes the file at shutdown.
        const address = try Io.net.UnixAddress.init(path);
        (try address.connect(io)).close(io);
        try windows_acl.refuseConnections(path);
        if (address.connect(io)) |stream| {
            stream.close(io);
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    test "unix socket file keeps the inherited list on Windows when the mode allows others" {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try socketPath(&tmp, "open.sock");
        defer gpa.free(path);
        var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "unix-test", .version = "1" } });
        defer server.deinit();
        var transport: unix.Server = .init(io, gpa, &server, .{ .path = path, .mode = 0o666 });
        defer transport.deinit();
        try transport.bind();
        // The list is not protected: it comes from the directory.
        const report = try windows_acl.inspect(transport.path.?);
        try std.testing.expect(!report.protected);
    }

    test "createPrivateDirectory gives an owner-only list on Windows" {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const dir = try tmpPath(&tmp, "private");
        defer gpa.free(dir);
        try unix.createPrivateDirectory(io, dir);
        const report = try windows_acl.inspect(dir);
        try std.testing.expect(report.protected);
        try std.testing.expectEqual(1, report.ace_count);
        try std.testing.expect(report.only_current_user);
    }

    test "unix socket server refuses a directory that others can write to on Windows" {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const dir = try tmpPath(&tmp, "open");
        defer gpa.free(dir);
        try unix.createPrivateDirectory(io, dir);
        try windows_acl.openToEveryone(dir);
        try std.testing.expectError(error.DirectoryNotPrivate, tryBind(&tmp, "open", 0o600));
        try std.testing.expectError(error.DirectoryNotPrivate, tryBind(&tmp, "open", 0o666));
        try std.testing.expectError(error.DirectoryNotPrivate, unix.createPrivateDirectory(io, dir));
    }
};
