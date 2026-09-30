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

/// A path in the temporary directory. It stays relative, because POSIX limits the socket
/// path to 108 bytes.
fn socketPath(tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
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
    waited = 0;
    while (true) : (waited += 1) {
        f.transport.connections_lock.lockUncancelable(io);
        const open = f.transport.connections.items.len;
        f.transport.connections_lock.unlock(io);
        if (open == 0) break;
        if (waited > 1000) return error.TestTimeout;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    var third_t: *unix.Client = undefined;
    var third: Client = undefined;
    try connectClient(f.path, &third_t, &third);
    defer third_t.deinit();
    defer third.deinit();
    _ = try third.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
}

test "unix socket server refuses a path that is not a socket" {
    if (!unix.supported) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "mcp.sock", .data = "keep me" });
    const path = try socketPath(&tmp, "mcp.sock");
    defer gpa.free(path);
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "unix-test", .version = "1" } });
    defer server.deinit();
    var transport: unix.Server = .init(io, gpa, &server, .{ .path = path });
    defer transport.deinit();
    try std.testing.expectError(error.PathNotSocket, transport.bind());
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("keep me", try tmp.dir.readFile(io, "mcp.sock", &buf));
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
    try std.testing.expectError(error.FileNotFound, f.tmp.dir.statFile(io, "stale.sock", .{ .follow_symlinks = false }));

    // `serve` removes the socket file at shutdown.
    f.halt();
    try std.testing.expectError(error.FileNotFound, f.tmp.dir.statFile(io, "mcp.sock", .{ .follow_symlinks = false }));
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
    try std.testing.expectError(error.FileNotFound, f.tmp.dir.statFile(io, "mcp.sock", .{ .follow_symlinks = false }));
}

test "unix socket file has mode 0600 on POSIX" {
    if (!unix.supported or builtin.os.tag == .windows) return error.SkipZigTest;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    const st = try f.tmp.dir.statFile(io, "mcp.sock", .{ .follow_symlinks = false });
    try std.testing.expectEqual(Io.File.Kind.unix_domain_socket, st.kind);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
}
