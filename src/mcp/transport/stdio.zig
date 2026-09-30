//! The stdio transport: newline-delimited JSON-RPC over stdin and stdout.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("Transport.zig");
const framer = @import("../util/line_framer.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;
const types = @import("../protocol/types.zig");
const errors = @import("../protocol/errors.zig");
const message = @import("../jsonrpc/message.zig");
const json = @import("../json.zig");
const Value = std.json.Value;
const Limits = @import("../Limits.zig");
const McpServer = @import("../server/Server.zig");
const router_mod = @import("router.zig");
const Router = router_mod.Router;

const log = std.log.scoped(.mcp_stdio);

/// Serves one MCP server over a reader/writer pair (normally stdin/stdout). The Unix socket
/// transport runs one of these for each connection.
pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    limits: Limits,
    out: *Io.Writer,
    /// The binding that the handlers see in `RequestContext.kind`.
    kind: Transport.Kind = .stdio,
    /// What `run` does with the requests in flight when the input ends.
    on_close: OnClose = .shutdown_subscriptions,
    /// When set, `run` reads no more frames after the flag becomes true.
    stop: ?*const std.atomic.Value(bool) = null,
    out_lock: Io.Mutex = .init,
    in_flight: std.ArrayList(*Slot) = .empty,
    in_flight_lock: Io.Mutex = .init,
    group: Io.Group = .init,
    permits: Io.Semaphore,
    closed: bool = false,

    /// The action at the end of the input.
    pub const OnClose = enum {
        /// End the listen streams of the whole MCP server, then wait for the other requests.
        /// Use it when the end of the input ends the server, as on stdio.
        shutdown_subscriptions,
        /// Cancel the requests of this peer only, then wait for them. Use it for one
        /// connection of a server with many peers.
        cancel_requests,
    };

    /// The cancellation reason of the requests of a peer that closed its connection.
    pub const connection_closed_reason = "connection closed";

    const Slot = struct {
        owner: *Server,
        arena: std.heap.ArenaAllocator,
        token: Transport.CancelToken = .{},
        id: ?RequestId = null,
        done: bool = false,
        message: jsonrpc.Message = undefined,
    };

    pub fn init(io: Io, gpa: Allocator, server: *McpServer, out: *Io.Writer) Server {
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .limits = server.options.limits,
            .out = out,
            .permits = .{ .permits = server.options.limits.max_in_flight_requests },
        };
    }

    pub fn deinit(self: *Server) void {
        self.in_flight.deinit(self.gpa);
    }

    /// Read frames from `in` until end of stream, then drain in-flight requests.
    pub fn run(self: *Server, in: *Io.Reader) !void {
        var line_reader: framer.Framer = .{ .reader = in, .max_line_bytes = self.limits.stdio.max_line_bytes };
        while (true) {
            if (self.stop) |s| if (s.load(.acquire)) break;
            const slot = try self.gpa.create(Slot);
            slot.* = .{ .owner = self, .arena = .init(self.gpa) };
            const arena = slot.arena.allocator();
            const line = line_reader.next(arena) catch |e| switch (e) {
                error.EndOfStream => {
                    self.destroySlot(slot);
                    break;
                },
                error.LineTooLong => {
                    self.destroySlot(slot);
                    log.warn("dropped a frame longer than {d} bytes", .{self.limits.stdio.max_line_bytes});
                    continue;
                },
                error.InvalidUtf8, error.ControlCharacter => {
                    self.destroySlot(slot);
                    try self.writeFrameError(null, errors.parseError("Parse error: invalid UTF-8"));
                    continue;
                },
                error.ReadFailed => {
                    self.destroySlot(slot);
                    break;
                },
                error.OutOfMemory => return error.OutOfMemory,
            };
            slot.message = jsonrpc.Message.parse(arena, line) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Syntax => {
                    self.destroySlot(slot);
                    try self.writeFrameError(null, errors.parseError("Parse error"));
                    continue;
                },
                error.Invalid => {
                    self.destroySlot(slot);
                    try self.writeFrameError(recoverId(arena, line), errors.invalidRequest("Invalid Request"));
                    continue;
                },
                error.InvalidId => {
                    self.destroySlot(slot);
                    try self.writeFrameError(null, errors.invalidRequest("Invalid Request: id must be a string or an integer"));
                    continue;
                },
            };
            switch (slot.message) {
                .request => |req| {
                    slot.id = req.id;
                    self.permits.waitUncancelable(self.io);
                    self.track(slot);
                    self.group.concurrent(self.io, runSlot, .{slot}) catch {
                        self.untrack(slot);
                        self.permits.post(self.io);
                        try self.writeFrameError(req.id, errors.internalError("Server busy"));
                        self.destroySlot(slot);
                    };
                },
                .notification => |n| {
                    self.handleNotification(arena, n);
                    self.destroySlot(slot);
                },
                .response, .error_response => {
                    log.warn("ignored a response sent by the client", .{});
                    self.destroySlot(slot);
                },
            }
        }
        switch (self.on_close) {
            .shutdown_subscriptions => self.server.shutdownSubscriptions(self.io),
            .cancel_requests => self.cancelInFlight(connection_closed_reason),
        }
        self.group.await(self.io) catch {};
        self.closed = true;
    }

    /// Cancel every request in flight that is not cancelled yet.
    fn cancelInFlight(self: *Server, reason: []const u8) void {
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        for (self.in_flight.items) |slot| {
            if (!slot.token.isCancelled()) slot.token.cancel(self.io, reason);
        }
    }

    fn recoverId(arena: Allocator, line: []const u8) ?RequestId {
        const tree = json.parseTree(arena, line) catch return null;
        if (tree != .object) return null;
        const id = tree.object.get("id") orelse return null;
        return RequestId.fromValue(arena, id);
    }

    fn handleNotification(self: *Server, arena: Allocator, n: jsonrpc.Message.Notification) void {
        if (!std.mem.eql(u8, n.method, "notifications/cancelled")) return;
        const params = n.params orelse return;
        const parsed = json.parseValue(types.CancelledNotificationParams, arena, params) catch return;
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        for (self.in_flight.items) |slot| {
            const id = slot.id orelse continue;
            if (!id.eql(parsed.requestId)) continue;
            const reason: ?[]const u8 = if (parsed.reason) |r| slot.arena.allocator().dupe(u8, r) catch null else null;
            slot.token.cancel(self.io, reason);
            return;
        }
    }

    fn track(self: *Server, slot: *Slot) void {
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        self.in_flight.append(self.gpa, slot) catch {};
    }

    fn untrack(self: *Server, slot: *Slot) void {
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        for (self.in_flight.items, 0..) |s, i| {
            if (s == slot) {
                _ = self.in_flight.swapRemove(i);
                return;
            }
        }
    }

    fn destroySlot(self: *Server, slot: *Slot) void {
        slot.arena.deinit();
        self.gpa.destroy(slot);
    }

    fn runSlot(slot: *Slot) Io.Cancelable!void {
        const self = slot.owner;
        defer {
            self.untrack(slot);
            self.permits.post(self.io);
            self.destroySlot(slot);
        }
        self.server.handle(self.io, .{
            .kind = self.kind,
            .arena = slot.arena.allocator(),
            .message = slot.message,
            .responder = .{ .ptr = slot, .vtable = &slot_vtable },
            .cancel = &slot.token,
        });
    }

    const slot_vtable: Transport.Responder.VTable = .{
        .notify = slotNotify,
        .finish = slotFinish,
        .abort = slotAbort,
    };

    fn slotNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const slot: *Slot = @ptrCast(@alignCast(ptr));
        if (slot.done) return error.Closed;
        try slot.owner.writeFrame(io, frame);
    }

    fn slotFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const slot: *Slot = @ptrCast(@alignCast(ptr));
        if (slot.done) return error.Closed;
        slot.done = true;
        try slot.owner.writeFrame(io, frame);
        // A server-initiated end of a listen stream is followed by a cancellation notification.
        if (slot.token.reason) |r| {
            if (std.mem.eql(u8, r, McpServer.shutdown_reason)) {
                var buf: [256]u8 = undefined;
                var fba: std.heap.FixedBufferAllocator = .init(&buf);
                var aw: Io.Writer.Allocating = .init(fba.allocator());
                message.writeNotification(&aw.writer, "notifications/cancelled", types.CancelledNotificationParams{ .requestId = slot.id.?, .reason = "server shutdown" }) catch return;
                slot.owner.writeFrame(io, aw.written()) catch {};
            }
        }
    }

    fn slotAbort(ptr: *anyopaque, io: Io) void {
        _ = io;
        const slot: *Slot = @ptrCast(@alignCast(ptr));
        slot.done = true;
    }

    fn writeFrame(self: *Server, io: Io, frame: []const u8) Transport.SendError!void {
        if (self.closed) return error.Closed;
        self.out_lock.lockUncancelable(io);
        defer self.out_lock.unlock(io);
        framer.writeFrame(self.out, frame) catch return error.WriteFailed;
    }

    fn writeFrameError(self: *Server, id: ?RequestId, err: errors.RpcError) !void {
        var buf: [1024]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        var aw: Io.Writer.Allocating = .init(fba.allocator());
        message.writeErrorResponse(&aw.writer, id, err.toWire()) catch return;
        self.writeFrame(self.io, aw.written()) catch {};
    }
};

/// Serve `server` over the process stdin and stdout until stdin closes.
pub fn serve(io: Io, gpa: Allocator, server: *McpServer) !void {
    const limits = server.options.limits;
    const in_buf = try gpa.alloc(u8, limits.stdio.read_buffer);
    defer gpa.free(in_buf);
    var out_buf: [64 * 1024]u8 = undefined;
    var stdin_reader = Io.File.stdin().readerStreaming(io, in_buf);
    var stdout_writer = Io.File.stdout().writerStreaming(io, &out_buf);
    var transport: Server = .init(io, gpa, server, &stdout_writer.interface);
    defer transport.deinit();
    try transport.run(&stdin_reader.interface);
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

/// Spawns a server process and speaks MCP over its stdin and stdout. One reader task demuxes
/// the frames to the requests in flight by id, progress token and subscription id.
pub const Client = struct {
    io: Io,
    gpa: Allocator,
    limits: Limits,
    options: SpawnOptions,
    child: std.process.Child,
    /// The Windows job object that holds the process tree, when `process_group` is on.
    job: if (builtin.os.tag == .windows) ?std.os.windows.HANDLE else void,
    in_buf: []u8,
    out_buf: []u8,
    stdout_reader: Io.File.Reader,
    stdin_writer: Io.File.Writer,
    out_lock: Io.Mutex = .init,
    router: Router,
    reader_future: ?Io.Future(void) = null,
    closed: std.atomic.Value(bool) = .init(false),
    /// True once the reader task saw the end of the stream for the last time.
    reader_done: std.atomic.Value(bool) = .init(false),
    /// Counts the restarts. A request that waits across a restart is lost.
    generation: std.atomic.Value(u32) = .init(0),
    restarts: u32 = 0,
    /// Receives notifications that belong to no request in flight.
    on_notification: ?*const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void = null,
    userdata: ?*anyopaque = null,

    pub const SpawnOptions = struct {
        /// The command. The slices must stay valid while the client lives (restarts reuse them).
        argv: []const []const u8,
        /// Environment for the child. Null inherits the parent environment.
        environ_map: ?*const std.process.Environ.Map = null,
        cwd: std.process.Child.Cwd = .inherit,
        limits: Limits = .{},
        /// How often a waiting request checks for cancellation.
        poll_interval: Io.Duration = .fromMilliseconds(50),
        /// Put the child in its own process group (POSIX) or job object (Windows), so that
        /// `close` and `kill` also end the processes it spawned.
        process_group: bool = true,
        /// Spawn the process again when it exits on its own, up to this many times. A
        /// request that waited during the exit fails with `error.Closed`. The client
        /// re-issues idempotent requests.
        max_restarts: u32 = 0,
    };

    const Pending = Router.Pending;

    /// Spawn the server process and start the reader task.
    pub fn spawn(io: Io, gpa: Allocator, options: SpawnOptions) !*Client {
        const self = try gpa.create(Client);
        errdefer gpa.destroy(self);
        const in_buf = try gpa.alloc(u8, options.limits.stdio.read_buffer);
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(out_buf);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .limits = options.limits,
            .options = options,
            .child = undefined,
            .job = if (builtin.os.tag == .windows) null else {},
            .in_buf = in_buf,
            .out_buf = out_buf,
            .stdout_reader = undefined,
            .stdin_writer = undefined,
            .router = .init(io, gpa),
        };
        if (builtin.os.tag == .windows and options.process_group) {
            self.job = win.createKillOnCloseJob() catch null;
        }
        errdefer if (builtin.os.tag == .windows) if (self.job) |j| std.os.windows.CloseHandle(j);
        try self.spawnChild();
        self.reader_future = try io.concurrent(readerLoop, .{self});
        return self;
    }

    /// Start the child and attach the streams. Used at spawn and at every restart.
    fn spawnChild(self: *Client) !void {
        const io = self.io;
        const options = self.options;
        const suspended = builtin.os.tag == .windows and self.job != null;
        const child = try std.process.spawn(io, .{
            .argv = options.argv,
            .environ_map = options.environ_map,
            .cwd = options.cwd,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
            .create_no_window = true,
            .pgid = if (builtin.os.tag != .windows and builtin.os.tag != .wasi and options.process_group) 0 else null,
            .start_suspended = suspended,
        });
        if (builtin.os.tag == .windows) if (self.job) |job| {
            // Assign before the first instruction runs, so no descendant can escape the job.
            win.assign(job, child.id.?) catch {};
            _ = std.os.windows.ntdll.NtResumeThread(child.thread_handle, null);
        };
        self.child = child;
        self.stdout_reader = self.child.stdout.?.readerStreaming(io, self.in_buf);
        self.stdin_writer = self.child.stdin.?.writerStreaming(io, self.out_buf);
    }

    pub fn transport(self: *Client) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &client_vtable };
    }

    /// Close stdin and wait for the process to exit. After `limits.shutdown_grace` the
    /// process tree gets a termination signal, and after one more grace period it is killed.
    pub fn close(self: *Client) void {
        const io = self.io;
        if (!self.closed.swap(true, .acq_rel)) {
            self.out_lock.lockUncancelable(io);
            self.stdin_writer.interface.flush() catch {};
            self.out_lock.unlock(io);
            if (self.child.stdin) |stdin| {
                stdin.close(io);
                self.child.stdin = null;
            }
        }
        if (self.reader_future) |*f| {
            if (!self.waitReader(self.limits.shutdown_grace)) {
                self.terminate(.graceful);
                if (!self.waitReader(self.limits.shutdown_grace)) self.terminate(.forced);
            }
            f.await(io);
            self.reader_future = null;
        }
        if (self.child.id != null) _ = self.child.wait(io) catch {};
        self.closeJob();
    }

    /// Terminate the process tree at once.
    pub fn kill(self: *Client) void {
        self.closed.store(true, .release);
        self.terminate(.forced);
        if (self.reader_future) |*f| {
            f.await(self.io);
            self.reader_future = null;
        }
        if (self.child.id != null) _ = self.child.wait(self.io) catch {};
        self.closeJob();
    }

    pub fn deinit(self: *Client) void {
        self.close();
        self.gpa.free(self.in_buf);
        self.gpa.free(self.out_buf);
        self.router.deinit();
        self.gpa.destroy(self);
    }

    /// The number of restarts so far.
    pub fn restartCount(self: *const Client) u32 {
        return self.generation.load(.acquire);
    }

    /// Wait until the reader saw the end of the stream, at most `grace`.
    fn waitReader(self: *Client, grace: Io.Duration) bool {
        const io = self.io;
        const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = grace, .clock = .awake });
        while (!self.reader_done.load(.acquire)) {
            if (Io.Clock.Timestamp.now(io, .awake).durationTo(deadline).raw.nanoseconds <= 0) return false;
            io.sleep(.fromMilliseconds(10), .awake) catch return false;
        }
        return true;
    }

    const Termination = enum { graceful, forced };

    /// Signal the process tree. On Windows a job has no graceful signal: both modes kill it.
    fn terminate(self: *Client, how: Termination) void {
        if (self.child.id == null) return;
        if (builtin.os.tag == .windows) {
            if (self.job) |job| {
                _ = win.TerminateJobObject(job, 1);
            } else {
                _ = std.os.windows.ntdll.NtTerminateProcess(self.child.id.?, @enumFromInt(1));
            }
            return;
        }
        if (builtin.os.tag == .wasi) return;
        const sig: std.posix.SIG = switch (how) {
            .graceful => .TERM,
            .forced => .KILL,
        };
        const pid = self.child.id.?;
        // With a process group the signal goes to the group, else to the process alone.
        const target: std.posix.pid_t = if (self.options.process_group) -pid else pid;
        std.posix.kill(target, sig) catch {};
    }

    fn closeJob(self: *Client) void {
        if (builtin.os.tag == .windows) if (self.job) |job| {
            std.os.windows.CloseHandle(job);
            self.job = null;
        };
    }

    const client_vtable: Transport.ClientTransport.VTable = .{
        .kind = .stdio,
        .exchange = exchange,
        .notify = notify,
    };

    fn writeFrame(self: *Client, frame: []const u8) Transport.SendError!void {
        if (self.closed.load(.acquire)) return error.Closed;
        self.out_lock.lockUncancelable(self.io);
        defer self.out_lock.unlock(self.io);
        framer.writeFrame(&self.stdin_writer.interface, frame) catch return error.WriteFailed;
        self.stdin_writer.interface.flush() catch return error.WriteFailed;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = io;
        const self: *Client = @ptrCast(@alignCast(ptr));
        return self.writeFrame(frame);
    }

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        var pending: Pending = .{ .id = ex.id, .generation = self.generation.load(.acquire) };
        defer pending.deinit(self.gpa);
        try self.router.register(&pending);
        defer self.router.unregister(&pending);
        self.writeFrame(ex.frame) catch |e| switch (e) {
            error.Closed => return error.Closed,
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                // The pipe broke. With restarts on, wait for the new process and report the
                // request as lost, so the caller can re-issue it.
                if (self.options.max_restarts > 0) self.awaitRestart(&pending);
                return error.Closed;
            },
        };
        const deadline: ?Io.Clock.Timestamp = ex.timeout.toTimestamp(io);
        while (true) {
            // Deliver everything that arrived.
            while (self.router.takeFrame(&pending)) |frame| {
                defer self.gpa.free(frame);
                const is_response = router_mod.frameIsResponse(frame);
                ex.sink.deliver(io, frame) catch return error.InvalidFrame;
                if (is_response) return;
            }
            if (ex.cancel.isCancelled()) {
                self.sendCancelled(ex.id, ex.cancel.reason);
                return error.Canceled;
            }
            if (deadline) |d| {
                if (Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw.nanoseconds <= 0) {
                    self.sendCancelled(ex.id, "timeout");
                    return error.Timeout;
                }
            }
            if (self.closed.load(.acquire)) return error.Closed;
            // The process was restarted: this request went with the old one.
            if (self.generation.load(.acquire) != pending.generation) return error.Closed;
            pending.event.waitTimeout(io, .{ .duration = .{ .raw = self.options.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return error.Canceled,
            };
            pending.event.reset();
        }
    }

    /// Block until the reader restarted the process (or gave up), at most one grace period.
    fn awaitRestart(self: *Client, pending: *Pending) void {
        const io = self.io;
        const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = self.limits.shutdown_grace, .clock = .awake });
        while (!self.closed.load(.acquire) and self.generation.load(.acquire) == pending.generation) {
            if (Io.Clock.Timestamp.now(io, .awake).durationTo(deadline).raw.nanoseconds <= 0) return;
            pending.event.waitTimeout(io, .{ .duration = .{ .raw = self.options.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return,
            };
            pending.event.reset();
        }
    }

    fn sendCancelled(self: *Client, id: RequestId, reason: ?[]const u8) void {
        var buf: [512]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        var aw: Io.Writer.Allocating = .init(fba.allocator());
        message.writeNotification(&aw.writer, "notifications/cancelled", types.CancelledNotificationParams{ .requestId = id, .reason = reason }) catch return;
        self.writeFrame(aw.written()) catch {};
    }

    fn readerLoop(self: *Client) void {
        while (true) {
            self.readUntilEof();
            // The stream ended. Restart when the exit was not ours and restarts remain.
            if (self.closed.load(.acquire) or self.restarts >= self.options.max_restarts) break;
            self.restarts += 1;
            if (!self.restartChild()) break;
            log.warn("stdio server exited; restarted it ({d} of {d})", .{ self.restarts, self.options.max_restarts });
        }
        self.closed.store(true, .release);
        self.reader_done.store(true, .release);
        self.router.wakeAll();
    }

    fn readUntilEof(self: *Client) void {
        self.router.readUntilEof(&self.stdout_reader.interface, self.limits.stdio.max_line_bytes, self.on_notification, self.userdata);
    }

    /// Reap the old process and spawn a new one. Returns false when the spawn failed.
    fn restartChild(self: *Client) bool {
        const io = self.io;
        self.out_lock.lockUncancelable(io);
        defer self.out_lock.unlock(io);
        if (self.child.stdin) |stdin| {
            stdin.close(io);
            self.child.stdin = null;
        }
        if (self.child.id != null) _ = self.child.wait(io) catch {};
        self.spawnChild() catch return false;
        _ = self.generation.fetchAdd(1, .acq_rel);
        self.router.wakeAll();
        return true;
    }
};

/// The Windows job object calls that std does not declare.
const win = if (builtin.os.tag == .windows) struct {
    const windows = std.os.windows;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: windows.DWORD = 0x2000;
    const JobObjectExtendedLimitInformation: c_int = 9;

    const IO_COUNTERS = extern struct {
        ReadOperationCount: u64,
        WriteOperationCount: u64,
        OtherOperationCount: u64,
        ReadTransferCount: u64,
        WriteTransferCount: u64,
        OtherTransferCount: u64,
    };

    const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
        PerProcessUserTimeLimit: windows.LARGE_INTEGER,
        PerJobUserTimeLimit: windows.LARGE_INTEGER,
        LimitFlags: windows.DWORD,
        MinimumWorkingSetSize: windows.SIZE_T,
        MaximumWorkingSetSize: windows.SIZE_T,
        ActiveProcessLimit: windows.DWORD,
        Affinity: windows.ULONG_PTR,
        PriorityClass: windows.DWORD,
        SchedulingClass: windows.DWORD,
    };

    const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        IoInfo: IO_COUNTERS,
        ProcessMemoryLimit: windows.SIZE_T,
        JobMemoryLimit: windows.SIZE_T,
        PeakProcessMemoryUsed: windows.SIZE_T,
        PeakJobMemoryUsed: windows.SIZE_T,
    };

    extern "kernel32" fn CreateJobObjectW(lpJobAttributes: ?*windows.SECURITY_ATTRIBUTES, lpName: ?windows.LPCWSTR) callconv(.winapi) ?windows.HANDLE;
    extern "kernel32" fn SetInformationJobObject(hJob: windows.HANDLE, JobObjectInformationClass: c_int, lpJobObjectInformation: *anyopaque, cbJobObjectInformationLength: windows.DWORD) callconv(.winapi) windows.BOOL;
    extern "kernel32" fn AssignProcessToJobObject(hJob: windows.HANDLE, hProcess: windows.HANDLE) callconv(.winapi) windows.BOOL;
    extern "kernel32" fn TerminateJobObject(hJob: windows.HANDLE, uExitCode: windows.UINT) callconv(.winapi) windows.BOOL;

    /// A job that kills every process in it when the last handle closes.
    fn createKillOnCloseJob() error{JobUnavailable}!windows.HANDLE {
        const job = CreateJobObjectW(null, null) orelse return error.JobUnavailable;
        var info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std.mem.zeroes(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, @sizeOf(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)) == .FALSE) {
            windows.CloseHandle(job);
            return error.JobUnavailable;
        }
        return job;
    }

    fn assign(job: windows.HANDLE, process: windows.HANDLE) error{AssignFailed}!void {
        if (AssignProcessToJobObject(job, process) == .FALSE) return error.AssignFailed;
    }
} else struct {};
