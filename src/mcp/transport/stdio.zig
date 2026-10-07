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
const Limits = @import("../Limits.zig");
const McpServer = @import("../server/Server.zig");
const router_mod = @import("router.zig");
const Router = router_mod.Router;

const log = std.log.scoped(.mcp_stdio);

/// Serves one MCP server over a reader/writer pair (normally stdin/stdout). The Unix socket
/// transport runs one of these for each connection. The WebSocket transport also runs one for
/// each connection: it gives each message to `receive`, and `sink` writes each frame.
pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    limits: Limits,
    /// The output of the line framing. Null when `sink` writes the frames.
    out: ?*Io.Writer,
    /// Writes each frame in place of the line framing on `out`.
    sink: ?Sink = null,
    /// The binding that the handlers see in `RequestContext.kind`.
    kind: Transport.Kind = .stdio,
    /// Transport data that each request gets in `Inbound.context`, for example the
    /// authorization principal of a WebSocket connection.
    context: ?*anyopaque = null,
    /// What `run` does with the requests in flight when the input ends.
    on_close: OnClose = .shutdown_subscriptions,
    /// What a new request gets when the limit of requests in flight is full.
    when_full: WhenFull = .wait,
    /// When set, `run` reads no more frames after the flag becomes true.
    stop: ?*const std.atomic.Value(bool) = null,
    /// The caller of the requests of this peer for the rate limits of the server. `init` gives
    /// each instance a new connection identifier.
    peer: Transport.Peer,
    out_lock: Io.Mutex = .init,
    in_flight: std.ArrayList(*Slot) = .empty,
    in_flight_lock: Io.Mutex = .init,
    group: Io.Group = .init,
    permits: Io.Semaphore,
    /// False after `stopAdmission`. Then the server drops each new request. Guarded by
    /// `in_flight_lock`.
    admitting: bool = true,
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

    /// The action for a new request when the limit of requests in flight is full.
    pub const WhenFull = union(enum) {
        /// The reader waits for one of the `limits.max_in_flight_requests` permits.
        wait,
        /// The server answers a new request with the error `-32603` when this number of
        /// requests runs. The reader does not wait, so it still reads cancellations.
        reject: u32,
    };

    /// Writes one serialized JSON-RPC message.
    pub const Sink = struct {
        ptr: *anyopaque,
        write: *const fn (ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void,
    };

    /// The cancellation reason of the requests of a peer that closed its connection.
    pub const connection_closed_reason = "connection closed";
    /// The message of the error for a request above the limit of `WhenFull.reject`.
    pub const too_many_requests_message = "The connection has too many requests in flight";

    const Slot = struct {
        owner: *Server,
        arena: std.heap.ArenaAllocator,
        token: Transport.CancelToken = .{},
        id: ?RequestId = null,
        /// True for a `subscriptions/listen` request. Only such a request can end with a
        /// server-sent `notifications/cancelled`.
        listen: bool = false,
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
            .peer = .{ .connection = Transport.nextConnectionId() },
            .permits = .{ .permits = server.options.limits.max_in_flight_requests },
        };
    }

    /// A server that writes each frame through `sink`, without the line framing. The caller
    /// gives each message of the peer to `receive`.
    pub fn initSink(io: Io, gpa: Allocator, server: *McpServer, sink: Sink) Server {
        var s: Server = .init(io, gpa, server, undefined);
        s.out = null;
        s.sink = sink;
        return s;
    }

    pub fn deinit(self: *Server) void {
        self.in_flight.deinit(self.gpa);
    }

    fn newSlot(self: *Server) Allocator.Error!*Slot {
        const slot = try self.gpa.create(Slot);
        slot.* = .{ .owner = self, .arena = .init(self.gpa) };
        return slot;
    }

    /// Process one complete message of the peer. The function copies `text`. A request runs
    /// in its own task. A message that is not valid JSON-RPC gets an error response.
    pub fn receive(self: *Server, text: []const u8) !void {
        const slot = try self.newSlot();
        const line = slot.arena.allocator().dupe(u8, text) catch {
            self.destroySlot(slot);
            return error.OutOfMemory;
        };
        try self.dispatch(slot, line);
    }

    /// Drop each request that arrives from now on. The requests in flight continue.
    pub fn stopAdmission(self: *Server) void {
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        self.admitting = false;
    }

    /// Wait for the requests in flight, at most `grace`. Then cancel the tasks that remain
    /// and wait for their end. After this call the server writes no more frames. Call
    /// `stopAdmission` before this function.
    pub fn awaitInFlight(self: *Server, grace: Io.Duration) void {
        const io = self.io;
        const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = grace, .clock = .awake });
        while (self.inFlightCount() > 0) {
            if (Io.Clock.Timestamp.now(io, .awake).durationTo(deadline).raw.nanoseconds <= 0) break;
            io.sleep(.fromMilliseconds(5), .awake) catch break;
        }
        if (self.inFlightCount() > 0) self.group.cancel(io) else self.group.await(io) catch {};
        self.closed = true;
    }

    fn inFlightCount(self: *Server) usize {
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        return self.in_flight.items.len;
    }

    /// Read frames from `in` until end of stream, then drain in-flight requests.
    pub fn run(self: *Server, in: *Io.Reader) !void {
        var line_reader: framer.Framer = .{ .reader = in, .max_line_bytes = self.limits.stdio.max_line_bytes };
        while (true) {
            if (self.stop) |s| if (s.load(.acquire)) break;
            const slot = try self.newSlot();
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
                error.OutOfMemory => {
                    self.destroySlot(slot);
                    return error.OutOfMemory;
                },
            };
            try self.dispatch(slot, line);
        }
        switch (self.on_close) {
            .shutdown_subscriptions => self.server.shutdownSubscriptions(self.io),
            .cancel_requests => self.cancelAll(connection_closed_reason, false),
        }
        self.group.await(self.io) catch {};
        self.closed = true;
    }

    /// Parse one message in the arena of `slot` and process it. The function owns `slot`.
    fn dispatch(self: *Server, slot: *Slot, line: []const u8) !void {
        const arena = slot.arena.allocator();
        slot.message = jsonrpc.Message.parseMaxDepth(arena, line, self.limits.json_max_depth) catch |e| switch (e) {
            error.OutOfMemory => {
                self.destroySlot(slot);
                return error.OutOfMemory;
            },
            error.Syntax => {
                self.destroySlot(slot);
                try self.writeFrameError(null, errors.parseError("Parse error"));
                return;
            },
            error.Invalid => {
                // The line and the recovered id are in the arena of the slot. Free the
                // slot only after the error response is out.
                defer self.destroySlot(slot);
                try self.writeFrameError(recoverId(arena, line), errors.invalidRequest("Invalid Request"));
                return;
            },
            error.InvalidId => {
                self.destroySlot(slot);
                try self.writeFrameError(null, errors.invalidRequest("Invalid Request: id must be a string or an integer"));
                return;
            },
        };
        switch (slot.message) {
            .request => |req| {
                slot.id = req.id;
                slot.listen = std.mem.eql(u8, req.method, "subscriptions/listen");
                try self.start(slot, req.id);
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

    /// Start the task of a request, or answer it when the limit is full. The admission and
    /// the start happen under `in_flight_lock`, so `stopAdmission` sees every started task.
    fn start(self: *Server, slot: *Slot, id: RequestId) !void {
        if (self.when_full == .wait) self.permits.waitUncancelable(self.io);
        const Outcome = enum { started, stopped, full, failed };
        self.in_flight_lock.lockUncancelable(self.io);
        const outcome: Outcome = outcome: {
            if (!self.admitting) break :outcome .stopped;
            switch (self.when_full) {
                .wait => {},
                .reject => |limit| if (self.in_flight.items.len >= limit) break :outcome .full,
            }
            self.in_flight.append(self.gpa, slot) catch {};
            self.group.concurrent(self.io, runSlot, .{slot}) catch {
                self.removeLocked(slot);
                break :outcome .failed;
            };
            break :outcome .started;
        };
        self.in_flight_lock.unlock(self.io);
        switch (outcome) {
            .started => {},
            .stopped => {
                self.releasePermit();
                self.destroySlot(slot);
            },
            .full => {
                defer self.destroySlot(slot);
                try self.writeFrameError(id, errors.internalError(too_many_requests_message));
            },
            .failed => {
                self.releasePermit();
                defer self.destroySlot(slot);
                try self.writeFrameError(id, errors.internalError("Server busy"));
            },
        }
    }

    fn releasePermit(self: *Server) void {
        if (self.when_full == .wait) self.permits.post(self.io);
    }

    /// Cancel every request in flight that has no cancel signal yet. With `by_server`, the
    /// requests end as at a server shutdown: a listen stream then ends with its result.
    pub fn cancelAll(self: *Server, reason: []const u8, by_server: bool) void {
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        for (self.in_flight.items) |slot| {
            if (slot.token.isCancelled()) continue;
            if (by_server) slot.token.shutdown(self.io, reason) else slot.token.cancel(self.io, reason);
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
        Transport.logCancellation(parsed.requestId, parsed.reason);
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

    fn untrack(self: *Server, slot: *Slot) void {
        self.in_flight_lock.lockUncancelable(self.io);
        defer self.in_flight_lock.unlock(self.io);
        self.removeLocked(slot);
    }

    fn removeLocked(self: *Server, slot: *Slot) void {
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
            self.releasePermit();
            self.destroySlot(slot);
        }
        self.server.handle(self.io, .{
            .kind = self.kind,
            .arena = slot.arena.allocator(),
            .message = slot.message,
            .responder = .{ .ptr = slot, .vtable = &slot_vtable },
            .cancel = &slot.token,
            .peer = self.peer,
            .context = self.context,
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
        // After a cancellation by the peer, the server sends nothing more for the request.
        if (slot.token.isCancelledByPeer()) return error.Closed;
        try slot.owner.writeFrame(io, frame);
    }

    fn slotFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const slot: *Slot = @ptrCast(@alignCast(ptr));
        if (slot.done) return error.Closed;
        slot.done = true;
        // A handler that ignored the cancellation gets no response out.
        if (slot.token.isCancelledByPeer()) return error.Closed;
        try slot.owner.writeFrame(io, frame);
        // Only a listen stream that the server ends at shutdown gets a cancellation
        // notification after its result.
        if (slot.listen and slot.token.isCancelled() and slot.token.server_shutdown) {
            var buf: [256]u8 = undefined;
            var fba: std.heap.FixedBufferAllocator = .init(&buf);
            var aw: Io.Writer.Allocating = .init(fba.allocator());
            message.writeNotification(&aw.writer, "notifications/cancelled", types.CancelledNotificationParams{ .requestId = slot.id.?, .reason = McpServer.shutdown_reason }) catch return;
            slot.owner.writeFrame(io, aw.written()) catch {};
        }
    }

    fn slotAbort(ptr: *anyopaque, io: Io) void {
        _ = io;
        const slot: *Slot = @ptrCast(@alignCast(ptr));
        slot.done = true;
    }

    fn writeFrame(self: *Server, io: Io, frame: []const u8) Transport.SendError!void {
        if (self.closed) return error.Closed;
        if (self.sink) |s| return s.write(s.ptr, io, frame);
        self.out_lock.lockUncancelable(io);
        defer self.out_lock.unlock(io);
        framer.writeFrame(self.out.?, frame) catch return error.WriteFailed;
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
    /// Counts the restarts. A request that waits across a restart fails.
    generation: std.atomic.Value(u32) = .init(0),
    restarts: u32 = 0,

    pub const SpawnOptions = struct {
        /// The command. The slices must stay valid while the client lives (restarts reuse them).
        argv: []const []const u8,
        /// Environment for the child. Null inherits the parent environment.
        environ_map: ?*const std.process.Environ.Map = null,
        cwd: std.process.Child.Cwd = .inherit,
        limits: Limits = .{},
        /// How often a request that waits checks for cancellation.
        poll_interval: Io.Duration = .fromMilliseconds(50),
        /// Put the child in its own process group (POSIX) or job object (Windows), so that
        /// `close` and `kill` also end the processes it spawned.
        process_group: bool = true,
        /// Spawn the process again when it exits on its own, up to this many times. A
        /// request that waited during the exit fails with `error.Closed`. The client
        /// re-issues idempotent requests.
        max_restarts: u32 = 0,
        /// Receives each notification that has no progress token and no subscription id, for
        /// example a log message of the server during a request. The router drops a
        /// notification whose progress token or subscription id names no request in flight.
        /// `spawn` starts the reader task, thus the client takes the function only here.
        ///
        /// The function runs on the reader task. It must not block: while it runs, the reader
        /// task routes no frame, and `close` does not return. `method` and `params` are valid
        /// only during the call.
        on_notification: ?router_mod.NotificationFn = null,
        userdata: ?*anyopaque = null,
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
            .router = .init(io, gpa, options.limits.json_max_depth),
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
    /// process tree gets a termination signal, and after one more grace period a kill signal.
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
        var pending: Pending = .{ .id = ex.id, .generation = self.generation.load(.acquire), .inline_exchange = if (ex.inline_notifications) ex else null };
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
        while (true) {
            // Deliver everything that arrived.
            while (try self.router.takeFrame(&pending)) |frame| {
                defer self.gpa.free(frame);
                const is_response = router_mod.frameIsResponse(frame);
                ex.deliver(io, frame) catch return error.InvalidFrame;
                if (is_response) return;
            }
            if (ex.cancel.isCancelled()) {
                self.sendCancelled(ex.id, ex.cancel.reason);
                return error.Canceled;
            }
            if (ex.expired(io)) {
                self.sendCancelled(ex.id, "timeout");
                return error.Timeout;
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
        self.router.readUntilEof(&self.stdout_reader.interface, self.limits.stdio.max_line_bytes, self.options.on_notification, self.options.userdata);
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
