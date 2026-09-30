//! The stdio transport: newline-delimited JSON-RPC over stdin and stdout.
const std = @import("std");
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

const log = std.log.scoped(.mcp_stdio);

/// Serves one MCP server over a reader/writer pair (normally stdin/stdout).
pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    limits: Limits,
    out: *Io.Writer,
    out_lock: Io.Mutex = .init,
    in_flight: std.ArrayList(*Slot) = .empty,
    in_flight_lock: Io.Mutex = .init,
    group: Io.Group = .init,
    permits: Io.Semaphore,
    closed: bool = false,

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
        self.server.shutdownSubscriptions(self.io);
        self.group.await(self.io) catch {};
        self.closed = true;
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
            .kind = .stdio,
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
    child: std.process.Child,
    in_buf: []u8,
    out_buf: []u8,
    stdout_reader: Io.File.Reader,
    stdin_writer: Io.File.Writer,
    out_lock: Io.Mutex = .init,
    pending: std.ArrayList(*Pending) = .empty,
    pending_lock: Io.Mutex = .init,
    reader_future: ?Io.Future(void) = null,
    closed: std.atomic.Value(bool) = .init(false),
    /// Receives notifications that belong to no request in flight.
    on_notification: ?*const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void = null,
    userdata: ?*anyopaque = null,

    pub const SpawnOptions = struct {
        argv: []const []const u8,
        /// Environment for the child. Null inherits the parent environment.
        environ_map: ?*const std.process.Environ.Map = null,
        cwd: std.process.Child.Cwd = .inherit,
        limits: Limits = .{},
        /// How often a waiting request checks for cancellation.
        poll_interval: Io.Duration = .fromMilliseconds(50),
    };

    const Pending = struct {
        id: RequestId,
        frames: std.ArrayList([]u8) = .empty,
        lock: Io.Mutex = .init,
        event: Io.Event = .unset,
    };

    /// Spawn the server process and start the reader task.
    pub fn spawn(io: Io, gpa: Allocator, options: SpawnOptions) !*Client {
        const self = try gpa.create(Client);
        errdefer gpa.destroy(self);
        const child = try std.process.spawn(io, .{
            .argv = options.argv,
            .environ_map = options.environ_map,
            .cwd = options.cwd,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
            .create_no_window = true,
        });
        const in_buf = try gpa.alloc(u8, options.limits.stdio.read_buffer);
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(out_buf);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .limits = options.limits,
            .child = child,
            .in_buf = in_buf,
            .out_buf = out_buf,
            .stdout_reader = undefined,
            .stdin_writer = undefined,
        };
        self.stdout_reader = self.child.stdout.?.readerStreaming(io, self.in_buf);
        self.stdin_writer = self.child.stdin.?.writerStreaming(io, self.out_buf);
        self.reader_future = try io.concurrent(readerLoop, .{self});
        return self;
    }

    pub fn transport(self: *Client) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &client_vtable };
    }

    /// Close stdin, wait for the reader to see the end of the stream, and reap the process.
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
            f.await(io);
            self.reader_future = null;
        }
        if (self.child.id != null) _ = self.child.wait(io) catch {};
    }

    /// Terminate the process at once.
    pub fn kill(self: *Client) void {
        self.closed.store(true, .release);
        self.child.kill(self.io);
        if (self.reader_future) |*f| {
            f.await(self.io);
            self.reader_future = null;
        }
    }

    pub fn deinit(self: *Client) void {
        self.close();
        self.gpa.free(self.in_buf);
        self.gpa.free(self.out_buf);
        self.pending.deinit(self.gpa);
        self.gpa.destroy(self);
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
        var pending: Pending = .{ .id = ex.id };
        defer {
            for (pending.frames.items) |f| self.gpa.free(f);
            pending.frames.deinit(self.gpa);
        }
        try self.register(&pending);
        defer self.unregister(&pending);
        self.writeFrame(ex.frame) catch |e| switch (e) {
            error.Closed => return error.Closed,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.WriteFailed,
        };
        const deadline: ?Io.Clock.Timestamp = ex.timeout.toTimestamp(io);
        while (true) {
            // Deliver everything that arrived.
            while (self.takeFrame(&pending)) |frame| {
                defer self.gpa.free(frame);
                const is_response = frameIsResponse(frame);
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
            pending.event.waitTimeout(io, .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return error.Canceled,
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

    fn register(self: *Client, p: *Pending) error{OutOfMemory}!void {
        self.pending_lock.lockUncancelable(self.io);
        defer self.pending_lock.unlock(self.io);
        try self.pending.append(self.gpa, p);
    }

    fn unregister(self: *Client, p: *Pending) void {
        self.pending_lock.lockUncancelable(self.io);
        defer self.pending_lock.unlock(self.io);
        for (self.pending.items, 0..) |item, i| if (item == p) {
            _ = self.pending.swapRemove(i);
            return;
        };
    }

    fn takeFrame(self: *Client, p: *Pending) ?[]u8 {
        p.lock.lockUncancelable(self.io);
        defer p.lock.unlock(self.io);
        if (p.frames.items.len == 0) return null;
        return p.frames.orderedRemove(0);
    }

    fn push(self: *Client, p: *Pending, frame: []const u8) void {
        const copy = self.gpa.dupe(u8, frame) catch return;
        p.lock.lockUncancelable(self.io);
        p.frames.append(self.gpa, copy) catch {
            self.gpa.free(copy);
        };
        p.lock.unlock(self.io);
        p.event.set(self.io);
    }

    fn frameIsResponse(frame: []const u8) bool {
        // A response has "result" or "error" and no "method" at the top level. The frames
        // come from the SDK's own parser, so a cheap check on the first key is enough.
        return std.mem.indexOf(u8, frame, "\"result\"") != null or std.mem.indexOf(u8, frame, "\"error\"") != null;
    }

    fn readerLoop(self: *Client) void {
        const io = self.io;
        var line_reader: framer.Framer = .{ .reader = &self.stdout_reader.interface, .max_line_bytes = self.limits.stdio.max_line_bytes };
        while (true) {
            var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const line = line_reader.next(arena) catch |e| switch (e) {
                error.LineTooLong, error.InvalidUtf8, error.ControlCharacter => continue,
                else => break,
            };
            const msg = jsonrpc.Message.parse(arena, line) catch continue;
            switch (msg) {
                .response => |r| self.route(r.id, line),
                .error_response => |e| if (e.id) |id| self.route(id, line),
                .notification => |n| self.routeNotification(arena, n, line),
                .request => {}, // servers do not send requests in this revision
            }
        }
        self.closed.store(true, .release);
        // Wake every waiter so it can see the end of the stream.
        self.pending_lock.lockUncancelable(io);
        defer self.pending_lock.unlock(io);
        for (self.pending.items) |p| p.event.set(io);
    }

    fn route(self: *Client, id: RequestId, line: []const u8) void {
        self.pending_lock.lockUncancelable(self.io);
        defer self.pending_lock.unlock(self.io);
        for (self.pending.items) |p| if (p.id.eql(id)) {
            self.push(p, line);
            return;
        };
    }

    fn routeNotification(self: *Client, arena: Allocator, n: jsonrpc.Message.Notification, line: []const u8) void {
        if (n.params) |params| if (params == .object) {
            // Request-scoped notifications carry the progress token or the subscription id,
            // both of which equal the request id.
            if (params.object.get("progressToken")) |token| {
                if (RequestId.fromValue(arena, token)) |id| {
                    self.route(id, line);
                    return;
                }
            }
            if (params.object.get("_meta")) |m| if (m == .object) {
                if (m.object.get("io.modelcontextprotocol/subscriptionId")) |sid| {
                    if (RequestId.fromValue(arena, sid)) |id| {
                        self.route(id, line);
                        return;
                    }
                }
                if (m.object.get("progressToken")) |token| {
                    if (RequestId.fromValue(arena, token)) |id| {
                        self.route(id, line);
                        return;
                    }
                }
            };
        };
        if (self.on_notification) |f| f(self.userdata, n.method, n.params);
    }
};
