//! In-process transports. `Harness` is for tests: frames go in as text, and frames come out
//! into a list. `ClientLink` connects a client to a server in the same process. You can use
//! it in production with the limits that its doc comment tells.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("Transport.zig");
const jsonrpc = @import("../jsonrpc.zig");
const Server = @import("../server/Server.zig");
const Principal = @import("../auth/resource_server.zig").Principal;

pub const Harness = struct {
    io: Io,
    gpa: Allocator,
    server: *Server,
    out: std.ArrayList([]u8) = .empty,
    out_lock: Io.Mutex = .init,
    finished: bool = false,
    /// The source of the requests for the rate limits of the server.
    peer: Transport.Peer = .unknown,
    /// The authorization principal of the requests. With a principal, the requests have the
    /// kind `streamable_http`, as the requests of the HTTP transport.
    principal: ?*const Principal = null,

    pub fn init(io: Io, gpa: Allocator, server: *Server) Harness {
        return .{ .io = io, .gpa = gpa, .server = server };
    }

    pub fn deinit(self: *Harness) void {
        for (self.out.items) |f| self.gpa.free(f);
        self.out.deinit(self.gpa);
    }

    pub fn clear(self: *Harness) void {
        for (self.out.items) |f| self.gpa.free(f);
        self.out.clearRetainingCapacity();
        self.finished = false;
    }

    /// Deliver one request frame and run the server inline. Send long-lived requests with
    /// `sendConcurrent`.
    pub fn send(self: *Harness, text: []const u8) !void {
        var token: Transport.CancelToken = .{};
        try self.sendWithToken(text, &token);
    }

    pub fn sendWithToken(self: *Harness, text: []const u8, token: *Transport.CancelToken) !void {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const msg = try jsonrpc.Message.parseMaxDepth(arena, text, self.server.options.limits.json_max_depth);
        self.server.handle(self.io, .{
            .kind = if (self.principal != null) .streamable_http else .memory,
            .arena = arena,
            .message = msg,
            .responder = self.responder(),
            .cancel = token,
            .context = @ptrCast(@constCast(self.principal)),
            .peer = self.peer,
        });
    }

    /// The last frame that was output, or null.
    pub fn last(self: *Harness) ?[]const u8 {
        if (self.out.items.len == 0) return null;
        return self.out.items[self.out.items.len - 1];
    }

    pub fn responder(self: *Harness) Transport.Responder {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.Responder.VTable = .{
        .notify = notify,
        .finish = finish,
        .abort = abort,
    };

    fn push(self: *Harness, frame: []const u8) Transport.SendError!void {
        const copy = try self.gpa.dupe(u8, frame);
        errdefer self.gpa.free(copy);
        self.out_lock.lockUncancelable(self.io);
        defer self.out_lock.unlock(self.io);
        try self.out.append(self.gpa, copy);
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = io;
        const self: *Harness = @ptrCast(@alignCast(ptr));
        try self.push(frame);
    }

    fn finish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = io;
        const self: *Harness = @ptrCast(@alignCast(ptr));
        try self.push(frame);
        self.finished = true;
    }

    fn abort(ptr: *anyopaque, io: Io) void {
        _ = io;
        const self: *Harness = @ptrCast(@alignCast(ptr));
        self.finished = true;
    }
};

/// An in-process client transport that gives each request straight to a server. It has no
/// task of its own and no deadlines. These are its limits:
///
/// - `exchange` runs the handler of the request on the task of the caller. The frames of
///   the request get to the sink on that task, also the acknowledgment of a listen stream.
///   The events of a listen stream get to the sink on the task that publishes them.
/// - Only the cancel token of the caller ends an exchange. The server uses that token as the
///   token of the request. Thus a server shutdown also fires it.
/// - The link does not obey `Exchange.timeout` and `Exchange.first_frame_timeout`. Thus
///   `RequestOptions.timeout`, `limits.request_timeout` and `limits.listen_ack_timeout` have no
///   effect on it.
/// - The link ignores `Exchange.inline_notifications`. The callbacks always run on the task
///   that gives the frame.
/// - A callback of a listen stream runs while the server holds the lock of the stream. Thus
///   it must not publish an event of the same server, for example with
///   `Server.setToolEnabled` or `Server.notifyToolsListChanged`. It also must not wait for a
///   task that publishes an event or ends a listen stream of the same server.
pub const ClientLink = struct {
    io: Io,
    gpa: Allocator,
    server: *Server,

    pub fn init(io: Io, gpa: Allocator, server: *Server) ClientLink {
        return .{ .io = io, .gpa = gpa, .server = server };
    }

    pub fn transport(self: *ClientLink) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &client_vtable };
    }

    const client_vtable: Transport.ClientTransport.VTable = .{
        .kind = .memory,
        .exchange = exchange,
        .notify = clientNotify,
    };

    const Forward = struct {
        sink: Transport.Exchange.Sink,
        /// Gives the frames of the request to the sink one at a time, as `out_lock` of stdio
        /// and `write_lock` of HTTP do. The events of a listen stream come from the task that
        /// publishes them, and the other frames from the task of the request.
        lock: Io.Mutex = .init,
        /// Set under `lock`. `exchange` reads it after the server returns, when no other task
        /// gives frames to the sink.
        failed: bool = false,
    };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *ClientLink = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const msg = jsonrpc.Message.parseMaxDepth(arena, ex.frame, self.server.options.limits.json_max_depth) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidFrame,
        };
        var forward: Forward = .{ .sink = ex.sink };
        self.server.handle(io, .{
            .kind = .memory,
            .arena = arena,
            .message = msg,
            .responder = .{ .ptr = &forward, .vtable = &forward_vtable },
            .cancel = ex.cancel,
        });
        if (forward.failed) return error.ReadFailed;
        if (ex.cancel.isCancelled()) return error.Canceled;
    }

    fn clientNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const self: *ClientLink = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const msg = jsonrpc.Message.parse(arena, frame) catch return error.WriteFailed;
        var token: Transport.CancelToken = .{};
        var forward: Forward = .{ .sink = .{ .ptr = undefined, .on_frame = dropFrame } };
        self.server.handle(io, .{
            .kind = .memory,
            .arena = arena,
            .message = msg,
            .responder = .{ .ptr = &forward, .vtable = &forward_vtable },
            .cancel = &token,
        });
    }

    fn dropFrame(_: *anyopaque, _: Io, _: []const u8) anyerror!void {}

    const forward_vtable: Transport.Responder.VTable = .{
        .notify = forwardNotify,
        .finish = forwardFinish,
        .abort = forwardAbort,
    };

    fn forwardNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const f: *Forward = @ptrCast(@alignCast(ptr));
        f.lock.lockUncancelable(io);
        defer f.lock.unlock(io);
        f.sink.deliver(io, frame) catch {
            f.failed = true;
            return error.Closed;
        };
    }

    fn forwardFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        return forwardNotify(ptr, io, frame);
    }

    fn forwardAbort(ptr: *anyopaque, io: Io) void {
        _ = ptr;
        _ = io;
    }
};

/// A sink that counts its calls and the calls that overlap another call.
const OverlapSink = struct {
    inside: std.atomic.Value(u32) = .init(0),
    calls: std.atomic.Value(u32) = .init(0),
    overlaps: std.atomic.Value(u32) = .init(0),

    fn onFrame(ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void {
        _ = frame;
        const self: *OverlapSink = @ptrCast(@alignCast(ptr));
        if (self.inside.fetchAdd(1, .acq_rel) != 0) _ = self.overlaps.fetchAdd(1, .monotonic);
        defer _ = self.inside.fetchSub(1, .acq_rel);
        _ = self.calls.fetchAdd(1, .monotonic);
        // Stay in the sink for a moment. A second task that does not wait then overlaps.
        try io.sleep(.fromMicroseconds(500), .awake);
    }

    fn forwardMany(forward: *ClientLink.Forward, count: usize) void {
        for (0..count) |_| ClientLink.forwardNotify(forward, std.testing.io, "{}") catch {};
    }
};

test "the memory link gives the frames of one request to the sink one at a time" {
    const io = std.testing.io;
    var sink: OverlapSink = .{};
    var forward: ClientLink.Forward = .{ .sink = .{ .ptr = &sink, .on_frame = OverlapSink.onFrame } };
    // An event of a listen stream comes from the task that publishes it, the other frames
    // from the task of the request.
    var a = try io.concurrent(OverlapSink.forwardMany, .{ &forward, 10 });
    var b = try io.concurrent(OverlapSink.forwardMany, .{ &forward, 10 });
    a.await(io);
    b.await(io);
    try std.testing.expectEqual(20, sink.calls.load(.monotonic));
    try std.testing.expectEqual(0, sink.overlaps.load(.monotonic));
}
