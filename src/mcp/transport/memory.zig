//! An in-process transport for tests: frames go in as text, frames come out into a list.
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
        const msg = try jsonrpc.Message.parse(arena, text);
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

/// An in-process client transport that hands frames straight to a server.
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
        failed: bool = false,
    };

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *ClientLink = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const msg = jsonrpc.Message.parse(arena, ex.frame) catch |e| switch (e) {
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
