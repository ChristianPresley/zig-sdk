//! An in-process transport for tests: frames go in as text, frames come out into a list.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("Transport.zig");
const jsonrpc = @import("../jsonrpc.zig");
const Server = @import("../server/Server.zig");

pub const Harness = struct {
    io: Io,
    gpa: Allocator,
    server: *Server,
    out: std.ArrayList([]u8) = .empty,
    out_lock: Io.Mutex = .init,
    finished: bool = false,

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

    /// Deliver one request frame and run the server inline. Long-lived requests must be sent
    /// with `sendConcurrent`.
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
            .kind = .memory,
            .arena = arena,
            .message = msg,
            .responder = self.responder(),
            .cancel = token,
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
