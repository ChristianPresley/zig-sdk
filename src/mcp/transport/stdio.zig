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
