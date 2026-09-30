//! Routes the frames that a client reads from one newline-delimited byte stream to the
//! requests in flight. The stdio client and the Unix socket client use it.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const framer = @import("../util/line_framer.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;

/// Receives a notification that belongs to no request in flight.
pub const NotificationFn = *const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void;

pub const Router = struct {
    io: Io,
    gpa: Allocator,
    pending: std.ArrayList(*Pending) = .empty,
    lock: Io.Mutex = .init,

    /// One request that waits for its frames.
    pub const Pending = struct {
        id: RequestId,
        /// The stdio client counts process restarts here.
        generation: u32 = 0,
        frames: std.ArrayList([]u8) = .empty,
        lock: Io.Mutex = .init,
        event: Io.Event = .unset,

        /// Free the frames that nobody took.
        pub fn deinit(p: *Pending, gpa: Allocator) void {
            for (p.frames.items) |f| gpa.free(f);
            p.frames.deinit(gpa);
        }
    };

    pub fn init(io: Io, gpa: Allocator) Router {
        return .{ .io = io, .gpa = gpa };
    }

    pub fn deinit(self: *Router) void {
        self.pending.deinit(self.gpa);
    }

    pub fn register(self: *Router, p: *Pending) error{OutOfMemory}!void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        try self.pending.append(self.gpa, p);
    }

    pub fn unregister(self: *Router, p: *Pending) void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.pending.items, 0..) |item, i| if (item == p) {
            _ = self.pending.swapRemove(i);
            return;
        };
    }

    /// Remove and return the oldest frame of `p`. The caller frees it with `gpa`.
    pub fn takeFrame(self: *Router, p: *Pending) ?[]u8 {
        p.lock.lockUncancelable(self.io);
        defer p.lock.unlock(self.io);
        if (p.frames.items.len == 0) return null;
        return p.frames.orderedRemove(0);
    }

    fn push(self: *Router, p: *Pending, frame: []const u8) void {
        const copy = self.gpa.dupe(u8, frame) catch return;
        p.lock.lockUncancelable(self.io);
        p.frames.append(self.gpa, copy) catch {
            self.gpa.free(copy);
        };
        p.lock.unlock(self.io);
        p.event.set(self.io);
    }

    /// Wake every waiter so that it can see the end of the stream.
    pub fn wakeAll(self: *Router) void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.pending.items) |p| p.event.set(self.io);
    }

    fn route(self: *Router, id: RequestId, line: []const u8) void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.pending.items) |p| if (p.id.eql(id)) {
            self.push(p, line);
            return;
        };
    }

    fn routeNotification(self: *Router, arena: Allocator, n: jsonrpc.Message.Notification, line: []const u8, on_notification: ?NotificationFn, userdata: ?*anyopaque) void {
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
        if (on_notification) |f| f(userdata, n.method, n.params);
    }

    /// Read frames from `in` and route them until the stream ends or a read fails.
    pub fn readUntilEof(self: *Router, in: *Io.Reader, max_line_bytes: usize, on_notification: ?NotificationFn, userdata: ?*anyopaque) void {
        var line_reader: framer.Framer = .{ .reader = in, .max_line_bytes = max_line_bytes };
        while (true) {
            var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const line = line_reader.next(arena) catch |e| switch (e) {
                error.LineTooLong, error.InvalidUtf8, error.ControlCharacter => continue,
                else => return,
            };
            const msg = jsonrpc.Message.parse(arena, line) catch continue;
            switch (msg) {
                .response => |r| self.route(r.id, line),
                .error_response => |e| if (e.id) |id| self.route(id, line),
                .notification => |n| self.routeNotification(arena, n, line, on_notification, userdata),
                .request => {}, // servers do not send requests in this revision
            }
        }
    }
};

/// True when `frame` is a response. A response has "result" or "error" and no "method" at
/// the top level. The frames come from the SDK parser, so a cheap check is enough.
pub fn frameIsResponse(frame: []const u8) bool {
    return std.mem.indexOf(u8, frame, "\"result\"") != null or std.mem.indexOf(u8, frame, "\"error\"") != null;
}

test "router routes responses by id and progress by token" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var router: Router = .init(io, gpa);
    defer router.deinit();
    var p: Router.Pending = .{ .id = .{ .integer = 7 } };
    defer p.deinit(gpa);
    try router.register(&p);
    defer router.unregister(&p);
    var in: Io.Reader = .fixed(
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":7,"progress":1}}
        \\{"jsonrpc":"2.0","id":8,"result":{}}
        \\{"jsonrpc":"2.0","id":7,"result":{}}
        \\
    );
    router.readUntilEof(&in, 1024, null, null);
    const first = router.takeFrame(&p).?;
    defer gpa.free(first);
    try std.testing.expect(!frameIsResponse(first));
    const second = router.takeFrame(&p).?;
    defer gpa.free(second);
    try std.testing.expect(frameIsResponse(second));
    try std.testing.expect(router.takeFrame(&p) == null);
}
