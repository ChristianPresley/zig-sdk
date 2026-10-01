//! Routes the frames that a client reads from one connection to the requests in flight. The
//! stdio client and the Unix socket client read a newline-delimited byte stream. The
//! WebSocket client gives each message to `Router.deliver`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const framer = @import("../util/line_framer.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;
const Transport = @import("Transport.zig");

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
        if (std.mem.eql(u8, n.method, "notifications/cancelled")) logCancelled(arena, n.params);
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
            self.deliver(arena, line, on_notification, userdata);
        }
    }

    /// Route one complete frame to the request that it belongs to. The router copies the
    /// frame. It drops a frame that is not a JSON-RPC message and a request, because servers
    /// do not send requests in this revision. `arena` holds the parsed message only.
    pub fn deliver(self: *Router, arena: Allocator, frame: []const u8, on_notification: ?NotificationFn, userdata: ?*anyopaque) void {
        const msg = jsonrpc.Message.parse(arena, frame) catch return;
        switch (msg) {
            .response => |r| self.route(r.id, frame),
            .error_response => |e| if (e.id) |id| self.route(id, frame),
            .notification => |n| self.routeNotification(arena, n, frame, on_notification, userdata),
            .request => {},
        }
    }
};

/// Log the request id and the reason of a `notifications/cancelled` from the server.
fn logCancelled(arena: Allocator, params: ?Value) void {
    const p = params orelse return;
    if (p != .object) return;
    const id = RequestId.fromValue(arena, p.object.get("requestId") orelse return) orelse return;
    const reason: ?[]const u8 = if (p.object.get("reason")) |r| (if (r == .string) r.string else null) else null;
    Transport.logCancellation(id, reason);
}

/// True when `frame` is a response. A response has "result" or "error" and no "method" at
/// the top level. Keys inside nested values do not count, so a notification with an
/// "error" member in its data is not a response.
pub fn frameIsResponse(frame: []const u8) bool {
    var buf: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var scanner: std.json.Scanner = .initCompleteInput(fba.allocator(), frame);
    return topLevelResponse(fba.allocator(), &scanner) catch fallbackIsResponse(frame);
}

fn topLevelResponse(fba: std.mem.Allocator, scanner: *std.json.Scanner) !bool {
    if (try scanner.next() != .object_begin) return error.NotAnObject;
    var found = false;
    while (true) {
        switch (try scanner.nextAllocMax(fba, .alloc_if_needed, 64)) {
            .object_end => return found,
            .string, .allocated_string => |key| {
                if (std.mem.eql(u8, key, "method")) return false;
                if (std.mem.eql(u8, key, "result") or std.mem.eql(u8, key, "error")) found = true;
            },
            else => return error.UnexpectedToken,
        }
        try scanner.skipValue();
    }
}

/// The check for a frame that the scanner cannot read in the fixed buffer.
fn fallbackIsResponse(frame: []const u8) bool {
    if (std.mem.indexOf(u8, frame, "\"method\"") != null) return false;
    return std.mem.indexOf(u8, frame, "\"result\"") != null or std.mem.indexOf(u8, frame, "\"error\"") != null;
}

test "only top-level keys make a frame a response" {
    try std.testing.expect(frameIsResponse("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
    try std.testing.expect(frameIsResponse("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"x\"}}"));
    try std.testing.expect(!frameIsResponse("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"error\",\"data\":{\"error\":\"disk full\",\"result\":1}}}"));
    try std.testing.expect(!frameIsResponse("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1,\"message\":\"\\\"error\\\"\"}}"));
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

test "router routes the progress of two concurrent requests by their tokens" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var router: Router = .init(io, gpa);
    defer router.deinit();
    var a: Router.Pending = .{ .id = .{ .integer = 1 } };
    defer a.deinit(gpa);
    var b: Router.Pending = .{ .id = .{ .string = "b" } };
    defer b.deinit(gpa);
    try router.register(&a);
    defer router.unregister(&a);
    try router.register(&b);
    defer router.unregister(&b);
    // The frames of the two requests arrive interleaved. The router drops a progress
    // notification with the token of no request in flight.
    var in: Io.Reader = .fixed(
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":0}}
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"b","progress":0}}
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"b","progress":1}}
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":99,"progress":0}}
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1}}
        \\{"jsonrpc":"2.0","id":"b","result":{}}
        \\{"jsonrpc":"2.0","id":1,"result":{}}
        \\
    );
    const Unrouted = struct {
        var count: usize = 0;
        fn record(userdata: ?*anyopaque, method: []const u8, params: ?Value) void {
            _ = userdata;
            _ = method;
            _ = params;
            count += 1;
        }
    };
    router.readUntilEof(&in, 1024, Unrouted.record, null);
    try std.testing.expectEqual(0, Unrouted.count);
    for ([_]*Router.Pending{ &a, &b }) |p| {
        const want_token = if (p == &a) "\"progressToken\":1," else "\"progressToken\":\"b\",";
        for (0..2) |i| {
            const frame = router.takeFrame(p).?;
            defer gpa.free(frame);
            try std.testing.expect(!frameIsResponse(frame));
            try std.testing.expect(std.mem.indexOf(u8, frame, want_token) != null);
            var buf: [16]u8 = undefined;
            try std.testing.expect(std.mem.indexOf(u8, frame, try std.fmt.bufPrint(&buf, "\"progress\":{d}", .{i})) != null);
        }
        const last = router.takeFrame(p).?;
        defer gpa.free(last);
        try std.testing.expect(frameIsResponse(last));
        try std.testing.expect(router.takeFrame(p) == null);
    }
}
