//! Routes the frames that a client reads from one connection to the requests in flight. The
//! stdio client and the Unix socket client read a newline-delimited byte stream. The
//! WebSocket client gives each message to `Router.deliver`.
//!
//! The router puts the frames of a request in the queue of the request, and the task of the
//! request takes them. A request with `Exchange.inline_notifications` gets its notifications
//! at once on the reader task. Thus such a notification gets to its sink before the router
//! routes the next frame, also when that frame is the response of another request.
//!
//! The router logs a warning in the scope `mcp_router` for each frame that it drops. The
//! warning has the reason and the request id, but no other part of the frame. When the router
//! cannot read a frame, it finds the request of the frame and makes that request fail with
//! `error.InvalidFrame`. Thus the request does not wait until its timeout. Examples are a
//! line over the length limit and a line that is not valid UTF-8. Other examples are a frame
//! that is not a JSON-RPC message and an error response with a null id.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const framer = @import("../util/line_framer.zig");
const json = @import("../json.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;
const Transport = @import("Transport.zig");

const log = std.log.scoped(.mcp_router);

/// Receives each notification that has no progress token and no subscription id, for example
/// a log message of the server during a request. The router drops a notification whose
/// progress token or subscription id names no request in flight. The function runs on the
/// reader task: while it runs, the router routes no frame. `method` and `params` are valid
/// only during the call.
pub const NotificationFn = *const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void;

pub const Router = struct {
    io: Io,
    gpa: Allocator,
    /// `Limits.json_max_depth` of the client. The router drops a deeper notification that
    /// belongs to no request.
    max_depth: u16,
    pending: std.ArrayList(*Pending) = .empty,
    lock: Io.Mutex = .init,
    /// The number of frames that the router dropped. Each drop also logs a warning.
    dropped_frames: std.atomic.Value(u64) = .init(0),

    /// One request that waits for its frames.
    pub const Pending = struct {
        id: RequestId,
        /// The stdio client counts process restarts here.
        generation: u32 = 0,
        /// The exchange that gets the notifications of the request at once on the reader
        /// task. Null puts them in `frames`. The transport sets it when
        /// `Exchange.inline_notifications` is on.
        inline_exchange: ?*Transport.Exchange = null,
        frames: std.ArrayList([]u8) = .empty,
        /// True after the request failed: the sink of `inline_exchange` refused a
        /// notification, or the router could not read a frame of the request. The router then
        /// drops the next frames of the request. `lock` guards it.
        failed: bool = false,
        lock: Io.Mutex = .init,
        /// The reader task holds this lock while it gives a notification to `inline_exchange`.
        /// `unregister` waits for it, thus the reader task does not use the exchange after the
        /// request ends.
        inline_lock: Io.Mutex = .init,
        event: Io.Event = .unset,

        /// Free the frames that nobody took.
        pub fn deinit(p: *Pending, gpa: Allocator) void {
            for (p.frames.items) |f| gpa.free(f);
            p.frames.deinit(gpa);
        }
    };

    pub fn init(io: Io, gpa: Allocator, max_depth: u16) Router {
        return .{ .io = io, .gpa = gpa, .max_depth = max_depth };
    }

    pub fn deinit(self: *Router) void {
        self.pending.deinit(self.gpa);
    }

    pub fn register(self: *Router, p: *Pending) error{OutOfMemory}!void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        try self.pending.append(self.gpa, p);
    }

    /// Remove `p`. When the reader task gives a notification to the exchange of `p` at this
    /// time, the function waits until the sink returns.
    pub fn unregister(self: *Router, p: *Pending) void {
        {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            for (self.pending.items, 0..) |item, i| if (item == p) {
                _ = self.pending.swapRemove(i);
                break;
            };
        }
        // The router takes `inline_lock` before it releases its own lock. After the removal,
        // no task can take it again for `p`.
        if (p.inline_exchange != null) {
            p.inline_lock.lockUncancelable(self.io);
            p.inline_lock.unlock(self.io);
        }
    }

    /// Remove and return the oldest frame of `p`. The caller frees it with `gpa`. After the
    /// request failed, the function gives the frames that arrived before the failure, and
    /// then `error.InvalidFrame`.
    pub fn takeFrame(self: *Router, p: *Pending) error{InvalidFrame}!?[]u8 {
        p.lock.lockUncancelable(self.io);
        defer p.lock.unlock(self.io);
        if (p.frames.items.len == 0) return if (p.failed) error.InvalidFrame else null;
        return p.frames.orderedRemove(0);
    }

    /// Put a copy of `frame` in the queue of `p`. The caller holds the router lock. When the
    /// memory for the copy is not available, the request fails.
    fn push(self: *Router, p: *Pending, frame: []const u8) void {
        p.lock.lockUncancelable(self.io);
        const dropped: ?What = if (p.failed)
            .{ .after_failure = p.id }
        else if (self.enqueue(p, frame))
            null
        else
            .{ .out_of_memory = p.id };
        if (dropped != null) {
            p.failed = true;
            self.countDrop();
        }
        p.lock.unlock(self.io);
        p.event.set(self.io);
        if (dropped) |what| logDrop(what, .none);
    }

    fn enqueue(self: *Router, p: *Pending, frame: []const u8) bool {
        const copy = self.gpa.dupe(u8, frame) catch return false;
        p.frames.append(self.gpa, copy) catch {
            self.gpa.free(copy);
            return false;
        };
        return true;
    }

    /// Give a notification to the exchange of `p` on this task. The caller holds
    /// `p.inline_lock`. A refusal of the sink makes the request fail.
    fn deliverInline(self: *Router, p: *Pending, frame: []const u8) void {
        {
            p.lock.lockUncancelable(self.io);
            defer p.lock.unlock(self.io);
            if (p.failed) return self.drop(.{ .after_failure = p.id }, .none);
        }
        p.inline_exchange.?.deliver(self.io, frame) catch {
            p.lock.lockUncancelable(self.io);
            p.failed = true;
            p.lock.unlock(self.io);
            p.event.set(self.io);
        };
    }

    /// Make `p` fail with `error.InvalidFrame` after the frames in its queue.
    fn fail(self: *Router, p: *Pending) void {
        p.lock.lockUncancelable(self.io);
        p.failed = true;
        p.lock.unlock(self.io);
        p.event.set(self.io);
    }

    /// Make the request with the id `id` fail.
    fn failId(self: *Router, id: RequestId) Outcome {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.pending.items) |p| if (p.id.eql(id)) {
            self.fail(p);
            return .{ .failed = id };
        };
        return .{ .unknown_id = id };
    }

    /// Make the request in flight fail when it is the only one. A response without a usable
    /// id can belong to any request in flight. The outcome has a copy of the id in `arena`.
    fn failOnly(self: *Router, arena: Allocator) Outcome {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.pending.items.len != 1) return .{ .ambiguous = self.pending.items.len };
        const p = self.pending.items[0];
        const id = p.id.dupe(arena) catch return .{ .ambiguous = 1 };
        self.fail(p);
        return .{ .failed = id };
    }

    /// Drop a frame that the router cannot read, and make its request fail. `scan` has the
    /// top-level members of the frame. The router finds the request by the "id" member. A
    /// frame with "result" or "error" but without a usable id fails the only request in
    /// flight. A frame with "method" is a notification or a request, and fails nothing.
    fn dropUnreadable(self: *Router, arena: Allocator, what: What, scan: *const framer.TopLevelScanner) void {
        // Count before the request wakes, thus its task sees the count.
        self.countDrop();
        const outcome: Outcome = outcome: {
            if (scan.method) break :outcome .notification;
            if (scan.id()) |text| if (parseId(arena, text)) |id| break :outcome self.failId(id);
            if (scan.response) break :outcome self.failOnly(arena);
            break :outcome .none;
        };
        logDrop(what, outcome);
    }

    /// Count a dropped frame and log a warning without the frame text.
    fn drop(self: *Router, what: What, outcome: Outcome) void {
        self.countDrop();
        logDrop(what, outcome);
    }

    fn countDrop(self: *Router) void {
        _ = self.dropped_frames.fetchAdd(1, .monotonic);
    }

    fn logDrop(what: What, outcome: Outcome) void {
        log.warn("{f}", .{DropNote{ .what = what, .outcome = outcome }});
    }

    /// Wake every waiter so that it can see the end of the stream.
    pub fn wakeAll(self: *Router) void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.pending.items) |p| p.event.set(self.io);
    }

    /// Give a frame to the request with the id `id`. The router gives a notification of a
    /// request with `inline_exchange` to its sink at once. It puts each other frame in the
    /// queue of the request.
    fn route(self: *Router, id: RequestId, line: []const u8, kind: enum { response, notification }) void {
        const target = target: {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            for (self.pending.items) |p| if (p.id.eql(id)) {
                if (kind == .response or p.inline_exchange == null) {
                    self.push(p, line);
                    return;
                }
                // Take `inline_lock` before the router lock opens. Thus `unregister` waits
                // until the sink returns.
                p.inline_lock.lockUncancelable(self.io);
                break :target p;
            };
            // For example a response after a timeout, or progress after the response.
            return self.drop(switch (kind) {
                .response => .{ .response = id },
                .notification => .{ .notification = id },
            }, .not_in_flight);
        };
        defer target.inline_lock.unlock(self.io);
        self.deliverInline(target, line);
    }

    fn routeNotification(self: *Router, arena: Allocator, n: jsonrpc.Message.Notification, line: []const u8, on_notification: ?NotificationFn, userdata: ?*anyopaque) void {
        if (std.mem.eql(u8, n.method, "notifications/cancelled")) logCancelled(arena, n.params);
        if (n.params) |params| if (params == .object) {
            // Request-scoped notifications carry the progress token or the subscription id,
            // both of which equal the request id.
            if (params.object.get("progressToken")) |token| {
                if (RequestId.fromValue(arena, token)) |id| {
                    self.route(id, line, .notification);
                    return;
                }
            }
            if (params.object.get("_meta")) |m| if (m == .object) {
                if (m.object.get("io.modelcontextprotocol/subscriptionId")) |sid| {
                    if (RequestId.fromValue(arena, sid)) |id| {
                        self.route(id, line, .notification);
                        return;
                    }
                }
                if (m.object.get("progressToken")) |token| {
                    if (RequestId.fromValue(arena, token)) |id| {
                        self.route(id, line, .notification);
                        return;
                    }
                }
            };
        };
        // The request of a routed frame checks its depth. Here the router does.
        json.checkDepth(line, self.max_depth) catch return self.drop(.{ .too_deep = self.max_depth }, .none);
        if (on_notification) |f| f(userdata, n.method, n.params);
    }

    /// Read frames from `in` and route them until the stream ends or a read fails. A line
    /// over `max_line_bytes` and a line that is not valid UTF-8 make their request fail.
    pub fn readUntilEof(self: *Router, in: *Io.Reader, max_line_bytes: usize, on_notification: ?NotificationFn, userdata: ?*anyopaque) void {
        var line_reader: framer.Framer = .{ .reader = in, .max_line_bytes = max_line_bytes };
        while (true) {
            var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const line = line_reader.next(arena) catch |e| switch (e) {
                error.LineTooLong => {
                    self.dropUnreadable(arena, .{ .too_long = max_line_bytes }, &line_reader.dropped);
                    continue;
                },
                error.InvalidUtf8, error.ControlCharacter => {
                    self.dropUnreadable(arena, .invalid_utf8, &line_reader.dropped);
                    continue;
                },
                else => return,
            };
            self.deliver(arena, line, on_notification, userdata);
        }
    }

    /// Route one complete frame to the request that it belongs to. The router copies a frame
    /// that it puts in a queue. It gives a notification of a request with `inline_exchange`
    /// to the sink before it returns. It drops a request, because servers do not send
    /// requests in this revision. `arena` holds the parsed message only.
    ///
    /// A frame that is not a JSON-RPC message makes the request with its top-level "id" fail.
    /// An error response with a null id makes the request in flight fail when it is the only
    /// one.
    pub fn deliver(self: *Router, arena: Allocator, frame: []const u8, on_notification: ?NotificationFn, userdata: ?*anyopaque) void {
        const msg = jsonrpc.Message.parse(arena, frame) catch {
            var scan: framer.TopLevelScanner = .{};
            scan.feed(frame);
            return self.dropUnreadable(arena, .invalid_message, &scan);
        };
        switch (msg) {
            .response => |r| self.route(r.id, frame, .response),
            .error_response => |e| if (e.id) |id| {
                self.route(id, frame, .response);
            } else {
                const scan: framer.TopLevelScanner = .{ .response = true };
                self.dropUnreadable(arena, .{ .null_id_error = e.code }, &scan);
            },
            .notification => |n| self.routeNotification(arena, n, frame, on_notification, userdata),
            .request => self.drop(.server_request, .none),
        }
    }
};

/// Parse the raw text of an "id" value. Null for a value that is not a valid request id.
fn parseId(arena: Allocator, text: []const u8) ?RequestId {
    const value = json.parseTree(arena, text) catch return null;
    return RequestId.fromValue(arena, value);
}

/// The kind of a frame that the router dropped.
const What = union(enum) {
    too_long: usize,
    invalid_utf8,
    invalid_message,
    /// An error response with a null id, with its error code.
    null_id_error: i64,
    server_request,
    /// A response for a request that is not in flight.
    response: RequestId,
    /// A notification for a request that is not in flight.
    notification: RequestId,
    /// A notification of no request that nests deeper than the limit.
    too_deep: u16,
    /// A frame of a request that failed before.
    after_failure: RequestId,
    /// A frame that the router did not copy, because no memory was available.
    out_of_memory: RequestId,
};

/// What the router did with the request of a dropped frame.
const Outcome = union(enum) {
    none,
    /// The request with this id fails with `error.InvalidFrame`.
    failed: RequestId,
    /// No request in flight has the id of the frame.
    unknown_id: RequestId,
    /// The request of the frame is not in flight.
    not_in_flight,
    /// This number of requests is in flight. Thus the router cannot find the request of a
    /// frame without a usable id.
    ambiguous: usize,
    /// The frame has a "method" member, thus it is not a response.
    notification,
};

/// The text of the warning for a dropped frame. It has no part of the frame text other than
/// the request id and the error code, and it shortens a long string id.
const DropNote = struct {
    what: What,
    outcome: Outcome,

    pub fn format(self: DropNote, w: *Io.Writer) Io.Writer.Error!void {
        try w.writeAll("dropped ");
        switch (self.what) {
            .too_long => |limit| try w.print("a frame longer than {d} bytes", .{limit}),
            .invalid_utf8 => try w.writeAll("a frame that is not valid UTF-8"),
            .invalid_message => try w.writeAll("a frame that is not a valid JSON-RPC message"),
            .null_id_error => |code| try w.print("an error response with the code {d} and a null id", .{code}),
            .server_request => try w.writeAll("a request of the server, because servers send no requests in this revision"),
            .response => |id| try w.print("the response of request {f}", .{IdText{ .id = id }}),
            .notification => |id| try w.print("a notification for request {f}", .{IdText{ .id = id }}),
            .too_deep => |limit| try w.print("a notification that nests deeper than {d} levels", .{limit}),
            .after_failure => |id| try w.print("a frame of request {f}, which failed before", .{IdText{ .id = id }}),
            .out_of_memory => |id| try w.print("a frame of request {f}, because no memory is available: the request fails", .{IdText{ .id = id }}),
        }
        switch (self.outcome) {
            .none => {},
            .failed => |id| try w.print(": request {f} fails", .{IdText{ .id = id }}),
            .unknown_id => |id| try w.print(": no request in flight has the id {f}", .{IdText{ .id = id }}),
            .not_in_flight => try w.writeAll(": the request is not in flight"),
            .ambiguous => |count| try w.print(": {d} requests are in flight, thus the request of the frame is not known", .{count}),
            .notification => try w.writeAll(": the frame is not a response"),
        }
    }
};

/// A request id for a log line. The text of a string id comes from the server, thus the note
/// writes at most `max_bytes` of it and replaces control characters.
const IdText = struct {
    id: RequestId,

    const max_bytes = 64;

    pub fn format(self: IdText, w: *Io.Writer) Io.Writer.Error!void {
        const text, const quote = switch (self.id) {
            .integer => |i| return w.print("{d}", .{i}),
            .string => |s| .{ s, true },
            .big => |digits| .{ digits, false },
        };
        if (quote) try w.writeByte('"');
        for (text[0..@min(text.len, max_bytes)]) |c| try w.writeByte(if (c < 0x20 or c == 0x7f) '?' else c);
        if (text.len > max_bytes) try w.writeAll("...");
        if (quote) try w.writeByte('"');
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

/// True when the scanner reads the top-level keys of `frame` and they make it a response.
/// A frame that the scanner cannot read in its fixed buffer gives false. The fallback check
/// of `frameIsResponse` finds the text "result" or "error" also in a value of a
/// notification. Use this check when a wrong "response" costs more than a wrong
/// "not a response".
pub fn frameIsResponseStrict(frame: []const u8) bool {
    var buf: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var scanner: std.json.Scanner = .initCompleteInput(fba.allocator(), frame);
    return topLevelResponse(fba.allocator(), &scanner) catch false;
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

/// The value of the top-level "method" member of `frame`, without a full parse. The slice
/// points into `frame`. The function does not check the remaining part of the frame. It
/// gives null when the frame has no such member, or when the value is not a string without
/// escape sequences. It also gives null when the scanner cannot read the keys in its fixed
/// buffer.
pub fn frameMethod(frame: []const u8) ?[]const u8 {
    var buf: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var scanner: std.json.Scanner = .initCompleteInput(fba.allocator(), frame);
    return topLevelMethod(fba.allocator(), &scanner) catch null;
}

fn topLevelMethod(fba: std.mem.Allocator, scanner: *std.json.Scanner) !?[]const u8 {
    if (try scanner.next() != .object_begin) return error.NotAnObject;
    while (true) {
        switch (try scanner.nextAllocMax(fba, .alloc_if_needed, 64)) {
            .object_end => return null,
            .string, .allocated_string => |key| if (std.mem.eql(u8, key, "method")) {
                return switch (try scanner.next()) {
                    .string => |name| name,
                    else => null,
                };
            },
            else => return error.UnexpectedToken,
        }
        try scanner.skipValue();
    }
}

test "the method of a frame comes from the top-level member only" {
    try std.testing.expectEqualStrings("notifications/progress", frameMethod("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1}}").?);
    // The member can come after the parameters.
    try std.testing.expectEqualStrings("notifications/message", frameMethod("{\"params\":{\"method\":\"x\",\"data\":[{\"method\":\"y\"}]},\"method\":\"notifications/message\",\"jsonrpc\":\"2.0\"}").?);
    // A "method" key inside a nested value does not count.
    try std.testing.expect(frameMethod("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"method\":\"notifications/progress\"}}") == null);
    // A value with an escape sequence, a value that is not a string, and a frame that is not
    // an object give null.
    try std.testing.expect(frameMethod("{\"jsonrpc\":\"2.0\",\"method\":\"notifications\\/progress\"}") == null);
    try std.testing.expect(frameMethod("{\"jsonrpc\":\"2.0\",\"method\":7}") == null);
    try std.testing.expect(frameMethod("[{\"method\":\"notifications/progress\"}]") == null);
    try std.testing.expect(frameMethod("{\"jsonrpc\":") == null);
}

test "only top-level keys make a frame a response" {
    try std.testing.expect(frameIsResponse("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
    try std.testing.expect(frameIsResponse("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"x\"}}"));
    try std.testing.expect(!frameIsResponse("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"error\",\"data\":{\"error\":\"disk full\",\"result\":1}}}"));
    try std.testing.expect(!frameIsResponse("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1,\"message\":\"\\\"error\\\"\"}}"));
}

test "the strict check gives false for a frame that the scanner cannot read" {
    try std.testing.expect(frameIsResponseStrict("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
    try std.testing.expect(frameIsResponseStrict("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"x\"}}"));
    try std.testing.expect(!frameIsResponseStrict("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"error\",\"data\":{\"error\":\"disk full\",\"result\":1}}}"));
    // A top-level key with an escape sequence is too long for the buffer of the scanner. The
    // "method" key has an escape sequence too, and a value has the text "error". The fallback
    // check takes this notification for a response, and the strict check does not.
    const notification = "{\"jsonrpc\":\"2.0\",\"\\u0078" ++ "x" ** 80 ++ "\":0,\"\\u006dethod\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"error\"}}";
    try std.testing.expect(frameIsResponse(notification));
    try std.testing.expect(!frameIsResponseStrict(notification));
    // A response that the scanner cannot read also gives false.
    try std.testing.expect(!frameIsResponseStrict("{\"jsonrpc\":\"2.0\",\"\\u0078" ++ "x" ** 80 ++ "\":0,\"id\":1,\"result\":{}}"));
}

test "router routes responses by id and progress by token" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var router: Router = .init(io, gpa, 64);
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
    const first = (try router.takeFrame(&p)).?;
    defer gpa.free(first);
    try std.testing.expect(!frameIsResponse(first));
    const second = (try router.takeFrame(&p)).?;
    defer gpa.free(second);
    try std.testing.expect(frameIsResponse(second));
    try std.testing.expect(try router.takeFrame(&p) == null);
}

test "router routes the progress of two concurrent requests by their tokens" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var router: Router = .init(io, gpa, 64);
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
    try std.testing.expectEqual(1, router.dropped_frames.load(.monotonic));
    for ([_]*Router.Pending{ &a, &b }) |p| {
        const want_token = if (p == &a) "\"progressToken\":1," else "\"progressToken\":\"b\",";
        for (0..2) |i| {
            const frame = (try router.takeFrame(p)).?;
            defer gpa.free(frame);
            try std.testing.expect(!frameIsResponse(frame));
            try std.testing.expect(std.mem.indexOf(u8, frame, want_token) != null);
            var buf: [16]u8 = undefined;
            try std.testing.expect(std.mem.indexOf(u8, frame, try std.fmt.bufPrint(&buf, "\"progress\":{d}", .{i})) != null);
        }
        const last = (try router.takeFrame(p)).?;
        defer gpa.free(last);
        try std.testing.expect(frameIsResponse(last));
        try std.testing.expect(try router.takeFrame(p) == null);
    }
}

/// Route `text` with a line limit of 1024 bytes, through a reader with a small buffer when
/// `small_buffer` is true. A line over the limit then takes the slow path of the framer.
fn routeText(router: *Router, text: []const u8, small_buffer: bool) void {
    var fixed: Io.Reader = .fixed(text);
    var buf: [16]u8 = undefined;
    var limited = fixed.limited(.unlimited, &buf);
    router.readUntilEof(if (small_buffer) &limited.interface else &fixed, 1024, null, null);
}

test "a frame that the router cannot read makes the request with its id fail" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Case = struct { line: []const u8, fails: ?i64 };
    const cases = [_]Case{
        // A line over the limit. The id comes after the result, as some servers write it.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"result\":{\"id\":2,\"text\":\"" ++ "x" ** 2000 ++ "\"},\"id\":1}", .fails = 1 },
        // A line that is not valid UTF-8.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"text\":\"\xff\"}}", .fails = 2 },
        // A response without a result is not a JSON-RPC message.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"id\":1}", .fails = 1 },
        // A response that nests too deep for the parser.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"a\":" ++ "[" ** 300 ++ "]" ** 300 ++ "}}", .fails = 2 },
        // A notification over the limit fails no request.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"message\":\"" ++ "x" ** 2000 ++ "\"}}", .fails = null },
        // A line that is not JSON, for example a log line of the server on the wrong stream.
        .{ .line = "server started", .fails = null },
        // An error response with a null id, while two requests are in flight.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}", .fails = null },
        // A response of a request that is not in flight, for example after its timeout.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}", .fails = null },
        // A request of the server.
        .{ .line = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}", .fails = null },
    };
    for (cases) |case| for ([_]bool{ false, true }) |small_buffer| {
        var router: Router = .init(io, gpa, 64);
        defer router.deinit();
        var a: Router.Pending = .{ .id = .{ .integer = 1 } };
        defer a.deinit(gpa);
        var b: Router.Pending = .{ .id = .{ .integer = 2 } };
        defer b.deinit(gpa);
        try router.register(&a);
        defer router.unregister(&a);
        try router.register(&b);
        defer router.unregister(&b);
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(gpa);
        try text.print(gpa, "{s}\n{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{}}}}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}\n", .{case.line});
        routeText(&router, text.items, small_buffer);

        for ([_]*Router.Pending{ &a, &b }) |p| {
            if (case.fails != null and case.fails.? == p.id.integer) {
                // The router drops the response after the failure too.
                try std.testing.expectError(error.InvalidFrame, router.takeFrame(p));
            } else {
                const response = (try router.takeFrame(p)).?;
                defer gpa.free(response);
                try std.testing.expect(frameIsResponse(response));
                try std.testing.expect(try router.takeFrame(p) == null);
            }
        }
        const drops: u64 = if (case.fails == null) 1 else 2;
        try std.testing.expectEqual(drops, router.dropped_frames.load(.monotonic));
    };
}

test "an error response with a null id makes the request fail when it is the only one" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var router: Router = .init(io, gpa, 64);
    defer router.deinit();
    var p: Router.Pending = .{ .id = .{ .string = "only" } };
    defer p.deinit(gpa);
    try router.register(&p);
    defer router.unregister(&p);
    // A progress notification before the error still gets to the request.
    routeText(&router,
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"only","progress":1}}
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}
        \\
    , false);
    const progress = (try router.takeFrame(&p)).?;
    defer gpa.free(progress);
    try std.testing.expect(!frameIsResponse(progress));
    try std.testing.expectError(error.InvalidFrame, router.takeFrame(&p));
    try std.testing.expectEqual(1, router.dropped_frames.load(.monotonic));

    // A frame with a string id that has an escape sequence finds its request too.
    var q: Router.Pending = .{ .id = .{ .string = "b" } };
    defer q.deinit(gpa);
    try router.register(&q);
    defer router.unregister(&q);
    routeText(&router, "{\"jsonrpc\":\"2.0\",\"id\":\"\\" ++ "u0062\"}\n", false);
    try std.testing.expectError(error.InvalidFrame, router.takeFrame(&q));
}

test "the warning of a dropped frame has the reason and a short request id only" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try w.print("{f}", .{DropNote{ .what = .{ .too_long = 1024 }, .outcome = .{ .failed = .{ .integer = 7 } } }});
    try std.testing.expectEqualStrings("dropped a frame longer than 1024 bytes: request 7 fails", w.buffered());
    w = .fixed(&buf);
    try w.print("{f}", .{DropNote{ .what = .{ .null_id_error = -32700 }, .outcome = .{ .ambiguous = 2 } }});
    try std.testing.expectEqualStrings("dropped an error response with the code -32700 and a null id: 2 requests are in flight, thus the request of the frame is not known", w.buffered());
    // The server sets the text of a string id. The note shortens it and replaces control
    // characters.
    w = .fixed(&buf);
    try w.print("{f}", .{DropNote{ .what = .{ .response = .{ .string = "a\nb" ++ "c" ** 100 } }, .outcome = .not_in_flight }});
    try std.testing.expectEqualStrings("dropped the response of request \"a?b" ++ "c" ** 61 ++ "...\": the request is not in flight", w.buffered());
}

/// The sink of a request with `inline_exchange` in the tests. It counts the notifications.
/// At each notification it records whether the queue of `other` holds a frame.
const InlineSink = struct {
    other: *Router.Pending,
    notifications: u32 = 0,
    other_had_frame: bool = false,
    /// The sink refuses a notification with this method.
    refuse: ?[]const u8 = null,

    fn onFrame(ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void {
        const self: *InlineSink = @ptrCast(@alignCast(ptr));
        // The router puts a response in the queue, also for a request with an inline exchange.
        if (frameIsResponse(frame)) return error.UnexpectedResponse;
        if (self.refuse) |m| if (std.mem.eql(u8, frameMethod(frame) orelse "", m)) return error.Refused;
        self.notifications += 1;
        self.other.lock.lockUncancelable(io);
        defer self.other.lock.unlock(io);
        if (self.other.frames.items.len != 0) self.other_had_frame = true;
    }

    fn exchange(self: *InlineSink, id: RequestId, cancel: *Transport.CancelToken) Transport.Exchange {
        return .{
            .frame = "",
            .id = id,
            .method = "subscriptions/listen",
            .params = null,
            .sink = .{ .ptr = self, .on_frame = onFrame },
            .cancel = cancel,
            .inline_notifications = true,
        };
    }
};

test "an inline notification reaches its sink before the router routes the response of another request" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // The server writes an event of the listen stream 1 and then the response of request 2.
    const frames =
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":1}}}
        \\{"jsonrpc":"2.0","id":2,"result":{}}
        \\
    ;
    for ([_]bool{ true, false }) |inline_on| {
        var router: Router = .init(io, gpa, 64);
        defer router.deinit();
        var call: Router.Pending = .{ .id = .{ .integer = 2 } };
        defer call.deinit(gpa);
        var sink: InlineSink = .{ .other = &call };
        var cancel: Transport.CancelToken = .{};
        var ex = sink.exchange(.{ .integer = 1 }, &cancel);
        var listen: Router.Pending = .{ .id = .{ .integer = 1 }, .inline_exchange = if (inline_on) &ex else null };
        defer listen.deinit(gpa);
        try router.register(&listen);
        defer router.unregister(&listen);
        try router.register(&call);
        defer router.unregister(&call);
        var in: Io.Reader = .fixed(frames);
        router.readUntilEof(&in, 1024, null, null);

        const response = (try router.takeFrame(&call)).?;
        defer gpa.free(response);
        try std.testing.expect(frameIsResponse(response));
        if (inline_on) {
            // The sink got the event before the response was in the queue of request 2.
            try std.testing.expectEqual(1, sink.notifications);
            try std.testing.expect(!sink.other_had_frame);
            try std.testing.expect(ex.got_frame.load(.acquire));
            try std.testing.expect(try router.takeFrame(&listen) == null);
        } else {
            // The event waits in the queue of the listen stream. The task of request 2 can
            // take the response first.
            try std.testing.expectEqual(0, sink.notifications);
            const event = (try router.takeFrame(&listen)).?;
            defer gpa.free(event);
            try std.testing.expect(!frameIsResponse(event));
        }
    }
}

test "a notification that the inline sink refuses makes its request fail after the earlier frames" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Case = struct { frames: []const u8, notifications: u32, response_first: bool };
    const cases = [_]Case{
        // The router drops the frames after the refusal, also the response.
        .{
            .frames =
            \\{"jsonrpc":"2.0","method":"test/ok","params":{"progressToken":1}}
            \\{"jsonrpc":"2.0","method":"test/bad","params":{"progressToken":1}}
            \\{"jsonrpc":"2.0","method":"test/ok","params":{"progressToken":1}}
            \\{"jsonrpc":"2.0","id":1,"result":{}}
            \\
            ,
            .notifications = 1,
            .response_first = false,
        },
        // A response that arrived before the refusal comes first.
        .{
            .frames =
            \\{"jsonrpc":"2.0","id":1,"result":{}}
            \\{"jsonrpc":"2.0","method":"test/bad","params":{"progressToken":1}}
            \\
            ,
            .notifications = 0,
            .response_first = true,
        },
    };
    for (cases) |case| {
        var router: Router = .init(io, gpa, 64);
        defer router.deinit();
        var other: Router.Pending = .{ .id = .{ .integer = 2 } };
        defer other.deinit(gpa);
        var sink: InlineSink = .{ .other = &other, .refuse = "test/bad" };
        var cancel: Transport.CancelToken = .{};
        var ex = sink.exchange(.{ .integer = 1 }, &cancel);
        var p: Router.Pending = .{ .id = .{ .integer = 1 }, .inline_exchange = &ex };
        defer p.deinit(gpa);
        try router.register(&p);
        defer router.unregister(&p);
        var in: Io.Reader = .fixed(case.frames);
        router.readUntilEof(&in, 1024, null, null);

        try std.testing.expectEqual(case.notifications, sink.notifications);
        if (case.response_first) {
            const response = (try router.takeFrame(&p)).?;
            defer gpa.free(response);
            try std.testing.expect(frameIsResponse(response));
        }
        try std.testing.expectError(error.InvalidFrame, router.takeFrame(&p));
        try std.testing.expectError(error.InvalidFrame, router.takeFrame(&p));
    }
}

/// A sink that blocks until the test releases it.
const BlockingSink = struct {
    entered: Io.Event = .unset,
    release: Io.Event = .unset,

    fn onFrame(ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void {
        _ = frame;
        const self: *BlockingSink = @ptrCast(@alignCast(ptr));
        self.entered.set(io);
        self.release.waitUncancelable(io);
    }
};

fn readFixed(router: *Router, in: *Io.Reader) void {
    router.readUntilEof(in, 1024, null, null);
}

fn unregisterAndMark(router: *Router, p: *Router.Pending, done: *std.atomic.Value(bool)) void {
    router.unregister(p);
    done.store(true, .release);
}

test "unregister waits until the inline sink returns" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var router: Router = .init(io, gpa, 64);
    defer router.deinit();
    var sink: BlockingSink = .{};
    var cancel: Transport.CancelToken = .{};
    var ex: Transport.Exchange = .{
        .frame = "",
        .id = .{ .integer = 1 },
        .method = "tools/call",
        .params = null,
        .sink = .{ .ptr = &sink, .on_frame = BlockingSink.onFrame },
        .cancel = &cancel,
        .inline_notifications = true,
    };
    var p: Router.Pending = .{ .id = .{ .integer = 1 }, .inline_exchange = &ex };
    defer p.deinit(gpa);
    try router.register(&p);
    var in: Io.Reader = .fixed("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":1,\"progress\":1}}\n");
    var reader = io.concurrent(readFixed, .{ &router, &in }) catch |e| {
        router.unregister(&p);
        return e;
    };
    sink.entered.waitUncancelable(io);

    var done: std.atomic.Value(bool) = .init(false);
    var unregistering = io.concurrent(unregisterAndMark, .{ &router, &p, &done }) catch |e| {
        sink.release.set(io);
        reader.await(io);
        router.unregister(&p);
        return e;
    };
    // The sink still runs, thus the request cannot end.
    io.sleep(.fromMilliseconds(20), .awake) catch {};
    const ended_early = done.load(.acquire);
    sink.release.set(io);
    unregistering.await(io);
    reader.await(io);
    try std.testing.expect(!ended_early);
    try std.testing.expect(done.load(.acquire));
}
