//! Interfaces between the protocol engine and the transports.
//!
//! A transport turns bytes into `Inbound` messages and gives each request a `Responder`.
//! A frame that a responder receives is a serialized JSON-RPC message without a trailing
//! newline. The engine never keeps a pointer into a frame after `finish` or `abort`.
const std = @import("std");
const Io = std.Io;
const jsonrpc = @import("../jsonrpc.zig");

/// Cooperative cancellation shared between a transport and the request handler.
pub const CancelToken = struct {
    flag: std.atomic.Value(bool) = .init(false),
    /// Set by the first call to `cancel` or `shutdown`. The later calls have no effect.
    claimed: std.atomic.Value(bool) = .init(false),
    event: Io.Event = .unset,
    reason: ?[]const u8 = null,
    /// True when the server itself ended the request at shutdown, not the peer. The reason
    /// text does not set this flag: a peer can send any reason text.
    server_shutdown: bool = false,

    pub fn isCancelled(self: *const CancelToken) bool {
        return self.flag.load(.acquire);
    }

    /// True when the peer, the transport or a deadline canceled the request. A request that
    /// the server ended at shutdown gives false.
    pub fn isCancelledByPeer(self: *const CancelToken) bool {
        return self.isCancelled() and !self.server_shutdown;
    }

    /// Mark the request as canceled and wake all tasks that wait on the event. Only the first
    /// cancellation counts.
    pub fn cancel(self: *CancelToken, io: Io, reason: ?[]const u8) void {
        self.fire(io, reason, false);
    }

    /// Mark the request as ended by the server at shutdown. A listen stream then ends with its
    /// result. Only the first cancellation counts.
    pub fn shutdown(self: *CancelToken, io: Io, reason: ?[]const u8) void {
        self.fire(io, reason, true);
    }

    fn fire(self: *CancelToken, io: Io, reason: ?[]const u8, by_server: bool) void {
        if (self.claimed.swap(true, .acq_rel)) return;
        self.reason = reason;
        self.server_shutdown = by_server;
        self.flag.store(true, .release);
        self.event.set(io);
    }

    pub fn check(self: *const CancelToken) error{Canceled}!void {
        if (self.isCancelled()) return error.Canceled;
    }

    /// Wait until a cancellation of the request.
    pub fn wait(self: *CancelToken, io: Io) Io.Cancelable!void {
        try self.event.wait(io);
    }
};

const cancel_log = std.log.scoped(.mcp_cancel);

/// Log a cancellation that the peer sent, with its reason, at the debug level of the scope
/// `mcp_cancel`. The receiver of `notifications/cancelled` calls this function.
pub fn logCancellation(id: jsonrpc.RequestId, reason: ?[]const u8) void {
    cancel_log.debug("{f}", .{CancellationNote{ .id = id, .reason = reason }});
}

/// The text of the log line of a cancellation.
pub const CancellationNote = struct {
    id: jsonrpc.RequestId,
    reason: ?[]const u8,

    pub fn format(self: CancellationNote, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("the peer canceled request {f}: {s}", .{ self.id, self.reason orelse "no reason given" });
    }
};

pub const SendError = error{
    /// The peer is gone or the stream was closed.
    Closed,
    WriteFailed,
    OutOfMemory,
} || Io.Cancelable;

/// The channel that carries messages related to one request: request-scoped notifications
/// and exactly one final response.
pub const Responder = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Send a notification related to the request (progress, logging, subscription events).
        notify: *const fn (ptr: *anyopaque, io: Io, frame: []const u8) SendError!void,
        /// Send the final response (result or error) and close the request stream.
        finish: *const fn (ptr: *anyopaque, io: Io, frame: []const u8) SendError!void,
        /// Close the request stream without a response (after a cancellation).
        abort: *const fn (ptr: *anyopaque, io: Io) void,
    };

    pub fn notify(self: Responder, io: Io, frame: []const u8) SendError!void {
        return self.vtable.notify(self.ptr, io, frame);
    }

    pub fn finish(self: Responder, io: Io, frame: []const u8) SendError!void {
        return self.vtable.finish(self.ptr, io, frame);
    }

    pub fn abort(self: Responder, io: Io) void {
        self.vtable.abort(self.ptr, io);
    }
};

/// Which binding delivered the request. Some rules are transport specific (for example
/// `notifications/cancelled` exists only on stdio, on the Unix socket and on WebSocket).
pub const Kind = enum { stdio, memory, streamable_http, grpc, unix_socket, websocket };

/// Where a request comes from, apart from its authorization principal. The rate limits of the
/// server use it as the caller of a request without a principal.
pub const Peer = union(enum) {
    /// The transport gives no data. All such requests share one caller.
    unknown,
    /// The connection of the request, on stdio and on a Unix socket. `nextConnectionId`
    /// gives the value.
    connection: u64,
    /// The IP address of the client, on HTTP, gRPC and WebSocket. The port does not count.
    address: Io.net.IpAddress,
};

var connection_ids: std.atomic.Value(u64) = .init(1);

/// A connection identifier that no other connection of the process has.
pub fn nextConnectionId() u64 {
    return connection_ids.fetchAdd(1, .monotonic);
}

/// One inbound message with everything a handler needs. The transport owns `arena` and frees
/// it after the engine returns.
pub const Inbound = struct {
    kind: Kind,
    arena: std.mem.Allocator,
    message: jsonrpc.Message,
    responder: Responder,
    cancel: *CancelToken,
    /// Transport-specific data (for example HTTP authentication) for the handler.
    context: ?*anyopaque = null,
    /// The source of the request, for the rate limits of the server.
    peer: Peer = .unknown,
};

/// A client transport: sends one request and streams its frames back.
pub const ClientTransport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        kind: Kind,
        /// Send the request and deliver every frame of its stream to the sink. The last frame
        /// is the response. Returns after the response, a cancellation or a stream failure.
        exchange: *const fn (ptr: *anyopaque, io: Io, ex: *Exchange) ExchangeError!void,
        /// Send a notification. The peer sends nothing back.
        notify: *const fn (ptr: *anyopaque, io: Io, frame: []const u8) SendError!void,
        /// The credential that the next request carries, for example the bearer token, in
        /// `arena`. Null when the transport sends no credential. The client uses it to keep
        /// the private cache entries of each authorization context apart.
        credential: ?*const fn (ptr: *anyopaque, arena: std.mem.Allocator) std.mem.Allocator.Error!?[]const u8 = null,
    };

    pub fn kind(self: ClientTransport) Kind {
        return self.vtable.kind;
    }

    /// The credential that the next request carries, or null. See `VTable.credential`.
    pub fn credential(self: ClientTransport, arena: std.mem.Allocator) std.mem.Allocator.Error!?[]const u8 {
        const f = self.vtable.credential orelse return null;
        return f(self.ptr, arena);
    }

    pub fn exchange(self: ClientTransport, io: Io, ex: *Exchange) ExchangeError!void {
        return self.vtable.exchange(self.ptr, io, ex);
    }

    pub fn notify(self: ClientTransport, io: Io, frame: []const u8) SendError!void {
        return self.vtable.notify(self.ptr, io, frame);
    }
};

pub const ExchangeError = error{
    Closed,
    WriteFailed,
    ReadFailed,
    OutOfMemory,
    /// The deadline passed before the response arrived.
    Timeout,
    /// The stream carried something that is not a JSON-RPC message for this request.
    InvalidFrame,
    /// The HTTP status carried no JSON-RPC body (for example 404 for a wrong path).
    HttpStatus,
    /// The transport cannot send the request. For example, an argument for a mirrored
    /// header is an integer outside the safe range of JavaScript.
    InvalidRequest,
} || Io.Cancelable;

/// One request in flight on a client transport.
pub const Exchange = struct {
    /// The serialized request frame.
    frame: []const u8,
    id: jsonrpc.RequestId,
    method: []const u8,
    /// The request params, for transports that mirror them into headers.
    params: ?std.json.Value,
    sink: Sink,
    cancel: *CancelToken,
    /// Absolute deadline, or `.none`.
    timeout: Io.Timeout = .none,
    /// Absolute deadline of the first frame, or `.none`. The client sets it for a
    /// `subscriptions/listen` stream, because the acknowledgment is the first message of the
    /// stream. After the first frame, only `timeout` applies.
    first_frame_timeout: Io.Timeout = .none,
    /// Set by `deliver` at the first frame.
    got_frame: std.atomic.Value(bool) = .init(false),
    /// Set by HTTP transports: the status of the response.
    http_status: u16 = 0,
    /// Give each notification of this request to the sink at once on the task that reads the
    /// connection. That task routes the next frame only after the sink returns. A transport
    /// with one reader task for many requests obeys it (stdio, Unix socket and WebSocket).
    /// A transport that gives each frame to the sink on the task that reads or writes it
    /// ignores the option.
    ///
    /// The sink then gets the notifications on the reader task and the response on the task
    /// of the request. The two tasks can call the sink at the same time. The reader task must
    /// not use the exchange after `exchange` returns.
    inline_notifications: bool = false,

    /// Give one frame to the sink. Transports call this function, not `Sink.deliver`, so that
    /// the first frame stops `first_frame_timeout`.
    pub fn deliver(ex: *Exchange, io: Io, frame: []const u8) anyerror!void {
        ex.got_frame.store(true, .release);
        return ex.sink.deliver(io, frame);
    }

    /// True when `timeout` passed, or when `first_frame_timeout` passed before the first
    /// frame. The transport then ends the exchange with `error.Timeout`.
    pub fn expired(ex: *const Exchange, io: Io) bool {
        if (passed(io, ex.timeout)) return true;
        return !ex.got_frame.load(.acquire) and passed(io, ex.first_frame_timeout);
    }

    fn passed(io: Io, timeout: Io.Timeout) bool {
        const d = timeout.toTimestamp(io) orelse return false;
        return Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw.nanoseconds <= 0;
    }

    pub const Sink = struct {
        ptr: *anyopaque,
        on_frame: *const fn (ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void,

        pub fn deliver(self: Sink, io: Io, frame: []const u8) anyerror!void {
            return self.on_frame(self.ptr, io, frame);
        }
    };
};

test "each connection gets a new identifier" {
    const a = nextConnectionId();
    const b = nextConnectionId();
    try std.testing.expect(a != b);
}

test "cancel token" {
    var token: CancelToken = .{};
    try std.testing.expect(!token.isCancelled());
    try token.check();
    token.cancel(std.testing.io, "user");
    try std.testing.expect(token.isCancelled());
    try std.testing.expectError(error.Canceled, token.check());
    try token.wait(std.testing.io);
}

test "only the first cancellation counts, and only shutdown marks the server as the origin" {
    const io = std.testing.io;
    var by_peer: CancelToken = .{};
    by_peer.cancel(io, "server shutdown");
    by_peer.shutdown(io, "later");
    try std.testing.expect(by_peer.isCancelledByPeer());
    try std.testing.expect(!by_peer.server_shutdown);
    try std.testing.expectEqualStrings("server shutdown", by_peer.reason.?);

    var by_server: CancelToken = .{};
    by_server.shutdown(io, "server shutdown");
    by_server.cancel(io, "user");
    try std.testing.expect(by_server.isCancelled());
    try std.testing.expect(!by_server.isCancelledByPeer());
    try std.testing.expectEqualStrings("server shutdown", by_server.reason.?);
}

test "the log line of a cancellation has the id and the reason" {
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try w.print("{f}", .{CancellationNote{ .id = .{ .integer = 7 }, .reason = "user pressed stop" }});
    try std.testing.expectEqualStrings("the peer canceled request 7: user pressed stop", w.buffered());
    w = .fixed(&buf);
    try w.print("{f}", .{CancellationNote{ .id = .{ .string = "a" }, .reason = null }});
    try std.testing.expectEqualStrings("the peer canceled request \"a\": no reason given", w.buffered());
    // The call does not fail without a log function for the debug level.
    logCancellation(.{ .integer = 7 }, "user pressed stop");
}
