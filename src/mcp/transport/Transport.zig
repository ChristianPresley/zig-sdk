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
    event: Io.Event = .unset,
    reason: ?[]const u8 = null,

    pub fn isCancelled(self: *const CancelToken) bool {
        return self.flag.load(.acquire);
    }

    /// Mark the request as canceled and wake all tasks that wait on the event.
    pub fn cancel(self: *CancelToken, io: Io, reason: ?[]const u8) void {
        self.reason = reason;
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
/// `notifications/cancelled` exists only on stdio and on the Unix socket).
pub const Kind = enum { stdio, memory, streamable_http, grpc, unix_socket };

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
    };

    pub fn kind(self: ClientTransport) Kind {
        return self.vtable.kind;
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
    /// Set by HTTP transports: the status of the response.
    http_status: u16 = 0,

    pub const Sink = struct {
        ptr: *anyopaque,
        on_frame: *const fn (ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void,

        pub fn deliver(self: Sink, io: Io, frame: []const u8) anyerror!void {
            return self.on_frame(self.ptr, io, frame);
        }
    };
};

test "cancel token" {
    var token: CancelToken = .{};
    try std.testing.expect(!token.isCancelled());
    try token.check();
    token.cancel(std.testing.io, "user");
    try std.testing.expect(token.isCancelled());
    try std.testing.expectError(error.Canceled, token.check());
    try token.wait(std.testing.io);
}
