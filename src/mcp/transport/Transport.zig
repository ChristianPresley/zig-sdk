//! Interfaces between the protocol engine and the transports.
//!
//! A transport turns bytes into `Inbound` messages and gives each request a `Responder`.
//! Frames handed to a responder are already serialized JSON-RPC messages without a trailing
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

    /// Mark the request cancelled and wake anyone waiting on the event.
    pub fn cancel(self: *CancelToken, io: Io, reason: ?[]const u8) void {
        self.reason = reason;
        self.flag.store(true, .release);
        self.event.set(io);
    }

    pub fn check(self: *const CancelToken) error{Canceled}!void {
        if (self.isCancelled()) return error.Canceled;
    }

    /// Wait until the request is cancelled.
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
        /// Close the request stream without a response (the request was cancelled).
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
/// `notifications/cancelled` exists only on stdio).
pub const Kind = enum { stdio, memory, streamable_http, grpc };

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

test "cancel token" {
    var token: CancelToken = .{};
    try std.testing.expect(!token.isCancelled());
    try token.check();
    token.cancel(std.testing.io, "user");
    try std.testing.expect(token.isCancelled());
    try std.testing.expectError(error.Canceled, token.check());
    try token.wait(std.testing.io);
}
