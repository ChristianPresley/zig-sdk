//! The client side of the typed binding: a channel that sends the eight MCP methods of
//! `model_context_protocol.Mcp` as unary RPCs. It uses the connection of a `Channel`, with
//! the same TLS, metadata and reconnect rules.
//!
//! - The channel converts the JSON-RPC params into the request message before it opens a
//!   stream. A part that the message cannot carry gives `error.InvalidRequest`, for example a
//!   cursor or an integer outside the range from -(2^53) to 2^53.
//! - It sends `mcp-protocol-version` and the routing metadata of the proto comments:
//!   `mcp_tool`, `mcp_prompt` and `mcp_resource`.
//! - It gives the response message to the client as a JSON-RPC response with the id of the
//!   request. An error status becomes a JSON-RPC error response, as in the reference
//!   transport.
//! - A method without an RPC, for example `server/discover`, gives `error.InvalidRequest`.
//!   With `fallback = .tunnel` it travels on the tunnel of the same connection instead.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("mcp");
const Transport = mcp.transport.Transport;
const envelope = mcp.transport.envelope;
const jsonrpc = mcp.jsonrpc;
const version = mcp.protocol.version;
const types = mcp.types;
const Connection = @import("../http2/Connection.zig");
const Header = Connection.Header;
const lpm = @import("../grpc/lpm.zig");
const status = @import("../grpc/status.zig");
const timeout = @import("../grpc/timeout.zig");
const codec = @import("../protobuf/codec.zig");
const grpc_client = @import("grpc_client.zig");
const grpc_server = @import("grpc_server.zig");
const service = @import("../typed/service.zig");
const convert = @import("../typed/convert.zig");

const log = std.log.scoped(.mcp_grpc_client);

/// What the channel does with a method that the typed service does not have.
pub const Fallback = enum {
    /// The request fails with `error.InvalidRequest`.
    none,
    /// The request travels on the tunnel `mcp.zig.transport.v1.Mcp/Call` of the same
    /// connection. Use it only with a server that serves both bindings, such as this SDK.
    tunnel,
};

pub const Options = struct {
    /// The connection: host, port, TLS, metadata and the largest response message.
    channel: grpc_client.Options,
    fallback: Fallback = .none,
    /// The nesting depth and the element count of a response message. Overflow: the call
    /// fails with `error.InvalidFrame`.
    limits: codec.Limits = .{},
};

pub const TypedChannel = struct {
    io: Io,
    gpa: Allocator,
    options: Options,
    /// The connection, and the tunnel for the fallback.
    channel: *grpc_client.Channel,

    pub fn init(io: Io, gpa: Allocator, options: Options) Allocator.Error!*TypedChannel {
        const self = try gpa.create(TypedChannel);
        errdefer gpa.destroy(self);
        const channel = try grpc_client.Channel.init(io, gpa, options.channel);
        self.* = .{ .io = io, .gpa = gpa, .options = options, .channel = channel };
        return self;
    }

    pub fn deinit(self: *TypedChannel) void {
        self.channel.deinit();
        self.gpa.destroy(self);
    }

    pub fn transport(self: *TypedChannel) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Connect now. Without this call, calls connect on demand.
    pub fn connect(self: *TypedChannel) grpc_client.ConnectError!void {
        return self.channel.connect();
    }

    /// End the connection gracefully.
    pub fn close(self: *TypedChannel) void {
        self.channel.close();
    }

    /// The negotiated application protocol of the current connection, when TLS is in use.
    pub fn alpn(self: *TypedChannel) ?[]const u8 {
        return self.channel.alpn();
    }

    const vtable: Transport.ClientTransport.VTable = .{
        .kind = .grpc,
        .exchange = exchange,
        .notify = notify,
        .credential = credential,
    };

    fn credential(ptr: *anyopaque, arena: Allocator) Allocator.Error!?[]const u8 {
        const self: *TypedChannel = @ptrCast(@alignCast(ptr));
        return self.channel.transport().credential(arena);
    }

    /// The typed service has no RPC for a notification.
    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        const self: *TypedChannel = @ptrCast(@alignCast(ptr));
        if (self.options.fallback == .tunnel) return self.channel.transport().notify(io, frame);
        log.warn("the typed gRPC binding has no RPC for a notification", .{});
        return error.WriteFailed;
    }

    const Task = struct {
        self: *TypedChannel,
        ex: *Transport.Exchange,
        rpc: service.Rpc,
        arena: Allocator,
        done: Io.Event = .unset,
        result: Transport.ExchangeError!void = {},

        fn run(t: *Task) void {
            t.result = t.self.perform(t.arena, t.ex, t.rpc);
            t.done.set(t.self.io);
        }
    };

    /// Run the call in a task so that cancellation and the deadline can interrupt it.
    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *TypedChannel = @ptrCast(@alignCast(ptr));
        const rpc = service.Rpc.fromMethod(ex.method) orelse {
            if (self.options.fallback == .tunnel) return self.channel.transport().exchange(io, ex);
            log.warn("the typed gRPC binding has no RPC for the method {s}", .{ex.method});
            return error.InvalidRequest;
        };
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        var task: Task = .{ .self = self, .ex = ex, .rpc = rpc, .arena = arena_state.allocator() };
        var future = io.concurrent(Task.run, .{&task}) catch return self.perform(task.arena, ex, rpc);
        const deadline = ex.timeout.toTimestamp(io);
        var stop: ?Transport.ExchangeError = null;
        while (true) {
            task.done.waitTimeout(io, .{ .duration = .{ .raw = self.options.channel.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => {
                    stop = error.Canceled;
                    break;
                },
            };
            if (task.done.isSet()) break;
            if (ex.cancel.isCancelled()) {
                stop = error.Canceled;
                break;
            }
            if (deadline) |d| if (Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw.nanoseconds <= 0) {
                stop = error.Timeout;
                break;
            };
        }
        if (stop) |err| {
            _ = future.cancel(io);
            return err;
        }
        future.await(io);
        return task.result;
    }

    fn perform(self: *TypedChannel, arena: Allocator, ex: *Transport.Exchange, rpc: service.Rpc) Transport.ExchangeError!void {
        const io = self.io;
        const params: Value = ex.params orelse .{ .object = .empty };
        // A part that the message cannot carry fails before a byte goes out.
        var cx: convert.Context = .{ .arena = arena, .limits = self.options.limits };
        var body: std.ArrayList(u8) = .empty;
        convert.encodeRequest(&cx, arena, &body, rpc, params) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unexpressible, error.Invalid => {
                log.warn("the typed gRPC binding cannot send {s}: {s}", .{ ex.method, cx.reason });
                return error.InvalidRequest;
            },
        };

        const link = self.channel.acquireLink() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            else => return error.WriteFailed,
        };
        const stream = link.h2.openStream() catch return error.Closed;
        defer stream.close();
        var remaining: ?Io.Duration = null;
        if (ex.timeout.toTimestamp(io)) |d| {
            const left = Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw;
            remaining = if (left.nanoseconds > 0) left else .{ .nanoseconds = 1 };
        }
        const headers = try self.callHeaders(arena, rpc, params, remaining);
        stream.sendHeaders(headers, false) catch |e| return mapStream(e);
        lpm.write(stream, self.gpa, body.items, true) catch |e| return mapStream(e);

        const response_headers = stream.waitHeaders() catch |e| return mapStream(e);
        const status_text = Connection.findHeader(response_headers, ":status") orelse "0";
        ex.http_status = std.fmt.parseInt(u16, status_text, 10) catch 0;
        if (ex.http_status != 200) return error.HttpStatus;
        if (Connection.findHeader(response_headers, "grpc-status")) |gs| {
            return finishError(io, arena, ex, response_headers, gs);
        }
        const payload = lpm.read(stream, self.gpa, self.options.channel.max_message_bytes) catch |e| switch (e) {
            error.Compressed, error.MessageTooLarge, error.Truncated => return error.InvalidFrame,
            else => |other| return mapStream(other),
        };
        defer if (payload) |p| self.gpa.free(p);
        if (payload != null) {
            // A unary response has exactly one message.
            const extra = lpm.read(stream, self.gpa, self.options.channel.max_message_bytes) catch |e| switch (e) {
                error.Compressed, error.MessageTooLarge, error.Truncated => return error.InvalidFrame,
                else => |other| return mapStream(other),
            };
            if (extra) |x| {
                self.gpa.free(x);
                return error.InvalidFrame;
            }
        }
        const trailers = stream.waitEnd() catch |e| return mapStream(e);
        const gs = Connection.findHeader(trailers, "grpc-status") orelse return error.InvalidFrame;
        const code = status.Code.fromWire(gs) orelse return error.InvalidFrame;
        if (code != .ok) return finishError(io, arena, ex, trailers, gs);
        const message = payload orelse return error.InvalidFrame;

        const result = convert.decodeResponse(&cx, rpc, message) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Invalid, error.Unexpressible => {
                log.warn("the {s} response of the typed gRPC binding is not valid: {s}", .{ ex.method, cx.reason });
                return error.InvalidFrame;
            },
            else => {
                log.warn("the {s} response of the typed gRPC binding is malformed: {t}", .{ ex.method, e });
                return error.InvalidFrame;
            },
        };
        var aw: Io.Writer.Allocating = .init(arena);
        jsonrpc.message.writeResponse(&aw.writer, ex.id, result) catch return error.OutOfMemory;
        ex.sink.deliver(io, aw.written()) catch return error.InvalidFrame;
    }

    /// The pseudo-headers and the metadata of one call.
    fn callHeaders(self: *TypedChannel, arena: Allocator, rpc: service.Rpc, params: Value, deadline: ?Io.Duration) Allocator.Error![]const Header {
        const options = self.options.channel;
        var headers: std.ArrayList(Header) = .empty;
        const authority = options.authority orelse try std.fmt.allocPrint(arena, "{s}:{d}", .{ options.host, options.port });
        try headers.appendSlice(arena, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = if (options.tls != null) "https" else "http" },
            .{ .name = ":path", .value = rpc.path() },
            .{ .name = ":authority", .value = authority },
            .{ .name = "content-type", .value = grpc_server.content_type },
            .{ .name = "te", .value = "trailers" },
            .{ .name = "user-agent", .value = "zig-sdk-mcp/" ++ version.version },
        });
        if (deadline) |d| {
            const buf = try arena.alloc(u8, 9);
            try headers.append(arena, .{ .name = "grpc-timeout", .value = timeout.format(buf[0..9], d) });
        }
        try headers.append(arena, .{ .name = envelope.header_protocol_version, .value = version.version });
        // A value with other bytes than visible ASCII and spaces does not go into the metadata.
        if (convert.route(rpc, params)) |r| if (r.value.len > 0 and envelope.isPlainHeaderValue(r.value)) {
            try headers.append(arena, .{ .name = r.header, .value = r.value });
        };
        for (options.extra_metadata) |h| try headers.append(arena, h);
        return headers.items;
    }
};

/// Interpret an error status. The JSON-RPC error comes from `mcp-error-bin`, else from
/// `mcp-error-code` and `grpc-message`, else from the status map of the reference transport.
/// The client gets it as a JSON-RPC error response with the id of the request.
fn finishError(io: Io, arena: Allocator, ex: *Transport.Exchange, trailers: []const Header, gs: []const u8) Transport.ExchangeError!void {
    const code = status.Code.fromWire(gs) orelse return error.InvalidFrame;
    if (code == .ok) return error.InvalidFrame;
    const message = if (Connection.findHeader(trailers, "grpc-message")) |m| try status.decodeMessage(arena, m) else "";
    log.debug("call ended with {t}: {s}", .{ code, message });
    var err: ?types.Error = null;
    if (Connection.findHeader(trailers, service.header_error_bin)) |bin| err = try errorFromBin(arena, bin);
    if (err == null) if (Connection.findHeader(trailers, service.header_error_code)) |c| {
        if (std.fmt.parseInt(i64, c, 10)) |n| {
            err = .{ .code = n, .message = message };
        } else |_| {}
    };
    if (err == null) if (service.codeForStatus(code)) |n| {
        err = .{ .code = n, .message = message };
    };
    if (err) |e| {
        var aw: Io.Writer.Allocating = .init(arena);
        jsonrpc.message.writeErrorResponse(&aw.writer, ex.id, e) catch return error.OutOfMemory;
        ex.sink.deliver(io, aw.written()) catch return error.InvalidFrame;
        return;
    }
    return switch (code) {
        .unavailable => error.Closed,
        .deadline_exceeded => error.Timeout,
        .cancelled => error.Canceled,
        .unauthenticated => {
            ex.http_status = 401;
            return error.HttpStatus;
        },
        .permission_denied => {
            ex.http_status = 403;
            return error.HttpStatus;
        },
        else => error.ReadFailed,
    };
}

/// The error object of a base64 JSON-RPC error response, or null when the value is not one.
fn errorFromBin(arena: Allocator, bin: []const u8) Allocator.Error!?types.Error {
    const decoder = std.base64.standard.Decoder;
    const len = decoder.calcSizeForSlice(bin) catch return null;
    const text = try arena.alloc(u8, len);
    decoder.decode(text, bin) catch return null;
    const msg = jsonrpc.Message.parse(arena, text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    return switch (msg) {
        .error_response => |r| .{ .code = r.code, .message = r.message, .data = r.data },
        else => null,
    };
}

fn mapStream(e: anyerror) Transport.ExchangeError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.Closed => error.Closed,
        error.WriteFailed => error.WriteFailed,
        else => error.ReadFailed,
    };
}
