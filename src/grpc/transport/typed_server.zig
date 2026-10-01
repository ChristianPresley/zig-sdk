//! The server side of the typed binding: the unary RPCs of `model_context_protocol.Mcp`. Each
//! RPC carries one MCP request. The server converts the request message into the JSON-RPC
//! request of the MCP method and runs it through the same server engine as the tunnel. Then
//! it converts the result into the response message.
//!
//! - A JSON-RPC error ends the call with headers only: `grpc-status`, `grpc-message`,
//!   `mcp-error-code` and, when it is small, `mcp-error-bin`.
//! - Notifications related to the request, for example progress, have no place in a unary
//!   response. The server drops them.
//! - A list result in pages becomes one response: the server follows `nextCursor` and merges
//!   the pages, because the messages have no cursor.
//! - A result that the messages cannot carry ends with `INTERNAL` and the code `-32603`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("mcp");
const Transport = mcp.transport.Transport;
const jsonrpc = mcp.jsonrpc;
const errors = mcp.protocol.errors;
const version = mcp.protocol.version;
const meta = mcp.protocol.meta;
const envelope = mcp.transport.envelope;
const resource_server = mcp.auth.resource_server;
const Connection = @import("../http2/Connection.zig");
const Stream = Connection.Stream;
const Header = Connection.Header;
const lpm = @import("../grpc/lpm.zig");
const status = @import("../grpc/status.zig");
const timeout = @import("../grpc/timeout.zig");
const grpc_server = @import("grpc_server.zig");
const service = @import("../typed/service.zig");
const convert = @import("../typed/convert.zig");

const log = std.log.scoped(.mcp_grpc);

/// The most pages that the server merges into one list response. A list with more pages ends
/// with `INTERNAL`, because the rest of the list has no place in the response.
pub const max_list_pages = 1024;

/// The JSON-RPC ids of the requests that the typed binding gives to the server engine.
var next_id: std.atomic.Value(i64) = .init(1);

/// Serve one call of `rpc`. The caller checked the method, the content type, the encoding and
/// the bearer token.
pub fn handleCall(self: *grpc_server.Server, stream: *Stream, arena: Allocator, headers: []const Header, rpc: service.Rpc, principal: ?*resource_server.Principal) !void {
    const io = self.io;
    const gpa = self.gpa;
    var deadline: ?Io.Duration = null;
    if (Connection.findHeader(headers, "grpc-timeout")) |t| {
        deadline = timeout.parse(t) catch return grpc_server.trailersOnly(stream, arena, .invalid_argument, "Invalid grpc-timeout", null, null);
    }

    // The one request message.
    const payload = lpm.read(stream, gpa, self.options.max_message_bytes) catch |e| switch (e) {
        error.MessageTooLarge => return grpc_server.trailersOnly(stream, arena, .resource_exhausted, "Message too large", null, null),
        error.Compressed => return grpc_server.trailersOnly(stream, arena, .unimplemented, "Compression is not supported", null, null),
        error.Truncated => return grpc_server.trailersOnly(stream, arena, .invalid_argument, "Truncated message", null, null),
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    } orelse return grpc_server.trailersOnly(stream, arena, .invalid_argument, "The call carried no message", null, null);
    // The params point into the payload.
    defer gpa.free(payload);

    var cx: convert.Context = .{ .arena = arena, .limits = self.options.typed_limits };
    var params = convert.decodeRequest(&cx, rpc, payload) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Invalid, error.Unexpressible => return rpcError(stream, arena, errors.invalidParams(cx.reason)),
        else => return rpcError(stream, arena, errors.parseError(try std.fmt.allocPrint(arena, "The message is not a valid {s}: {t}", .{ requestName(rpc), e }))),
    };

    // The routing metadata must agree with the message, as `mcp-name` on the tunnel.
    if (rpc.routeHeader()) |name| {
        const expected: ?[]const u8 = if (convert.route(rpc, params)) |r| r.value else null;
        for (headers) |h| {
            if (!std.mem.eql(u8, h.name, name)) continue;
            if (expected == null or !std.mem.eql(u8, h.value, expected.?)) {
                const message = try std.fmt.allocPrint(arena, "Header mismatch: {s} value '{s}' does not match the message value '{s}'", .{ name, h.value, expected orelse "" });
                return rpcError(stream, arena, errors.headerMismatch(message));
            }
        }
    }
    if (try completeMeta(arena, &params, Connection.findHeader(headers, envelope.header_protocol_version))) |message| {
        return rpcError(stream, arena, errors.headerMismatch(message));
    }

    var token: Transport.CancelToken = .{};
    var watcher: ?Io.Future(void) = io.concurrent(watchCancel, .{ stream, &token, io }) catch null;
    defer if (watcher) |*w| {
        _ = w.cancel(io);
    };
    var deadline_hit: std.atomic.Value(bool) = .init(false);
    var deadline_future: ?Io.Future(void) = null;
    if (deadline) |d| deadline_future = io.concurrent(deadlineTask, .{ io, d, &token, &deadline_hit }) catch null;
    defer if (deadline_future) |*f| {
        _ = f.cancel(io);
    };

    const outcome = try run(self, arena, rpc, params, &token, principal);
    const result = switch (outcome) {
        .result => |r| r,
        .rpc_error => |e| return rpcError(stream, arena, e),
        .cancelled => {
            const code: status.Code = if (deadline_hit.load(.acquire)) .deadline_exceeded else .cancelled;
            return grpc_server.trailersOnly(stream, arena, code, "The request was cancelled", null, null);
        },
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    convert.encodeResult(&cx, gpa, &out, rpc, result) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unexpressible, error.Invalid => {
            log.warn("the typed binding cannot express the {s} result: {s}", .{ rpc.method(), cx.reason });
            const message = try std.fmt.allocPrint(arena, "The typed gRPC binding cannot express {s}", .{cx.reason});
            return rpcError(stream, arena, errors.internalError(message));
        },
    };
    stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = grpc_server.content_type } }, false) catch return;
    lpm.write(stream, gpa, out.items, false) catch return;
    stream.sendHeaders(&.{.{ .name = "grpc-status", .value = status.Code.ok.wire() }}, true) catch return;
}

fn requestName(rpc: service.Rpc) []const u8 {
    return switch (rpc) {
        .complete => "CompletionRequest",
        inline else => |r| comptime r.rpcName() ++ "Request",
    };
}

/// Add the `_meta` keys that the server engine needs and that a client of the typed binding
/// does not always send. The protocol version comes from `mcp-protocol-version`, else it is
/// the version of this SDK. The client capabilities are empty. Returns a mismatch message
/// when the metadata and `_meta` name different versions.
fn completeMeta(arena: Allocator, params: *Value, header: ?[]const u8) Allocator.Error!?[]const u8 {
    const object = &params.object;
    if (object.getPtr("_meta") == null) try object.put(arena, "_meta", .{ .object = .empty });
    const m = &object.getPtr("_meta").?.object;
    if (m.get(meta.key_protocol_version)) |pv| {
        if (header) |h| if (pv != .string or !std.mem.eql(u8, h, pv.string)) {
            const body = if (pv == .string) pv.string else "?";
            return try std.fmt.allocPrint(arena, "Header mismatch: mcp-protocol-version value '{s}' does not match the _meta value '{s}'", .{ h, body });
        };
    } else {
        try m.put(arena, meta.key_protocol_version, .{ .string = header orelse version.version });
    }
    if (m.get(meta.key_client_capabilities) == null) try m.put(arena, meta.key_client_capabilities, .{ .object = .empty });
    return null;
}

const Outcome = union(enum) {
    result: Value,
    rpc_error: errors.RpcError,
    cancelled,
};

/// Run the request. A list result with `nextCursor` gets the next pages.
fn run(self: *grpc_server.Server, arena: Allocator, rpc: service.Rpc, params: Value, token: *Transport.CancelToken, principal: ?*resource_server.Principal) !Outcome {
    const first = try runOnce(self, arena, rpc.method(), params, token, principal);
    const key = rpc.listKey() orelse return first;
    var merged = switch (first) {
        .result => |r| r,
        else => return first,
    };
    if (merged != .object) return first;
    var pages: u32 = 1;
    while (merged.object.get("nextCursor")) |next| {
        if (next != .string or next.string.len == 0) break;
        // The cursor stays in the result, and the conversion refuses it.
        if (pages >= max_list_pages) return .{ .result = merged };
        if (token.isCancelled()) return .cancelled;
        var page_params: std.json.ObjectMap = .empty;
        var it = params.object.iterator();
        while (it.next()) |kv| try page_params.put(arena, kv.key_ptr.*, kv.value_ptr.*);
        try page_params.put(arena, "cursor", next);
        const page = switch (try runOnce(self, arena, rpc.method(), .{ .object = page_params }, token, principal)) {
            .result => |r| r,
            else => |other| return other,
        };
        pages += 1;
        if (page != .object) return .{ .rpc_error = errors.internalError("A page of the list is not an object") };
        const items = page.object.get(key) orelse Value.null;
        const target = merged.object.getPtr(key);
        if (items == .array and target != null and target.?.* == .array) try target.?.array.appendSlice(items.array.items);
        if (page.object.get("nextCursor")) |n| {
            try merged.object.put(arena, "nextCursor", n);
        } else {
            _ = merged.object.orderedRemove("nextCursor");
        }
    }
    if (merged.object.get("nextCursor")) |n| if (n == .string and n.string.len == 0) {
        _ = merged.object.orderedRemove("nextCursor");
    };
    return .{ .result = merged };
}

/// Run one JSON-RPC request through the server engine.
fn runOnce(self: *grpc_server.Server, arena: Allocator, method: []const u8, params: Value, token: *Transport.CancelToken, principal: ?*resource_server.Principal) !Outcome {
    if (token.isCancelled()) return .cancelled;
    var capture: Capture = .{ .arena = arena };
    self.server.handle(self.io, .{
        .kind = .grpc,
        .arena = arena,
        .message = .{ .request = .{ .id = .{ .integer = next_id.fetchAdd(1, .monotonic) }, .method = method, .params = params } },
        .responder = .{ .ptr = &capture, .vtable = &capture_vtable },
        .cancel = token,
        .context = principal,
    });
    const frame = capture.frame orelse return .cancelled;
    const msg = jsonrpc.Message.parse(arena, frame) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .rpc_error = errors.internalError("The server engine wrote a response that is not JSON-RPC") },
    };
    return switch (msg) {
        .response => |r| .{ .result = r.result },
        .error_response => |e| .{ .rpc_error = .{ .code = e.code, .message = e.message, .data = e.data } },
        else => .{ .rpc_error = errors.internalError("The server engine wrote no response") },
    };
}

/// The responder of one engine call: it keeps the final frame.
const Capture = struct {
    arena: Allocator,
    frame: ?[]const u8 = null,
};

const capture_vtable: Transport.Responder.VTable = .{
    .notify = captureNotify,
    .finish = captureFinish,
    .abort = captureAbort,
};

/// A unary response has no place for a notification related to the request.
fn captureNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    _ = ptr;
    _ = io;
    _ = frame;
}

fn captureFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    _ = io;
    const c: *Capture = @ptrCast(@alignCast(ptr));
    if (c.frame != null) return error.Closed;
    c.frame = try c.arena.dupe(u8, frame);
}

fn captureAbort(ptr: *anyopaque, io: Io) void {
    _ = ptr;
    _ = io;
}

/// Cancel the request when the client resets the stream or the connection goes away.
fn watchCancel(stream: *Stream, token: *Transport.CancelToken, io: Io) void {
    stream.waitCancelled() catch return;
    token.cancel(io, "stream reset");
}

fn deadlineTask(io: Io, duration: Io.Duration, token: *Transport.CancelToken, hit: *std.atomic.Value(bool)) void {
    io.sleep(duration, .awake) catch return;
    hit.store(true, .release);
    token.cancel(io, "deadline exceeded");
}

/// End the call with a JSON-RPC error in headers only. The status follows
/// `service.statusForCode`.
pub fn rpcError(stream: *Stream, arena: Allocator, err: errors.RpcError) !void {
    var list: std.ArrayList(Header) = .empty;
    try list.append(arena, .{ .name = ":status", .value = "200" });
    try list.append(arena, .{ .name = "content-type", .value = grpc_server.content_type });
    try list.append(arena, .{ .name = "grpc-status", .value = service.statusForCode(err.code).wire() });
    try list.append(arena, .{ .name = "grpc-message", .value = try status.encodeMessage(arena, service.shorten(err.message, service.max_error_message_bytes)) });
    try list.append(arena, .{ .name = service.header_error_code, .value = try std.fmt.allocPrint(arena, "{d}", .{err.code}) });
    var aw: Io.Writer.Allocating = .init(arena);
    jsonrpc.message.writeErrorResponse(&aw.writer, null, err.toWire()) catch return error.OutOfMemory;
    const encoder = std.base64.standard.Encoder;
    const size = encoder.calcSize(aw.written().len);
    if (size <= service.max_error_bin_bytes) {
        const out = try arena.alloc(u8, size);
        try list.append(arena, .{ .name = service.header_error_bin, .value = encoder.encode(out, aw.written()) });
    }
    try stream.sendHeaders(list.items, true);
}
