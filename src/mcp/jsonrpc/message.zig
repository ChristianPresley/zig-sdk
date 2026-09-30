//! Parse and build JSON-RPC 2.0 messages.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const RequestId = @import("id.zig").RequestId;
const types = @import("../protocol/types.zig");

pub const jsonrpc_version = "2.0";

/// A parsed inbound message. All slices point into the arena that parsed it.
pub const Message = union(enum) {
    request: Request,
    notification: Notification,
    response: Response,
    error_response: ErrorResponse,

    pub const Request = struct {
        id: RequestId,
        method: []const u8,
        params: ?Value,
    };
    pub const Notification = struct {
        method: []const u8,
        params: ?Value,
    };
    pub const Response = struct {
        id: RequestId,
        result: Value,
    };
    pub const ErrorResponse = struct {
        id: ?RequestId,
        code: i64,
        message: []const u8,
        data: ?Value,
    };

    pub const ParseError = error{
        /// The text is not valid JSON.
        Syntax,
        /// The text is valid JSON but not a JSON-RPC 2.0 message.
        Invalid,
        /// The message has an id that is not a string or an integer.
        InvalidId,
        OutOfMemory,
    };

    /// Parse one message. `text` must be a single JSON value (no batches).
    pub fn parse(arena: Allocator, text: []const u8) ParseError!Message {
        const tree = json.parseTree(arena, text) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Syntax,
        };
        return fromValue(arena, tree);
    }

    pub fn fromValue(arena: Allocator, tree: Value) ParseError!Message {
        if (tree != .object) return error.Invalid;
        const obj = tree.object;
        const version = obj.get("jsonrpc") orelse return error.Invalid;
        if (version != .string or !std.mem.eql(u8, version.string, jsonrpc_version)) return error.Invalid;

        const id_value = obj.get("id");
        const method_value = obj.get("method");
        const result_value = obj.get("result");
        const error_value = obj.get("error");

        if (method_value) |mv| {
            if (mv != .string) return error.Invalid;
            if (result_value != null or error_value != null) return error.Invalid;
            const params = obj.get("params");
            if (params) |p| if (p != .object and p != .null) return error.Invalid;
            const clean_params: ?Value = if (params) |p| (if (p == .null) null else p) else null;
            if (id_value) |iv| {
                if (iv == .null) return error.InvalidId;
                const id = RequestId.fromValue(arena, iv) orelse return error.InvalidId;
                return .{ .request = .{ .id = id, .method = mv.string, .params = clean_params } };
            }
            return .{ .notification = .{ .method = mv.string, .params = clean_params } };
        }
        if (error_value) |ev| {
            if (result_value != null) return error.Invalid;
            if (ev != .object) return error.Invalid;
            const code = ev.object.get("code") orelse return error.Invalid;
            if (code != .integer) return error.Invalid;
            const msg = ev.object.get("message") orelse return error.Invalid;
            if (msg != .string) return error.Invalid;
            var id: ?RequestId = null;
            if (id_value) |iv| {
                if (iv != .null) id = RequestId.fromValue(arena, iv) orelse return error.InvalidId;
            }
            return .{ .error_response = .{ .id = id, .code = code.integer, .message = msg.string, .data = ev.object.get("data") } };
        }
        if (result_value) |rv| {
            const iv = id_value orelse return error.Invalid;
            if (iv == .null) return error.InvalidId;
            const id = RequestId.fromValue(arena, iv) orelse return error.InvalidId;
            return .{ .response = .{ .id = id, .result = rv } };
        }
        return error.Invalid;
    }

    pub fn method(self: Message) ?[]const u8 {
        return switch (self) {
            .request => |r| r.method,
            .notification => |n| n.method,
            else => null,
        };
    }
};

/// Outbound envelopes. These structs serialize with the wire options.
pub fn OutRequest(comptime P: type) type {
    return struct {
        jsonrpc: []const u8 = jsonrpc_version,
        id: RequestId,
        method: []const u8,
        params: P,
    };
}

pub fn OutNotification(comptime P: type) type {
    return struct {
        jsonrpc: []const u8 = jsonrpc_version,
        method: []const u8,
        params: P,
    };
}

pub fn OutResponse(comptime R: type) type {
    return struct {
        jsonrpc: []const u8 = jsonrpc_version,
        id: RequestId,
        result: R,
    };
}

pub const OutErrorResponse = struct {
    jsonrpc: []const u8 = jsonrpc_version,
    id: ?RequestId,
    @"error": types.Error,

    pub fn jsonStringify(self: OutErrorResponse, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("jsonrpc");
        try jws.write(self.jsonrpc);
        try jws.objectField("id");
        if (self.id) |id| try jws.write(id) else try jws.write(null);
        try jws.objectField("error");
        try jws.write(self.@"error");
        try jws.endObject();
    }
};

/// Serialize a request envelope.
pub fn writeRequest(writer: *std.Io.Writer, id: RequestId, method_name: []const u8, params: anytype) std.Io.Writer.Error!void {
    try json.write(OutRequest(@TypeOf(params)){ .id = id, .method = method_name, .params = params }, writer);
}

/// Serialize a response envelope around `result`.
pub fn writeResponse(writer: *std.Io.Writer, id: RequestId, result: anytype) std.Io.Writer.Error!void {
    try json.write(OutResponse(@TypeOf(result)){ .id = id, .result = result }, writer);
}

/// Serialize an error envelope. `id` is null only when the request id could not be read.
pub fn writeErrorResponse(writer: *std.Io.Writer, id: ?RequestId, err: types.Error) std.Io.Writer.Error!void {
    try json.write(OutErrorResponse{ .id = id, .@"error" = err }, writer);
}

/// Serialize a notification envelope.
pub fn writeNotification(writer: *std.Io.Writer, method_name: []const u8, params: anytype) std.Io.Writer.Error!void {
    try json.write(OutNotification(@TypeOf(params)){ .method = method_name, .params = params }, writer);
}

test "parse request, notification, response, error" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const req = try Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\",\"params\":{\"_meta\":{}}}");
    try std.testing.expect(req == .request);
    try std.testing.expectEqual(@as(i64, 7), req.request.id.integer);
    try std.testing.expectEqualStrings("tools/list", req.request.method);

    const note = try Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}");
    try std.testing.expect(note == .notification);

    const resp = try Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"result\":{\"resultType\":\"complete\"}}");
    try std.testing.expect(resp == .response);

    const err = try Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"x\"}}");
    try std.testing.expect(err == .error_response);
    try std.testing.expect(err.error_response.id == null);

    try std.testing.expectError(error.Syntax, Message.parse(arena, "{"));
    try std.testing.expectError(error.Invalid, Message.parse(arena, "[]"));
    try std.testing.expectError(error.Invalid, Message.parse(arena, "{\"jsonrpc\":\"1.0\",\"method\":\"x\"}"));
    try std.testing.expectError(error.InvalidId, Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"x\"}"));
    try std.testing.expectError(error.InvalidId, Message.parse(arena, "{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"x\"}"));
}

test "write error response with null id" {
    const gpa = std.testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try writeErrorResponse(&aw.writer, null, .{ .code = -32700, .message = "Parse error" });
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}", aw.written());
}
