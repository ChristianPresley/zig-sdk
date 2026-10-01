//! JSON-RPC and MCP error codes and error-object constructors.
//!
//! SDK-local failures (timeouts, closed transports) are Zig errors and never wire codes.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const json = @import("../json.zig");

pub const Code = enum(i64) {
    parse_error = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,
    header_mismatch = -32020,
    missing_required_client_capability = -32021,
    unsupported_protocol_version = -32022,
    /// A request over a rate limit of the server. The specification defines no code for this
    /// condition. It recommends that a new code is outside the JSON-RPC range from -32768 to
    /// -32000, thus the SDK uses an application code.
    rate_limited = -31429,
    _,

    pub fn int(self: Code) i64 {
        return @intFromEnum(self);
    }

    /// Codes that this implementation must never emit: reserved codes from earlier revisions
    /// and undefined codes in the MCP-reserved range.
    pub fn isEmittable(code: i64) bool {
        if (code == -32002 or code == -32042) return false;
        if (code <= -32020 and code >= -32099) {
            return code == -32020 or code == -32021 or code == -32022;
        }
        return true;
    }
};

/// A wire error object. The arena of the message under construction owns all slices.
pub const RpcError = struct {
    code: i64,
    message: []const u8,
    data: ?std.json.Value = null,

    pub fn toWire(self: RpcError) types.Error {
        return .{ .code = self.code, .message = self.message, .data = self.data };
    }
};

pub fn parseError(message: []const u8) RpcError {
    return .{ .code = Code.parse_error.int(), .message = message };
}

pub fn invalidRequest(message: []const u8) RpcError {
    return .{ .code = Code.invalid_request.int(), .message = message };
}

pub fn methodNotFound(message: []const u8) RpcError {
    return .{ .code = Code.method_not_found.int(), .message = message };
}

pub fn invalidParams(message: []const u8) RpcError {
    return .{ .code = Code.invalid_params.int(), .message = message };
}

pub fn internalError(message: []const u8) RpcError {
    return .{ .code = Code.internal_error.int(), .message = message };
}

pub fn headerMismatch(message: []const u8) RpcError {
    return .{ .code = Code.header_mismatch.int(), .message = message };
}

/// Builds `-32022` with the mandated `data.supported` and `data.requested` fields.
pub fn unsupportedProtocolVersion(arena: Allocator, supported: []const []const u8, requested: []const u8) Allocator.Error!RpcError {
    const data = try toValue(arena, types.UnsupportedProtocolVersionData{ .supported = supported, .requested = requested });
    const message = try std.fmt.allocPrint(arena, "Unsupported protocol version {s}. This server implements {s}.", .{ requested, supported[0] });
    return .{ .code = Code.unsupported_protocol_version.int(), .message = message, .data = data };
}

/// Builds `-32021` with the mandated `data.requiredCapabilities` object.
pub fn missingRequiredClientCapability(arena: Allocator, required: types.ClientCapabilities, message: []const u8) Allocator.Error!RpcError {
    const data = try toValue(arena, types.MissingRequiredClientCapabilityData{ .requiredCapabilities = required });
    return .{ .code = Code.missing_required_client_capability.int(), .message = message, .data = data };
}

/// The value of `data.reason` in a `-31429` error.
pub const rate_limited_reason = "rate_limited";

/// Builds `-31429` for a request over a rate limit, with `data.reason`, `data.retryAfterMs`
/// and `data.limit`. `retry_after_ms` is the time until the limit admits the request again.
/// `limit` names the limit: `caller`, `tool` or `total`.
pub fn rateLimited(arena: Allocator, message: []const u8, retry_after_ms: u64, limit: []const u8) Allocator.Error!RpcError {
    var map: std.json.ObjectMap = .empty;
    try map.put(arena, "reason", .{ .string = rate_limited_reason });
    try map.put(arena, "retryAfterMs", .{ .integer = std.math.cast(i64, retry_after_ms) orelse std.math.maxInt(i64) });
    try map.put(arena, "limit", .{ .string = limit });
    return .{ .code = Code.rate_limited.int(), .message = message, .data = .{ .object = map } };
}

/// Builds `-32602` for a resource that does not exist, with `data.uri`.
pub fn resourceNotFound(arena: Allocator, uri: []const u8) Allocator.Error!RpcError {
    var map: std.json.ObjectMap = .empty;
    try map.put(arena, "uri", .{ .string = uri });
    return .{
        .code = Code.invalid_params.int(),
        .message = try std.fmt.allocPrint(arena, "Resource not found: {s}", .{uri}),
        .data = .{ .object = map },
    };
}

/// Convert any serializable value into a `std.json.Value` tree allocated in `arena`.
pub fn toValue(arena: Allocator, value: anytype) Allocator.Error!std.json.Value {
    const text = try json.writeAlloc(arena, value);
    return json.parseTree(arena, text) catch return error.OutOfMemory;
}

test "emittable codes" {
    try std.testing.expect(Code.isEmittable(-32602));
    try std.testing.expect(Code.isEmittable(-32021));
    try std.testing.expect(!Code.isEmittable(-32002));
    try std.testing.expect(!Code.isEmittable(-32042));
    try std.testing.expect(!Code.isEmittable(-32023));
    try std.testing.expect(Code.isEmittable(-32000));
    // The rate limit code is outside the JSON-RPC range of reserved codes.
    try std.testing.expect(Code.isEmittable(Code.rate_limited.int()));
    try std.testing.expect(Code.rate_limited.int() > -32000);
}

test "rate limited error shape" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const e = try rateLimited(arena, "Too many tool calls", 250, "caller");
    const out = try json.writeAlloc(gpa, e.toWire());
    defer gpa.free(out);
    try std.testing.expectEqualStrings(
        "{\"code\":-31429,\"message\":\"Too many tool calls\",\"data\":{\"reason\":\"rate_limited\",\"retryAfterMs\":250,\"limit\":\"caller\"}}",
        out,
    );
}

test "unsupported protocol version error shape" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const e = try unsupportedProtocolVersion(arena, &.{"2026-07-28"}, "v999.0.0");
    const out = try json.writeAlloc(gpa, e.toWire());
    defer gpa.free(out);
    try std.testing.expectEqualStrings(
        "{\"code\":-32022,\"message\":\"Unsupported protocol version v999.0.0. This server implements 2026-07-28.\",\"data\":{\"supported\":[\"2026-07-28\"],\"requested\":\"v999.0.0\"}}",
        out,
    );
}
