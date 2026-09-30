//! The messages of `proto/mcp_zig_transport_v1.proto`: `JsonRpcMessage` carries one
//! JSON-RPC message as bytes in field 1.
const std = @import("std");
const Allocator = std.mem.Allocator;
const wire = @import("wire.zig");

pub const jsonrpc_field: u32 = 1;

pub const DecodeError = wire.Error || error{ MissingJsonRpc, DuplicateJsonRpc };

/// Encode a `JsonRpcMessage`.
pub fn encodeJsonRpcMessage(gpa: Allocator, out: *std.ArrayList(u8), jsonrpc: []const u8) Allocator.Error!void {
    const w: wire.Writer = .{ .out = out, .gpa = gpa };
    try w.bytesField(jsonrpc_field, jsonrpc);
}

/// The encoded size of a `JsonRpcMessage`.
pub fn encodedLen(jsonrpc: []const u8) usize {
    return 1 + wire.varintLen(jsonrpc.len) + jsonrpc.len;
}

/// Decode a `JsonRpcMessage`. Unknown fields are skipped. The returned slice points into
/// `bytes`.
pub fn decodeJsonRpcMessage(bytes: []const u8) DecodeError![]const u8 {
    var r: wire.Reader = .init(bytes);
    var jsonrpc: ?[]const u8 = null;
    while (try r.next()) |field| {
        if (field.number == jsonrpc_field) {
            if (field.wire_type != .length_delimited) return error.Malformed;
            if (jsonrpc != null) return error.DuplicateJsonRpc;
            jsonrpc = field.value.bytes;
        }
    }
    return jsonrpc orelse error.MissingJsonRpc;
}

test "round trip" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const text = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\"}";
    try encodeJsonRpcMessage(gpa, &out, text);
    try std.testing.expectEqual(encodedLen(text), out.items.len);
    try std.testing.expectEqual(0x0a, out.items[0]);
    try std.testing.expectEqualStrings(text, try decodeJsonRpcMessage(out.items));
    // A reserved field is skipped; a missing field is an error.
    try out.appendSlice(gpa, &.{ 0x10, 0x05 });
    try std.testing.expectEqualStrings(text, try decodeJsonRpcMessage(out.items));
    try std.testing.expectError(error.MissingJsonRpc, decodeJsonRpcMessage(&.{ 0x10, 0x05 }));
    try std.testing.expectError(error.Malformed, decodeJsonRpcMessage(&.{ 0x08, 0x05 }));
}
