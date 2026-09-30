//! The gRPC status codes and the mapping from JSON-RPC error codes.
const std = @import("std");

pub const Code = enum(u8) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,

    pub fn fromWire(text: []const u8) ?Code {
        const n = std.fmt.parseInt(u8, text, 10) catch return null;
        if (n > 16) return null;
        return @enumFromInt(n);
    }

    pub fn wire(self: Code) []const u8 {
        return switch (self) {
            inline else => |c| std.fmt.comptimePrint("{d}", .{@intFromEnum(c)}),
        };
    }
};

/// The gRPC status for a JSON-RPC error that ends a Call before any message.
pub fn forJsonRpcCode(code: i64) Code {
    return switch (code) {
        -32601 => .unimplemented,
        -32700, -32600, -32602, -32020, -32021, -32022 => .invalid_argument,
        else => .unknown,
    };
}

/// Percent-encode a status message for the `grpc-message` header.
pub fn encodeMessage(arena: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (text) |c| {
        if (c >= 0x20 and c <= 0x7e and c != '%') {
            try out.append(arena, c);
        } else {
            var buf: [3]u8 = undefined;
            try out.appendSlice(arena, std.fmt.bufPrint(&buf, "%{X:0>2}", .{c}) catch unreachable);
        }
    }
    return out.items;
}

/// Decode a `grpc-message` header. Malformed escapes are kept as they are.
pub fn decodeMessage(arena: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (text[i] == '%' and i + 2 < text.len + 0 and i + 2 <= text.len - 1) {
            const byte = std.fmt.parseInt(u8, text[i + 1 .. i + 3], 16) catch {
                try out.append(arena, '%');
                continue;
            };
            try out.append(arena, byte);
            i += 2;
        } else {
            try out.append(arena, text[i]);
        }
    }
    return out.items;
}

test "codes and messages" {
    try std.testing.expectEqual(Code.unimplemented, Code.fromWire("12").?);
    try std.testing.expect(Code.fromWire("17") == null);
    try std.testing.expectEqualStrings("3", Code.invalid_argument.wire());
    try std.testing.expectEqual(Code.unimplemented, forJsonRpcCode(-32601));
    try std.testing.expectEqual(Code.invalid_argument, forJsonRpcCode(-32020));
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const encoded = try encodeMessage(arena, "Header mismatch: 100% é");
    try std.testing.expectEqualStrings("Header mismatch: 100%25 %C3%A9", encoded);
    try std.testing.expectEqualStrings("Header mismatch: 100% é", try decodeMessage(arena, encoded));
    try std.testing.expectEqualStrings("bad%zz", try decodeMessage(arena, "bad%zz"));
}
