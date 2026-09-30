//! JSON-RPC request identifiers. The SDK accepts strings and integers. Integers that do not fit
//! in an `i64` keep their digits verbatim. The parser rejects fractional or exponent numbers.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");

pub const RequestId = union(enum) {
    string: []const u8,
    integer: i64,
    /// Digits of an integer outside the `i64` range, echoed byte for byte.
    big: []const u8,

    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !RequestId {
        const value = try std.json.innerParse(Value, allocator, source, options);
        return jsonParseFromValue(allocator, value, options);
    }

    pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: std.json.ParseOptions) !RequestId {
        _ = options;
        return fromValue(allocator, source) orelse error.UnexpectedToken;
    }

    pub fn jsonStringify(self: RequestId, jws: anytype) !void {
        switch (self) {
            .string => |s| try jws.write(s),
            .integer => |i| try jws.write(i),
            .big => |digits| try jws.print("{s}", .{digits}),
        }
    }

    /// Convert a parsed JSON value into an id. Returns null for values that are not a valid id.
    pub fn fromValue(allocator: Allocator, value: Value) ?RequestId {
        return switch (value) {
            .string => |s| .{ .string = allocator.dupe(u8, s) catch return null },
            .integer => |i| .{ .integer = i },
            .number_string => |digits| blk: {
                if (!isIntegerDigits(digits)) break :blk null;
                break :blk .{ .big = allocator.dupe(u8, digits) catch return null };
            },
            else => null,
        };
    }

    pub fn eql(a: RequestId, b: RequestId) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .string => |s| std.mem.eql(u8, s, b.string),
            .integer => |i| i == b.integer,
            .big => |d| std.mem.eql(u8, d, b.big),
        };
    }

    pub fn hash(self: RequestId) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&.{@intFromEnum(std.meta.activeTag(self))});
        switch (self) {
            .string => |s| h.update(s),
            .integer => |i| h.update(std.mem.asBytes(&i)),
            .big => |d| h.update(d),
        }
        return h.final();
    }

    pub fn dupe(self: RequestId, allocator: Allocator) Allocator.Error!RequestId {
        return switch (self) {
            .string => |s| .{ .string = try allocator.dupe(u8, s) },
            .integer => self,
            .big => |d| .{ .big = try allocator.dupe(u8, d) },
        };
    }

    pub fn format(self: RequestId, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .string => |s| try w.print("\"{s}\"", .{s}),
            .integer => |i| try w.print("{d}", .{i}),
            .big => |d| try w.writeAll(d),
        }
    }

    fn isIntegerDigits(digits: []const u8) bool {
        if (digits.len == 0) return false;
        for (digits, 0..) |c, i| {
            if (c == '-' and i == 0) continue;
            if (c < '0' or c > '9') return false;
        }
        return true;
    }
};

pub const HashContext = struct {
    pub fn hash(_: HashContext, key: RequestId) u64 {
        return key.hash();
    }
    pub fn eql(_: HashContext, a: RequestId, b: RequestId) bool {
        return a.eql(b);
    }
};

test "request id parse and print" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "42", .out = "42" },
        .{ .in = "\"abc\"", .out = "\"abc\"" },
        .{ .in = "-7", .out = "-7" },
        .{ .in = "9223372036854775808", .out = "9223372036854775808" },
        .{ .in = "123456789012345678901234567890", .out = "123456789012345678901234567890" },
    };
    for (cases) |c| {
        const tree = try json.parseTree(arena, c.in);
        const id = try json.parseValue(RequestId, arena, tree);
        const out = try json.writeAlloc(gpa, id);
        defer gpa.free(out);
        try std.testing.expectEqualStrings(c.out, out);
    }
    const bad = try json.parseTree(arena, "1.5");
    try std.testing.expectError(error.UnexpectedToken, json.parseValue(RequestId, arena, bad));
    const nul = try json.parseTree(arena, "null");
    try std.testing.expectError(error.UnexpectedToken, json.parseValue(RequestId, arena, nul));
}
