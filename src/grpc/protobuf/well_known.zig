//! The well-known types that the typed binding uses: `google.protobuf.Struct`, `Value` and
//! `ListValue` as `std.json.Value` trees, and `google.protobuf.Duration`.
//!
//! A `Value` keeps every number as a `double`. The encoder refuses an integer outside the
//! range from -(2^53) to 2^53, because a `double` does not keep it exact. The decoder gives
//! an integer for a whole number in that range and a float for other numbers. A number that
//! is not finite has no JSON form, and the decoder refuses it.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const wire = @import("wire.zig");
const codec = @import("codec.zig");

/// `google.protobuf.Duration`.
pub const Duration = struct {
    seconds: i64 = 0,
    nanos: i32 = 0,
    pub const proto = [_]codec.Field{
        .{ .name = "seconds", .number = 1, .kind = .int64 },
        .{ .name = "nanos", .number = 2, .kind = .int32 },
    };
};

/// The largest integer that a `double` keeps exact, 2^53.
pub const max_exact_integer: i64 = 1 << 53;

const struct_fields = 1;
const entry_key = 1;
const entry_value = 2;
const value_null = 1;
const value_number = 2;
const value_string = 3;
const value_bool = 4;
const value_struct = 5;
const value_list = 6;
const list_values = 1;

/// Encode the fields of a `Struct` without a tag or a length.
pub fn encodeStruct(w: wire.Writer, object: std.json.ObjectMap, limits: codec.Limits, depth: u16) codec.EncodeError!void {
    if (depth >= limits.max_depth) return error.TooDeep;
    var it = object.iterator();
    while (it.next()) |kv| {
        const entry = try w.beginNested(struct_fields);
        try w.bytesField(entry_key, kv.key_ptr.*);
        const value = try w.beginNested(entry_value);
        try encodeValue(w, kv.value_ptr.*, limits, depth + 1);
        try w.endNested(value);
        try w.endNested(entry);
    }
}

/// Encode the fields of a `Value` without a tag or a length. The member of the `oneof` is
/// always on the wire, also with its default value.
pub fn encodeValue(w: wire.Writer, value: Value, limits: codec.Limits, depth: u16) codec.EncodeError!void {
    if (depth >= limits.max_depth) return error.TooDeep;
    switch (value) {
        .null => try w.varintField(value_null, 0),
        .bool => |b| try w.varintField(value_bool, @intFromBool(b)),
        .integer => |i| {
            if (i < -max_exact_integer or i > max_exact_integer) return error.UnsafeInteger;
            try w.tag(value_number, .fixed64);
            try w.fixed64(@bitCast(@as(f64, @floatFromInt(i))));
        },
        .float => |f| {
            if (!std.math.isFinite(f)) return error.InvalidValue;
            try w.tag(value_number, .fixed64);
            try w.fixed64(@bitCast(f));
        },
        // The JSON parser keeps an integer outside the range of `i64` as text.
        .number_string => return error.UnsafeInteger,
        .string => |s| try w.bytesField(value_string, s),
        .array => |a| {
            const start = try w.beginNested(value_list);
            for (a.items) |item| {
                const one = try w.beginNested(list_values);
                try encodeValue(w, item, limits, depth + 1);
                try w.endNested(one);
            }
            try w.endNested(start);
        },
        .object => |o| {
            const start = try w.beginNested(value_struct);
            try encodeStruct(w, o, limits, depth + 1);
            try w.endNested(start);
        },
    }
}

/// Decode a `Struct` into a JSON object. Strings point into `bytes`. A key that occurs two
/// times keeps the last value, as in a protobuf map.
pub fn decodeStruct(arena: Allocator, bytes: []const u8, budget: *codec.Budget, depth: u16) codec.DecodeError!Value {
    if (depth >= budget.limits.max_depth) return error.TooDeep;
    var map: std.json.ObjectMap = .empty;
    var r: wire.Reader = .init(bytes);
    while (try r.next()) |f| {
        if (f.number != struct_fields) continue;
        if (f.wire_type != .length_delimited) return error.WrongWireType;
        try budget.take(1);
        var key: []const u8 = "";
        var value: ?Value = null;
        var er: wire.Reader = .init(f.value.bytes);
        while (try er.next()) |ef| switch (ef.number) {
            entry_key => {
                if (ef.wire_type != .length_delimited) return error.WrongWireType;
                if (!std.unicode.utf8ValidateSlice(ef.value.bytes)) return error.InvalidUtf8;
                key = ef.value.bytes;
            },
            entry_value => {
                if (ef.wire_type != .length_delimited) return error.WrongWireType;
                if (value != null) return error.DuplicateField;
                value = try decodeValue(arena, ef.value.bytes, budget, depth + 1);
            },
            else => {},
        };
        // A map entry without a value has the default `Value`, which has no kind.
        try map.put(arena, key, value orelse return error.InvalidValue);
    }
    return .{ .object = map };
}

/// Decode a `Value`. Exactly one member of its `oneof` must be on the wire.
pub fn decodeValue(arena: Allocator, bytes: []const u8, budget: *codec.Budget, depth: u16) codec.DecodeError!Value {
    if (depth >= budget.limits.max_depth) return error.TooDeep;
    var result: ?Value = null;
    var r: wire.Reader = .init(bytes);
    while (try r.next()) |f| {
        const v: Value = switch (f.number) {
            value_null => blk: {
                if (f.wire_type != .varint) return error.WrongWireType;
                break :blk .null;
            },
            value_number => blk: {
                if (f.wire_type != .fixed64) return error.WrongWireType;
                break :blk try numberValue(@bitCast(f.value.fixed64));
            },
            value_string => blk: {
                if (f.wire_type != .length_delimited) return error.WrongWireType;
                if (!std.unicode.utf8ValidateSlice(f.value.bytes)) return error.InvalidUtf8;
                break :blk .{ .string = f.value.bytes };
            },
            value_bool => blk: {
                if (f.wire_type != .varint) return error.WrongWireType;
                break :blk .{ .bool = f.value.varint != 0 };
            },
            value_struct => blk: {
                if (f.wire_type != .length_delimited) return error.WrongWireType;
                break :blk try decodeStruct(arena, f.value.bytes, budget, depth + 1);
            },
            value_list => blk: {
                if (f.wire_type != .length_delimited) return error.WrongWireType;
                break :blk try decodeList(arena, f.value.bytes, budget, depth + 1);
            },
            else => continue,
        };
        if (result != null) return error.DuplicateField;
        result = v;
    }
    return result orelse error.InvalidValue;
}

fn decodeList(arena: Allocator, bytes: []const u8, budget: *codec.Budget, depth: u16) codec.DecodeError!Value {
    if (depth >= budget.limits.max_depth) return error.TooDeep;
    var array: std.json.Array = .init(arena);
    var r: wire.Reader = .init(bytes);
    while (try r.next()) |f| {
        if (f.number != list_values) continue;
        if (f.wire_type != .length_delimited) return error.WrongWireType;
        try budget.take(1);
        try array.append(try decodeValue(arena, f.value.bytes, budget, depth + 1));
    }
    return .{ .array = array };
}

/// The JSON form of a `double`: an integer for a whole number that a `double` keeps exact.
pub fn numberValue(f: f64) error{InvalidValue}!Value {
    if (!std.math.isFinite(f)) return error.InvalidValue;
    const limit: f64 = @floatFromInt(max_exact_integer);
    if (@trunc(f) == f and @abs(f) <= limit) return .{ .integer = @intFromFloat(f) };
    return .{ .float = f };
}

test "struct round trip keeps integers, floats, nesting and key order" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text = "{\"z\":1,\"a\":-2.5,\"s\":\"\u{e9}\",\"b\":false,\"n\":null,\"l\":[[],{},[1]],\"o\":{\"p\":{\"q\":9007199254740992}},\"\":\"\"}";
    const tree = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const w: wire.Writer = .{ .out = &out, .gpa = gpa };
    try encodeStruct(w, tree.object, .{}, 0);
    var budget: codec.Budget = .{ .limits = .{} };
    const back = try decodeStruct(arena, out.items, &budget, 0);
    const again = try std.json.Stringify.valueAlloc(arena, back, .{});
    try std.testing.expectEqualStrings(text, again);
}

test "value refusals" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var budget: codec.Budget = .{ .limits = .{} };
    // A Value without a kind, and a Value with two kinds.
    try std.testing.expectError(error.InvalidValue, decodeValue(arena, &.{}, &budget, 0));
    try std.testing.expectError(error.DuplicateField, decodeValue(arena, &.{ 0x08, 0x00, 0x20, 0x01 }, &budget, 0));
    // NaN as a number.
    try std.testing.expectError(error.InvalidValue, decodeValue(arena, &.{ 0x11, 0, 0, 0, 0, 0, 0, 0xf8, 0x7f }, &budget, 0));
    // A map entry without a value.
    try std.testing.expectError(error.InvalidValue, decodeStruct(arena, &.{ 0x0a, 0x03, 0x0a, 0x01, 'k' }, &budget, 0));
    // A list in a list in a list, with a depth limit of two.
    var shallow: codec.Budget = .{ .limits = .{ .max_depth = 2 } };
    try std.testing.expectError(error.TooDeep, decodeValue(arena, &.{ 0x32, 0x04, 0x0a, 0x02, 0x32, 0x00 }, &shallow, 0));
    try std.testing.expectEqual(@as(i64, -3), (try numberValue(-3.0)).integer);
    try std.testing.expectEqual(@as(f64, 0.5), (try numberValue(0.5)).float);
    try std.testing.expect((try numberValue(1e300)) == .float);
}

test "duration round trip" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try codec.encode(Duration, gpa, &out, .{ .seconds = 90, .nanos = 5_000_000 }, .{});
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 90, 0x10, 0xc0, 0x96, 0xb1, 0x02 }, out.items);
    const back = try codec.decode(Duration, arena_state.allocator(), out.items, .{});
    try std.testing.expectEqual(90, back.seconds);
    try std.testing.expectEqual(5_000_000, back.nanos);
}
