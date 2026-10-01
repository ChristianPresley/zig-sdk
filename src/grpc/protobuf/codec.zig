//! A table-driven codec for the protobuf messages of the typed gRPC binding. A message is a
//! Zig struct with a default for each field and a `proto` table. The table gives the field
//! number and the wire kind of each struct field. The shape of the struct field gives the
//! cardinality:
//!
//! - `T` is a singular field without presence. The encoder omits the default value.
//! - `?T` is a field with presence: a message, or a scalar with the `optional` label.
//! - `[]const T` is a repeated field. Numeric kinds use the packed encoding. The decoder
//!   also accepts the unpacked encoding.
//!
//! A `map<K, V>` field is a repeated message with the fields `key = 1` and `value = 2`. The
//! `json_struct` kind maps `google.protobuf.Struct` to a `std.json.Value` object.
//!
//! The decoder skips unknown fields. It refuses a singular field that occurs two times. It
//! also refuses a wrong wire type for the table and a string that is not UTF-8. `Limits`
//! keeps the nesting depth and the count of decoded elements in bounds. Strings and bytes
//! of the result point into the input, so the input must live as long as the result.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const wire = @import("wire.zig");
const well_known = @import("well_known.zig");

pub const Kind = enum {
    string,
    bytes,
    bool,
    int32,
    int64,
    uint32,
    uint64,
    enumeration,
    float,
    double,
    message,
    json_struct,
};

/// One row of the `proto` table of a message.
pub const Field = struct {
    /// The name of the struct field.
    name: []const u8,
    number: u32,
    kind: Kind,
};

pub const Limits = struct {
    /// The maximum nesting depth of messages, `Struct` and `ListValue` values.
    max_depth: u16 = 64,
    /// The maximum count of decoded elements: messages, repeated values, `Struct` fields and
    /// `ListValue` values.
    max_elements: u32 = 1 << 18,
};

pub const DecodeError = wire.Error || Allocator.Error || error{
    /// The wire type of a field does not agree with the kind of the field.
    WrongWireType,
    /// A singular field, or a member of a `oneof`, occurs more than one time.
    DuplicateField,
    /// A string field is not valid UTF-8.
    InvalidUtf8,
    /// The nesting is deeper than `Limits.max_depth`.
    TooDeep,
    /// The message has more elements than `Limits.max_elements`.
    TooManyElements,
    /// A well-known value has no JSON form: a number that is not finite, or a `Value`
    /// without a kind.
    InvalidValue,
};

pub const EncodeError = Allocator.Error || error{
    /// An integer is outside the range that a `double` keeps exact, from -(2^53) to 2^53.
    UnsafeInteger,
    /// A `json_struct` field has a value that is not a JSON object.
    InvalidValue,
    /// The nesting is deeper than `Limits.max_depth`.
    TooDeep,
    /// A message is larger than 4 GiB.
    MessageTooLarge,
};

/// The element count of one decode call.
pub const Budget = struct {
    limits: Limits,
    elements: u32 = 0,

    pub fn take(self: *Budget, n: u32) error{TooManyElements}!void {
        if (n > self.limits.max_elements -| self.elements) return error.TooManyElements;
        self.elements += n;
    }
};

/// Decode a message of type `T`.
pub fn decode(comptime T: type, arena: Allocator, bytes: []const u8, limits: Limits) DecodeError!T {
    var budget: Budget = .{ .limits = limits };
    return decodeMessage(T, arena, bytes, &budget, 0);
}

/// Encode a message of type `T` and append the bytes to `out`.
pub fn encode(comptime T: type, gpa: Allocator, out: *std.ArrayList(u8), value: T, limits: Limits) EncodeError!void {
    const w: wire.Writer = .{ .out = out, .gpa = gpa };
    try encodeMessage(T, w, value, limits, 0);
}

/// The cardinality of a struct field: see the top of this file.
pub const Shape = enum { singular, optional, repeated };

pub fn shapeOf(comptime FT: type, comptime kind: Kind) Shape {
    return switch (@typeInfo(FT)) {
        .optional => .optional,
        .pointer => |p| blk: {
            if (p.size != .slice) @compileError("a protobuf field is a value, an optional or a slice");
            if ((kind == .string or kind == .bytes) and p.child == u8) break :blk .singular;
            break :blk .repeated;
        },
        else => .singular,
    };
}

/// The type of one value of a field: the child of an optional or of a slice.
pub fn BaseOf(comptime FT: type, comptime kind: Kind) type {
    return switch (shapeOf(FT, kind)) {
        .singular => FT,
        .optional => @typeInfo(FT).optional.child,
        .repeated => @typeInfo(FT).pointer.child,
    };
}

fn wireTypeOf(comptime kind: Kind) wire.WireType {
    return switch (kind) {
        .bool, .int32, .int64, .uint32, .uint64, .enumeration => .varint,
        .float => .fixed32,
        .double => .fixed64,
        .string, .bytes, .message, .json_struct => .length_delimited,
    };
}

fn isPackable(comptime kind: Kind) bool {
    return wireTypeOf(kind) != .length_delimited;
}

/// Decode one message. `depth` is the nesting depth of the message.
pub fn decodeMessage(comptime T: type, arena: Allocator, bytes: []const u8, budget: *Budget, depth: u16) DecodeError!T {
    if (depth >= budget.limits.max_depth) return error.TooDeep;
    try budget.take(1);
    var result: T = .{};
    var caps = [_]usize{0} ** T.proto.len;
    var seen = [_]bool{false} ** T.proto.len;
    var r: wire.Reader = .init(bytes);
    while (try r.next()) |f| {
        inline for (T.proto, 0..) |spec, i| {
            if (f.number == spec.number) try decodeField(T, spec, &result, f, arena, budget, depth, &caps[i], &seen[i]);
        }
    }
    return result;
}

fn decodeField(comptime T: type, comptime spec: Field, result: *T, f: wire.Field, arena: Allocator, budget: *Budget, depth: u16, cap: *usize, seen: *bool) DecodeError!void {
    const FT = @FieldType(T, spec.name);
    const B = BaseOf(FT, spec.kind);
    switch (comptime shapeOf(FT, spec.kind)) {
        .singular, .optional => {
            if (seen.*) return error.DuplicateField;
            seen.* = true;
            @field(result, spec.name) = try decodeValue(B, spec.kind, f, arena, budget, depth);
        },
        .repeated => {
            const slot: *[]const B = &@field(result, spec.name);
            if (comptime isPackable(spec.kind)) {
                if (f.wire_type == .length_delimited) {
                    var sub: wire.Reader = .init(f.value.bytes);
                    while (!sub.eof()) {
                        const one: wire.Field = switch (comptime wireTypeOf(spec.kind)) {
                            .varint => .{ .number = f.number, .wire_type = .varint, .value = .{ .varint = try sub.varint() } },
                            .fixed32 => .{ .number = f.number, .wire_type = .fixed32, .value = .{ .fixed32 = try sub.fixed32() } },
                            .fixed64 => .{ .number = f.number, .wire_type = .fixed64, .value = .{ .fixed64 = try sub.fixed64() } },
                            else => unreachable,
                        };
                        try budget.take(1);
                        try append(B, arena, slot, cap, try decodeValue(B, spec.kind, one, arena, budget, depth));
                    }
                    return;
                }
            }
            try budget.take(1);
            try append(B, arena, slot, cap, try decodeValue(B, spec.kind, f, arena, budget, depth));
        },
    }
}

/// Append to a slice in `arena`. When the buffer is full, the function makes it two times
/// larger. `cap` is the capacity of the buffer behind the slice.
fn append(comptime E: type, arena: Allocator, slot: *[]const E, cap: *usize, elem: E) Allocator.Error!void {
    if (slot.len == cap.*) {
        const new_cap = @max(4, cap.* * 2);
        const buf = try arena.alloc(E, new_cap);
        @memcpy(buf[0..slot.len], slot.*);
        slot.* = buf[0..slot.len];
        cap.* = new_cap;
    }
    const buf: [*]E = @constCast(slot.ptr);
    buf[slot.len] = elem;
    slot.* = buf[0 .. slot.len + 1];
}

fn expectWire(f: wire.Field, wt: wire.WireType) DecodeError!void {
    if (f.wire_type != wt) return error.WrongWireType;
}

fn decodeValue(comptime B: type, comptime kind: Kind, f: wire.Field, arena: Allocator, budget: *Budget, depth: u16) DecodeError!B {
    try expectWire(f, wireTypeOf(kind));
    switch (kind) {
        .string => {
            if (!std.unicode.utf8ValidateSlice(f.value.bytes)) return error.InvalidUtf8;
            return f.value.bytes;
        },
        .bytes => return f.value.bytes,
        .bool => return f.value.varint != 0,
        .int32 => return @bitCast(@as(u32, @truncate(f.value.varint))),
        .int64 => return @bitCast(f.value.varint),
        .uint32 => return @truncate(f.value.varint),
        .uint64 => return f.value.varint,
        .enumeration => return @enumFromInt(@as(i32, @bitCast(@as(u32, @truncate(f.value.varint))))),
        .float => return @bitCast(f.value.fixed32),
        .double => return @bitCast(f.value.fixed64),
        .message => return decodeMessage(B, arena, f.value.bytes, budget, depth + 1),
        .json_struct => return well_known.decodeStruct(arena, f.value.bytes, budget, depth + 1),
    }
}

/// Encode the fields of one message without a tag or a length.
pub fn encodeMessage(comptime T: type, w: wire.Writer, value: T, limits: Limits, depth: u16) EncodeError!void {
    if (depth >= limits.max_depth) return error.TooDeep;
    inline for (T.proto) |spec| {
        const fv = @field(value, spec.name);
        const FT = @TypeOf(fv);
        switch (comptime shapeOf(FT, spec.kind)) {
            .singular => {
                if (spec.kind == .message or spec.kind == .json_struct) @compileError("a message field is optional or repeated: " ++ spec.name);
                if (!isDefault(spec.kind, fv)) try encodeField(spec.kind, w, spec.number, fv, limits, depth);
            },
            .optional => if (fv) |v| try encodeField(spec.kind, w, spec.number, v, limits, depth),
            .repeated => if (fv.len > 0) {
                if (comptime isPackable(spec.kind)) {
                    const start = try w.beginNested(spec.number);
                    for (fv) |v| try encodeRaw(spec.kind, w, v);
                    try w.endNested(start);
                } else {
                    for (fv) |v| try encodeField(spec.kind, w, spec.number, v, limits, depth);
                }
            },
        }
    }
}

fn isDefault(comptime kind: Kind, v: anytype) bool {
    return switch (kind) {
        .string, .bytes => v.len == 0,
        .bool => !v,
        .int32, .int64, .uint32, .uint64 => v == 0,
        .float, .double => v == 0 and !std.math.signbit(v),
        .enumeration => @intFromEnum(v) == 0,
        .message, .json_struct => unreachable,
    };
}

fn encodeField(comptime kind: Kind, w: wire.Writer, number: u32, v: anytype, limits: Limits, depth: u16) EncodeError!void {
    switch (kind) {
        .message => {
            const start = try w.beginNested(number);
            try encodeMessage(@TypeOf(v), w, v, limits, depth + 1);
            try w.endNested(start);
        },
        .json_struct => {
            if (v != .object) return error.InvalidValue;
            const start = try w.beginNested(number);
            try well_known.encodeStruct(w, v.object, limits, depth + 1);
            try w.endNested(start);
        },
        else => {
            try w.tag(number, wireTypeOf(kind));
            try encodeRaw(kind, w, v);
        },
    }
}

/// Encode a scalar value without its tag.
fn encodeRaw(comptime kind: Kind, w: wire.Writer, v: anytype) Allocator.Error!void {
    switch (kind) {
        .string, .bytes => {
            try w.varint(v.len);
            try w.out.appendSlice(w.gpa, v);
        },
        .bool => try w.varint(@intFromBool(v)),
        // A negative int32 is a sign-extended 64-bit varint.
        .int32 => try w.varint(@bitCast(@as(i64, v))),
        .int64 => try w.varint(@bitCast(v)),
        .uint32, .uint64 => try w.varint(v),
        .enumeration => try w.varint(@bitCast(@as(i64, @intFromEnum(v)))),
        .float => try w.fixed32(@bitCast(v)),
        .double => try w.fixed64(@bitCast(v)),
        .message, .json_struct => unreachable,
    }
}

// -- Tests ---------------------------------------------------------------------------------------

const TestEnum = enum(i32) { zero = 0, one = 1, _ };

const Inner = struct {
    name: []const u8 = "",
    pub const proto = [_]Field{.{ .name = "name", .number = 1, .kind = .string }};
};

const Outer = struct {
    id: i32 = 0,
    big: u64 = 0,
    flag: bool = false,
    ratio: ?f32 = null,
    weight: f64 = 0,
    kind: TestEnum = .zero,
    data: []const u8 = "",
    tags: []const []const u8 = &.{},
    numbers: []const i64 = &.{},
    inner: ?Inner = null,
    inners: []const Inner = &.{},
    meta: ?Value = null,
    pub const proto = [_]Field{
        .{ .name = "id", .number = 1, .kind = .int32 },
        .{ .name = "big", .number = 2, .kind = .uint64 },
        .{ .name = "flag", .number = 3, .kind = .bool },
        .{ .name = "ratio", .number = 4, .kind = .float },
        .{ .name = "weight", .number = 5, .kind = .double },
        .{ .name = "kind", .number = 6, .kind = .enumeration },
        .{ .name = "data", .number = 7, .kind = .bytes },
        .{ .name = "tags", .number = 8, .kind = .string },
        .{ .name = "numbers", .number = 9, .kind = .int64 },
        .{ .name = "inner", .number = 10, .kind = .message },
        .{ .name = "inners", .number = 11, .kind = .message },
        .{ .name = "meta", .number = 12, .kind = .json_struct },
    };
};

test "codec round trip of every kind and shape" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const meta = try std.json.parseFromSliceLeaky(Value, arena, "{\"a\":[1,true,null,\"x\",{\"b\":2.5}]}", .{});
    const value: Outer = .{
        .id = -5,
        .big = std.math.maxInt(u64),
        .flag = true,
        .ratio = 0,
        .weight = 1.5,
        .kind = @enumFromInt(7),
        .data = "\x00\xff",
        .tags = &.{ "a", "" },
        .numbers = &.{ -1, 0, 300 },
        .inner = .{ .name = "i" },
        .inners = &.{ .{}, .{ .name = "j" } },
        .meta = meta,
    };
    try encode(Outer, gpa, &out, value, .{});
    const back = try decode(Outer, arena, out.items, .{});
    try std.testing.expectEqual(-5, back.id);
    try std.testing.expectEqual(std.math.maxInt(u64), back.big);
    try std.testing.expect(back.flag);
    // An optional scalar keeps its presence, also with the default value.
    try std.testing.expectEqual(@as(?f32, 0), back.ratio);
    try std.testing.expectEqual(1.5, back.weight);
    // An unknown enum value stays as it is.
    try std.testing.expectEqual(7, @intFromEnum(back.kind));
    try std.testing.expectEqualSlices(u8, "\x00\xff", back.data);
    try std.testing.expectEqual(2, back.tags.len);
    try std.testing.expectEqualStrings("", back.tags[1]);
    try std.testing.expectEqualSlices(i64, &.{ -1, 0, 300 }, back.numbers);
    try std.testing.expectEqualStrings("i", back.inner.?.name);
    try std.testing.expectEqual(2, back.inners.len);
    try std.testing.expectEqualStrings("j", back.inners[1].name);
    const text = try std.json.Stringify.valueAlloc(arena, back.meta.?, .{});
    try std.testing.expectEqualStrings("{\"a\":[1,true,null,\"x\",{\"b\":2.5}]}", text);

    // The default values take no bytes.
    out.clearRetainingCapacity();
    try encode(Outer, gpa, &out, .{}, .{});
    try std.testing.expectEqual(0, out.items.len);
}

test "codec accepts unpacked repeated numbers and skips unknown fields" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // numbers = 1 unpacked, an unknown field 99, numbers = 2 unpacked, numbers = [3, 4] packed.
    const bytes = [_]u8{ 0x48, 0x01, 0x98, 0x06, 0x05, 0x48, 0x02, 0x4a, 0x02, 0x03, 0x04 };
    const v = try decode(Outer, arena, &bytes, .{});
    try std.testing.expectEqualSlices(i64, &.{ 1, 2, 3, 4 }, v.numbers);
}

test "codec refuses malformed input" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // id two times.
    try std.testing.expectError(error.DuplicateField, decode(Outer, arena, &.{ 0x08, 0x01, 0x08, 0x02 }, .{}));
    // id as a length-delimited field.
    try std.testing.expectError(error.WrongWireType, decode(Outer, arena, &.{ 0x0a, 0x00 }, .{}));
    // A tag that is not valid UTF-8 in a string.
    try std.testing.expectError(error.InvalidUtf8, decode(Outer, arena, &.{ 0x42, 0x01, 0xff }, .{}));
    // A length past the end.
    try std.testing.expectError(error.Truncated, decode(Outer, arena, &.{ 0x52, 0x05, 0x0a }, .{}));
    // A packed float list with a length that is not a multiple of four.
    try std.testing.expectError(error.Truncated, decode(Outer, arena, &.{ 0x4a, 0x01, 0x80 }, .{}));
    // Too many elements and too deep.
    try std.testing.expectError(error.TooManyElements, decode(Outer, arena, &.{ 0x48, 0x01, 0x48, 0x02 }, .{ .max_elements = 2 }));
    try std.testing.expectError(error.TooDeep, decode(Outer, arena, &.{ 0x52, 0x00 }, .{ .max_depth = 1 }));
}

test "codec refuses an integer that a double does not keep exact" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const ok = try std.json.parseFromSliceLeaky(Value, arena, "{\"n\":9007199254740992}", .{});
    try encode(Outer, gpa, &out, .{ .meta = ok }, .{});
    const too_big = try std.json.parseFromSliceLeaky(Value, arena, "{\"n\":9007199254740993}", .{});
    try std.testing.expectError(error.UnsafeInteger, encode(Outer, gpa, &out, .{ .meta = too_big }, .{}));
    try std.testing.expectError(error.InvalidValue, encode(Outer, gpa, &out, .{ .meta = .{ .string = "x" } }, .{}));
}
