//! A writer with the API of `std.json.Stringify` that builds a `Value` tree in place of JSON
//! text. The tree is the same as the tree that `json.parseTree` gives for the text that
//! `std.json.Stringify` writes. Thus a transport that needs a tree, for example the typed
//! gRPC binding, does not serialize a result and then parse the text again.
//!
//! The writer gives `error.WriteFailed` for a value that the text path also refuses. Some
//! examples are an infinite float, a duplicate key and a tree that is too deep. `failure`
//! then tells the cause. The caller then uses the text path, which gives the same response
//! as before.
const std = @import("std");
const Allocator = std.mem.Allocator;
const json = @import("json.zig");
const Value = std.json.Value;

/// The cause of a failed write.
pub const Failure = error{
    OutOfMemory,
    /// The text of the value is not a JSON text, or `json.parseTree` refuses it.
    Unrepresentable,
    /// The calls of the API are not in a valid order.
    Misuse,
};

pub const Error = std.Io.Writer.Error;

/// Build the tree of `value` with the options `json.wire_options`. The memory of the tree comes
/// from `arena`, also the strings, thus the tree does not point into `value`. Only the names
/// of enum tags and errors point to static memory of the program. A tree
/// that nests deeper than `max_depth` fails, as `json.parseTreeMaxDepth` does.
pub fn toValue(arena: Allocator, value: anytype, max_depth: u16) Failure!Value {
    var w: ValueWriter = undefined;
    w.init(arena, max_depth);
    w.write(value) catch return w.failure orelse error.Misuse;
    return w.finish();
}

pub const ValueWriter = struct {
    arena: Allocator,
    /// The options of the text path. The tree applies `emit_null_optional_fields` and
    /// `emit_strings_as_arrays`.
    options: std.json.Stringify.Options,
    /// The text of a raw write (`beginWriteRaw`, `beginObjectFieldRaw`). A hook of a type
    /// writes the text here, as into the writer of `std.json.Stringify`.
    writer: *std.Io.Writer,
    raw: std.Io.Writer.Allocating,
    raw_mode: enum { none, value, key } = .none,
    stack: std.ArrayList(Open) = .empty,
    root: ?Value = null,
    max_depth: u16,
    /// The cause of the first failed call. Each call after it fails too.
    failure: ?Failure = null,

    /// An array or an object that is not complete. `key` is the key of the next member of
    /// an object, or null before the key.
    const Open = union(enum) {
        array: std.json.Array,
        object: struct { members: std.json.ObjectMap, key: ?[]const u8 },
    };

    /// Prepare the writer in place: `writer` points into the struct.
    pub fn init(w: *ValueWriter, arena: Allocator, max_depth: u16) void {
        w.* = .{
            .arena = arena,
            .options = json.wire_options,
            .writer = undefined,
            .raw = .init(arena),
            .max_depth = @min(max_depth, json.max_tree_depth),
        };
        w.writer = &w.raw.writer;
    }

    /// The tree after a complete value.
    pub fn finish(w: *ValueWriter) Failure!Value {
        if (w.failure) |f| return f;
        if (w.stack.items.len != 0 or w.raw_mode != .none) return error.Misuse;
        return w.root orelse error.Misuse;
    }

    fn note(w: *ValueWriter, cause: Failure) void {
        if (w.failure == null) w.failure = cause;
    }

    fn fail(w: *ValueWriter, cause: Failure) Error {
        w.note(cause);
        return error.WriteFailed;
    }

    fn check(w: *ValueWriter) Error!void {
        if (w.failure != null) return error.WriteFailed;
        if (w.raw_mode != .none) return w.fail(error.Misuse);
    }

    /// Put a complete value into the array or the object at the top of the stack, or make
    /// it the root.
    fn complete(w: *ValueWriter, value: Value) Error!void {
        if (w.stack.items.len == 0) {
            if (w.root != null) return w.fail(error.Misuse);
            w.root = value;
            return;
        }
        switch (w.stack.items[w.stack.items.len - 1]) {
            .array => |*array| array.append(value) catch return w.fail(error.OutOfMemory),
            .object => |*object| {
                const key = object.key orelse return w.fail(error.Misuse);
                const entry = object.members.getOrPut(w.arena, key) catch return w.fail(error.OutOfMemory);
                // The parser of the text path refuses a duplicate key.
                if (entry.found_existing) return w.fail(error.Unrepresentable);
                entry.value_ptr.* = value;
                object.key = null;
            },
        }
    }

    fn open(w: *ValueWriter, container: Open) Error!void {
        try w.check();
        if (w.stack.items.len + 1 > w.max_depth) return w.fail(error.Unrepresentable);
        if (w.stack.items.len > 0) {
            const top = w.stack.items[w.stack.items.len - 1];
            if (top == .object and top.object.key == null) return w.fail(error.Misuse);
        } else if (w.root != null) return w.fail(error.Misuse);
        w.stack.append(w.arena, container) catch return w.fail(error.OutOfMemory);
    }

    pub fn beginArray(w: *ValueWriter) Error!void {
        try w.open(.{ .array = .init(w.arena) });
    }

    pub fn beginObject(w: *ValueWriter) Error!void {
        try w.open(.{ .object = .{ .members = .empty, .key = null } });
    }

    pub fn endArray(w: *ValueWriter) Error!void {
        try w.check();
        if (w.stack.items.len == 0 or w.stack.items[w.stack.items.len - 1] != .array) return w.fail(error.Misuse);
        try w.complete(.{ .array = w.stack.pop().?.array });
    }

    pub fn endObject(w: *ValueWriter) Error!void {
        try w.check();
        if (w.stack.items.len == 0) return w.fail(error.Misuse);
        const top = w.stack.items[w.stack.items.len - 1];
        if (top != .object or top.object.key != null) return w.fail(error.Misuse);
        try w.complete(.{ .object = w.stack.pop().?.object.members });
    }

    /// The key of the next member. The writer copies the key into the arena.
    pub fn objectField(w: *ValueWriter, key: []const u8) Error!void {
        try w.check();
        // The text path writes the bytes of the key, and its parser refuses invalid UTF-8.
        if (!std.unicode.utf8ValidateSlice(key)) return w.fail(error.Unrepresentable);
        try w.setKey(w.arena.dupe(u8, key) catch return w.fail(error.OutOfMemory));
    }

    /// A key as a JSON string with its quotes.
    pub fn objectFieldRaw(w: *ValueWriter, quoted_key: []const u8) Error!void {
        try w.check();
        try w.setKey(try w.parseKey(quoted_key));
    }

    pub fn beginObjectFieldRaw(w: *ValueWriter) Error!void {
        try w.check();
        w.raw.clearRetainingCapacity();
        w.raw_mode = .key;
    }

    /// End a raw key. A failure shows in the next call and in `finish`.
    pub fn endObjectFieldRaw(w: *ValueWriter) void {
        if (w.failure != null) return;
        if (w.raw_mode != .key) {
            w.note(error.Misuse);
            return;
        }
        w.raw_mode = .none;
        const key = w.parseKey(w.raw.written()) catch return;
        w.setKey(key) catch return;
    }

    fn parseKey(w: *ValueWriter, quoted_key: []const u8) Error![]const u8 {
        const value = json.parseTree(w.arena, quoted_key) catch |e| return w.fail(if (e == error.OutOfMemory) error.OutOfMemory else error.Unrepresentable);
        if (value != .string) return w.fail(error.Unrepresentable);
        return value.string;
    }

    fn setKey(w: *ValueWriter, key: []const u8) Error!void {
        if (w.stack.items.len == 0) return w.fail(error.Misuse);
        const top = &w.stack.items[w.stack.items.len - 1];
        if (top.* != .object or top.object.key != null) return w.fail(error.Misuse);
        top.object.key = key;
    }

    /// A raw JSON value from `fmt` and `args`, as `std.json.Stringify.print` writes it.
    pub fn print(w: *ValueWriter, comptime fmt: []const u8, args: anytype) Error!void {
        try w.check();
        const text = std.fmt.allocPrint(w.arena, fmt, args) catch return w.fail(error.OutOfMemory);
        try w.rawValue(text);
    }

    pub fn beginWriteRaw(w: *ValueWriter) Error!void {
        try w.check();
        w.raw.clearRetainingCapacity();
        w.raw_mode = .value;
    }

    /// End a raw value. A failure shows in the next call and in `finish`.
    pub fn endWriteRaw(w: *ValueWriter) void {
        if (w.failure != null) return;
        if (w.raw_mode != .value) {
            w.note(error.Misuse);
            return;
        }
        w.raw_mode = .none;
        w.rawValue(w.raw.written()) catch return;
    }

    fn rawValue(w: *ValueWriter, text: []const u8) Error!void {
        // The value nests inside the open containers, as in the text.
        const room: u16 = @intCast(w.max_depth - w.stack.items.len);
        const value = json.parseTreeMaxDepth(w.arena, text, room) catch |e| return w.fail(if (e == error.OutOfMemory) error.OutOfMemory else error.Unrepresentable);
        try w.complete(value);
    }

    fn string(w: *ValueWriter, s: []const u8) Error!void {
        try w.complete(.{ .string = w.arena.dupe(u8, s) catch return w.fail(error.OutOfMemory) });
    }

    /// An integer as the text path writes it, and as its parser reads it again.
    fn integer(w: *ValueWriter, n: anytype) Error!void {
        var buf: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{}", .{n}) catch {
            // Only an integer of more than 200 bits gets here.
            const long = std.fmt.allocPrint(w.arena, "{}", .{n}) catch return w.fail(error.OutOfMemory);
            return w.complete(Value.parseFromNumberSlice(long));
        };
        const value = Value.parseFromNumberSlice(text);
        if (value == .integer) return w.complete(value);
        try w.complete(.{ .number_string = w.arena.dupe(u8, text) catch return w.fail(error.OutOfMemory) });
    }

    /// A float as the text path writes it, and as its parser reads it again. The parser
    /// refuses `nan` and `inf`.
    fn float(w: *ValueWriter, f: f64) Error!void {
        if (!std.math.isFinite(f)) return w.fail(error.Unrepresentable);
        var buf: [64]u8 = undefined;
        // A very small or very large float can have hundreds of digits.
        const text = std.fmt.bufPrint(&buf, "{}", .{f}) catch std.fmt.allocPrint(w.arena, "{}", .{f}) catch return w.fail(error.OutOfMemory);
        const value = json.parseTree(w.arena, text) catch |e| return w.fail(if (e == error.OutOfMemory) error.OutOfMemory else error.Unrepresentable);
        switch (value) {
            .integer, .float, .number_string => try w.complete(value),
            else => return w.fail(error.Unrepresentable),
        }
    }

    /// Write `v` with the rules of `std.json.Stringify.write`. A type with a `jsonStringify`
    /// function gets this writer.
    pub fn write(w: *ValueWriter, v: anytype) Error!void {
        try w.check();
        const T = @TypeOf(v);
        switch (@typeInfo(T)) {
            .int => {
                if (w.options.emit_nonportable_numbers_as_strings and (v <= -(1 << 53) or v >= (1 << 53))) {
                    const text = std.fmt.allocPrint(w.arena, "{}", .{v}) catch return w.fail(error.OutOfMemory);
                    return w.complete(.{ .string = text });
                }
                return w.integer(v);
            },
            .comptime_int => return w.write(@as(std.math.IntFittingRange(v, v), v)),
            .float, .comptime_float => {
                if (@as(f64, @floatCast(v)) == v) return w.float(@as(f64, @floatCast(v)));
                const text = std.fmt.allocPrint(w.arena, "{}", .{v}) catch return w.fail(error.OutOfMemory);
                return w.complete(.{ .string = text });
            },
            .bool => return w.complete(.{ .bool = v }),
            .null => return w.complete(.null),
            .optional => return if (v) |payload| w.write(payload) else w.write(null),
            .@"enum" => |info| {
                if (std.meta.hasFn(T, "jsonStringify")) return v.jsonStringify(w);
                if (info.mode == .nonexhaustive) {
                    inline for (info.field_names) |fname| {
                        if (v == @field(T, fname)) break;
                    } else return w.write(@backingInt(v));
                }
                return w.tagName(@tagName(v));
            },
            .enum_literal => return w.tagName(@tagName(v)),
            .@"union" => {
                if (std.meta.hasFn(T, "jsonStringify")) return v.jsonStringify(w);
                const info = @typeInfo(T).@"union";
                const Tag = info.tag_type orelse @compileError("Unable to stringify untagged union '" ++ @typeName(T) ++ "'");
                try w.beginObject();
                inline for (info.field_names, info.field_types) |fname, ftype| {
                    if (v == @field(Tag, fname)) {
                        try w.objectField(fname);
                        if (ftype == void) {
                            try w.beginObject();
                            try w.endObject();
                        } else {
                            try w.write(@field(v, fname));
                        }
                        break;
                    }
                } else unreachable;
                return w.endObject();
            },
            .@"struct" => |info| {
                if (std.meta.hasFn(T, "jsonStringify")) return v.jsonStringify(w);
                if (info.is_tuple) try w.beginArray() else try w.beginObject();
                inline for (info.field_names, info.field_types) |fname, ftype| {
                    if (ftype == void) continue;
                    const skip = @typeInfo(ftype) == .optional and !w.options.emit_null_optional_fields and @field(v, fname) == null;
                    if (!skip) {
                        if (!info.is_tuple) try w.objectField(fname);
                        try w.write(@field(v, fname));
                    }
                }
                return if (info.is_tuple) w.endArray() else w.endObject();
            },
            .error_set => return w.tagName(@errorName(v)),
            .pointer => |ptr| switch (ptr.size) {
                .one => switch (@typeInfo(ptr.child)) {
                    .array => return w.write(@as([]const std.meta.Elem(ptr.child), v)),
                    else => return w.write(v.*),
                },
                .many, .slice => {
                    if (ptr.size == .many and ptr.sentinel() == null)
                        @compileError("unable to stringify type '" ++ @typeName(T) ++ "' without sentinel");
                    const slice = if (ptr.size == .many) std.mem.span(v) else v;
                    if (ptr.child == u8 and !w.options.emit_strings_as_arrays and std.unicode.utf8ValidateSlice(slice)) {
                        return w.string(slice);
                    }
                    try w.beginArray();
                    for (slice) |x| try w.write(x);
                    return w.endArray();
                },
                else => @compileError("Unable to stringify type '" ++ @typeName(T) ++ "'"),
            },
            .array => return w.write(&v),
            .vector => |info| {
                const array: [info.len]info.child = v;
                return w.write(&array);
            },
            else => @compileError("Unable to stringify type '" ++ @typeName(T) ++ "'"),
        }
    }

    /// The name of a tag or of an error as a string. The text path writes the bytes and its
    /// parser refuses invalid UTF-8.
    fn tagName(w: *ValueWriter, name: []const u8) Error!void {
        if (!std.unicode.utf8ValidateSlice(name)) return w.fail(error.Unrepresentable);
        try w.complete(.{ .string = name });
    }
};

const testing = std.testing;

/// The tree of the text path: serialize with the wire options, then parse.
fn textTree(arena: Allocator, value: anytype, max_depth: u16) !Value {
    const text = try json.writeAlloc(arena, value);
    return json.parseTreeMaxDepth(arena, text, max_depth);
}

/// Fail when `toValue` and the text path do not give the same tree, or when only one of
/// them fails.
fn expectSameAsText(value: anytype, max_depth: u16) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const expected = textTree(arena, value, max_depth);
    const actual = toValue(arena, value, max_depth);
    if (expected) |e| {
        try json.expectSameTree(e, try actual);
    } else |_| {
        try testing.expect(std.meta.isError(actual));
    }
}

const Color = enum { red, green };
const OpenEnum = enum(u8) { one = 1, _ };
const Shape = union(enum) { circle: f64, square: struct { side: u32 }, none };
const Raw = json.Raw;

const Hooked = struct {
    a: u8,
    pub fn jsonStringify(self: Hooked, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectFieldRaw("\"k\\u0065y\"");
        try jws.write(self.a);
        try jws.beginObjectFieldRaw();
        try jws.writer.writeAll("\"raw key\"");
        jws.endObjectFieldRaw();
        try jws.beginWriteRaw();
        try jws.writer.writeAll("[1, {\"x\": 2.5e3}]");
        jws.endWriteRaw();
        try jws.objectField("printed");
        try jws.print("{d}", .{12345678901234567890123});
        try jws.endObject();
    }
};

const Duplicate = struct {
    pub fn jsonStringify(_: Duplicate, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("a");
        try jws.write(1);
        try jws.objectField("a");
        try jws.write(2);
        try jws.endObject();
    }
};

const Everything = struct {
    s: []const u8 = "text \"quoted\" \n\\ \xc3\xa9 \xf0\x9f\x98\x80",
    invalid: []const u8 = "\xff\xfe",
    empty: []const u8 = "",
    absent: ?u32 = null,
    present: ?u32 = 7,
    nothing: void = {},
    flag: bool = true,
    small: i8 = -8,
    big: u64 = std.math.maxInt(u64),
    huge: i128 = std.math.minInt(i128),
    float: f64 = 0.1,
    whole: f64 = 3.0,
    tiny: f64 = 5e-324,
    large: f64 = 1.7976931348623157e308,
    single: f32 = 0.1,
    color: Color = .green,
    open: OpenEnum = @fromBackingInt(@intCast(9)),
    named: OpenEnum = .one,
    shapes: [3]Shape = .{ .{ .circle = 1.5 }, .{ .square = .{ .side = 4 } }, .none },
    tuple: struct { u8, []const u8 } = .{ 1, "two" },
    list: []const u16 = &.{ 1, 2, 3 },
    err: anyerror = error.Example,
    literal: @TypeOf(.literal) = .literal,
    raw: Raw = .{ .text = "{\"z\":[true,null]}" },
    hooked: Hooked = .{ .a = 5 },
    tree: Value = .{ .number_string = "1e999" },
};

test "toValue gives the tree of the text path" {
    try expectSameAsText(Everything{}, json.max_tree_depth);
    try expectSameAsText(@as(u8, 0), json.max_tree_depth);
    try expectSameAsText(@as(?u8, null), json.max_tree_depth);
    try expectSameAsText("plain", json.max_tree_depth);
    try expectSameAsText(.{}, json.max_tree_depth);
    try expectSameAsText([_]u8{ 1, 2 }, json.max_tree_depth);
    try expectSameAsText(@as([]const []const u8, &.{ "a", "\xff" }), json.max_tree_depth);
    try expectSameAsText(@as(f64, -0.0), json.max_tree_depth);
    try expectSameAsText(@as(f64, 1e21), json.max_tree_depth);
    try expectSameAsText(@as(f64, 123456789.125), json.max_tree_depth);
    try expectSameAsText(@as(f128, 0.1), json.max_tree_depth);
}

test "toValue copies a parsed tree with each kind of number and string" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const tree = try json.parseTree(arena, "{\"a\":[1,-0,1.5,1e400,123456789012345678901234,\"\\u00e9\\n\",null,true],\"b\":{\"\":{}}}");
    try expectSameAsText(tree, json.max_tree_depth);
    // A hand-made number string that the parser reads as an integer.
    try expectSameAsText(Value{ .number_string = "42" }, json.max_tree_depth);
}

test "toValue fails where the text path fails" {
    try expectSameAsText(Duplicate{}, json.max_tree_depth);
    try expectSameAsText(std.math.nan(f64), json.max_tree_depth);
    try expectSameAsText(std.math.inf(f64), json.max_tree_depth);
    try expectSameAsText(Raw{ .text = "{\"a\":" }, json.max_tree_depth);
    try expectSameAsText(Raw{ .text = "1 2" }, json.max_tree_depth);
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectError(error.Unrepresentable, toValue(arena, Duplicate{}, json.max_tree_depth));
    try testing.expectError(error.Unrepresentable, toValue(arena, std.math.inf(f64), json.max_tree_depth));
    // The text path writes a NaN as the string "nan".
    try testing.expectEqualStrings("nan", (try toValue(arena, std.math.nan(f64), json.max_tree_depth)).string);
}

test "toValue applies the depth limit of the text path" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const deep = try json.parseTree(arena, try json.nestedArrays(arena, 5));
    for (3..8) |limit| try expectSameAsText(deep, @intCast(limit));
    const nested = .{ .a = .{ .b = .{ .c = 1 } } };
    for (1..5) |limit| try expectSameAsText(nested, @intCast(limit));
    // A raw value counts the containers around it.
    const wrapped = .{ .a = .{ .b = Raw{ .text = "[[1]]" } } };
    for (2..6) |limit| try expectSameAsText(wrapped, @intCast(limit));
}

test "toValue does not point into the value" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text = try testing.allocator.dupe(u8, "abc");
    const key = try testing.allocator.dupe(u8, "key");
    var object: std.json.ObjectMap = .empty;
    try object.put(arena, key, .{ .string = text });
    const tree = try toValue(arena, .{ .s = text, .v = Value{ .object = object } }, json.max_tree_depth);
    @memset(text, 'x');
    @memset(key, 'x');
    testing.allocator.free(text);
    testing.allocator.free(key);
    try testing.expectEqualStrings("abc", tree.object.get("s").?.string);
    try testing.expectEqualStrings("abc", tree.object.get("v").?.object.get("key").?.string);
}
