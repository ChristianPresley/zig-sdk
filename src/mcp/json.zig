//! JSON helpers shared by the protocol types: discriminated unions, raw passthrough and
//! stringify defaults.
const std = @import("std");
const Allocator = std.mem.Allocator;
pub const Value = std.json.Value;
pub const ParseOptions = std.json.ParseOptions;

/// Stringify options used for every wire message: minified, optional `null` fields omitted.
pub const wire_options: std.json.Stringify.Options = .{
    .whitespace = .minified,
    .emit_null_optional_fields = false,
};

/// Parse options for every inbound message: the parser ignores unknown fields for forward
/// compatibility, and duplicate fields keep the last value.
pub const wire_parse_options: ParseOptions = .{
    .ignore_unknown_fields = true,
    .duplicate_field_behavior = .use_last,
};

/// Serialize `value` into `writer` with the wire options.
pub fn write(value: anytype, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try std.json.Stringify.value(value, wire_options, writer);
}

/// Serialize `value` into a newly allocated buffer with the wire options.
pub fn writeAlloc(gpa: Allocator, value: anytype) Allocator.Error![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    write(value, &aw.writer) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

/// Parse a `Value` tree into `T` with the wire parse options. All memory comes from `arena`.
pub fn parseValue(comptime T: type, arena: Allocator, value: Value) ParseValueError!T {
    return std.json.parseFromValueLeaky(T, arena, value, wire_parse_options);
}

pub const ParseValueError = std.json.ParseFromValueError;

/// The maximum nesting depth that `std.json.Stringify` can write in a safe build mode.
/// `parseTree` rejects a deeper text, thus the SDK can serialize each tree that it parses.
pub const max_tree_depth: u16 = 256;

/// The maximum nesting depth of a JSON-RPC message, also when `Limits.json_max_depth` is
/// larger. The margin to `max_tree_depth` is for the objects that the SDK puts around a
/// value from a message, for example a response around a result.
pub const max_message_depth: u16 = 200;

/// Parse a complete JSON text into a `Value` tree. All memory comes from `arena`. A text
/// that nests deeper than `max_tree_depth` gives `error.TooDeep`.
pub fn parseTree(arena: Allocator, text: []const u8) ParseTreeError!Value {
    return parseTreeMaxDepth(arena, text, max_tree_depth);
}

/// Parse a complete JSON text into a `Value` tree. A text that nests deeper than
/// `max_depth` gives `error.TooDeep`. All memory comes from `arena`.
pub fn parseTreeMaxDepth(arena: Allocator, text: []const u8, max_depth: u16) ParseTreeError!Value {
    try checkDepth(text, @min(max_depth, max_tree_depth));
    return std.json.parseFromSliceLeaky(Value, arena, text, .{ .allocate = .alloc_always });
}

pub const ParseTreeError = std.json.ParseError(std.json.Scanner) || error{TooDeep};

/// Give `error.TooDeep` when the arrays and objects of `text` nest deeper than `max_depth`.
/// The depth of a scalar is 0, and the depth of `[]` and of `{}` is 1. The function does
/// not check the syntax. It ignores the brackets in strings. It uses no recursion and no
/// memory, thus it is safe on all input.
pub fn checkDepth(text: []const u8, max_depth: u16) error{TooDeep}!void {
    var depth: usize = 0;
    var in_string = false;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (in_string) {
            switch (c) {
                // The escaped character cannot end the string.
                '\\' => i += 1,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '[', '{' => {
                depth += 1;
                if (depth > max_depth) return error.TooDeep;
            },
            ']', '}' => depth -|= 1,
            else => {},
        }
    }
}

/// Hooks for a `union(enum)` whose field names are the values of the discriminator `key`.
///
/// Use it as:
/// ```zig
/// pub const jsonParse = json.Discriminated(@This(), "type").jsonParse;
/// pub const jsonParseFromValue = json.Discriminated(@This(), "type").jsonParseFromValue;
/// pub const jsonStringify = json.Discriminated(@This(), "type").jsonStringify;
/// ```
pub fn Discriminated(comptime U: type, comptime key: []const u8) type {
    return struct {
        pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) !U {
            const value = try std.json.innerParse(Value, allocator, source, options);
            return jsonParseFromValue(allocator, value, options);
        }

        pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !U {
            if (source != .object) return error.UnexpectedToken;
            const tag_value = source.object.get(key) orelse return error.MissingField;
            if (tag_value != .string) return error.UnexpectedToken;
            const tag = tag_value.string;
            inline for (@typeInfo(U).@"union".fields) |field| {
                if (std.mem.eql(u8, field.name, tag)) {
                    const payload = try std.json.innerParseFromValue(field.type, allocator, source, options);
                    return @unionInit(U, field.name, payload);
                }
            }
            return error.InvalidEnumTag;
        }

        pub fn jsonStringify(self: U, jws: anytype) !void {
            switch (self) {
                inline else => |payload| try jws.write(payload),
            }
        }
    };
}

/// Hooks for a `union(enum)` that serializes as its active payload. A `classify` function
/// from the caller inspects the object and selects the payload to parse.
pub fn Classified(comptime U: type, comptime classify: fn (Value) ?std.meta.Tag(U)) type {
    return struct {
        pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) !U {
            const value = try std.json.innerParse(Value, allocator, source, options);
            return jsonParseFromValue(allocator, value, options);
        }

        pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !U {
            const tag = classify(source) orelse return error.UnexpectedToken;
            switch (tag) {
                inline else => |t| {
                    const Payload = @FieldType(U, @tagName(t));
                    const payload = try std.json.innerParseFromValue(Payload, allocator, source, options);
                    return @unionInit(U, @tagName(t), payload);
                },
            }
        }

        pub fn jsonStringify(self: U, jws: anytype) !void {
            switch (self) {
                inline else => |payload| try jws.write(payload),
            }
        }
    };
}

/// True when `value` is an object that has the key.
pub fn hasKey(value: Value, key: []const u8) bool {
    return value == .object and value.object.get(key) != null;
}

/// Return the string at `key` when the object has a string there.
pub fn getString(value: Value, key: []const u8) ?[]const u8 {
    if (value != .object) return null;
    const v = value.object.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

/// A JSON value stored as its verbatim (minified) text. Serialized without re-encoding.
pub const Raw = struct {
    text: []const u8,

    pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) !Raw {
        const value = try std.json.innerParse(Value, allocator, source, options);
        return jsonParseFromValue(allocator, value, options);
    }

    pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !Raw {
        _ = options;
        return .{ .text = try writeAlloc(allocator, source) };
    }

    pub fn jsonStringify(self: Raw, jws: anytype) !void {
        try jws.print("{s}", .{self.text});
    }
};

/// A text of `depth` nested arrays, for the tests of the depth limits.
pub fn nestedArrays(gpa: Allocator, depth: usize) Allocator.Error![]u8 {
    const text = try gpa.alloc(u8, 2 * depth);
    @memset(text[0..depth], '[');
    @memset(text[depth..], ']');
    return text;
}

test "the depth check counts brackets outside strings" {
    try checkDepth("1", 0);
    try checkDepth("{\"a\":[1]}", 2);
    try std.testing.expectError(error.TooDeep, checkDepth("{\"a\":[1]}", 1));
    try std.testing.expectError(error.TooDeep, checkDepth("[]", 0));
    // Brackets in strings and after an escaped quote do not count.
    try checkDepth("[\"[[[{{{\"]", 1);
    try checkDepth("[\"\\\"[[\"]", 1);
    try checkDepth("[\"\\\\\",[1]]", 2);
    try std.testing.expectError(error.TooDeep, checkDepth("[\"\\\\\",[1]]", 1));
    // Closed containers give their depth back.
    try checkDepth("[[],[],[[]]]", 3);
}

test "parseTree rejects a text that std.json.Stringify cannot write" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ok = try nestedArrays(arena, max_tree_depth);
    const tree = try parseTree(arena, ok);
    // The serializer accepts each tree that the parser gives.
    try std.testing.expectEqualStrings(ok, try writeAlloc(arena, tree));
    try std.testing.expectError(error.TooDeep, parseTree(arena, try nestedArrays(arena, max_tree_depth + 1)));
    // A deep text does not exhaust the stack.
    try std.testing.expectError(error.TooDeep, parseTree(arena, try nestedArrays(arena, 1 << 20)));
    try std.testing.expectError(error.TooDeep, parseTreeMaxDepth(arena, "[[1]]", 1));
}

test "Raw round trip" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const tree = try parseTree(arena, "{\"a\":[1,2,{\"b\":null}]}");
    const raw = try parseValue(Raw, arena, tree);
    try std.testing.expectEqualStrings("{\"a\":[1,2,{\"b\":null}]}", raw.text);
    const out = try writeAlloc(gpa, raw);
    defer gpa.free(out);
    try std.testing.expectEqualStrings("{\"a\":[1,2,{\"b\":null}]}", out);
}
