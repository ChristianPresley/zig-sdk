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
///
/// The tree is the same as the tree of `std.json.parseFromSliceLeaky(Value, ...)`, and the
/// errors are the same. The function copies the text into `arena` one time. A string or a
/// number without an escape is a slice of that copy. Only a string with an escape gets
/// its own memory.
pub fn parseTreeMaxDepth(arena: Allocator, text: []const u8, max_depth: u16) ParseTreeError!Value {
    try checkDepth(text, @min(max_depth, max_tree_depth));
    const copy = try arena.dupe(u8, text);
    var scanner: std.json.Scanner = .initCompleteInput(arena, copy);
    defer scanner.deinit();
    var builder: TreeBuilder = .{ .arena = arena, .scanner = &scanner, .max_value_len = copy.len };
    const root = try builder.build();
    // The scanner gives an error for a token after the root value.
    if (try scanner.next() != .end_of_document) return error.UnexpectedToken;
    return root;
}

/// Builds a `Value` tree from the tokens of a scanner without recursion. The `stack` holds
/// the arrays and objects that are not complete.
const TreeBuilder = struct {
    arena: Allocator,
    scanner: *std.json.Scanner,
    max_value_len: usize,
    stack: std.ArrayList(Open) = .empty,

    /// An array or an object that is not complete. `key` is the key of the next member of
    /// an object, or null before the key.
    const Open = union(enum) {
        array: std.json.Array,
        object: struct { members: std.json.ObjectMap, key: ?[]const u8 },
    };

    fn build(b: *TreeBuilder) ParseTreeError!Value {
        while (true) {
            const value = try b.step() orelse continue;
            if (try b.attach(value)) |root| return root;
        }
    }

    fn token(b: *TreeBuilder) ParseTreeError!std.json.Token {
        return b.scanner.nextAllocMax(b.arena, .alloc_if_needed, b.max_value_len);
    }

    /// Read one token. The result is a complete value, or null after a key or after the
    /// start of an array or an object.
    fn step(b: *TreeBuilder) ParseTreeError!?Value {
        if (b.stack.items.len > 0) {
            const top = &b.stack.items[b.stack.items.len - 1];
            if (top.* == .object and top.object.key == null) {
                switch (try b.token()) {
                    .string, .allocated_string => |key| {
                        top.object.key = key;
                        return null;
                    },
                    .object_end => return .{ .object = b.stack.pop().?.object.members },
                    // The scanner gives a syntax error for each other token here.
                    else => return error.UnexpectedToken,
                }
            }
        }
        switch (try b.token()) {
            .string, .allocated_string => |s| return .{ .string = s },
            .number, .allocated_number => |n| return Value.parseFromNumberSlice(n),
            .true => return .{ .bool = true },
            .false => return .{ .bool = false },
            .null => return .null,
            .array_begin => {
                try b.stack.append(b.arena, .{ .array = .init(b.arena) });
                return null;
            },
            .object_begin => {
                try b.stack.append(b.arena, .{ .object = .{ .members = .empty, .key = null } });
                return null;
            },
            .array_end => return .{ .array = b.stack.pop().?.array },
            else => return error.UnexpectedToken,
        }
    }

    /// Put a complete value into the array or the object at the top of the stack. The
    /// result is the value when it is the root.
    fn attach(b: *TreeBuilder, value: Value) ParseTreeError!?Value {
        if (b.stack.items.len == 0) return value;
        switch (b.stack.items[b.stack.items.len - 1]) {
            .array => |*array| try array.append(value),
            .object => |*object| {
                const entry = try object.members.getOrPut(b.arena, object.key.?);
                if (entry.found_existing) return error.DuplicateField;
                entry.value_ptr.* = value;
                object.key = null;
            },
        }
        return null;
    }
};

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

/// The tree of the `std.json` parser, which `parseTreeMaxDepth` used before. The tests
/// compare the two trees.
fn stdTree(arena: Allocator, text: []const u8, max_depth: u16) ParseTreeError!Value {
    try checkDepth(text, @min(max_depth, max_tree_depth));
    return std.json.parseFromSliceLeaky(Value, arena, text, .{ .allocate = .alloc_always });
}

/// Fail when the trees are not identical: the same kinds, the same float bits and the same
/// order of the object members.
fn expectSameTree(expected: Value, actual: Value) !void {
    try std.testing.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(actual));
    switch (expected) {
        .null => {},
        .bool => |x| try std.testing.expectEqual(x, actual.bool),
        .integer => |x| try std.testing.expectEqual(x, actual.integer),
        .float => |x| try std.testing.expectEqual(@as(u64, @bitCast(x)), @as(u64, @bitCast(actual.float))),
        .number_string => |x| try std.testing.expectEqualStrings(x, actual.number_string),
        .string => |x| try std.testing.expectEqualStrings(x, actual.string),
        .array => |x| {
            try std.testing.expectEqual(x.items.len, actual.array.items.len);
            for (x.items, actual.array.items) |a, b| try expectSameTree(a, b);
        },
        .object => |x| {
            try std.testing.expectEqual(x.count(), actual.object.count());
            for (x.keys(), x.values(), actual.object.keys(), actual.object.values()) |ka, va, kb, vb| {
                try std.testing.expectEqualStrings(ka, kb);
                try expectSameTree(va, vb);
            }
        },
    }
}

/// Fail when `parseTreeMaxDepth` and the `std.json` parser do not give the same tree or the
/// same error for `text`.
fn expectSameParse(text: []const u8, max_depth: u16) !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const expected = stdTree(arena, text, max_depth);
    const actual = parseTreeMaxDepth(arena, text, max_depth);
    if (expected) |e| {
        try expectSameTree(e, actual catch |err| {
            std.debug.print("text {s}: std gives a tree, parseTree gives {t}\n", .{ text, err });
            return err;
        });
    } else |e| {
        if (actual) |_| {
            std.debug.print("text {s}: std gives {t}, parseTree gives a tree\n", .{ text, e });
            return error.TestUnexpectedResult;
        } else |a| try std.testing.expectEqual(e, a);
    }
}

test "parseTree gives the trees and the errors of std.json" {
    const texts = [_][]const u8{
        // Scalars, empty containers and white space.
        "null",
        "true",
        "false",
        "0",
        "\"\"",
        "{}",
        "[]",
        " \t\r\n{ \"a\" : [ 1 , 2 ] , \"b\" : { } }\n",
        "[[],{},[{}],{\"x\":[]}]",
        // Escapes in values and in keys.
        "\"line\\nbreak\\ttab\\rcr\\b\\f\"",
        "\"quote \\\" slash \\/ backslash \\\\\"",
        "{\"k\\\"ey\":\"v\\\"al\"}",
        "{\"\\n\":1,\"\\\\\":2}",
        "\"\\u0041\\u00e9\\u4e2d\"",
        "\"\\ud83d\\ude00 pair\"",
        "{\"\\ud83d\\ude00\":\"\\ud83d\\ude00\"}",
        "\"\\u0000 nul\"",
        "\"\xc3\xa9 \xe4\xb8\xad \xf0\x9f\x98\x80 without escapes\"",
        // Numbers: integers, floats, exponents and numbers that do not fit.
        "9223372036854775807",
        "-9223372036854775808",
        "9223372036854775808",
        "-9223372036854775809",
        "123456789012345678901234567890",
        "1.5",
        "-0",
        "-0.0",
        "1e2",
        "1E+2",
        "1.5e-7",
        "2.5E-308",
        "1e400",
        "-1e400",
        "[1,1.0,1e0,-1,10000000000000000000000]",
        // Duplicate keys, also when an escape gives the same key.
        "{\"a\":1,\"a\":2}",
        "{\"o\":{\"b\":1,\"b\":1}}",
        "{\"a\":1,\"\\u0061\":2}",
        "[{\"a\":1},{\"a\":2}]",
        "{\"a\":{\"a\":{\"a\":1}}}",
        // Syntax errors, data after the value and incomplete texts.
        "",
        " ",
        "{",
        "[1,",
        "{\"a\"}",
        "{\"a\":}",
        "{1:2}",
        "[1,]",
        "{\"a\":1,}",
        "{} x",
        "[] []",
        "1 2",
        "01",
        "1.",
        ".5",
        "+1",
        "1e",
        "nul",
        "\"open",
        "\"\\x\"",
        "\"\\u12\"",
        "\"\\ud800\"",
        "\"\\udc00\\ud800\"",
        "\"tab\tin string\"",
        // Invalid UTF-8 in a value and in a key.
        "\"\xff\"",
        "{\"\xc3\x28\":1}",
        "\"\xed\xa0\x80\"",
        "\"\xf0\x9f\x98\"",
    };
    for (texts) |text| try expectSameParse(text, max_tree_depth);
}

test "parseTree applies the depth limit" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try expectSameParse("[[1]]", 2);
    try expectSameParse("[[1]]", 1);
    try expectSameParse("{\"a\":{\"b\":{}}}", 3);
    try expectSameParse("{\"a\":{\"b\":{}}}", 2);
    try expectSameParse(try nestedArrays(arena, max_message_depth), max_message_depth);
    try expectSameParse(try nestedArrays(arena, max_message_depth + 1), max_message_depth);
    _ = try parseTreeMaxDepth(arena, try nestedArrays(arena, max_message_depth), max_message_depth);
    try std.testing.expectError(error.TooDeep, parseTreeMaxDepth(arena, try nestedArrays(arena, max_message_depth + 1), max_message_depth));
    try std.testing.expectError(error.TooDeep, parseTreeMaxDepth(arena, "{\"a\":{\"b\":{}}}", 2));
}

test "parseTree and std.json agree on an object with many keys and on a long escaped string" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // 5000 keys: each key needs a check for a duplicate.
    var many: std.ArrayList(u8) = .empty;
    try many.append(arena, '{');
    for (0..5000) |i| {
        if (i > 0) try many.append(arena, ',');
        try many.print(arena, "\"k{d}\":{d}", .{ i, i });
    }
    try many.append(arena, '}');
    try expectSameParse(many.items, max_message_depth);
    // The same key at the end of many keys is a duplicate.
    many.items.len -= 1;
    try many.appendSlice(arena, ",\"k0\":1}");
    try expectSameParse(many.items, max_message_depth);
    // A string of about 200 KiB with escapes: the builder makes its own copy of it.
    var long: std.ArrayList(u8) = .empty;
    try long.append(arena, '"');
    for (0..20000) |_| try long.appendSlice(arena, "ab\\n\\u00e9\\\"");
    try long.append(arena, '"');
    try expectSameParse(long.items, max_message_depth);
}

test "parseTree gives the specific errors" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectError(error.DuplicateField, parseTree(arena, "{\"a\":1,\"a\":2}"));
    try std.testing.expectError(error.DuplicateField, parseTree(arena, "[{\"x\":{\"b\":1,\"b\":2}}]"));
    try std.testing.expectError(error.SyntaxError, parseTree(arena, "{} x"));
    try std.testing.expectError(error.SyntaxError, parseTree(arena, "\"\xff\""));
    try std.testing.expectError(error.UnexpectedEndOfInput, parseTree(arena, "[1,"));
}

test "parseTree values do not use the memory of the text" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text = try gpa.dupe(u8, "{\"plain\":\"abc\",\"esc\\\"aped\":\"a\\nb\",\"n\":12345678901234567890123,\"f\":2.5,\"i\":-7}");
    const tree = try parseTree(arena, text);
    // The caller can change or free the text after the parse.
    @memset(text, 'x');
    gpa.free(text);
    try std.testing.expectEqualStrings("abc", tree.object.get("plain").?.string);
    try std.testing.expectEqualStrings("a\nb", tree.object.get("esc\"aped").?.string);
    try std.testing.expectEqualStrings("12345678901234567890123", tree.object.get("n").?.number_string);
    try std.testing.expectEqual(@as(f64, 2.5), tree.object.get("f").?.float);
    try std.testing.expectEqual(@as(i64, -7), tree.object.get("i").?.integer);
}

/// Write a random JSON text into `out`, with values of all kinds, escapes in keys and in
/// strings, and sometimes a duplicate key.
fn randomText(random: std.Random, gpa: Allocator, out: *std.ArrayList(u8), depth: u8) !void {
    const pieces = [_][]const u8{ "a", "b", "\\n", "\\\"", "\\\\", "\\u00e9", "\\ud83d\\ude00", "\xc3\xa9", "\xf0\x9f\x98\x80", " ", "\\/", "\\u0000" };
    const numbers = [_][]const u8{ "0", "-1", "42", "9223372036854775807", "9223372036854775808", "-9223372036854775809", "1.5", "-0.0", "1e3", "2.5E-3", "1e400", "123456789012345678901234567890" };
    switch (random.uintLessThan(u8, if (depth == 0) 5 else 7)) {
        0 => try out.appendSlice(gpa, ([_][]const u8{ "null", "true", "false" })[random.uintLessThan(usize, 3)]),
        1, 2 => try out.appendSlice(gpa, numbers[random.uintLessThan(usize, numbers.len)]),
        3, 4 => {
            try out.append(gpa, '"');
            for (0..random.uintLessThan(usize, 5)) |_| try out.appendSlice(gpa, pieces[random.uintLessThan(usize, pieces.len)]);
            try out.append(gpa, '"');
        },
        5 => {
            try out.append(gpa, '[');
            for (0..random.uintLessThan(usize, 4)) |i| {
                if (i > 0) try out.append(gpa, ',');
                try randomText(random, gpa, out, depth - 1);
            }
            try out.append(gpa, ']');
        },
        else => {
            try out.append(gpa, '{');
            for (0..random.uintLessThan(usize, 4)) |i| {
                if (i > 0) try out.appendSlice(gpa, " , ");
                try out.append(gpa, '"');
                // Few different keys: some objects get a duplicate key.
                try out.appendSlice(gpa, pieces[random.uintLessThan(usize, 6)]);
                try out.appendSlice(gpa, "\":");
                try randomText(random, gpa, out, depth - 1);
            }
            try out.append(gpa, '}');
        },
    }
}

test "parseTree and std.json agree on random texts and on damaged texts" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x6a736f6e);
    const random = prng.random();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    const damage = "{}[]\":,\\ \xff0e-";
    for (0..3000) |_| {
        text.clearRetainingCapacity();
        try randomText(random, gpa, &text, 5);
        try expectSameParse(text.items, max_tree_depth);
        // Change, remove or add one byte.
        const at = random.uintLessThan(usize, text.items.len);
        switch (random.uintLessThan(u8, 3)) {
            0 => text.items[at] = random.int(u8),
            1 => _ = text.orderedRemove(at),
            else => try text.insert(gpa, at, damage[random.uintLessThan(usize, damage.len)]),
        }
        try expectSameParse(text.items, max_tree_depth);
    }
}

test "parseTree and std.json agree on every JSON fixture" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var root = try std.Io.Dir.cwd().openDir(io, "test/fixtures", .{ .iterate = true });
    defer root.close(io);
    var walker = try root.walk(gpa);
    defer walker.deinit();
    var checked: usize = 0;
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.basename, ".json")) continue;
        const text = try entry.dir.readFileAlloc(io, entry.basename, gpa, .limited(16 << 20));
        defer gpa.free(text);
        expectSameParse(text, max_tree_depth) catch |e| {
            std.debug.print("fixture {s}\n", .{entry.path});
            return e;
        };
        checked += 1;
    }
    try std.testing.expect(checked >= 200);
}
