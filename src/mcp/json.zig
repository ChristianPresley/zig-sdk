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

/// Parse options used for every inbound message: unknown fields are ignored for forward
/// compatibility, duplicate fields keep the last value.
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

/// Parse a complete JSON text into a `Value` tree. All memory comes from `arena`.
pub fn parseTree(arena: Allocator, text: []const u8) ParseTreeError!Value {
    return std.json.parseFromSliceLeaky(Value, arena, text, .{ .allocate = .alloc_always });
}

pub const ParseTreeError = std.json.ParseError(std.json.Scanner);

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

/// Hooks for a `union(enum)` that is serialized as its active payload and parsed by a
/// caller-supplied `classify` function that inspects the object.
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
