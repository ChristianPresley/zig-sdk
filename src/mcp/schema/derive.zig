//! Derive a JSON Schema (2020-12) document from a Zig type at compile time.
//!
//! Descriptions, header annotations and patterns come from an optional `pub const json_schema`
//! declaration on the struct:
//! ```zig
//! const Args = struct {
//!     a: i64,
//!     unit: ?[]const u8 = null,
//!     pub const json_schema = .{
//!         .description = "Add two integers.",
//!         .fields = .{
//!             .a = .{ .description = "Left operand" },
//!             .unit = .{ .header = "X-Unit", .pattern = "^[a-z]+$" },
//!         },
//!     };
//! };
//! ```
//!
//! Only a string field can have a `pattern`. The server compiles it when it registers
//! the tool.
const std = @import("std");

/// The JSON Schema text for `T`, computed at compile time.
pub fn schemaText(comptime T: type) []const u8 {
    const text = comptime blk: {
        @setEvalBranchQuota(100_000);
        break :blk render(T, null, 0);
    };
    return text;
}

fn fieldMeta(comptime T: type, comptime name: []const u8) ?FieldMeta {
    if (!@hasDecl(T, "json_schema")) return null;
    const js = T.json_schema;
    if (!@hasField(@TypeOf(js), "fields")) return null;
    const fields = js.fields;
    if (!@hasField(@TypeOf(fields), name)) return null;
    const f = @field(fields, name);
    var m: FieldMeta = .{};
    if (@hasField(@TypeOf(f), "description")) m.description = f.description;
    if (@hasField(@TypeOf(f), "header")) m.header = f.header;
    if (@hasField(@TypeOf(f), "pattern")) m.pattern = f.pattern;
    return m;
}

const FieldMeta = struct {
    description: ?[]const u8 = null,
    header: ?[]const u8 = null,
    pattern: ?[]const u8 = null,
};

fn typeDescription(comptime T: type) ?[]const u8 {
    if (!@hasDecl(T, "json_schema")) return null;
    const js = T.json_schema;
    if (!@hasField(@TypeOf(js), "description")) return null;
    return js.description;
}

fn jsonString(comptime s: []const u8) []const u8 {
    {
        var out: []const u8 = "\"";
        for (s) |c| {
            out = out ++ switch (c) {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                else => if (c < 0x20) std.fmt.comptimePrint("\\u{x:0>4}", .{c}) else &[_]u8{c},
            };
        }
        return out ++ "\"";
    }
}

fn render(comptime T: type, comptime meta: ?FieldMeta, comptime depth: usize) []const u8 {
    {
        if (depth > 16) @compileError("schema derivation: type nesting too deep for " ++ @typeName(T));
        var extra: []const u8 = "";
        var pattern: []const u8 = "";
        if (meta) |m| {
            if (m.description) |d| extra = extra ++ ",\"description\":" ++ jsonString(d);
            if (m.header) |h| extra = extra ++ ",\"x-mcp-header\":" ++ jsonString(h);
            if (m.pattern) |p| pattern = ",\"pattern\":" ++ jsonString(p);
        }
        const passes_meta = switch (@typeInfo(T)) {
            .optional => true,
            .pointer => |info| info.size == .one,
            else => false,
        };
        const is_string = switch (@typeInfo(T)) {
            .pointer => |info| info.size == .slice and info.child == u8,
            .array => |info| info.child == u8,
            else => false,
        };
        if (pattern.len > 0 and !passes_meta and !is_string) {
            @compileError("schema derivation: a pattern needs a string field, not " ++ @typeName(T));
        }
        switch (@typeInfo(T)) {
            .bool => return "{\"type\":\"boolean\"" ++ extra ++ "}",
            .int => |info| {
                var bounds: []const u8 = "";
                if (info.bits < 53) {
                    bounds = std.fmt.comptimePrint(",\"minimum\":{d},\"maximum\":{d}", .{ std.math.minInt(T), std.math.maxInt(T) });
                }
                return "{\"type\":\"integer\"" ++ bounds ++ extra ++ "}";
            },
            .float => return "{\"type\":\"number\"" ++ extra ++ "}",
            .optional => |info| return render(info.child, meta, depth + 1),
            .pointer => |info| {
                if (info.size == .slice) {
                    if (info.child == u8) return "{\"type\":\"string\"" ++ pattern ++ extra ++ "}";
                    return "{\"type\":\"array\",\"items\":" ++ render(info.child, null, depth + 1) ++ extra ++ "}";
                }
                if (info.size == .one) return render(info.child, meta, depth + 1);
                @compileError("schema derivation: unsupported pointer type " ++ @typeName(T));
            },
            .array => |info| {
                if (info.child == u8) return "{\"type\":\"string\"" ++ pattern ++ extra ++ "}";
                return "{\"type\":\"array\",\"items\":" ++ render(info.child, null, depth + 1) ++ extra ++ "}";
            },
            .@"enum" => |info| {
                var values: []const u8 = "";
                for (info.fields, 0..) |f, i| {
                    values = values ++ (if (i > 0) "," else "") ++ jsonString(f.name);
                }
                return "{\"type\":\"string\",\"enum\":[" ++ values ++ "]" ++ extra ++ "}";
            },
            .@"struct" => |info| {
                if (T == std.json.Value) return "{}";
                if (info.is_tuple) @compileError("schema derivation: tuples are not supported");
                var props: []const u8 = "";
                var required: []const u8 = "";
                var required_count: usize = 0;
                for (info.fields, 0..) |f, i| {
                    const fm = fieldMeta(T, f.name);
                    props = props ++ (if (i > 0) "," else "") ++ jsonString(f.name) ++ ":" ++ render(f.type, fm, depth + 1);
                    const is_optional = @typeInfo(f.type) == .optional;
                    if (!is_optional and f.default_value_ptr == null) {
                        required = required ++ (if (required_count > 0) "," else "") ++ jsonString(f.name);
                        required_count += 1;
                    }
                }
                var out: []const u8 = "{\"type\":\"object\",\"properties\":{" ++ props ++ "}";
                if (required_count > 0) out = out ++ ",\"required\":[" ++ required ++ "]";
                if (typeDescription(T)) |d| out = out ++ ",\"description\":" ++ jsonString(d);
                if (meta) |m| {
                    if (m.description) |d| out = out ++ ",\"description\":" ++ jsonString(d);
                }
                return out ++ ",\"additionalProperties\":false}";
            },
            .@"union" => |info| {
                if (info.tag_type == null) @compileError("schema derivation: untagged unions are not supported");
                var variants: []const u8 = "";
                for (info.fields, 0..) |f, i| {
                    variants = variants ++ (if (i > 0) "," else "") ++ render(f.type, null, depth + 1);
                }
                return "{\"oneOf\":[" ++ variants ++ "]" ++ extra ++ "}";
            },
            else => @compileError("schema derivation: unsupported type " ++ @typeName(T)),
        }
    }
}

test "derive schema for a struct" {
    const Args = struct {
        a: i64,
        b: i32 = 0,
        unit: ?[]const u8 = null,
        flags: []const bool = &.{},
        mode: enum { fast, slow } = .fast,
        pub const json_schema = .{
            .description = "Add two integers.",
            .fields = .{ .a = .{ .description = "Left operand" }, .unit = .{ .header = "X-Unit" } },
        };
    };
    const text = schemaText(Args);
    try std.testing.expectEqualStrings(
        "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"integer\",\"description\":\"Left operand\"},\"b\":{\"type\":\"integer\",\"minimum\":-2147483648,\"maximum\":2147483647},\"unit\":{\"type\":\"string\",\"x-mcp-header\":\"X-Unit\"},\"flags\":{\"type\":\"array\",\"items\":{\"type\":\"boolean\"}},\"mode\":{\"type\":\"string\",\"enum\":[\"fast\",\"slow\"]}},\"required\":[\"a\"],\"description\":\"Add two integers.\",\"additionalProperties\":false}",
        text,
    );
    // The text must be valid JSON.
    const gpa = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
}

test "derive a pattern for a string field" {
    const Args = struct {
        code: []const u8,
        note: ?[]const u8 = null,
        pub const json_schema = .{
            .fields = .{ .code = .{ .pattern = "^[A-Z]{3}\\d$", .description = "Code" }, .note = .{ .pattern = "^\\S" } },
        };
    };
    const text = schemaText(Args);
    try std.testing.expectEqualStrings(
        "{\"type\":\"object\",\"properties\":{\"code\":{\"type\":\"string\",\"pattern\":\"^[A-Z]{3}\\\\d$\",\"description\":\"Code\"},\"note\":{\"type\":\"string\",\"pattern\":\"^\\\\S\"}},\"required\":[\"code\"],\"additionalProperties\":false}",
        text,
    );
    const validator = @import("validator.zig");
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const schema = try validator.compileText(arena, text, .{});
    const good = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"code\":\"ABC1\",\"note\":\"x\"}", .{});
    try std.testing.expect((try validator.validate(arena, &schema, good)).valid);
    const bad = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"code\":\"abc1\",\"note\":\" x\"}", .{});
    try std.testing.expectEqual(2, (try validator.validate(arena, &schema, bad)).failures.len);
}
