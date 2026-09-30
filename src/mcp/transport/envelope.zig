//! Request metadata mirrored into transport headers (Streamable HTTP `Mcp-*` headers and gRPC
//! `mcp-*` metadata): value encoding with the base64 sentinel, derivation from a message and
//! verification of headers against the body.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const meta_mod = @import("../protocol/meta.zig");
const methods = @import("../protocol/methods.zig");

pub const header_protocol_version = "mcp-protocol-version";
pub const header_method = "mcp-method";
pub const header_name = "mcp-name";
pub const header_param_prefix = "mcp-param-";

pub const sentinel_start = "=?base64?";
pub const sentinel_end = "?=";

/// True when `value` can travel as a header value verbatim. Such a value has only visible
/// ASCII, spaces and tabs, no whitespace at its ends, and does not have the sentinel form.
pub fn isPlainHeaderValue(value: []const u8) bool {
    if (value.len == 0) return true;
    if (value[0] == ' ' or value[0] == '\t' or value[value.len - 1] == ' ' or value[value.len - 1] == '\t') return false;
    for (value) |c| {
        if (c == ' ' or c == '\t') continue;
        if (c < 0x21 or c > 0x7e) return false;
    }
    if (std.mem.startsWith(u8, value, sentinel_start) and std.mem.endsWith(u8, value, sentinel_end)) return false;
    return true;
}

/// Encode a string value for a header. Returns `value` itself when it is plain.
pub fn encodeValue(arena: Allocator, value: []const u8) Allocator.Error![]const u8 {
    if (isPlainHeaderValue(value)) return value;
    const encoder = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, sentinel_start.len + encoder.calcSize(value.len) + sentinel_end.len);
    @memcpy(out[0..sentinel_start.len], sentinel_start);
    _ = encoder.encode(out[sentinel_start.len .. out.len - sentinel_end.len], value);
    @memcpy(out[out.len - sentinel_end.len ..], sentinel_end);
    return out;
}

pub const DecodeError = error{ InvalidEncoding, OutOfMemory };

/// Decode a header value. The function returns a plain value as it is and decodes the base64
/// of a sentinel value.
pub fn decodeValue(arena: Allocator, value: []const u8) DecodeError![]const u8 {
    if (!(std.mem.startsWith(u8, value, sentinel_start) and std.mem.endsWith(u8, value, sentinel_end))) return value;
    const body = value[sentinel_start.len .. value.len - sentinel_end.len];
    // Standard alphabet with mandatory padding: unpadded or non-alphabet input is rejected.
    const decoder = std.base64.standard.Decoder;
    const len = decoder.calcSizeForSlice(body) catch return error.InvalidEncoding;
    const out = try arena.alloc(u8, len);
    decoder.decode(out, body) catch return error.InvalidEncoding;
    return out;
}

/// The largest safe integer of JavaScript, 2^53 - 1. A mirrored integer must be in the range
/// from `-max_safe_integer` to `max_safe_integer`.
pub const max_safe_integer: i64 = (1 << 53) - 1;

/// True when `value` is in the safe integer range of JavaScript.
pub fn isSafeInteger(value: i64) bool {
    return value >= -max_safe_integer and value <= max_safe_integer;
}

/// True when a JSON number is not an integer outside the safe range. An integer outside the
/// range cannot go into a header.
pub fn isSafeNumber(value: Value) bool {
    return switch (value) {
        .integer => |i| isSafeInteger(i),
        .float => |f| @trunc(f) != f or @abs(f) <= @as(f64, @floatFromInt(max_safe_integer)),
        .number_string => false,
        else => true,
    };
}

pub const EncodeParamError = error{
    OutOfMemory,
    /// The value is an integer outside the safe range of JavaScript.
    UnsafeInteger,
};

/// Encode a JSON parameter value for an `Mcp-Param-*` header. The function accepts only
/// strings, integers and booleans. Null means "omit the header". An integer outside the
/// safe range gives `error.UnsafeInteger`.
pub fn encodeParam(arena: Allocator, value: Value) EncodeParamError!?[]const u8 {
    if (!isSafeNumber(value)) return error.UnsafeInteger;
    return switch (value) {
        .null => null,
        .string => |s| try encodeValue(arena, s),
        .integer => |i| try std.fmt.allocPrint(arena, "{d}", .{i}),
        // JSON Schema counts 42.0 as an integer.
        .float => |f| if (@trunc(f) == f) try std.fmt.allocPrint(arena, "{d}", .{@as(i64, @intFromFloat(f))}) else null,
        .bool => |b| if (b) "true" else "false",
        else => null,
    };
}

/// True when `value` has only the characters of an HTTP field value: visible ASCII, space
/// and horizontal tab. A value with other characters must use the base64 sentinel.
pub fn isFieldValue(value: []const u8) bool {
    for (value) |c| {
        if (c == 0x09) continue;
        if (c < 0x20 or c > 0x7e) return false;
    }
    return true;
}

/// A rejection of a request because of a header problem. The message is the mandated
/// `-32020` error message.
pub const Rejection = struct {
    message: []const u8,
};

/// Headers relevant to the envelope, already lowercased by the transport.
pub const Headers = struct {
    protocol_version: ?[]const u8 = null,
    method: ?[]const u8 = null,
    name: ?[]const u8 = null,
    /// `Mcp-Param-*` headers: name (lowercased, without prefix) and raw value.
    params: []const Param = &.{},

    pub const Param = struct { name: []const u8, value: []const u8 };

    pub fn param(self: Headers, name: []const u8) ?[]const u8 {
        for (self.params) |p| if (std.ascii.eqlIgnoreCase(p.name, name)) return p.value;
        return null;
    }
};

/// Verify the mirrored headers of a request against its body. `params` is the request
/// `params` object (or null) and `schema` the tool input schema when the method is
/// `tools/call` and the tool exists.
pub fn verify(arena: Allocator, headers: Headers, method: []const u8, params: ?Value, schema: ?Value) Allocator.Error!?Rejection {
    const meta_version: ?[]const u8 = blk: {
        const p = params orelse break :blk null;
        if (p != .object) break :blk null;
        const m = p.object.get("_meta") orelse break :blk null;
        break :blk json.getString(m, meta_mod.key_protocol_version);
    };
    const hv = headers.protocol_version orelse return .{ .message = "Header mismatch: the MCP-Protocol-Version header is missing" };
    if (!isPlainHeaderValue(hv)) return .{ .message = "Header mismatch: MCP-Protocol-Version has an invalid value" };
    if (meta_version) |mv| {
        if (!std.mem.eql(u8, hv, mv)) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: MCP-Protocol-Version header value '{s}' does not match body value '{s}'", .{ hv, mv }) };
    }
    const hm = headers.method orelse return .{ .message = "Header mismatch: the Mcp-Method header is missing" };
    if (!isFieldValue(hm)) return .{ .message = "Header mismatch: Mcp-Method has invalid characters" };
    if (!std.mem.eql(u8, hm, method)) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Method header value '{s}' does not match body method '{s}'", .{ hm, method }) };

    const source: methods.HeaderNameSource = if (methods.Method.fromName(method)) |m| m.headerNameSource() else if (isTaskMethod(method)) .task_id else .none;
    if (source != .none) {
        const key: []const u8 = switch (source) {
            .name => "name",
            .uri => "uri",
            .task_id => "taskId",
            .none => unreachable,
        };
        const body_value = blk: {
            const p = params orelse break :blk null;
            break :blk json.getString(p, key);
        };
        const raw = headers.name orelse return .{ .message = "Header mismatch: the Mcp-Name header is missing" };
        if (!isFieldValue(raw)) return .{ .message = "Header mismatch: Mcp-Name has invalid characters" };
        const decoded = decodeValue(arena, raw) catch return .{ .message = "Header mismatch: Mcp-Name header has an invalid encoding" };
        if (body_value) |bv| {
            if (!std.mem.eql(u8, decoded, bv)) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Name header value '{s}' does not match body value '{s}'", .{ decoded, bv }) };
        }
    }

    // Mcp-Param-* headers declared by the tool schema.
    if (schema) |s| {
        const annotations = switch (try headerAnnotations(arena, s)) {
            .valid => |list| list,
            // Registration rejects such a schema. The server mirrors no parameter of it.
            .invalid => &.{},
        };
        const arguments: ?Value = blk: {
            const p = params orelse break :blk null;
            if (p != .object) break :blk null;
            break :blk p.object.get("arguments");
        };
        for (annotations) |annotation| {
            const name = annotation.header;
            const body_value: ?Value = if (arguments) |a| valueAtPath(a, annotation.path) else null;
            const header_value = headers.param(name);
            if (header_value) |raw| {
                if (!isFieldValue(raw)) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Param-{s} has invalid characters", .{name}) };
            }
            const bv = body_value orelse {
                if (header_value != null) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Param-{s} is present but the body has no value", .{name}) };
                continue;
            };
            if (!isSafeNumber(bv)) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: the value of Mcp-Param-{s} is an integer outside the safe range", .{name}) };
            const raw = header_value orelse return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: the Mcp-Param-{s} header is missing", .{name}) };
            const decoded = decodeValue(arena, raw) catch return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Param-{s} has an invalid encoding", .{name}) };
            if (!paramMatches(decoded, bv)) {
                return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Param-{s} header value '{s}' does not match the body", .{ name, decoded }) };
            }
        }
    }
    return null;
}

fn paramMatches(decoded: []const u8, body: Value) bool {
    return switch (body) {
        .string => |s| std.mem.eql(u8, decoded, s),
        .bool => |b| std.mem.eql(u8, decoded, if (b) "true" else "false"),
        .integer => |i| blk: {
            if (std.fmt.parseInt(i64, decoded, 10)) |h| {
                break :blk h == i;
            } else |_| {}
            if (std.fmt.parseFloat(f64, decoded)) |h| {
                break :blk h == @as(f64, @floatFromInt(i));
            } else |_| {}
            break :blk false;
        },
        .float => |f| blk: {
            const h = std.fmt.parseFloat(f64, decoded) catch break :blk false;
            break :blk h == f;
        },
        .number_string => |s| std.mem.eql(u8, decoded, s),
        else => false,
    };
}

/// Validate an `x-mcp-header` annotation per the specification: non-empty token characters,
/// no control characters.
pub fn isValidHeaderAnnotation(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (!isTchar(c)) return false;
    }
    return true;
}

fn isTchar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or std.mem.findScalar(u8, "!#$%&'*+-.^_`|~", c) != null;
}

/// The deepest schema nesting that the `x-mcp-header` walk follows.
pub const max_header_schema_depth = 64;
/// The largest number of `x-mcp-header` annotations in one input schema.
pub const max_header_annotations = 64;

/// One `x-mcp-header` annotation on a property that a chain of `properties` keywords
/// reaches from the schema root.
pub const HeaderAnnotation = struct {
    /// The property names from the root to the annotated property.
    path: []const []const u8,
    /// The name part of the `Mcp-Param-{name}` header.
    header: []const u8,
};

/// The reason why an `x-mcp-header` annotation is invalid.
pub const HeaderProblem = enum {
    not_string,
    invalid_name,
    not_primitive,
    duplicate,
    not_reachable,
    too_many,
    too_deep,

    /// A short text for a log message.
    pub fn text(self: HeaderProblem) []const u8 {
        return switch (self) {
            .not_string => "the x-mcp-header value is not a string",
            .invalid_name => "the x-mcp-header value is empty or is not an HTTP token",
            .not_primitive => "the annotated property does not have the type string, integer or boolean",
            .duplicate => "two x-mcp-header values are equal without regard to case",
            .not_reachable => "the annotation is not on a property that a chain of properties keywords reaches from the schema root",
            .too_many => "the schema has too many x-mcp-header annotations",
            .too_deep => "the schema is too deep",
        };
    }
};

/// The result of the `x-mcp-header` walk over a tool input schema.
pub const HeaderAnnotations = union(enum) {
    /// All annotations are valid. The list has them in schema order.
    valid: []const HeaderAnnotation,
    /// The first invalid annotation. The tool must not show in `tools/list`.
    invalid: Invalid,

    pub const Invalid = struct {
        problem: HeaderProblem,
        /// The `x-mcp-header` value, when it is a string.
        annotation: ?[]const u8 = null,
    };
};

/// Find and check every `x-mcp-header` annotation of a tool input schema. The walk goes into
/// every subschema. An annotation is valid only on a property that a chain of `properties`
/// keywords reaches from the root. A chain through `items`, `anyOf`, `if`, `$defs` or
/// another keyword makes the annotation invalid. The walk ignores the data of `const`, `enum`,
/// `default` and `examples`.
pub fn headerAnnotations(arena: Allocator, schema: Value) Allocator.Error!HeaderAnnotations {
    var walker: HeaderWalker = .{ .arena = arena };
    var path: [max_header_schema_depth][]const u8 = undefined;
    try walker.walk(schema, &path, 0, 0);
    if (walker.invalid) |invalid| return .{ .invalid = invalid };
    return .{ .valid = walker.found.items };
}

/// True when every `x-mcp-header` annotation of a tool input schema is valid. Transports that
/// carry headers must not show a tool with an invalid annotation in `tools/list`.
pub fn schemaHeadersValid(arena: Allocator, schema: Value) Allocator.Error!bool {
    return (try headerAnnotations(arena, schema)) == .valid;
}

/// The value at `path` in the arguments of a tool call. Null when a step is absent or is
/// not an object, and when the value is null.
pub fn valueAtPath(arguments: Value, path: []const []const u8) ?Value {
    var current = arguments;
    for (path) |key| {
        if (current != .object) return null;
        current = current.object.get(key) orelse return null;
    }
    return if (current == .null) null else current;
}

/// Keywords whose operand is data and not a schema.
const data_keywords = std.StaticStringMap(void).initComptime(.{
    .{"const"}, .{"enum"}, .{"default"}, .{"examples"}, .{"x-mcp-header"},
});

/// Keywords whose operand is an object of subschemas under names that are not keywords.
const schema_map_keywords = std.StaticStringMap(void).initComptime(.{
    .{"patternProperties"}, .{"$defs"}, .{"definitions"}, .{"dependentSchemas"}, .{"dependencies"}, .{"dependentRequired"},
});

const HeaderWalker = struct {
    arena: Allocator,
    found: std.ArrayList(HeaderAnnotation) = .empty,
    invalid: ?HeaderAnnotations.Invalid = null,

    fn fail(self: *HeaderWalker, problem: HeaderProblem, annotation: ?[]const u8) void {
        if (self.invalid == null) self.invalid = .{ .problem = problem, .annotation = annotation };
    }

    /// Walk one schema node. `path_len` is the length of the `properties` chain to the node,
    /// or null when another keyword is on the way from the root.
    fn walk(self: *HeaderWalker, node: Value, path: *[max_header_schema_depth][]const u8, path_len: ?usize, depth: usize) Allocator.Error!void {
        if (self.invalid != null) return;
        if (node != .object) return;
        if (depth >= max_header_schema_depth) return self.fail(.too_deep, null);
        if (node.object.get("x-mcp-header")) |annotation| {
            try self.record(node, annotation, path[0 .. path_len orelse 0], path_len != null);
        }
        var it = node.object.iterator();
        while (it.next()) |kv| {
            const key = kv.key_ptr.*;
            const value = kv.value_ptr.*;
            if (data_keywords.has(key)) continue;
            if (std.mem.eql(u8, key, "properties") or schema_map_keywords.has(key)) {
                if (value != .object) continue;
                const chain = std.mem.eql(u8, key, "properties");
                var entries = value.object.iterator();
                while (entries.next()) |entry| {
                    var child_len: ?usize = null;
                    if (chain) if (path_len) |n| {
                        path[n] = entry.key_ptr.*;
                        child_len = n + 1;
                    };
                    try self.walk(entry.value_ptr.*, path, child_len, depth + 1);
                }
                continue;
            }
            switch (value) {
                .object => try self.walk(value, path, null, depth + 1),
                .array => |list| for (list.items) |item| try self.walk(item, path, null, depth + 1),
                else => {},
            }
        }
    }

    fn record(self: *HeaderWalker, node: Value, annotation: Value, path: []const []const u8, reachable: bool) Allocator.Error!void {
        const name: ?[]const u8 = if (annotation == .string) annotation.string else null;
        // The root is not a property.
        if (!reachable or path.len == 0) return self.fail(.not_reachable, name);
        const header = name orelse return self.fail(.not_string, null);
        if (!isValidHeaderAnnotation(header)) return self.fail(.invalid_name, header);
        const t = json.getString(node, "type") orelse return self.fail(.not_primitive, header);
        if (!(std.mem.eql(u8, t, "string") or std.mem.eql(u8, t, "integer") or std.mem.eql(u8, t, "boolean"))) return self.fail(.not_primitive, header);
        for (self.found.items) |f| if (std.ascii.eqlIgnoreCase(f.header, header)) return self.fail(.duplicate, header);
        if (self.found.items.len == max_header_annotations) return self.fail(.too_many, header);
        try self.found.append(self.arena, .{ .path = try self.arena.dupe([]const u8, path), .header = header });
    }
};

test "sentinel encoding" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("us-west1", try encodeValue(arena, "us-west1"));
    try std.testing.expectEqualStrings("us west 1", try encodeValue(arena, "us west 1"));
    const enc = try encodeValue(arena, "Hello, 世界");
    try std.testing.expect(std.mem.startsWith(u8, enc, "=?base64?"));
    try std.testing.expectEqualStrings("Hello, 世界", try decodeValue(arena, enc));
    try std.testing.expect(std.mem.startsWith(u8, try encodeValue(arena, " padded "), "=?base64?"));
    try std.testing.expect(std.mem.startsWith(u8, try encodeValue(arena, "=?base64?x?="), "=?base64?"));
    try std.testing.expect(std.mem.startsWith(u8, try encodeValue(arena, "line1\nline2"), "=?base64?"));
    try std.testing.expectEqualStrings("", try encodeValue(arena, ""));
    // SEP-2243 test-case table: padding is mandatory and the alphabet is strict.
    try std.testing.expectEqualStrings("Hello", try decodeValue(arena, "=?base64?SGVsbG8=?="));
    try std.testing.expectError(error.InvalidEncoding, decodeValue(arena, "=?base64?SGVsbG8?="));
    try std.testing.expectError(error.InvalidEncoding, decodeValue(arena, "=?base64?SGVs!!!bG8=?="));
    try std.testing.expectEqualStrings("SGVsbG8=", try decodeValue(arena, "SGVsbG8="));
    try std.testing.expectEqualStrings("=?base64?SGVsbG8=", try decodeValue(arena, "=?base64?SGVsbG8="));
}

test "verify headers against body" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const params = try json.parseTree(arena,
        \\{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"echo","arguments":{"region":"us-west1","priority":42,"verbose":null}}
    );
    const schema = try json.parseTree(arena,
        \\{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"priority":{"type":"integer","x-mcp-header":"Priority"},"verbose":{"type":"boolean","x-mcp-header":"Verbose"}}}
    );
    const ok: Headers = .{ .protocol_version = "2026-07-28", .method = "tools/call", .name = "echo", .params = &.{ .{ .name = "region", .value = "us-west1" }, .{ .name = "priority", .value = "42.0" } } };
    try std.testing.expect((try verify(arena, ok, "tools/call", params, schema)) == null);
    const bad_name: Headers = .{ .protocol_version = "2026-07-28", .method = "tools/call", .name = "other", .params = &.{} };
    try std.testing.expect((try verify(arena, bad_name, "tools/call", params, schema)) != null);
    const missing_version: Headers = .{ .method = "tools/call", .name = "echo" };
    try std.testing.expect((try verify(arena, missing_version, "tools/call", params, null)) != null);
    const extra_param: Headers = .{ .protocol_version = "2026-07-28", .method = "tools/call", .name = "echo", .params = &.{ .{ .name = "region", .value = "us-west1" }, .{ .name = "priority", .value = "42" }, .{ .name = "verbose", .value = "true" } } };
    try std.testing.expect((try verify(arena, extra_param, "tools/call", params, schema)) != null);
    try std.testing.expect(try schemaHeadersValid(arena, schema));
    const dup = try json.parseTree(arena, "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"x-mcp-header\":\"X\"},\"b\":{\"type\":\"string\",\"x-mcp-header\":\"x\"}}}");
    try std.testing.expect(!try schemaHeadersValid(arena, dup));
    const num = try json.parseTree(arena, "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"number\",\"x-mcp-header\":\"X\"}}}");
    try std.testing.expect(!try schemaHeadersValid(arena, num));
}

test "header annotation walk, value paths, field values and safe integers" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const nested = try json.parseTree(arena,
        \\{"type":"object","properties":{"a":{"type":"object","properties":{"b":{"type":"integer","x-mcp-header":"B"}}}}}
    );
    const found = (try headerAnnotations(arena, nested)).valid;
    try std.testing.expectEqual(1, found.len);
    try std.testing.expectEqualStrings("B", found[0].header);
    try std.testing.expectEqual(2, found[0].path.len);
    try std.testing.expectEqualStrings("a", found[0].path[0]);
    try std.testing.expectEqualStrings("b", found[0].path[1]);
    const args = try json.parseTree(arena, "{\"a\":{\"b\":5},\"b\":6}");
    try std.testing.expectEqual(5, valueAtPath(args, found[0].path).?.integer);
    try std.testing.expect(valueAtPath(try json.parseTree(arena, "{\"a\":7}"), found[0].path) == null);

    // A schema deeper than the walk limit is invalid.
    var deep: std.ArrayList(u8) = .empty;
    for (0..max_header_schema_depth) |_| try deep.appendSlice(arena, "{\"properties\":{\"p\":");
    try deep.appendSlice(arena, "{\"type\":\"string\"}");
    for (0..max_header_schema_depth) |_| try deep.appendSlice(arena, "}}");
    const too_deep = try headerAnnotations(arena, try json.parseTree(arena, deep.items));
    try std.testing.expectEqual(HeaderProblem.too_deep, too_deep.invalid.problem);

    try std.testing.expect(isFieldValue("us west\t1"));
    try std.testing.expect(!isFieldValue("Gr\u{fc}\u{df}e"));
    try std.testing.expect(!isFieldValue("a\x7fb"));
    try std.testing.expect(!isFieldValue("a\rb"));
    try std.testing.expect(isSafeInteger(max_safe_integer) and isSafeInteger(-max_safe_integer));
    try std.testing.expect(!isSafeInteger(max_safe_integer + 1) and !isSafeInteger(-max_safe_integer - 1));
    try std.testing.expect(isSafeNumber(.{ .float = 0.5 }));
    try std.testing.expect(!isSafeNumber(.{ .float = 9007199254740992.0 }));
    try std.testing.expect(!isSafeNumber(.{ .number_string = "1e999" }));
}

/// The Tasks extension methods that mirror `params.taskId` into `Mcp-Name`.
pub fn isTaskMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "tasks/get") or std.mem.eql(u8, method, "tasks/update") or std.mem.eql(u8, method, "tasks/cancel");
}
