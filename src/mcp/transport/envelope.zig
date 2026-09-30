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

/// Encode a JSON parameter value for an `Mcp-Param-*` header. The function accepts only
/// strings, integers and booleans. Null means "omit the header".
pub fn encodeParam(arena: Allocator, value: Value) Allocator.Error!?[]const u8 {
    return switch (value) {
        .null => null,
        .string => |s| try encodeValue(arena, s),
        .integer => |i| try std.fmt.allocPrint(arena, "{d}", .{i}),
        .bool => |b| if (b) "true" else "false",
        .number_string => |s| s,
        else => null,
    };
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
        const decoded = decodeValue(arena, raw) catch return .{ .message = "Header mismatch: Mcp-Name header has an invalid encoding" };
        if (body_value) |bv| {
            if (!std.mem.eql(u8, decoded, bv)) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Name header value '{s}' does not match body value '{s}'", .{ decoded, bv }) };
        }
    }

    // Mcp-Param-* headers declared by the tool schema.
    if (schema) |s| {
        const props = blk: {
            if (s != .object) break :blk null;
            const p = s.object.get("properties") orelse break :blk null;
            break :blk if (p == .object) p.object else null;
        };
        const arguments: ?Value = blk: {
            const p = params orelse break :blk null;
            if (p != .object) break :blk null;
            break :blk p.object.get("arguments");
        };
        if (props) |properties| {
            var it = properties.iterator();
            while (it.next()) |kv| {
                const annotation_name = json.getString(kv.value_ptr.*, "x-mcp-header") orelse continue;
                const body_value: ?Value = blk: {
                    const a = arguments orelse break :blk null;
                    if (a != .object) break :blk null;
                    const v = a.object.get(kv.key_ptr.*) orelse break :blk null;
                    break :blk if (v == .null) null else v;
                };
                const header_value = headers.param(annotation_name);
                if (body_value == null) {
                    if (header_value != null) return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Param-{s} is present but the body has no value", .{annotation_name}) };
                    continue;
                }
                const raw = header_value orelse return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: the Mcp-Param-{s} header is missing", .{annotation_name}) };
                const decoded = decodeValue(arena, raw) catch return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Param-{s} has an invalid encoding", .{annotation_name}) };
                if (!paramMatches(decoded, body_value.?)) {
                    return .{ .message = try std.fmt.allocPrint(arena, "Header mismatch: Mcp-Param-{s} header value '{s}' does not match the body", .{ annotation_name, decoded }) };
                }
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

/// Check every `x-mcp-header` annotation of a tool input schema. Returns false when
/// transports that carry headers must not show the tool in `tools/list`.
pub fn schemaHeadersValid(schema: Value) bool {
    if (schema != .object) return true;
    const props = schema.object.get("properties") orelse return true;
    if (props != .object) return true;
    var seen: [64][]const u8 = undefined;
    var count: usize = 0;
    var it = props.object.iterator();
    while (it.next()) |kv| {
        const prop = kv.value_ptr.*;
        if (prop != .object) continue;
        const annotation = prop.object.get("x-mcp-header") orelse continue;
        if (annotation != .string) return false;
        const name = annotation.string;
        if (!isValidHeaderAnnotation(name)) return false;
        const t = json.getString(prop, "type") orelse return false;
        if (!(std.mem.eql(u8, t, "string") or std.mem.eql(u8, t, "integer") or std.mem.eql(u8, t, "boolean"))) return false;
        for (seen[0..count]) |s| if (std.ascii.eqlIgnoreCase(s, name)) return false;
        if (count == seen.len) return false;
        seen[count] = name;
        count += 1;
    }
    return true;
}

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
    try std.testing.expect(schemaHeadersValid(schema));
    const dup = try json.parseTree(arena, "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\",\"x-mcp-header\":\"X\"},\"b\":{\"type\":\"string\",\"x-mcp-header\":\"x\"}}}");
    try std.testing.expect(!schemaHeadersValid(dup));
    const num = try json.parseTree(arena, "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"number\",\"x-mcp-header\":\"X\"}}}");
    try std.testing.expect(!schemaHeadersValid(num));
}

/// The Tasks extension methods that mirror `params.taskId` into `Mcp-Name`.
pub fn isTaskMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "tasks/get") or std.mem.eql(u8, method, "tasks/update") or std.mem.eql(u8, method, "tasks/cancel");
}
