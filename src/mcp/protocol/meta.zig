//! Per-request `_meta` rules: reserved keys, key grammar, and the envelope lift.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("types.zig");
const json = @import("../json.zig");

pub const key_protocol_version = "io.modelcontextprotocol/protocolVersion";
pub const key_client_info = "io.modelcontextprotocol/clientInfo";
pub const key_client_capabilities = "io.modelcontextprotocol/clientCapabilities";
pub const key_log_level = "io.modelcontextprotocol/logLevel";
pub const key_subscription_id = "io.modelcontextprotocol/subscriptionId";
pub const key_server_info = "io.modelcontextprotocol/serverInfo";
pub const key_progress_token = "progressToken";

/// The request keys that the SDK owns. The client writes them or routes notifications by them.
/// `RequestOptions.meta` of the client cannot set them. The other keys under
/// `io.modelcontextprotocol/` are not in this list, because extensions define keys there.
pub const sdk_owned_request_keys = [_][]const u8{
    key_protocol_version,
    key_client_info,
    key_client_capabilities,
    key_log_level,
    key_subscription_id,
    key_progress_token,
};

/// True when `key` is one of `sdk_owned_request_keys`. The comparison is case-sensitive, as
/// JSON keys are.
pub fn isSdkOwnedRequestKey(key: []const u8) bool {
    for (sdk_owned_request_keys) |owned| if (std.mem.eql(u8, owned, key)) return true;
    return false;
}

/// The lifted per-request envelope.
pub const RequestMeta = struct {
    protocol_version: []const u8,
    client_capabilities: types.ClientCapabilities,
    client_info: ?types.Implementation,
    log_level: ?types.LoggingLevel,
    progress_token: ?types.ProgressToken,

    pub fn fromWire(m: types.RequestMetaObject) RequestMeta {
        return .{
            .protocol_version = m.@"io.modelcontextprotocol/protocolVersion",
            .client_capabilities = m.@"io.modelcontextprotocol/clientCapabilities",
            .client_info = m.@"io.modelcontextprotocol/clientInfo",
            .log_level = m.@"io.modelcontextprotocol/logLevel",
            .progress_token = m.progressToken,
        };
    }
};

pub const LiftError = error{
    MissingMeta,
    MissingProtocolVersion,
    MissingClientCapabilities,
    InvalidMeta,
    OutOfMemory,
};

/// Lift the envelope out of `params._meta`. Returns the precise failure so the dispatcher can
/// produce the mandated `-32602` message.
pub fn lift(arena: Allocator, params: ?Value) LiftError!RequestMeta {
    const p = params orelse return error.MissingMeta;
    if (p != .object) return error.InvalidMeta;
    const m = p.object.get("_meta") orelse return error.MissingMeta;
    if (m != .object) return error.InvalidMeta;
    const pv = m.object.get(key_protocol_version) orelse return error.MissingProtocolVersion;
    if (pv != .string) return error.InvalidMeta;
    const caps = m.object.get(key_client_capabilities) orelse return error.MissingClientCapabilities;
    if (caps != .object) return error.InvalidMeta;
    const wire = json.parseValue(types.RequestMetaObject, arena, m) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidMeta,
    };
    return RequestMeta.fromWire(wire);
}

pub const KeyError = error{ InvalidPrefix, InvalidName, ReservedPrefix };

/// Validate a `_meta` key against the specification grammar:
/// optional prefix of dot-separated labels followed by `/`, then a name.
pub fn validateKey(key: []const u8) KeyError!void {
    if (key.len == 0) return error.InvalidName;
    const slash = std.mem.findScalar(u8, key, '/');
    const name = if (slash) |s| key[s + 1 ..] else key;
    if (slash) |s| {
        const prefix = key[0..s];
        if (prefix.len == 0) return error.InvalidPrefix;
        var labels = std.mem.splitScalar(u8, prefix, '.');
        var index: usize = 0;
        while (labels.next()) |label| : (index += 1) {
            if (label.len == 0) return error.InvalidPrefix;
            if (!std.ascii.isAlphabetic(label[0])) return error.InvalidPrefix;
            if (!std.ascii.isAlphanumeric(label[label.len - 1])) return error.InvalidPrefix;
            for (label) |c| {
                if (!(std.ascii.isAlphanumeric(c) or c == '-')) return error.InvalidPrefix;
            }
        }
    }
    if (name.len == 0) return error.InvalidName;
    if (!std.ascii.isAlphanumeric(name[0]) or !std.ascii.isAlphanumeric(name[name.len - 1])) return error.InvalidName;
    for (name) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.')) return error.InvalidName;
    }
}

/// True when the key uses a prefix reserved for the protocol (`*.modelcontextprotocol/` or
/// `*.mcp/`).
pub fn isReservedPrefix(key: []const u8) bool {
    const slash = std.mem.findScalar(u8, key, '/') orelse return false;
    const prefix = key[0..slash];
    var labels = std.mem.splitScalar(u8, prefix, '.');
    _ = labels.next() orelse return false;
    const second = labels.next() orelse return false;
    return std.mem.eql(u8, second, "modelcontextprotocol") or std.mem.eql(u8, second, "mcp");
}

test "meta key grammar" {
    try validateKey("progressToken");
    try validateKey("io.modelcontextprotocol/protocolVersion");
    try validateKey("com.example-corp.app/my_key.v2");
    try std.testing.expectError(error.InvalidPrefix, validateKey("1abc/x"));
    try std.testing.expectError(error.InvalidPrefix, validateKey("a..b/x"));
    try std.testing.expectError(error.InvalidName, validateKey("io.modelcontextprotocol/"));
    try std.testing.expectError(error.InvalidName, validateKey("-bad"));
    try std.testing.expect(isReservedPrefix("io.modelcontextprotocol/protocolVersion"));
    try std.testing.expect(isReservedPrefix("org.mcp/x"));
    try std.testing.expect(!isReservedPrefix("com.example/x"));
}

test "the SDK owns its request keys and no other key of the prefix" {
    for (sdk_owned_request_keys) |key| try std.testing.expect(isSdkOwnedRequestKey(key));
    try std.testing.expect(!isSdkOwnedRequestKey("io.modelcontextprotocol/ui"));
    try std.testing.expect(!isSdkOwnedRequestKey("io.modelcontextprotocol/LogLevel"));
    try std.testing.expect(!isSdkOwnedRequestKey("traceparent"));
    try std.testing.expect(!isSdkOwnedRequestKey("com.example/x"));
}

test "lift envelope" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ok = try json.parseTree(arena,
        \\{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}},"progressToken":"p1"}}
    );
    const m = try lift(arena, ok);
    try std.testing.expectEqualStrings("2026-07-28", m.protocol_version);
    try std.testing.expect(m.client_capabilities.hasElicitation(.form));
    try std.testing.expect(!m.client_capabilities.hasElicitation(.url));
    try std.testing.expect(m.progress_token.? == .string);

    const missing = try json.parseTree(arena, "{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}");
    try std.testing.expectError(error.MissingClientCapabilities, lift(arena, missing));
    try std.testing.expectError(error.MissingMeta, lift(arena, null));
}
