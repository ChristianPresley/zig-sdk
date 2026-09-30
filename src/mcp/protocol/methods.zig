//! The comptime method table for MCP 2026-07-28.
const std = @import("std");
const types = @import("types.zig");

/// Where the `Mcp-Name` header (or gRPC `mcp-name` metadata) takes its value from.
pub const HeaderNameSource = enum { none, name, uri, task_id };

pub const Method = enum {
    @"server/discover",
    @"tools/list",
    @"tools/call",
    @"resources/list",
    @"resources/templates/list",
    @"resources/read",
    @"prompts/list",
    @"prompts/get",
    @"completion/complete",
    @"subscriptions/listen",

    pub fn name(self: Method) []const u8 {
        return @tagName(self);
    }

    pub fn fromName(text: []const u8) ?Method {
        return map.get(text);
    }

    /// Results of this method carry `ttlMs` and `cacheScope`.
    pub fn isCacheable(self: Method) bool {
        return switch (self) {
            .@"server/discover", .@"tools/list", .@"resources/list", .@"resources/templates/list", .@"resources/read", .@"prompts/list" => true,
            else => false,
        };
    }

    /// This method can return `InputRequiredResult`.
    pub fn allowsInputRequired(self: Method) bool {
        return switch (self) {
            .@"tools/call", .@"resources/read", .@"prompts/get" => true,
            else => false,
        };
    }

    /// The response stream stays open until the server tears it down.
    pub fn isLongLived(self: Method) bool {
        return self == .@"subscriptions/listen";
    }

    /// The client can re-issue a lost request automatically.
    pub fn isIdempotent(self: Method) bool {
        return switch (self) {
            .@"tools/call", .@"subscriptions/listen" => false,
            else => true,
        };
    }

    pub fn headerNameSource(self: Method) HeaderNameSource {
        return switch (self) {
            .@"tools/call", .@"prompts/get" => .name,
            .@"resources/read" => .uri,
            else => .none,
        };
    }

    /// The server capability that must be declared for the method to exist.
    pub const Gate = enum { none, tools, resources, prompts, completions, subscriptions };

    pub fn gate(self: Method) Gate {
        return switch (self) {
            .@"server/discover" => .none,
            .@"tools/list", .@"tools/call" => .tools,
            .@"resources/list", .@"resources/templates/list", .@"resources/read" => .resources,
            .@"prompts/list", .@"prompts/get" => .prompts,
            .@"completion/complete" => .completions,
            .@"subscriptions/listen" => .subscriptions,
        };
    }

    pub fn Params(comptime self: Method) type {
        return switch (self) {
            .@"server/discover" => types.RequestParams,
            .@"tools/list", .@"resources/list", .@"resources/templates/list", .@"prompts/list" => types.PaginatedRequestParams,
            .@"tools/call" => types.CallToolRequestParams,
            .@"resources/read" => types.ReadResourceRequestParams,
            .@"prompts/get" => types.GetPromptRequestParams,
            .@"completion/complete" => types.CompleteRequestParams,
            .@"subscriptions/listen" => types.SubscriptionsListenRequestParams,
        };
    }

    pub fn Result(comptime self: Method) type {
        return switch (self) {
            .@"server/discover" => types.DiscoverResult,
            .@"tools/list" => types.ListToolsResult,
            .@"tools/call" => types.CallToolResult,
            .@"resources/list" => types.ListResourcesResult,
            .@"resources/templates/list" => types.ListResourceTemplatesResult,
            .@"resources/read" => types.ReadResourceResult,
            .@"prompts/list" => types.ListPromptsResult,
            .@"prompts/get" => types.GetPromptResult,
            .@"completion/complete" => types.CompleteResult,
            .@"subscriptions/listen" => types.SubscriptionsListenResult,
        };
    }

    const map = std.StaticStringMap(Method).initComptime(blk: {
        const fields = @typeInfo(Method).@"enum".fields;
        var kvs: [fields.len]struct { []const u8, Method } = undefined;
        for (fields, 0..) |f, i| kvs[i] = .{ f.name, @enumFromInt(f.value) };
        break :blk kvs;
    });
};

/// Notifications a client can send. Only cancellation exists in this revision.
pub const ClientNotification = enum {
    @"notifications/cancelled",

    pub fn fromName(text: []const u8) ?ClientNotification {
        if (std.mem.eql(u8, text, "notifications/cancelled")) return .@"notifications/cancelled";
        return null;
    }
};

/// Notifications a server can send.
pub const ServerNotification = enum {
    @"notifications/cancelled",
    @"notifications/progress",
    @"notifications/message",
    @"notifications/resources/updated",
    @"notifications/resources/list_changed",
    @"notifications/tools/list_changed",
    @"notifications/prompts/list_changed",
    @"notifications/subscriptions/acknowledged",

    pub fn name(self: ServerNotification) []const u8 {
        return @tagName(self);
    }
};

/// Methods that existed in earlier revisions and were removed. A server answers them with
/// `-32601` like any unknown method, but names them for diagnostics.
pub const removed_methods = [_][]const u8{
    "initialize",
    "notifications/initialized",
    "ping",
    "logging/setLevel",
    "resources/subscribe",
    "resources/unsubscribe",
    "notifications/roots/list_changed",
    "sampling/createMessage",
    "elicitation/create",
    "roots/list",
    "tasks/get",
    "tasks/list",
    "tasks/result",
    "tasks/cancel",
};

pub fn isRemovedMethod(text: []const u8) bool {
    for (removed_methods) |m| if (std.mem.eql(u8, m, text)) return true;
    return false;
}

test "method table" {
    try std.testing.expectEqual(Method.@"tools/call", Method.fromName("tools/call").?);
    try std.testing.expect(Method.fromName("initialize") == null);
    try std.testing.expect(isRemovedMethod("initialize"));
    try std.testing.expect(Method.@"resources/read".isCacheable());
    try std.testing.expect(!Method.@"tools/call".isCacheable());
    try std.testing.expect(Method.@"tools/call".allowsInputRequired());
    try std.testing.expectEqual(HeaderNameSource.uri, Method.@"resources/read".headerNameSource());
    try std.testing.expectEqual(10, @typeInfo(Method).@"enum".fields.len);
}
