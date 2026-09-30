//! Compares the vendored `schema.json` definitions with the fixture directories. It reports
//! the definitions that have examples but no entry in the export map, and a summary count.
//!
//! Usage: `census [fixtures-dir]`.
const std = @import("std");
const Io = std.Io;

const default_dir = "test/fixtures/mcp_schema_2026_07_28";

/// Names of every schema definition that has a Zig counterpart or is intentionally
/// represented differently. Kept in sync with src/mcp/protocol/types.zig.
const covered = [_][]const u8{
    "Annotations",                                 "AudioContent",                      "BaseMetadata",                        "BlobResourceContents",
    "BooleanSchema",                               "CacheableResult",                   "CallToolRequest",                     "CallToolRequestParams",
    "CallToolResult",                              "CallToolResultResponse",            "CancelledNotification",               "CancelledNotificationParams",
    "ClientCapabilities",                          "ClientNotification",                "ClientRequest",                       "ClientResult",
    "CompleteRequest",                             "CompleteRequestParams",             "CompleteResult",                      "CompleteResultResponse",
    "ContentBlock",                                "CreateMessageRequest",              "CreateMessageRequestParams",          "CreateMessageResult",
    "Cursor",                                      "DiscoverRequest",                   "DiscoverResult",                      "DiscoverResultResponse",
    "ElicitRequest",                               "ElicitRequestFormParams",           "ElicitRequestParams",                 "ElicitRequestURLParams",
    "ElicitResult",                                "EmbeddedResource",                  "EmptyResult",                         "EnumSchema",
    "Error",                                       "GetPromptRequest",                  "GetPromptRequestParams",              "GetPromptResult",
    "GetPromptResultResponse",                     "HeaderMismatchError",               "Icon",                                "Icons",
    "ImageContent",                                "Implementation",                    "InputRequest",                        "InputRequests",
    "InputRequiredResult",                         "InputResponse",                     "InputResponseRequestParams",          "InputResponses",
    "InternalError",                               "InvalidParamsError",                "InvalidRequestError",                 "JSONArray",
    "JSONObject",                                  "JSONRPCErrorResponse",              "JSONRPCMessage",                      "JSONRPCNotification",
    "JSONRPCRequest",                              "JSONRPCResponse",                   "JSONRPCResultResponse",               "JSONValue",
    "LegacyTitledEnumSchema",                      "ListPromptsRequest",                "ListPromptsResult",                   "ListPromptsResultResponse",
    "ListResourceTemplatesRequest",                "ListResourceTemplatesResult",       "ListResourceTemplatesResultResponse", "ListResourcesRequest",
    "ListResourcesResult",                         "ListResourcesResultResponse",       "ListRootsRequest",                    "ListRootsResult",
    "ListToolsRequest",                            "ListToolsResult",                   "ListToolsResultResponse",             "LoggingLevel",
    "LoggingMessageNotification",                  "LoggingMessageNotificationParams",  "MetaObject",                          "MethodNotFoundError",
    "MissingRequiredClientCapabilityError",        "ModelHint",                         "ModelPreferences",                    "MultiSelectEnumSchema",
    "Notification",                                "NotificationMetaObject",            "NotificationParams",                  "NumberSchema",
    "PaginatedRequest",                            "PaginatedRequestParams",            "PaginatedResult",                     "ParseError",
    "PrimitiveSchemaDefinition",                   "ProgressNotification",              "ProgressNotificationParams",          "ProgressToken",
    "Prompt",                                      "PromptArgument",                    "PromptListChangedNotification",       "PromptMessage",
    "PromptReference",                             "ReadResourceRequest",               "ReadResourceRequestParams",           "ReadResourceResult",
    "ReadResourceResultResponse",                  "Request",                           "RequestId",                           "RequestMetaObject",
    "RequestParams",                               "Resource",                          "ResourceContents",                    "ResourceLink",
    "ResourceListChangedNotification",             "ResourceRequestParams",             "ResourceTemplate",                    "ResourceTemplateReference",
    "ResourceUpdatedNotification",                 "ResourceUpdatedNotificationParams", "Result",                              "ResultMetaObject",
    "ResultType",                                  "Role",                              "Root",                                "SamplingMessage",
    "SamplingMessageContentBlock",                 "ServerCapabilities",                "ServerNotification",                  "ServerResult",
    "SingleSelectEnumSchema",                      "StringSchema",                      "SubscriptionFilter",                  "SubscriptionsAcknowledgedNotification",
    "SubscriptionsAcknowledgedNotificationParams", "SubscriptionsListenRequest",        "SubscriptionsListenRequestParams",    "SubscriptionsListenResult",
    "SubscriptionsListenResultMetaObject",         "SubscriptionsListenResultResponse", "TextContent",                         "TextResourceContents",
    "TitledMultiSelectEnumSchema",                 "TitledSingleSelectEnumSchema",      "Tool",                                "ToolAnnotations",
    "ToolChoice",                                  "ToolListChangedNotification",       "ToolResultContent",                   "ToolUseContent",
    "UnsupportedProtocolVersionError",             "UntitledMultiSelectEnumSchema",     "UntitledSingleSelectEnumSchema",
};

fn isCovered(name: []const u8) bool {
    for (covered) |c| if (std.mem.eql(u8, c, name)) return true;
    return false;
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const dir_path: []const u8 = if (args.len > 1) args[1] else default_dir;

    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    const schema_text = try dir.readFileAlloc(io, "schema.json", arena, .limited(16 << 20));
    var parsed = try std.json.parseFromSlice(std.json.Value, arena, schema_text, .{});
    defer parsed.deinit();
    const defs = parsed.value.object.get("$defs") orelse return error.NoDefinitions;

    var missing: usize = 0;
    var total: usize = 0;
    var it = defs.object.iterator();
    while (it.next()) |kv| {
        total += 1;
        if (!isCovered(kv.key_ptr.*)) {
            std.debug.print("::error::census: schema definition {s} has no Zig counterpart\n", .{kv.key_ptr.*});
            missing += 1;
        }
    }
    // Every covered name must exist in the schema, or the list is stale.
    var stale: usize = 0;
    for (covered) |name| {
        if (defs.object.get(name) == null) {
            std.debug.print("::error::census: {s} is listed as covered but is not in schema.json\n", .{name});
            stale += 1;
        }
    }
    // Every fixture directory must be a schema definition.
    var fixtures: usize = 0;
    var examples = try dir.openDir(io, "examples", .{ .iterate = true });
    defer examples.close(io);
    var ex_it = examples.iterate();
    while (try ex_it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        fixtures += 1;
        if (defs.object.get(entry.name) == null) {
            std.debug.print("::error::census: fixture directory {s} is not a schema definition\n", .{entry.name});
            stale += 1;
        }
    }
    std.debug.print("census: {d} definitions, {d} fixture types, {d} without Zig counterpart, {d} stale\n", .{ total, fixtures, missing, stale });
    return if (missing == 0 and stale == 0) 0 else 1;
}
