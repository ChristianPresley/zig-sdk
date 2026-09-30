//! Maps every schema definition that has an example fixture to its Zig type and wire role.
//! `golden_test.zig` uses this table; the census tool checks it against `schema.json`.
const std = @import("std");
const types = @import("types.zig");

pub const Role = enum {
    /// A plain data type: the example is the value itself.
    data,
    /// A JSON-RPC request envelope; `T` is the params type.
    request,
    /// A JSON-RPC notification envelope; `T` is the params type.
    notification,
    /// A JSON-RPC result response envelope; `T` is the result type.
    response,
    /// A JSON-RPC error response envelope.
    error_response,
};

pub const Entry = struct {
    name: []const u8,
    role: Role,
    T: type,
};

pub const entries = [_]Entry{
    .{ .name = "AudioContent", .role = .data, .T = types.AudioContent },
    .{ .name = "BlobResourceContents", .role = .data, .T = types.BlobResourceContents },
    .{ .name = "BooleanSchema", .role = .data, .T = types.BooleanSchema },
    .{ .name = "CallToolRequest", .role = .request, .T = types.CallToolRequestParams },
    .{ .name = "CallToolRequestParams", .role = .data, .T = types.CallToolRequestParams },
    .{ .name = "CallToolResult", .role = .data, .T = types.CallToolResult },
    .{ .name = "CallToolResultResponse", .role = .response, .T = types.CallToolResult },
    .{ .name = "CancelledNotification", .role = .notification, .T = types.CancelledNotificationParams },
    .{ .name = "CancelledNotificationParams", .role = .data, .T = types.CancelledNotificationParams },
    .{ .name = "ClientCapabilities", .role = .data, .T = types.ClientCapabilities },
    .{ .name = "CompleteRequest", .role = .request, .T = types.CompleteRequestParams },
    .{ .name = "CompleteRequestParams", .role = .data, .T = types.CompleteRequestParams },
    .{ .name = "CompleteResult", .role = .data, .T = types.CompleteResult },
    .{ .name = "CompleteResultResponse", .role = .response, .T = types.CompleteResult },
    .{ .name = "CreateMessageRequest", .role = .data, .T = types.CreateMessageRequest },
    .{ .name = "CreateMessageRequestParams", .role = .data, .T = types.CreateMessageRequestParams },
    .{ .name = "CreateMessageResult", .role = .data, .T = types.CreateMessageResult },
    .{ .name = "DiscoverRequest", .role = .request, .T = types.RequestParams },
    .{ .name = "DiscoverResult", .role = .data, .T = types.DiscoverResult },
    .{ .name = "DiscoverResultResponse", .role = .response, .T = types.DiscoverResult },
    .{ .name = "ElicitRequest", .role = .data, .T = types.ElicitRequest },
    .{ .name = "ElicitRequestFormParams", .role = .data, .T = types.ElicitRequestFormParams },
    .{ .name = "ElicitRequestURLParams", .role = .data, .T = types.ElicitRequestURLParams },
    .{ .name = "ElicitResult", .role = .data, .T = types.ElicitResult },
    .{ .name = "EmbeddedResource", .role = .data, .T = types.EmbeddedResource },
    .{ .name = "GetPromptRequest", .role = .request, .T = types.GetPromptRequestParams },
    .{ .name = "GetPromptRequestParams", .role = .data, .T = types.GetPromptRequestParams },
    .{ .name = "GetPromptResult", .role = .data, .T = types.GetPromptResult },
    .{ .name = "GetPromptResultResponse", .role = .response, .T = types.GetPromptResult },
    .{ .name = "HeaderMismatchError", .role = .error_response, .T = void },
    .{ .name = "ImageContent", .role = .data, .T = types.ImageContent },
    .{ .name = "InputRequests", .role = .data, .T = types.InputRequests },
    .{ .name = "InputRequiredResult", .role = .data, .T = types.InputRequiredResult },
    .{ .name = "InputResponses", .role = .data, .T = types.InputResponses },
    .{ .name = "InternalError", .role = .data, .T = types.Error },
    .{ .name = "InvalidParamsError", .role = .data, .T = types.Error },
    .{ .name = "ListPromptsRequest", .role = .request, .T = types.PaginatedRequestParams },
    .{ .name = "ListPromptsResult", .role = .data, .T = types.ListPromptsResult },
    .{ .name = "ListPromptsResultResponse", .role = .response, .T = types.ListPromptsResult },
    .{ .name = "ListResourceTemplatesRequest", .role = .request, .T = types.PaginatedRequestParams },
    .{ .name = "ListResourceTemplatesResult", .role = .data, .T = types.ListResourceTemplatesResult },
    .{ .name = "ListResourceTemplatesResultResponse", .role = .response, .T = types.ListResourceTemplatesResult },
    .{ .name = "ListResourcesRequest", .role = .request, .T = types.PaginatedRequestParams },
    .{ .name = "ListResourcesResult", .role = .data, .T = types.ListResourcesResult },
    .{ .name = "ListResourcesResultResponse", .role = .response, .T = types.ListResourcesResult },
    .{ .name = "ListRootsRequest", .role = .data, .T = types.ListRootsRequest },
    .{ .name = "ListRootsResult", .role = .data, .T = types.ListRootsResult },
    .{ .name = "ListToolsRequest", .role = .request, .T = types.PaginatedRequestParams },
    .{ .name = "ListToolsResult", .role = .data, .T = types.ListToolsResult },
    .{ .name = "ListToolsResultResponse", .role = .response, .T = types.ListToolsResult },
    .{ .name = "LoggingMessageNotification", .role = .notification, .T = types.LoggingMessageNotificationParams },
    .{ .name = "LoggingMessageNotificationParams", .role = .data, .T = types.LoggingMessageNotificationParams },
    .{ .name = "MethodNotFoundError", .role = .data, .T = types.Error },
    .{ .name = "MissingRequiredClientCapabilityError", .role = .error_response, .T = void },
    .{ .name = "ModelPreferences", .role = .data, .T = types.ModelPreferences },
    .{ .name = "NumberSchema", .role = .data, .T = types.NumberSchema },
    .{ .name = "PaginatedRequestParams", .role = .data, .T = types.PaginatedRequestParams },
    .{ .name = "ParseError", .role = .data, .T = types.Error },
    .{ .name = "ProgressNotification", .role = .notification, .T = types.ProgressNotificationParams },
    .{ .name = "ProgressNotificationParams", .role = .data, .T = types.ProgressNotificationParams },
    .{ .name = "PromptListChangedNotification", .role = .notification, .T = types.NotificationParams },
    .{ .name = "ReadResourceRequest", .role = .request, .T = types.ReadResourceRequestParams },
    .{ .name = "ReadResourceResult", .role = .data, .T = types.ReadResourceResult },
    .{ .name = "ReadResourceResultResponse", .role = .response, .T = types.ReadResourceResult },
    .{ .name = "Resource", .role = .data, .T = types.Resource },
    .{ .name = "ResourceLink", .role = .data, .T = types.ResourceLink },
    .{ .name = "ResourceListChangedNotification", .role = .notification, .T = types.NotificationParams },
    .{ .name = "ResourceUpdatedNotification", .role = .notification, .T = types.ResourceUpdatedNotificationParams },
    .{ .name = "ResourceUpdatedNotificationParams", .role = .data, .T = types.ResourceUpdatedNotificationParams },
    .{ .name = "Root", .role = .data, .T = types.Root },
    .{ .name = "SamplingMessage", .role = .data, .T = types.SamplingMessage },
    .{ .name = "ServerCapabilities", .role = .data, .T = types.ServerCapabilities },
    .{ .name = "StringSchema", .role = .data, .T = types.StringSchema },
    .{ .name = "SubscriptionsAcknowledgedNotification", .role = .notification, .T = types.SubscriptionsAcknowledgedNotificationParams },
    .{ .name = "SubscriptionsListenRequest", .role = .request, .T = types.SubscriptionsListenRequestParams },
    .{ .name = "SubscriptionsListenResult", .role = .data, .T = types.SubscriptionsListenResult },
    .{ .name = "SubscriptionsListenResultResponse", .role = .response, .T = types.SubscriptionsListenResult },
    .{ .name = "TextContent", .role = .data, .T = types.TextContent },
    .{ .name = "TextResourceContents", .role = .data, .T = types.TextResourceContents },
    .{ .name = "TitledMultiSelectEnumSchema", .role = .data, .T = types.TitledMultiSelectEnumSchema },
    .{ .name = "TitledSingleSelectEnumSchema", .role = .data, .T = types.TitledSingleSelectEnumSchema },
    .{ .name = "Tool", .role = .data, .T = types.Tool },
    .{ .name = "ToolListChangedNotification", .role = .notification, .T = types.NotificationParams },
    .{ .name = "ToolResultContent", .role = .data, .T = types.ToolResultContent },
    .{ .name = "ToolUseContent", .role = .data, .T = types.ToolUseContent },
    .{ .name = "UnsupportedProtocolVersionError", .role = .error_response, .T = void },
    .{ .name = "UntitledMultiSelectEnumSchema", .role = .data, .T = types.UntitledMultiSelectEnumSchema },
    .{ .name = "UntitledSingleSelectEnumSchema", .role = .data, .T = types.UntitledSingleSelectEnumSchema },
};

pub fn find(name: []const u8) ?usize {
    inline for (entries, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, name)) return i;
    }
    return null;
}
