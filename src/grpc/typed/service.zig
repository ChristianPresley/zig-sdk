//! The typed service `model_context_protocol.Mcp` of the Google Cloud proto files: its eight
//! unary RPCs, their MCP methods, the routing metadata and the status mapping.
const std = @import("std");
const status = @import("../grpc/status.zig");
const pb = @import("../protobuf/mcp_messages.zig");

/// The path prefix of the typed service.
pub const path_prefix = "/" ++ pb.service_name ++ "/";

/// The routing metadata of the proto comments. The value is the tool name, the prompt name,
/// or the resource URI. For `Complete`, `mcp_resource` has the URI of a resource reference or
/// the name of a prompt reference.
pub const header_tool = "mcp_tool";
pub const header_prompt = "mcp_prompt";
pub const header_resource = "mcp_resource";

/// The JSON-RPC error code in the trailers, as in the reference transport.
pub const header_error_code = "mcp-error-code";
/// The JSON-RPC error response in the trailers, base64. An extension of this SDK.
pub const header_error_bin = "mcp-error-bin";

/// The largest `mcp-error-bin` value that the server sends. A larger error response travels
/// without it.
pub const max_error_bin_bytes = 4096;

/// The longest error text that the server puts in `grpc-message`, before the percent
/// encoding. The server cuts a longer text at a UTF-8 boundary.
pub const max_error_message_bytes = 1024;

/// The first `max` bytes of `text` or less, without a part of a UTF-8 sequence at the end.
pub fn shorten(text: []const u8, max: usize) []const u8 {
    if (text.len <= max) return text;
    var end = max;
    while (end > 0 and (text[end] & 0xc0) == 0x80) end -= 1;
    return text[0..end];
}

pub const Rpc = enum {
    list_resources,
    read_resource,
    list_resource_templates,
    list_prompts,
    get_prompt,
    list_tools,
    call_tool,
    complete,

    /// The method name in the proto service.
    pub fn rpcName(self: Rpc) []const u8 {
        return switch (self) {
            .list_resources => "ListResources",
            .read_resource => "ReadResource",
            .list_resource_templates => "ListResourceTemplates",
            .list_prompts => "ListPrompts",
            .get_prompt => "GetPrompt",
            .list_tools => "ListTools",
            .call_tool => "CallTool",
            .complete => "Complete",
        };
    }

    /// The MCP method of the RPC.
    pub fn method(self: Rpc) []const u8 {
        return switch (self) {
            .list_resources => "resources/list",
            .read_resource => "resources/read",
            .list_resource_templates => "resources/templates/list",
            .list_prompts => "prompts/list",
            .get_prompt => "prompts/get",
            .list_tools => "tools/list",
            .call_tool => "tools/call",
            .complete => "completion/complete",
        };
    }

    /// The HTTP/2 path of the RPC.
    pub fn path(self: Rpc) []const u8 {
        return switch (self) {
            inline else => |r| path_prefix ++ comptime r.rpcName(),
        };
    }

    pub fn fromPath(text: []const u8) ?Rpc {
        if (!std.mem.startsWith(u8, text, path_prefix)) return null;
        const name = text[path_prefix.len..];
        inline for (std.meta.fields(Rpc)) |f| {
            const r: Rpc = @enumFromInt(f.value);
            if (std.mem.eql(u8, name, r.rpcName())) return r;
        }
        return null;
    }

    pub fn fromMethod(text: []const u8) ?Rpc {
        inline for (std.meta.fields(Rpc)) |f| {
            const r: Rpc = @enumFromInt(f.value);
            if (std.mem.eql(u8, text, r.method())) return r;
        }
        return null;
    }

    /// The list results carry items in this field. Null for the other RPCs.
    pub fn listKey(self: Rpc) ?[]const u8 {
        return switch (self) {
            .list_resources => "resources",
            .list_resource_templates => "resourceTemplates",
            .list_prompts => "prompts",
            .list_tools => "tools",
            else => null,
        };
    }

    /// The routing metadata of the RPC, or null when the RPC has none.
    pub fn routeHeader(self: Rpc) ?[]const u8 {
        return switch (self) {
            .call_tool => header_tool,
            .get_prompt => header_prompt,
            .read_resource, .complete => header_resource,
            else => null,
        };
    }

    /// The request message type of the RPC.
    pub fn Request(comptime self: Rpc) type {
        return switch (self) {
            .list_resources => pb.ListResourcesRequest,
            .read_resource => pb.ReadResourceRequest,
            .list_resource_templates => pb.ListResourceTemplatesRequest,
            .list_prompts => pb.ListPromptsRequest,
            .get_prompt => pb.GetPromptRequest,
            .list_tools => pb.ListToolsRequest,
            .call_tool => pb.CallToolRequest,
            .complete => pb.CompletionRequest,
        };
    }

    /// The response message type of the RPC.
    pub fn Response(comptime self: Rpc) type {
        return switch (self) {
            .list_resources => pb.ListResourcesResponse,
            .read_resource => pb.ReadResourceResponse,
            .list_resource_templates => pb.ListResourceTemplatesResponse,
            .list_prompts => pb.ListPromptsResponse,
            .get_prompt => pb.GetPromptResponse,
            .list_tools => pb.ListToolsResponse,
            .call_tool => pb.CallToolResponse,
            .complete => pb.CompletionResponse,
        };
    }
};

/// The gRPC status of a JSON-RPC error on the typed binding. The reference transport maps
/// `-32700`, `-32600` and `-32602` to `INVALID_ARGUMENT`, `-32601` to `UNIMPLEMENTED` and the
/// other codes to `INTERNAL`. This SDK also maps the MCP codes `-32020`, `-32021` and
/// `-32022` to `INVALID_ARGUMENT`, as on the tunnel.
pub fn statusForCode(code: i64) status.Code {
    return switch (code) {
        -32601 => .unimplemented,
        -32700, -32600, -32602, -32020, -32021, -32022 => .invalid_argument,
        else => .internal,
    };
}

/// The JSON-RPC error code for a gRPC status without `mcp-error-code`, as in the reference
/// transport. Null for a status that the client gives to the application as a transport
/// error: `CANCELLED`, `DEADLINE_EXCEEDED`, `UNAVAILABLE`, `UNAUTHENTICATED` and
/// `PERMISSION_DENIED`.
pub fn codeForStatus(code: status.Code) ?i64 {
    return switch (code) {
        .ok, .cancelled, .deadline_exceeded, .unavailable, .unauthenticated, .permission_denied => null,
        .invalid_argument => -32602,
        .unimplemented => -32601,
        .not_found => -32600,
        else => -32603,
    };
}

test "rpc table" {
    try std.testing.expectEqualStrings("/model_context_protocol.Mcp/CallTool", Rpc.call_tool.path());
    try std.testing.expectEqual(Rpc.list_resource_templates, Rpc.fromPath("/model_context_protocol.Mcp/ListResourceTemplates").?);
    try std.testing.expect(Rpc.fromPath("/model_context_protocol.Mcp/Initialize") == null);
    try std.testing.expect(Rpc.fromPath("/mcp.zig.transport.v1.Mcp/Call") == null);
    try std.testing.expectEqual(Rpc.complete, Rpc.fromMethod("completion/complete").?);
    try std.testing.expect(Rpc.fromMethod("server/discover") == null);
    for (std.enums.values(Rpc)) |r| {
        try std.testing.expectEqual(r, Rpc.fromMethod(r.method()).?);
        try std.testing.expectEqual(r, Rpc.fromPath(r.path()).?);
    }
    try std.testing.expectEqual(status.Code.invalid_argument, statusForCode(-32602));
    try std.testing.expectEqual(status.Code.unimplemented, statusForCode(-32601));
    try std.testing.expectEqual(status.Code.internal, statusForCode(-32603));
    try std.testing.expectEqual(status.Code.internal, statusForCode(-1));
    try std.testing.expectEqual(@as(?i64, -32602), codeForStatus(.invalid_argument));
    try std.testing.expectEqual(@as(?i64, null), codeForStatus(.deadline_exceeded));
    try std.testing.expectEqual(@as(?i64, -32603), codeForStatus(.unknown));
    try std.testing.expectEqualStrings("abc", shorten("abc", 3));
    try std.testing.expectEqualStrings("ab", shorten("abc", 2));
    // The cut does not split the two bytes of an e with an acute accent.
    try std.testing.expectEqualStrings("a", shorten("a\u{e9}", 2));
}
