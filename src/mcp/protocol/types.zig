//! Typed mirrors of `schema/2026-07-28/schema.ts`. Field names are the wire names.
//! The parser ignores unknown fields on input. The writer omits optional fields that are
//! null on output (see `json.wire_options`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const json = @import("../json.zig");
pub const Value = std.json.Value;
pub const RequestId = @import("../jsonrpc/id.zig").RequestId;

/// A free-form JSON object. Callers validate that the value is an object.
pub const MetaObject = Value;
/// A free-form JSON object used by `experimental` and `extensions` maps.
pub const JSONObject = Value;
pub const Empty = struct {};
pub const Cursor = []const u8;

pub const ProgressToken = union(enum) {
    string: []const u8,
    integer: i64,

    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !ProgressToken {
        const value = try std.json.innerParse(Value, allocator, source, options);
        return jsonParseFromValue(allocator, value, options);
    }

    pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: std.json.ParseOptions) !ProgressToken {
        _ = options;
        return switch (source) {
            .string => |s| .{ .string = try allocator.dupe(u8, s) },
            .integer => |i| .{ .integer = i },
            else => error.UnexpectedToken,
        };
    }

    pub fn jsonStringify(self: ProgressToken, jws: anytype) !void {
        switch (self) {
            .string => |s| try jws.write(s),
            .integer => |i| try jws.write(i),
        }
    }

    pub fn eql(a: ProgressToken, b: ProgressToken) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .string => |s| std.mem.eql(u8, s, b.string),
            .integer => |i| i == b.integer,
        };
    }
};

// ---------------------------------------------------------------------------------------------
// `_meta` objects
// ---------------------------------------------------------------------------------------------

pub const RequestMetaObject = struct {
    progressToken: ?ProgressToken = null,
    @"io.modelcontextprotocol/protocolVersion": []const u8,
    @"io.modelcontextprotocol/clientInfo": ?Implementation = null,
    @"io.modelcontextprotocol/clientCapabilities": ClientCapabilities,
    @"io.modelcontextprotocol/logLevel": ?LoggingLevel = null,
};

pub const NotificationMetaObject = struct {
    @"io.modelcontextprotocol/subscriptionId": ?RequestId = null,
};

pub const ResultMetaObject = struct {
    @"io.modelcontextprotocol/serverInfo": ?Implementation = null,
};

pub const SubscriptionsListenResultMetaObject = struct {
    @"io.modelcontextprotocol/serverInfo": ?Implementation = null,
    @"io.modelcontextprotocol/subscriptionId": RequestId,
};

pub const RequestParams = struct {
    _meta: RequestMetaObject,
};

pub const NotificationParams = struct {
    _meta: ?NotificationMetaObject = null,
};

pub const result_type_complete = "complete";
pub const result_type_input_required = "input_required";

/// A result with no payload.
pub const EmptyResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
};

pub const CacheScope = enum { public, private };

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

pub const Error = struct {
    code: i64,
    message: []const u8,
    data: ?Value = null,
};

pub const UnsupportedProtocolVersionData = struct {
    supported: []const []const u8,
    requested: []const u8,
};

pub const MissingRequiredClientCapabilityData = struct {
    requiredCapabilities: ClientCapabilities,
};

// ---------------------------------------------------------------------------------------------
// Multi round-trip requests
// ---------------------------------------------------------------------------------------------

pub const InputRequest = union(enum) {
    @"sampling/createMessage": CreateMessageRequest,
    @"roots/list": ListRootsRequest,
    @"elicitation/create": ElicitRequest,

    pub const jsonParse = json.Discriminated(@This(), "method").jsonParse;
    pub const jsonParseFromValue = json.Discriminated(@This(), "method").jsonParseFromValue;
    pub const jsonStringify = json.Discriminated(@This(), "method").jsonStringify;
};

/// The server-chosen request key identifies each response. Only the request that it answers
/// tells its shape, so the SDK keeps it as raw JSON and decodes it on demand.
pub const InputRequests = std.json.ArrayHashMap(InputRequest);
pub const InputResponses = std.json.ArrayHashMap(Value);

pub const InputRequiredResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_input_required,
    inputRequests: ?InputRequests = null,
    requestState: ?[]const u8 = null,
};

pub const InputResponseRequestParams = struct {
    _meta: RequestMetaObject,
    inputResponses: ?InputResponses = null,
    requestState: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------------------------
// Cancellation, discovery, capabilities, implementation
// ---------------------------------------------------------------------------------------------

pub const CancelledNotificationParams = struct {
    _meta: ?NotificationMetaObject = null,
    requestId: RequestId,
    reason: ?[]const u8 = null,
};

pub const DiscoverResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    ttlMs: ?i64 = null,
    cacheScope: ?CacheScope = null,
    supportedVersions: []const []const u8,
    capabilities: ServerCapabilities,
    instructions: ?[]const u8 = null,
};

pub const ClientCapabilities = struct {
    experimental: ?JSONObject = null,
    roots: ?Empty = null,
    sampling: ?Sampling = null,
    elicitation: ?Elicitation = null,
    extensions: ?JSONObject = null,

    pub const Sampling = struct {
        context: ?JSONObject = null,
        tools: ?JSONObject = null,
    };
    pub const Elicitation = struct {
        form: ?JSONObject = null,
        url: ?JSONObject = null,
    };

    /// True when the client declared the elicitation capability with the given mode.
    /// An empty `elicitation` object means form mode only.
    pub fn hasElicitation(self: ClientCapabilities, mode: ElicitationMode) bool {
        const e = self.elicitation orelse return false;
        return switch (mode) {
            .form => e.form != null or (e.form == null and e.url == null),
            .url => e.url != null,
        };
    }

    pub fn hasExtension(self: ClientCapabilities, id: []const u8) bool {
        const ext = self.extensions orelse return false;
        return ext == .object and ext.object.get(id) != null;
    }

    /// A copy with the extension `id` declared with `settings`. The copy keeps the other
    /// extensions. The function allocates the new `extensions` object in `arena`.
    pub fn withExtension(self: ClientCapabilities, arena: Allocator, id: []const u8, settings: Value) Allocator.Error!ClientCapabilities {
        var ext: std.json.ObjectMap = .empty;
        if (self.extensions) |existing| if (existing == .object) {
            var it = existing.object.iterator();
            while (it.next()) |kv| try ext.put(arena, kv.key_ptr.*, kv.value_ptr.*);
        };
        try ext.put(arena, id, settings);
        var out = self;
        out.extensions = .{ .object = ext };
        return out;
    }
};

pub const ServerCapabilities = struct {
    experimental: ?JSONObject = null,
    logging: ?JSONObject = null,
    completions: ?JSONObject = null,
    prompts: ?Prompts = null,
    resources: ?Resources = null,
    tools: ?Tools = null,
    extensions: ?JSONObject = null,

    pub const Prompts = struct { listChanged: ?bool = null };
    pub const Resources = struct { subscribe: ?bool = null, listChanged: ?bool = null };
    pub const Tools = struct { listChanged: ?bool = null };
};

pub const Icon = struct {
    src: []const u8,
    mimeType: ?[]const u8 = null,
    sizes: ?[]const []const u8 = null,
    theme: ?enum { light, dark } = null,
};

pub const Implementation = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    icons: ?[]const Icon = null,
    version: []const u8,
    description: ?[]const u8 = null,
    websiteUrl: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------------------------
// Progress, pagination
// ---------------------------------------------------------------------------------------------

pub const ProgressNotificationParams = struct {
    _meta: ?NotificationMetaObject = null,
    progressToken: ProgressToken,
    progress: f64,
    total: ?f64 = null,
    message: ?[]const u8 = null,
};

pub const PaginatedRequestParams = struct {
    _meta: RequestMetaObject,
    cursor: ?Cursor = null,
};

// ---------------------------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------------------------

pub const ListResourcesResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    nextCursor: ?Cursor = null,
    ttlMs: ?i64 = null,
    cacheScope: ?CacheScope = null,
    resources: []const Resource,
};

pub const ListResourceTemplatesResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    nextCursor: ?Cursor = null,
    ttlMs: ?i64 = null,
    cacheScope: ?CacheScope = null,
    resourceTemplates: []const ResourceTemplate,
};

pub const ReadResourceRequestParams = struct {
    _meta: RequestMetaObject,
    inputResponses: ?InputResponses = null,
    requestState: ?[]const u8 = null,
    uri: []const u8,
};

pub const ReadResourceResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    ttlMs: ?i64 = null,
    cacheScope: ?CacheScope = null,
    contents: []const ResourceContents,
};

pub const SubscriptionFilter = struct {
    toolsListChanged: ?bool = null,
    promptsListChanged: ?bool = null,
    resourcesListChanged: ?bool = null,
    resourceSubscriptions: ?[]const []const u8 = null,
};

pub const SubscriptionsListenRequestParams = struct {
    _meta: RequestMetaObject,
    notifications: SubscriptionFilter,
};

pub const SubscriptionsListenResult = struct {
    _meta: SubscriptionsListenResultMetaObject,
    resultType: []const u8 = result_type_complete,
};

pub const SubscriptionsAcknowledgedNotificationParams = struct {
    _meta: ?NotificationMetaObject = null,
    notifications: SubscriptionFilter,
};

pub const ResourceUpdatedNotificationParams = struct {
    _meta: ?NotificationMetaObject = null,
    uri: []const u8,
};

pub const Resource = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    icons: ?[]const Icon = null,
    uri: []const u8,
    description: ?[]const u8 = null,
    mimeType: ?[]const u8 = null,
    annotations: ?Annotations = null,
    size: ?i64 = null,
    _meta: ?MetaObject = null,
};

pub const ResourceTemplate = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    icons: ?[]const Icon = null,
    uriTemplate: []const u8,
    description: ?[]const u8 = null,
    mimeType: ?[]const u8 = null,
    annotations: ?Annotations = null,
    _meta: ?MetaObject = null,
};

pub const TextResourceContents = struct {
    uri: []const u8,
    mimeType: ?[]const u8 = null,
    _meta: ?MetaObject = null,
    text: []const u8,
};

pub const BlobResourceContents = struct {
    uri: []const u8,
    mimeType: ?[]const u8 = null,
    _meta: ?MetaObject = null,
    /// Base64-encoded bytes.
    blob: []const u8,
};

pub const ResourceContents = union(enum) {
    text: TextResourceContents,
    blob: BlobResourceContents,

    fn classify(v: Value) ?std.meta.Tag(ResourceContents) {
        if (json.hasKey(v, "text")) return .text;
        if (json.hasKey(v, "blob")) return .blob;
        return null;
    }
    pub const jsonParse = json.Classified(@This(), classify).jsonParse;
    pub const jsonParseFromValue = json.Classified(@This(), classify).jsonParseFromValue;
    pub const jsonStringify = json.Classified(@This(), classify).jsonStringify;

    pub fn uri(self: ResourceContents) []const u8 {
        return switch (self) {
            inline else => |c| c.uri,
        };
    }
};

// ---------------------------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------------------------

pub const ListPromptsResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    nextCursor: ?Cursor = null,
    ttlMs: ?i64 = null,
    cacheScope: ?CacheScope = null,
    prompts: []const Prompt,
};

pub const GetPromptRequestParams = struct {
    _meta: RequestMetaObject,
    inputResponses: ?InputResponses = null,
    requestState: ?[]const u8 = null,
    name: []const u8,
    arguments: ?std.json.ArrayHashMap([]const u8) = null,
};

pub const GetPromptResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    description: ?[]const u8 = null,
    messages: []const PromptMessage,
};

pub const Prompt = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    icons: ?[]const Icon = null,
    description: ?[]const u8 = null,
    arguments: ?[]const PromptArgument = null,
    _meta: ?MetaObject = null,
};

pub const PromptArgument = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    required: ?bool = null,
};

pub const Role = enum { user, assistant };

pub const PromptMessage = struct {
    role: Role,
    content: ContentBlock,
};

pub const ResourceLink = struct {
    type: enum { resource_link } = .resource_link,
    name: []const u8,
    title: ?[]const u8 = null,
    icons: ?[]const Icon = null,
    uri: []const u8,
    description: ?[]const u8 = null,
    mimeType: ?[]const u8 = null,
    annotations: ?Annotations = null,
    size: ?i64 = null,
    _meta: ?MetaObject = null,
};

pub const EmbeddedResource = struct {
    type: enum { resource } = .resource,
    resource: ResourceContents,
    annotations: ?Annotations = null,
    _meta: ?MetaObject = null,
};

// ---------------------------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------------------------

pub const ListToolsResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    nextCursor: ?Cursor = null,
    ttlMs: ?i64 = null,
    cacheScope: ?CacheScope = null,
    tools: []const Tool,
};

pub const CallToolResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    content: []const ContentBlock,
    structuredContent: ?Value = null,
    isError: ?bool = null,

    /// Build a result with a single text block.
    pub fn text(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!CallToolResult {
        const blocks = try arena.alloc(ContentBlock, 1);
        blocks[0] = .{ .text = .{ .text = try std.fmt.allocPrint(arena, fmt, args) } };
        return .{ .content = blocks };
    }

    /// Build an error result with a single text block.
    pub fn err(arena: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!CallToolResult {
        var r = try text(arena, fmt, args);
        r.isError = true;
        return r;
    }
};

pub const CallToolRequestParams = struct {
    _meta: RequestMetaObject,
    inputResponses: ?InputResponses = null,
    requestState: ?[]const u8 = null,
    name: []const u8,
    arguments: ?Value = null,
};

pub const ToolAnnotations = struct {
    title: ?[]const u8 = null,
    readOnlyHint: ?bool = null,
    destructiveHint: ?bool = null,
    idempotentHint: ?bool = null,
    openWorldHint: ?bool = null,
};

pub const Tool = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    icons: ?[]const Icon = null,
    description: ?[]const u8 = null,
    /// A JSON Schema object with `"type": "object"`.
    inputSchema: Value,
    outputSchema: ?Value = null,
    annotations: ?ToolAnnotations = null,
    _meta: ?MetaObject = null,
};

// ---------------------------------------------------------------------------------------------
// Logging (deprecated in 2026-07-28, still part of the schema)
// ---------------------------------------------------------------------------------------------

pub const LoggingLevel = enum {
    debug,
    info,
    notice,
    warning,
    @"error",
    critical,
    alert,
    emergency,

    /// Severity order: higher is more severe.
    pub fn severity(self: LoggingLevel) u8 {
        return @intFromEnum(self);
    }
};

pub const LoggingMessageNotificationParams = struct {
    _meta: ?NotificationMetaObject = null,
    level: LoggingLevel,
    logger: ?[]const u8 = null,
    data: Value,
};

// ---------------------------------------------------------------------------------------------
// Sampling (deprecated in 2026-07-28, still part of the schema)
// ---------------------------------------------------------------------------------------------

pub const CreateMessageRequestParams = struct {
    messages: []const SamplingMessage,
    modelPreferences: ?ModelPreferences = null,
    systemPrompt: ?[]const u8 = null,
    includeContext: ?enum { none, thisServer, allServers } = null,
    temperature: ?f64 = null,
    maxTokens: i64,
    stopSequences: ?[]const []const u8 = null,
    metadata: ?JSONObject = null,
    tools: ?[]const Tool = null,
    toolChoice: ?ToolChoice = null,
};

pub const ToolChoice = struct {
    mode: ?enum { auto, required, none } = null,
};

pub const CreateMessageRequest = struct {
    method: enum { @"sampling/createMessage" } = .@"sampling/createMessage",
    params: CreateMessageRequestParams,
};

pub const CreateMessageResult = struct {
    role: Role,
    content: SamplingContent,
    _meta: ?MetaObject = null,
    model: []const u8,
    /// `endTurn`, `stopSequence`, `maxTokens`, `toolUse` or any other string.
    stopReason: ?[]const u8 = null,
};

pub const SamplingMessage = struct {
    role: Role,
    content: SamplingContent,
    _meta: ?MetaObject = null,
};

/// One content block or an array of content blocks.
pub const SamplingContent = union(enum) {
    single: SamplingMessageContentBlock,
    list: []const SamplingMessageContentBlock,

    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !SamplingContent {
        const value = try std.json.innerParse(Value, allocator, source, options);
        return jsonParseFromValue(allocator, value, options);
    }

    pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: std.json.ParseOptions) !SamplingContent {
        return switch (source) {
            .array => .{ .list = try std.json.innerParseFromValue([]const SamplingMessageContentBlock, allocator, source, options) },
            .object => .{ .single = try std.json.innerParseFromValue(SamplingMessageContentBlock, allocator, source, options) },
            else => error.UnexpectedToken,
        };
    }

    pub fn jsonStringify(self: SamplingContent, jws: anytype) !void {
        switch (self) {
            inline else => |payload| try jws.write(payload),
        }
    }

    /// The content blocks as one slice.
    pub fn blocks(self: *const SamplingContent) []const SamplingMessageContentBlock {
        return switch (self.*) {
            .single => |*b| b[0..1],
            .list => |l| l,
        };
    }
};

pub const SamplingMessagesError = error{
    /// A user message has tool results and other content.
    MixedToolResults,
    /// A tool use has no tool result in the next message, or that message is not a user
    /// message with only tool results.
    UnmatchedToolUse,
};

/// Check the tool rules of the sampling messages. A user message with a tool result has
/// only tool results. The message after an assistant message with tool uses is a user
/// message with only tool results. It has a tool result for each tool use.
pub fn checkSamplingMessages(messages: []const SamplingMessage) SamplingMessagesError!void {
    for (messages, 0..) |*m, i| {
        const own = m.content.blocks();
        if (m.role == .user) {
            var results: usize = 0;
            for (own) |b| {
                if (b == .tool_result) results += 1;
            }
            if (results > 0 and results != own.len) return error.MixedToolResults;
            continue;
        }
        var uses: usize = 0;
        for (own) |b| {
            if (b == .tool_use) uses += 1;
        }
        if (uses == 0) continue;
        if (i + 1 >= messages.len or messages[i + 1].role != .user) return error.UnmatchedToolUse;
        const next = messages[i + 1].content.blocks();
        for (next) |b| if (b != .tool_result) return error.UnmatchedToolUse;
        for (own) |b| {
            if (b != .tool_use) continue;
            const found = for (next) |r| {
                if (std.mem.eql(u8, r.tool_result.toolUseId, b.tool_use.id)) break true;
            } else false;
            if (!found) return error.UnmatchedToolUse;
        }
    }
}

pub const SamplingMessageContentBlock = union(enum) {
    text: TextContent,
    image: ImageContent,
    audio: AudioContent,
    tool_use: ToolUseContent,
    tool_result: ToolResultContent,

    pub const jsonParse = json.Discriminated(@This(), "type").jsonParse;
    pub const jsonParseFromValue = json.Discriminated(@This(), "type").jsonParseFromValue;
    pub const jsonStringify = json.Discriminated(@This(), "type").jsonStringify;
};

pub const Annotations = struct {
    audience: ?[]const Role = null,
    priority: ?f64 = null,
    lastModified: ?[]const u8 = null,
};

pub const ContentBlock = union(enum) {
    text: TextContent,
    image: ImageContent,
    audio: AudioContent,
    resource_link: ResourceLink,
    resource: EmbeddedResource,

    pub const jsonParse = json.Discriminated(@This(), "type").jsonParse;
    pub const jsonParseFromValue = json.Discriminated(@This(), "type").jsonParseFromValue;
    pub const jsonStringify = json.Discriminated(@This(), "type").jsonStringify;
};

pub const TextContent = struct {
    type: enum { text } = .text,
    text: []const u8,
    annotations: ?Annotations = null,
    _meta: ?MetaObject = null,
};

pub const ImageContent = struct {
    type: enum { image } = .image,
    /// Base64-encoded bytes.
    data: []const u8,
    mimeType: []const u8,
    annotations: ?Annotations = null,
    _meta: ?MetaObject = null,
};

pub const AudioContent = struct {
    type: enum { audio } = .audio,
    /// Base64-encoded bytes.
    data: []const u8,
    mimeType: []const u8,
    annotations: ?Annotations = null,
    _meta: ?MetaObject = null,
};

pub const ToolUseContent = struct {
    type: enum { tool_use } = .tool_use,
    id: []const u8,
    name: []const u8,
    input: Value,
    _meta: ?MetaObject = null,
};

pub const ToolResultContent = struct {
    type: enum { tool_result } = .tool_result,
    toolUseId: []const u8,
    content: []const ContentBlock,
    structuredContent: ?Value = null,
    isError: ?bool = null,
    _meta: ?MetaObject = null,
};

pub const ModelPreferences = struct {
    hints: ?[]const ModelHint = null,
    costPriority: ?f64 = null,
    speedPriority: ?f64 = null,
    intelligencePriority: ?f64 = null,
};

pub const ModelHint = struct {
    name: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------------------------

pub const CompleteRequestParams = struct {
    _meta: RequestMetaObject,
    ref: CompletionReference,
    argument: struct {
        name: []const u8,
        value: []const u8,
    },
    context: ?struct {
        arguments: ?std.json.ArrayHashMap([]const u8) = null,
    } = null,
};

pub const CompletionReference = union(enum) {
    @"ref/prompt": PromptReference,
    @"ref/resource": ResourceTemplateReference,

    pub const jsonParse = json.Discriminated(@This(), "type").jsonParse;
    pub const jsonParseFromValue = json.Discriminated(@This(), "type").jsonParseFromValue;
    pub const jsonStringify = json.Discriminated(@This(), "type").jsonStringify;
};

pub const CompleteResult = struct {
    _meta: ?ResultMetaObject = null,
    resultType: []const u8 = result_type_complete,
    completion: Completion,

    pub const Completion = struct {
        values: []const []const u8,
        total: ?i64 = null,
        hasMore: ?bool = null,
    };
};

pub const ResourceTemplateReference = struct {
    type: enum { @"ref/resource" } = .@"ref/resource",
    uri: []const u8,
};

pub const PromptReference = struct {
    type: enum { @"ref/prompt" } = .@"ref/prompt",
    name: []const u8,
    title: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------------------------
// Roots (deprecated in 2026-07-28, still part of the schema)
// ---------------------------------------------------------------------------------------------

pub const ListRootsRequest = struct {
    method: enum { @"roots/list" } = .@"roots/list",
    params: ?struct {
        _meta: ?MetaObject = null,
    } = null,
};

pub const ListRootsResult = struct {
    roots: []const Root,
};

pub const Root = struct {
    uri: []const u8,
    name: ?[]const u8 = null,
    _meta: ?MetaObject = null,
};

// ---------------------------------------------------------------------------------------------
// Elicitation
// ---------------------------------------------------------------------------------------------

pub const ElicitationMode = enum { form, url };

pub const ElicitRequestFormParams = struct {
    mode: ?enum { form } = null,
    message: []const u8,
    requestedSchema: RequestedSchema,

    pub const RequestedSchema = struct {
        @"$schema": ?[]const u8 = null,
        type: enum { object } = .object,
        properties: std.json.ArrayHashMap(PrimitiveSchemaDefinition),
        required: ?[]const []const u8 = null,
    };
};

pub const ElicitRequestURLParams = struct {
    mode: enum { url } = .url,
    message: []const u8,
    url: []const u8,
};

/// True when `text` is a valid absolute URL. The URL has a scheme and a host that is not
/// empty. It has no space and no ASCII control character.
pub fn isValidUrl(text: []const u8) bool {
    for (text) |c| if (c <= 0x20 or c == 0x7f) return false;
    const uri = std.Uri.parse(text) catch return false;
    const host = uri.host orelse return false;
    return !host.isEmpty();
}

pub const ElicitRequestParams = union(enum) {
    form: ElicitRequestFormParams,
    url: ElicitRequestURLParams,

    fn classify(v: Value) ?std.meta.Tag(ElicitRequestParams) {
        if (v != .object) return null;
        const mode_text = json.getString(v, "mode") orelse return .form;
        if (std.mem.eql(u8, mode_text, "url")) return .url;
        if (std.mem.eql(u8, mode_text, "form")) return .form;
        return null;
    }
    pub const jsonParse = json.Classified(@This(), classify).jsonParse;
    pub const jsonParseFromValue = json.Classified(@This(), classify).jsonParseFromValue;
    pub const jsonStringify = json.Classified(@This(), classify).jsonStringify;

    pub fn mode(self: ElicitRequestParams) ElicitationMode {
        return switch (self) {
            .form => .form,
            .url => .url,
        };
    }
};

pub const ElicitRequest = struct {
    method: enum { @"elicitation/create" } = .@"elicitation/create",
    params: ElicitRequestParams,
};

pub const PrimitiveSchemaDefinition = union(enum) {
    string: StringSchema,
    number: NumberSchema,
    boolean: BooleanSchema,
    @"enum": EnumSchema,

    fn classify(v: Value) ?std.meta.Tag(PrimitiveSchemaDefinition) {
        const t = json.getString(v, "type") orelse return null;
        if (std.mem.eql(u8, t, "boolean")) return .boolean;
        if (std.mem.eql(u8, t, "number") or std.mem.eql(u8, t, "integer")) return .number;
        if (std.mem.eql(u8, t, "array")) return .@"enum";
        if (std.mem.eql(u8, t, "string")) {
            if (json.hasKey(v, "enum") or json.hasKey(v, "oneOf")) return .@"enum";
            return .string;
        }
        return null;
    }
    pub const jsonParse = json.Classified(@This(), classify).jsonParse;
    pub const jsonParseFromValue = json.Classified(@This(), classify).jsonParseFromValue;
    pub const jsonStringify = json.Classified(@This(), classify).jsonStringify;
};

pub const StringSchema = struct {
    type: enum { string } = .string,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    minLength: ?i64 = null,
    maxLength: ?i64 = null,
    format: ?enum { email, uri, date, @"date-time" } = null,
    default: ?[]const u8 = null,
};

pub const NumberSchema = struct {
    type: enum { number, integer },
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    minimum: ?f64 = null,
    maximum: ?f64 = null,
    default: ?f64 = null,
};

pub const BooleanSchema = struct {
    type: enum { boolean } = .boolean,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    default: ?bool = null,
};

pub const UntitledSingleSelectEnumSchema = struct {
    type: enum { string } = .string,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    @"enum": []const []const u8,
    default: ?[]const u8 = null,
};

pub const TitledOption = struct {
    @"const": []const u8,
    title: []const u8,
};

pub const TitledSingleSelectEnumSchema = struct {
    type: enum { string } = .string,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    oneOf: []const TitledOption,
    default: ?[]const u8 = null,
};

pub const SingleSelectEnumSchema = union(enum) {
    untitled: UntitledSingleSelectEnumSchema,
    titled: TitledSingleSelectEnumSchema,

    fn classify(v: Value) ?std.meta.Tag(SingleSelectEnumSchema) {
        if (json.hasKey(v, "oneOf")) return .titled;
        if (json.hasKey(v, "enum")) return .untitled;
        return null;
    }
    pub const jsonParse = json.Classified(@This(), classify).jsonParse;
    pub const jsonParseFromValue = json.Classified(@This(), classify).jsonParseFromValue;
    pub const jsonStringify = json.Classified(@This(), classify).jsonStringify;
};

pub const UntitledMultiSelectEnumSchema = struct {
    type: enum { array } = .array,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    minItems: ?i64 = null,
    maxItems: ?i64 = null,
    items: struct {
        type: enum { string } = .string,
        @"enum": []const []const u8,
    },
    default: ?[]const []const u8 = null,
};

pub const TitledMultiSelectEnumSchema = struct {
    type: enum { array } = .array,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    minItems: ?i64 = null,
    maxItems: ?i64 = null,
    items: struct {
        anyOf: []const TitledOption,
    },
    default: ?[]const []const u8 = null,
};

pub const MultiSelectEnumSchema = union(enum) {
    untitled: UntitledMultiSelectEnumSchema,
    titled: TitledMultiSelectEnumSchema,

    fn classify(v: Value) ?std.meta.Tag(MultiSelectEnumSchema) {
        if (v != .object) return null;
        const items = v.object.get("items") orelse return null;
        if (json.hasKey(items, "anyOf")) return .titled;
        if (json.hasKey(items, "enum")) return .untitled;
        return null;
    }
    pub const jsonParse = json.Classified(@This(), classify).jsonParse;
    pub const jsonParseFromValue = json.Classified(@This(), classify).jsonParseFromValue;
    pub const jsonStringify = json.Classified(@This(), classify).jsonStringify;
};

pub const LegacyTitledEnumSchema = struct {
    type: enum { string } = .string,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    @"enum": []const []const u8,
    enumNames: ?[]const []const u8 = null,
    default: ?[]const u8 = null,
};

pub const EnumSchema = union(enum) {
    single_select: SingleSelectEnumSchema,
    multi_select: MultiSelectEnumSchema,
    legacy_titled: LegacyTitledEnumSchema,

    fn classify(v: Value) ?std.meta.Tag(EnumSchema) {
        const t = json.getString(v, "type") orelse return null;
        if (std.mem.eql(u8, t, "array")) return .multi_select;
        if (json.hasKey(v, "enumNames")) return .legacy_titled;
        return .single_select;
    }
    pub const jsonParse = json.Classified(@This(), classify).jsonParse;
    pub const jsonParseFromValue = json.Classified(@This(), classify).jsonParseFromValue;
    pub const jsonStringify = json.Classified(@This(), classify).jsonStringify;
};

pub const ElicitResult = struct {
    action: enum { accept, decline, cancel },
    content: ?Value = null,
};

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

test "content block discriminated round trip" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text = "{\"type\":\"image\",\"data\":\"AAAA\",\"mimeType\":\"image/png\"}";
    const tree = try json.parseTree(arena, text);
    const block = try json.parseValue(ContentBlock, arena, tree);
    try std.testing.expect(block == .image);
    try std.testing.expectEqualStrings("image/png", block.image.mimeType);
    const out = try json.writeAlloc(gpa, block);
    defer gpa.free(out);
    try std.testing.expectEqualStrings(text, out);
}

test "elicitation form params default mode" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text =
        \\{"message":"Name?","requestedSchema":{"type":"object","properties":{"name":{"type":"string"},"n":{"type":"integer","minimum":1},"ok":{"type":"boolean"},"c":{"type":"string","enum":["a","b"]},"m":{"type":"array","items":{"type":"string","enum":["x"]}}},"required":["name"]}}
    ;
    const tree = try json.parseTree(arena, text);
    const params = try json.parseValue(ElicitRequestParams, arena, tree);
    try std.testing.expect(params == .form);
    const props = params.form.requestedSchema.properties.map;
    try std.testing.expect(props.get("name").? == .string);
    try std.testing.expect(props.get("n").? == .number);
    try std.testing.expect(props.get("ok").? == .boolean);
    try std.testing.expect(props.get("c").? == .@"enum");
    try std.testing.expect(props.get("c").?.@"enum" == .single_select);
    try std.testing.expect(props.get("m").?.@"enum" == .multi_select);
}

test "valid URLs for URL elicitation" {
    const good = [_][]const u8{ "https://example.com/connect", "http://localhost:8080/a?b=c#d", "https://xn--bcher-kva.example/", "custom-app://host/path" };
    for (good) |u| try std.testing.expect(isValidUrl(u));
    const bad = [_][]const u8{ "", "example.com/connect", "/relative/path", "https://", "https:///path", "mailto:user@example.com", "https://exa mple.com/", "https://example.com/\n", "1http://example.com/" };
    for (bad) |u| try std.testing.expect(!isValidUrl(u));
}

test "sampling message tool rules" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Case = struct { text: []const u8, err: ?SamplingMessagesError };
    const cases = [_]Case{
        .{ .text = "[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"hi\"}}]", .err = null },
        // Two tool uses, both answered in the next user message.
        .{ .text = "[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"w?\"}},{\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"a\",\"name\":\"w\",\"input\":{}},{\"type\":\"tool_use\",\"id\":\"b\",\"name\":\"w\",\"input\":{}}]},{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"toolUseId\":\"b\",\"content\":[]},{\"type\":\"tool_result\",\"toolUseId\":\"a\",\"content\":[]}]},{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":\"ok\"}}]", .err = null },
        // A tool result together with text.
        .{ .text = "[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"here\"},{\"type\":\"tool_result\",\"toolUseId\":\"a\",\"content\":[]}]}]", .err = error.MixedToolResults },
        // The result for "b" is missing.
        .{ .text = "[{\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"a\",\"name\":\"w\",\"input\":{}},{\"type\":\"tool_use\",\"id\":\"b\",\"name\":\"w\",\"input\":{}}]},{\"role\":\"user\",\"content\":{\"type\":\"tool_result\",\"toolUseId\":\"a\",\"content\":[]}}]", .err = error.UnmatchedToolUse },
        // Another message comes before the tool result.
        .{ .text = "[{\"role\":\"assistant\",\"content\":{\"type\":\"tool_use\",\"id\":\"a\",\"name\":\"w\",\"input\":{}}},{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":\"x\"}},{\"role\":\"user\",\"content\":{\"type\":\"tool_result\",\"toolUseId\":\"a\",\"content\":[]}}]", .err = error.UnmatchedToolUse },
        // The tool use is the last message.
        .{ .text = "[{\"role\":\"assistant\",\"content\":{\"type\":\"tool_use\",\"id\":\"a\",\"name\":\"w\",\"input\":{}}}]", .err = error.UnmatchedToolUse },
    };
    for (cases) |c| {
        const messages = try json.parseValue([]const SamplingMessage, arena, try json.parseTree(arena, c.text));
        if (c.err) |e| {
            try std.testing.expectError(e, checkSamplingMessages(messages));
        } else try checkSamplingMessages(messages);
    }
}
