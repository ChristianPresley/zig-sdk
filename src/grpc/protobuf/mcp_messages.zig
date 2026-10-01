//! The messages of `mcp_messages.proto` (package `model_context_protocol`) that the eight RPCs
//! of the typed binding use. The field numbers follow the proto file of the Google Cloud
//! repository `mcp-grpc-transport-proto`, release v0.2.0. A copy of the file is in
//! `test/fixtures/google_mcp_grpc_proto/`.
//!
//! The struct field names are the proto field names. `codec` encodes and decodes the
//! messages. The decoder skips the deprecated fields `resume_data`, the `minimum` and
//! `maximum` of `NumberSchema` and every other unknown field.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const codec = @import("codec.zig");
const well_known = @import("well_known.zig");
const F = codec.Field;

pub const Duration = well_known.Duration;

/// The package and service name of the typed binding.
pub const service_name = "model_context_protocol.Mcp";

// -- Enumerations --------------------------------------------------------------------------------

pub const ResultType = enum(i32) { unspecified = 0, complete = 1, input_required = 2, _ };
pub const CacheScope = enum(i32) { unspecified = 0, public = 1, private = 2, _ };
pub const Role = enum(i32) { unknown = 0, user = 1, assistant = 2, _ };

// -- Common fields -------------------------------------------------------------------------------

/// An entry of `map<string, InputResponse>`.
pub const InputResponseEntry = struct {
    key: []const u8 = "",
    value: ?InputResponse = null,
    pub const proto = [_]F{
        .{ .name = "key", .number = 1, .kind = .string },
        .{ .name = "value", .number = 2, .kind = .message },
    };
};

/// An entry of `map<string, InputRequest>`.
pub const InputRequestEntry = struct {
    key: []const u8 = "",
    value: ?InputRequest = null,
    pub const proto = [_]F{
        .{ .name = "key", .number = 1, .kind = .string },
        .{ .name = "value", .number = 2, .kind = .message },
    };
};

/// An entry of `map<string, string>`.
pub const StringEntry = struct {
    key: []const u8 = "",
    value: []const u8 = "",
    pub const proto = [_]F{
        .{ .name = "key", .number = 1, .kind = .string },
        .{ .name = "value", .number = 2, .kind = .string },
    };
};

pub const RequestFields = struct {
    metadata: ?Value = null,
    input_responses: []const InputResponseEntry = &.{},
    request_state: ?[]const u8 = null,
    pub const proto = [_]F{
        .{ .name = "metadata", .number = 1, .kind = .json_struct },
        .{ .name = "input_responses", .number = 6, .kind = .message },
        .{ .name = "request_state", .number = 8, .kind = .string },
    };
};

pub const ResponseFields = struct {
    instructions: []const u8 = "",
    metadata: ?Value = null,
    input_requests: []const InputRequestEntry = &.{},
    result_type: ResultType = .unspecified,
    request_state: ?[]const u8 = null,
    pub const proto = [_]F{
        .{ .name = "instructions", .number = 1, .kind = .string },
        .{ .name = "metadata", .number = 2, .kind = .json_struct },
        .{ .name = "input_requests", .number = 7, .kind = .message },
        .{ .name = "result_type", .number = 9, .kind = .enumeration },
        .{ .name = "request_state", .number = 10, .kind = .string },
    };
};

// -- Input requests and responses ----------------------------------------------------------------

pub const InputRequest = struct {
    sampling_create_message: ?SamplingCreateMessageRequest = null,
    list_roots_request: ?ListRootsRequest = null,
    notify_on_root_list_update: bool = false,
    elicit_request: ?ElicitRequest = null,
    pub const proto = [_]F{
        .{ .name = "sampling_create_message", .number = 8, .kind = .message },
        .{ .name = "list_roots_request", .number = 9, .kind = .message },
        .{ .name = "notify_on_root_list_update", .number = 10, .kind = .bool },
        .{ .name = "elicit_request", .number = 11, .kind = .message },
    };
};

pub const InputResponse = struct {
    sampling_create_message_result: ?SamplingCreateMessageResult = null,
    root_list_result: ?ListRootsResult = null,
    elicit_result: ?ElicitResult = null,
    pub const proto = [_]F{
        .{ .name = "sampling_create_message_result", .number = 7, .kind = .message },
        .{ .name = "root_list_result", .number = 8, .kind = .message },
        .{ .name = "elicit_result", .number = 9, .kind = .message },
    };
};

pub const ListRootsRequest = struct {
    pub const proto = [_]F{};
};

pub const ListRootsResult = struct {
    roots: []const Root = &.{},
    pub const proto = [_]F{.{ .name = "roots", .number = 1, .kind = .message }};

    pub const Root = struct {
        uri: []const u8 = "",
        name: []const u8 = "",
        pub const proto = [_]F{
            .{ .name = "uri", .number = 1, .kind = .string },
            .{ .name = "name", .number = 2, .kind = .string },
        };
    };
};

pub const SamplingMessage = struct {
    role: Role = .unknown,
    text: ?TextContent = null,
    image: ?ImageContent = null,
    audio: ?AudioContent = null,
    pub const proto = [_]F{
        .{ .name = "role", .number = 1, .kind = .enumeration },
        .{ .name = "text", .number = 2, .kind = .message },
        .{ .name = "image", .number = 3, .kind = .message },
        .{ .name = "audio", .number = 4, .kind = .message },
    };
};

pub const SamplingCreateMessageRequest = struct {
    messages: []const SamplingMessage = &.{},
    model_preferences: ?ModelPreferences = null,
    system_prompt: []const u8 = "",
    include_context: IncludeContext = .none,
    temperature: ?f32 = null,
    max_tokens: i32 = 0,
    stop_sequence: []const []const u8 = &.{},
    pub const proto = [_]F{
        .{ .name = "messages", .number = 1, .kind = .message },
        .{ .name = "model_preferences", .number = 2, .kind = .message },
        .{ .name = "system_prompt", .number = 3, .kind = .string },
        .{ .name = "include_context", .number = 4, .kind = .enumeration },
        .{ .name = "temperature", .number = 5, .kind = .float },
        .{ .name = "max_tokens", .number = 6, .kind = .int32 },
        .{ .name = "stop_sequence", .number = 7, .kind = .string },
    };

    pub const IncludeContext = enum(i32) { none = 0, this_server = 1, all_servers = 2, _ };

    pub const ModelPreferences = struct {
        hints: []const ModelHint = &.{},
        intelligence_priority: ?f32 = null,
        speed_priority: ?f32 = null,
        cost_priority: ?f32 = null,
        pub const proto = [_]F{
            .{ .name = "hints", .number = 1, .kind = .message },
            .{ .name = "intelligence_priority", .number = 2, .kind = .float },
            .{ .name = "speed_priority", .number = 3, .kind = .float },
            .{ .name = "cost_priority", .number = 4, .kind = .float },
        };
    };

    pub const ModelHint = struct {
        name: []const u8 = "",
        pub const proto = [_]F{.{ .name = "name", .number = 1, .kind = .string }};
    };
};

pub const SamplingCreateMessageResult = struct {
    message: ?SamplingMessage = null,
    model: []const u8 = "",
    stop_reason: []const u8 = "",
    pub const proto = [_]F{
        .{ .name = "message", .number = 1, .kind = .message },
        .{ .name = "model", .number = 2, .kind = .string },
        .{ .name = "stop_reason", .number = 3, .kind = .string },
    };
};

pub const PrimitiveSchemaDefinition = struct {
    string_schema: ?StringSchema = null,
    number_schema: ?NumberSchema = null,
    boolean_schema: ?BooleanSchema = null,
    enum_schema: ?EnumSchema = null,
    pub const proto = [_]F{
        .{ .name = "string_schema", .number = 1, .kind = .message },
        .{ .name = "number_schema", .number = 2, .kind = .message },
        .{ .name = "boolean_schema", .number = 3, .kind = .message },
        .{ .name = "enum_schema", .number = 4, .kind = .message },
    };

    pub const StringSchema = struct {
        title: []const u8 = "",
        description: []const u8 = "",
        min_length: ?u64 = null,
        max_length: ?u64 = null,
        format: Format = .unknown,
        default_value: ?[]const u8 = null,
        pub const proto = [_]F{
            .{ .name = "title", .number = 1, .kind = .string },
            .{ .name = "description", .number = 2, .kind = .string },
            .{ .name = "min_length", .number = 3, .kind = .uint64 },
            .{ .name = "max_length", .number = 4, .kind = .uint64 },
            .{ .name = "format", .number = 5, .kind = .enumeration },
            .{ .name = "default_value", .number = 6, .kind = .string },
        };

        pub const Format = enum(i32) { unknown = 0, email = 1, uri = 2, date = 3, date_time = 4, _ };
    };

    pub const NumberSchema = struct {
        title: []const u8 = "",
        description: []const u8 = "",
        double_range: ?DoubleRange = null,
        integer_range: ?IntegerRange = null,
        default_number: ?f64 = null,
        default_integer: ?i64 = null,
        pub const proto = [_]F{
            .{ .name = "title", .number = 1, .kind = .string },
            .{ .name = "description", .number = 2, .kind = .string },
            .{ .name = "double_range", .number = 5, .kind = .message },
            .{ .name = "integer_range", .number = 6, .kind = .message },
            .{ .name = "default_number", .number = 7, .kind = .double },
            .{ .name = "default_integer", .number = 8, .kind = .int64 },
        };

        pub const DoubleRange = struct {
            minimum: ?f64 = null,
            maximum: ?f64 = null,
            pub const proto = [_]F{
                .{ .name = "minimum", .number = 1, .kind = .double },
                .{ .name = "maximum", .number = 2, .kind = .double },
            };
        };

        pub const IntegerRange = struct {
            minimum: ?i64 = null,
            maximum: ?i64 = null,
            pub const proto = [_]F{
                .{ .name = "minimum", .number = 1, .kind = .int64 },
                .{ .name = "maximum", .number = 2, .kind = .int64 },
            };
        };
    };

    pub const BooleanSchema = struct {
        title: []const u8 = "",
        description: []const u8 = "",
        default: bool = false,
        pub const proto = [_]F{
            .{ .name = "title", .number = 1, .kind = .string },
            .{ .name = "description", .number = 2, .kind = .string },
            .{ .name = "default", .number = 3, .kind = .bool },
        };
    };

    pub const EnumSchema = struct {
        title: []const u8 = "",
        description: []const u8 = "",
        enum_list: []const []const u8 = &.{},
        enum_names: []const []const u8 = &.{},
        single_select: ?SingleSelect = null,
        multi_select: ?MultiSelect = null,
        pub const proto = [_]F{
            .{ .name = "title", .number = 1, .kind = .string },
            .{ .name = "description", .number = 2, .kind = .string },
            .{ .name = "enum_list", .number = 3, .kind = .string },
            .{ .name = "enum_names", .number = 4, .kind = .string },
            .{ .name = "single_select", .number = 5, .kind = .message },
            .{ .name = "multi_select", .number = 6, .kind = .message },
        };

        pub const MultiSelect = struct {
            default_items: []const []const u8 = &.{},
            min_items: ?u32 = null,
            max_items: ?u32 = null,
            pub const proto = [_]F{
                .{ .name = "default_items", .number = 1, .kind = .string },
                .{ .name = "min_items", .number = 2, .kind = .uint32 },
                .{ .name = "max_items", .number = 3, .kind = .uint32 },
            };
        };

        pub const SingleSelect = struct {
            default_item: ?[]const u8 = null,
            pub const proto = [_]F{.{ .name = "default_item", .number = 1, .kind = .string }};
        };
    };
};

/// An entry of `map<string, PrimitiveSchemaDefinition>`.
pub const SchemaEntry = struct {
    key: []const u8 = "",
    value: ?PrimitiveSchemaDefinition = null,
    pub const proto = [_]F{
        .{ .name = "key", .number = 1, .kind = .string },
        .{ .name = "value", .number = 2, .kind = .message },
    };
};

pub const ElicitRequest = struct {
    message: []const u8 = "",
    requested_schema: []const SchemaEntry = &.{},
    required_fields: []const []const u8 = &.{},
    url_mode: ?UrlMode = null,
    pub const proto = [_]F{
        .{ .name = "message", .number = 1, .kind = .string },
        .{ .name = "requested_schema", .number = 2, .kind = .message },
        .{ .name = "required_fields", .number = 3, .kind = .string },
        .{ .name = "url_mode", .number = 4, .kind = .message },
    };

    pub const UrlMode = struct {
        id: []const u8 = "",
        url: []const u8 = "",
        pub const proto = [_]F{
            .{ .name = "id", .number = 1, .kind = .string },
            .{ .name = "url", .number = 2, .kind = .string },
        };
    };
};

pub const ElicitResult = struct {
    type: Type = .unknown,
    content: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "type", .number = 1, .kind = .enumeration },
        .{ .name = "content", .number = 2, .kind = .json_struct },
    };

    pub const Type = enum(i32) { unknown = 0, accept = 1, decline = 2, cancel = 3, _ };
};

// -- Content -------------------------------------------------------------------------------------

pub const Annotations = struct {
    audience: []const Role = &.{},
    priority: ?f32 = null,
    last_modified: ?[]const u8 = null,
    pub const proto = [_]F{
        .{ .name = "audience", .number = 1, .kind = .enumeration },
        .{ .name = "priority", .number = 2, .kind = .float },
        .{ .name = "last_modified", .number = 3, .kind = .string },
    };
};

pub const Icon = struct {
    src: []const u8 = "",
    mime_type: []const u8 = "",
    sizes: []const []const u8 = &.{},
    theme: Theme = .unspecified,
    pub const proto = [_]F{
        .{ .name = "src", .number = 1, .kind = .string },
        .{ .name = "mime_type", .number = 2, .kind = .string },
        .{ .name = "sizes", .number = 3, .kind = .string },
        .{ .name = "theme", .number = 4, .kind = .enumeration },
    };

    pub const Theme = enum(i32) { unspecified = 0, light = 1, dark = 2, _ };
};

pub const TextContent = struct {
    text: []const u8 = "",
    annotations: ?Annotations = null,
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "text", .number = 1, .kind = .string },
        .{ .name = "annotations", .number = 2, .kind = .message },
        .{ .name = "metadata", .number = 3, .kind = .json_struct },
    };
};

/// `ImageContent`. As in the reference transport, `data` has the base64 text of MCP.
pub const ImageContent = struct {
    data: []const u8 = "",
    mime_type: []const u8 = "",
    annotations: ?Annotations = null,
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "data", .number = 1, .kind = .bytes },
        .{ .name = "mime_type", .number = 2, .kind = .string },
        .{ .name = "annotations", .number = 3, .kind = .message },
        .{ .name = "metadata", .number = 4, .kind = .json_struct },
    };
};

/// `AudioContent`. As in the reference transport, `data` has the base64 text of MCP.
pub const AudioContent = ImageContent;

pub const ResourceContents = struct {
    uri: []const u8 = "",
    mime_type: []const u8 = "",
    text: []const u8 = "",
    /// The base64 text of MCP, as in the reference transport.
    blob: []const u8 = "",
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "uri", .number = 1, .kind = .string },
        .{ .name = "mime_type", .number = 2, .kind = .string },
        .{ .name = "text", .number = 3, .kind = .string },
        .{ .name = "blob", .number = 4, .kind = .bytes },
        .{ .name = "metadata", .number = 5, .kind = .json_struct },
    };
};

pub const EmbeddedResource = struct {
    contents: ?ResourceContents = null,
    annotations: ?Annotations = null,
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "contents", .number = 1, .kind = .message },
        .{ .name = "annotations", .number = 2, .kind = .message },
        .{ .name = "metadata", .number = 3, .kind = .json_struct },
    };
};

// -- Resources -----------------------------------------------------------------------------------

pub const Resource = struct {
    uri: []const u8 = "",
    name: []const u8 = "",
    title: []const u8 = "",
    description: []const u8 = "",
    mime_type: []const u8 = "",
    annotations: ?Annotations = null,
    size: u64 = 0,
    icons: []const Icon = &.{},
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "uri", .number = 1, .kind = .string },
        .{ .name = "name", .number = 2, .kind = .string },
        .{ .name = "title", .number = 7, .kind = .string },
        .{ .name = "description", .number = 3, .kind = .string },
        .{ .name = "mime_type", .number = 4, .kind = .string },
        .{ .name = "annotations", .number = 5, .kind = .message },
        .{ .name = "size", .number = 6, .kind = .uint64 },
        .{ .name = "icons", .number = 8, .kind = .message },
        .{ .name = "metadata", .number = 9, .kind = .json_struct },
    };
};

pub const ListResourcesRequest = struct {
    common: ?RequestFields = null,
    pub const proto = [_]F{.{ .name = "common", .number = 1, .kind = .message }};
};

pub const ListResourcesResponse = struct {
    common: ?ResponseFields = null,
    resources: []const Resource = &.{},
    ttl: ?Duration = null,
    cache_scope: CacheScope = .unspecified,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "resources", .number = 2, .kind = .message },
        .{ .name = "ttl", .number = 3, .kind = .message },
        .{ .name = "cache_scope", .number = 4, .kind = .enumeration },
    };
};

pub const ReadResourceRequest = struct {
    common: ?RequestFields = null,
    uri: []const u8 = "",
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "uri", .number = 2, .kind = .string },
    };
};

pub const ReadResourceResponse = struct {
    common: ?ResponseFields = null,
    resource: []const ResourceContents = &.{},
    ttl: ?Duration = null,
    cache_scope: CacheScope = .unspecified,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "resource", .number = 2, .kind = .message },
        .{ .name = "ttl", .number = 3, .kind = .message },
        .{ .name = "cache_scope", .number = 4, .kind = .enumeration },
    };
};

pub const ResourceTemplate = struct {
    uri_template: []const u8 = "",
    name: []const u8 = "",
    title: []const u8 = "",
    description: []const u8 = "",
    mime_type: []const u8 = "",
    annotations: ?Annotations = null,
    icons: []const Icon = &.{},
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "uri_template", .number = 1, .kind = .string },
        .{ .name = "name", .number = 2, .kind = .string },
        .{ .name = "title", .number = 6, .kind = .string },
        .{ .name = "description", .number = 3, .kind = .string },
        .{ .name = "mime_type", .number = 4, .kind = .string },
        .{ .name = "annotations", .number = 5, .kind = .message },
        .{ .name = "icons", .number = 7, .kind = .message },
        .{ .name = "metadata", .number = 8, .kind = .json_struct },
    };
};

pub const ListResourceTemplatesRequest = ListResourcesRequest;

pub const ListResourceTemplatesResponse = struct {
    common: ?ResponseFields = null,
    resource_templates: []const ResourceTemplate = &.{},
    ttl: ?Duration = null,
    cache_scope: CacheScope = .unspecified,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "resource_templates", .number = 2, .kind = .message },
        .{ .name = "ttl", .number = 3, .kind = .message },
        .{ .name = "cache_scope", .number = 4, .kind = .enumeration },
    };
};

// -- Prompts -------------------------------------------------------------------------------------

pub const Prompt = struct {
    name: []const u8 = "",
    title: []const u8 = "",
    description: []const u8 = "",
    arguments: []const Argument = &.{},
    icons: []const Icon = &.{},
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "name", .number = 1, .kind = .string },
        .{ .name = "title", .number = 4, .kind = .string },
        .{ .name = "description", .number = 2, .kind = .string },
        .{ .name = "arguments", .number = 3, .kind = .message },
        .{ .name = "icons", .number = 5, .kind = .message },
        .{ .name = "metadata", .number = 6, .kind = .json_struct },
    };

    pub const Argument = struct {
        name: []const u8 = "",
        title: []const u8 = "",
        description: []const u8 = "",
        required: bool = false,
        pub const proto = [_]F{
            .{ .name = "name", .number = 1, .kind = .string },
            .{ .name = "title", .number = 4, .kind = .string },
            .{ .name = "description", .number = 2, .kind = .string },
            .{ .name = "required", .number = 3, .kind = .bool },
        };
    };
};

pub const ListPromptsRequest = ListResourcesRequest;

pub const ListPromptsResponse = struct {
    common: ?ResponseFields = null,
    prompts: []const Prompt = &.{},
    ttl: ?Duration = null,
    cache_scope: CacheScope = .unspecified,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "prompts", .number = 2, .kind = .message },
        .{ .name = "ttl", .number = 3, .kind = .message },
        .{ .name = "cache_scope", .number = 4, .kind = .enumeration },
    };
};

pub const PromptMessage = struct {
    role: Role = .unknown,
    text: ?TextContent = null,
    image: ?ImageContent = null,
    audio: ?AudioContent = null,
    embedded_resource: ?EmbeddedResource = null,
    resource_link: ?Resource = null,
    pub const proto = [_]F{
        .{ .name = "role", .number = 1, .kind = .enumeration },
        .{ .name = "text", .number = 2, .kind = .message },
        .{ .name = "image", .number = 3, .kind = .message },
        .{ .name = "audio", .number = 4, .kind = .message },
        .{ .name = "embedded_resource", .number = 5, .kind = .message },
        .{ .name = "resource_link", .number = 6, .kind = .message },
    };
};

pub const GetPromptRequest = struct {
    common: ?RequestFields = null,
    name: []const u8 = "",
    arguments: []const StringEntry = &.{},
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "name", .number = 2, .kind = .string },
        .{ .name = "arguments", .number = 3, .kind = .message },
    };
};

pub const GetPromptResponse = struct {
    common: ?ResponseFields = null,
    description: []const u8 = "",
    messages: []const PromptMessage = &.{},
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "description", .number = 2, .kind = .string },
        .{ .name = "messages", .number = 3, .kind = .message },
    };
};

// -- Tools ---------------------------------------------------------------------------------------

pub const ToolAnnotations = struct {
    title: []const u8 = "",
    read_only_hint: bool = false,
    destructive_hint: bool = false,
    idempotent_hint: bool = false,
    open_world_hint: bool = false,
    pub const proto = [_]F{
        .{ .name = "title", .number = 1, .kind = .string },
        .{ .name = "read_only_hint", .number = 2, .kind = .bool },
        .{ .name = "destructive_hint", .number = 3, .kind = .bool },
        .{ .name = "idempotent_hint", .number = 4, .kind = .bool },
        .{ .name = "open_world_hint", .number = 5, .kind = .bool },
    };
};

pub const Tool = struct {
    name: []const u8 = "",
    title: []const u8 = "",
    description: []const u8 = "",
    input_schema: ?Value = null,
    output_schema: ?Value = null,
    annotations: ?ToolAnnotations = null,
    icons: []const Icon = &.{},
    metadata: ?Value = null,
    pub const proto = [_]F{
        .{ .name = "name", .number = 1, .kind = .string },
        .{ .name = "title", .number = 6, .kind = .string },
        .{ .name = "description", .number = 2, .kind = .string },
        .{ .name = "input_schema", .number = 3, .kind = .json_struct },
        .{ .name = "output_schema", .number = 5, .kind = .json_struct },
        .{ .name = "annotations", .number = 4, .kind = .message },
        .{ .name = "icons", .number = 7, .kind = .message },
        .{ .name = "metadata", .number = 8, .kind = .json_struct },
    };
};

pub const ListToolsRequest = ListResourcesRequest;

pub const ListToolsResponse = struct {
    common: ?ResponseFields = null,
    tools: []const Tool = &.{},
    ttl: ?Duration = null,
    cache_scope: CacheScope = .unspecified,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "tools", .number = 2, .kind = .message },
        .{ .name = "ttl", .number = 3, .kind = .message },
        .{ .name = "cache_scope", .number = 4, .kind = .enumeration },
    };
};

pub const CallToolRequest = struct {
    common: ?RequestFields = null,
    request: ?Request = null,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "request", .number = 2, .kind = .message },
    };

    pub const Request = struct {
        name: []const u8 = "",
        arguments: ?Value = null,
        pub const proto = [_]F{
            .{ .name = "name", .number = 1, .kind = .string },
            .{ .name = "arguments", .number = 2, .kind = .json_struct },
        };
    };
};

pub const CallToolResponse = struct {
    common: ?ResponseFields = null,
    content: []const Content = &.{},
    structured_content: ?Value = null,
    is_error: bool = false,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "content", .number = 2, .kind = .message },
        .{ .name = "structured_content", .number = 3, .kind = .json_struct },
        .{ .name = "is_error", .number = 4, .kind = .bool },
    };

    pub const Content = struct {
        text: ?TextContent = null,
        image: ?ImageContent = null,
        audio: ?AudioContent = null,
        embedded_resource: ?EmbeddedResource = null,
        resource_link: ?Resource = null,
        pub const proto = [_]F{
            .{ .name = "text", .number = 1, .kind = .message },
            .{ .name = "image", .number = 2, .kind = .message },
            .{ .name = "audio", .number = 3, .kind = .message },
            .{ .name = "embedded_resource", .number = 4, .kind = .message },
            .{ .name = "resource_link", .number = 7, .kind = .message },
        };
    };
};

// -- Completion ----------------------------------------------------------------------------------

pub const ResourceReference = struct {
    uri: []const u8 = "",
    pub const proto = [_]F{.{ .name = "uri", .number = 1, .kind = .string }};
};

pub const PromptReference = struct {
    name: []const u8 = "",
    title: []const u8 = "",
    pub const proto = [_]F{
        .{ .name = "name", .number = 1, .kind = .string },
        .{ .name = "title", .number = 2, .kind = .string },
    };
};

pub const CompletionRequest = struct {
    common: ?RequestFields = null,
    resource_reference: ?ResourceReference = null,
    prompt_reference: ?PromptReference = null,
    argument: ?Argument = null,
    context: ?Context = null,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "resource_reference", .number = 2, .kind = .message },
        .{ .name = "prompt_reference", .number = 3, .kind = .message },
        .{ .name = "argument", .number = 4, .kind = .message },
        .{ .name = "context", .number = 5, .kind = .message },
    };

    pub const Argument = struct {
        name: []const u8 = "",
        value: []const u8 = "",
        pub const proto = [_]F{
            .{ .name = "name", .number = 1, .kind = .string },
            .{ .name = "value", .number = 2, .kind = .string },
        };
    };

    pub const Context = struct {
        arguments: []const StringEntry = &.{},
        pub const proto = [_]F{.{ .name = "arguments", .number = 1, .kind = .message }};
    };
};

pub const CompletionResponse = struct {
    common: ?ResponseFields = null,
    values: []const []const u8 = &.{},
    total_matches: ?i64 = null,
    has_more: bool = false,
    pub const proto = [_]F{
        .{ .name = "common", .number = 1, .kind = .message },
        .{ .name = "values", .number = 2, .kind = .string },
        .{ .name = "total_matches", .number = 3, .kind = .int64 },
        .{ .name = "has_more", .number = 4, .kind = .bool },
    };
};

// -- Tests ---------------------------------------------------------------------------------------

/// Every message type of this file.
const all_messages = [_]type{
    InputResponseEntry,
    InputRequestEntry,
    StringEntry,
    RequestFields,
    ResponseFields,
    InputRequest,
    InputResponse,
    ListRootsRequest,
    ListRootsResult,
    ListRootsResult.Root,
    SamplingMessage,
    SamplingCreateMessageRequest,
    SamplingCreateMessageRequest.ModelPreferences,
    SamplingCreateMessageRequest.ModelHint,
    SamplingCreateMessageResult,
    PrimitiveSchemaDefinition,
    PrimitiveSchemaDefinition.StringSchema,
    PrimitiveSchemaDefinition.NumberSchema,
    PrimitiveSchemaDefinition.NumberSchema.DoubleRange,
    PrimitiveSchemaDefinition.NumberSchema.IntegerRange,
    PrimitiveSchemaDefinition.BooleanSchema,
    PrimitiveSchemaDefinition.EnumSchema,
    PrimitiveSchemaDefinition.EnumSchema.MultiSelect,
    PrimitiveSchemaDefinition.EnumSchema.SingleSelect,
    SchemaEntry,
    ElicitRequest,
    ElicitRequest.UrlMode,
    ElicitResult,
    Annotations,
    Icon,
    TextContent,
    ImageContent,
    ResourceContents,
    EmbeddedResource,
    Resource,
    ListResourcesRequest,
    ListResourcesResponse,
    ReadResourceRequest,
    ReadResourceResponse,
    ResourceTemplate,
    ListResourceTemplatesResponse,
    Prompt,
    Prompt.Argument,
    ListPromptsResponse,
    PromptMessage,
    GetPromptRequest,
    GetPromptResponse,
    ToolAnnotations,
    Tool,
    ListToolsResponse,
    CallToolRequest,
    CallToolRequest.Request,
    CallToolResponse,
    CallToolResponse.Content,
    ResourceReference,
    PromptReference,
    CompletionRequest,
    CompletionRequest.Argument,
    CompletionRequest.Context,
    CompletionResponse,
    Duration,
};

/// A value of `T` with every field set to a value other than the default. Repeated fields
/// get two values.
fn sample(comptime T: type, arena: Allocator) Allocator.Error!T {
    var v: T = .{};
    inline for (T.proto) |spec| {
        const FT = @FieldType(T, spec.name);
        const B = codec.BaseOf(FT, spec.kind);
        @field(v, spec.name) = switch (comptime codec.shapeOf(FT, spec.kind)) {
            .singular, .optional => try sampleValue(B, spec, arena, 0),
            .repeated => blk: {
                const items = try arena.alloc(B, 2);
                items[0] = try sampleValue(B, spec, arena, 0);
                items[1] = try sampleValue(B, spec, arena, 1);
                break :blk items;
            },
        };
    }
    return v;
}

fn sampleValue(comptime B: type, comptime spec: F, arena: Allocator, i: u8) Allocator.Error!B {
    return switch (spec.kind) {
        .string => try std.fmt.allocPrint(arena, "s{d}-{d}-\u{e9}", .{ spec.number, i }),
        .bytes => try std.fmt.allocPrint(arena, "\x00\xff{d}", .{i}),
        .bool => true,
        .int32 => -@as(i32, spec.number) - i,
        .int64 => -(@as(i64, 1) << 40) - spec.number - i,
        .uint32 => 1000 + spec.number + i,
        .uint64 => (@as(u64, 1) << 63) + spec.number + i,
        .enumeration => @enumFromInt(1 + @as(i32, i)),
        .float => 0.25 + @as(f32, @floatFromInt(i)),
        .double => -1.5e10 - @as(f64, @floatFromInt(i)),
        .message => try sample(B, arena),
        .json_struct => std.json.parseFromSliceLeaky(Value, arena, "{\"k\":[1,\"x\",{\"n\":null}],\"b\":true,\"f\":0.5}", .{}) catch return error.OutOfMemory,
    };
}

fn expectSame(comptime T: type, a: T, b: T) !void {
    inline for (T.proto) |spec| {
        const FT = @FieldType(T, spec.name);
        const B = codec.BaseOf(FT, spec.kind);
        const x = @field(a, spec.name);
        const y = @field(b, spec.name);
        switch (comptime codec.shapeOf(FT, spec.kind)) {
            .singular => try expectSameValue(B, spec.kind, x, y),
            .optional => {
                try std.testing.expectEqual(x == null, y == null);
                if (x) |xv| try expectSameValue(B, spec.kind, xv, y.?);
            },
            .repeated => {
                try std.testing.expectEqual(x.len, y.len);
                for (x, y) |xv, yv| try expectSameValue(B, spec.kind, xv, yv);
            },
        }
    }
}

fn expectSameValue(comptime B: type, comptime kind: codec.Kind, x: B, y: B) !void {
    switch (kind) {
        .string, .bytes => try std.testing.expectEqualSlices(u8, x, y),
        .message => try expectSame(B, x, y),
        .json_struct => {
            const gpa = std.testing.allocator;
            const xs = try std.json.Stringify.valueAlloc(gpa, x, .{});
            defer gpa.free(xs);
            const ys = try std.json.Stringify.valueAlloc(gpa, y, .{});
            defer gpa.free(ys);
            try std.testing.expectEqualStrings(xs, ys);
        },
        else => try std.testing.expectEqual(x, y),
    }
}

test "every message survives a round trip with every field set" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // An unknown field of each wire type: varint 1000, fixed64 1001, bytes 1002, fixed32 1003.
    const unknown = [_]u8{ 0xc0, 0x3e, 0x07, 0xc9, 0x3e, 1, 2, 3, 4, 5, 6, 7, 8, 0xd2, 0x3e, 0x02, 'z', 'z', 0xdd, 0x3e, 1, 2, 3, 4 };
    inline for (all_messages) |T| {
        const value = try sample(T, arena);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try codec.encode(T, gpa, &out, value, .{});
        const back = try codec.decode(T, arena, out.items, .{});
        try expectSame(T, value, back);

        // The encoder is deterministic.
        var again: std.ArrayList(u8) = .empty;
        defer again.deinit(gpa);
        try codec.encode(T, gpa, &again, back, .{});
        try std.testing.expectEqualSlices(u8, out.items, again.items);

        // The decoder skips unknown fields.
        try again.appendSlice(gpa, &unknown);
        try expectSame(T, value, try codec.decode(T, arena, again.items, .{}));

        // Each prefix of the bytes decodes or fails with an error.
        for (0..out.items.len) |n| _ = codec.decode(T, arena, out.items[0..n], .{}) catch {};
    }
}

test "the field numbers of a tool call" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const arguments = try std.json.parseFromSliceLeaky(Value, arena, "{\"a\":1}", .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try codec.encode(CallToolRequest, gpa, &out, .{
        .common = .{ .metadata = .{ .object = .empty } },
        .request = .{ .name = "add", .arguments = arguments },
    }, .{});
    // common = 1 { metadata = 1 {} }, request = 2 { name = 1 "add", arguments = 2 { fields = 1
    // { key = 1 "a", value = 2 { number_value = 2 1.0 } } } }.
    const expected = [_]u8{
        0x0a, 0x02, 0x0a, 0x00, 0x12, 0x17, 0x0a, 0x03, 'a', 'd', 'd', 0x12, 0x10, 0x0a, 0x0e, 0x0a,
        0x01, 'a',  0x12, 0x09, 0x11, 0,    0,    0,    0,   0,   0,   0xf0, 0x3f,
    };
    try std.testing.expectEqualSlices(u8, &expected, out.items);
}
