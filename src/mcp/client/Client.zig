//! The MCP client. It builds requests with the mandatory `_meta` and sends them through a
//! client transport. It parses the typed result and drives multi round-trip requests with
//! the application hooks.
//!
//! Every method takes an arena that owns the returned result.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("../protocol/types.zig");
const version = @import("../protocol/version.zig");
const errors = @import("../protocol/errors.zig");
const meta_mod = @import("../protocol/meta.zig");
const methods = @import("../protocol/methods.zig");
const json = @import("../json.zig");
const message = @import("../jsonrpc/message.zig");
const RequestId = @import("../jsonrpc/id.zig").RequestId;
const Transport = @import("../transport/Transport.zig");
const Limits = @import("../Limits.zig");
const tasks = @import("../server/tasks.zig");
const skills = @import("../protocol/skills.zig");
const apps = @import("../protocol/apps.zig");
const cache_mod = @import("cache.zig");
const validator = @import("../schema/validator.zig");
/// The client rules for icons: scheme, origin, size and format checks, selection and fetch.
pub const icons = @import("icons.zig");

const Client = @This();

gpa: Allocator,
io: Io,
options: Options,
transport: ?Transport.ClientTransport = null,
next_id: std.atomic.Value(i64) = .init(1),
cache: cache_mod.Cache,

pub const Options = struct {
    info: types.Implementation,
    capabilities: types.ClientCapabilities = .{},
    hooks: Hooks = .{},
    limits: Limits = .{},
    /// Ask the server for log messages at this level and above (deprecated feature).
    log_level: ?types.LoggingLevel = null,
    /// The result cache for results that carry a positive `ttlMs`. Off by default.
    cache: cache_mod.Options = .{},
    /// The scheme, origin and format rules for icons. The defaults obey the specification.
    icons: icons.Policy = .{},
};

/// The context every hook receives.
pub const HookContext = struct {
    io: Io,
    /// Owns everything the hook returns.
    arena: Allocator,
    userdata: ?*anyopaque,
    /// The server-chosen key of the input request.
    key: []const u8,
    /// The method the input request belongs to.
    method: []const u8,
};

pub const Hooks = struct {
    userdata: ?*anyopaque = null,
    /// Answer a form elicitation. Required when `capabilities.elicitation` allows form mode.
    /// The client validates the accepted content against `requestedSchema` before it sends
    /// the answer. Content that is not valid gives `error.HookFailed`.
    elicit_form: ?*const fn (ctx: *HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult = null,
    /// Answer a URL elicitation. The hook shows the URL to the user and never opens it alone.
    /// The client does not call the hook when the URL is not a valid absolute URL.
    elicit_url: ?*const fn (ctx: *HookContext, params: types.ElicitRequestURLParams) anyerror!types.ElicitResult = null,
    /// Answer a sampling request. Required when `capabilities.sampling` declares sampling.
    /// The client does not call the hook when the messages break the tool result rules.
    sample: ?*const fn (ctx: *HookContext, params: types.CreateMessageRequestParams) anyerror!types.CreateMessageResult = null,
    /// List the roots. Required when `capabilities.roots` declares roots.
    list_roots: ?*const fn (ctx: *HookContext) anyerror![]const types.Root = null,
    /// A server notification that belongs to no request (stdio only).
    on_notification: ?*const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void = null,
    /// Decode, sanitize or convert a checked icon image. The formats that need a decoder
    /// (GIF, WebP and SVG) pass only when this hook is set and the icon policy turns them on.
    /// The hook returns an error to reject the image.
    icon_decoder: ?*const fn (userdata: ?*anyopaque, arena: Allocator, image: icons.Image) anyerror!icons.Image = null,
};

pub const Diagnostics = struct {
    /// The JSON-RPC error of the last failed request, in the request arena.
    rpc_error: ?types.Error = null,
    /// True when the result had no `resultType` (a specification violation the SDK tolerates).
    result_type_absent: bool = false,
    /// True when `structuredContent` did not match `outputSchema`.
    structured_content_invalid: bool = false,
};

pub const RequestOptions = struct {
    /// Relative timeout for the whole request, with all multi round-trip rounds.
    timeout: ?Io.Duration = null,
    cancel: ?*Transport.CancelToken = null,
    on_progress: ?*const fn (userdata: ?*anyopaque, params: types.ProgressNotificationParams) void = null,
    on_log: ?*const fn (userdata: ?*anyopaque, params: types.LoggingMessageNotificationParams) void = null,
    /// Any notification on the request stream that is not progress or log.
    on_notification: ?*const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void = null,
    /// Return an `InputRequiredResult` to the caller. The client does not call the hooks.
    allow_input_required: bool = false,
    /// Return the `CreateTaskResult` of a `tools/call` in `Response.task`. The client does not
    /// wait for the task. Only meaningful when `capabilities.extensions` declares the extension.
    allow_task: bool = false,
    /// What to do when the client loses the stream before any response byte arrived.
    retry: Retry = .auto,
    /// How this request uses the result cache.
    cache_mode: cache_mod.Mode = .default,
    diagnostics: ?*Diagnostics = null,
    userdata: ?*anyopaque = null,
};

pub const Retry = enum {
    /// Re-issue idempotent methods with a new id, up to `limits.max_lost_stream_retries`.
    auto,
    /// Never re-issue.
    never,
    /// Re-issue every method, also `tools/call` and a `subscriptions/listen` stream that
    /// already delivered events. Use it to keep a listen stream open across a server restart.
    force,
};

pub const RequestError = error{
    /// The server answered with a JSON-RPC error. See `Diagnostics.rpc_error`.
    Rpc,
    Timeout,
    Canceled,
    Closed,
    TransportFailed,
    OutOfMemory,
    /// The response is not a valid result for the method.
    InvalidResponse,
    /// The server asked for an input kind the client did not declare.
    UndeclaredInputRequest,
    /// A hook failed or is missing.
    HookFailed,
    TooManyRounds,
    NotConnected,
    /// The task ended with the status `cancelled`.
    TaskCancelled,
};

pub fn init(gpa: Allocator, io: Io, options: Options) Client {
    return .{ .gpa = gpa, .io = io, .options = options, .cache = .init(gpa, io, options.cache) };
}

pub fn deinit(self: *Client) void {
    self.cache.deinit();
    self.* = undefined;
}

/// Drop every cached result.
pub fn invalidateCache(self: *Client) void {
    self.cache.invalidate(null);
}

/// Use `transport` for the next requests. The call drops every cached result, because the
/// new transport can reach another server or send another credential.
pub fn connect(self: *Client, transport: Transport.ClientTransport) void {
    self.cache.invalidate(null);
    self.transport = transport;
}

// -- Icons --------------------------------------------------------------------------------------

pub const IconOptions = struct {
    /// The URL of the MCP endpoint. `https` icons must have its origin or a trusted origin.
    /// Null for a server without a URL, for example on stdio.
    server_url: ?[]const u8 = null,
    /// The trust policy for `https` icons. Null uses the system trust store.
    tls: ?icons.TlsSetup = null,
};

/// Get the image of an icon with the icon policy, `limits.icon`, `limits.http.max_redirect_hops`
/// and the `icon_decoder` hook. The request carries no credentials of the MCP connection.
/// The image bytes are in `arena`.
pub fn fetchIcon(self: *Client, arena: Allocator, icon: types.Icon, options: IconOptions) icons.Error!icons.Image {
    return icons.fetch(self.io, self.gpa, arena, icon, .{
        .server_url = options.server_url,
        .policy = self.options.icons,
        .limits = self.options.limits.icon,
        .max_redirect_hops = self.options.limits.http.max_redirect_hops,
        .tls = options.tls,
        .decoder = if (self.options.hooks.icon_decoder) |f| .{ .userdata = self.options.hooks.userdata, .decode = f } else null,
    });
}

/// Select the icon of `list` that fits `want` best under the icon policy. Formats that need a
/// decoder are not candidates when the `icon_decoder` hook is not set.
pub fn selectIcon(self: *const Client, list: ?[]const types.Icon, want: icons.Want, server_url: ?[]const u8) ?types.Icon {
    return icons.select(list, want, server_url, self.options.icons.effective(self.options.hooks.icon_decoder != null));
}

/// A result together with the raw `Value` that the client parsed.
pub fn Response(comptime T: type) type {
    return struct {
        result: T,
        raw: Value,
        /// Set when the server returned `InputRequiredResult` and `allow_input_required` was on.
        input_required: ?types.InputRequiredResult = null,
        /// Set when the server returned `CreateTaskResult` and `allow_task` was on.
        task: ?tasks.CreateTaskResult = null,
    };
}

// -- Typed API ----------------------------------------------------------------------------------

pub fn discover(self: *Client, arena: Allocator, options: RequestOptions) RequestError!types.DiscoverResult {
    return (try self.request(arena, .@"server/discover", .{ .object = .empty }, options)).result;
}

pub fn listTools(self: *Client, arena: Allocator, cursor: ?[]const u8, options: RequestOptions) RequestError!types.ListToolsResult {
    return (try self.request(arena, .@"tools/list", try cursorParams(arena, cursor), options)).result;
}

pub fn listResources(self: *Client, arena: Allocator, cursor: ?[]const u8, options: RequestOptions) RequestError!types.ListResourcesResult {
    return (try self.request(arena, .@"resources/list", try cursorParams(arena, cursor), options)).result;
}

pub fn listResourceTemplates(self: *Client, arena: Allocator, cursor: ?[]const u8, options: RequestOptions) RequestError!types.ListResourceTemplatesResult {
    return (try self.request(arena, .@"resources/templates/list", try cursorParams(arena, cursor), options)).result;
}

pub fn listPrompts(self: *Client, arena: Allocator, cursor: ?[]const u8, options: RequestOptions) RequestError!types.ListPromptsResult {
    return (try self.request(arena, .@"prompts/list", try cursorParams(arena, cursor), options)).result;
}

/// Call a tool. `arguments` is any value that serializes to a JSON object, or null.
/// Call a tool. The server can turn the call into a task of the Tasks extension. The client
/// then waits for the task, answers its input requests with the hooks and returns its result.
pub fn callTool(self: *Client, arena: Allocator, name: []const u8, arguments: anytype, options: RequestOptions) RequestError!types.CallToolResult {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "name", .{ .string = name });
    if (@TypeOf(arguments) != @TypeOf(null)) try params.put(arena, "arguments", try toValue(arena, arguments));
    var wait_options = options;
    wait_options.allow_task = false;
    const response = try self.request(arena, .@"tools/call", .{ .object = params }, wait_options);
    return response.result;
}

/// Call a tool and return the `CreateTaskResult` when the server created a task.
pub fn callToolOrTask(self: *Client, arena: Allocator, name: []const u8, arguments: anytype, options: RequestOptions) RequestError!ToolOutcome {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "name", .{ .string = name });
    if (@TypeOf(arguments) != @TypeOf(null)) try params.put(arena, "arguments", try toValue(arena, arguments));
    var task_options = options;
    task_options.allow_task = true;
    const response = try self.request(arena, .@"tools/call", .{ .object = params }, task_options);
    if (response.task) |t| return .{ .task = t };
    return .{ .complete = response.result };
}

pub const ToolOutcome = union(enum) {
    complete: types.CallToolResult,
    task: tasks.CreateTaskResult,
};

// -- Tasks extension ----------------------------------------------------------------------------

pub const AwaitOptions = struct {
    /// The poll interval. Null uses `pollIntervalMs` from the task, or one second.
    poll_interval: ?Io.Duration = null,
    /// The whole wait. Null waits without limit.
    timeout: ?Io.Duration = null,
    cancel: ?*Transport.CancelToken = null,
    /// Options for every `tasks/get` and `tasks/update` request.
    request: RequestOptions = .{},
};

/// Read a task.
pub fn getTask(self: *Client, arena: Allocator, task_id: []const u8, options: RequestOptions) RequestError!tasks.DetailedTask {
    return (try self.requestAs(arena, tasks.DetailedTask, "tasks/get", try taskParams(arena, task_id), options)).result;
}

/// Deliver answers to the input requests of a task. `input_responses` is an object keyed by
/// the request keys of the task.
pub fn updateTask(self: *Client, arena: Allocator, task_id: []const u8, input_responses: Value, options: RequestOptions) RequestError!void {
    var params = try taskParams(arena, task_id);
    try params.object.put(arena, "inputResponses", input_responses);
    _ = try self.requestAs(arena, types.EmptyResult, "tasks/update", params, options);
}

/// Ask the server to cancel a task. The server also accepts the call on a finished task.
pub fn cancelTask(self: *Client, arena: Allocator, task_id: []const u8, options: RequestOptions) RequestError!void {
    _ = try self.requestAs(arena, types.EmptyResult, "tasks/cancel", try taskParams(arena, task_id), options);
}

/// Poll a task until it ends. The hooks answer input requests. The task that the function
/// returns has the status `completed`. A failed task sets `Diagnostics.rpc_error` from the
/// task and returns `error.Rpc`. A canceled task returns `error.TaskCancelled`.
pub fn awaitTask(self: *Client, arena: Allocator, task_id: []const u8, options: AwaitOptions) RequestError!tasks.DetailedTask {
    const deadline: ?Io.Clock.Timestamp = if (options.timeout) |d| Io.Clock.Timestamp.now(self.io, .awake).addDuration(.{ .raw = d, .clock = .awake }) else null;
    var default_interval: Io.Duration = .fromMilliseconds(1000);
    while (true) {
        if (options.cancel) |c| if (c.isCancelled()) return error.Canceled;
        const task = try self.getTask(arena, task_id, options.request);
        if (task.pollIntervalMs) |ms| if (ms > 0) {
            default_interval = .fromMilliseconds(ms);
        };
        const status = std.meta.stringToEnum(tasks.Status, task.status) orelse return error.InvalidResponse;
        switch (status) {
            .completed => return task,
            .failed => {
                if (options.request.diagnostics) |d| d.rpc_error = task.@"error";
                return error.Rpc;
            },
            .cancelled => return error.TaskCancelled,
            .input_required => {
                const requests = task.inputRequests orelse return error.InvalidResponse;
                if (requests != .object) return error.InvalidResponse;
                var answers: std.json.ObjectMap = .empty;
                var it = requests.object.iterator();
                while (it.next()) |kv| {
                    const req = json.parseValue(types.InputRequest, arena, kv.value_ptr.*) catch return error.InvalidResponse;
                    try answers.put(arena, kv.key_ptr.*, try self.answerInput(arena, kv.key_ptr.*, "tools/call", req));
                }
                try self.updateTask(arena, task_id, .{ .object = answers }, options.request);
                continue;
            },
            .working => {},
        }
        const interval = options.poll_interval orelse default_interval;
        if (deadline) |dl| {
            const now = Io.Clock.Timestamp.now(self.io, .awake);
            if (now.durationTo(dl).raw.nanoseconds <= 0) return error.Timeout;
        }
        self.io.sleep(interval, .awake) catch return error.Canceled;
    }
}

/// The tool result of a completed task.
pub fn taskResult(arena: Allocator, task: tasks.DetailedTask) RequestError!types.CallToolResult {
    const raw = task.result orelse return error.InvalidResponse;
    return json.parseValue(types.CallToolResult, arena, raw) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidResponse,
    };
}

fn taskParams(arena: Allocator, task_id: []const u8) Allocator.Error!Value {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "taskId", .{ .string = task_id });
    return .{ .object = params };
}

// -- Skills extension ---------------------------------------------------------------------------

/// List the skills of the server. A server that declares the extension provides it. An
/// empty or partial list does not prove that the server has no other skills.
pub fn listSkills(self: *Client, arena: Allocator, cursor: ?[]const u8, options: RequestOptions) RequestError!skills.ListSkillsResult {
    return (try self.requestAs(arena, skills.ListSkillsResult, skills.method_list, try cursorParams(arena, cursor), options)).result;
}

/// Get the entry of one skill by the URI of its `SKILL.md`. An unknown URI gives
/// `error.Rpc` with code `-32602`.
pub fn getSkill(self: *Client, arena: Allocator, uri: []const u8, options: RequestOptions) RequestError!skills.GetSkillResult {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "uri", .{ .string = uri });
    return (try self.requestAs(arena, skills.GetSkillResult, skills.method_get, .{ .object = params }, options)).result;
}

/// List the direct children of a directory resource. Send it only to a server that declares
/// `directoryRead: true` (see `skills.serverSupportsDirectoryRead`). The result is a live
/// observation. It does not extend the file list of a held entry.
pub fn readDirectory(self: *Client, arena: Allocator, uri: []const u8, cursor: ?[]const u8, options: RequestOptions) RequestError!skills.ReadDirectoryResult {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "uri", .{ .string = uri });
    if (cursor) |c| try params.put(arena, "cursor", .{ .string = c });
    return (try self.requestAs(arena, skills.ReadDirectoryResult, skills.method_directory_read, .{ .object = params }, options)).result;
}

pub const SkillReadError = RequestError || skills.VerifyError || skills.EntryError;

/// Read one file of a skill under the held entry and verify it. The function refuses a URI
/// that the file list of the entry does not name, before it sends a request. It then checks
/// the size and the SHA-256 digest. For `SKILL.md` it also compares the frontmatter field by
/// field. A failure means that the content must not be used. Refresh the entry with
/// `getSkill` and ask the user again for approval.
pub fn readSkillFile(self: *Client, arena: Allocator, entry: skills.Skill, uri: []const u8, options: RequestOptions) SkillReadError![]const u8 {
    const limits = self.options.limits.skills;
    try skills.validateEntry(entry, @max(limits.max_files, skills.max_files_per_skill), @max(limits.max_bytes, skills.max_bytes_per_skill));
    try skills.checkReadable(entry, uri);
    const result = try self.readResource(arena, uri, options);
    for (result.contents) |c| {
        if (!std.mem.eql(u8, c.uri(), uri)) continue;
        const bytes = skills.contentBytes(arena, c) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidBlob => return error.InvalidResponse,
        };
        try skills.verifyFile(arena, entry, uri, bytes);
        return bytes;
    }
    return error.InvalidResponse;
}

// -- MCP Apps extension -------------------------------------------------------------------------

/// The UI metadata of a tool. Null when the tool has none, or when this client did not
/// declare the extension. Such a client uses the tool as a plain tool.
pub fn toolUi(self: *const Client, arena: Allocator, tool: types.Tool) apps.MetaError!?apps.ToolMeta {
    if (!apps.clientSupports(self.options.capabilities)) return null;
    return apps.toolMeta(arena, tool);
}

pub const UiReadError = RequestError || apps.ReadError;

/// Read a view with `resources/read`. `listing_meta` is the `_meta` of the resource from
/// `resources/list`, or null. The UI metadata of the content item has priority over it.
pub fn readUiResource(self: *Client, arena: Allocator, uri: []const u8, listing_meta: ?Value, options: RequestOptions) UiReadError!apps.UiResource {
    if (!apps.isUiUri(uri)) return error.NotUiUri;
    const result = try self.readResource(arena, uri, options);
    return apps.uiResourceFromRead(arena, uri, result, listing_meta);
}

pub fn readResource(self: *Client, arena: Allocator, uri: []const u8, options: RequestOptions) RequestError!types.ReadResourceResult {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "uri", .{ .string = uri });
    return (try self.request(arena, .@"resources/read", .{ .object = params }, options)).result;
}

pub fn getPrompt(self: *Client, arena: Allocator, name: []const u8, arguments: anytype, options: RequestOptions) RequestError!types.GetPromptResult {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "name", .{ .string = name });
    if (@TypeOf(arguments) != @TypeOf(null)) try params.put(arena, "arguments", try toValue(arena, arguments));
    return (try self.request(arena, .@"prompts/get", .{ .object = params }, options)).result;
}

pub fn complete(self: *Client, arena: Allocator, params: types.CompleteRequestParams, options: RequestOptions) RequestError!types.CompleteResult {
    return (try self.request(arena, .@"completion/complete", try toValue(arena, params), options)).result;
}

/// Open a `subscriptions/listen` stream. `on_event` receives every event notification. The
/// call returns when the server closes the stream gracefully, or with `error.Canceled` when
/// the cancel token fires.
pub fn listen(self: *Client, arena: Allocator, filter: types.SubscriptionsListenRequestParams, options: RequestOptions) RequestError!types.SubscriptionsListenResult {
    return (try self.request(arena, .@"subscriptions/listen", try toValue(arena, filter), options)).result;
}

/// Send any request by method name and parse the result as `T`.
pub fn requestAs(self: *Client, arena: Allocator, comptime T: type, method_name: []const u8, params: Value, options: RequestOptions) RequestError!Response(T) {
    const raw = try self.requestRaw(arena, method_name, params, options, methods.Method.fromName(method_name));
    return finishResponse(T, arena, raw, options);
}

/// Send a request from the method table and parse its result type.
pub fn request(self: *Client, arena: Allocator, comptime method: methods.Method, params: Value, options: RequestOptions) RequestError!Response(method.Result()) {
    const raw = try self.requestRaw(arena, method.name(), params, options, method);
    return finishResponse(method.Result(), arena, raw, options);
}

fn finishResponse(comptime T: type, arena: Allocator, raw: Raw, options: RequestOptions) RequestError!Response(T) {
    if (raw.input_required) |ir| {
        std.debug.assert(options.allow_input_required);
        return .{ .result = undefined, .raw = raw.value, .input_required = ir };
    }
    if (raw.task) |t| {
        std.debug.assert(options.allow_task);
        return .{ .result = undefined, .raw = raw.value, .task = t };
    }
    const result = json.parseValue(T, arena, raw.value) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidResponse,
    };
    return .{ .result = result, .raw = raw.value };
}

const Raw = struct {
    value: Value,
    input_required: ?types.InputRequiredResult = null,
    task: ?tasks.CreateTaskResult = null,
};

// -- Pipeline -----------------------------------------------------------------------------------

/// Collects the frames of one exchange.
const Collector = struct {
    client: *Client,
    arena: Allocator,
    id: RequestId,
    options: RequestOptions,
    response: ?Value = null,
    rpc_error: ?types.Error = null,
    invalid: bool = false,
    /// Frames delivered so far. The client retries a lost stream only when nothing arrived.
    frames: u32 = 0,

    fn onFrame(ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void {
        _ = io;
        const self: *Collector = @ptrCast(@alignCast(ptr));
        self.frames += 1;
        const msg = message.Message.parse(self.arena, frame) catch {
            self.invalid = true;
            return error.InvalidFrame;
        };
        switch (msg) {
            .response => |r| {
                if (!r.id.eql(self.id)) return; // a late response for another request
                self.response = r.result;
            },
            .error_response => |e| {
                if (e.id) |id| if (!id.eql(self.id)) return;
                self.rpc_error = .{ .code = e.code, .message = e.message, .data = e.data };
            },
            .notification => |n| self.client.dispatchNotification(n.method, n.params, self.options),
            .request => {
                // Servers do not send requests in this revision.
                self.invalid = true;
                return error.InvalidFrame;
            },
        }
    }
};

fn dispatchNotification(self: *Client, method_name: []const u8, params: ?Value, options: RequestOptions) void {
    // A change notification invalidates the cached lists and reads.
    if (cache_mod.Cache.methodForNotification(method_name)) |m| self.cache.invalidate(m);
    // Parsed notification params live only for the callback.
    var scratch: std.heap.ArenaAllocator = .init(self.gpa);
    defer scratch.deinit();
    if (std.mem.eql(u8, method_name, "notifications/progress")) {
        if (options.on_progress) |f| {
            const p = json.parseValue(types.ProgressNotificationParams, scratch.allocator(), params orelse .null) catch return;
            f(options.userdata, p);
        }
        return;
    }
    if (std.mem.eql(u8, method_name, "notifications/message")) {
        if (options.on_log) |f| {
            const p = json.parseValue(types.LoggingMessageNotificationParams, scratch.allocator(), params orelse .null) catch return;
            f(options.userdata, p);
        }
        return;
    }
    if (options.on_notification) |f| {
        f(options.userdata, method_name, params);
    } else if (self.options.hooks.on_notification) |f| {
        f(self.options.hooks.userdata, method_name, params);
    }
}

fn requestRaw(self: *Client, arena: Allocator, method_name: []const u8, params: Value, options: RequestOptions, known: ?methods.Method) RequestError!Raw {
    const transport = self.transport orelse return error.NotConnected;
    if (params != .object) return error.InvalidResponse;
    var own_token: Transport.CancelToken = .{};
    const cancel = options.cancel orelse &own_token;
    const deadline: Io.Timeout = if (options.timeout) |d| .{ .deadline = Io.Clock.Timestamp.now(self.io, .awake).addDuration(.{ .raw = d, .clock = .awake }) } else .none;

    // The cache serves idempotent reads that a server marked with a lifetime. A retry of a
    // multi round-trip request depends on inputs outside the key, so it is not cacheable.
    const cacheable = self.options.cache.enabled and options.cache_mode != .bypass and known != null and known.?.isCacheable() and
        params.object.get("inputResponses") == null and params.object.get("requestState") == null;
    const cache_key: ?[]u8 = if (cacheable) try cache_mod.Cache.key(arena, method_name, params) else null;
    const auth_context: cache_mod.Context = if (cacheable) cache_mod.contextOf(try transport.credential(arena)) else null;
    if (cacheable) self.cache.enterContext(auth_context);
    if (cache_key) |k| if (options.cache_mode == .default) if (self.cache.get(k, auth_context)) |text| {
        const value = json.parseTree(arena, text) catch return error.InvalidResponse;
        return .{ .value = value };
    };

    var round: u32 = 0;
    var version_retried = false;
    var lost_retries: u32 = 0;
    var input_responses: ?std.json.ObjectMap = null;
    var request_state: ?[]const u8 = null;
    while (round < self.options.limits.mrtr_max_rounds_client) : (round += 1) {
        const id: RequestId = .{ .integer = self.next_id.fetchAdd(1, .monotonic) };
        var object = try cloneObject(arena, params.object);
        try object.put(arena, "_meta", try self.buildMeta(arena, id));
        if (input_responses) |ir| try object.put(arena, "inputResponses", .{ .object = ir });
        if (request_state) |rs| try object.put(arena, "requestState", .{ .string = rs });
        const full: Value = .{ .object = object };

        var aw: Io.Writer.Allocating = .init(arena);
        message.writeRequest(&aw.writer, id, method_name, full) catch return error.OutOfMemory;
        const frame = aw.written();

        var collector: Collector = .{ .client = self, .arena = arena, .id = id, .options = options };
        var ex: Transport.Exchange = .{
            .frame = frame,
            .id = id,
            .method = method_name,
            .params = full,
            .sink = .{ .ptr = &collector, .on_frame = Collector.onFrame },
            .cancel = cancel,
            .timeout = deadline,
        };
        transport.exchange(self.io, &ex) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
            error.InvalidFrame, error.HttpStatus => return error.InvalidResponse,
            error.Closed, error.WriteFailed, error.ReadFailed => {
                if (self.canRetryLost(options, known, collector.frames, lost_retries)) {
                    lost_retries += 1;
                    round -|= 1;
                    continue;
                }
                return if (e == error.Closed) error.Closed else error.TransportFailed;
            },
        };
        if (collector.rpc_error) |rpc| {
            // One retry when the server rejects the version but supports ours (-32022).
            if (rpc.code == errors.Code.unsupported_protocol_version.int() and !version_retried and supportsOurVersion(rpc.data)) {
                version_retried = true;
                round -|= 1;
                continue;
            }
            // An invalid cursor: the cached pages of the list are no longer reliable.
            if (rpc.code == errors.Code.invalid_params.int() and known != null and known.?.isCacheable() and params.object.get("cursor") != null) {
                self.cache.invalidate(method_name);
            }
            if (options.diagnostics) |d| d.rpc_error = rpc;
            return error.Rpc;
        }
        const result = collector.response orelse return error.InvalidResponse;
        if (result != .object) return error.InvalidResponse;

        // Result type.
        const result_type = json.getString(result, "resultType");
        if (result_type == null) {
            if (options.diagnostics) |d| d.result_type_absent = true;
            return .{ .value = result };
        }
        if (std.mem.eql(u8, result_type.?, types.result_type_complete)) {
            if (cache_key) |k| if (input_responses == null) if (result.object.get("ttlMs")) |ttl| if (ttl == .integer) {
                const text = try json.writeAlloc(arena, result);
                // A result without cacheScope counts as private.
                const scope_text = json.getString(result, "cacheScope") orelse "private";
                const scope: types.CacheScope = if (std.mem.eql(u8, scope_text, "public")) .public else .private;
                // A credential change during the request, for example after a challenge, leaves
                // the context of a private result unclear. The client does not store it then.
                const unchanged = cache_mod.sameContext(auth_context, cache_mod.contextOf(try transport.credential(arena)));
                if (scope == .public or unchanged) try self.cache.put(k, method_name, text, ttl.integer, scope, auth_context);
            };
            return .{ .value = result };
        }
        if (std.mem.eql(u8, result_type.?, "task")) {
            // Only a `tools/call` can become a task, and only when the client declared the extension.
            if (known != .@"tools/call" or !self.options.capabilities.hasExtension(tasks.extension_id)) return error.InvalidResponse;
            const created = json.parseValue(tasks.CreateTaskResult, arena, result) catch return error.InvalidResponse;
            if (options.allow_task) return .{ .value = result, .task = created };
            const done = try self.awaitTask(arena, created.taskId, .{
                .timeout = options.timeout,
                .cancel = options.cancel,
                .request = options,
            });
            return .{ .value = done.result orelse return error.InvalidResponse };
        }
        if (!std.mem.eql(u8, result_type.?, types.result_type_input_required)) return error.InvalidResponse;
        if (known) |m| if (!m.allowsInputRequired()) return error.InvalidResponse;
        const ir = json.parseValue(types.InputRequiredResult, arena, result) catch return error.InvalidResponse;
        if (options.allow_input_required) return .{ .value = result, .input_required = ir };

        // Drive the hooks and retry with the answers.
        var answers: std.json.ObjectMap = .empty;
        if (ir.inputRequests) |reqs| {
            var it = reqs.map.iterator();
            while (it.next()) |kv| {
                const answer = try self.answerInput(arena, kv.key_ptr.*, method_name, kv.value_ptr.*);
                try answers.put(arena, kv.key_ptr.*, answer);
            }
        }
        input_responses = answers;
        request_state = ir.requestState;
    }
    return error.TooManyRounds;
}

/// True when the client can send a request again with a new id after it lost the stream.
fn canRetryLost(self: *Client, options: RequestOptions, known: ?methods.Method, frames: u32, done: u32) bool {
    if (done >= self.options.limits.max_lost_stream_retries) return false;
    if (options.cancel) |c| if (c.isCancelled()) return false;
    return switch (options.retry) {
        .never => false,
        .force => true,
        .auto => frames == 0 and known != null and known.?.isIdempotent(),
    };
}

/// True when `data.supported` of a -32022 error lists the revision this SDK speaks.
fn supportsOurVersion(data: ?Value) bool {
    const d = data orelse return false;
    if (d != .object) return false;
    const supported = d.object.get("supported") orelse return false;
    if (supported != .array) return false;
    for (supported.array.items) |v| if (v == .string and std.mem.eql(u8, v.string, version.version)) return true;
    return false;
}

fn answerInput(self: *Client, arena: Allocator, key: []const u8, method_name: []const u8, req: types.InputRequest) RequestError!Value {
    const hooks = self.options.hooks;
    const caps = self.options.capabilities;
    var ctx: HookContext = .{ .io = self.io, .arena = arena, .userdata = hooks.userdata, .key = key, .method = method_name };
    switch (req) {
        .@"elicitation/create" => |e| switch (e.params) {
            .form => |form| {
                if (!caps.hasElicitation(.form)) return error.UndeclaredInputRequest;
                const f = hooks.elicit_form orelse return error.HookFailed;
                const result = f(&ctx, form) catch return error.HookFailed;
                if (result.action != .accept and result.content != null) return error.HookFailed;
                if (result.action == .accept and !try self.contentMatches(arena, form, result.content)) return error.HookFailed;
                return toValue(arena, result);
            },
            .url => |url| {
                if (!caps.hasElicitation(.url)) return error.UndeclaredInputRequest;
                if (!types.isValidUrl(url.url)) return error.InvalidResponse;
                const f = hooks.elicit_url orelse return error.HookFailed;
                const result = f(&ctx, url) catch return error.HookFailed;
                if (result.content != null) return error.HookFailed;
                return toValue(arena, result);
            },
        },
        .@"sampling/createMessage" => |s| {
            if (caps.sampling == null) return error.UndeclaredInputRequest;
            types.checkSamplingMessages(s.params.messages) catch return error.InvalidResponse;
            const f = hooks.sample orelse return error.HookFailed;
            const result = f(&ctx, s.params) catch return error.HookFailed;
            return toValue(arena, result);
        },
        .@"roots/list" => {
            if (caps.roots == null) return error.UndeclaredInputRequest;
            const f = hooks.list_roots orelse return error.HookFailed;
            const roots = f(&ctx) catch return error.HookFailed;
            for (roots) |r| if (!std.mem.startsWith(u8, r.uri, "file://")) return error.HookFailed;
            return toValue(arena, types.ListRootsResult{ .roots = roots });
        },
    }
}

/// True when the accepted content of a form elicitation is valid against `requestedSchema`.
/// Content that is absent counts as an empty object. A schema that does not compile gives
/// `error.InvalidResponse`.
fn contentMatches(self: *Client, arena: Allocator, form: types.ElicitRequestFormParams, content: ?Value) RequestError!bool {
    var requested = form.requestedSchema;
    // The requested schema is a flat object of primitives in the dialect of 2020-12.
    requested.@"$schema" = null;
    const root = try toValue(arena, requested);
    const schema = validator.compile(arena, root, .{ .allow_unsupported_keywords = true, .limits = self.options.limits.schema }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidResponse,
    };
    const report = validator.validate(arena, &schema, content orelse .{ .object = .empty }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    return report.valid;
}

fn buildMeta(self: *Client, arena: Allocator, id: RequestId) Allocator.Error!Value {
    var m: std.json.ObjectMap = .empty;
    try m.put(arena, meta_mod.key_protocol_version, .{ .string = version.version });
    try m.put(arena, meta_mod.key_client_info, try toValue(arena, self.options.info));
    try m.put(arena, meta_mod.key_client_capabilities, try toValue(arena, self.options.capabilities));
    if (self.options.log_level) |level| try m.put(arena, meta_mod.key_log_level, .{ .string = @tagName(level) });
    try m.put(arena, meta_mod.key_progress_token, switch (id) {
        .integer => |i| .{ .integer = i },
        .string => |s| .{ .string = s },
        .big => |b| .{ .number_string = b },
    });
    return .{ .object = m };
}

fn cursorParams(arena: Allocator, cursor: ?[]const u8) Allocator.Error!Value {
    var params: std.json.ObjectMap = .empty;
    if (cursor) |c| try params.put(arena, "cursor", .{ .string = c });
    return .{ .object = params };
}

fn cloneObject(arena: Allocator, object: std.json.ObjectMap) Allocator.Error!std.json.ObjectMap {
    var out: std.json.ObjectMap = .empty;
    var it = object.iterator();
    while (it.next()) |kv| try out.put(arena, kv.key_ptr.*, kv.value_ptr.*);
    return out;
}

/// Serialize any value with the wire options and parse it back as a tree.
pub fn toValue(arena: Allocator, value: anytype) Allocator.Error!Value {
    if (@TypeOf(value) == Value) return value;
    const text = try json.writeAlloc(arena, value);
    return json.parseTree(arena, text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => unreachable, // the SDK wrote it
    };
}
