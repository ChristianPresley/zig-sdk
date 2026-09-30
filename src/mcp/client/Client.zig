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

const Client = @This();

gpa: Allocator,
io: Io,
options: Options,
transport: ?Transport.ClientTransport = null,
next_id: std.atomic.Value(i64) = .init(1),

pub const Options = struct {
    info: types.Implementation,
    capabilities: types.ClientCapabilities = .{},
    hooks: Hooks = .{},
    limits: Limits = .{},
    /// Ask the server for log messages at this level and above (deprecated feature).
    log_level: ?types.LoggingLevel = null,
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
    elicit_form: ?*const fn (ctx: *HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult = null,
    /// Answer a URL elicitation. The hook shows the URL to the user and never opens it alone.
    elicit_url: ?*const fn (ctx: *HookContext, params: types.ElicitRequestURLParams) anyerror!types.ElicitResult = null,
    /// Answer a sampling request. Required when `capabilities.sampling` is declared.
    sample: ?*const fn (ctx: *HookContext, params: types.CreateMessageRequestParams) anyerror!types.CreateMessageResult = null,
    /// List the roots. Required when `capabilities.roots` is declared.
    list_roots: ?*const fn (ctx: *HookContext) anyerror![]const types.Root = null,
    /// A server notification that belongs to no request (stdio only).
    on_notification: ?*const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void = null,
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
    /// Relative timeout for the whole request, including multi round-trip rounds.
    timeout: ?Io.Duration = null,
    cancel: ?*Transport.CancelToken = null,
    on_progress: ?*const fn (userdata: ?*anyopaque, params: types.ProgressNotificationParams) void = null,
    on_log: ?*const fn (userdata: ?*anyopaque, params: types.LoggingMessageNotificationParams) void = null,
    /// Any notification on the request stream that is not progress or log.
    on_notification: ?*const fn (userdata: ?*anyopaque, method: []const u8, params: ?Value) void = null,
    /// Return an `InputRequiredResult` to the caller instead of driving the hooks.
    allow_input_required: bool = false,
    diagnostics: ?*Diagnostics = null,
    userdata: ?*anyopaque = null,
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
};

pub fn init(gpa: Allocator, io: Io, options: Options) Client {
    return .{ .gpa = gpa, .io = io, .options = options };
}

pub fn deinit(self: *Client) void {
    self.* = undefined;
}

pub fn connect(self: *Client, transport: Transport.ClientTransport) void {
    self.transport = transport;
}

/// A result together with the raw `Value` it was parsed from.
pub fn Response(comptime T: type) type {
    return struct {
        result: T,
        raw: Value,
        /// Set when the server returned `InputRequiredResult` and `allow_input_required` was on.
        input_required: ?types.InputRequiredResult = null,
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
pub fn callTool(self: *Client, arena: Allocator, name: []const u8, arguments: anytype, options: RequestOptions) RequestError!types.CallToolResult {
    var params: std.json.ObjectMap = .empty;
    try params.put(arena, "name", .{ .string = name });
    if (@TypeOf(arguments) != @TypeOf(null)) try params.put(arena, "arguments", try toValue(arena, arguments));
    return (try self.request(arena, .@"tools/call", .{ .object = params }, options)).result;
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
    const result = json.parseValue(T, arena, raw.value) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidResponse,
    };
    return .{ .result = result, .raw = raw.value };
}

const Raw = struct {
    value: Value,
    input_required: ?types.InputRequiredResult = null,
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

    fn onFrame(ptr: *anyopaque, io: Io, frame: []const u8) anyerror!void {
        _ = io;
        const self: *Collector = @ptrCast(@alignCast(ptr));
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

    var round: u32 = 0;
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
            error.Closed => return error.Closed,
            error.InvalidFrame, error.HttpStatus => return error.InvalidResponse,
            error.WriteFailed, error.ReadFailed => return error.TransportFailed,
        };
        if (collector.rpc_error) |rpc| {
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
        if (std.mem.eql(u8, result_type.?, types.result_type_complete)) return .{ .value = result };
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
                return toValue(arena, result);
            },
            .url => |url| {
                if (!caps.hasElicitation(.url)) return error.UndeclaredInputRequest;
                const f = hooks.elicit_url orelse return error.HookFailed;
                const result = f(&ctx, url) catch return error.HookFailed;
                if (result.content != null) return error.HookFailed;
                return toValue(arena, result);
            },
        },
        .@"sampling/createMessage" => |s| {
            if (caps.sampling == null) return error.UndeclaredInputRequest;
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
