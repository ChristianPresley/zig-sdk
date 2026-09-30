//! Everything a handler needs about the request it serves.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("../protocol/types.zig");
const meta_mod = @import("../protocol/meta.zig");
const errors = @import("../protocol/errors.zig");
const json = @import("../json.zig");
const message = @import("../jsonrpc/message.zig");
const Transport = @import("../transport/Transport.zig");
const RequestId = @import("../jsonrpc/id.zig").RequestId;
const Server = @import("Server.zig");

const Principal = @import("../auth/resource_server.zig").Principal;
const tasks = @import("tasks.zig");

const RequestContext = @This();

io: Io,
gpa: Allocator,
/// Freed when the request completes. Results can point into it.
arena: Allocator,
server: *Server,
id: RequestId,
method: []const u8,
meta: meta_mod.RequestMeta,
/// The raw `params` object.
params: ?Value,
/// Responses to input requests from an earlier round, keyed by the server-chosen key.
input_responses: ?types.InputResponses = null,
/// The caller state that was sealed into `requestState` in an earlier round.
request_state: ?[]const u8 = null,
cancel: *Transport.CancelToken,
responder: Transport.Responder,
kind: Transport.Kind,
/// The `userdata` given at registration of the tool, resource or prompt.
userdata: ?*anyopaque = null,
/// Transport data for the request. The HTTP server stores the authorization principal.
transport_context: ?*anyopaque = null,
/// Set while a handler runs inside a task of the Tasks extension.
task: ?*tasks.Task = null,
/// Set by `setError`. Returned as the JSON-RPC error of the request.
rpc_error: ?errors.RpcError = null,
/// `params.name` or `params.uri`, used to bind sealed state to its target.
target: []const u8 = "",
progress_sent: u32 = 0,
long_lived: bool = false,

pub const Error = error{ Canceled, Rpc, OutOfMemory };

/// True when the handler runs inside a task. A tool that returns `.start_task` runs again
/// with this set.
pub fn inTask(self: *const RequestContext) bool {
    return self.task != null;
}

/// The authorization principal of the request, when the transport checked a bearer token.
pub fn principal(self: *const RequestContext) ?*const Principal {
    const p = self.transport_context orelse return null;
    if (self.kind != .streamable_http) return null;
    return @ptrCast(@alignCast(p));
}

/// Return `error.Canceled` when the client cancelled the request.
pub fn checkCancel(self: *RequestContext) error{Canceled}!void {
    try self.cancel.check();
}

pub fn isCancelled(self: *const RequestContext) bool {
    return self.cancel.isCancelled();
}

/// Record a JSON-RPC error for the request and return `error.Rpc`.
pub fn setError(self: *RequestContext, err: errors.RpcError) error{Rpc} {
    self.rpc_error = err;
    return error.Rpc;
}

pub fn invalidParams(self: *RequestContext, comptime fmt: []const u8, args: anytype) Error {
    const msg = std.fmt.allocPrint(self.arena, fmt, args) catch return error.OutOfMemory;
    return self.setError(errors.invalidParams(msg));
}

/// Send `notifications/progress` on the request stream. Dropped when the request carried no
/// progress token or when the per-request rate limit is exceeded.
pub fn progress(self: *RequestContext, value: f64, total: ?f64, note: ?[]const u8) Error!void {
    const token = self.meta.progress_token orelse return;
    if (self.progress_sent >= self.server.options.limits.max_progress_rate_per_s * 60) return;
    self.progress_sent += 1;
    const params: types.ProgressNotificationParams = .{ .progressToken = token, .progress = value, .total = total, .message = note };
    try self.sendNotification("notifications/progress", params);
}

/// Send `notifications/message` on the request stream. Dropped unless the server declares the
/// logging capability, the request set a log level, and `level` is at least that level.
pub fn log(self: *RequestContext, level: types.LoggingLevel, logger: ?[]const u8, data: Value) Error!void {
    if (self.server.options.capabilities.logging == null) return;
    const min = self.meta.log_level orelse return;
    if (level.severity() < min.severity()) return;
    if (self.long_lived) return;
    const params: types.LoggingMessageNotificationParams = .{ .level = level, .logger = logger, .data = data };
    try self.sendNotification("notifications/message", params);
}

/// Log a formatted text message at `level`.
pub fn logText(self: *RequestContext, level: types.LoggingLevel, logger: ?[]const u8, comptime fmt: []const u8, args: anytype) Error!void {
    const text = try std.fmt.allocPrint(self.arena, fmt, args);
    try self.log(level, logger, .{ .string = text });
}

pub fn sendNotification(self: *RequestContext, method_name: []const u8, params: anytype) Error!void {
    try self.checkCancel();
    var aw: Io.Writer.Allocating = .init(self.arena);
    message.writeNotification(&aw.writer, method_name, params) catch return error.OutOfMemory;
    self.responder.notify(self.io, aw.written()) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
        error.Closed, error.WriteFailed => return error.Canceled,
    };
}

pub const CapabilityPath = enum { roots, sampling, sampling_tools, elicitation_form, elicitation_url };

/// True when the client declared the capability for this request.
pub fn hasClientCapability(self: *const RequestContext, path: CapabilityPath) bool {
    const caps = self.meta.client_capabilities;
    return switch (path) {
        .roots => caps.roots != null,
        .sampling => caps.sampling != null,
        .sampling_tools => caps.sampling != null and caps.sampling.?.tools != null,
        .elicitation_form => caps.hasElicitation(.form),
        .elicitation_url => caps.hasElicitation(.url),
    };
}

/// Fail the request with `-32021` unless the client declared `path`.
pub fn requireClientCapability(self: *RequestContext, path: CapabilityPath) Error!void {
    if (self.hasClientCapability(path)) return;
    const required: types.ClientCapabilities = switch (path) {
        .roots => .{ .roots = .{} },
        .sampling => .{ .sampling = .{} },
        .sampling_tools => .{ .sampling = .{ .tools = .{ .object = .empty } } },
        .elicitation_form => .{ .elicitation = .{ .form = .{ .object = .empty } } },
        .elicitation_url => .{ .elicitation = .{ .url = .{ .object = .empty } } },
    };
    const err = try errors.missingRequiredClientCapability(self.arena, required, "The request needs a client capability that the client did not declare");
    return self.setError(err);
}

/// The response the client gave for input request `key`, decoded as `T`. Returns null when the
/// client sent no response for that key.
pub fn inputResponse(self: *RequestContext, comptime T: type, key: []const u8) Error!?T {
    const responses = self.input_responses orelse return null;
    const value = responses.map.get(key) orelse return null;
    return json.parseValue(T, self.arena, value) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return self.invalidParams("inputResponses[{s}] has an unexpected shape", .{key}),
    };
}

pub fn elicitResponse(self: *RequestContext, key: []const u8) Error!?types.ElicitResult {
    return self.inputResponse(types.ElicitResult, key);
}

pub fn sampleResponse(self: *RequestContext, key: []const u8) Error!?types.CreateMessageResult {
    return self.inputResponse(types.CreateMessageResult, key);
}

pub fn rootsResponse(self: *RequestContext, key: []const u8) Error!?types.ListRootsResult {
    return self.inputResponse(types.ListRootsResult, key);
}

/// Decode the caller state from an earlier round as `T` (the state is JSON text).
pub fn state(self: *RequestContext, comptime T: type) Error!?T {
    const text = self.request_state orelse return null;
    const tree = json.parseTree(self.arena, text) catch return self.invalidParams("requestState payload is not JSON", .{});
    return json.parseValue(T, self.arena, tree) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return self.invalidParams("requestState payload has an unexpected shape", .{}),
    };
}

/// True when the client answered every key in `keys`.
pub fn hasAllResponses(self: *const RequestContext, keys: []const []const u8) bool {
    const responses = self.input_responses orelse return keys.len == 0;
    for (keys) |k| if (responses.map.get(k) == null) return false;
    return true;
}
