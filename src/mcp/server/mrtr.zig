//! Builders for multi round-trip request results.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../protocol/types.zig");

/// The outcome of a handler: a complete result or a request for more input.
pub fn Outcome(comptime T: type) type {
    return union(enum) {
        complete: T,
        input_required: InputRequired,
        /// Only for tools: turn this call into a task and run the handler again inside it.
        /// Without the tasks extension the handler runs again at once.
        start_task,
    };
}

/// Collects the input requests and the state for an `InputRequiredResult`.
pub const InputRequired = struct {
    arena: Allocator,
    requests: types.InputRequests = .{},
    /// Caller state (JSON text) to seal into `requestState`.
    state: ?[]const u8 = null,

    pub fn init(arena: Allocator) InputRequired {
        return .{ .arena = arena };
    }

    pub const Error = error{
        OutOfMemory,
        DuplicateKey,
        /// The URL of a URL elicitation is not a valid absolute URL.
        InvalidUrl,
    };

    fn put(self: *InputRequired, key: []const u8, request: types.InputRequest) Error!void {
        const gop = try self.requests.map.getOrPut(self.arena, key);
        if (gop.found_existing) return error.DuplicateKey;
        gop.value_ptr.* = request;
    }

    pub fn elicitForm(self: *InputRequired, key: []const u8, message: []const u8, schema: types.ElicitRequestFormParams.RequestedSchema) Error!void {
        try self.put(key, .{ .@"elicitation/create" = .{ .params = .{ .form = .{ .message = message, .requestedSchema = schema } } } });
    }

    /// Ask the user to open `url`. The URL must be a valid absolute URL, see `types.isValidUrl`.
    pub fn elicitUrl(self: *InputRequired, key: []const u8, message: []const u8, url: []const u8) Error!void {
        if (!types.isValidUrl(url)) return error.InvalidUrl;
        try self.put(key, .{ .@"elicitation/create" = .{ .params = .{ .url = .{ .message = message, .url = url } } } });
    }

    pub fn sample(self: *InputRequired, key: []const u8, params: types.CreateMessageRequestParams) Error!void {
        try self.put(key, .{ .@"sampling/createMessage" = .{ .params = params } });
    }

    pub fn listRoots(self: *InputRequired, key: []const u8) Error!void {
        try self.put(key, .{ .@"roots/list" = .{} });
    }

    /// Set the state that the client must echo on the retry. Any JSON text.
    pub fn setState(self: *InputRequired, state_json: []const u8) void {
        self.state = state_json;
    }

    pub fn setStateFmt(self: *InputRequired, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        self.state = try std.fmt.allocPrint(self.arena, fmt, args);
    }

    pub fn count(self: *const InputRequired) usize {
        return self.requests.map.count();
    }

    /// A schema with one string property.
    pub fn stringSchema(arena: Allocator, name: []const u8, description: ?[]const u8, required: bool) Allocator.Error!types.ElicitRequestFormParams.RequestedSchema {
        var props: types.ElicitRequestFormParams.RequestedSchema = .{ .properties = .{} };
        try props.properties.map.put(arena, name, .{ .string = .{ .description = description } });
        if (required) {
            const req = try arena.alloc([]const u8, 1);
            req[0] = name;
            props.required = req;
        }
        return props;
    }
};

test "input required builder" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var ir: InputRequired = .init(arena);
    try ir.elicitForm("user_name", "Your name?", try InputRequired.stringSchema(arena, "name", null, true));
    try ir.listRoots("client_roots");
    try std.testing.expectError(error.DuplicateKey, ir.listRoots("client_roots"));
    try std.testing.expectEqual(2, ir.count());
    // A URL elicitation needs a valid absolute URL.
    try std.testing.expectError(error.InvalidUrl, ir.elicitUrl("link", "Open it.", "example.com/connect"));
    try std.testing.expectError(error.InvalidUrl, ir.elicitUrl("link", "Open it.", "https://"));
    try std.testing.expectEqual(2, ir.count());
    const json = @import("../json.zig");
    const out = try json.writeAlloc(gpa, ir.requests);
    defer gpa.free(out);
    try std.testing.expectEqualStrings(
        "{\"user_name\":{\"method\":\"elicitation/create\",\"params\":{\"message\":\"Your name?\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}}},\"client_roots\":{\"method\":\"roots/list\"}}",
        out,
    );
}
