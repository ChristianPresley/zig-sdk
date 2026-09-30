//! The `x-mcp-header` bindings a client learns from `tools/list` results, shared by the
//! Streamable HTTP and the gRPC clients. The client removes tools with invalid annotations
//! from the list that the application sees and logs a warning for each of them.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const envelope = @import("envelope.zig");

const log = std.log.scoped(.mcp_tool_headers);

pub const Header = std.http.Header;

const Binding = struct { path: [][]u8, header: []u8 };
const Entry = struct { name: []u8, bindings: []Binding };

/// A tool that the client removed from a `tools/list` result.
pub const Rejection = struct {
    tool: []const u8,
    problem: envelope.HeaderProblem,
    /// The `x-mcp-header` value, when it is a string.
    annotation: ?[]const u8,
};

/// Receives each rejection after the log message. The data lives until `learn` returns.
pub const RejectHook = struct {
    userdata: ?*anyopaque = null,
    call: *const fn (userdata: ?*anyopaque, rejection: Rejection) void,
};

pub const Map = struct {
    gpa: Allocator,
    io: Io,
    entries: std.StringHashMapUnmanaged(Entry) = .empty,
    lock: Io.Mutex = .init,
    /// Optional. The client calls it for each tool that it removes.
    on_reject: ?RejectHook = null,

    pub fn init(gpa: Allocator, io: Io) Map {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(self: *Map) void {
        var it = self.entries.valueIterator();
        while (it.next()) |e| self.freeEntry(e.*);
        self.entries.deinit(self.gpa);
    }

    fn freeBindings(gpa: Allocator, bindings: []const Binding) void {
        for (bindings) |b| {
            for (b.path) |step| gpa.free(step);
            gpa.free(b.path);
            gpa.free(b.header);
        }
    }

    fn freeEntry(self: *Map, e: Entry) void {
        freeBindings(self.gpa, e.bindings);
        self.gpa.free(e.bindings);
        self.gpa.free(e.name);
    }

    /// Scan a `tools/list` result frame. Returns a rewritten frame without the tools that have
    /// invalid annotations, or null when all annotations are valid. The function logs a
    /// warning with the tool name and the reason for each tool that it removes.
    pub fn learn(self: *Map, arena: Allocator, frame: []const u8) !?[]const u8 {
        var tree = try json.parseTree(arena, frame);
        if (tree != .object) return null;
        const result = tree.object.get("result") orelse return null;
        if (result != .object) return null;
        const tools = result.object.get("tools") orelse return null;
        if (tools != .array) return null;
        var kept: std.json.Array = .init(arena);
        var removed = false;
        for (tools.array.items) |tool| {
            if (tool != .object) continue;
            const name = json.getString(tool, "name") orelse continue;
            const schema = tool.object.get("inputSchema") orelse .null;
            switch (try envelope.headerAnnotations(arena, schema)) {
                .invalid => |invalid| {
                    self.reject(.{ .tool = name, .problem = invalid.problem, .annotation = invalid.annotation });
                    removed = true;
                    continue;
                },
                .valid => |annotations| try self.store(name, annotations),
            }
            try kept.append(tool);
        }
        if (!removed) return null;
        var new_result = result;
        try new_result.object.put(arena, "tools", .{ .array = kept });
        try tree.object.put(arena, "result", new_result);
        return try json.writeAlloc(arena, tree);
    }

    fn reject(self: *Map, rejection: Rejection) void {
        log.warn("the client removes the tool '{s}' from tools/list: {s} (x-mcp-header '{s}')", .{ rejection.tool, rejection.problem.text(), rejection.annotation orelse "" });
        if (self.on_reject) |hook| hook.call(hook.userdata, rejection);
    }

    fn store(self: *Map, name: []const u8, annotations: []const envelope.HeaderAnnotation) !void {
        var bindings: std.ArrayList(Binding) = .empty;
        errdefer {
            freeBindings(self.gpa, bindings.items);
            bindings.deinit(self.gpa);
        }
        for (annotations) |a| {
            try bindings.ensureUnusedCapacity(self.gpa, 1);
            const path = try self.gpa.alloc([]u8, a.path.len);
            var filled: usize = 0;
            errdefer {
                for (path[0..filled]) |step| self.gpa.free(step);
                self.gpa.free(path);
            }
            for (a.path) |step| {
                path[filled] = try self.gpa.dupe(u8, step);
                filled += 1;
            }
            const header = try self.gpa.dupe(u8, a.header);
            bindings.appendAssumeCapacity(.{ .path = path, .header = header });
        }
        const owned_name = try self.gpa.dupe(u8, name);
        errdefer self.gpa.free(owned_name);
        const entry: Entry = .{ .name = owned_name, .bindings = try bindings.toOwnedSlice(self.gpa) };
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.entries.fetchRemove(name)) |old| self.freeEntry(old.value);
        self.entries.put(self.gpa, entry.name, entry) catch |e| {
            self.freeEntry(entry);
            return e;
        };
    }

    pub const AppendError = envelope.EncodeParamError;

    /// Append the `mcp-param-*` headers for the arguments of a tool call to a list of headers
    /// with `name` and `value` fields. The function reads each value at the exact property
    /// path of its annotation. `lowercase` keeps the annotated header name as it is when
    /// false, for HTTP/1.1, and lowercases it for HTTP/2. An integer outside the safe range
    /// gives `error.UnsafeInteger`.
    pub fn appendParamHeaders(self: *Map, arena: Allocator, headers: anytype, tool: []const u8, arguments: Value, lowercase: bool) AppendError!void {
        if (arguments != .object) return;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const entry = self.entries.get(tool) orelse return;
        for (entry.bindings) |b| {
            const value = envelope.valueAtPath(arguments, b.path) orelse continue;
            const encoded = (try envelope.encodeParam(arena, value)) orelse continue;
            const suffix = if (lowercase) try std.ascii.allocLowerString(arena, b.header) else b.header;
            const name = try std.mem.concat(arena, u8, &.{ envelope.header_param_prefix, suffix });
            try headers.append(arena, .{ .name = name, .value = encoded });
        }
    }
};
