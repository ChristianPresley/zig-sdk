//! The `x-mcp-header` bindings a client learns from `tools/list` results, shared by the
//! Streamable HTTP and the gRPC clients. Tools with invalid annotations are removed from
//! the list the application sees.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const envelope = @import("envelope.zig");

pub const Header = std.http.Header;

const Binding = struct { param: []u8, header: []u8 };
const Entry = struct { name: []u8, bindings: []Binding };

pub const Map = struct {
    gpa: Allocator,
    io: Io,
    entries: std.StringHashMapUnmanaged(Entry) = .empty,
    lock: Io.Mutex = .init,

    pub fn init(gpa: Allocator, io: Io) Map {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(self: *Map) void {
        var it = self.entries.valueIterator();
        while (it.next()) |e| self.freeEntry(e.*);
        self.entries.deinit(self.gpa);
    }

    fn freeEntry(self: *Map, e: Entry) void {
        for (e.bindings) |b| {
            self.gpa.free(b.param);
            self.gpa.free(b.header);
        }
        self.gpa.free(e.bindings);
        self.gpa.free(e.name);
    }

    /// Scan a `tools/list` result frame. Returns a rewritten frame when tools with invalid
    /// annotations were removed, else null.
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
            if (!envelope.schemaHeadersValid(schema)) {
                removed = true;
                continue;
            }
            try self.store(name, schema);
            try kept.append(tool);
        }
        if (!removed) return null;
        var new_result = result;
        try new_result.object.put(arena, "tools", .{ .array = kept });
        try tree.object.put(arena, "result", new_result);
        return try json.writeAlloc(arena, tree);
    }

    fn store(self: *Map, name: []const u8, schema: Value) !void {
        var bindings: std.ArrayList(Binding) = .empty;
        errdefer {
            for (bindings.items) |b| {
                self.gpa.free(b.param);
                self.gpa.free(b.header);
            }
            bindings.deinit(self.gpa);
        }
        if (schema == .object) if (schema.object.get("properties")) |props| if (props == .object) {
            var it = props.object.iterator();
            while (it.next()) |kv| {
                const prop = kv.value_ptr.*;
                if (prop != .object) continue;
                const header = json.getString(prop, "x-mcp-header") orelse continue;
                try bindings.append(self.gpa, .{
                    .param = try self.gpa.dupe(u8, kv.key_ptr.*),
                    .header = try self.gpa.dupe(u8, header),
                });
            }
        };
        const entry: Entry = .{ .name = try self.gpa.dupe(u8, name), .bindings = try bindings.toOwnedSlice(self.gpa) };
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.entries.fetchRemove(name)) |old| self.freeEntry(old.value);
        self.entries.put(self.gpa, entry.name, entry) catch |e| {
            self.freeEntry(entry);
            return e;
        };
    }

    /// Append the `mcp-param-*` headers for the arguments of a tool call to a list of headers
    /// with `name` and `value` fields. `lowercase` keeps the annotated header name as it is
    /// when false, for HTTP/1.1, and lowercases it for HTTP/2.
    pub fn appendParamHeaders(self: *Map, arena: Allocator, headers: anytype, tool: []const u8, arguments: Value, lowercase: bool) Allocator.Error!void {
        if (arguments != .object) return;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const entry = self.entries.get(tool) orelse return;
        for (entry.bindings) |b| {
            const value = arguments.object.get(b.param) orelse continue;
            const encoded = (try envelope.encodeParam(arena, value)) orelse continue;
            const suffix = if (lowercase) try std.ascii.allocLowerString(arena, b.header) else b.header;
            const name = try std.mem.concat(arena, u8, &.{ envelope.header_param_prefix, suffix });
            try headers.append(arena, .{ .name = name, .value = encoded });
        }
    }
};
