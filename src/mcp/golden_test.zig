//! Golden tests: every vendored schema example must parse into its Zig type and serialize
//! back to a structurally identical document.
const std = @import("std");
const Value = std.json.Value;
const json = @import("json.zig");
const message = @import("jsonrpc/message.zig");
const export_map = @import("protocol/export_map.zig");

const fixtures_dir = "test/fixtures/mcp_schema_2026_07_28/examples";

fn valueEql(a: Value, b: Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |x| return b == .bool and b.bool == x,
        .integer => |x| return switch (b) {
            .integer => |y| x == y,
            .float => |y| @as(f64, @floatFromInt(x)) == y,
            .number_string => |s| (std.fmt.parseInt(i64, s, 10) catch return false) == x,
            else => false,
        },
        .float => |x| return switch (b) {
            .integer => |y| x == @as(f64, @floatFromInt(y)),
            .float => |y| x == y,
            .number_string => |s| (std.fmt.parseFloat(f64, s) catch return false) == x,
            else => false,
        },
        .number_string => |s| return switch (b) {
            .number_string => |t| std.mem.eql(u8, s, t),
            else => valueEql(b, a),
        },
        .string => |x| return b == .string and std.mem.eql(u8, b.string, x),
        .array => |x| {
            if (b != .array or b.array.items.len != x.items.len) return false;
            for (x.items, b.array.items) |i, j| if (!valueEql(i, j)) return false;
            return true;
        },
        .object => |x| {
            if (b != .object or b.object.count() != x.count()) return false;
            var it = x.iterator();
            while (it.next()) |kv| {
                const other = b.object.get(kv.key_ptr.*) orelse return false;
                if (!valueEql(kv.value_ptr.*, other)) return false;
            }
            return true;
        },
    }
}

fn roundTrip(arena: std.mem.Allocator, comptime entry: export_map.Entry, text: []const u8) ![]u8 {
    const tree = try json.parseTree(arena, text);
    var aw: std.Io.Writer.Allocating = .init(arena);
    switch (entry.role) {
        .data => {
            const typed = try json.parseValue(entry.T, arena, tree);
            try json.write(typed, &aw.writer);
        },
        .request => {
            const msg = try message.Message.fromValue(arena, tree);
            const req = msg.request;
            const params = try json.parseValue(entry.T, arena, req.params.?);
            try message.writeRequest(&aw.writer, req.id, req.method, params);
        },
        .notification => {
            const msg = try message.Message.fromValue(arena, tree);
            const note = msg.notification;
            if (note.params) |p| {
                const params = try json.parseValue(entry.T, arena, p);
                try message.writeNotification(&aw.writer, note.method, params);
            } else {
                try aw.writer.print("{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\"}}", .{note.method});
            }
        },
        .response => {
            const msg = try message.Message.fromValue(arena, tree);
            const resp = msg.response;
            const result = try json.parseValue(entry.T, arena, resp.result);
            try message.writeResponse(&aw.writer, resp.id, result);
        },
        .error_response => {
            const msg = try message.Message.fromValue(arena, tree);
            const e = msg.error_response;
            try message.writeErrorResponse(&aw.writer, e.id, .{ .code = e.code, .message = e.message, .data = e.data });
        },
    }
    return aw.toOwnedSlice();
}

test "golden fixtures round trip" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var root = std.Io.Dir.cwd().openDir(io, fixtures_dir, .{ .iterate = true }) catch |e| {
        std.debug.print("cannot open {s}: {t}\n", .{ fixtures_dir, e });
        return e;
    };
    defer root.close(io);

    var failures: usize = 0;
    var checked: usize = 0;
    var it = root.iterate();
    while (try it.next(io)) |type_entry| {
        if (type_entry.kind != .directory) continue;
        const index = export_map.find(type_entry.name) orelse {
            std.debug.print("golden: no export_map entry for fixture type {s}\n", .{type_entry.name});
            failures += 1;
            continue;
        };
        var dir = try root.openDir(io, type_entry.name, .{ .iterate = true });
        defer dir.close(io);
        var files = dir.iterate();
        while (try files.next(io)) |file| {
            if (file.kind != .file or !std.mem.endsWith(u8, file.name, ".json")) continue;
            var arena_state: std.heap.ArenaAllocator = .init(gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const text = try dir.readFileAlloc(io, file.name, arena, .limited(1 << 20));
            checked += 1;
            const out = blk: {
                switch (index) {
                    inline 0...export_map.entries.len - 1 => |i| break :blk roundTrip(arena, export_map.entries[i], text),
                    else => unreachable,
                }
            } catch |e| {
                std.debug.print("golden: {s}/{s}: {t}\n", .{ type_entry.name, file.name, e });
                failures += 1;
                continue;
            };
            var original = try json.parseTree(arena, text);
            const produced = try json.parseTree(arena, out);
            // Known fixture quirk: the ListRootsRequest example carries an `id` that the
            // schema definition does not have (input requests are not JSON-RPC requests).
            if (std.mem.eql(u8, type_entry.name, "ListRootsRequest")) _ = original.object.orderedRemove("id");
            if (!valueEql(original, produced)) {
                std.debug.print("golden: {s}/{s}: mismatch\n  expected {s}\n  produced {s}\n", .{ type_entry.name, file.name, text, out });
                failures += 1;
            }
        }
    }
    std.debug.print("golden: {d} fixtures checked\n", .{checked});
    try std.testing.expect(checked > 100);
    try std.testing.expectEqual(0, failures);
}
