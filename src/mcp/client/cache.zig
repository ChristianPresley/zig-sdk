//! The client result cache. It keeps results that carry a positive `ttlMs`, keyed by the
//! method and the parameters, until the hint expires or a list-changed notification arrives.
//! One client speaks for one identity, so a `private` result never crosses to another one.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");

pub const Options = struct {
    enabled: bool = false,
    /// Entries kept at the same time. Overflow: the cache drops the oldest entry.
    max_entries: u32 = 256,
    /// The longest lifetime accepted from a server hint.
    max_ttl_ms: i64 = 3_600_000,
};

pub const Mode = enum {
    /// Serve from the cache when possible, store the result otherwise.
    default,
    /// Neither read nor store.
    bypass,
    /// Store the fresh result, but do not serve the cached one.
    refresh,
};

const Entry = struct {
    key: []u8,
    method: []u8,
    text: []u8,
    expires_ms: i64,
};

pub const Cache = struct {
    gpa: Allocator,
    io: Io,
    options: Options,
    entries: std.ArrayList(Entry) = .empty,
    lock: Io.Mutex = .init,

    pub fn init(gpa: Allocator, io: Io, options: Options) Cache {
        return .{ .gpa = gpa, .io = io, .options = options };
    }

    pub fn deinit(self: *Cache) void {
        for (self.entries.items) |e| self.freeEntry(e);
        self.entries.deinit(self.gpa);
    }

    fn freeEntry(self: *Cache, e: Entry) void {
        self.gpa.free(e.key);
        self.gpa.free(e.method);
        self.gpa.free(e.text);
    }

    fn nowMs(self: *Cache) i64 {
        return @intCast(@divFloor(Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_ms));
    }

    /// The key of a request: the method and the parameters without `_meta`.
    pub fn key(arena: Allocator, method: []const u8, params: Value) Allocator.Error![]u8 {
        var copy: std.json.ObjectMap = .empty;
        if (params == .object) {
            var it = params.object.iterator();
            while (it.next()) |kv| {
                if (std.mem.eql(u8, kv.key_ptr.*, "_meta")) continue;
                try copy.put(arena, kv.key_ptr.*, kv.value_ptr.*);
            }
        }
        const text = try json.writeAlloc(arena, Value{ .object = copy });
        return std.mem.concat(arena, u8, &.{ method, "\x00", text });
    }

    /// The cached result text, or null.
    pub fn get(self: *Cache, request_key: []const u8) ?[]const u8 {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const now = self.nowMs();
        for (self.entries.items, 0..) |e, i| {
            if (!std.mem.eql(u8, e.key, request_key)) continue;
            if (e.expires_ms <= now) {
                self.freeEntry(self.entries.orderedRemove(i));
                return null;
            }
            return e.text;
        }
        return null;
    }

    /// Store a result. `ttl_ms` of zero or less stores nothing.
    pub fn put(self: *Cache, request_key: []const u8, method: []const u8, text: []const u8, ttl_ms: i64) Allocator.Error!void {
        if (ttl_ms <= 0) return;
        const ttl = @min(ttl_ms, self.options.max_ttl_ms);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.entries.items, 0..) |e, i| if (std.mem.eql(u8, e.key, request_key)) {
            self.freeEntry(self.entries.orderedRemove(i));
            break;
        };
        while (self.entries.items.len >= self.options.max_entries and self.entries.items.len > 0) {
            self.freeEntry(self.entries.orderedRemove(0));
        }
        const entry: Entry = .{
            .key = try self.gpa.dupe(u8, request_key),
            .method = try self.gpa.dupe(u8, method),
            .text = try self.gpa.dupe(u8, text),
            .expires_ms = self.nowMs() + ttl,
        };
        errdefer self.freeEntry(entry);
        try self.entries.append(self.gpa, entry);
    }

    /// Drop the entries of one method, or all entries with null.
    pub fn invalidate(self: *Cache, method: ?[]const u8) void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = self.entries.items[i];
            if (method == null or std.mem.eql(u8, e.method, method.?)) {
                self.freeEntry(self.entries.orderedRemove(i));
            } else i += 1;
        }
    }

    /// The method a list-changed or updated notification invalidates.
    pub fn methodForNotification(notification: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, notification, "notifications/tools/list_changed")) return "tools/list";
        if (std.mem.eql(u8, notification, "notifications/prompts/list_changed")) return "prompts/list";
        if (std.mem.eql(u8, notification, "notifications/resources/list_changed")) return "resources/list";
        if (std.mem.eql(u8, notification, "notifications/resources/updated")) return "resources/read";
        return null;
    }

    pub fn count(self: *Cache) usize {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        return self.entries.items.len;
    }
};

test "keys, lifetime and invalidation" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var cache: Cache = .init(gpa, std.testing.io, .{ .enabled = true, .max_entries = 2 });
    defer cache.deinit();
    const params = try json.parseTree(arena, "{\"_meta\":{\"x\":1},\"uri\":\"file:///a\"}");
    const k = try Cache.key(arena, "resources/read", params);
    try std.testing.expectEqualStrings("resources/read\x00{\"uri\":\"file:///a\"}", k);
    try std.testing.expect(cache.get(k) == null);
    try cache.put(k, "resources/read", "{\"contents\":[]}", 60_000);
    try std.testing.expectEqualStrings("{\"contents\":[]}", cache.get(k).?);
    try cache.put("k2", "tools/list", "{}", 0); // not stored
    try std.testing.expectEqual(1, cache.count());
    try cache.put("k2", "tools/list", "{}", 60_000);
    try cache.put("k3", "prompts/list", "{}", 60_000); // evicts the oldest
    try std.testing.expectEqual(2, cache.count());
    try std.testing.expect(cache.get(k) == null);
    cache.invalidate(Cache.methodForNotification("notifications/tools/list_changed"));
    try std.testing.expectEqual(1, cache.count());
    cache.invalidate(null);
    try std.testing.expectEqual(0, cache.count());
}
