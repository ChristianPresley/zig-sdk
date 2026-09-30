//! The client result cache. It keeps results that carry a positive `ttlMs`, keyed by the
//! method and the parameters, until the hint expires or a list-changed notification arrives.
//! A `private` entry, and an entry without `cacheScope`, belongs to one authorization context:
//! the digest of the credential that the transport sends. The cache serves such an entry only
//! in the same context and drops it when the context changes.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const json = @import("../json.zig");
const types = @import("../protocol/types.zig");

/// The authorization context of a request: the SHA-256 digest of the credential, or null when
/// the request carries no credential.
pub const Context = ?[32]u8;

/// The context of a credential.
pub fn contextOf(credential: ?[]const u8) Context {
    const c = credential orelse return null;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(c, &digest, .{});
    return digest;
}

/// True when two contexts are equal.
pub fn sameContext(a: Context, b: Context) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, &a.?, &b.?);
}

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
    scope: types.CacheScope,
    /// The context of a private entry. A public entry ignores it.
    context: Context,

    fn visibleIn(self: Entry, context: Context) bool {
        return self.scope == .public or sameContext(self.context, context);
    }
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

    /// The cached result text for a request in `context`, or null.
    pub fn get(self: *Cache, request_key: []const u8, context: Context) ?[]const u8 {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const now = self.nowMs();
        for (self.entries.items, 0..) |e, i| {
            if (!std.mem.eql(u8, e.key, request_key) or !e.visibleIn(context)) continue;
            if (e.expires_ms <= now) {
                self.freeEntry(self.entries.orderedRemove(i));
                return null;
            }
            return e.text;
        }
        return null;
    }

    /// Store a result that a request in `context` received. `ttl_ms` of zero or less stores
    /// nothing.
    pub fn put(self: *Cache, request_key: []const u8, method: []const u8, text: []const u8, ttl_ms: i64, scope: types.CacheScope, context: Context) Allocator.Error!void {
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
            .scope = scope,
            .context = context,
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

    /// Drop the private entries of every context other than `context`. The client calls this
    /// before each request, so a change of the credential drops the private entries.
    pub fn enterContext(self: *Cache, context: Context) void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (!self.entries.items[i].visibleIn(context)) {
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
    try std.testing.expect(cache.get(k, null) == null);
    try cache.put(k, "resources/read", "{\"contents\":[]}", 60_000, .public, null);
    try std.testing.expectEqualStrings("{\"contents\":[]}", cache.get(k, null).?);
    try cache.put("k2", "tools/list", "{}", 0, .public, null); // not stored
    try std.testing.expectEqual(1, cache.count());
    try cache.put("k2", "tools/list", "{}", 60_000, .public, null);
    try cache.put("k3", "prompts/list", "{}", 60_000, .public, null); // evicts the oldest
    try std.testing.expectEqual(2, cache.count());
    try std.testing.expect(cache.get(k, null) == null);
    cache.invalidate(Cache.methodForNotification("notifications/tools/list_changed"));
    try std.testing.expectEqual(1, cache.count());
    cache.invalidate(null);
    try std.testing.expectEqual(0, cache.count());
}

test "private entries belong to one authorization context" {
    const gpa = std.testing.allocator;
    var cache: Cache = .init(gpa, std.testing.io, .{ .enabled = true });
    defer cache.deinit();
    const alice = contextOf("token-alice");
    const bob = contextOf("token-bob");
    try std.testing.expect(!sameContext(alice, bob));
    try std.testing.expect(sameContext(contextOf(null), null));

    try cache.put("mine", "resources/read", "{\"a\":1}", 60_000, .private, alice);
    try cache.put("list", "tools/list", "{\"b\":2}", 60_000, .public, alice);
    // The private entry is visible only in its own context. The public entry is shared.
    try std.testing.expect(cache.get("mine", alice) != null);
    try std.testing.expect(cache.get("mine", bob) == null);
    try std.testing.expect(cache.get("mine", null) == null);
    try std.testing.expect(cache.get("list", bob) != null);
    // A request in another context drops the private entries of the old context.
    cache.enterContext(bob);
    try std.testing.expectEqual(1, cache.count());
    try std.testing.expect(cache.get("mine", alice) == null);
}
