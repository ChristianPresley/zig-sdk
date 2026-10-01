//! Rate limits. A `Window` counts events in windows of one second. The server limits the
//! progress notifications that a request sends with it, and the client limits the progress
//! notifications that a request receives. A `Bucket` is a token bucket, and a `Table` keeps
//! one bucket for each caller, with a limit on the number of callers.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Rate = @import("../Limits.zig").Rate;

/// Counts events in windows of one second. The first event starts a window. An event after
/// the end of the window starts the next window.
pub const Window = struct {
    start: i96 = 0,
    count: u32 = 0,

    /// Return true and count the event when the window has fewer than `per_second` events.
    /// Return false when the event is over the limit.
    pub fn admit(self: *Window, io: Io, per_second: u32) bool {
        return self.admitAt(Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds, per_second);
    }

    /// The same as `admit`, with the time in nanoseconds from the caller.
    pub fn admitAt(self: *Window, now: i96, per_second: u32) bool {
        if (self.count == 0 or now - self.start >= std.time.ns_per_s) {
            self.start = now;
            self.count = 0;
        }
        if (self.count >= per_second) return false;
        self.count += 1;
        return true;
    }
};

/// A token bucket for one `Rate`. One token is `rate.periodNs()` units of `level`. Each
/// nanosecond adds `rate.count` units, up to the capacity of the rate.
pub const Bucket = struct {
    level: u128,
    /// The time of the last refill, in nanoseconds.
    last: i96,

    /// A full bucket at the time `now`.
    pub fn full(rate: Rate, now: i96) Bucket {
        return .{ .level = maxLevel(rate), .last = now };
    }

    fn maxLevel(rate: Rate) u128 {
        return @as(u128, rate.capacity()) * rate.periodNs();
    }

    /// Add the tokens of the time since the last refill. A time before the last refill adds
    /// nothing.
    pub fn refill(self: *Bucket, rate: Rate, now: i96) void {
        if (now <= self.last) return;
        const elapsed: u128 = @intCast(now - self.last);
        self.last = now;
        self.level = @min(maxLevel(rate), self.level +| (elapsed *| rate.count));
    }

    /// Refill the bucket, then take one token. Return 0 when the bucket had a token. Else
    /// return the nanoseconds until the bucket has one token, at least 1. The bucket does
    /// not change then. A rate with a count of zero admits every event.
    pub fn take(self: *Bucket, rate: Rate, now: i96) u64 {
        if (!rate.enabled()) return 0;
        self.refill(rate, now);
        const unit = rate.periodNs();
        if (self.level >= unit) {
            self.level -= unit;
            return 0;
        }
        const missing = unit - self.level;
        const wait = (missing + rate.count - 1) / rate.count;
        return @intCast(@max(1, @min(wait, std.math.maxInt(u64))));
    }

    /// Put back the token of an event that a different limit refused.
    pub fn giveBack(self: *Bucket, rate: Rate) void {
        if (!rate.enabled()) return;
        self.level = @min(maxLevel(rate), self.level + rate.periodNs());
    }
};

/// The key of a caller in a `Table`: 16 bytes of a hash of the identity of the caller.
pub const Key = [16]u8;

/// One bucket for each caller, for at most `max_keys` callers. When the table is full, the
/// bucket of a new caller replaces the bucket of the caller that the table used least
/// recently. All operations take a constant time. The table is not thread-safe.
pub const Table = struct {
    entries: std.ArrayList(Entry) = .empty,
    index: std.AutoHashMapUnmanaged(Key, u32) = .empty,
    /// The entry of the most recent use, or `none`.
    newest: u32 = none,
    /// The entry of the least recent use, or `none`.
    oldest: u32 = none,
    max_keys: u32,
    /// Callers that the table forgot to make space for new callers.
    forgotten: u64 = 0,

    const none = std.math.maxInt(u32);

    pub const Entry = struct {
        key: Key,
        bucket: Bucket,
        /// Events that the bucket refused and that the caller did not get a report of.
        dropped: u64 = 0,
        newer: u32 = none,
        older: u32 = none,
    };

    /// A table for at most `max_keys` callers. A value of zero counts as 1.
    pub fn init(max_keys: u32) Table {
        return .{ .max_keys = @max(max_keys, 1) };
    }

    pub fn deinit(self: *Table, gpa: Allocator) void {
        self.entries.deinit(gpa);
        self.index.deinit(gpa);
        self.* = undefined;
    }

    /// The number of callers with a bucket.
    pub fn count(self: *const Table) usize {
        return self.index.count();
    }

    /// True when the table has a bucket for `key`.
    pub fn contains(self: *const Table, key: Key) bool {
        return self.index.contains(key);
    }

    /// The entry of `key`, now the most recent one. A new caller gets a full bucket of
    /// `rate`. The pointer is valid until the next call of `get`.
    pub fn get(self: *Table, gpa: Allocator, key: Key, rate: Rate, now: i96) Allocator.Error!*Entry {
        if (self.index.get(key)) |i| {
            self.unlink(i);
            self.pushNewest(i);
            return &self.entries.items[i];
        }
        try self.index.ensureUnusedCapacity(gpa, 1);
        const i: u32 = if (self.entries.items.len < self.max_keys) blk: {
            try self.entries.ensureUnusedCapacity(gpa, 1);
            self.entries.appendAssumeCapacity(undefined);
            break :blk @intCast(self.entries.items.len - 1);
        } else blk: {
            const old = self.oldest;
            self.unlink(old);
            _ = self.index.remove(self.entries.items[old].key);
            self.forgotten += 1;
            break :blk old;
        };
        self.entries.items[i] = .{ .key = key, .bucket = .full(rate, now) };
        self.index.putAssumeCapacityNoClobber(key, i);
        self.pushNewest(i);
        return &self.entries.items[i];
    }

    fn unlink(self: *Table, i: u32) void {
        const items = self.entries.items;
        const e = &items[i];
        if (e.newer != none) items[e.newer].older = e.older else self.newest = e.older;
        if (e.older != none) items[e.older].newer = e.newer else self.oldest = e.newer;
        e.newer = none;
        e.older = none;
    }

    fn pushNewest(self: *Table, i: u32) void {
        const items = self.entries.items;
        items[i].older = self.newest;
        items[i].newer = none;
        if (self.newest != none) items[self.newest].newer = i else self.oldest = i;
        self.newest = i;
    }
};

test "a window admits the limit, then drops until the next second" {
    var w: Window = .{};
    const t0: i96 = 5 * std.time.ns_per_s;
    try std.testing.expect(w.admitAt(t0, 2));
    try std.testing.expect(w.admitAt(t0 + 10, 2));
    try std.testing.expect(!w.admitAt(t0 + 20, 2));
    try std.testing.expect(!w.admitAt(t0 + std.time.ns_per_s - 1, 2));
    // A new window starts one second after the first event.
    try std.testing.expect(w.admitAt(t0 + std.time.ns_per_s, 2));
    try std.testing.expect(w.admitAt(t0 + std.time.ns_per_s + 1, 2));
    try std.testing.expect(!w.admitAt(t0 + std.time.ns_per_s + 2, 2));
}

test "a limit of zero drops every event" {
    var w: Window = .{};
    try std.testing.expect(!w.admitAt(0, 0));
    try std.testing.expect(!w.admitAt(2 * std.time.ns_per_s, 0));
}

test "a token bucket admits the burst, then one event for each refill interval" {
    const ms = std.time.ns_per_ms;
    // 10 tokens per second: one token each 100 ms, at most 3 tokens.
    const rate: Rate = .{ .count = 10, .burst = 3 };
    const t0: i96 = 7 * std.time.ns_per_s;
    var b: Bucket = .full(rate, t0);
    for (0..3) |_| try std.testing.expectEqual(0, b.take(rate, t0));
    // The bucket is empty. The next token comes after 100 ms.
    try std.testing.expectEqual(100 * ms, b.take(rate, t0));
    try std.testing.expectEqual(60 * ms, b.take(rate, t0 + 40 * ms));
    try std.testing.expectEqual(0, b.take(rate, t0 + 100 * ms));
    try std.testing.expectEqual(100 * ms, b.take(rate, t0 + 100 * ms));
    // After a long pause, the bucket holds only the burst.
    const later = t0 + 3600 * std.time.ns_per_s;
    for (0..3) |_| try std.testing.expectEqual(0, b.take(rate, later));
    try std.testing.expect(b.take(rate, later) > 0);
    // A clock that goes back adds nothing.
    try std.testing.expect(b.take(rate, t0) > 0);
}

test "a token bucket with a long period and a token that comes back" {
    // 2 tokens per minute: one token each 30 s.
    const rate: Rate = .{ .count = 2, .period = .fromSeconds(60) };
    var b: Bucket = .full(rate, 0);
    try std.testing.expectEqual(0, b.take(rate, 0));
    try std.testing.expectEqual(0, b.take(rate, 0));
    try std.testing.expectEqual(30 * std.time.ns_per_s, b.take(rate, 0));
    b.giveBack(rate);
    try std.testing.expectEqual(0, b.take(rate, 0));
    // A rate of zero admits every event.
    var off: Bucket = .full(.{}, 0);
    for (0..100) |_| try std.testing.expectEqual(0, off.take(.{}, 0));
    // Large values do not overflow.
    const huge: Rate = .{ .count = std.math.maxInt(u32), .period = .{ .nanoseconds = std.math.maxInt(i96) } };
    var h: Bucket = .full(huge, 0);
    try std.testing.expectEqual(0, h.take(huge, std.math.maxInt(i96)));
}

test "the caller table forgets the caller that it used least recently" {
    const gpa = std.testing.allocator;
    const rate: Rate = .{ .count = 1, .period = .fromSeconds(60) };
    var t: Table = .init(2);
    defer t.deinit(gpa);
    const a: Key = @splat('a');
    const b: Key = @splat('b');
    const c: Key = @splat('c');
    try std.testing.expectEqual(0, (try t.get(gpa, a, rate, 0)).bucket.take(rate, 0));
    try std.testing.expectEqual(0, (try t.get(gpa, b, rate, 0)).bucket.take(rate, 0));
    // A use of `a` makes `b` the oldest caller. A third caller replaces `b`.
    try std.testing.expect((try t.get(gpa, a, rate, 0)).bucket.take(rate, 0) > 0);
    try std.testing.expectEqual(0, (try t.get(gpa, c, rate, 0)).bucket.take(rate, 0));
    try std.testing.expectEqual(2, t.count());
    try std.testing.expect(t.contains(a) and t.contains(c) and !t.contains(b));
    try std.testing.expectEqual(1, t.forgotten);
    // The caller `b` comes back with a full bucket and replaces `a`.
    try std.testing.expectEqual(0, (try t.get(gpa, b, rate, 0)).bucket.take(rate, 0));
    try std.testing.expect(t.contains(b) and t.contains(c) and !t.contains(a));
    // Many callers never make the table grow over its limit.
    for (0..1000) |i| {
        var k: Key = @splat(0);
        std.mem.writeInt(u64, k[0..8], i, .little);
        _ = try t.get(gpa, k, rate, 0);
    }
    try std.testing.expectEqual(2, t.count());
    try std.testing.expectEqual(2, t.entries.items.len);
}
