//! A cache of the serialized result of a list request. The server engine keeps the JSON text
//! of the first page of `tools/list` here. The next request then gets the same bytes without
//! a new serialization.
//!
//! The cache has one slot for each view of the list. For `tools/list`, a client of the MCP
//! Apps fallback gets a different view. Each slot has the version of the list that it holds.
//! A change of the list increments the version, and all slots become stale. A reader reads
//! the version before it reads the list. Thus a slot never holds an old list with a new
//! version.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const lockfree = @import("../util/lockfree.zig");

const ListCache = @This();

/// The count of views of a list.
pub const views = 2;

/// The version of the list. It changes at each change of the list.
version: std.atomic.Value(u64) = .init(1),
/// The text of each view. A newer text replaces the text of a slot with one atomic operation.
slots: [views]std.atomic.Value(?*Text) = @splat(.init(null)),
/// The texts that a newer text replaced. A reader can still copy one of them. The cache frees
/// them when no task reads. Thus the cache has no lock.
retired: lockfree.Retired(Text, "next") = .{},

/// The JSON text of one view at one version. The bytes follow the struct, from the
/// general-purpose allocator of the server.
const Text = struct {
    next: ?*Text = null,
    version: u64,
    len: usize,

    fn create(gpa: Allocator, version: u64, text: []const u8) Allocator.Error!*Text {
        const mem = try gpa.alignedAlloc(u8, .of(Text), @sizeOf(Text) + text.len);
        const t: *Text = @ptrCast(mem.ptr);
        t.* = .{ .version = version, .len = text.len };
        @memcpy(mem[@sizeOf(Text)..], text);
        return t;
    }

    fn bytes(t: *const Text) []const u8 {
        const base: [*]const u8 = @ptrCast(t);
        return base[@sizeOf(Text)..][0..t.len];
    }

    fn free(gpa: Allocator, t: *Text) void {
        const base: [*]align(@alignOf(Text)) u8 = @ptrCast(t);
        gpa.free(base[0 .. @sizeOf(Text) + t.len]);
    }
};

pub fn deinit(self: *ListCache, gpa: Allocator) void {
    for (&self.slots) |*s| if (s.load(.acquire)) |t| Text.free(gpa, t);
    self.retired.deinit(gpa, Text.free);
    self.* = undefined;
}

/// Make all slots stale. Call this function after each change of the list.
pub fn invalidate(self: *ListCache) void {
    _ = self.version.fetchAdd(1, .acq_rel);
}

/// The version of the list now. Read it before the list, and give it to `put`.
pub fn current(self: *const ListCache) u64 {
    return self.version.load(.acquire);
}

/// Write the text of `view` to `w` when the slot has the current version. Returns false when
/// the slot is stale or empty, and then writes nothing.
pub fn writeTo(self: *ListCache, gpa: Allocator, view: usize, w: *Io.Writer) Io.Writer.Error!bool {
    self.retired.enter();
    defer self.retired.leave(gpa, Text.free);
    const text = self.slots[view].load(.seq_cst) orelse return false;
    if (text.version != self.current()) return false;
    try w.writeAll(text.bytes());
    return true;
}

/// Keep a copy of `text` for `view`. The text is the list at `version`. The function does
/// nothing when the list changed after `version`.
pub fn put(self: *ListCache, gpa: Allocator, view: usize, version: u64, text: []const u8) Allocator.Error!void {
    if (version != self.current()) return;
    const fresh = try Text.create(gpa, version, text);
    const slot = &self.slots[view];
    // The loop reads the version of the old text, thus it counts as a reader.
    self.retired.enter();
    defer self.retired.leave(gpa, Text.free);
    var old = slot.load(.seq_cst);
    while (true) {
        // A slot can only go to a newer version.
        if (old) |o| if (version <= o.version) {
            Text.free(gpa, fresh);
            return;
        };
        old = slot.cmpxchgWeak(old, fresh, .seq_cst, .seq_cst) orelse break;
    }
    if (old) |o| self.retired.retire(o, gpa, Text.free);
}

test "a slot is current until the list changes" {
    const gpa = std.testing.allocator;
    var cache: ListCache = .{};
    defer cache.deinit(gpa);
    var buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try std.testing.expect(!try cache.writeTo(gpa, 0, &w));

    const v = cache.current();
    try cache.put(gpa, 0, v, "{\"tools\":[]}");
    try std.testing.expect(try cache.writeTo(gpa, 0, &w));
    try std.testing.expectEqualStrings("{\"tools\":[]}", w.buffered());
    // The other view has its own slot.
    try std.testing.expect(!try cache.writeTo(gpa, 1, &w));

    // A change makes the slot stale. A text of the old version does not go in.
    cache.invalidate();
    try std.testing.expect(!try cache.writeTo(gpa, 0, &w));
    try cache.put(gpa, 0, v, "{\"tools\":[1]}");
    try std.testing.expect(!try cache.writeTo(gpa, 0, &w));
    try cache.put(gpa, 0, cache.current(), "{\"tools\":[2]}");
    w = .fixed(&buf);
    try std.testing.expect(try cache.writeTo(gpa, 0, &w));
    try std.testing.expectEqualStrings("{\"tools\":[2]}", w.buffered());
}
