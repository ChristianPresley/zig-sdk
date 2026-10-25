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

const ListCache = @This();

/// The count of views of a list.
pub const views = 2;

/// The version of the list. It changes at each change of the list.
version: std.atomic.Value(u64) = .init(1),
lock: Io.Mutex = .init,
slots: [views]Slot = @splat(.{}),

const Slot = struct {
    version: u64 = 0,
    /// The JSON text, from the general-purpose allocator of the server.
    text: ?[]u8 = null,
};

pub fn deinit(self: *ListCache, gpa: Allocator) void {
    for (&self.slots) |*s| if (s.text) |t| gpa.free(t);
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
pub fn writeTo(self: *ListCache, io: Io, view: usize, w: *Io.Writer) Io.Writer.Error!bool {
    self.lock.lockUncancelable(io);
    defer self.lock.unlock(io);
    const slot = &self.slots[view];
    const text = slot.text orelse return false;
    if (slot.version != self.current()) return false;
    try w.writeAll(text);
    return true;
}

/// Keep a copy of `text` for `view`. The text is the list at `version`. The function does
/// nothing when the list changed after `version`.
pub fn put(self: *ListCache, io: Io, gpa: Allocator, view: usize, version: u64, text: []const u8) Allocator.Error!void {
    if (version != self.current()) return;
    const copy = try gpa.dupe(u8, text);
    var old: ?[]u8 = copy;
    {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        const slot = &self.slots[view];
        // A slot can only go to a newer version.
        if (version > slot.version or slot.text == null) {
            old = slot.text;
            slot.* = .{ .version = version, .text = copy };
        }
    }
    if (old) |o| gpa.free(o);
}

test "a slot is current until the list changes" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var cache: ListCache = .{};
    defer cache.deinit(gpa);
    var buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try std.testing.expect(!try cache.writeTo(io, 0, &w));

    const v = cache.current();
    try cache.put(io, gpa, 0, v, "{\"tools\":[]}");
    try std.testing.expect(try cache.writeTo(io, 0, &w));
    try std.testing.expectEqualStrings("{\"tools\":[]}", w.buffered());
    // The other view has its own slot.
    try std.testing.expect(!try cache.writeTo(io, 1, &w));

    // A change makes the slot stale. A text of the old version does not go in.
    cache.invalidate();
    try std.testing.expect(!try cache.writeTo(io, 0, &w));
    try cache.put(io, gpa, 0, v, "{\"tools\":[1]}");
    try std.testing.expect(!try cache.writeTo(io, 0, &w));
    try cache.put(io, gpa, 0, cache.current(), "{\"tools\":[2]}");
    w = .fixed(&buf);
    try std.testing.expect(try cache.writeTo(io, 0, &w));
    try std.testing.expectEqualStrings("{\"tools\":[2]}", w.buffered());
}
