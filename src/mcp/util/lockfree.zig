//! Lock-free queues for the gRPC transport. No operation waits for another task: a task that
//! loses a race tries again with the new state.
const std = @import("std");

/// A stack of items with the link `field`. Many tasks push. One task at a time takes all the
/// items at once. No task removes one item, thus an item that a task pushes again cannot
/// confuse a removal.
pub fn Stack(comptime T: type, comptime field: []const u8) type {
    return struct {
        head: std.atomic.Value(?*T) = .init(null),

        const Self = @This();

        pub fn push(self: *Self, item: *T) void {
            var head = self.head.load(.monotonic);
            while (true) {
                @field(item, field) = head;
                head = self.head.cmpxchgWeak(head, item, .seq_cst, .monotonic) orelse return;
            }
        }

        /// Take all items, the newest first.
        pub fn takeAll(self: *Self) ?*T {
            if (self.head.load(.seq_cst) == null) return null;
            return self.head.swap(null, .seq_cst);
        }

        /// Take all items, the oldest first.
        pub fn takeAllInOrder(self: *Self) ?*T {
            var newest_first = self.takeAll() orelse return null;
            var oldest_first: ?*T = null;
            while (true) {
                const next = @field(newest_first, field);
                @field(newest_first, field) = oldest_first;
                oldest_first = newest_first;
                newest_first = next orelse return oldest_first;
            }
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head.load(.seq_cst) == null;
        }
    };
}

/// A bounded queue of pointers for many producers and many consumers (the algorithm of
/// Dmitry Vyukov). Each cell has a sequence number that tells if the cell is free or full for
/// the position of a task. A full queue refuses a push.
pub fn Ring(comptime T: type, comptime capacity: usize) type {
    std.debug.assert(std.math.isPowerOfTwo(capacity));
    return struct {
        cells: [capacity]Cell = init: {
            @setEvalBranchQuota(capacity * 8 + 1000);
            var cells: [capacity]Cell = undefined;
            for (&cells, 0..) |*c, i| c.* = .{ .seq = .init(i), .item = null };
            break :init cells;
        },
        head: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),
        tail: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),

        const Self = @This();
        const mask = capacity - 1;
        const Cell = struct {
            seq: std.atomic.Value(usize),
            item: ?*T,
        };

        /// Add `item` at the end. False when the queue is full.
        pub fn push(self: *Self, item: *T) bool {
            var pos = self.tail.load(.monotonic);
            while (true) {
                const cell = &self.cells[pos & mask];
                const seq = cell.seq.load(.acquire);
                const dif = @as(isize, @bitCast(seq -% pos));
                if (dif == 0) {
                    pos = self.tail.cmpxchgWeak(pos, pos +% 1, .seq_cst, .monotonic) orelse {
                        cell.item = item;
                        cell.seq.store(pos +% 1, .seq_cst);
                        return true;
                    };
                } else if (dif < 0) {
                    return false;
                } else {
                    pos = self.tail.load(.monotonic);
                }
            }
        }

        /// Take the first item, or null when the queue is empty.
        pub fn pop(self: *Self) ?*T {
            var pos = self.head.load(.monotonic);
            while (true) {
                const cell = &self.cells[pos & mask];
                const seq = cell.seq.load(.acquire);
                const dif = @as(isize, @bitCast(seq -% (pos +% 1)));
                if (dif == 0) {
                    pos = self.head.cmpxchgWeak(pos, pos +% 1, .seq_cst, .monotonic) orelse {
                        const item = cell.item;
                        cell.seq.store(pos +% mask +% 1, .seq_cst);
                        return item;
                    };
                } else if (dif < 0) {
                    return null;
                } else {
                    pos = self.head.load(.monotonic);
                }
            }
        }

        /// The queue has an item, or a push of an item is under way.
        pub fn hasItems(self: *const Self) bool {
            return self.tail.load(.seq_cst) != self.head.load(.seq_cst);
        }
    };
}

/// A fixed set of places for free objects of type `T`. A task takes an object from a place, or
/// puts an object back in a free place. Each place changes with one atomic operation, thus a
/// task never sees an object twice.
pub fn Pool(comptime T: type, comptime places: usize) type {
    return struct {
        items: [places]std.atomic.Value(?*T) = @splat(.init(null)),

        const Self = @This();

        /// An object from the pool, or null when the pool is empty.
        pub fn take(self: *Self) ?*T {
            for (&self.items) |*place| {
                if (place.load(.monotonic) == null) continue;
                if (place.swap(null, .acquire)) |item| return item;
            }
            return null;
        }

        /// Keep `item`. False when the pool is full: the caller then frees the object.
        pub fn put(self: *Self, item: *T) bool {
            for (&self.items) |*place| {
                if (place.load(.monotonic) != null) continue;
                if (place.cmpxchgStrong(null, item, .release, .monotonic) == null) return true;
            }
            return false;
        }
    };
}

/// The objects that left a shared place, for example an entry of a cache that a newer entry
/// replaced. A task that reads the places counts itself with `enter` and `leave`. The objects
/// go to `free` only when no task reads. A task that reads now can hold one of them: it found
/// the object in its place before the object left. Thus a task can take a reference to an
/// object that it found.
pub fn Retired(comptime T: type, comptime field: []const u8) type {
    return struct {
        readers: std.atomic.Value(u32) = .init(0),
        list: Stack(T, field) = .{},

        const Self = @This();

        pub fn enter(self: *Self) void {
            _ = self.readers.fetchAdd(1, .seq_cst);
        }

        pub fn leave(self: *Self, context: anytype, comptime free: fn (@TypeOf(context), *T) void) void {
            if (self.readers.fetchSub(1, .seq_cst) == 1) self.reclaim(context, free);
        }

        /// `item` left its place. It goes to `free` when no task reads the places.
        pub fn retire(self: *Self, item: *T, context: anytype, comptime free: fn (@TypeOf(context), *T) void) void {
            self.list.push(item);
            self.enter();
            self.leave(context, free);
        }

        fn reclaim(self: *Self, context: anytype, comptime free: fn (@TypeOf(context), *T) void) void {
            var list = self.list.takeAll() orelse return;
            // The objects left their places before this check. A task that reads now entered
            // before that, thus it can have one of them.
            const keep = self.readers.load(.seq_cst) != 0;
            while (true) {
                const next = @field(list, field);
                if (keep) self.list.push(list) else free(context, list);
                list = next orelse return;
            }
        }

        /// Free each object. No task reads the places now.
        pub fn deinit(self: *Self, context: anytype, comptime free: fn (@TypeOf(context), *T) void) void {
            var list = self.list.takeAll();
            while (list) |item| {
                list = @field(item, field);
                free(context, item);
            }
        }
    };
}

/// A count of permits. A task takes a permit and waits while the count is zero. Any task gives
/// a permit back. The count and the wait use one atomic word, without a lock.
pub const Permits = struct {
    count: std.atomic.Value(u32),
    waiters: std.atomic.Value(u32) = .init(0),

    pub fn init(count: u32) Permits {
        return .{ .count = .init(count) };
    }

    /// Take a permit. Wait while the count is zero.
    pub fn take(self: *Permits, io: std.Io) void {
        while (true) {
            var n = self.count.load(.seq_cst);
            while (n > 0) n = self.count.cmpxchgWeak(n, n - 1, .seq_cst, .seq_cst) orelse return;
            _ = self.waiters.fetchAdd(1, .seq_cst);
            defer _ = self.waiters.fetchSub(1, .seq_cst);
            io.futexWaitUncancelable(u32, &self.count.raw, 0);
        }
    }

    /// Give a permit back.
    pub fn give(self: *Permits, io: std.Io) void {
        _ = self.count.fetchAdd(1, .seq_cst);
        if (self.waiters.load(.seq_cst) != 0) io.futexWake(u32, &self.count.raw, 1);
    }
};

test "the ring keeps the order and refuses a push when it is full" {
    const Item = struct { n: usize };
    var items: [5]Item = undefined;
    for (&items, 0..) |*it, i| it.* = .{ .n = i };
    var ring: Ring(Item, 4) = .{};
    try std.testing.expect(!ring.hasItems());
    for (items[0..4]) |*it| try std.testing.expect(ring.push(it));
    try std.testing.expect(!ring.push(&items[4]));
    for (0..4) |i| try std.testing.expectEqual(i, ring.pop().?.n);
    try std.testing.expect(ring.pop() == null);
    // The positions wrap around.
    for (0..10) |i| {
        try std.testing.expect(ring.push(&items[i % 5]));
        try std.testing.expectEqual(i % 5, ring.pop().?.n);
    }
}

test "many tasks push and pop each item once" {
    const io = std.testing.io;
    const Item = struct { n: usize, seen: std.atomic.Value(u32) = .init(0) };
    const count = 4000;
    const items = try std.testing.allocator.alloc(Item, count);
    defer std.testing.allocator.free(items);
    for (items, 0..) |*it, i| it.* = .{ .n = i };
    const R = Ring(Item, 64);
    var ring: R = .{};
    var popped: std.atomic.Value(usize) = .init(0);
    const Worker = struct {
        fn produce(r: *R, slice: []Item) void {
            for (slice) |*it| while (!r.push(it)) std.atomic.spinLoopHint();
        }
        fn consume(r: *R, done: *std.atomic.Value(usize)) void {
            while (done.load(.acquire) < count) {
                const it = r.pop() orelse continue;
                _ = it.seen.fetchAdd(1, .monotonic);
                _ = done.fetchAdd(1, .acq_rel);
            }
        }
    };
    var group: std.Io.Group = .init;
    for (0..4) |i| try group.concurrent(io, Worker.produce, .{ &ring, items[i * 1000 ..][0..1000] });
    for (0..3) |_| try group.concurrent(io, Worker.consume, .{ &ring, &popped });
    try group.await(io);
    for (items) |*it| try std.testing.expectEqual(1, it.seen.load(.monotonic));
}

test "the stack gives the items in order and the pool gives each object once" {
    const Node = struct { next: ?*@This() = null, n: usize };
    var nodes: [3]Node = .{ .{ .n = 0 }, .{ .n = 1 }, .{ .n = 2 } };
    var stack: Stack(Node, "next") = .{};
    for (&nodes) |*n| stack.push(n);
    var it = stack.takeAllInOrder();
    var i: usize = 0;
    while (it) |n| : (it = n.next) {
        try std.testing.expectEqual(i, n.n);
        i += 1;
    }
    try std.testing.expectEqual(3, i);
    try std.testing.expect(stack.isEmpty());

    var pool: Pool(Node, 2) = .{};
    try std.testing.expect(pool.put(&nodes[0]));
    try std.testing.expect(pool.put(&nodes[1]));
    try std.testing.expect(!pool.put(&nodes[2]));
    const a = pool.take().?;
    const b = pool.take().?;
    try std.testing.expect(a != b);
    try std.testing.expect(pool.take() == null);
}

test "a retired object waits for the readers that entered before it left" {
    const Obj = struct { next: ?*@This() = null, freed: bool = false };
    var retired: Retired(Obj, "next") = .{};
    var obj: Obj = .{};
    const Free = struct {
        fn free(_: void, o: *Obj) void {
            o.freed = true;
        }
    };
    retired.enter();
    retired.retire(&obj, {}, Free.free);
    try std.testing.expect(!obj.freed);
    retired.leave({}, Free.free);
    try std.testing.expect(obj.freed);
}

test "permits count down and a give wakes the task that waits" {
    const io = std.testing.io;
    var permits: Permits = .init(1);
    permits.take(io);
    const Giver = struct {
        fn run(p: *Permits) void {
            std.testing.io.sleep(.fromMilliseconds(20), .awake) catch {};
            p.give(std.testing.io);
        }
    };
    var giver = try io.concurrent(Giver.run, .{&permits});
    permits.take(io);
    giver.await(io);
    try std.testing.expectEqual(0, permits.count.load(.seq_cst));
}
