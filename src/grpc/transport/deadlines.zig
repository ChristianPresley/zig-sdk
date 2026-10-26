//! The `grpc-timeout` of the calls of a server. One task cancels each call at its deadline.
//! Before, each call with a deadline started its own task, which slept until the deadline. The
//! end of the call then canceled that task. That task cost a thread of the pool, a wake-up and
//! a cancel for each call, also when the call ended in time.
//!
//! No task holds a lock. A call puts its entry in a lock-free queue, and puts it in a second
//! queue at its end. Only the task of the deadlines uses the list of entries, sorted by
//! deadline. A client usually gives each call the same timeout. Thus a new entry goes at the
//! end of the list, and the task does not wake for it. The task wakes for the entries of ended
//! calls after `ends_per_wake` of them, to free their memory.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("mcp").transport.Transport;
const Stack = @import("mcp").util.lockfree.Stack;

const Deadlines = @This();

/// The new entries, for the task.
inbox: Stack(Entry, "next_in") = .{},
/// The entries of the calls that ended, for the task.
ended: Stack(Entry, "next_ended") = .{},
/// The count of `ended` since the last wake of the task.
ended_count: std.atomic.Value(u32) = .init(0),
/// Changes when the task must wake: for an earlier deadline, for the ended entries or for the
/// stop. The task waits on it.
epoch: std.atomic.Value(u32) = .init(0),
/// The awake time in nanoseconds when the task wakes by itself. A deadline at that time or
/// later does not wake the task. The maximum value: the task waits for `epoch` only.
wakes_at: std.atomic.Value(i64) = .init(std.math.maxInt(i64)),
state: std.atomic.Value(State) = .init(.idle),
/// The task. Valid in the states `running` and `stopping`.
task: ?Io.Future(void) = null,
/// The allocator of the entries. Valid in the states `running` and `stopping`.
gpa: Allocator = undefined,
/// The sorted list of the entries. Only the task uses the fields.
head: ?*Entry = null,
tail: ?*Entry = null,

const State = enum(u32) {
    /// No call had a deadline yet.
    idle,
    /// The first call with a deadline starts the task.
    starting,
    running,
    /// The task could not start. The calls then start their own tasks, as before.
    unavailable,
    stopping,
};

/// The task wakes after this many ended calls to free their entries.
pub const ends_per_wake = 256;

/// One call with a deadline. The call and the task each have a reference. The last release
/// frees the entry.
pub const Entry = struct {
    at: Io.Clock.Timestamp,
    token: *Transport.CancelToken,
    /// Set before the cancel when the deadline passed.
    hit: *std.atomic.Value(bool),
    status: std.atomic.Value(Status) = .init(.active),
    refs: std.atomic.Value(u32) = .init(2),
    next_in: ?*Entry = null,
    next_ended: ?*Entry = null,
    /// The links of the sorted list. Only the task uses them.
    prev: ?*Entry = null,
    next: ?*Entry = null,
    in_list: bool = false,

    const Status = enum(u32) { active, ended, firing, fired };

    fn release(e: *Entry, gpa: Allocator) void {
        if (e.refs.fetchSub(1, .acq_rel) == 1) gpa.destroy(e);
    }

    fn ns(e: *const Entry) i64 {
        return @intCast(e.at.raw.nanoseconds);
    }
};

/// The deadline of one call. The owner keeps it in place from `start` to `finish`.
pub const Watch = struct {
    entry: ?*Entry = null,
    /// The task of the call when the task of the server cannot run.
    future: ?Io.Future(void) = null,

    /// Cancel `token` after `duration`, and set `hit` before the cancel.
    pub fn start(w: *Watch, d: *Deadlines, io: Io, gpa: Allocator, duration: Io.Duration, token: *Transport.CancelToken, hit: *std.atomic.Value(bool)) void {
        if (d.add(io, gpa, duration, token, hit)) |e| {
            w.entry = e;
            return;
        }
        w.future = io.concurrent(sleepThenCancel, .{ io, duration, token, hit }) catch null;
    }

    /// The call ended. After this call the deadline does not cancel the token.
    pub fn finish(w: *Watch, d: *Deadlines, io: Io) void {
        if (w.entry) |e| d.end(io, e);
        w.entry = null;
        if (w.future) |*f| _ = f.cancel(io);
        w.future = null;
    }

    fn sleepThenCancel(io: Io, duration: Io.Duration, token: *Transport.CancelToken, hit: *std.atomic.Value(bool)) void {
        io.sleep(duration, .awake) catch return;
        hit.store(true, .release);
        token.cancel(io, "deadline exceeded");
    }
};

/// Start the task at the first call. False when the task does not run: the caller then
/// watches the deadline itself.
fn ensureTask(self: *Deadlines, io: Io, gpa: Allocator) bool {
    switch (self.state.load(.acquire)) {
        .running => return true,
        .starting, .unavailable, .stopping => return false,
        .idle => {},
    }
    if (self.state.cmpxchgStrong(.idle, .starting, .acq_rel, .acquire) != null) return self.state.load(.acquire) == .running;
    self.gpa = gpa;
    self.task = io.concurrent(run, .{ self, io }) catch {
        self.state.store(.unavailable, .release);
        return false;
    };
    if (self.state.cmpxchgStrong(.starting, .running, .acq_rel, .acquire) != null) {
        // A stop came meanwhile. The stop leaves the task to this call.
        self.wake(io);
        var f = self.task.?;
        self.task = null;
        f.await(io);
        return false;
    }
    return true;
}

/// Add an entry for a call. Null when the task cannot run.
fn add(self: *Deadlines, io: Io, gpa: Allocator, duration: Io.Duration, token: *Transport.CancelToken, hit: *std.atomic.Value(bool)) ?*Entry {
    if (!self.ensureTask(io, gpa)) return null;
    const e = gpa.create(Entry) catch return null;
    e.* = .{ .at = .fromNow(io, .{ .raw = duration, .clock = .awake }), .token = token, .hit = hit };
    self.inbox.push(e);
    // The task reads the queue before it sleeps, and it sleeps until `wakes_at` at most.
    if (e.ns() < self.wakes_at.load(.seq_cst)) self.wake(io);
    return e;
}

/// The call of `e` ended. After this call the task does not cancel the token.
fn end(self: *Deadlines, io: Io, e: *Entry) void {
    if (e.status.cmpxchgStrong(.active, .ended, .seq_cst, .seq_cst)) |_| {
        // The deadline passed, and the task cancels the token now. The token belongs to the
        // caller, thus wait for the end of the cancel. The cancel takes no lock.
        while (e.status.load(.seq_cst) == .firing) io.futexWaitUncancelable(Entry.Status, &e.status.raw, .firing);
        e.release(self.gpa);
        return;
    }
    // The reference of the caller goes to the queue.
    self.ended.push(e);
    if (self.ended_count.fetchAdd(1, .monotonic) + 1 == ends_per_wake) self.wake(io);
}

/// Stop the task. Call after the last call ended.
pub fn stop(self: *Deadlines, io: Io) void {
    const old = self.state.swap(.stopping, .acq_rel);
    // A start that did not end yet sees the stop and stops the task.
    if (old != .running) return;
    self.wake(io);
    var f = self.task.?;
    self.task = null;
    f.await(io);
}

fn wake(self: *Deadlines, io: Io) void {
    _ = self.epoch.fetchAdd(1, .seq_cst);
    io.futexWake(u32, &self.epoch.raw, 1);
}

fn insert(self: *Deadlines, entry: *Entry) void {
    // Find the place from the end: usually the new deadline is the latest.
    var after = self.tail;
    while (after) |a| : (after = a.prev) {
        if (a.at.compare(.lte, entry.at)) break;
    }
    entry.prev = after;
    entry.next = if (after) |a| a.next else self.head;
    if (entry.next) |n| n.prev = entry else self.tail = entry;
    if (after) |a| a.next = entry else self.head = entry;
    entry.in_list = true;
}

fn unlink(self: *Deadlines, entry: *Entry) void {
    if (!entry.in_list) return;
    if (entry.prev) |p| p.next = entry.next else self.head = entry.next;
    if (entry.next) |n| n.prev = entry.prev else self.tail = entry.prev;
    entry.prev = null;
    entry.next = null;
    entry.in_list = false;
    // The reference of the task.
    entry.release(self.gpa);
}

/// Take the changes of the calls. Only the task calls this function.
fn sync(self: *Deadlines) void {
    // First the ended entries, then the new entries. An entry is in `inbox` before it is in
    // `ended`, thus this pass sees the new entry of each ended entry that it takes.
    var ended = self.ended.takeAll();
    self.ended_count.store(0, .monotonic);
    var new = self.inbox.takeAll();
    while (new) |e| {
        new = e.next_in;
        if (e.status.load(.seq_cst) == .active) {
            self.insert(e);
        } else {
            // The call ended already: the reference of the task goes now.
            e.release(self.gpa);
        }
    }
    while (ended) |e| {
        ended = e.next_ended;
        self.unlink(e);
        // The reference of the caller.
        e.release(self.gpa);
    }
}

fn run(self: *Deadlines, io: Io) void {
    while (true) {
        const seen = self.epoch.load(.seq_cst);
        self.sync();
        if (self.state.load(.acquire) == .stopping) break;
        const now = Io.Clock.Timestamp.now(io, .awake);
        while (self.head) |first| {
            if (first.at.compare(.gt, now)) break;
            if (first.status.cmpxchgStrong(.active, .firing, .seq_cst, .seq_cst) == null) {
                first.hit.store(true, .release);
                first.token.cancel(io, "deadline exceeded");
                first.status.store(.fired, .seq_cst);
                io.futexWake(Entry.Status, &first.status.raw, std.math.maxInt(u32));
            }
            self.unlink(first);
        }
        const at: ?Io.Clock.Timestamp = if (self.head) |first| first.at else null;
        self.wakes_at.store(if (self.head) |first| first.ns() else std.math.maxInt(i64), .seq_cst);
        // An entry that came before the store above did not wake the task.
        if (!self.inbox.isEmpty()) continue;
        if (at) |deadline| {
            io.futexWaitTimeout(u32, &self.epoch.raw, seen, .{ .deadline = deadline }) catch {};
        } else {
            io.futexWait(u32, &self.epoch.raw, seen) catch {};
        }
    }
    // The stop comes after the last call: free the entries.
    self.sync();
    while (self.head) |first| self.unlink(first);
}

test "the task cancels at the deadline only the calls that did not end" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var d: Deadlines = .{};
    defer d.stop(io);
    var tokens: [3]Transport.CancelToken = .{ .{}, .{}, .{} };
    var hits: [3]std.atomic.Value(bool) = .{ .init(false), .init(false), .init(false) };
    var watches: [3]Watch = .{ .{}, .{}, .{} };
    const delays = [_]i64{ 50, 20, 5000 };
    for (&watches, &tokens, &hits, delays) |*w, *t, *h, ms| {
        w.start(&d, io, gpa, .fromMilliseconds(ms), t, h);
        try std.testing.expect(w.entry != null);
    }
    // The call of watch 0 ends in time.
    watches[0].finish(&d, io);
    try io.sleep(.fromMilliseconds(200), .awake);
    try std.testing.expect(!tokens[0].isCancelled());
    try std.testing.expect(!hits[0].load(.acquire));
    try std.testing.expect(tokens[1].isCancelled());
    try std.testing.expect(hits[1].load(.acquire));
    try std.testing.expect(!tokens[2].isCancelled());
    watches[1].finish(&d, io);
    watches[2].finish(&d, io);
}

test "many calls end in time while other calls pass their deadlines" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var d: Deadlines = .{};
    defer d.stop(io);
    const Call = struct {
        token: Transport.CancelToken = .{},
        hit: std.atomic.Value(bool) = .init(false),
        watch: Watch = .{},
    };
    const Runner = struct {
        fn run(dl: *Deadlines, calls: []Call, short: bool) void {
            for (calls) |*c| {
                c.watch.start(dl, std.testing.io, std.testing.allocator, if (short) .fromMicroseconds(1) else .fromSeconds(60), &c.token, &c.hit);
                if (short) std.testing.io.sleep(.fromMicroseconds(50), .awake) catch {};
                c.watch.finish(dl, std.testing.io);
            }
        }
    };
    const calls = try gpa.alloc(Call, 4 * 1000);
    defer gpa.free(calls);
    for (calls) |*c| c.* = .{};
    var group: Io.Group = .init;
    for (0..4) |i| try group.concurrent(io, Runner.run, .{ &d, calls[i * 1000 ..][0..1000], i == 0 });
    try group.await(io);
    for (calls[1000..]) |*c| try std.testing.expect(!c.token.isCancelled());
}
