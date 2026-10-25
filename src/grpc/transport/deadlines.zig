//! The `grpc-timeout` of the calls of a server. One task cancels each call at its deadline.
//! Before, each call with a deadline started its own task, which slept until the deadline. The
//! end of the call then canceled that task. That task cost a thread of the pool, a wake-up and
//! a cancel for each call, also when the call ended in time.
//!
//! The calls wait in a list sorted by deadline. A client usually gives each call the same
//! timeout. Thus a new call goes at the end of the list, and the task does not wake.
const std = @import("std");
const Io = std.Io;
const Transport = @import("mcp").transport.Transport;

const Deadlines = @This();

lock: Io.Mutex = .init,
head: ?*Entry = null,
tail: ?*Entry = null,
/// Changes when the task must wake: for an earlier deadline or for the stop. The task waits on it.
epoch: std.atomic.Value(u32) = .init(0),
/// The time when the task wakes by itself, or null when it waits for `epoch` only. A deadline
/// at that time or later does not wake the task.
wakes_at: ?Io.Clock.Timestamp = null,
task: ?Io.Future(void) = null,
/// The task could not start. The calls then start their own tasks, as before.
unavailable: bool = false,
stopping: bool = false,

/// One call with a deadline. The owner keeps it in place from `add` to `remove`.
pub const Entry = struct {
    at: Io.Clock.Timestamp,
    token: *Transport.CancelToken,
    /// Set before the cancel when the deadline passed.
    hit: *std.atomic.Value(bool),
    prev: ?*Entry = null,
    next: ?*Entry = null,
    queued: bool = false,
};

/// The deadline of one call. The owner keeps it in place from `start` to `finish`.
pub const Watch = struct {
    entry: Entry = undefined,
    queued: bool = false,
    /// The task of the call when the task of the server cannot run.
    future: ?Io.Future(void) = null,

    /// Cancel `token` after `duration`, and set `hit` before the cancel.
    pub fn start(w: *Watch, d: *Deadlines, io: Io, duration: Io.Duration, token: *Transport.CancelToken, hit: *std.atomic.Value(bool)) void {
        w.entry = .{ .at = .fromNow(io, .{ .raw = duration, .clock = .awake }), .token = token, .hit = hit };
        if (d.add(io, &w.entry)) {
            w.queued = true;
            return;
        }
        w.future = io.concurrent(sleepThenCancel, .{ io, duration, token, hit }) catch null;
    }

    /// The call ended. After this call the deadline does not cancel the token.
    pub fn finish(w: *Watch, d: *Deadlines, io: Io) void {
        if (w.queued) d.remove(io, &w.entry);
        w.queued = false;
        if (w.future) |*f| _ = f.cancel(io);
        w.future = null;
    }

    fn sleepThenCancel(io: Io, duration: Io.Duration, token: *Transport.CancelToken, hit: *std.atomic.Value(bool)) void {
        io.sleep(duration, .awake) catch return;
        hit.store(true, .release);
        token.cancel(io, "deadline exceeded");
    }
};

/// Add `entry`. False when the task cannot run: the caller then watches the deadline itself.
pub fn add(self: *Deadlines, io: Io, entry: *Entry) bool {
    self.lock.lockUncancelable(io);
    defer self.lock.unlock(io);
    if (self.stopping or self.unavailable) return false;
    if (self.task == null) {
        self.task = io.concurrent(run, .{ self, io }) catch {
            self.unavailable = true;
            return false;
        };
    }
    // Find the place from the end: usually the new deadline is the latest.
    var after = self.tail;
    while (after) |a| : (after = a.prev) {
        if (a.at.compare(.lte, entry.at)) break;
    }
    entry.prev = after;
    entry.next = if (after) |a| a.next else self.head;
    if (entry.next) |n| n.prev = entry else self.tail = entry;
    if (after) |a| a.next = entry else self.head = entry;
    entry.queued = true;
    if (self.head == entry) {
        if (self.wakes_at) |w| {
            if (w.compare(.lte, entry.at)) return true;
        }
        self.wakeLocked(io);
    }
    return true;
}

/// Remove `entry` at the end of its call. After this call the task does not touch it.
pub fn remove(self: *Deadlines, io: Io, entry: *Entry) void {
    self.lock.lockUncancelable(io);
    defer self.lock.unlock(io);
    if (!entry.queued) return;
    self.unlinkLocked(entry);
}

/// Stop the task. Call after the last call ended.
pub fn stop(self: *Deadlines, io: Io) void {
    self.lock.lockUncancelable(io);
    self.stopping = true;
    self.wakeLocked(io);
    const task = self.task;
    self.task = null;
    self.lock.unlock(io);
    if (task) |t| {
        var f = t;
        f.await(io);
    }
}

fn unlinkLocked(self: *Deadlines, entry: *Entry) void {
    if (entry.prev) |p| p.next = entry.next else self.head = entry.next;
    if (entry.next) |n| n.prev = entry.prev else self.tail = entry.prev;
    entry.prev = null;
    entry.next = null;
    entry.queued = false;
}

fn wakeLocked(self: *Deadlines, io: Io) void {
    _ = self.epoch.fetchAdd(1, .release);
    io.futexWake(u32, &self.epoch.raw, 1);
}

fn run(self: *Deadlines, io: Io) void {
    self.lock.lockUncancelable(io);
    while (!self.stopping) {
        const seen = self.epoch.load(.acquire);
        const first = self.head orelse {
            self.wakes_at = null;
            self.lock.unlock(io);
            io.futexWait(u32, &self.epoch.raw, seen) catch {};
            self.lock.lockUncancelable(io);
            continue;
        };
        if (first.at.compare(.lte, Io.Clock.Timestamp.now(io, first.at.clock))) {
            // The owner removes the entry under the same lock, thus it is still valid. The
            // cancel of the token takes no lock.
            self.unlinkLocked(first);
            first.hit.store(true, .release);
            first.token.cancel(io, "deadline exceeded");
            continue;
        }
        const at = first.at;
        self.wakes_at = at;
        self.lock.unlock(io);
        io.futexWaitTimeout(u32, &self.epoch.raw, seen, .{ .deadline = at }) catch {};
        self.lock.lockUncancelable(io);
        self.wakes_at = null;
    }
    self.lock.unlock(io);
}

test "the task cancels at the deadline only the calls that did not end" {
    const io = std.testing.io;
    var d: Deadlines = .{};
    defer d.stop(io);
    var tokens: [3]Transport.CancelToken = .{ .{}, .{}, .{} };
    var hits: [3]std.atomic.Value(bool) = .{ .init(false), .init(false), .init(false) };
    var entries: [3]Entry = undefined;
    const now = Io.Clock.Timestamp.now(io, .awake);
    const delays = [_]i64{ 50, 20, 5000 };
    for (&entries, &tokens, &hits, delays) |*e, *t, *h, ms| {
        e.* = .{ .at = now.addDuration(.{ .raw = .fromMilliseconds(ms), .clock = .awake }), .token = t, .hit = h };
        try std.testing.expect(d.add(io, e));
    }
    // The entry with the earliest deadline is the head, whatever the order of the adds.
    try std.testing.expectEqual(&entries[1], d.head.?);
    try std.testing.expectEqual(&entries[2], d.tail.?);
    // The call of entry 0 ends in time.
    d.remove(io, &entries[0]);
    try io.sleep(.fromMilliseconds(200), .awake);
    try std.testing.expect(!tokens[0].isCancelled());
    try std.testing.expect(!hits[0].load(.acquire));
    try std.testing.expect(tokens[1].isCancelled());
    try std.testing.expect(hits[1].load(.acquire));
    try std.testing.expect(!tokens[2].isCancelled());
    d.remove(io, &entries[1]);
    d.remove(io, &entries[2]);
    try std.testing.expect(d.head == null and d.tail == null);
}
