//! A rate limit in windows of one second. The server limits the progress notifications that a
//! request sends, and the client limits the progress notifications that a request receives.
const std = @import("std");
const Io = std.Io;

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
