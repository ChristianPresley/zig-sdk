//! The `grpc-timeout` header: a positive integer of at most eight digits and a unit.
const std = @import("std");
const Io = std.Io;

pub const Error = error{InvalidTimeout};

/// Parse a header value into a duration.
pub fn parse(text: []const u8) Error!Io.Duration {
    if (text.len < 2 or text.len > 9) return error.InvalidTimeout;
    const digits = text[0 .. text.len - 1];
    for (digits) |c| if (!std.ascii.isDigit(c)) return error.InvalidTimeout;
    const value = std.fmt.parseInt(u64, digits, 10) catch return error.InvalidTimeout;
    const ns: u64 = switch (text[text.len - 1]) {
        'H' => value * std.time.ns_per_hour,
        'M' => value * std.time.ns_per_min,
        'S' => value * std.time.ns_per_s,
        'm' => value * std.time.ns_per_ms,
        'u' => value * std.time.ns_per_us,
        'n' => value,
        else => return error.InvalidTimeout,
    };
    return .{ .nanoseconds = @intCast(@min(ns, std.math.maxInt(i64))) };
}

/// Format a duration with the largest unit that represents it exactly within eight digits.
pub fn format(buf: *[9]u8, duration: Io.Duration) []const u8 {
    const ns: u64 = @intCast(@max(duration.nanoseconds, 0));
    const units = [_]struct { div: u64, suffix: u8 }{
        .{ .div = std.time.ns_per_hour, .suffix = 'H' },
        .{ .div = std.time.ns_per_min, .suffix = 'M' },
        .{ .div = std.time.ns_per_s, .suffix = 'S' },
        .{ .div = std.time.ns_per_ms, .suffix = 'm' },
        .{ .div = std.time.ns_per_us, .suffix = 'u' },
        .{ .div = 1, .suffix = 'n' },
    };
    // Exact first, then the smallest unit that fits (rounding up so the deadline never
    // comes early).
    for (units) |u| {
        if (ns % u.div == 0 and ns / u.div <= 99_999_999) {
            return std.fmt.bufPrint(buf, "{d}{c}", .{ ns / u.div, u.suffix }) catch unreachable;
        }
    }
    var i: usize = units.len;
    while (i > 0) {
        i -= 1;
        const u = units[i];
        const value = (ns + u.div - 1) / u.div;
        if (value <= 99_999_999) return std.fmt.bufPrint(buf, "{d}{c}", .{ value, u.suffix }) catch unreachable;
    }
    return std.fmt.bufPrint(buf, "99999999H", .{}) catch unreachable;
}

test "parse and format" {
    try std.testing.expectEqual(1500 * std.time.ns_per_ms, (try parse("1500m")).nanoseconds);
    try std.testing.expectEqual(2 * std.time.ns_per_hour, (try parse("2H")).nanoseconds);
    try std.testing.expectError(error.InvalidTimeout, parse("m"));
    try std.testing.expectError(error.InvalidTimeout, parse("123456789S"));
    try std.testing.expectError(error.InvalidTimeout, parse("10x"));
    var buf: [9]u8 = undefined;
    try std.testing.expectEqualStrings("30S", format(&buf, .fromSeconds(30)));
    try std.testing.expectEqualStrings("50m", format(&buf, .fromMilliseconds(50)));
    try std.testing.expectEqualStrings("1500m", format(&buf, .fromMilliseconds(1500)));
    try std.testing.expectEqualStrings("0H", format(&buf, .{ .nanoseconds = 0 }));
    // Not exact in any unit within eight digits: rounded up in the smallest unit that fits.
    try std.testing.expectEqualStrings("123457m", format(&buf, .{ .nanoseconds = 123_456_789_123 }));
}
