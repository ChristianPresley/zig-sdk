//! The rate limits of the server for each caller: tool calls and log messages. See
//! `Limits.RateLimits` for the rules and the caller of a request.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Limits = @import("../Limits.zig");
const Transport = @import("../transport/Transport.zig");
const Principal = @import("../auth/resource_server.zig").Principal;
const rate_limit = @import("../util/rate_limit.zig");

const Rate = Limits.Rate;
pub const Key = rate_limit.Key;

/// The key of the caller of a request. The key of a principal uses the issuer, the subject
/// and the client of the token. Without a principal, the key uses the peer. With `tool`, the
/// key is for the bucket of that tool only.
pub fn callerKey(principal: ?*const Principal, peer: Transport.Peer, tool: ?[]const u8) Key {
    var h: Sha256 = .init(.{});
    if (principal) |p| {
        h.update("principal");
        for ([_]?[]const u8{ p.issuer, p.subject, p.client_id }) |part| feed(&h, part);
    } else switch (peer) {
        .unknown => h.update("unknown"),
        .connection => |id| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, id, .little);
            h.update("connection");
            h.update(&bytes);
        },
        .address => |address| {
            h.update("address");
            switch (address) {
                .ip4 => |a| {
                    h.update("4");
                    h.update(&a.bytes);
                },
                .ip6 => |a| {
                    // An IPv4 address in an IPv6 socket counts as that IPv4 address. Other
                    // IPv6 addresses count by their /64 network.
                    const mapped = std.mem.allEqual(u8, a.bytes[0..10], 0) and a.bytes[10] == 0xff and a.bytes[11] == 0xff;
                    if (mapped) {
                        h.update("4");
                        h.update(a.bytes[12..16]);
                    } else {
                        h.update("6");
                        h.update(a.bytes[0..8]);
                    }
                },
            }
        },
    }
    if (tool) |name| {
        h.update("tool");
        feed(&h, name);
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    h.final(&digest);
    return digest[0..@sizeOf(Key)].*;
}

/// Hash one part with its length, or a `-` for a part that is absent.
fn feed(h: *Sha256, part: ?[]const u8) void {
    const p = part orelse {
        h.update("-");
        return;
    };
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, p.len, .little);
    h.update(":");
    h.update(&len);
    h.update(p);
}

/// The limit that refused a tool call. The name is the value of `data.limit` in the error.
pub const Limit = enum {
    /// `RateLimits.tool_calls`.
    caller,
    /// `ToolDef.rate_limit` of the tool.
    tool,
    /// `RateLimits.tool_calls_total`.
    total,
};

/// Why the server refuses a tool call.
pub const Denial = struct {
    limit: Limit,
    /// The time until the limit admits the call again.
    retry_after_ns: u64,

    /// The time until the limit admits the call again, in whole milliseconds, at least 1.
    pub fn retryAfterMs(self: Denial) u64 {
        return @max(1, std.math.divCeil(u64, self.retry_after_ns, std.time.ns_per_ms) catch unreachable);
    }
};

/// What the server does with one log message.
pub const LogDecision = union(enum) {
    /// Send the message.
    send,
    /// Drop the message. The limiter counted it.
    drop,
    /// Send a summary with this count of dropped messages, then the message.
    send_summary: u64,
};

/// Counters of the rate limits, for metrics.
pub const Stats = struct {
    /// Tool calls that a rate limit refused.
    tool_calls_refused: u64 = 0,
    /// Log messages that the server dropped.
    log_messages_dropped: u64 = 0,
    /// Buckets of callers now, for the tool calls and the log messages together.
    buckets: usize = 0,
    /// Buckets that the server forgot to make space for new callers. A high value can tell
    /// that more callers use the server than `RateLimits.max_callers`.
    buckets_forgotten: u64 = 0,
};

/// The buckets of all callers. The server has one limiter. It is thread-safe.
pub const Limiter = struct {
    lock: Io.Mutex = .init,
    tools: rate_limit.Table,
    logs: rate_limit.Table,
    /// The bucket of `RateLimits.tool_calls_total`, made at the first call.
    total: ?rate_limit.Bucket = null,
    tool_calls_refused: u64 = 0,
    log_messages_dropped: u64 = 0,

    pub fn init(max_callers: u32) Limiter {
        return .{ .tools = .init(max_callers), .logs = .init(max_callers) };
    }

    pub fn deinit(self: *Limiter, gpa: Allocator) void {
        self.tools.deinit(gpa);
        self.logs.deinit(gpa);
        self.* = undefined;
    }

    /// Take a token for one tool call: first from the bucket of `key` at `per_caller`, then
    /// from the total bucket at `total`. Without `key`, only the total bucket counts. Return
    /// null when both buckets admit the call. When the total bucket refuses the call, the
    /// token goes back to the bucket of the caller.
    pub fn admitToolCall(self: *Limiter, gpa: Allocator, io: Io, key: ?Key, per_caller: Rate, limit: Limit, total: Rate, now: i96) Allocator.Error!?Denial {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        var entry: ?*rate_limit.Table.Entry = null;
        if (key) |k| if (per_caller.enabled()) {
            const e = try self.tools.get(gpa, k, per_caller, now);
            const wait = e.bucket.take(per_caller, now);
            if (wait > 0) {
                self.tool_calls_refused += 1;
                return .{ .limit = limit, .retry_after_ns = wait };
            }
            entry = e;
        };
        if (total.enabled()) {
            if (self.total == null) self.total = .full(total, now);
            const wait = self.total.?.take(total, now);
            if (wait > 0) {
                if (entry) |e| e.bucket.giveBack(per_caller);
                self.tool_calls_refused += 1;
                return .{ .limit = .total, .retry_after_ns = wait };
            }
        }
        return null;
    }

    /// Take a token for one log message from the bucket of `key`.
    pub fn admitLog(self: *Limiter, gpa: Allocator, io: Io, key: Key, rate: Rate, now: i96) Allocator.Error!LogDecision {
        if (!rate.enabled()) return .send;
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        const e = try self.logs.get(gpa, key, rate, now);
        if (e.bucket.take(rate, now) > 0) {
            e.dropped += 1;
            self.log_messages_dropped += 1;
            return .drop;
        }
        if (e.dropped == 0) return .send;
        const dropped = e.dropped;
        e.dropped = 0;
        return .{ .send_summary = dropped };
    }

    /// A copy of the counters.
    pub fn stats(self: *Limiter, io: Io) Stats {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        return .{
            .tool_calls_refused = self.tool_calls_refused,
            .log_messages_dropped = self.log_messages_dropped,
            .buckets = self.tools.count() + self.logs.count(),
            .buckets_forgotten = self.tools.forgotten + self.logs.forgotten,
        };
    }
};

test "caller keys keep principals, addresses and connections apart" {
    const alice: Principal = .{ .issuer = "https://as.example", .subject = "alice", .client_id = "app" };
    const bob: Principal = .{ .issuer = "https://as.example", .subject = "bob", .client_id = "app" };
    const split: Principal = .{ .issuer = "https://as.example", .subject = "alic", .client_id = "eapp" };
    const no_client: Principal = .{ .issuer = "https://as.example", .subject = "alice" };
    const v4: Transport.Peer = .{ .address = try Io.net.IpAddress.parse("192.0.2.1", 1000) };
    const keys = [_]Key{
        callerKey(&alice, .unknown, null),
        callerKey(&bob, .unknown, null),
        callerKey(&split, .unknown, null),
        callerKey(&no_client, .unknown, null),
        callerKey(&alice, .unknown, "search"),
        callerKey(null, .unknown, null),
        callerKey(null, .{ .connection = 1 }, null),
        callerKey(null, .{ .connection = 2 }, null),
        callerKey(null, v4, null),
        callerKey(null, .{ .address = try Io.net.IpAddress.parse("192.0.2.2", 1000) }, null),
        callerKey(null, v4, "search"),
    };
    for (keys, 0..) |a, i| for (keys[i + 1 ..]) |b| try std.testing.expect(!std.mem.eql(u8, &a, &b));
    // A principal counts the same on every address and connection. The port of an address
    // does not count.
    try std.testing.expectEqualSlices(u8, &keys[0], &callerKey(&alice, v4, null));
    try std.testing.expectEqualSlices(u8, &keys[8], &callerKey(null, .{ .address = try Io.net.IpAddress.parse("192.0.2.1", 2000) }, null));
}

test "an IPv6 caller key covers the /64 network, and an IPv4-mapped address counts as IPv4" {
    const net_a1 = callerKey(null, .{ .address = try Io.net.IpAddress.parse("2001:db8:1:2::1", 1) }, null);
    const net_a2 = callerKey(null, .{ .address = try Io.net.IpAddress.parse("2001:db8:1:2:ffff::9", 1) }, null);
    const net_b = callerKey(null, .{ .address = try Io.net.IpAddress.parse("2001:db8:1:3::1", 1) }, null);
    try std.testing.expectEqualSlices(u8, &net_a1, &net_a2);
    try std.testing.expect(!std.mem.eql(u8, &net_a1, &net_b));
    const mapped_1 = callerKey(null, .{ .address = try Io.net.IpAddress.parse("::ffff:192.0.2.1", 1) }, null);
    const mapped_2 = callerKey(null, .{ .address = try Io.net.IpAddress.parse("::ffff:192.0.2.2", 1) }, null);
    const plain_1 = callerKey(null, .{ .address = try Io.net.IpAddress.parse("192.0.2.1", 1) }, null);
    try std.testing.expect(!std.mem.eql(u8, &mapped_1, &mapped_2));
    try std.testing.expectEqualSlices(u8, &mapped_1, &plain_1);
}

test "the limiter refuses a caller over its rate and gives back the token that the total limit refused" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var l: Limiter = .init(16);
    defer l.deinit(gpa);
    const per_caller: Rate = .{ .count = 2, .period = .fromSeconds(1) };
    const a = callerKey(null, .{ .connection = 1 }, null);
    const b = callerKey(null, .{ .connection = 2 }, null);
    try std.testing.expectEqual(null, try l.admitToolCall(gpa, io, a, per_caller, .caller, .{}, 0));
    try std.testing.expectEqual(null, try l.admitToolCall(gpa, io, a, per_caller, .caller, .{}, 0));
    const denial = (try l.admitToolCall(gpa, io, a, per_caller, .caller, .{}, 0)).?;
    try std.testing.expectEqual(Limit.caller, denial.limit);
    try std.testing.expectEqual(500, denial.retryAfterMs());
    // The other caller has its own bucket.
    try std.testing.expectEqual(null, try l.admitToolCall(gpa, io, b, per_caller, .caller, .{}, 0));

    // A total limit of one call: the second caller gets a refusal of the total limit and
    // keeps its own token.
    const total: Rate = .{ .count = 1, .period = .fromSeconds(10) };
    var t: Limiter = .init(16);
    defer t.deinit(gpa);
    try std.testing.expectEqual(null, try t.admitToolCall(gpa, io, a, per_caller, .caller, total, 0));
    for (0..3) |_| {
        const d = (try t.admitToolCall(gpa, io, b, per_caller, .caller, total, 0)).?;
        try std.testing.expectEqual(Limit.total, d.limit);
        try std.testing.expectEqual(10_000, d.retryAfterMs());
    }
    // After 10 s, the second caller still has its two tokens.
    try std.testing.expectEqual(null, try t.admitToolCall(gpa, io, b, per_caller, .caller, .{}, 10 * std.time.ns_per_s));
    try std.testing.expectEqual(null, try t.admitToolCall(gpa, io, b, per_caller, .caller, .{}, 10 * std.time.ns_per_s));
    try std.testing.expectEqual(3, t.stats(io).tool_calls_refused);
    try std.testing.expectEqual(1, l.stats(io).tool_calls_refused);
}

test "the limiter drops log messages over the rate and reports the count once" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var l: Limiter = .init(16);
    defer l.deinit(gpa);
    const rate: Rate = .{ .count = 1, .period = .fromSeconds(1) };
    const k = callerKey(null, .{ .connection = 7 }, null);
    try std.testing.expectEqual(LogDecision.send, try l.admitLog(gpa, io, k, rate, 0));
    try std.testing.expectEqual(LogDecision.drop, try l.admitLog(gpa, io, k, rate, 0));
    try std.testing.expectEqual(LogDecision.drop, try l.admitLog(gpa, io, k, rate, 0));
    try std.testing.expectEqual(LogDecision{ .send_summary = 2 }, try l.admitLog(gpa, io, k, rate, std.time.ns_per_s));
    try std.testing.expectEqual(LogDecision.drop, try l.admitLog(gpa, io, k, rate, std.time.ns_per_s));
    try std.testing.expectEqual(LogDecision{ .send_summary = 1 }, try l.admitLog(gpa, io, k, rate, 2 * std.time.ns_per_s));
    try std.testing.expectEqual(LogDecision.send, try l.admitLog(gpa, io, k, rate, 3 * std.time.ns_per_s));
    // A rate of zero sends every message.
    for (0..10) |_| try std.testing.expectEqual(LogDecision.send, try l.admitLog(gpa, io, k, .{}, 0));
    try std.testing.expectEqual(3, l.stats(io).log_messages_dropped);
}
