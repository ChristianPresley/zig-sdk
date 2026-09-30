//! Checks that every commit in a range has the maintainer as sole author and committer and
//! carries no attribution trailer. Usage: `commit-policy <git range>` (default `origin/main..HEAD`).
const std = @import("std");

const maintainer_name = "Christian Presley";
const maintainer_email = "chrispresley@outlook.com";
const trailers = [_][]const u8{ "co-authored-by:", "signed-off-by:", "reviewed-by:", "acked-by:" };

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const range: []const u8 = if (args.len > 1) args[1] else "origin/main..HEAD";

    const result = try std.process.run(arena, io, .{
        .argv = &.{ "git", "log", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e", range },
        .stdout_limit = .limited(64 << 20),
    });
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("commit-policy: git log failed: {s}\n", .{result.stderr});
        return 2;
    }

    var failures: usize = 0;
    var count: usize = 0;
    var records = std.mem.splitScalar(u8, result.stdout, 0x1e);
    while (records.next()) |raw| {
        const record = std.mem.trim(u8, raw, "\r\n ");
        if (record.len == 0) continue;
        count += 1;
        var fields = std.mem.splitScalar(u8, record, 0x1f);
        const hash = fields.next() orelse continue;
        const an = fields.next() orelse "";
        const ae = fields.next() orelse "";
        const cn = fields.next() orelse "";
        const ce = fields.next() orelse "";
        const body = fields.rest();
        const short = hash[0..@min(hash.len, 10)];
        if (!std.mem.eql(u8, an, maintainer_name) or !std.mem.eql(u8, ae, maintainer_email)) {
            std.debug.print("::error::commit {s}: author is {s} <{s}>, expected the maintainer\n", .{ short, an, ae });
            failures += 1;
        }
        if (!std.mem.eql(u8, cn, maintainer_name) or !std.mem.eql(u8, ce, maintainer_email)) {
            std.debug.print("::error::commit {s}: committer is {s} <{s}>, expected the maintainer\n", .{ short, cn, ce });
            failures += 1;
        }
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line| {
            var lower_buf: [256]u8 = undefined;
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed.len > lower_buf.len) continue;
            const lower = std.ascii.lowerString(&lower_buf, trimmed);
            for (trailers) |t| {
                if (std.mem.startsWith(u8, lower, t)) {
                    std.debug.print("::error::commit {s}: attribution trailer is not permitted: {s}\n", .{ short, trimmed });
                    failures += 1;
                }
            }
        }
    }
    std.debug.print("commit-policy: {d} commits checked, {d} problems\n", .{ count, failures });
    return if (failures == 0) 0 else 1;
}
