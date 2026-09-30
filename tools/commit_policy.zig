//! Checks every commit in a range against the repository commit policy:
//! - The maintainer is the sole author and the sole committer.
//! - The message has no attribution trailer.
//! - The subject follows Conventional Commits (`type(scope): description`).
//! - The body describes every changed file on its own line (`path: what changed`).
//!
//! Usage: `commit-policy <git range>` (default `origin/main..HEAD`).
const std = @import("std");

const maintainer_name = "Christian Presley";
const maintainer_email = "chrispresley@outlook.com";
const trailers = [_][]const u8{ "co-authored-by:", "signed-off-by:", "reviewed-by:", "acked-by:" };
const types = [_][]const u8{ "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert" };
const max_subject_len = 100;

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
        failures += checkMessage(short, body);
        failures += try checkFilesDescribed(arena, io, hash, short, body);
    }
    std.debug.print("commit-policy: {d} commits checked, {d} problems\n", .{ count, failures });
    return if (failures == 0) 0 else 1;
}

/// Subject format and trailers. Returns the number of problems.
fn checkMessage(short: []const u8, body: []const u8) usize {
    var failures: usize = 0;
    var lines = std.mem.splitScalar(u8, body, '\n');
    const subject = std.mem.trim(u8, lines.next() orelse "", " \t\r");
    if (!subjectIsConventional(subject)) {
        std.debug.print("::error::commit {s}: subject is not a Conventional Commit (type(scope): description): {s}\n", .{ short, subject });
        failures += 1;
    }
    if (subject.len > max_subject_len) {
        std.debug.print("::error::commit {s}: subject is longer than {d} characters\n", .{ short, max_subject_len });
        failures += 1;
    }
    if (lines.next()) |second| {
        if (std.mem.trim(u8, second, " \t\r").len != 0) {
            std.debug.print("::error::commit {s}: the second line must be blank\n", .{short});
            failures += 1;
        }
    }
    lines = std.mem.splitScalar(u8, body, '\n');
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
    return failures;
}

pub fn subjectIsConventional(subject: []const u8) bool {
    const colon = std.mem.indexOf(u8, subject, ": ") orelse return false;
    var head = subject[0..colon];
    if (std.mem.endsWith(u8, head, "!")) head = head[0 .. head.len - 1];
    var type_name = head;
    if (std.mem.indexOfScalar(u8, head, '(')) |open| {
        if (head.len == 0 or head[head.len - 1] != ')') return false;
        const scope = head[open + 1 .. head.len - 1];
        if (scope.len == 0) return false;
        for (scope) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '/' or c == ',' or c == ' ')) return false;
        type_name = head[0..open];
    }
    var known = false;
    for (types) |t| if (std.mem.eql(u8, type_name, t)) {
        known = true;
    };
    if (!known) return false;
    const description = subject[colon + 2 ..];
    return description.len > 0;
}

/// Every file changed by the commit must have a body line `path: ...`.
fn checkFilesDescribed(arena: std.mem.Allocator, io: std.Io, hash: []const u8, short: []const u8, body: []const u8) !usize {
    const result = try std.process.run(arena, io, .{
        .argv = &.{ "git", "show", "--name-only", "--format=", hash },
        .stdout_limit = .limited(16 << 20),
    });
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("::error::commit {s}: git show failed\n", .{short});
        return 1;
    }
    var failures: usize = 0;
    var files = std.mem.splitScalar(u8, result.stdout, '\n');
    while (files.next()) |raw| {
        const file = std.mem.trim(u8, raw, " \t\r");
        if (file.len == 0) continue;
        if (!bodyDescribes(body, file)) {
            std.debug.print("::error::commit {s}: the body has no line for {s}\n", .{ short, file });
            failures += 1;
        }
    }
    return failures;
}

pub fn bodyDescribes(body: []const u8, file: []const u8) bool {
    var lines = std.mem.splitScalar(u8, body, '\n');
    _ = lines.next(); // subject
    while (lines.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, file) and trimmed.len > file.len and trimmed[file.len] == ':') return true;
    }
    return false;
}

test "conventional subjects" {
    try std.testing.expect(subjectIsConventional("feat(tls): add the server"));
    try std.testing.expect(subjectIsConventional("fix: close the stream"));
    try std.testing.expect(subjectIsConventional("refactor(http)!: rename the option"));
    try std.testing.expect(!subjectIsConventional("Add the server"));
    try std.testing.expect(!subjectIsConventional("feat(): empty scope"));
    try std.testing.expect(!subjectIsConventional("feat:no space"));
    try std.testing.expect(!subjectIsConventional("wip(tls): unknown type"));
}

test "body describes files" {
    const body = "feat(x): subject\n\nsrc/a.zig: the a module.\nREADME.md: notes.\n";
    try std.testing.expect(bodyDescribes(body, "src/a.zig"));
    try std.testing.expect(bodyDescribes(body, "README.md"));
    try std.testing.expect(!bodyDescribes(body, "src/a.zi"));
    try std.testing.expect(!bodyDescribes(body, "src/b.zig"));
}
