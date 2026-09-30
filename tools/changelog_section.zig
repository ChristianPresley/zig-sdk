//! Prints the section of `CHANGELOG.md` for one version, for release notes.
//! Usage: `changelog-section vX.Y.Z [--out PATH]`
const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: changelog-section vX.Y.Z [--out PATH]\n", .{});
        return 2;
    }
    const version = if (args[1][0] == 'v') args[1][1..] else args[1];
    var out_path: ?[]const u8 = null;
    if (args.len >= 4 and std.mem.eql(u8, args[2], "--out")) out_path = args[3];
    const changelog = try Io.Dir.cwd().readFileAlloc(io, "CHANGELOG.md", arena, .limited(4 << 20));
    const section = extract(changelog, version) orelse {
        std.debug.print("::error::CHANGELOG.md has no section for {s}\n", .{version});
        return 1;
    };
    if (out_path) |p| {
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = section });
    } else {
        var buf: [4096]u8 = undefined;
        var stdout = Io.File.stdout().writer(io, &buf);
        try stdout.interface.writeAll(section);
        try stdout.interface.flush();
    }
    return 0;
}

/// The text below `## [version]` up to the next `## ` heading, trimmed.
pub fn extract(changelog: []const u8, version: []const u8) ?[]const u8 {
    var heading_buf: [128]u8 = undefined;
    const heading = std.fmt.bufPrint(&heading_buf, "## [{s}]", .{version}) catch return null;
    const start = std.mem.indexOf(u8, changelog, heading) orelse return null;
    const body_start = (std.mem.indexOfScalarPos(u8, changelog, start, '\n') orelse return null) + 1;
    const end = std.mem.indexOfPos(u8, changelog, body_start, "\n## ") orelse changelog.len;
    return std.mem.trim(u8, changelog[body_start..end], "\n\r ");
}

test "extract a section" {
    const text = "# Changelog\n\n## [Unreleased]\n\n- soon\n\n## [0.1.0] - 2026-10-01\n\n### Added\n\n- first\n\n## [0.0.1]\n\n- zero\n";
    try std.testing.expectEqualStrings("### Added\n\n- first", extract(text, "0.1.0").?);
    try std.testing.expectEqualStrings("- zero", extract(text, "0.0.1").?);
    try std.testing.expect(extract(text, "9.9.9") == null);
}
