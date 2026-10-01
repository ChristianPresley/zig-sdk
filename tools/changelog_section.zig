//! Prints the section of `CHANGELOG.md` for one version, for release notes.
//!
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

/// The text below `## [version]` up to the next `## ` heading or the first link reference
/// definition, trimmed.
pub fn extract(changelog: []const u8, version: []const u8) ?[]const u8 {
    var heading_buf: [128]u8 = undefined;
    const heading = std.fmt.bufPrint(&heading_buf, "## [{s}]", .{version}) catch return null;
    const start = std.mem.indexOf(u8, changelog, heading) orelse return null;
    const body_start = (std.mem.indexOfScalarPos(u8, changelog, start, '\n') orelse return null) + 1;
    var end = std.mem.indexOfPos(u8, changelog, body_start, "\n## ") orelse changelog.len;
    if (firstLinkDefinition(changelog[body_start..end])) |offset| end = body_start + offset;
    return std.mem.trim(u8, changelog[body_start..end], "\n\r ");
}

/// The offset of the first line of `text` that is a link reference definition
/// (`[label]: url`), or null.
fn firstLinkDefinition(text: []const u8) ?usize {
    var pos: usize = 0;
    while (pos < text.len) {
        const line_end = std.mem.indexOfScalarPos(u8, text, pos, '\n') orelse text.len;
        const line = text[pos..line_end];
        if (line.len > 0 and line[0] == '[' and std.mem.indexOf(u8, line, "]: ") != null) return pos;
        pos = line_end + 1;
    }
    return null;
}

test "extract a section" {
    const text = "# Changelog\n\n## [Unreleased]\n\n- soon\n\n## [0.1.0] - 2026-10-01\n\n### Added\n\n- first\n\n## [0.0.1]\n\n- zero\n";
    try std.testing.expectEqualStrings("### Added\n\n- first", extract(text, "0.1.0").?);
    try std.testing.expectEqualStrings("- zero", extract(text, "0.0.1").?);
    try std.testing.expect(extract(text, "9.9.9") == null);
}

test "the link reference definitions at the end are not part of the last section" {
    const text = "## [0.2.0] - 2026-10-01\n\n- second [link](x)\n\n## [0.1.0] - 2026-09-30\n\n- first\n\n[0.2.0]: https://example.com/compare/v0.1.0...v0.2.0\n[0.1.0]: https://example.com/tree/v0.1.0\n";
    try std.testing.expectEqualStrings("- second [link](x)", extract(text, "0.2.0").?);
    try std.testing.expectEqualStrings("- first", extract(text, "0.1.0").?);
}
