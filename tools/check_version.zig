//! Checks that a release tag matches the package version.
//! Usage: `check-version vX.Y.Z` compares the tag with `.version` in `build.zig.zon`.
const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: check-version vX.Y.Z\n", .{});
        return 2;
    }
    const tag = args[1];
    if (tag.len < 2 or tag[0] != 'v') {
        std.debug.print("::error::the tag {s} does not start with v\n", .{tag});
        return 1;
    }
    const wanted = tag[1..];
    _ = std.SemanticVersion.parse(wanted) catch {
        std.debug.print("::error::the tag {s} is not a semantic version\n", .{tag});
        return 1;
    };
    const zon = try Io.Dir.cwd().readFileAlloc(io, "build.zig.zon", arena, .limited(1 << 20));
    const actual = packageVersion(zon) orelse {
        std.debug.print("::error::build.zig.zon has no .version field\n", .{});
        return 1;
    };
    if (!std.mem.eql(u8, actual, wanted)) {
        std.debug.print("::error::the tag {s} does not match build.zig.zon version {s}\n", .{ tag, actual });
        return 1;
    }
    const changelog = try Io.Dir.cwd().readFileAlloc(io, "CHANGELOG.md", arena, .limited(4 << 20));
    const heading = try std.fmt.allocPrint(arena, "## [{s}]", .{wanted});
    if (std.mem.indexOf(u8, changelog, heading) == null) {
        std.debug.print("::error::CHANGELOG.md has no section {s}\n", .{heading});
        return 1;
    }
    std.debug.print("check-version: {s} matches build.zig.zon and CHANGELOG.md\n", .{tag});
    return 0;
}

/// The value of `.version = "..."` in a zon file.
pub fn packageVersion(zon: []const u8) ?[]const u8 {
    const key = ".version = \"";
    const start = (std.mem.indexOf(u8, zon, key) orelse return null) + key.len;
    const end = std.mem.indexOfScalarPos(u8, zon, start, '"') orelse return null;
    return zon[start..end];
}

test "package version" {
    try std.testing.expectEqualStrings("0.1.0", packageVersion(".{ .name = .mcp, .version = \"0.1.0\" }").?);
    try std.testing.expect(packageVersion(".{ .name = .mcp }") == null);
}
