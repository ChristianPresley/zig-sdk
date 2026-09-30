//! The lint-docs tool checks prose against the project profile of ASD-STE100.
//!
//! It checks Markdown files, the `///` and `//!` doc comments of Zig files and, with
//! `--string-literals`, the user-visible messages of the SDK. The rule ids cite ASD-STE100
//! Issue 9 by rule number. The tool does not copy the rule text of the standard.
//!
//! Usage: `lint-docs [--format text|github|json] [--strict] [--string-literals] [--wiki-dir DIR] [--dictionary DIR] [--rule ID=off|warn|error] [PATH...]`
const std = @import("std");
const Io = std.Io;
const Linter = @import("Linter.zig");
const Dictionary = @import("Dictionary.zig");

/// The paths that the tool checks when the command line gives no path and no wiki directory.
const default_paths = [_][]const u8{
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "VERSIONING.md", ".github/pull_request_template.md",
    "docs",      "src",             "tools",       "conformance",   "examples",
    "bench",
};

const usage =
    \\Usage: lint-docs [options] [PATH...]
    \\
    \\Without a PATH and without --wiki-dir, the tool checks the prose of the repository.
    \\
    \\Options:
    \\  --format text|github|json  The output format. The default is text, or github in GitHub Actions.
    \\  --strict                   Every warning is an error.
    \\  --string-literals          Also check the `.message = "..."` string literals of Zig files.
    \\  --wiki-dir DIR             Check the wiki clone in DIR, with its page links and templates.
    \\  --dictionary DIR           The directory of the word lists. The default is docs/dictionary.
    \\  --rule ID=off|warn|error   Change the severity of a rule.
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    var linter: Linter = .{ .arena = arena, .io = io, .dir = Io.Dir.cwd() };
    var paths: std.ArrayList([]const u8) = .empty;
    var format: ?Linter.Format = null;
    var dictionary_dir: []const u8 = "docs/dictionary";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const needs_value = std.mem.eql(u8, a, "--format") or std.mem.eql(u8, a, "--wiki-dir") or
            std.mem.eql(u8, a, "--rule") or std.mem.eql(u8, a, "--dictionary");
        if (needs_value and i + 1 >= args.len) {
            std.debug.print("lint-docs: {s} needs a value\n{s}", .{ a, usage });
            return 2;
        }
        if (std.mem.eql(u8, a, "--format")) {
            i += 1;
            format = std.meta.stringToEnum(Linter.Format, args[i]) orelse {
                std.debug.print("lint-docs: unknown format {s}\n{s}", .{ args[i], usage });
                return 2;
            };
        } else if (std.mem.eql(u8, a, "--strict")) {
            linter.strict = true;
        } else if (std.mem.eql(u8, a, "--string-literals")) {
            linter.string_literals = true;
        } else if (std.mem.eql(u8, a, "--wiki-dir")) {
            i += 1;
            linter.wiki_dir = std.mem.trimEnd(u8, args[i], "/\\");
            try paths.append(arena, linter.wiki_dir.?);
        } else if (std.mem.eql(u8, a, "--dictionary")) {
            i += 1;
            dictionary_dir = args[i];
        } else if (std.mem.eql(u8, a, "--rule")) {
            i += 1;
            linter.setRule(args[i]) catch {
                std.debug.print("lint-docs: invalid rule setting {s}\n{s}", .{ args[i], usage });
                return 2;
            };
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            std.debug.print("{s}", .{usage});
            return 0;
        } else if (std.mem.startsWith(u8, a, "--")) {
            std.debug.print("lint-docs: unknown option {s}\n{s}", .{ a, usage });
            return 2;
        } else {
            try paths.append(arena, a);
        }
    }
    if (paths.items.len == 0) try paths.appendSlice(arena, &default_paths);
    linter.format = format orelse if (init.environ_map.get("GITHUB_ACTIONS") != null) .github else .text;
    linter.dict = try Dictionary.load(arena, io, linter.dir, dictionary_dir);
    for (paths.items) |p| linter.lintPath(p) catch |err| switch (err) {
        error.PathNotFound => return 2,
        else => |e| return e,
    };

    var buf: [8192]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &buf);
    try linter.print(&stdout.interface);
    try stdout.interface.flush();
    return if (linter.errors > 0) 1 else 0;
}

test {
    _ = @import("text.zig");
    _ = @import("markdown.zig");
    _ = @import("rules.zig");
    _ = @import("zig_source.zig");
    _ = @import("Dictionary.zig");
    _ = Linter;
}
