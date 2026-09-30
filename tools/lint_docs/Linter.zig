//! The state of one lint-docs run: the options, the dictionary and the findings.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Dictionary = @import("Dictionary.zig");
const markdown = @import("markdown.zig");
const rules = @import("rules.zig");
const text = @import("text.zig");
const zig_source = @import("zig_source.zig");

const Linter = @This();

/// The output format.
pub const Format = enum { text, github, json };

/// A rule setting from `--rule ID=off|warn|error`.
pub const Setting = enum { off, warn, err };

/// One finding.
pub const Finding = struct {
    file: []const u8,
    line: usize,
    rule: []const u8,
    severity: rules.Severity,
    message: []const u8,
};

arena: Allocator,
io: Io,
dir: Io.Dir,
dict: Dictionary = .{},
format: Format = .text,
/// With `strict`, every warning is an error.
strict: bool = false,
/// With `string_literals`, the linter checks the `.message` string literals in Zig files.
string_literals: bool = false,
/// The directory of the wiki clone, for the wiki link and page template rules.
wiki_dir: ?[]const u8 = null,
settings: std.StringHashMapUnmanaged(Setting) = .empty,
findings: std.ArrayList(Finding) = .empty,
anchor_cache: std.StringHashMapUnmanaged(?[]const []const u8) = .empty,
errors: usize = 0,
warnings: usize = 0,
files: usize = 0,
/// The file that the linter checks now.
current_file: []const u8 = "",

/// Records a finding, after the `--rule` settings and `--strict`.
pub fn report(self: *Linter, file: []const u8, line: usize, rule: []const u8, severity: rules.Severity, message: []const u8) !void {
    var sev = severity;
    if (self.settings.get(rule)) |setting| switch (setting) {
        .off => return,
        .warn => sev = .warn,
        .err => sev = .err,
    };
    if (self.strict) sev = .err;
    try self.findings.append(self.arena, .{ .file = file, .line = line, .rule = rule, .severity = sev, .message = message });
    switch (sev) {
        .err => self.errors += 1,
        .warn => self.warnings += 1,
    }
}

fn reportf(self: *Linter, line: usize, rule: []const u8, severity: rules.Severity, comptime fmt: []const u8, args: anytype) !void {
    try self.report(self.current_file, line, rule, severity, try std.fmt.allocPrint(self.arena, fmt, args));
}

fn sinkReport(context: *anyopaque, line: usize, rule: []const u8, severity: rules.Severity, message: []const u8) anyerror!void {
    const self: *Linter = @ptrCast(@alignCast(context));
    try self.report(self.current_file, line, rule, severity, message);
}

fn sink(self: *Linter) rules.Sink {
    return .{ .context = self, .reportFn = sinkReport, .arena = self.arena, .dict = &self.dict };
}

/// Sets a rule to `off`, `warn` or `error`. The argument has the form `ID=setting`.
pub fn setRule(self: *Linter, spec: []const u8) !void {
    const eq = std.mem.findScalar(u8, spec, '=') orelse return error.InvalidRuleSetting;
    const value = spec[eq + 1 ..];
    const setting: Setting = if (std.mem.eql(u8, value, "off"))
        .off
    else if (std.mem.eql(u8, value, "warn"))
        .warn
    else if (std.mem.eql(u8, value, "error"))
        .err
    else
        return error.InvalidRuleSetting;
    try self.settings.put(self.arena, spec[0..eq], setting);
}

/// Checks a file, or every Markdown and Zig file in a directory.
pub fn lintPath(self: *Linter, path: []const u8) !void {
    const stat = self.dir.statFile(self.io, path, .{}) catch |err| {
        std.debug.print("lint-docs: cannot open {s}: {t}\n", .{ path, err });
        return error.PathNotFound;
    };
    if (stat.kind != .directory) return self.lintFile(path);
    var sub = try self.dir.openDir(self.io, path, .{ .iterate = true });
    defer sub.close(self.io);
    var walker = try sub.walk(self.arena);
    defer walker.deinit();
    var paths: std.ArrayList([]const u8) = .empty;
    while (try walker.next(self.io)) |entry| {
        if (entry.kind != .file) continue;
        if (isExcluded(entry.path)) continue;
        try paths.append(self.arena, try std.fs.path.join(self.arena, &.{ path, entry.path }));
    }
    // A sorted order gives the same output on every system.
    std.mem.sort([]const u8, paths.items, {}, lessThan);
    for (paths.items) |p| try self.lintFile(p);
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Fixtures, generated files and hidden directories are exempt.
fn isExcluded(path: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    while (it.next()) |part| {
        if (part[0] == '.') return true;
        if (std.mem.eql(u8, part, "fixtures") or std.mem.eql(u8, part, "generated")) return true;
    }
    return false;
}

/// Checks one file. The linter ignores files that are not Markdown or Zig.
pub fn lintFile(self: *Linter, path: []const u8) !void {
    const is_md = std.mem.endsWith(u8, path, ".md");
    const is_zig = std.mem.endsWith(u8, path, ".zig");
    if (!is_md and !is_zig) return;
    const source = try self.dir.readFileAlloc(self.io, path, self.arena, .limited(16 << 20));
    if (is_md) try self.lintMarkdown(path, source) else try self.lintZig(path, source);
}

/// Returns true when the page says that a tool made it.
fn isGenerated(source: []const u8) bool {
    return std.mem.find(u8, source[0..@min(source.len, 512)], "generated by zig build") != null;
}

/// Checks the text of a Markdown file.
pub fn lintMarkdown(self: *Linter, path: []const u8, source: []const u8) !void {
    // Generated pages are exempt from the profile. They say so in their header comment.
    if (isGenerated(source)) return;
    self.files += 1;
    self.current_file = path;
    try self.checkWhitespace(source);
    const doc = try markdown.extract(self.arena, source, .{ .indented_code = true });
    for (doc.blocks) |block| try rules.checkBlock(self.sink(), block);
    const wiki = self.isWikiPage(path);
    try self.checkLinks(path, source, doc.links, wiki);
    if (wiki) try self.checkPageTemplate(path, source);
}

/// Checks the doc comments of a Zig file and, with `string_literals`, its messages.
pub fn lintZig(self: *Linter, path: []const u8, source: []const u8) !void {
    self.files += 1;
    self.current_file = path;
    const is_test_file = std.mem.endsWith(u8, path, "_test.zig");
    const result = try zig_source.scan(self.arena, source, self.string_literals and !is_test_file);
    for (result.parse_errors) |e| try self.reportf(e.line, "PRJ-11", .err, "Zig parse error: {s}", .{e.message});
    for (result.doc_comments) |doc| {
        const extracted = try markdown.extract(self.arena, doc.text, .{ .first_line = doc.line, .indented_code = true });
        for (extracted.blocks) |block| try rules.checkBlock(self.sink(), block);
        const summary = zig_source.summary(doc.text);
        if (summary.len > 0 and !endsSentence(summary)) {
            try self.reportf(doc.line, "PRJ-7", .warn, "doc comment summary does not end with a period: \"{s}\"", .{text.excerpt(summary)});
        }
    }
    for (result.string_literals) |lit| {
        try rules.checkBlock(self.sink(), .{ .text = lit.text, .line = lit.line, .mode = .descriptive, .kind = .paragraph });
    }
}

/// A summary ends with `.`, `!`, `?` or `:`. A `)` or a `"` can follow the last one.
fn endsSentence(summary: []const u8) bool {
    var s = std.mem.trimEnd(u8, summary, " \t");
    while (s.len > 0 and (s[s.len - 1] == ')' or s[s.len - 1] == '"')) s = s[0 .. s.len - 1];
    if (s.len == 0) return false;
    return switch (s[s.len - 1]) {
        '.', '!', '?', ':' => true,
        else => false,
    };
}

/// PRJ-10: no space or tab at the end of a line.
fn checkWhitespace(self: *Linter, source: []const u8) !void {
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        line_no += 1;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len > 0 and (line[line.len - 1] == ' ' or line[line.len - 1] == '\t')) {
            try self.reportf(line_no, "PRJ-10", .err, "trailing whitespace", .{});
        }
    }
}

fn isWikiPage(self: *Linter, path: []const u8) bool {
    const wiki = self.wiki_dir orelse return false;
    return std.mem.startsWith(u8, path, wiki);
}

/// PRJ-9: a link to a wiki page, a repository file or an anchor has a target that exists.
fn checkLinks(self: *Linter, path: []const u8, source: []const u8, links: []const markdown.Link, wiki: bool) !void {
    const own_anchors = try markdown.anchors(self.arena, source);
    for (links) |link| {
        const target = link.target;
        if (target.len == 0) {
            try self.reportf(link.line, "PRJ-9", .err, "link without a target", .{});
            continue;
        }
        if (target[0] == '#') {
            if (!Dictionary.has(own_anchors, target[1..])) try self.reportf(link.line, "PRJ-9", .err, "anchor \"{s}\" does not exist on this page", .{target});
            continue;
        }
        if (std.mem.startsWith(u8, target, "mailto:")) continue;
        if (std.mem.find(u8, target, "://")) |_| {
            if (self.wiki_dir != null) {
                if (std.mem.find(u8, target, "github.com/ChristianPresley/zig-sdk/wiki/")) |i| {
                    const page = target[i + "github.com/ChristianPresley/zig-sdk/wiki/".len ..];
                    try self.checkWikiTarget(link.line, page);
                }
            }
            continue;
        }
        if (wiki) {
            if (!text.isWikiPageTarget(target)) {
                try self.reportf(link.line, "PRJ-9", .err, "wiki link \"{s}\" is not a page name", .{target});
                continue;
            }
            try self.checkWikiTarget(link.line, target);
            continue;
        }
        // A relative link to a file of the repository.
        const file_part = text.pageOf(target);
        const dir_name = std.fs.path.dirname(path) orelse ".";
        const resolved = try std.fs.path.join(self.arena, &.{ dir_name, file_part });
        self.dir.access(self.io, resolved, .{}) catch {
            try self.reportf(link.line, "PRJ-9", .err, "link target \"{s}\" does not exist", .{target});
        };
    }
}

fn checkWikiTarget(self: *Linter, line: usize, target: []const u8) !void {
    const wiki = self.wiki_dir orelse return;
    const page = text.pageOf(target);
    const page_file = try std.fmt.allocPrint(self.arena, "{s}/{s}.md", .{ wiki, page });
    const page_anchors = try self.anchorsOf(page_file);
    const list = page_anchors orelse {
        try self.reportf(line, "PRJ-9", .err, "wiki page \"{s}\" does not exist", .{page});
        return;
    };
    if (page.len < target.len) {
        const anchor = target[page.len + 1 ..];
        if (!Dictionary.has(list, anchor)) try self.reportf(line, "PRJ-9", .err, "anchor \"{s}\" does not exist on the wiki page \"{s}\"", .{ anchor, page });
    }
}

fn anchorsOf(self: *Linter, file: []const u8) !?[]const []const u8 {
    if (self.anchor_cache.get(file)) |cached| return cached;
    const value: ?[]const []const u8 = blk: {
        const source = self.dir.readFileAlloc(self.io, file, self.arena, .limited(16 << 20)) catch break :blk null;
        break :blk try markdown.anchors(self.arena, source);
    };
    try self.anchor_cache.put(self.arena, file, value);
    return value;
}

/// PRJ-8: a wiki page has the page template, and its citations and references match.
fn checkPageTemplate(self: *Linter, path: []const u8, source: []const u8) !void {
    const base = std.fs.path.basename(path);
    if (base[0] == '_') return; // The sidebar and the footer.
    if (std.mem.find(u8, source, "<!-- ste: ") == null) try self.reportf(1, "PRJ-8", .err, "page has no \"<!-- ste: ... -->\" marker", .{});
    if (std.mem.find(u8, source, "**Applies to:**") == null) try self.reportf(1, "PRJ-8", .err, "page has no \"**Applies to:**\" line", .{});
    // Every reference has a citation, and every citation has a reference.
    var n: usize = 1;
    while (n < 100) : (n += 1) {
        const anchor = try std.fmt.allocPrint(self.arena, "name=\"ref-{d}\"", .{n});
        const cite = try std.fmt.allocPrint(self.arena, "(#ref-{d})", .{n});
        const has_anchor = std.mem.find(u8, source, anchor) != null;
        const has_cite = std.mem.find(u8, source, cite) != null;
        if (!has_anchor and !has_cite) break;
        if (has_anchor and !has_cite) try self.reportf(lineOf(source, anchor), "PRJ-8", .err, "reference {d} has no citation", .{n});
        if (has_cite and !has_anchor) try self.reportf(lineOf(source, cite), "PRJ-8", .err, "citation {d} has no reference", .{n});
    }
}

fn lineOf(source: []const u8, needle: []const u8) usize {
    const i = std.mem.find(u8, source, needle) orelse return 1;
    return std.mem.count(u8, source[0..i], "\n") + 1;
}

/// Writes the findings and the summary line.
pub fn print(self: *Linter, w: *Io.Writer) !void {
    switch (self.format) {
        .text => {
            for (self.findings.items) |f| try w.print("{s}:{d}: {s} {s}: {s}\n", .{ f.file, f.line, severityName(f.severity), f.rule, f.message });
            try w.print("lint-docs: {d} files, {d} errors, {d} warnings\n", .{ self.files, self.errors, self.warnings });
        },
        .github => {
            for (self.findings.items) |f| {
                try w.print("::{s} file=", .{if (f.severity == .err) "error" else "warning"});
                try escapeGithub(w, f.file, true);
                try w.print(",line={d},title=", .{f.line});
                try escapeGithub(w, f.rule, true);
                try w.writeAll("::");
                try escapeGithub(w, f.message, false);
                try w.writeAll("\n");
            }
            try w.print("lint-docs: {d} files, {d} errors, {d} warnings\n", .{ self.files, self.errors, self.warnings });
        },
        .json => {
            const Out = struct {
                file: []const u8,
                line: usize,
                rule: []const u8,
                severity: []const u8,
                message: []const u8,
            };
            const out = try self.arena.alloc(Out, self.findings.items.len);
            for (self.findings.items, out) |f, *o| o.* = .{ .file = f.file, .line = f.line, .rule = f.rule, .severity = severityName(f.severity), .message = f.message };
            try std.json.Stringify.value(.{
                .files = self.files,
                .errors = self.errors,
                .warnings = self.warnings,
                .findings = out,
            }, .{ .whitespace = .indent_2 }, w);
            try w.writeAll("\n");
        },
    }
}

fn severityName(severity: rules.Severity) []const u8 {
    return if (severity == .err) "error" else "warning";
}

/// Escapes a value of a GitHub workflow command.
fn escapeGithub(w: *Io.Writer, value: []const u8, property: bool) !void {
    for (value) |c| switch (c) {
        '%' => try w.writeAll("%25"),
        '\r' => try w.writeAll("%0D"),
        '\n' => try w.writeAll("%0A"),
        ':' => if (property) try w.writeAll("%3A") else try w.writeByte(c),
        ',' => if (property) try w.writeAll("%2C") else try w.writeByte(c),
        else => try w.writeByte(c),
    };
}

fn testLinter(arena: Allocator) !Linter {
    return .{
        .arena = arena,
        .io = std.testing.io,
        .dir = Io.Dir.cwd(),
        .dict = .{ .abbreviations = &.{"MCP"}, .ing_allow = &.{"string"} },
    };
}

test "strict mode and rule settings" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var linter = try testLinter(arena_state.allocator());
    try linter.lintMarkdown("a.md", "the server stops.\n");
    try std.testing.expectEqual(1, linter.warnings);
    try std.testing.expectEqual(0, linter.errors);

    linter = try testLinter(arena_state.allocator());
    linter.strict = true;
    try linter.lintMarkdown("a.md", "the server stops.\n");
    try std.testing.expectEqual(1, linter.errors);

    linter = try testLinter(arena_state.allocator());
    try linter.setRule("PRJ-1=off");
    try linter.lintMarkdown("a.md", "the server stops.\n");
    try std.testing.expectEqual(0, linter.findings.items.len);
    try std.testing.expectError(error.InvalidRuleSetting, linter.setRule("PRJ-1=maybe"));
}

test "trailing whitespace and anchors" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var linter = try testLinter(arena_state.allocator());
    try linter.lintMarkdown("a.md", "# Title\n\nSee [the title](#title). \nSee [no](#none).\n");
    try std.testing.expectEqual(2, linter.findings.items.len);
    try std.testing.expectEqualStrings("PRJ-10", linter.findings.items[0].rule);
    try std.testing.expectEqualStrings("PRJ-9", linter.findings.items[1].rule);
}

test "zig doc comments, summaries, messages and parse errors" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var linter = try testLinter(arena_state.allocator());
    linter.string_literals = true;
    try linter.lintZig("a.zig",
        \\/// Returns the value
        \\pub fn f() void {
        \\    _ = .{ .message = "Don't stop" };
        \\}
        \\
    );
    try std.testing.expectEqual(2, linter.findings.items.len);
    try std.testing.expectEqualStrings("PRJ-7", linter.findings.items[0].rule);
    try std.testing.expectEqualStrings("STE-4.2", linter.findings.items[1].rule);

    linter = try testLinter(arena_state.allocator());
    try linter.lintZig("b.zig", "pub fn f( void {}\n");
    try std.testing.expectEqualStrings("PRJ-11", linter.findings.items[0].rule);
}

test "output formats" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var linter = try testLinter(arena_state.allocator());
    try linter.report("a,b.md", 3, "STE-8.1", .err, "semicolon: 50%");
    var aw: Io.Writer.Allocating = .init(arena_state.allocator());
    linter.format = .github;
    try linter.print(&aw.writer);
    try std.testing.expect(std.mem.startsWith(u8, aw.written(), "::error file=a%2Cb.md,line=3,title=STE-8.1::semicolon: 50%25\n"));
    aw.clearRetainingCapacity();
    linter.format = .json;
    try linter.print(&aw.writer);
    try std.testing.expect(std.mem.find(u8, aw.written(), "\"rule\": \"STE-8.1\"") != null);
}

test "page template of a wiki page" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var linter = try testLinter(arena_state.allocator());
    linter.wiki_dir = "wiki";
    try linter.checkPageTemplate("wiki/Page.md", "# Page\n\nText<sup>[1](#ref-1)</sup>.\n");
    try std.testing.expectEqual(3, linter.findings.items.len);
}
