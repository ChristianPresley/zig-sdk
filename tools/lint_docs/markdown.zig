//! The Markdown pre-pass of lint-docs. It removes code, HTML comments, quotations and
//! headings, and gives the prose as blocks: paragraphs, list items and table cells.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Procedural text has shorter sentences than descriptive text (STE-5.1 and STE-6.3).
pub const Mode = enum { descriptive, procedural };

/// The kind of a block of prose.
pub const Kind = enum { paragraph, cell };

/// A block of prose with the line where it starts.
pub const Block = struct {
    text: []const u8,
    line: usize,
    mode: Mode,
    kind: Kind,
};

/// A link target with the line of the link.
pub const Link = struct { target: []const u8, line: usize };

/// The result of the pre-pass.
pub const Document = struct {
    blocks: []const Block,
    links: []const Link,
};

/// Options of the pre-pass.
pub const Options = struct {
    /// The line number of the first line of `text`.
    first_line: usize = 1,
    /// Doc comments treat lines with four or more leading spaces as code.
    indented_code: bool = true,
};

/// Runs the pre-pass on `text`.
pub fn extract(arena: Allocator, text: []const u8, options: Options) !Document {
    var p: Parser = .{ .arena = arena };
    var fence: ?[]const u8 = null;
    var in_comment = false;
    var in_list = false;
    var line_no: usize = options.first_line - 1;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        line_no += 1;
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        const trimmed = std.mem.trim(u8, line, " \t");
        if (fence) |marker| {
            if (std.mem.startsWith(u8, trimmed, marker)) fence = null;
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, "```") or std.mem.startsWith(u8, trimmed, "~~~")) {
            try p.flush();
            fence = trimmed[0..3];
            continue;
        }
        if (in_comment) {
            if (std.mem.find(u8, trimmed, "-->") != null) in_comment = false;
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, "<!--")) {
            try p.flush();
            if (std.mem.startsWith(u8, std.mem.trimStart(u8, trimmed[4..], " "), "ste: procedural")) p.page_mode = .procedural;
            if (std.mem.find(u8, trimmed, "-->") == null) in_comment = true;
            continue;
        }
        if (trimmed.len == 0) {
            try p.flush();
            continue;
        }
        try p.collectLinks(line, line_no);
        const indent = leadingSpaces(line);
        if (trimmed[0] == '#') {
            try p.flush();
            in_list = false;
            const heading = std.mem.trim(u8, trimmed, "# \t");
            p.section_mode = if (startsWithAny(heading, &.{ "steps", "procedure", "how to" })) .procedural else .descriptive;
            continue;
        }
        if (trimmed[0] == '|') {
            try p.flush();
            try p.tableRow(trimmed, line_no);
            continue;
        }
        if (isThematicBreak(trimmed)) {
            try p.flush();
            continue;
        }
        if (trimmed[0] == '>') {
            // Quoted text, such as a quotation of the specification, is exempt.
            try p.flush();
            continue;
        }
        if (trimmed[0] == '[' and std.mem.find(u8, trimmed, "]:") != null) {
            // A footnote or a link reference definition.
            try p.flush();
            continue;
        }
        if (bulletItem(trimmed)) |rest| {
            try p.flush();
            in_list = true;
            try p.start(line_no, p.mode(), taskItem(rest));
            continue;
        }
        if (orderedItem(trimmed)) |rest| {
            try p.flush();
            in_list = true;
            try p.start(line_no, .procedural, rest);
            continue;
        }
        if (options.indented_code and indent >= 4 and p.paragraph.items.len == 0 and !in_list) continue;
        if (indent == 0 and p.paragraph.items.len == 0) in_list = false;
        if (p.paragraph.items.len == 0) {
            try p.start(line_no, p.mode(), trimmed);
        } else {
            try p.paragraph.append(arena, ' ');
            try p.paragraph.appendSlice(arena, trimmed);
        }
    }
    try p.flush();
    return .{ .blocks = p.blocks.items, .links = p.links.items };
}

const Parser = struct {
    arena: Allocator,
    blocks: std.ArrayList(Block) = .empty,
    links: std.ArrayList(Link) = .empty,
    paragraph: std.ArrayList(u8) = .empty,
    paragraph_line: usize = 0,
    paragraph_mode: Mode = .descriptive,
    page_mode: Mode = .descriptive,
    section_mode: Mode = .descriptive,
    /// The index of the first block of the last table row.
    row_start: usize = 0,

    fn mode(p: *Parser) Mode {
        return if (p.page_mode == .procedural) .procedural else p.section_mode;
    }

    fn start(p: *Parser, line: usize, m: Mode, text: []const u8) !void {
        p.paragraph_line = line;
        p.paragraph_mode = m;
        try p.paragraph.appendSlice(p.arena, text);
    }

    fn flush(p: *Parser) !void {
        if (p.paragraph.items.len == 0) return;
        try p.blocks.append(p.arena, .{
            .text = try p.arena.dupe(u8, p.paragraph.items),
            .line = p.paragraph_line,
            .mode = p.paragraph_mode,
            .kind = .paragraph,
        });
        p.paragraph.clearRetainingCapacity();
    }

    fn tableRow(p: *Parser, row: []const u8, line: usize) !void {
        var cells: std.ArrayList([]const u8) = .empty;
        var start_index: usize = 1;
        var i: usize = 1;
        var in_code = false;
        while (i < row.len) : (i += 1) {
            const c = row[i];
            if (c == '`') in_code = !in_code;
            if (c == '\\') {
                i += 1;
                continue;
            }
            if (c == '|' and !in_code) {
                try cells.append(p.arena, std.mem.trim(u8, row[start_index..i], " \t"));
                start_index = i + 1;
            }
        }
        if (start_index < row.len) try cells.append(p.arena, std.mem.trim(u8, row[start_index..], " \t"));
        // The delimiter row has only `-`, `:` and spaces.
        var delimiter = true;
        for (cells.items) |cell| {
            for (cell) |c| if (c != '-' and c != ':' and c != ' ') {
                delimiter = false;
            };
        }
        if (delimiter) {
            // The row before the delimiter row is the header row. Its cells are labels.
            p.blocks.shrinkRetainingCapacity(p.row_start);
            return;
        }
        p.row_start = p.blocks.items.len;
        for (cells.items) |cell| {
            if (cell.len == 0) continue;
            try p.blocks.append(p.arena, .{ .text = cell, .line = line, .mode = p.mode(), .kind = .cell });
        }
    }

    fn collectLinks(p: *Parser, line: []const u8, line_no: usize) !void {
        var i: usize = 0;
        var in_code = false;
        while (i < line.len) : (i += 1) {
            if (line[i] == '`') in_code = !in_code;
            if (in_code) continue;
            if (line[i] == ']' and i + 1 < line.len and line[i + 1] == '(') {
                const end = std.mem.findScalarPos(u8, line, i + 2, ')') orelse continue;
                var target = std.mem.trim(u8, line[i + 2 .. end], " ");
                // A title after the target: [text](target "title").
                if (std.mem.findScalar(u8, target, ' ')) |space| target = target[0..space];
                try p.links.append(p.arena, .{ .target = target, .line = line_no });
                i = end;
            }
        }
    }
};

fn leadingSpaces(line: []const u8) usize {
    var n: usize = 0;
    for (line) |c| switch (c) {
        ' ' => n += 1,
        '\t' => n += 4,
        else => break,
    };
    return n;
}

fn startsWithAny(text: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix| if (std.ascii.startsWithIgnoreCase(text, prefix)) return true;
    return false;
}

fn isThematicBreak(line: []const u8) bool {
    if (line.len < 3) return false;
    const c = line[0];
    if (c != '-' and c != '*' and c != '_' and c != '=') return false;
    for (line) |d| if (d != c and d != ' ') return false;
    return true;
}

fn bulletItem(line: []const u8) ?[]const u8 {
    if (line.len >= 2 and (line[0] == '-' or line[0] == '*' or line[0] == '+') and line[1] == ' ') return std.mem.trimStart(u8, line[2..], " ");
    return null;
}

fn taskItem(item: []const u8) []const u8 {
    if (item.len >= 4 and item[0] == '[' and item[2] == ']' and item[3] == ' ') return item[4..];
    return item;
}

/// Returns the text of an ordered list item such as `1. Text`, or null.
pub fn orderedItem(line: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < line.len and std.ascii.isDigit(line[i])) i += 1;
    if (i == 0 or i + 1 >= line.len) return null;
    if (line[i] != '.' and line[i] != ')') return null;
    if (line[i + 1] != ' ') return null;
    return std.mem.trimStart(u8, line[i + 2 ..], " ");
}

/// Returns every anchor of a Markdown page: the heading anchors and the `name` and `id` attributes.
pub fn anchors(arena: Allocator, text: []const u8) ![]const []const u8 {
    const slug = @import("text.zig").slug;
    var out: std.ArrayList([]const u8) = .empty;
    var fence: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const trimmed = std.mem.trim(u8, raw_line, " \t\r");
        if (fence) |marker| {
            if (std.mem.startsWith(u8, trimmed, marker)) fence = null;
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, "```") or std.mem.startsWith(u8, trimmed, "~~~")) {
            fence = trimmed[0..3];
            continue;
        }
        if (trimmed.len > 0 and trimmed[0] == '#') {
            const base = try slug(arena, std.mem.trim(u8, trimmed, "# \t"));
            // GitHub adds `-1`, `-2` and so on to a repeated anchor.
            var name = base;
            var n: usize = 1;
            while (has(out.items, name)) : (n += 1) name = try std.fmt.allocPrint(arena, "{s}-{d}", .{ base, n });
            try out.append(arena, name);
        }
        for ([_][]const u8{ "name=\"", "id=\"" }) |attr| {
            var pos: usize = 0;
            while (std.mem.findPos(u8, trimmed, pos, attr)) |i| {
                const value_start = i + attr.len;
                const end = std.mem.findScalarPos(u8, trimmed, value_start, '"') orelse break;
                try out.append(arena, trimmed[value_start..end]);
                pos = end;
            }
        }
    }
    return out.items;
}

fn has(list: []const []const u8, item: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, item)) return true;
    return false;
}

test "pre-pass removes code, comments, quotations and headings" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const doc = try extract(arena_state.allocator(),
        \\# Title
        \\
        \\<!-- ste: descriptive -->
        \\
        \\First line
        \\continues here.
        \\
        \\```zig
        \\const x = 1;
        \\```
        \\
        \\> A quotation that MUST be exempt.
        \\
        \\## Steps
        \\
        \\1. Do this.
        \\- [ ] Check [that](Other-Page).
        \\
        \\| A | B |
        \\| --- | --- |
        \\| one | two |
    , .{});
    try std.testing.expectEqual(5, doc.blocks.len);
    try std.testing.expectEqualStrings("First line continues here.", doc.blocks[0].text);
    try std.testing.expectEqual(5, doc.blocks[0].line);
    try std.testing.expectEqual(Mode.descriptive, doc.blocks[0].mode);
    try std.testing.expectEqual(Mode.procedural, doc.blocks[1].mode);
    try std.testing.expectEqualStrings("Check [that](Other-Page).", doc.blocks[2].text);
    try std.testing.expectEqual(Kind.cell, doc.blocks[3].kind);
    try std.testing.expectEqual(1, doc.links.len);
    try std.testing.expectEqualStrings("Other-Page", doc.links[0].target);
}

test "page marker sets the procedural mode" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const doc = try extract(arena_state.allocator(), "<!-- ste: procedural | reviewed: 2026-09-30 -->\n\nText.\n", .{});
    try std.testing.expectEqual(Mode.procedural, doc.blocks[0].mode);
}

test "anchors of a page" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const list = try anchors(arena_state.allocator(), "# A b\n## A b\n1. <a name=\"ref-1\"></a> x\n```\n# not\n```\n");
    try std.testing.expectEqual(3, list.len);
    try std.testing.expectEqualStrings("a-b-1", list[1]);
    try std.testing.expectEqualStrings("ref-1", list[2]);
}
