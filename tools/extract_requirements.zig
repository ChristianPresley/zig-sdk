//! The `extract-requirements` tool finds the normative sentences of the MCP specification.
//!
//! The tool reads each `.mdx` page of the vendored specification and splits the page into
//! sentences. It keeps each sentence that has an RFC 2119 keyword in uppercase. It gives
//! each sentence a stable id and writes the list to `docs/spec/requirements.zon`.
//!
//! Usage: `extract-requirements [--check] [--spec DIR] [--out PATH]`
//!
//! `--check` does not write. It fails when the file on disk is not equal to a new extraction.
//!
//! Rules of the extraction:
//! - Front matter, fenced code, `.mdx` comments, `import` and `export` lines and tag-only
//!   lines are not prose. The tool removes tags inside prose and keeps their text.
//! - Each paragraph, list item and table cell is split into sentences.
//! - A sentence with a keyword that ends with a colon and has a nested list after it is a
//!   stem. Each item of the list without its own keyword becomes one requirement, with the
//!   stem in front of it.
//! - A keyword in double quotes or in a code span is a mention and does not count.
//! - The id is `<page>#<ordinal>-<hash>`. The ordinal counts the requirements of the page
//!   from 001. The hash is the first six hex digits of the SHA-256 of the sentence text.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Level = enum { must, must_not, should, should_not, may };

pub const Party = enum { client, server, both, authorization_server };

pub const Requirement = struct {
    id: []const u8,
    page: []const u8,
    line: usize,
    section: []const u8,
    anchor: []const u8,
    level: Level,
    keywords: []const []const u8,
    party: Party,
    text: []const u8,
};

const Upstream = struct {
    repo: []const u8,
    commit: []const u8,
    path: []const u8,
    fetched: []const u8 = "",
};

const default_spec_dir = "test/fixtures/mcp_spec_2026_07_28";
const default_out = "docs/spec/requirements.zon";

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    var check = false;
    var spec_dir: []const u8 = default_spec_dir;
    var out_path: []const u8 = default_out;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--check")) {
            check = true;
        } else if (std.mem.eql(u8, args[i], "--spec") and i + 1 < args.len) {
            i += 1;
            spec_dir = args[i];
        } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else {
            std.debug.print("extract-requirements: unknown argument {s}\n", .{args[i]});
            return 2;
        }
    }

    const cwd = Io.Dir.cwd();
    const upstream_path = try std.fs.path.join(arena, &.{ spec_dir, "UPSTREAM.zon" });
    const upstream_text = try cwd.readFileAllocOptions(io, upstream_path, arena, .limited(64 << 10), .of(u8), 0);
    const upstream = try std.zon.parse.fromSliceAlloc(Upstream, arena, upstream_text, null, .{ .ignore_unknown_fields = true });

    // Collect the pages in a stable order.
    var pages: std.ArrayList([]const u8) = .empty;
    {
        var dir = try cwd.openDir(io, spec_dir, .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(arena);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".mdx")) continue;
            const rel = try arena.dupe(u8, entry.path);
            std.mem.replaceScalar(u8, rel, '\\', '/');
            try pages.append(arena, rel);
        }
    }
    std.mem.sort([]const u8, pages.items, {}, lessThanString);

    var all: std.ArrayList(Requirement) = .empty;
    for (pages.items) |rel| {
        const full = try std.fs.path.join(arena, &.{ spec_dir, rel });
        const text = try cwd.readFileAlloc(io, full, arena, .limited(4 << 20));
        try extractPage(arena, pageSlug(rel), text, &all);
    }

    const rendered = try render(arena, upstream, spec_dir, all.items);

    var counts = [_]usize{0} ** @typeInfo(Level).@"enum".fields.len;
    for (all.items) |r| counts[@intFromEnum(r.level)] += 1;
    std.debug.print("extract-requirements: {d} pages, {d} requirements (must {d}, must_not {d}, should {d}, should_not {d}, may {d})\n", .{
        pages.items.len, all.items.len, counts[0], counts[1], counts[2], counts[3], counts[4],
    });

    if (check) {
        const current = cwd.readFileAlloc(io, out_path, arena, .limited(16 << 20)) catch |e| {
            std.debug.print("::error file={s}::cannot read the requirements file: {t}. Run zig build extract-requirements.\n", .{ out_path, e });
            return 1;
        };
        if (!std.mem.eql(u8, std.mem.trimEnd(u8, current, "\r\n"), std.mem.trimEnd(u8, rendered, "\r\n")) and
            !eqlIgnoringCr(current, rendered))
        {
            std.debug.print("::error file={s}::the requirements file is out of date. Run zig build extract-requirements.\n", .{out_path});
            return 1;
        }
        std.debug.print("extract-requirements: {s} is up to date\n", .{out_path});
        return 0;
    }
    if (std.fs.path.dirname(out_path)) |parent| try cwd.createDirPath(io, parent);
    try cwd.writeFile(io, .{ .sub_path = out_path, .data = rendered });
    std.debug.print("extract-requirements: wrote {s}\n", .{out_path});
    return 0;
}

fn eqlIgnoringCr(a: []const u8, b: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (true) {
        while (i < a.len and a[i] == '\r') i += 1;
        while (j < b.len and b[j] == '\r') j += 1;
        if (i == a.len or j == b.len) return i == a.len and j == b.len;
        if (a[i] != b[j]) return false;
        i += 1;
        j += 1;
    }
}

fn lessThanString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// The slug of a page: the path without `.mdx`, and without a last `/index` part.
pub fn pageSlug(rel: []const u8) []const u8 {
    var slug = rel;
    if (std.mem.endsWith(u8, slug, ".mdx")) slug = slug[0 .. slug.len - 4];
    if (std.mem.endsWith(u8, slug, "/index")) slug = slug[0 .. slug.len - "/index".len];
    return slug;
}

// ----------------------------------------------------------------------------------------
// Block structure
// ----------------------------------------------------------------------------------------

const UnitKind = enum { heading, para, item, row, separator };

const Unit = struct {
    kind: UnitKind,
    /// Column of the first character. Paragraphs outside lists use the column too.
    indent: usize,
    line: usize,
    text: std.ArrayList(u8) = .empty,
};

fn leadingColumns(line: []const u8) usize {
    var n: usize = 0;
    for (line) |c| switch (c) {
        ' ' => n += 1,
        '\t' => n += 4,
        else => break,
    };
    return n;
}

fn listMarker(trimmed: []const u8) ?[]const u8 {
    if (trimmed.len >= 2 and (trimmed[0] == '-' or trimmed[0] == '*' or trimmed[0] == '+') and trimmed[1] == ' ')
        return std.mem.trimStart(u8, trimmed[2..], " ");
    var i: usize = 0;
    while (i < trimmed.len and std.ascii.isDigit(trimmed[i])) i += 1;
    if (i == 0 or i > 3 or i + 1 >= trimmed.len) return null;
    if (trimmed[i] != '.' and trimmed[i] != ')') return null;
    if (trimmed[i + 1] != ' ') return null;
    return std.mem.trimStart(u8, trimmed[i + 2 ..], " ");
}

/// True when the line has only tags and white space.
fn tagOnly(trimmed: []const u8) bool {
    if (trimmed.len < 2 or trimmed[0] != '<') return false;
    if (!(std.ascii.isAlphabetic(trimmed[1]) or trimmed[1] == '/')) return false;
    var i: usize = 0;
    while (i < trimmed.len) {
        if (trimmed[i] == ' ' or trimmed[i] == '\t') {
            i += 1;
            continue;
        }
        if (trimmed[i] != '<') return false;
        const close = std.mem.findScalarPos(u8, trimmed, i, '>') orelse return false;
        i = close + 1;
    }
    return true;
}

fn isRule(trimmed: []const u8) bool {
    if (trimmed.len < 3) return false;
    for (trimmed) |c| if (c != '-' and c != '*' and c != '_' and c != ' ') return false;
    return true;
}

fn parseUnits(arena: Allocator, text: []const u8) ![]Unit {
    var units: std.ArrayList(Unit) = .empty;
    var open: ?usize = null; // index of the open paragraph or list item
    var fence: ?[]const u8 = null;
    var in_tag = false;
    var in_comment = false;
    var in_mdx_comment = false;
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');

    // Front matter.
    if (std.mem.startsWith(u8, text, "---")) {
        _ = lines.next();
        line_no += 1;
        while (lines.next()) |l| {
            line_no += 1;
            if (std.mem.eql(u8, std.mem.trimEnd(u8, l, "\r"), "---")) break;
        }
    }

    while (lines.next()) |raw| {
        line_no += 1;
        const line = std.mem.trimEnd(u8, raw, "\r \t");
        const trimmed = std.mem.trimStart(u8, line, " \t");
        const indent = leadingColumns(line);

        if (fence) |marker| {
            if (std.mem.startsWith(u8, trimmed, marker) and std.mem.trim(u8, trimmed, marker[0..1]).len == 0) fence = null;
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, "```") or std.mem.startsWith(u8, trimmed, "~~~")) {
            var n: usize = 0;
            while (n < trimmed.len and trimmed[n] == trimmed[0]) n += 1;
            fence = trimmed[0..n];
            open = null;
            try units.append(arena, .{ .kind = .separator, .indent = indent, .line = line_no });
            continue;
        }
        if (in_comment) {
            if (std.mem.find(u8, trimmed, "-->") != null) in_comment = false;
            continue;
        }
        if (in_mdx_comment) {
            if (std.mem.find(u8, trimmed, "*/}") != null) in_mdx_comment = false;
            continue;
        }
        if (in_tag) {
            if (std.mem.findScalar(u8, trimmed, '>') != null) in_tag = false;
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, "<!--")) {
            if (std.mem.find(u8, trimmed, "-->") == null) in_comment = true;
            open = null;
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, "{/*")) {
            if (std.mem.find(u8, trimmed, "*/}") == null) in_mdx_comment = true;
            open = null;
            continue;
        }
        if (trimmed.len == 0) {
            open = null;
            continue;
        }
        if (indent == 0 and (std.mem.startsWith(u8, trimmed, "import ") or std.mem.startsWith(u8, trimmed, "export "))) {
            open = null;
            continue;
        }
        // A tag that opens on this line and closes on a later line.
        if (trimmed[0] == '<' and trimmed.len > 1 and std.ascii.isAlphabetic(trimmed[1]) and std.mem.findScalar(u8, trimmed, '>') == null) {
            in_tag = true;
            open = null;
            try units.append(arena, .{ .kind = .separator, .indent = indent, .line = line_no });
            continue;
        }
        if (tagOnly(trimmed) or isRule(trimmed)) {
            open = null;
            try units.append(arena, .{ .kind = .separator, .indent = indent, .line = line_no });
            continue;
        }
        if (trimmed[0] == '#') {
            var n: usize = 0;
            while (n < trimmed.len and trimmed[n] == '#') n += 1;
            if (n <= 6 and n < trimmed.len and trimmed[n] == ' ') {
                open = null;
                var u: Unit = .{ .kind = .heading, .indent = indent, .line = line_no };
                try u.text.appendSlice(arena, std.mem.trim(u8, trimmed[n..], " #"));
                try units.append(arena, u);
                continue;
            }
        }
        if (trimmed[0] == '|') {
            open = null;
            var sep = true;
            for (trimmed) |c| if (c != '|' and c != '-' and c != ':' and c != ' ') {
                sep = false;
                break;
            };
            if (sep) continue;
            var u: Unit = .{ .kind = .row, .indent = indent, .line = line_no };
            try u.text.appendSlice(arena, trimmed);
            try units.append(arena, u);
            continue;
        }
        var body = trimmed;
        if (std.mem.startsWith(u8, body, "> ")) body = body[2..] else if (std.mem.eql(u8, body, ">")) continue;
        if (listMarker(body)) |rest| {
            var u: Unit = .{ .kind = .item, .indent = indent, .line = line_no };
            try u.text.appendSlice(arena, rest);
            try units.append(arena, u);
            open = units.items.len - 1;
            continue;
        }
        if (open) |o| {
            try units.items[o].text.append(arena, ' ');
            try units.items[o].text.appendSlice(arena, body);
            continue;
        }
        var u: Unit = .{ .kind = .para, .indent = indent, .line = line_no };
        try u.text.appendSlice(arena, body);
        try units.append(arena, u);
        open = units.items.len - 1;
    }
    return units.items;
}

// ----------------------------------------------------------------------------------------
// Inline text
// ----------------------------------------------------------------------------------------

/// Removes emphasis, link targets, images, tags and entities. Keeps code spans as they are
/// and collapses white space.
pub fn normalize(arena: Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try normalizeInto(arena, &out, s);
    // Collapse white space.
    var collapsed: std.ArrayList(u8) = .empty;
    var space = true;
    for (out.items) |c| {
        const ws = c == ' ' or c == '\t' or c == '\n';
        if (ws) {
            if (!space) try collapsed.append(arena, ' ');
            space = true;
        } else {
            try collapsed.append(arena, c);
            space = false;
        }
    }
    return std.mem.trim(u8, collapsed.items, " ");
}

fn normalizeInto(arena: Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        switch (c) {
            '`' => {
                var n: usize = 0;
                while (i + n < s.len and s[i + n] == '`') n += 1;
                const ticks = s[i .. i + n];
                if (std.mem.findPos(u8, s, i + n, ticks)) |end| {
                    try out.appendSlice(arena, s[i .. end + n]);
                    i = end + n;
                } else {
                    try out.appendSlice(arena, ticks);
                    i += n;
                }
            },
            '*' => i += 1,
            '_' => {
                // Emphasis with underscores opens before a word or closes after a word.
                const before = i > 0 and std.ascii.isAlphanumeric(s[i - 1]);
                const after = i + 1 < s.len and std.ascii.isAlphanumeric(s[i + 1]);
                if (before != after) {
                    i += 1;
                } else {
                    try out.append(arena, c);
                    i += 1;
                }
            },
            '\\' => {
                if (i + 1 < s.len) try out.append(arena, s[i + 1]);
                i += 2;
            },
            '!' => {
                if (i + 1 < s.len and s[i + 1] == '[') {
                    if (linkEnd(s, i + 1)) |l| {
                        i = l.end;
                        continue;
                    }
                }
                try out.append(arena, c);
                i += 1;
            },
            '[' => {
                if (linkEnd(s, i)) |l| {
                    try normalizeInto(arena, out, s[i + 1 .. l.text_end]);
                    i = l.end;
                } else {
                    try out.append(arena, c);
                    i += 1;
                }
            },
            '<' => {
                if (i + 1 < s.len and (std.ascii.isAlphabetic(s[i + 1]) or s[i + 1] == '/' or s[i + 1] == '!')) {
                    if (std.mem.findScalarPos(u8, s, i, '>')) |close| {
                        const inner = s[i + 1 .. close];
                        if (std.mem.find(u8, inner, "://") != null and std.mem.findScalar(u8, inner, ' ') == null) {
                            try out.appendSlice(arena, inner);
                        } else if (std.mem.eql(u8, inner, "sup")) {
                            try out.append(arena, '^');
                        } else if (std.mem.eql(u8, inner, "/sup") or std.mem.eql(u8, inner, "sub") or std.mem.eql(u8, inner, "/sub")) {
                            // Inline tags join to the text around them.
                        } else {
                            try out.append(arena, ' ');
                        }
                        i = close + 1;
                        continue;
                    }
                }
                try out.append(arena, c);
                i += 1;
            },
            '&' => {
                const entities = [_][2][]const u8{
                    .{ "&lt;", "<" },  .{ "&gt;", ">" },   .{ "&amp;", "&" },  .{ "&quot;", "\"" },
                    .{ "&#39;", "'" }, .{ "&nbsp;", " " }, .{ "&#x7B;", "{" }, .{ "&#x7D;", "}" },
                };
                for (entities) |e| {
                    if (std.mem.startsWith(u8, s[i..], e[0])) {
                        try out.appendSlice(arena, e[1]);
                        i += e[0].len;
                        break;
                    }
                } else {
                    try out.append(arena, c);
                    i += 1;
                }
            },
            else => {
                try out.append(arena, c);
                i += 1;
            },
        }
    }
}

const LinkEnd = struct { text_end: usize, end: usize };

/// Finds the end of `[text](target)` that starts at `start`.
fn linkEnd(s: []const u8, start: usize) ?LinkEnd {
    var depth: usize = 0;
    var i = start;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if (depth == 0) break;
            },
            '`' => {
                const end = std.mem.findScalarPos(u8, s, i + 1, '`') orelse return null;
                i = end;
            },
            else => {},
        }
    } else return null;
    const text_end = i;
    if (text_end + 1 >= s.len or s[text_end + 1] != '(') return null;
    var parens: usize = 0;
    var j = text_end + 1;
    while (j < s.len) : (j += 1) {
        switch (s[j]) {
            '(' => parens += 1,
            ')' => {
                parens -= 1;
                if (parens == 0) return .{ .text_end = text_end, .end = j + 1 };
            },
            else => {},
        }
    }
    return null;
}

const abbreviations = [_][]const u8{ "e.g", "i.e", "etc", "vs", "cf", "approx", "Fig", "No", "Sec" };

fn isAbbreviation(before: []const u8) bool {
    var k = before.len;
    while (k > 0 and before[k - 1] != ' ' and before[k - 1] != '(') k -= 1;
    const word = before[k..];
    if (word.len == 1 and std.ascii.isAlphabetic(word[0])) return true;
    for (abbreviations) |a| if (std.mem.eql(u8, word, a)) return true;
    return false;
}

/// Splits normalized text into sentences.
pub fn splitSentences(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var start: usize = 0;
    var in_code = false;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '`') {
            in_code = !in_code;
            continue;
        }
        if (in_code) continue;
        if (c != '.' and c != '!' and c != '?') continue;
        var j = i + 1;
        while (j < text.len and (text[j] == ')' or text[j] == '"' or text[j] == '\'')) j += 1;
        if (j + 1 >= text.len or text[j] != ' ') continue;
        const next = text[j + 1];
        if (!(std.ascii.isUpper(next) or next == '`' or next == '[' or next == '(' or next == '"')) continue;
        if (c == '.' and isAbbreviation(text[start..i])) continue;
        const sentence = std.mem.trim(u8, text[start..j], " ");
        if (sentence.len > 0) try out.append(arena, sentence);
        start = j + 1;
        i = j;
    }
    const rest = std.mem.trim(u8, text[start..], " ");
    if (rest.len > 0) try out.append(arena, rest);
    return out.items;
}

// ----------------------------------------------------------------------------------------
// Keywords and parties
// ----------------------------------------------------------------------------------------

pub const Keywords = struct {
    list: []const []const u8,
    level: Level,
    /// Byte offset of the first keyword in the sentence.
    first: usize,
};

fn levelOf(keyword: []const u8) Level {
    const map = [_]struct { []const u8, Level }{
        .{ "MUST NOT", .must_not },  .{ "SHALL NOT", .must_not },    .{ "MUST", .must },                  .{ "REQUIRED", .must },
        .{ "SHALL", .must },         .{ "SHOULD NOT", .should_not }, .{ "NOT RECOMMENDED", .should_not }, .{ "SHOULD", .should },
        .{ "RECOMMENDED", .should }, .{ "MAY", .may },               .{ "OPTIONAL", .may },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], keyword)) return m[1];
    unreachable;
}

fn levelClass(level: Level) u8 {
    return switch (level) {
        .must, .must_not => 0,
        .should, .should_not => 1,
        .may => 2,
    };
}

fn isWordByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// Finds the RFC 2119 keywords of a sentence. Returns null when it has none.
pub fn findKeywords(arena: Allocator, s: []const u8) !?Keywords {
    var list: std.ArrayList([]const u8) = .empty;
    var level: ?Level = null;
    var first: usize = 0;
    var in_code = false;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '`') {
            in_code = !in_code;
            i += 1;
            continue;
        }
        if (in_code or !std.ascii.isUpper(c) or (i > 0 and isWordByte(s[i - 1]))) {
            i += 1;
            continue;
        }
        var e = i;
        while (e < s.len and std.ascii.isUpper(s[e])) e += 1;
        // A word inside an identifier or joined by a hyphen, such as "SHOULD-constrained",
        // is a mention.
        if (e < s.len and (isWordByte(s[e]) or (s[e] == '-' and e + 1 < s.len and std.ascii.isAlphabetic(s[e + 1])))) {
            i = e;
            continue;
        }
        const word = s[i..e];
        var phrase_end = e;
        var phrase: ?[]const u8 = null;
        const two = [_][2][]const u8{ .{ "MUST", "NOT" }, .{ "SHALL", "NOT" }, .{ "SHOULD", "NOT" }, .{ "NOT", "RECOMMENDED" } };
        for (two) |t| {
            if (std.mem.eql(u8, word, t[0]) and std.mem.startsWith(u8, s[e..], " ") and std.mem.startsWith(u8, s[e + 1 ..], t[1])) {
                const after = e + 1 + t[1].len;
                if (after == s.len or !isWordByte(s[after])) {
                    phrase = try std.fmt.allocPrint(arena, "{s} {s}", .{ t[0], t[1] });
                    phrase_end = after;
                    break;
                }
            }
        }
        if (phrase == null) {
            const single = [_][]const u8{ "MUST", "REQUIRED", "SHALL", "SHOULD", "RECOMMENDED", "MAY", "OPTIONAL" };
            for (single) |k| if (std.mem.eql(u8, word, k)) {
                phrase = k;
                break;
            };
        }
        if (phrase) |p| {
            const quoted = (i > 0 and s[i - 1] == '"') or (phrase_end < s.len and s[phrase_end] == '"');
            if (!quoted) {
                const lv = levelOf(p);
                if (level == null or levelClass(lv) < levelClass(level.?)) {
                    level = lv;
                }
                if (list.items.len == 0) first = i;
                var seen = false;
                for (list.items) |k| if (std.mem.eql(u8, k, p)) {
                    seen = true;
                };
                if (!seen) try list.append(arena, p);
            }
        }
        i = phrase_end;
    }
    if (level) |lv| return .{ .list = list.items, .level = lv, .first = first };
    return null;
}

const Role = struct { party: Party, pos: usize, end: usize };

fn nextRole(lower: []const u8, from: usize) ?Role {
    const patterns = [_]struct { []const u8, Party }{
        .{ "authorization server", .authorization_server },
        .{ "resource server", .server },
        .{ "server", .server },
        .{ "client", .client },
        .{ "host", .client },
        .{ "application", .client },
        .{ "user agent", .client },
        .{ "implementation", .both },
        .{ "implementor", .both },
        .{ "sender", .both },
        .{ "receiver", .both },
        .{ "recipient", .both },
        .{ "both parties", .both },
        .{ "either party", .both },
        .{ "parties", .both },
        .{ "peer", .both },
    };
    var best: ?Role = null;
    for (patterns) |p| {
        var at = from;
        while (std.mem.findPos(u8, lower, at, p[0])) |pos| {
            at = pos + 1;
            // Whole words only. A plural "s" is part of the word.
            if (pos > 0 and std.ascii.isAlphanumeric(lower[pos - 1])) continue;
            var end = pos + p[0].len;
            if (end < lower.len and lower[end] == 's') end += 1;
            if (end < lower.len and std.ascii.isAlphanumeric(lower[end])) continue;
            if (best == null or pos < best.?.pos or (pos == best.?.pos and p[0].len > best.?.end - best.?.pos)) {
                best = .{ .party = p[1], .pos = pos, .end = pos + p[0].len };
            }
            break;
        }
    }
    return best;
}

/// Finds the party that a requirement binds, from the subject before the first keyword.
pub fn partyOf(arena: Allocator, sentence: []const u8, first_keyword: usize, page: []const u8) !Party {
    const prefix = try std.ascii.allocLowerString(arena, sentence[0..first_keyword]);
    // Code spans are not subjects.
    var clean: std.ArrayList(u8) = .empty;
    var in_code = false;
    for (prefix) |c| {
        if (c == '`') {
            in_code = !in_code;
            try clean.append(arena, ' ');
            continue;
        }
        try clean.append(arena, if (in_code) ' ' else c);
    }
    const text = clean.items;
    // The main clause starts after the last comma.
    const clause_start = if (std.mem.findLast(u8, text, ", ")) |k| k + 2 else 0;
    if (nextRole(text, clause_start)) |role| {
        if (nextRole(text, role.end)) |other| {
            var gap = std.mem.trim(u8, text[role.end..other.pos], " s,");
            for ([_][]const u8{ " mcp", " the" }) |filler| {
                if (std.mem.endsWith(u8, gap, filler)) gap = gap[0 .. gap.len - filler.len];
            }
            const joined = std.mem.eql(u8, gap, "and") or std.mem.eql(u8, gap, "or") or std.mem.eql(u8, gap, "and/or");
            if (joined and other.party != role.party) return .both;
        }
        return role.party;
    }
    // No subject in the main clause: use the last role before it.
    var last: ?Role = null;
    var at: usize = 0;
    while (nextRole(text, at)) |role| {
        last = role;
        at = role.end;
    }
    if (last) |role| return role.party;
    if (std.mem.startsWith(u8, page, "client/")) return .client;
    if (std.mem.startsWith(u8, page, "server/")) return .server;
    return .both;
}

// ----------------------------------------------------------------------------------------
// Pages
// ----------------------------------------------------------------------------------------

/// The heading anchor as the specification site makes it.
pub fn anchorOf(arena: Allocator, heading: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (heading) |c| {
        if (std.ascii.isAlphanumeric(c)) {
            try out.append(arena, std.ascii.toLower(c));
        } else if (c == ' ' or c == '-') {
            try out.append(arena, '-');
        } else if (c == '_') {
            try out.append(arena, '_');
        }
    }
    return out.items;
}

const Stem = struct {
    indent: isize,
    text: []const u8,
    has_keyword: bool,
};

const PageState = struct {
    arena: Allocator,
    slug: []const u8,
    section: []const u8 = "",
    anchor: []const u8 = "",
    ordinal: usize = 0,
    out: *std.ArrayList(Requirement),

    fn emit(self: *PageState, text: []const u8, kw: Keywords, line: usize) !void {
        try self.emitWithSubject(text, kw, line, text, kw.first);
    }

    /// `subject_text` and `subject_end` give the words that name the party.
    fn emitWithSubject(self: *PageState, text: []const u8, kw: Keywords, line: usize, subject_text: []const u8, subject_end: usize) !void {
        self.ordinal += 1;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(text, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        const id = try std.fmt.allocPrint(self.arena, "{s}#{d:0>3}-{s}", .{ self.slug, self.ordinal, hex[0..6] });
        try self.out.append(self.arena, .{
            .id = id,
            .page = self.slug,
            .line = line,
            .section = self.section,
            .anchor = self.anchor,
            .level = kw.level,
            .keywords = kw.list,
            .party = try partyOf(self.arena, subject_text, subject_end, self.slug),
            .text = text,
        });
    }
};

fn isStem(sentence: []const u8) bool {
    return sentence.len > 0 and sentence[sentence.len - 1] == ':';
}

fn nextIsChildItem(units: []const Unit, index: usize, indent: isize) bool {
    if (index + 1 >= units.len) return false;
    const next = units[index + 1];
    return next.kind == .item and @as(isize, @intCast(next.indent)) > indent;
}

pub fn extractPage(arena: Allocator, slug: []const u8, text: []const u8, out: *std.ArrayList(Requirement)) !void {
    const units = try parseUnits(arena, text);
    var state: PageState = .{ .arena = arena, .slug = slug, .out = out };
    var stems: std.ArrayList(Stem) = .empty;

    for (units, 0..) |unit, index| {
        switch (unit.kind) {
            .separator => {},
            .heading => {
                stems.clearRetainingCapacity();
                state.section = try normalize(arena, unit.text.items);
                state.anchor = try anchorOf(arena, state.section);
            },
            .row => {
                var cells: std.ArrayList([]const u8) = .empty;
                var it = std.mem.splitScalar(u8, std.mem.trim(u8, unit.text.items, "| "), '|');
                while (it.next()) |cell| try cells.append(arena, try normalize(arena, cell));
                if (cells.items.len == 0) continue;
                const label = cells.items[0];
                for (cells.items, 0..) |cell, ci| {
                    for (try splitSentences(arena, cell)) |sentence| {
                        const kw = try findKeywords(arena, sentence) orelse continue;
                        if (ci == 0) {
                            try state.emit(sentence, kw, unit.line);
                        } else {
                            const joined = try std.fmt.allocPrint(arena, "{s}: {s}", .{ label, sentence });
                            const kw2 = (try findKeywords(arena, joined)).?;
                            // The row label is not the subject of the cell.
                            try state.emitWithSubject(joined, kw2, unit.line, sentence, kw.first);
                        }
                    }
                }
            },
            .para, .item => {
                const indent: isize = if (unit.kind == .para) -1 else @intCast(unit.indent);
                if (unit.kind == .para and unit.indent == 0) stems.clearRetainingCapacity();
                if (unit.kind == .item) {
                    while (stems.items.len > 0 and stems.items[stems.items.len - 1].indent >= indent) _ = stems.pop();
                }
                const normalized = try normalize(arena, unit.text.items);
                const sentences = try splitSentences(arena, normalized);
                for (sentences, 0..) |sentence, si| {
                    var text_out = sentence;
                    var kw = try findKeywords(arena, sentence);
                    if (si == 0 and unit.kind == .item and stems.items.len > 0) {
                        // The stem gives the keyword, or the subject of an item that starts with
                        // a keyword.
                        const stem = stems.items[stems.items.len - 1];
                        const compose = if (kw) |k| k.first == 0 else stem.has_keyword;
                        if (compose) {
                            text_out = try std.fmt.allocPrint(arena, "{s} {s}", .{ stem.text, sentence });
                            kw = try findKeywords(arena, text_out);
                        }
                    }
                    const last = si + 1 == sentences.len;
                    if (last and isStem(text_out) and nextIsChildItem(units, index, indent)) {
                        // A stem: its list items carry the requirement.
                        try stems.append(arena, .{ .indent = indent, .text = text_out, .has_keyword = kw != null });
                        continue;
                    }
                    if (kw) |k| try state.emit(text_out, k, unit.line);
                }
            },
        }
    }
}

// ----------------------------------------------------------------------------------------
// Output
// ----------------------------------------------------------------------------------------

fn render(arena: Allocator, upstream: Upstream, spec_dir: []const u8, reqs: []const Requirement) ![]const u8 {
    var aw: Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("// Generated by zig build extract-requirements. Do not edit.\n");
    try w.writeAll("// Each entry is one normative sentence of the MCP specification, quoted from the\n");
    try w.print("// licensed fixture {s}. Map each id in docs/spec/requirement_tests.zon.\n", .{spec_dir});
    try w.writeAll(".{\n");
    try w.print("    .repo = \"{f}\",\n", .{std.zig.fmtString(upstream.repo)});
    try w.print("    .commit = \"{f}\",\n", .{std.zig.fmtString(upstream.commit)});
    try w.print("    .path = \"{f}\",\n", .{std.zig.fmtString(upstream.path)});
    try w.print("    .fixture = \"{f}\",\n", .{std.zig.fmtString(spec_dir)});
    try w.writeAll("    .requirements = .{\n");
    for (reqs) |r| {
        try w.writeAll("        .{\n");
        try w.print("            .id = \"{f}\",\n", .{std.zig.fmtString(r.id)});
        try w.print("            .page = \"{f}\",\n", .{std.zig.fmtString(r.page)});
        try w.print("            .line = {d},\n", .{r.line});
        try w.print("            .section = \"{f}\",\n", .{std.zig.fmtString(r.section)});
        try w.print("            .anchor = \"{f}\",\n", .{std.zig.fmtString(r.anchor)});
        try w.print("            .level = .{t},\n", .{r.level});
        try w.writeAll("            .keywords = .{");
        for (r.keywords, 0..) |k, ki| {
            if (ki > 0) try w.writeAll(", ");
            try w.print("\"{f}\"", .{std.zig.fmtString(k)});
        }
        try w.writeAll("},\n");
        try w.print("            .party = .{t},\n", .{r.party});
        try w.print("            .text = \"{f}\",\n", .{std.zig.fmtString(r.text)});
        try w.writeAll("        },\n");
    }
    try w.writeAll("    },\n}\n");
    return aw.toOwnedSlice();
}

// ----------------------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------------------

test "sentences split at a stop before an uppercase letter only" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const s = try splitSentences(arena, "Clients MUST send it, e.g. `x.y`. Servers MAY stop. Version 1.2 is old.");
    try std.testing.expectEqual(3, s.len);
    try std.testing.expectEqualStrings("Clients MUST send it, e.g. `x.y`.", s[0]);
}

test "keywords, quotes and code spans" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const k = (try findKeywords(arena, "Servers MAY cache and MUST NOT share it.")).?;
    try std.testing.expectEqual(Level.must_not, k.level);
    try std.testing.expectEqual(2, k.list.len);
    try std.testing.expect(try findKeywords(arena, "The words \"MUST\" and \"SHOULD NOT\" are defined.") == null);
    try std.testing.expect(try findKeywords(arena, "Use `MUST_HAVE` here.") == null);
    try std.testing.expect(try findKeywords(arena, "MUSTARD is not a keyword.") == null);
}

test "normalize removes emphasis, links and tags" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const n = try normalize(arena, "Servers **MUST** read [the spec](/x/y) <br/> and `a*b`.");
    try std.testing.expectEqualStrings("Servers MUST read the spec and `a*b`.", n);
}

test "a stem distributes over its list items" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(Requirement) = .empty;
    const page =
        \\---
        \\title: T
        \\---
        \\## Rules
        \\
        \\Clients **MUST**:
        \\
        \\- check the input
        \\- log the error
        \\
        \\Servers **SHOULD** declare it:
        \\
        \\```json
        \\{ "MUST": 1 }
        \\```
    ;
    try extractPage(arena, "client/x", page, &out);
    try std.testing.expectEqual(3, out.items.len);
    try std.testing.expectEqualStrings("Clients MUST: check the input", out.items[0].text);
    try std.testing.expectEqual(Party.client, out.items[0].party);
    try std.testing.expectEqualStrings("Servers SHOULD declare it:", out.items[2].text);
    try std.testing.expectEqual(Party.server, out.items[2].party);
    try std.testing.expectEqualStrings("rules", out.items[0].anchor);
    try std.testing.expect(std.mem.startsWith(u8, out.items[0].id, "client/x#001-"));
}

test "party from the main clause" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cases = [_]struct { []const u8, Party }{
        .{ "When a client sends it, the server MUST", .server },
        .{ "Servers receiving requests from clients MUST", .server },
        .{ "Clients and servers MUST", .both },
        .{ "Authorization servers MUST", .authorization_server },
        .{ "The `client_id` MUST", .both },
    };
    for (cases) |c| {
        const pos = std.mem.find(u8, c[0], "MUST").?;
        try std.testing.expectEqual(c[1], try partyOf(arena, c[0], pos, "basic"));
    }
}
