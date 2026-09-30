//! lint-docs: checks prose against the project ASD-STE100 profile.
//!
//! Checked surfaces: Markdown files and `///`/`//!` doc comments in Zig files. Rules are
//! cited by ASD-STE100 Issue 9 rule number; no rule text of the standard is reproduced.
//!
//! Usage: lint-docs [--format text|github] [--strict] [--wiki-dir DIR] [--rule ID=off] PATH...
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const max_words_procedural = 20; // STE-5.1
const max_words_descriptive = 25; // STE-6.3
const max_sentences_per_paragraph = 6; // STE-6.6

const contractions = [_][]const u8{
    "don't",    "doesn't",   "didn't",   "isn't",   "aren't", "wasn't",  "weren't", "can't", "cannot't", "won't",
    "wouldn't", "shouldn't", "couldn't", "mustn't", "hasn't", "haven't", "hadn't",  "it's",  "that's",   "there's",
    "here's",   "what's",    "who's",    "let's",   "you're", "we're",   "they're", "i'm",   "i've",     "you've",
    "we've",    "they've",   "i'll",     "you'll",  "we'll",  "they'll", "it'll",   "i'd",   "you'd",    "we'd",
};

const latin = [_][]const u8{ "e.g.", "i.e.", "etc.", "etc", "vs.", "viz.", "et al.", "cf.", "n.b." };

const pronouns = [_][]const u8{ "he", "she", "him", "his", "hers", "himself", "herself" };

const auxiliary_chains = [_][]const u8{
    "would have been", "could have been", "should have been", "might have been", "has been",   "have been", "had been",
    "will have",       "would have",      "could have",       "should have",     "might have", "being",
};

const passive_verbs = [_][]const u8{ "is", "are", "was", "were", "be", "been", "being" };

/// Words that end in "ing" but are approved technical nouns or adjectives in this project.
const default_ing_allowlist = [_][]const u8{
    "string",     "logging",   "streaming",  "encoding",  "decoding", "setting",  "settings", "listing",  "nothing",
    "something",  "anything",  "everything", "during",    "thing",    "things",   "ring",     "spring",   "bring",
    "morning",    "warning",   "warnings",   "heading",   "headings", "building", "meaning",  "meaning",  "sampling",
    "processing", "handling",  "training",   "rebinding", "signing",  "framing",  "padding",  "pending",  "binding",
    "bindings",   "matching",  "caching",    "testing",   "spelling", "wording",  "counting", "timing",   "indexing",
    "hashing",    "tooling",   "sizing",     "leading",   "trailing", "ordering", "naming",   "existing", "following",
    "including",  "remaining", "underlying", "incoming",  "outgoing", "missing",  "pinging",  "polling",  "clearing",
    "reading",    "writing",   "buffering",  "swing",     "king",     "wing",     "sing",
};

const Format = enum { text, github };

const Severity = enum { err, warn };

const Finding = struct {
    file: []const u8,
    line: usize,
    rule: []const u8,
    severity: Severity,
    message: []const u8,
};

const Mode = enum { descriptive, procedural };

const Sentence = struct {
    text: []const u8,
    line: usize,
    mode: Mode,
};

const Linter = struct {
    arena: Allocator,
    io: Io,
    format: Format,
    strict: bool,
    findings: std.ArrayList(Finding) = .empty,
    disabled: std.ArrayList([]const u8) = .empty,
    banned: std.ArrayList(Banned) = .empty,
    ing_allow: std.ArrayList([]const u8) = .empty,
    errors: usize = 0,
    warnings: usize = 0,
    files: usize = 0,

    const Banned = struct { word: []const u8, replacement: []const u8, rule: []const u8 };

    fn ruleEnabled(self: *Linter, rule: []const u8) bool {
        for (self.disabled.items) |d| if (std.mem.eql(u8, d, rule)) return false;
        return true;
    }

    fn report(self: *Linter, file: []const u8, line: usize, rule: []const u8, severity: Severity, comptime fmt: []const u8, args: anytype) !void {
        if (!self.ruleEnabled(rule)) return;
        const message = try std.fmt.allocPrint(self.arena, fmt, args);
        try self.findings.append(self.arena, .{ .file = file, .line = line, .rule = rule, .severity = severity, .message = message });
        switch (severity) {
            .err => self.errors += 1,
            .warn => self.warnings += 1,
        }
    }

    fn loadWordList(self: *Linter, dir: Io.Dir, path: []const u8) !void {
        const text = dir.readFileAlloc(self.io, path, self.arena, .limited(1 << 20)) catch return;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            var line = std.mem.trim(u8, raw, " \t\r");
            if (std.mem.findScalar(u8, line, '#')) |i| line = std.mem.trim(u8, line[0..i], " \t");
            if (line.len == 0) continue;
            if (std.mem.find(u8, line, "->")) |i| {
                const word = std.mem.trim(u8, line[0..i], " \t");
                const rest = std.mem.trim(u8, line[i + 2 ..], " \t");
                try self.banned.append(self.arena, .{ .word = word, .replacement = rest, .rule = "STE-1.1" });
            } else {
                try self.banned.append(self.arena, .{ .word = line, .replacement = "", .rule = "STE-1.1" });
            }
        }
    }

    fn loadAllowlist(self: *Linter, dir: Io.Dir, path: []const u8) !void {
        const text = dir.readFileAlloc(self.io, path, self.arena, .limited(1 << 20)) catch return;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            try self.ing_allow.append(self.arena, line);
        }
    }

    fn lintPath(self: *Linter, dir: Io.Dir, path: []const u8) !void {
        const stat = dir.statFile(self.io, path, .{}) catch |e| {
            std.debug.print("lint-docs: cannot stat {s}: {t}\n", .{ path, e });
            return;
        };
        if (stat.kind == .directory) {
            var sub = try dir.openDir(self.io, path, .{ .iterate = true });
            defer sub.close(self.io);
            var walker = try sub.walk(self.arena);
            defer walker.deinit();
            while (try walker.next(self.io)) |entry| {
                if (entry.kind != .file) continue;
                if (std.mem.find(u8, entry.path, "fixtures") != null or std.mem.find(u8, entry.path, "generated") != null) continue;
                const full = try std.fs.path.join(self.arena, &.{ path, entry.path });
                try self.lintFile(dir, full);
            }
        } else {
            try self.lintFile(dir, path);
        }
    }

    fn lintFile(self: *Linter, dir: Io.Dir, path: []const u8) !void {
        const is_md = std.mem.endsWith(u8, path, ".md");
        const is_zig = std.mem.endsWith(u8, path, ".zig");
        if (!is_md and !is_zig) return;
        const text = try dir.readFileAlloc(self.io, path, self.arena, .limited(16 << 20));
        self.files += 1;
        var sentences: std.ArrayList(Sentence) = .empty;
        if (is_md) try self.extractMarkdown(path, text, &sentences) else try self.extractZigDocs(text, &sentences);
        for (sentences.items) |s| try self.checkSentence(path, s);
    }

    // ------------------------------------------------------------------------------------
    // Extraction
    // ------------------------------------------------------------------------------------

    /// Markdown pre-pass: drop fenced code, tables, HTML comments and link targets; keep
    /// headings out of the length rules; detect procedural sections and list items.
    fn extractMarkdown(self: *Linter, path: []const u8, text: []const u8, out: *std.ArrayList(Sentence)) !void {
        var in_fence = false;
        var in_comment = false;
        var mode: Mode = .descriptive;
        var paragraph: std.ArrayList(u8) = .empty;
        var paragraph_line: usize = 1;
        var paragraph_mode: Mode = .descriptive;
        var line_no: usize = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            line_no += 1;
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            const trimmed = std.mem.trim(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, "```") or std.mem.startsWith(u8, trimmed, "~~~")) {
                in_fence = !in_fence;
                try self.flushParagraph(path, &paragraph, paragraph_line, paragraph_mode, out);
                continue;
            }
            if (in_fence) continue;
            if (in_comment) {
                if (std.mem.find(u8, trimmed, "-->") != null) in_comment = false;
                continue;
            }
            if (std.mem.startsWith(u8, trimmed, "<!--")) {
                if (std.mem.find(u8, trimmed, "-->") == null) in_comment = true;
                continue;
            }
            if (trimmed.len == 0) {
                try self.flushParagraph(path, &paragraph, paragraph_line, paragraph_mode, out);
                continue;
            }
            if (trimmed[0] == '#') {
                try self.flushParagraph(path, &paragraph, paragraph_line, paragraph_mode, out);
                const heading = std.mem.trim(u8, trimmed, "# \t");
                mode = if (std.ascii.startsWithIgnoreCase(heading, "steps") or std.ascii.startsWithIgnoreCase(heading, "procedure") or std.ascii.startsWithIgnoreCase(heading, "how to")) .procedural else .descriptive;
                continue;
            }
            if (trimmed[0] == '|' or std.mem.startsWith(u8, trimmed, "---") or std.mem.startsWith(u8, trimmed, "===")) {
                try self.flushParagraph(path, &paragraph, paragraph_line, paragraph_mode, out);
                continue;
            }
            // List items: each item is its own paragraph. Ordered items are procedural.
            var item_mode = mode;
            var body = trimmed;
            if (std.mem.startsWith(u8, body, "- ") or std.mem.startsWith(u8, body, "* ") or std.mem.startsWith(u8, body, "+ ")) {
                try self.flushParagraph(path, &paragraph, paragraph_line, paragraph_mode, out);
                body = body[2..];
                paragraph_line = line_no;
                paragraph_mode = item_mode;
            } else if (isOrderedItem(body)) |rest| {
                try self.flushParagraph(path, &paragraph, paragraph_line, paragraph_mode, out);
                body = rest;
                item_mode = .procedural;
                paragraph_line = line_no;
                paragraph_mode = item_mode;
            } else if (std.mem.startsWith(u8, body, "> ")) {
                body = body[2..];
            }
            if (paragraph.items.len == 0) {
                paragraph_line = line_no;
                paragraph_mode = item_mode;
            } else {
                try paragraph.append(self.arena, ' ');
            }
            try paragraph.appendSlice(self.arena, body);
        }
        try self.flushParagraph(path, &paragraph, paragraph_line, paragraph_mode, out);
    }

    fn isOrderedItem(line: []const u8) ?[]const u8 {
        var i: usize = 0;
        while (i < line.len and std.ascii.isDigit(line[i])) i += 1;
        if (i == 0 or i + 1 >= line.len) return null;
        if (line[i] != '.' and line[i] != ')') return null;
        if (line[i + 1] != ' ') return null;
        return line[i + 2 ..];
    }

    fn extractZigDocs(self: *Linter, text: []const u8, out: *std.ArrayList(Sentence)) !void {
        var paragraph: std.ArrayList(u8) = .empty;
        var paragraph_line: usize = 1;
        var line_no: usize = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            line_no += 1;
            const trimmed = std.mem.trim(u8, raw_line, " \t\r");
            var body: ?[]const u8 = null;
            if (std.mem.startsWith(u8, trimmed, "///")) body = trimmed[3..] else if (std.mem.startsWith(u8, trimmed, "//!")) body = trimmed[3..];
            if (body) |b| {
                const content = std.mem.trim(u8, b, " \t");
                // Code blocks and list-like lines in doc comments are skipped.
                if (std.mem.startsWith(u8, content, "```")) {
                    try self.flushParagraphPlain(&paragraph, paragraph_line, out);
                    continue;
                }
                if (content.len == 0) {
                    try self.flushParagraphPlain(&paragraph, paragraph_line, out);
                    continue;
                }
                if (paragraph.items.len == 0) paragraph_line = line_no else try paragraph.append(self.arena, ' ');
                try paragraph.appendSlice(self.arena, content);
            } else {
                try self.flushParagraphPlain(&paragraph, paragraph_line, out);
            }
        }
        try self.flushParagraphPlain(&paragraph, paragraph_line, out);
    }

    fn flushParagraphPlain(self: *Linter, paragraph: *std.ArrayList(u8), line: usize, out: *std.ArrayList(Sentence)) !void {
        if (paragraph.items.len == 0) return;
        // Doc-comment paragraphs inside fenced blocks are common; skip paragraphs that look
        // like code (start with a Zig keyword or contain `=>`).
        const text = paragraph.items;
        if (std.mem.find(u8, text, "=>") == null and !std.mem.startsWith(u8, text, "const ") and !std.mem.startsWith(u8, text, "pub ")) {
            try self.splitSentences(text, line, .descriptive, out);
        }
        paragraph.clearRetainingCapacity();
    }

    fn flushParagraph(self: *Linter, path: []const u8, paragraph: *std.ArrayList(u8), line: usize, mode: Mode, out: *std.ArrayList(Sentence)) !void {
        if (paragraph.items.len == 0) return;
        const start = out.items.len;
        try self.splitSentences(paragraph.items, line, mode, out);
        const count = out.items.len - start;
        if (count > max_sentences_per_paragraph) {
            try self.report(path, line, "STE-6.6", .err, "paragraph has {d} sentences; the maximum is {d}", .{ count, max_sentences_per_paragraph });
        }
        paragraph.clearRetainingCapacity();
    }

    /// Split a paragraph into sentences at `.`, `!` or `?` followed by whitespace or the end.
    fn splitSentences(self: *Linter, text: []const u8, line: usize, mode: Mode, out: *std.ArrayList(Sentence)) !void {
        const cleaned = try stripInline(self.arena, text);
        var start: usize = 0;
        var i: usize = 0;
        while (i < cleaned.len) : (i += 1) {
            const c = cleaned[i];
            if (c == '.' or c == '!' or c == '?') {
                const at_end = i + 1 >= cleaned.len;
                const next_space = !at_end and (cleaned[i + 1] == ' ' or cleaned[i + 1] == '\t');
                if (at_end or next_space) {
                    const s = std.mem.trim(u8, cleaned[start .. i + 1], " \t");
                    if (s.len > 0) try out.append(self.arena, .{ .text = s, .line = line, .mode = mode });
                    start = i + 1;
                }
            }
        }
        const rest = std.mem.trim(u8, cleaned[start..], " \t");
        if (rest.len > 0) try out.append(self.arena, .{ .text = rest, .line = line, .mode = mode });
    }

    /// Replace inline code spans with a single token, links with their text, and drop
    /// emphasis markers and HTML tags.
    fn stripInline(arena: Allocator, text: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < text.len) {
            const c = text[i];
            if (c == '`') {
                const end = std.mem.findScalarPos(u8, text, i + 1, '`') orelse text.len;
                try out.appendSlice(arena, "CODE");
                i = @min(end + 1, text.len);
                continue;
            }
            if (c == '[') {
                // [text](url) or [text][ref]
                if (std.mem.findScalarPos(u8, text, i, ']')) |close| {
                    const inner = text[i + 1 .. close];
                    var after = close + 1;
                    if (after < text.len and (text[after] == '(' or text[after] == '[')) {
                        const closer: u8 = if (text[after] == '(') ')' else ']';
                        after = (std.mem.findScalarPos(u8, text, after, closer) orelse text.len) + 1;
                    }
                    if (std.mem.startsWith(u8, inner, "^")) {
                        i = after;
                        continue;
                    }
                    try out.appendSlice(arena, inner);
                    i = @min(after, text.len);
                    continue;
                }
            }
            if (c == '<') {
                if (std.mem.findScalarPos(u8, text, i, '>')) |close| {
                    i = close + 1;
                    continue;
                }
            }
            if (c == '*' or c == '_') {
                i += 1;
                continue;
            }
            try out.append(arena, c);
            i += 1;
        }
        return out.items;
    }

    // ------------------------------------------------------------------------------------
    // Rules
    // ------------------------------------------------------------------------------------

    fn checkSentence(self: *Linter, path: []const u8, s: Sentence) !void {
        const words = countWords(s.text);
        const limit: usize = if (s.mode == .procedural) max_words_procedural else max_words_descriptive;
        const rule = if (s.mode == .procedural) "STE-5.1" else "STE-6.3";
        if (words > limit) {
            try self.report(path, s.line, rule, .err, "sentence has {d} words; the maximum is {d}: \"{s}\"", .{ words, limit, excerpt(s.text) });
        }
        if (std.mem.findScalar(u8, s.text, ';') != null) {
            try self.report(path, s.line, "STE-8.1", .err, "semicolon in sentence: \"{s}\"", .{excerpt(s.text)});
        }
        var lower_buf: [4096]u8 = undefined;
        if (s.text.len > lower_buf.len) return;
        const lower = std.ascii.lowerString(&lower_buf, s.text);
        for (contractions) |c| {
            if (containsWord(lower, c)) try self.report(path, s.line, "STE-4.2", .err, "contraction \"{s}\": write the full words", .{c});
        }
        for (latin) |l| {
            if (containsWord(lower, l)) try self.report(path, s.line, "STE-GR-6", .err, "Latin abbreviation \"{s}\": use English words", .{l});
        }
        for (pronouns) |p| {
            if (containsWord(lower, p)) try self.report(path, s.line, "STE-GR-7", .err, "gendered pronoun \"{s}\": name the person or role", .{p});
        }
        for (self.banned.items) |b| {
            if (containsWord(lower, b.word)) {
                if (b.replacement.len > 0) {
                    try self.report(path, s.line, b.rule, .err, "\"{s}\" is not an approved word; use {s}", .{ b.word, b.replacement });
                } else {
                    try self.report(path, s.line, b.rule, .err, "\"{s}\" is not an approved word", .{b.word});
                }
            }
        }
        for (auxiliary_chains) |a| {
            if (containsWord(lower, a)) try self.report(path, s.line, "STE-3.4", .warn, "complex verb form \"{s}\": use the simple present, past or future", .{a});
        }
        try self.checkPassive(path, s.line, lower);
        try self.checkIng(path, s.line, lower);
        if (s.text.len > 0 and std.ascii.isLower(s.text[0]) and !std.mem.startsWith(u8, s.text, "http")) {
            try self.report(path, s.line, "PRJ-1", .warn, "sentence starts with a lowercase letter: \"{s}\"", .{excerpt(s.text)});
        }
    }

    fn checkPassive(self: *Linter, path: []const u8, line: usize, lower: []const u8) !void {
        var it = std.mem.tokenizeAny(u8, lower, " \t,.:!?\"()");
        var prev: ?[]const u8 = null;
        while (it.next()) |word| {
            defer prev = word;
            const p = prev orelse continue;
            var is_aux = false;
            for (passive_verbs) |v| if (std.mem.eql(u8, p, v)) {
                is_aux = true;
            };
            if (!is_aux) continue;
            if (word.len > 4 and std.mem.endsWith(u8, word, "ed") and !std.mem.eql(u8, word, "need") and !std.mem.eql(u8, word, "used")) {
                try self.report(path, line, "STE-3.6", .warn, "possible passive voice \"{s} {s}\": use the active voice", .{ p, word });
                return;
            }
        }
    }

    fn checkIng(self: *Linter, path: []const u8, line: usize, lower: []const u8) !void {
        var it = std.mem.tokenizeAny(u8, lower, " \t,.:!?\"()/");
        while (it.next()) |word| {
            if (word.len < 6 or !std.mem.endsWith(u8, word, "ing")) continue;
            var allowed = false;
            for (default_ing_allowlist) |a| if (std.mem.eql(u8, a, word)) {
                allowed = true;
            };
            for (self.ing_allow.items) |a| if (std.mem.eql(u8, a, word)) {
                allowed = true;
            };
            if (!allowed) try self.report(path, line, "STE-3.5", .warn, "\"-ing\" form \"{s}\": use a verb, or declare a technical noun", .{word});
        }
    }

    // ------------------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------------------

    /// Count words per STE 8.5-8.7: parenthesized text, numbers, hyphenated words and code
    /// tokens count as one word each.
    fn countWords(text: []const u8) usize {
        var count: usize = 0;
        var depth: usize = 0;
        var in_word = false;
        for (text) |c| {
            if (c == '(') {
                if (depth == 0) {
                    if (in_word) {
                        count += 1;
                        in_word = false;
                    }
                    count += 1;
                }
                depth += 1;
                continue;
            }
            if (c == ')') {
                if (depth > 0) depth -= 1;
                continue;
            }
            if (depth > 0) continue;
            if (c == ' ' or c == '\t') {
                if (in_word) count += 1;
                in_word = false;
            } else {
                in_word = true;
            }
        }
        if (in_word) count += 1;
        return count;
    }

    fn containsWord(haystack: []const u8, needle: []const u8) bool {
        var pos: usize = 0;
        while (std.mem.findPos(u8, haystack, pos, needle)) |i| {
            const before_ok = i == 0 or !isWordChar(haystack[i - 1]);
            const end = i + needle.len;
            const after_ok = end >= haystack.len or !isWordChar(haystack[end]);
            if (before_ok and after_ok) return true;
            pos = i + 1;
        }
        return false;
    }

    fn isWordChar(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '\'' or c == '-' or c == '_';
    }

    fn excerpt(text: []const u8) []const u8 {
        return if (text.len > 60) text[0..60] else text;
    }

    fn print(self: *Linter, w: *Io.Writer) !void {
        for (self.findings.items) |f| {
            switch (self.format) {
                .text => try w.print("{s}:{d}: {s} {s}: {s}\n", .{ f.file, f.line, if (f.severity == .err) "error" else "warning", f.rule, f.message }),
                .github => try w.print("::{s} file={s},line={d},title={s}::{s}\n", .{ if (f.severity == .err) "error" else "warning", f.file, f.line, f.rule, f.message }),
            }
        }
        try w.print("lint-docs: {d} files, {d} errors, {d} warnings\n", .{ self.files, self.errors, self.warnings });
    }
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    var linter: Linter = .{ .arena = arena, .io = io, .format = .text, .strict = false };
    var paths: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--format")) {
            i += 1;
            linter.format = if (std.mem.eql(u8, args[i], "github")) .github else .text;
        } else if (std.mem.eql(u8, a, "--strict")) {
            linter.strict = true;
        } else if (std.mem.eql(u8, a, "--wiki-dir")) {
            i += 1;
            try paths.append(arena, args[i]);
        } else if (std.mem.startsWith(u8, a, "--rule")) {
            i += 1;
            const spec = args[i];
            if (std.mem.endsWith(u8, spec, "=off")) try linter.disabled.append(arena, spec[0 .. spec.len - 4]);
        } else {
            try paths.append(arena, a);
        }
    }
    if (init.environ_map.get("GITHUB_ACTIONS") != null) linter.format = .github;
    const cwd = Io.Dir.cwd();
    try linter.loadWordList(cwd, "docs/dictionary/project_word_list.txt");
    try linter.loadAllowlist(cwd, "docs/dictionary/ing_allowlist.txt");
    for (paths.items) |p| try linter.lintPath(cwd, p);

    var buf: [8192]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &buf);
    try linter.print(&stdout.interface);
    try stdout.interface.flush();
    if (linter.errors > 0) return 1;
    if (linter.strict and linter.warnings > 0) return 1;
    return 0;
}

test "word counting follows STE 8.5-8.7" {
    try std.testing.expectEqual(3, Linter.countWords("Run the test."));
    try std.testing.expectEqual(4, Linter.countWords("Run the test (see below) now."));
    try std.testing.expectEqual(2, Linter.countWords("zero-copy parser"));
    try std.testing.expectEqual(2, Linter.countWords("Zig 0.16.0"));
}

test "contraction and pronoun detection" {
    try std.testing.expect(Linter.containsWord("do not use don't here", "don't"));
    try std.testing.expect(!Linter.containsWord("the shell", "he"));
    try std.testing.expect(Linter.containsWord("he runs", "he"));
}
