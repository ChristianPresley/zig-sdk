//! Text helpers of lint-docs: the inline pre-pass, the sentence splitter and the word counter.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// The inline pre-pass replaces a code span with this token.
pub const code_token = "{code}";
/// The inline pre-pass replaces the text of a link to a wiki page that has the page name with this token.
pub const name_token = "{name}";

/// Replaces code spans with `code_token` and links with their text.
/// Removes emphasis markers, HTML tags and superscript citations.
pub fn stripInline(arena: Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < text.len) {
        const c = text[i];
        if (c == '\\' and i + 1 < text.len and std.ascii.isPunctuation(text[i + 1])) {
            try out.append(arena, text[i + 1]);
            i += 2;
            continue;
        }
        if (c == '`') {
            var ticks: usize = 0;
            while (i + ticks < text.len and text[i + ticks] == '`') ticks += 1;
            const fence = text[i .. i + ticks];
            const end = std.mem.findPos(u8, text, i + ticks, fence) orelse text.len;
            try out.appendSlice(arena, code_token);
            i = @min(end + ticks, text.len);
            continue;
        }
        if (c == '!' and i + 1 < text.len and text[i + 1] == '[') {
            // An image: keep the alternative text.
            i += 1;
            continue;
        }
        if (c == '[') {
            if (findClose(text, i)) |close| {
                const inner = text[i + 1 .. close];
                var after = close + 1;
                var target: []const u8 = "";
                if (after < text.len and (text[after] == '(' or text[after] == '[')) {
                    const closer: u8 = if (text[after] == '(') ')' else ']';
                    const end = std.mem.findScalarPos(u8, text, after, closer) orelse text.len;
                    target = text[after + 1 .. end];
                    after = end + 1;
                }
                if (std.mem.startsWith(u8, inner, "^")) {
                    // A footnote reference.
                    i = @min(after, text.len);
                    continue;
                }
                const wiki_target = wikiTarget(target);
                if (isWikiPageTarget(wiki_target) and (sameName(inner, pageOf(wiki_target)) or sameName(inner, anchorOf(wiki_target)))) {
                    try out.appendSlice(arena, name_token);
                } else {
                    try out.appendSlice(arena, try stripInline(arena, inner));
                }
                i = @min(after, text.len);
                continue;
            }
        }
        if (c == '<') {
            if (std.mem.startsWith(u8, text[i..], "<sup>")) {
                const end = std.mem.findPos(u8, text, i, "</sup>") orelse text.len;
                i = @min(end + "</sup>".len, text.len);
                continue;
            }
            if (i + 1 < text.len and (std.ascii.isAlphabetic(text[i + 1]) or text[i + 1] == '/' or text[i + 1] == '!')) {
                if (std.mem.findScalarPos(u8, text, i, '>')) |close| {
                    i = close + 1;
                    continue;
                }
            }
        }
        if (c == '*') {
            i += 1;
            continue;
        }
        if (c == '_') {
            const before_word = i > 0 and std.ascii.isAlphanumeric(text[i - 1]);
            const after_word = i + 1 < text.len and std.ascii.isAlphanumeric(text[i + 1]);
            if (!(before_word and after_word)) {
                i += 1;
                continue;
            }
        }
        try out.append(arena, c);
        i += 1;
    }
    return out.items;
}

/// Returns the index of the `]` that closes the `[` at `open`, or null.
fn findClose(text: []const u8, open: usize) ?usize {
    var depth: usize = 0;
    var i = open;
    while (i < text.len) : (i += 1) {
        switch (text[i]) {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if (depth == 0) return i;
            },
            '`' => {
                const end = std.mem.findScalarPos(u8, text, i + 1, '`') orelse return null;
                i = end;
            },
            else => {},
        }
    }
    return null;
}

/// Returns true for a link target that names a wiki page, such as `Server-Guide#steps`.
pub fn isWikiPageTarget(target: []const u8) bool {
    if (target.len == 0 or target[0] == '#') return false;
    const page = pageOf(target);
    if (page.len == 0) return false;
    for (page) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_')) return false;
    }
    return true;
}

/// Returns the page part of a URL of a GitHub wiki, such as `Home` of
/// `https://github.com/owner/repo/wiki/Home`. Other targets stay as they are.
pub fn wikiTarget(target: []const u8) []const u8 {
    if (std.mem.find(u8, target, "://") == null) return target;
    const marker = "/wiki/";
    const i = std.mem.findLast(u8, target, marker) orelse return target;
    return target[i + marker.len ..];
}

/// Returns the part of a link target before `#`.
pub fn pageOf(target: []const u8) []const u8 {
    const hash = std.mem.findScalar(u8, target, '#') orelse target.len;
    return target[0..hash];
}

/// Returns the part of a link target after `#`, or an empty slice.
pub fn anchorOf(target: []const u8) []const u8 {
    const hash = std.mem.findScalar(u8, target, '#') orelse return "";
    return target[hash + 1 ..];
}

/// Compares two names on their letters and digits only, and ignores the case.
pub fn sameName(a: []const u8, b: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (true) {
        while (i < a.len and !std.ascii.isAlphanumeric(a[i])) i += 1;
        while (j < b.len and !std.ascii.isAlphanumeric(b[j])) j += 1;
        if (i == a.len or j == b.len) return i == a.len and j == b.len;
        if (std.ascii.toLower(a[i]) != std.ascii.toLower(b[j])) return false;
        i += 1;
        j += 1;
    }
}

/// Splits a paragraph into sentences at `.`, `!` or `?` that a space or the end follows.
pub fn splitSentences(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var start: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '.' or c == '!' or c == '?') {
            var end = i + 1;
            // A closing quote or parenthesis stays with its sentence.
            while (end < text.len and (text[end] == '"' or text[end] == ')')) end += 1;
            const at_end = end >= text.len;
            // "e.g." and "i.e." do not end a sentence. STE-GR-6 reports them.
            const latin_pair = i >= 3 and text[i - 2] == '.' and std.ascii.isAlphabetic(text[i - 1]) and std.ascii.isAlphabetic(text[i - 3]) and (i < 4 or !std.ascii.isAlphanumeric(text[i - 4]));
            if (!latin_pair and (at_end or text[end] == ' ' or text[end] == '\t')) {
                const s = std.mem.trim(u8, text[start..end], " \t");
                if (s.len > 0) try out.append(arena, s);
                start = end;
                i = end;
            }
        }
    }
    const rest = std.mem.trim(u8, text[start..], " \t");
    if (rest.len > 0) try out.append(arena, rest);
    return out.items;
}

/// Counts words as ASD-STE100 rules 8.4 to 8.7 tell: text in parentheses, numbers,
/// hyphenated words and code spans count as one word each.
pub fn countWords(text: []const u8) usize {
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
        } else if (!(c == '-' or c == '/' or c == '|') or in_word) {
            in_word = true;
        }
    }
    if (in_word) count += 1;
    return count;
}

/// Returns true when `needle` occurs in `haystack` as whole words.
pub fn containsWord(haystack: []const u8, needle: []const u8) bool {
    return findWord(haystack, needle, 0) != null;
}

/// Returns the index of the next occurrence of `needle` as whole words at or after `from`.
pub fn findWord(haystack: []const u8, needle: []const u8, from: usize) ?usize {
    var pos = from;
    while (std.mem.findPos(u8, haystack, pos, needle)) |i| {
        const before_ok = i == 0 or !isWordChar(haystack[i - 1]);
        const end = i + needle.len;
        const after_ok = end >= haystack.len or !isWordChar(haystack[end]);
        if (before_ok and after_ok) return i;
        pos = i + 1;
    }
    return null;
}

/// Returns true for a character that can be part of a word.
pub fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '\'' or c == '-' or c == '_' or c == '{' or c == '}' or c >= 0x80;
}

/// Iterates over the words of a sentence. A word has no punctuation at its two ends.
pub const WordIterator = struct {
    text: []const u8,
    index: usize = 0,

    pub const Word = struct { text: []const u8, start: usize };

    pub fn next(it: *WordIterator) ?Word {
        while (it.index < it.text.len) {
            while (it.index < it.text.len and isSpace(it.text[it.index])) it.index += 1;
            const start = it.index;
            while (it.index < it.text.len and !isSpace(it.text[it.index])) it.index += 1;
            if (start == it.index) return null;
            var word = it.text[start..it.index];
            var offset = start;
            while (word.len > 0 and isEdgePunctuation(word[0])) {
                word = word[1..];
                offset += 1;
            }
            while (word.len > 0 and isEdgePunctuation(word[word.len - 1])) word = word[0 .. word.len - 1];
            if (word.len > 0) return .{ .text = word, .start = offset };
        }
        return null;
    }

    fn isSpace(c: u8) bool {
        return c == ' ' or c == '\t' or c == '\n' or c == '\r';
    }

    fn isEdgePunctuation(c: u8) bool {
        return switch (c) {
            ',', '.', ';', ':', '!', '?', '"', '\'', '(', ')', '[', ']' => true,
            else => false,
        };
    }
};

/// Replaces each text in double quotes with the token `{quote}`. An odd quote mark stays.
pub fn removeQuotes(arena: Allocator, s: []const u8) ![]const u8 {
    if (std.mem.findScalar(u8, s, '"') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '"') {
            if (std.mem.findScalarPos(u8, s, i + 1, '"')) |close| {
                try out.appendSlice(arena, "{quote}");
                i = close + 1;
                continue;
            }
        }
        try out.append(arena, s[i]);
        i += 1;
    }
    return out.items;
}

/// Returns true for a word that is a URL.
pub fn isUrl(word: []const u8) bool {
    return std.mem.find(u8, word, "://") != null or std.mem.startsWith(u8, word, "www.");
}

/// Returns the first 60 bytes of a sentence for a message.
pub fn excerpt(text: []const u8) []const u8 {
    return if (text.len > 60) text[0..60] else text;
}

/// Returns the GitHub anchor of a heading: lowercase, only letters, digits, `-` and `_`,
/// and a `-` for each space.
pub fn slug(arena: Allocator, heading: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (heading) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c >= 0x80) {
            try out.append(arena, std.ascii.toLower(c));
        } else if (c == ' ') {
            try out.append(arena, '-');
        }
    }
    return out.items;
}

test "word counting follows the rules of the standard" {
    try std.testing.expectEqual(3, countWords("Run the test."));
    try std.testing.expectEqual(5, countWords("Run the test (see below) now."));
    try std.testing.expectEqual(2, countWords("zero-copy parser"));
    try std.testing.expectEqual(2, countWords("Zig 0.16.0"));
    try std.testing.expectEqual(3, countWords("Use {code} - it"));
}

test "whole-word search" {
    try std.testing.expect(containsWord("do not use don't here", "don't"));
    try std.testing.expect(!containsWord("the shell", "he"));
    try std.testing.expect(containsWord("he runs", "he"));
    try std.testing.expect(containsWord("we set up the server", "set up"));
    try std.testing.expect(!containsWord("the setup is done", "set up"));
}

test "inline pre-pass" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("Run {code} now.", try stripInline(arena, "Run `zig build` now."));
    try std.testing.expectEqualStrings("See the guide.", try stripInline(arena, "See the [guide](https://example.com)."));
    try std.testing.expectEqualStrings("See {name}.", try stripInline(arena, "See [Getting Started](Getting-Started)."));
    try std.testing.expectEqualStrings("{name}: a key.", try stripInline(arena, "[RFC-2119](Bibliography#rfc-2119): a key."));
    try std.testing.expectEqualStrings("Read {name}.", try stripInline(arena, "Read [Getting Started](https://github.com/o/r/wiki/Getting-Started)."));
    try std.testing.expectEqualStrings("The SDK obeys MCP.", try stripInline(arena, "The SDK obeys **MCP**<sup>[1](#ref-1)</sup>."));
    try std.testing.expectEqualStrings("Set max_restarts.", try stripInline(arena, "Set max_restarts."));
    try std.testing.expectEqualStrings("A {code} span.", try stripInline(arena, "A ``a ` b`` span."));
}

test "sentence splitting" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const s = try splitSentences(arena_state.allocator(), "Zig 0.16.0 is required. Run it (now.) Then stop");
    try std.testing.expectEqual(3, s.len);
    try std.testing.expectEqualStrings("Run it (now.)", s[1]);
}

test "heading anchors" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("steps-try-the-cli-against-the-stdio-server", try slug(arena, "Steps: try the CLI against the stdio server"));
    try std.testing.expectEqualStrings("zig-016-relnotes", try slug(arena, "ZIG-0.16-RELNOTES"));
}

test "quotations" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectEqualStrings("A {quote} b \"c", try removeQuotes(arena_state.allocator(), "A \"x; y\" b \"c"));
}

test "word iterator" {
    var it: WordIterator = .{ .text = "Hello, (world)! \"x\"" };
    try std.testing.expectEqualStrings("Hello", it.next().?.text);
    try std.testing.expectEqualStrings("world", it.next().?.text);
    try std.testing.expectEqualStrings("x", it.next().?.text);
    try std.testing.expect(it.next() == null);
}
