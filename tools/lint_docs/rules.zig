//! The sentence rules of lint-docs. Each rule has the id of an ASD-STE100 rule (`STE-<n>`,
//! `STE-GR-<n>`) or of a project rule (`PRJ-<n>`). The file `docs/style/ste-profile.md`
//! tells what each rule checks.
const std = @import("std");
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const markdown = @import("markdown.zig");
const Dictionary = @import("Dictionary.zig");

/// A finding is an error or a warning.
pub const Severity = enum { err, warn };

/// The rules call `report` on the sink.
pub const Sink = struct {
    context: *anyopaque,
    reportFn: *const fn (context: *anyopaque, line: usize, rule: []const u8, severity: Severity, message: []const u8) anyerror!void,
    arena: Allocator,
    dict: *const Dictionary,

    pub fn report(sink: Sink, line: usize, rule: []const u8, severity: Severity, comptime fmt: []const u8, args: anytype) !void {
        const message = try std.fmt.allocPrint(sink.arena, fmt, args);
        try sink.reportFn(sink.context, line, rule, severity, message);
    }
};

/// The maximum number of words in a procedural sentence (STE-5.1).
pub const max_words_procedural = 20;
/// The maximum number of words in a descriptive sentence (STE-6.3).
pub const max_words_descriptive = 25;
/// The maximum number of sentences in a paragraph (STE-6.6).
pub const max_sentences_per_paragraph = 6;

const contractions = [_][]const u8{
    "don't",     "doesn't",  "didn't",  "isn't",  "aren't",  "wasn't",  "weren't", "can't",  "won't",   "wouldn't",
    "shouldn't", "couldn't", "mustn't", "hasn't", "haven't", "hadn't",  "it's",    "that's", "there's", "here's",
    "what's",    "who's",    "let's",   "you're", "we're",   "they're", "i'm",     "i've",   "you've",  "we've",
    "they've",   "i'll",     "you'll",  "we'll",  "they'll", "it'll",   "i'd",     "you'd",  "we'd",    "they'd",
};

const latin = [_][]const u8{ "e.g.", "i.e.", "etc.", "etc", "vs.", "viz.", "et al.", "cf.", "n.b." };

const pronouns = [_][]const u8{ "he", "she", "him", "his", "hers", "himself", "herself" };

/// The key words of RFC 2119 (PRJ-6). "NOT" makes a pair with some of them.
const rfc2119 = [_][]const u8{ "MUST", "SHALL", "SHOULD", "REQUIRED", "RECOMMENDED", "MAY", "OPTIONAL" };

/// Verb forms with more than one auxiliary (STE-3.4).
const complex_forms = [_][]const u8{ "has been", "have been", "had been", "will be able", "being" };

const be_forms = [_][]const u8{ "is", "are", "was", "were", "be", "been" };

const perfect_forms = [_][]const u8{ "has", "have", "had" };

/// Adverbs that can stand between an auxiliary and a participle.
const adverbs = [_][]const u8{
    "not",       "also",     "always",      "never",    "only",       "then",       "now",   "still", "already", "automatically",
    "usually",   "often",    "immediately", "first",    "again",      "fully",      "once",  "each",  "all",     "both",
    "correctly", "silently", "safely",      "directly", "explicitly", "internally", "later", "just",  "yet",     "ever",
};

/// Irregular past participles. Forms that are also the base form, such as "set" or "read", are not in the list.
const irregular_participles = [_][]const u8{
    "been",    "done",    "gone",      "seen",   "known",      "given", "taken",  "written",   "sent",       "built",
    "made",    "kept",    "held",      "found",  "shown",      "bound", "chosen", "begun",     "broken",     "drawn",
    "driven",  "fallen",  "forgotten", "frozen", "hidden",     "lost",  "meant",  "paid",      "said",       "sold",
    "spent",   "stolen",  "told",      "thrown", "understood", "won",   "worn",   "spun",      "sought",     "taught",
    "thought", "brought", "bought",    "caught", "fought",     "got",   "gotten", "laid",      "led",        "lent",
    "felt",    "fed",     "dealt",     "hung",   "struck",     "stuck", "swept",  "withdrawn", "overridden", "rewritten",
    "undone",  "torn",    "sworn",     "woven",  "arisen",     "risen", "shaken", "spoken",    "stridden",   "proven",
};

/// Checks one block of prose.
pub fn checkBlock(sink: Sink, block: markdown.Block) !void {
    const cleaned = try text.stripInline(sink.arena, block.text);
    const sentences = try text.splitSentences(sink.arena, cleaned);
    if (block.kind == .paragraph and sentences.len > max_sentences_per_paragraph) {
        try sink.report(block.line, "STE-6.6", .err, "paragraph has {d} sentences; the maximum is {d}", .{ sentences.len, max_sentences_per_paragraph });
    }
    for (sentences) |s| try checkSentence(sink, block.line, block.mode, block.kind, s);
}

/// Checks one sentence after the inline pre-pass.
pub fn checkSentence(sink: Sink, line: usize, mode: markdown.Mode, kind: markdown.Kind, s: []const u8) !void {
    // A table cell that has only RFC 2119 key words names the words and does not use them.
    if (kind == .cell and onlyKeywords(s)) return;
    const words = text.countWords(s);
    const limit: usize = if (mode == .procedural) max_words_procedural else max_words_descriptive;
    if (words > limit) {
        const rule = if (mode == .procedural) "STE-5.1" else "STE-6.3";
        try sink.report(line, rule, .err, "sentence has {d} words; the maximum is {d}: \"{s}\"", .{ words, limit, text.excerpt(s) });
    }
    // Quoted text, such as the title of a document or a quotation of the specification,
    // counts for the length of the sentence only.
    const own = try text.removeQuotes(sink.arena, s);
    if (std.mem.findScalar(u8, own, ';') != null) {
        try sink.report(line, "STE-8.1", .err, "semicolon in sentence: \"{s}\"", .{text.excerpt(s)});
    }
    const lower = try std.ascii.allocLowerString(sink.arena, own);
    for (contractions) |c| {
        if (text.containsWord(lower, c)) try sink.report(line, "STE-4.2", .err, "contraction \"{s}\": write the full words", .{c});
    }
    for (latin) |l| {
        if (text.containsWord(lower, l)) try sink.report(line, "STE-GR-6", .err, "Latin abbreviation \"{s}\": use English words", .{l});
    }
    for (pronouns) |p| {
        if (text.containsWord(lower, p)) try sink.report(line, "STE-GR-7", .err, "gendered pronoun \"{s}\": name the person or the role", .{p});
    }
    try checkList(sink, line, lower, sink.dict.banned, "STE-1.1", .err, "is not an approved word");
    try checkList(sink, line, lower, sink.dict.spelling, "PRJ-3", .warn, "is not the US spelling");
    try checkList(sink, line, lower, sink.dict.synonyms, "PRJ-4", .warn, "is a synonym of a project term");
    try checkList(sink, line, lower, sink.dict.phrasal_verbs, "PRJ-5", .warn, "is a phrasal verb");
    try checkRfc2119(sink, line, own);
    try checkAbbreviations(sink, line, own);
    try checkComplexForms(sink, line, lower);
    try checkPassive(sink, line, lower);
    try checkIng(sink, line, lower);
    if (kind == .paragraph) try checkStart(sink, line, s);
}

fn checkList(sink: Sink, line: usize, lower: []const u8, list: []const Dictionary.Replacement, rule: []const u8, severity: Severity, what: []const u8) !void {
    for (list) |entry| {
        if (!text.containsWord(lower, entry.word)) continue;
        if (entry.replacement.len > 0) {
            try sink.report(line, rule, severity, "\"{s}\" {s}: use {s}", .{ entry.word, what, entry.replacement });
        } else {
            try sink.report(line, rule, severity, "\"{s}\" {s}", .{ entry.word, what });
        }
    }
}

/// PRJ-6: the uppercase key words of RFC 2119 occur only in quotations.
fn checkRfc2119(sink: Sink, line: usize, s: []const u8) !void {
    for (rfc2119) |keyword| {
        var pos: usize = 0;
        while (text.findWord(s, keyword, pos)) |i| : (pos = i + keyword.len) {
            if (std.mem.count(u8, s[0..i], "\"") % 2 == 1) continue;
            try sink.report(line, "PRJ-6", .err, "RFC 2119 key word \"{s}\" outside a quotation: use the project wording", .{keyword});
            break;
        }
    }
}

/// A table cell that has only key words, such as `MUST NOT`, names the words and does not use them.
fn onlyKeywords(s: []const u8) bool {
    var it: text.WordIterator = .{ .text = s };
    while (it.next()) |w| {
        if (std.mem.eql(u8, w.text, "NOT")) continue;
        if (!Dictionary.has(&rfc2119, w.text)) return false;
    }
    return true;
}

/// PRJ-2: an abbreviation is in `docs/dictionary/abbreviations.txt`.
fn checkAbbreviations(sink: Sink, line: usize, s: []const u8) !void {
    var it: text.WordIterator = .{ .text = s };
    while (it.next()) |w| {
        if (text.isUrl(w.text)) continue;
        if (Dictionary.has(sink.dict.abbreviations, w.text)) continue;
        var parts = std.mem.tokenizeAny(u8, w.text, "-/.,:=+");
        while (parts.next()) |raw_part| {
            var part = raw_part;
            if (std.mem.endsWith(u8, part, "'s")) part = part[0 .. part.len - 2];
            if (part.len > 2 and part[part.len - 1] == 's' and isAbbreviation(part[0 .. part.len - 1])) part = part[0 .. part.len - 1];
            if (!isAbbreviation(part)) continue;
            if (Dictionary.has(&rfc2119, part) or std.mem.eql(u8, part, "NOT")) continue;
            if (Dictionary.has(sink.dict.abbreviations, part)) continue;
            try sink.report(line, "PRJ-2", .warn, "abbreviation \"{s}\" is not in the dictionary: add it to abbreviations.txt or write the full words", .{part});
        }
    }
}

/// An abbreviation has two or more uppercase letters and no lowercase letter.
fn isAbbreviation(word: []const u8) bool {
    var upper: usize = 0;
    for (word) |c| {
        if (std.ascii.isUpper(c)) {
            upper += 1;
        } else if (!std.ascii.isDigit(c)) return false;
    }
    return upper >= 2;
}

/// STE-3.4: no perfect tenses and no forms with more than one auxiliary.
fn checkComplexForms(sink: Sink, line: usize, lower: []const u8) !void {
    for (complex_forms) |form| {
        if (text.containsWord(lower, form)) {
            try sink.report(line, "STE-3.4", .warn, "complex verb form \"{s}\": use the simple present, past or future", .{form});
            return;
        }
    }
    if (try findAfter(sink.arena, lower, &perfect_forms, false, sink.dict)) |pair| {
        try sink.report(line, "STE-3.4", .warn, "complex verb form \"{s}\": use the simple present, past or future", .{pair});
    }
}

/// STE-3.6: a form of "be" and a past participle is a possible passive.
fn checkPassive(sink: Sink, line: usize, lower: []const u8) !void {
    if (try findAfter(sink.arena, lower, &be_forms, true, sink.dict)) |pair| {
        try sink.report(line, "STE-3.6", .warn, "possible passive voice \"{s}\": use the active voice", .{pair});
    }
}

/// Returns "auxiliary participle" for the first auxiliary of `auxiliaries` that a past
/// participle follows, with an optional adverb between them.
fn findAfter(arena: Allocator, lower: []const u8, auxiliaries: []const []const u8, allow_adjectives: bool, dict: *const Dictionary) !?[]const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var it: text.WordIterator = .{ .text = lower };
    while (it.next()) |w| try words.append(arena, w.text);
    const list = words.items;
    for (list, 0..) |w, i| {
        if (!Dictionary.has(auxiliaries, w)) continue;
        var j = i + 1;
        while (j < list.len and j < i + 3 and Dictionary.has(&adverbs, list[j])) j += 1;
        if (j >= list.len) continue;
        const p = list[j];
        if (allow_adjectives and Dictionary.has(dict.participles, p)) continue;
        if (isParticiple(p)) return try std.fmt.allocPrint(arena, "{s} {s}", .{ w, p });
    }
    return null;
}

fn isParticiple(word: []const u8) bool {
    if (Dictionary.has(&irregular_participles, word)) return true;
    if (word.len <= 4 or !std.mem.endsWith(u8, word, "ed")) return false;
    if (std.mem.endsWith(u8, word, "eed")) return false;
    for (word) |c| if (!std.ascii.isLower(c)) return false;
    return true;
}

/// STE-3.5: a word that ends in "-ing" is in `docs/dictionary/ing_allowlist.txt`.
fn checkIng(sink: Sink, line: usize, lower: []const u8) !void {
    var it: text.WordIterator = .{ .text = lower };
    while (it.next()) |w| {
        if (text.isUrl(w.text)) continue;
        var parts = std.mem.tokenizeAny(u8, w.text, "-/");
        while (parts.next()) |part| {
            if (part.len < 5 or !std.mem.endsWith(u8, part, "ing")) continue;
            if (std.mem.eql(u8, part, "being")) continue; // STE-3.4 reports it.
            var letters = true;
            for (part) |c| if (!std.ascii.isLower(c)) {
                letters = false;
            };
            if (!letters) continue;
            if (Dictionary.has(sink.dict.ing_allow, part)) continue;
            try sink.report(line, "STE-3.5", .warn, "\"-ing\" form \"{s}\": use a verb, or declare a technical noun", .{part});
        }
    }
}

/// PRJ-1: a sentence starts with an uppercase letter, a number, code or a declared name.
fn checkStart(sink: Sink, line: usize, s: []const u8) !void {
    if (s.len == 0 or !std.ascii.isLower(s[0])) return;
    var it: text.WordIterator = .{ .text = s };
    const first = (it.next() orelse return).text;
    if (text.isUrl(first)) return;
    if (sink.dict.isLowercaseName(first)) return;
    try sink.report(line, "PRJ-1", .warn, "sentence starts with a lowercase letter: \"{s}\"", .{text.excerpt(s)});
}

const TestSink = struct {
    arena: Allocator,
    rules: std.ArrayList([]const u8) = .empty,

    fn reportFn(context: *anyopaque, line: usize, rule: []const u8, severity: Severity, message: []const u8) anyerror!void {
        _ = line;
        _ = severity;
        _ = message;
        const self: *TestSink = @ptrCast(@alignCast(context));
        try self.rules.append(self.arena, rule);
    }

    fn check(self: *TestSink, dict: *const Dictionary, mode: markdown.Mode, sentence: []const u8) ![]const []const u8 {
        self.rules.clearRetainingCapacity();
        const sink: Sink = .{ .context = self, .reportFn = reportFn, .arena = self.arena, .dict = dict };
        try checkBlock(sink, .{ .text = sentence, .line = 1, .mode = mode, .kind = .paragraph });
        return self.rules.items;
    }
};

fn expectRules(expected: []const []const u8, actual: []const []const u8) !void {
    if (expected.len != actual.len) {
        std.debug.print("expected {any}, found {any}\n", .{ expected, actual });
        return error.TestExpectedEqual;
    }
    for (expected, actual) |e, a| try std.testing.expectEqualStrings(e, a);
}

test "sentence rules" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dict: Dictionary = .{
        .banned = &.{.{ .word = "should", .replacement = "must" }},
        .ing_allow = &.{"string"},
        .participles = &.{"enabled"},
        .abbreviations = &.{ "MCP", "gRPC" },
        .spelling = &.{.{ .word = "behaviour", .replacement = "behavior" }},
        .synonyms = &.{.{ .word = "plugin", .replacement = "extension" }},
        .phrasal_verbs = &.{.{ .word = "set up", .replacement = "configure" }},
    };
    var sink: TestSink = .{ .arena = arena };
    try expectRules(&.{}, try sink.check(&dict, .descriptive, "The MCP server sends a string."));
    try expectRules(&.{"STE-1.1"}, try sink.check(&dict, .descriptive, "You should stop."));
    try expectRules(&.{"STE-8.1"}, try sink.check(&dict, .descriptive, "Stop; go."));
    try expectRules(&.{"STE-4.2"}, try sink.check(&dict, .descriptive, "Don't stop."));
    try expectRules(&.{"STE-GR-6"}, try sink.check(&dict, .descriptive, "Use a tool, e.g. a hammer."));
    try expectRules(&.{"STE-GR-7"}, try sink.check(&dict, .descriptive, "The user signs, then he stops."));
    try expectRules(&.{"PRJ-3"}, try sink.check(&dict, .descriptive, "The behaviour changes."));
    try expectRules(&.{"PRJ-4"}, try sink.check(&dict, .descriptive, "Add a plugin."));
    try expectRules(&.{"PRJ-5"}, try sink.check(&dict, .descriptive, "Set up the server."));
    try expectRules(&.{"PRJ-6"}, try sink.check(&dict, .descriptive, "A server MUST answer."));
    try expectRules(&.{}, try sink.check(&dict, .descriptive, "The text says \"a server MUST answer\"."));
    try expectRules(&.{}, try sink.check(&dict, .descriptive, "The title is \"Describing JSON; a behaviour\"."));
    try expectRules(&.{"PRJ-2"}, try sink.check(&dict, .descriptive, "The XYZ layer stops."));
    try expectRules(&.{}, try sink.check(&dict, .descriptive, "The MCPs and the {code} stop."));
    try expectRules(&.{ "STE-3.4", "STE-3.6" }, try sink.check(&dict, .descriptive, "The server has been stopped."));
    try expectRules(&.{"STE-3.4"}, try sink.check(&dict, .descriptive, "The server has stopped."));
    try expectRules(&.{"STE-3.6"}, try sink.check(&dict, .descriptive, "The request is not processed."));
    try expectRules(&.{"STE-3.6"}, try sink.check(&dict, .descriptive, "The frame was sent."));
    try expectRules(&.{}, try sink.check(&dict, .descriptive, "The option is enabled."));
    try expectRules(&.{"STE-3.5"}, try sink.check(&dict, .descriptive, "The server stops by sending a frame."));
    try expectRules(&.{"PRJ-1"}, try sink.check(&dict, .descriptive, "the server stops."));
    try expectRules(&.{}, try sink.check(&dict, .descriptive, "gRPC is a transport."));
    try expectRules(&.{}, try sink.check(&dict, .descriptive, "{code} is a function."));
    try expectRules(&.{"STE-6.3"}, try sink.check(&dict, .descriptive, "One two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour twentyfive twentysix."));
    try expectRules(&.{"STE-5.1"}, try sink.check(&dict, .procedural, "Do one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty."));
    try expectRules(&.{"STE-6.6"}, try sink.check(&dict, .descriptive, "A. B. C. D. E. F. G."));
}

test "a table cell that names key words is not a use" {
    try std.testing.expect(onlyKeywords("MUST NOT"));
    try std.testing.expect(!onlyKeywords("You MUST"));
}
