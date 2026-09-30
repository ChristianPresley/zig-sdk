//! The word lists of lint-docs. The lists are the files in `docs/dictionary/`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const Dictionary = @This();

/// A word or a phrase that the project does not use, with the replacement.
pub const Replacement = struct { word: []const u8, replacement: []const u8 };

/// Words that the project does not use (STE-1.1).
banned: []const Replacement = &.{},
/// Words that end in `-ing` and that the project approves (STE-3.5).
ing_allow: []const []const u8 = &.{},
/// Past participles that the project approves as adjectives after a form of "be" (STE-3.6).
participles: []const []const u8 = &.{},
/// Abbreviations and names with a fixed case that the project declares (PRJ-2).
abbreviations: []const []const u8 = &.{},
/// British spellings with the US spelling (PRJ-3).
spelling: []const Replacement = &.{},
/// Terms that have a preferred synonym (PRJ-4).
synonyms: []const Replacement = &.{},
/// Phrasal verbs with the replacement (PRJ-5).
phrasal_verbs: []const Replacement = &.{},

/// Reads every list from `path`. A list that does not exist stays empty.
pub fn load(arena: Allocator, io: Io, dir: Io.Dir, path: []const u8) !Dictionary {
    var sub = dir.openDir(io, path, .{}) catch |err| {
        std.debug.print("lint-docs: cannot open the dictionary {s}: {t}\n", .{ path, err });
        return .{};
    };
    defer sub.close(io);
    return .{
        .banned = try pairs(arena, try read(arena, io, sub, "project_word_list.txt"), "->"),
        .ing_allow = try words(arena, try read(arena, io, sub, "ing_allowlist.txt")),
        .participles = try words(arena, try read(arena, io, sub, "participles.txt")),
        .abbreviations = try keys(arena, try read(arena, io, sub, "abbreviations.txt")),
        .spelling = try pairs(arena, try read(arena, io, sub, "spelling_us.txt"), "->"),
        .synonyms = try pairs(arena, try read(arena, io, sub, "synonyms.txt"), "->"),
        .phrasal_verbs = try pairs(arena, try read(arena, io, sub, "phrasal_verbs.txt"), "->"),
    };
}

fn read(arena: Allocator, io: Io, dir: Io.Dir, name: []const u8) ![]const u8 {
    return dir.readFileAlloc(io, name, arena, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => "",
        else => |e| return e,
    };
}

/// Returns the lines of a list without comments and empty lines.
pub fn words(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        try out.append(arena, line);
    }
    return out.items;
}

/// Returns the part before `:` of each line, such as `TLS` of `TLS: Transport Layer Security`.
pub fn keys(arena: Allocator, text: []const u8) ![]const []const u8 {
    const lines = try words(arena, text);
    const out = try arena.alloc([]const u8, lines.len);
    for (lines, out) |line, *key| {
        const colon = std.mem.find(u8, line, ": ") orelse line.len;
        key.* = std.mem.trim(u8, line[0..colon], " \t");
    }
    return out;
}

/// Returns the lines `word -> replacement` of a list. The word is in lowercase.
pub fn pairs(arena: Allocator, text: []const u8, separator: []const u8) ![]const Replacement {
    const lines = try words(arena, text);
    var out: std.ArrayList(Replacement) = .empty;
    for (lines) |line| {
        if (std.mem.find(u8, line, separator)) |i| {
            const word = std.mem.trim(u8, line[0..i], " \t");
            const rest = std.mem.trim(u8, line[i + separator.len ..], " \t");
            try out.append(arena, .{ .word = try std.ascii.allocLowerString(arena, word), .replacement = rest });
        } else {
            try out.append(arena, .{ .word = try std.ascii.allocLowerString(arena, line), .replacement = "" });
        }
    }
    return out.items;
}

/// Returns true when `word` is in `list`.
pub fn has(list: []const []const u8, word: []const u8) bool {
    for (list) |item| if (std.mem.eql(u8, item, word)) return true;
    return false;
}

/// Returns true when `word` is a declared name with a fixed case that starts with a
/// lowercase letter, such as `gRPC` or `stdio`. A sentence can start with such a name.
pub fn isLowercaseName(dict: Dictionary, word: []const u8) bool {
    if (word.len == 0 or !std.ascii.isLower(word[0])) return false;
    return has(dict.abbreviations, word);
}

test "pairs and keys" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const p = try pairs(arena, "# comment\nShould -> must\n\nsession\n", "->");
    try std.testing.expectEqual(2, p.len);
    try std.testing.expectEqualStrings("should", p[0].word);
    try std.testing.expectEqualStrings("must", p[0].replacement);
    try std.testing.expectEqualStrings("", p[1].replacement);
    const k = try keys(arena, "TLS: Transport Layer Security\nHTTP/2: version 2\n");
    try std.testing.expectEqualStrings("TLS", k[0]);
    try std.testing.expectEqualStrings("HTTP/2", k[1]);
}
