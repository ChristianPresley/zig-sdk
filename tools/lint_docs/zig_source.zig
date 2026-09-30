//! The Zig part of lint-docs. It parses a source file with `std.zig.Ast` and gives the
//! doc comments, the user-visible string literals and the parse errors.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;

/// The lines of one doc comment as Markdown, without the `///` or `//!` marks.
pub const DocComment = struct {
    text: []const u8,
    /// The line of the first `///` or `//!` line.
    line: usize,
};

/// A string literal that the SDK shows to a user.
pub const StringLiteral = struct {
    text: []const u8,
    line: usize,
};

/// A parse error with its line and the message of the Zig parser.
pub const ParseError = struct {
    line: usize,
    message: []const u8,
};

/// The result of the Zig pass.
pub const Source = struct {
    doc_comments: []const DocComment,
    string_literals: []const StringLiteral,
    parse_errors: []const ParseError,
};

/// Parses `source` and collects the doc comments. With `string_literals`, it also collects
/// the string literals of `.message = "..."` field values outside `test` blocks.
pub fn scan(arena: Allocator, source: []const u8, string_literals: bool) !Source {
    const source_z = try arena.dupeZ(u8, source);
    var tree = try Ast.parse(arena, source_z, .zig);
    defer tree.deinit(arena);

    var errors: std.ArrayList(ParseError) = .empty;
    for (tree.errors) |e| {
        var aw: std.Io.Writer.Allocating = .init(arena);
        try tree.renderError(e, &aw.writer);
        const loc = tree.tokenLocation(0, e.token);
        try errors.append(arena, .{ .line = loc.line + 1, .message = aw.written() });
    }

    var docs: std.ArrayList(DocComment) = .empty;
    var literals: std.ArrayList(StringLiteral) = .empty;
    const tags = tree.tokens.items(.tag);
    const starts = tree.tokens.items(.start);

    var line: usize = 1;
    var offset: usize = 0;
    var current: std.ArrayList(u8) = .empty;
    var current_line: usize = 0;
    var current_tag: std.zig.Token.Tag = .invalid;
    var previous_line: usize = 0;
    var test_depth: ?usize = null;
    var brace_depth: usize = 0;
    var i: usize = 0;
    while (i < tags.len) : (i += 1) {
        const start = starts[i];
        line += std.mem.count(u8, source[offset..start], "\n");
        offset = start;
        const tag = tags[i];
        switch (tag) {
            .doc_comment, .container_doc_comment => {
                const slice = tree.tokenSlice(@intCast(i));
                var body = std.mem.trimEnd(u8, slice[3..], "\r");
                if (body.len > 0 and body[0] == ' ') body = body[1..];
                const continues = current.items.len > 0 and current_tag == tag and previous_line + 1 == line;
                if (!continues) {
                    try flushDoc(arena, &docs, &current, current_line);
                    current_line = line;
                    current_tag = tag;
                } else {
                    try current.append(arena, '\n');
                }
                // An empty doc comment line keeps the paragraph break.
                try current.appendSlice(arena, if (current.items.len == 0 and body.len == 0) " " else body);
                previous_line = line;
                continue;
            },
            .keyword_test => {
                if (test_depth == null) test_depth = brace_depth;
            },
            .l_brace => brace_depth += 1,
            .r_brace => {
                if (brace_depth > 0) brace_depth -= 1;
                if (test_depth) |d| if (brace_depth == d) {
                    test_depth = null;
                };
            },
            .string_literal => {
                if (string_literals and test_depth == null and i >= 3 and
                    tags[i - 1] == .equal and tags[i - 2] == .identifier and tags[i - 3] == .period and
                    std.mem.eql(u8, tree.tokenSlice(@intCast(i - 2)), "message"))
                {
                    const raw = tree.tokenSlice(@intCast(i));
                    const value = std.zig.string_literal.parseAlloc(arena, raw) catch raw;
                    try literals.append(arena, .{ .text = value, .line = line });
                }
            },
            else => {},
        }
        try flushDoc(arena, &docs, &current, current_line);
    }
    try flushDoc(arena, &docs, &current, current_line);
    return .{ .doc_comments = docs.items, .string_literals = literals.items, .parse_errors = errors.items };
}

fn flushDoc(arena: Allocator, docs: *std.ArrayList(DocComment), current: *std.ArrayList(u8), line: usize) !void {
    if (current.items.len == 0) return;
    try docs.append(arena, .{ .text = try arena.dupe(u8, current.items), .line = line });
    current.clearRetainingCapacity();
}

/// Returns the summary of a doc comment: the text before the first empty line, a list or a code block.
pub fn summary(doc: []const u8) []const u8 {
    var end: usize = 0;
    var lines = std.mem.splitScalar(u8, doc, '\n');
    var first = true;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) break;
        if (!first and (std.mem.startsWith(u8, line, "- ") or std.mem.startsWith(u8, line, "* ") or std.mem.startsWith(u8, line, "```"))) break;
        if (first and std.mem.startsWith(u8, line, "```")) return "";
        first = false;
        end = @intFromPtr(raw.ptr) - @intFromPtr(doc.ptr) + raw.len;
    }
    return std.mem.trim(u8, doc[0..end], " \t\r\n");
}

test "doc comments, string literals and parse errors" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const src =
        \\//! Module summary.
        \\//! Second line.
        \\
        \\/// A function.
        \\///
        \\/// More text.
        \\pub fn f() void {
        \\    _ = .{ .message = "Header mismatch" };
        \\}
        \\
        \\test "x" {
        \\    _ = .{ .message = "boom" };
        \\}
    ;
    const result = try scan(arena, src, true);
    try std.testing.expectEqual(2, result.doc_comments.len);
    try std.testing.expectEqualStrings("Module summary.\nSecond line.", result.doc_comments[0].text);
    try std.testing.expectEqual(1, result.doc_comments[0].line);
    try std.testing.expectEqualStrings("A function.\n\nMore text.", result.doc_comments[1].text);
    try std.testing.expectEqual(4, result.doc_comments[1].line);
    try std.testing.expectEqual(1, result.string_literals.len);
    try std.testing.expectEqualStrings("Header mismatch", result.string_literals[0].text);
    try std.testing.expectEqual(8, result.string_literals[0].line);
    try std.testing.expectEqual(0, result.parse_errors.len);

    const bad = try scan(arena, "const x = ;\n", false);
    try std.testing.expectEqual(1, bad.parse_errors.len);
    try std.testing.expectEqual(1, bad.parse_errors[0].line);
}

test "doc comment summary" {
    try std.testing.expectEqualStrings("One line.", summary("One line.\n\nMore."));
    try std.testing.expectEqualStrings("Two\nlines", summary("Two\nlines\n- item"));
    try std.testing.expectEqualStrings("", summary("```zig\ncode\n```"));
}
