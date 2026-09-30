//! A regular expression engine for the JSON Schema keywords `pattern` and `patternProperties`.
//!
//! The engine reads the ECMA-262 dialect that JSON Schema 2020-12 recommends. It compiles a
//! pattern to a Thompson automaton and runs the automaton as a Pike machine. The engine never
//! goes back in the input. The time of one match is linear in the input length multiplied by
//! the program size. Thus no pattern can cause catastrophic run time.
//!
//! The engine reads the pattern and the input as Unicode code points. It uses the escape rules
//! of the ECMA-262 `u` flag with four relaxations from ECMA-262 Annex B:
//!
//! - A `{` that does not start a quantifier, and a `}` or `]` outside a class, are literals.
//! - A `-` next to a class escape in a class is a literal.
//! - An identity escape can escape each code point that is not an ASCII letter or digit.
//!
//! A search has no implicit anchor. A pattern matches when it matches a part of the input. The engine
//! has no flags. Thus `^` and `$` match only at the start and at the end of the input.
//!
//! The engine rejects these features with `error.UnsupportedRegex`:
//!
//! - Backreferences (`\1` to `\9` and `\k<name>`).
//! - Lookahead and lookbehind assertions.
//! - Pattern modifiers (`(?i:x)`).
//! - Legacy octal escapes (`\01`).
//! - Unicode property escapes other than `\p{Any}`, `\p{ASCII}` and `\p{ASCII_Hex_Digit}`.
//!
//! The engine accepts a lazy quantifier. It has the same result as a greedy quantifier, because
//! the engine only tells if a match exists.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    OutOfMemory,
    /// The pattern is not a valid ECMA-262 regular expression.
    InvalidRegex,
    /// The pattern uses a feature that the engine does not support.
    UnsupportedRegex,
    /// The pattern is longer than `Options.max_pattern_bytes`, its program is larger than
    /// `Options.max_states`, or it has more than `max_group_depth` levels of groups.
    RegexTooLarge,
};

pub const Options = struct {
    /// Maximum bytes of the pattern text.
    max_pattern_bytes: usize = 4096,
    /// Maximum instructions of the compiled program. A counted repetition multiplies the
    /// size of its operand.
    max_states: u32 = 4096,
    /// When set, receives the location of a compile error.
    diagnostic: ?*Diagnostic = null,
};

/// The location of a compile error.
pub const Diagnostic = struct {
    /// Byte offset in the pattern where the compiler found the error.
    offset: usize = 0,
};

/// Maximum depth of groups in groups. Deeper patterns fail with `error.RegexTooLarge`.
pub const max_group_depth = 128;

/// An inclusive range of code points.
pub const Range = struct { lo: u21, hi: u21 };

const max_code_point: u21 = 0x10FFFF;

const Assert = enum { begin, end, word_boundary, not_word_boundary };

const Span = struct { start: u32, len: u32 };

const Inst = union(enum) {
    char: u21,
    any,
    set: Span,
    split: [2]u32,
    jmp: u32,
    assert: Assert,
    match,
};

/// A compiled regular expression. The value is immutable and threads can share it.
pub const Regex = struct {
    insts: []const Inst,
    ranges: []const Range,
    /// True when every match must start at the first code point.
    anchored: bool,

    /// Free a regular expression that `compile` made with the same allocator.
    pub fn deinit(self: *Regex, gpa: Allocator) void {
        gpa.free(self.insts);
        gpa.free(self.ranges);
        self.* = undefined;
    }

    /// The number of `u32` items that `isMatchBuffer` needs.
    pub fn bufferLen(self: *const Regex) usize {
        return 5 * self.insts.len;
    }

    /// Tell if the pattern matches a part of `input`. The function allocates one buffer.
    pub fn isMatch(self: *const Regex, gpa: Allocator, input: []const u8) Allocator.Error!bool {
        const buffer = try gpa.alloc(u32, self.bufferLen());
        defer gpa.free(buffer);
        return self.isMatchBuffer(buffer, input);
    }

    /// Tell if the pattern matches a part of `input`. The function uses `buffer` as work
    /// memory and does not allocate. The buffer has at least `bufferLen()` items.
    pub fn isMatchBuffer(self: *const Regex, buffer: []u32, input: []const u8) bool {
        var work: u64 = 0;
        return self.run(buffer, input, &work);
    }

    fn run(self: *const Regex, buffer: []u32, input: []const u8, work: *u64) bool {
        const n = self.insts.len;
        std.debug.assert(buffer.len >= 5 * n);
        var cur: SparseSet = .{ .dense = buffer[0..n], .sparse = buffer[n .. 2 * n] };
        var nxt: SparseSet = .{ .dense = buffer[2 * n .. 3 * n], .sparse = buffer[3 * n .. 4 * n] };
        const stack = buffer[4 * n .. 5 * n];
        var pos: usize = 0;
        var prev: ?u21 = null;
        var here = decodeAt(input, 0);
        while (true) {
            if (pos == 0 or !self.anchored) {
                const at: Context = .{ .prev = prev, .next = if (here) |d| d.cp else null };
                if (self.addThread(&cur, stack, 0, at, work)) return true;
            }
            const d = here orelse return false;
            if (cur.len == 0 and self.anchored) return false;
            const after = decodeAt(input, pos + d.len);
            const at_next: Context = .{ .prev = d.cp, .next = if (after) |a| a.cp else null };
            nxt.len = 0;
            for (cur.dense[0..cur.len]) |pc| {
                work.* += 1;
                const ok = switch (self.insts[pc]) {
                    .char => |c| c == d.cp,
                    .any => !isLineTerminator(d.cp),
                    .set => |s| inRanges(self.ranges[s.start..][0..s.len], d.cp),
                    else => false,
                };
                if (ok and self.addThread(&nxt, stack, pc + 1, at_next, work)) return true;
            }
            std.mem.swap(SparseSet, &cur, &nxt);
            pos += d.len;
            prev = d.cp;
            here = after;
        }
    }

    /// Add the thread at `start` and every thread that it reaches without input. Return true
    /// when one of them reaches the match instruction.
    fn addThread(self: *const Regex, set: *SparseSet, stack: []u32, start: u32, at: Context, work: *u64) bool {
        if (set.contains(start)) return false;
        set.insert(start);
        var sp: usize = 0;
        stack[sp] = start;
        sp += 1;
        while (sp > 0) {
            sp -= 1;
            const pc = stack[sp];
            work.* += 1;
            const targets: [2]?u32 = switch (self.insts[pc]) {
                .match => return true,
                .jmp => |t| .{ t, null },
                .split => |t| .{ t[1], t[0] },
                .assert => |a| .{ if (at.holds(a)) pc + 1 else null, null },
                else => .{ null, null },
            };
            for (targets) |maybe| if (maybe) |t| if (!set.contains(t)) {
                set.insert(t);
                stack[sp] = t;
                sp += 1;
            };
        }
        return false;
    }
};

const SparseSet = struct {
    dense: []u32,
    sparse: []u32,
    len: u32 = 0,

    fn contains(self: *const SparseSet, v: u32) bool {
        const i = self.sparse[v];
        return i < self.len and self.dense[i] == v;
    }

    fn insert(self: *SparseSet, v: u32) void {
        self.sparse[v] = self.len;
        self.dense[self.len] = v;
        self.len += 1;
    }
};

const Context = struct {
    prev: ?u21,
    next: ?u21,

    fn holds(self: Context, a: Assert) bool {
        return switch (a) {
            .begin => self.prev == null,
            .end => self.next == null,
            .word_boundary => isWordOpt(self.prev) != isWordOpt(self.next),
            .not_word_boundary => isWordOpt(self.prev) == isWordOpt(self.next),
        };
    }
};

fn isWordOpt(cp: ?u21) bool {
    const c = cp orelse return false;
    return inRanges(&word_ranges, c);
}

fn isLineTerminator(cp: u21) bool {
    return cp == '\n' or cp == '\r' or cp == 0x2028 or cp == 0x2029;
}

fn inRanges(ranges: []const Range, cp: u21) bool {
    var lo: usize = 0;
    var hi: usize = ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const r = ranges[mid];
        if (cp < r.lo) {
            hi = mid;
        } else if (cp > r.hi) {
            lo = mid + 1;
        } else return true;
    }
    return false;
}

const Decoded = struct { cp: u21, len: u3 };

/// Decode one code point. Bytes that are not UTF-8 decode to `U+FFFD` one byte at a time.
/// Encoded surrogates decode to their code point.
fn decodeAt(s: []const u8, i: usize) ?Decoded {
    if (i >= s.len) return null;
    const bad: Decoded = .{ .cp = 0xFFFD, .len = 1 };
    const b0 = s[i];
    if (b0 < 0x80) return .{ .cp = b0, .len = 1 };
    const len: u3 = if (b0 & 0xE0 == 0xC0) 2 else if (b0 & 0xF0 == 0xE0) 3 else if (b0 & 0xF8 == 0xF0) 4 else return bad;
    if (i + len > s.len) return bad;
    var cp: u32 = b0 & (@as(u8, 0x7F) >> len);
    for (s[i + 1 .. i + len]) |b| {
        if (b & 0xC0 != 0x80) return bad;
        cp = (cp << 6) | (b & 0x3F);
    }
    const min: u32 = switch (len) {
        2 => 0x80,
        3 => 0x800,
        else => 0x10000,
    };
    if (cp < min or cp > max_code_point) return bad;
    return .{ .cp = @intCast(cp), .len = len };
}

// -- Character sets --------------------------------------------------------------------------

const digit_ranges = [_]Range{.{ .lo = '0', .hi = '9' }};
const word_ranges = [_]Range{ .{ .lo = '0', .hi = '9' }, .{ .lo = 'A', .hi = 'Z' }, .{ .lo = '_', .hi = '_' }, .{ .lo = 'a', .hi = 'z' } };
/// ECMA-262 WhiteSpace and LineTerminator. The Zs code points come from Unicode 16.
const space_ranges = [_]Range{
    .{ .lo = 0x09, .hi = 0x0D },     .{ .lo = 0x20, .hi = 0x20 },     .{ .lo = 0xA0, .hi = 0xA0 },
    .{ .lo = 0x1680, .hi = 0x1680 }, .{ .lo = 0x2000, .hi = 0x200A }, .{ .lo = 0x2028, .hi = 0x2029 },
    .{ .lo = 0x202F, .hi = 0x202F }, .{ .lo = 0x205F, .hi = 0x205F }, .{ .lo = 0x3000, .hi = 0x3000 },
    .{ .lo = 0xFEFF, .hi = 0xFEFF },
};
const any_ranges = [_]Range{.{ .lo = 0, .hi = max_code_point }};
const ascii_ranges = [_]Range{.{ .lo = 0, .hi = 0x7F }};
const hex_ranges = [_]Range{ .{ .lo = '0', .hi = '9' }, .{ .lo = 'A', .hi = 'F' }, .{ .lo = 'a', .hi = 'f' } };

/// Append `table` or its complement. The ranges of `table` go up in order and do not
/// overlap.
fn appendTable(gpa: Allocator, out: *std.ArrayList(Range), table: []const Range, negate: bool) Allocator.Error!void {
    if (!negate) return out.appendSlice(gpa, table);
    var next: u32 = 0;
    for (table) |r| {
        if (r.lo > next) try out.append(gpa, .{ .lo = @intCast(next), .hi = r.lo - 1 });
        next = @as(u32, r.hi) + 1;
    }
    if (next <= max_code_point) try out.append(gpa, .{ .lo = @intCast(next), .hi = max_code_point });
}

fn rangeLessThan(_: void, a: Range, b: Range) bool {
    return a.lo < b.lo;
}

/// Sort and merge `items` in place and return the merged prefix.
fn normalize(items: []Range) []Range {
    if (items.len == 0) return items;
    std.mem.sort(Range, items, {}, rangeLessThan);
    var n: usize = 0;
    for (items) |r| {
        if (n > 0 and @as(u32, r.lo) <= @as(u32, items[n - 1].hi) + 1) {
            items[n - 1].hi = @max(items[n - 1].hi, r.hi);
        } else {
            items[n] = r;
            n += 1;
        }
    }
    return items[0..n];
}

// -- Parser ----------------------------------------------------------------------------------

const NodeIndex = u32;

const Node = union(enum) {
    empty,
    char: u21,
    any,
    set: Span,
    assert: Assert,
    concat: Span,
    alt: Span,
    repeat: Repeat,
};

const Repeat = struct { sub: NodeIndex, min: u32, max: ?u32 };

const Quantifier = struct { min: u32, max: ?u32, end: usize };

const Parser = struct {
    gpa: Allocator,
    cps: []const u21,
    offsets: []const usize,
    max_states: u32,
    diagnostic: ?*Diagnostic,
    pos: usize = 0,
    nodes: std.ArrayList(Node) = .empty,
    sizes: std.ArrayList(u64) = .empty,
    kids: std.ArrayList(NodeIndex) = .empty,
    ranges: std.ArrayList(Range) = .empty,

    fn deinit(p: *Parser) void {
        p.nodes.deinit(p.gpa);
        p.sizes.deinit(p.gpa);
        p.kids.deinit(p.gpa);
        p.ranges.deinit(p.gpa);
    }

    fn fail(p: *Parser, err: Error) Error {
        if (p.diagnostic) |d| d.offset = p.offsets[@min(p.pos, p.cps.len)];
        return err;
    }

    fn peek(p: *const Parser) ?u21 {
        return p.peekAt(0);
    }

    fn peekAt(p: *const Parser, ahead: usize) ?u21 {
        const i = p.pos + ahead;
        return if (i < p.cps.len) p.cps[i] else null;
    }

    fn eat(p: *Parser, c: u21) bool {
        if (p.peek() != c) return false;
        p.pos += 1;
        return true;
    }

    fn add(p: *Parser, node: Node, size: u64) Error!NodeIndex {
        if (size > p.max_states) return p.fail(error.RegexTooLarge);
        try p.nodes.append(p.gpa, node);
        try p.sizes.append(p.gpa, size);
        return @intCast(p.nodes.items.len - 1);
    }

    fn addList(p: *Parser, items: []const NodeIndex, comptime tag: std.meta.Tag(Node)) Error!NodeIndex {
        var size: u64 = 0;
        for (items) |k| size +|= p.sizes.items[k];
        if (tag == .alt) size +|= 2 * (items.len - 1);
        const span: Span = .{ .start = @intCast(p.kids.items.len), .len = @intCast(items.len) };
        try p.kids.appendSlice(p.gpa, items);
        return p.add(@unionInit(Node, @tagName(tag), span), size);
    }

    fn parseDisjunction(p: *Parser, depth: u32) Error!NodeIndex {
        if (depth > max_group_depth) return p.fail(error.RegexTooLarge);
        var alts: std.ArrayList(NodeIndex) = .empty;
        defer alts.deinit(p.gpa);
        try alts.append(p.gpa, try p.parseAlternative(depth));
        while (p.eat('|')) try alts.append(p.gpa, try p.parseAlternative(depth));
        if (alts.items.len == 1) return alts.items[0];
        return p.addList(alts.items, .alt);
    }

    fn parseAlternative(p: *Parser, depth: u32) Error!NodeIndex {
        var terms: std.ArrayList(NodeIndex) = .empty;
        defer terms.deinit(p.gpa);
        while (p.peek()) |c| {
            if (c == '|' or c == ')') break;
            try terms.append(p.gpa, try p.parseTerm(depth));
        }
        return switch (terms.items.len) {
            0 => p.add(.empty, 0),
            1 => terms.items[0],
            else => p.addList(terms.items, .concat),
        };
    }

    fn parseTerm(p: *Parser, depth: u32) Error!NodeIndex {
        const c = p.peek().?;
        const assertion: ?Assert = switch (c) {
            '^' => .begin,
            '$' => .end,
            '\\' => if (p.peekAt(1)) |n| switch (n) {
                'b' => .word_boundary,
                'B' => .not_word_boundary,
                else => null,
            } else null,
            else => null,
        };
        if (assertion) |a| {
            p.pos += if (c == '\\') 2 else 1;
            if (try p.scanQuantifier() != null) return p.fail(error.InvalidRegex);
            return p.add(.{ .assert = a }, 1);
        }
        const atom = try p.parseAtom(depth);
        const q = (try p.scanQuantifier()) orelse return atom;
        p.pos = q.end;
        const s = p.sizes.items[atom];
        const size = if (q.max) |m|
            s *| q.min +| (m - q.min) *| (s + 1)
        else
            s *| q.min +| s +| 2;
        return p.add(.{ .repeat = .{ .sub = atom, .min = q.min, .max = q.max } }, size);
    }

    /// Read a quantifier at the current position. The position does not change.
    fn scanQuantifier(p: *Parser) Error!?Quantifier {
        const c = p.peek() orelse return null;
        var q: Quantifier = switch (c) {
            '*' => .{ .min = 0, .max = null, .end = p.pos + 1 },
            '+' => .{ .min = 1, .max = null, .end = p.pos + 1 },
            '?' => .{ .min = 0, .max = 1, .end = p.pos + 1 },
            '{' => blk: {
                var i = p.pos + 1;
                const min = p.scanNumber(&i) orelse return null;
                var max: ?u32 = min;
                if (i < p.cps.len and p.cps[i] == ',') {
                    i += 1;
                    max = p.scanNumber(&i);
                }
                if (i >= p.cps.len or p.cps[i] != '}') return null;
                if (max) |m| if (m < min) return p.fail(error.InvalidRegex);
                break :blk .{ .min = min, .max = max, .end = i + 1 };
            },
            else => return null,
        };
        if (q.end < p.cps.len and p.cps[q.end] == '?') q.end += 1;
        return q;
    }

    fn scanNumber(p: *const Parser, i: *usize) ?u32 {
        const start = i.*;
        var v: u32 = 0;
        while (i.* < p.cps.len and isDigit(p.cps[i.*])) : (i.* += 1) {
            v = v *| 10 +| (p.cps[i.*] - '0');
        }
        return if (i.* == start) null else v;
    }

    fn parseAtom(p: *Parser, depth: u32) Error!NodeIndex {
        const c = p.peek().?;
        switch (c) {
            '*', '+', '?' => return p.fail(error.InvalidRegex),
            '{' => {
                if (try p.scanQuantifier() != null) return p.fail(error.InvalidRegex);
                p.pos += 1;
                return p.add(.{ .char = '{' }, 1);
            },
            '.' => {
                p.pos += 1;
                return p.add(.any, 1);
            },
            '(' => return p.parseGroup(depth),
            '[' => return p.parseClass(),
            '\\' => return p.parseAtomEscape(),
            else => {
                p.pos += 1;
                return p.add(.{ .char = c }, 1);
            },
        }
    }

    fn parseGroup(p: *Parser, depth: u32) Error!NodeIndex {
        p.pos += 1;
        if (p.eat('?')) {
            const n = p.peek() orelse return p.fail(error.InvalidRegex);
            switch (n) {
                ':' => p.pos += 1,
                '=', '!' => return p.fail(error.UnsupportedRegex),
                '<' => {
                    const n2 = p.peekAt(1);
                    if (n2 == '=' or n2 == '!') return p.fail(error.UnsupportedRegex);
                    p.pos += 1;
                    try p.parseGroupName();
                },
                else => {
                    // Pattern modifiers look like `(?i:x)` or `(?-i:x)`.
                    var i: usize = 0;
                    while (p.peekAt(i)) |m| : (i += 1) {
                        if (!(isAsciiLetter(m) or m == '-')) break;
                    }
                    if (i > 0 and p.peekAt(i) == ':') return p.fail(error.UnsupportedRegex);
                    return p.fail(error.InvalidRegex);
                },
            }
        }
        const inner = try p.parseDisjunction(depth + 1);
        if (!p.eat(')')) return p.fail(error.InvalidRegex);
        return inner;
    }

    fn parseGroupName(p: *Parser) Error!void {
        const start = p.pos;
        while (p.peek()) |c| {
            if (c == '>') break;
            const ok = isAsciiLetter(c) or c == '_' or c == '$' or c >= 0x80 or (isDigit(c) and p.pos > start);
            if (!ok) return p.fail(error.InvalidRegex);
            p.pos += 1;
        }
        if (p.pos == start or !p.eat('>')) return p.fail(error.InvalidRegex);
    }

    fn parseAtomEscape(p: *Parser) Error!NodeIndex {
        p.pos += 1;
        const e = p.peek() orelse return p.fail(error.InvalidRegex);
        switch (e) {
            'd', 'D', 'w', 'W', 's', 'S', 'p', 'P' => {
                var tmp: std.ArrayList(Range) = .empty;
                defer tmp.deinit(p.gpa);
                try p.parseSetEscape(&tmp);
                return p.addSet(tmp.items, false);
            },
            'k' => return p.fail(if (p.peekAt(1) == '<') error.UnsupportedRegex else error.InvalidRegex),
            else => return p.add(.{ .char = try p.parseCharEscape() }, 1),
        }
    }

    /// Parse `\d`, `\D`, `\w`, `\W`, `\s`, `\S`, `\p{...}` or `\P{...}` after the backslash.
    fn parseSetEscape(p: *Parser, out: *std.ArrayList(Range)) Error!void {
        const e = p.peek().?;
        p.pos += 1;
        switch (e) {
            'd', 'D' => try appendTable(p.gpa, out, &digit_ranges, e == 'D'),
            'w', 'W' => try appendTable(p.gpa, out, &word_ranges, e == 'W'),
            's', 'S' => try appendTable(p.gpa, out, &space_ranges, e == 'S'),
            'p', 'P' => {
                if (!p.eat('{')) return p.fail(error.InvalidRegex);
                const start = p.pos;
                while (p.peek()) |c| : (p.pos += 1) {
                    if (c == '}') break;
                    if (!(isAsciiLetter(c) or isDigit(c) or c == '_' or c == '=')) return p.fail(error.InvalidRegex);
                }
                const name = p.cps[start..p.pos];
                if (name.len == 0 or !p.eat('}')) return p.fail(error.InvalidRegex);
                const table: []const Range = if (eqlAscii(name, "Any"))
                    &any_ranges
                else if (eqlAscii(name, "ASCII"))
                    &ascii_ranges
                else if (eqlAscii(name, "ASCII_Hex_Digit") or eqlAscii(name, "AHex"))
                    &hex_ranges
                else
                    return p.fail(error.UnsupportedRegex);
                try appendTable(p.gpa, out, table, e == 'P');
            },
            else => unreachable,
        }
    }

    /// Parse a character escape after the backslash and return its code point.
    fn parseCharEscape(p: *Parser) Error!u21 {
        const e = p.peek() orelse return p.fail(error.InvalidRegex);
        p.pos += 1;
        switch (e) {
            'f' => return 0x0C,
            'n' => return 0x0A,
            'r' => return 0x0D,
            't' => return 0x09,
            'v' => return 0x0B,
            'c' => {
                const l = p.peek() orelse return p.fail(error.InvalidRegex);
                if (!isAsciiLetter(l)) return p.fail(error.InvalidRegex);
                p.pos += 1;
                return l % 32;
            },
            '0' => {
                if (p.peek()) |d| if (isDigit(d)) return p.fail(error.UnsupportedRegex);
                return 0;
            },
            '1'...'9' => return p.fail(error.UnsupportedRegex),
            'x' => {
                const hi = hexValue(p.peekAt(0)) orelse return p.fail(error.InvalidRegex);
                const lo = hexValue(p.peekAt(1)) orelse return p.fail(error.InvalidRegex);
                p.pos += 2;
                return hi * 16 + lo;
            },
            'u' => return p.parseUnicodeEscape(),
            else => {
                if (isAsciiLetter(e) or isDigit(e)) return p.fail(error.InvalidRegex);
                return e;
            },
        }
    }

    fn parseUnicodeEscape(p: *Parser) Error!u21 {
        if (p.eat('{')) {
            var v: u32 = 0;
            var count: usize = 0;
            while (hexValue(p.peek())) |h| : (count += 1) {
                v = v * 16 + h;
                if (v > max_code_point) return p.fail(error.InvalidRegex);
                p.pos += 1;
            }
            if (count == 0 or !p.eat('}')) return p.fail(error.InvalidRegex);
            return @intCast(v);
        }
        const hi = p.hex4(0) orelse return p.fail(error.InvalidRegex);
        p.pos += 4;
        if (hi >= 0xD800 and hi <= 0xDBFF and p.peekAt(0) == '\\' and p.peekAt(1) == 'u') {
            if (p.hex4(2)) |lo| if (lo >= 0xDC00 and lo <= 0xDFFF) {
                p.pos += 6;
                return 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
            };
        }
        return hi;
    }

    fn hex4(p: *const Parser, ahead: usize) ?u21 {
        var v: u21 = 0;
        for (0..4) |i| v = v * 16 + (hexValue(p.peekAt(ahead + i)) orelse return null);
        return v;
    }

    fn parseClass(p: *Parser) Error!NodeIndex {
        p.pos += 1;
        const negate = p.eat('^');
        var tmp: std.ArrayList(Range) = .empty;
        defer tmp.deinit(p.gpa);
        while (true) {
            const c = p.peek() orelse return p.fail(error.InvalidRegex);
            if (c == ']') {
                p.pos += 1;
                break;
            }
            const a = try p.parseClassAtom(&tmp);
            const after_dash = p.peekAt(1);
            if (p.peek() == '-' and after_dash != null and after_dash.? != ']') {
                p.pos += 1;
                const b = try p.parseClassAtom(&tmp);
                if (a != null and b != null) {
                    if (a.? > b.?) return p.fail(error.InvalidRegex);
                    try tmp.append(p.gpa, .{ .lo = a.?, .hi = b.? });
                } else {
                    // Annex B: a dash next to a class escape is a literal.
                    if (a) |x| try tmp.append(p.gpa, .{ .lo = x, .hi = x });
                    try tmp.append(p.gpa, .{ .lo = '-', .hi = '-' });
                    if (b) |y| try tmp.append(p.gpa, .{ .lo = y, .hi = y });
                }
            } else if (a) |x| {
                try tmp.append(p.gpa, .{ .lo = x, .hi = x });
            }
        }
        return p.addSet(tmp.items, negate);
    }

    /// Parse one class atom. Return its code point, or null when it was a set escape that
    /// the function appended to `out`.
    fn parseClassAtom(p: *Parser, out: *std.ArrayList(Range)) Error!?u21 {
        const c = p.peek().?;
        p.pos += 1;
        if (c != '\\') return c;
        const e = p.peek() orelse return p.fail(error.InvalidRegex);
        switch (e) {
            'b' => {
                p.pos += 1;
                return 0x08;
            },
            '-' => {
                p.pos += 1;
                return '-';
            },
            'd', 'D', 'w', 'W', 's', 'S', 'p', 'P' => {
                try p.parseSetEscape(out);
                return null;
            },
            else => return try p.parseCharEscape(),
        }
    }

    fn addSet(p: *Parser, items: []Range, negate: bool) Error!NodeIndex {
        const merged = normalize(items);
        if (!negate and merged.len == 1 and merged[0].lo == merged[0].hi) return p.add(.{ .char = merged[0].lo }, 1);
        const start: u32 = @intCast(p.ranges.items.len);
        try appendTable(p.gpa, &p.ranges, merged, negate);
        const len: u32 = @as(u32, @intCast(p.ranges.items.len)) - start;
        return p.add(.{ .set = .{ .start = start, .len = len } }, 1);
    }
};

fn isDigit(c: u21) bool {
    return c >= '0' and c <= '9';
}

fn isAsciiLetter(c: u21) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

fn hexValue(c: ?u21) ?u21 {
    const x = c orelse return null;
    return switch (x) {
        '0'...'9' => x - '0',
        'a'...'f' => x - 'a' + 10,
        'A'...'F' => x - 'A' + 10,
        else => null,
    };
}

fn eqlAscii(cps: []const u21, s: []const u8) bool {
    if (cps.len != s.len) return false;
    for (cps, s) |a, b| if (a != b) return false;
    return true;
}

// -- Code generation -------------------------------------------------------------------------

const Emitter = struct {
    gpa: Allocator,
    p: *const Parser,
    insts: std.ArrayList(Inst) = .empty,

    fn here(e: *const Emitter) u32 {
        return @intCast(e.insts.items.len);
    }

    fn emit(e: *Emitter, index: NodeIndex) Allocator.Error!void {
        switch (e.p.nodes.items[index]) {
            .empty => {},
            .char => |c| try e.insts.append(e.gpa, .{ .char = c }),
            .any => try e.insts.append(e.gpa, .any),
            .set => |s| try e.insts.append(e.gpa, .{ .set = s }),
            .assert => |a| try e.insts.append(e.gpa, .{ .assert = a }),
            .concat => |span| for (e.p.kids.items[span.start..][0..span.len]) |k| try e.emit(k),
            .alt => |span| {
                const kids = e.p.kids.items[span.start..][0..span.len];
                var jumps: std.ArrayList(u32) = .empty;
                defer jumps.deinit(e.gpa);
                for (kids, 0..) |k, i| {
                    if (i + 1 == kids.len) {
                        try e.emit(k);
                        break;
                    }
                    const split_at = e.here();
                    try e.insts.append(e.gpa, .{ .split = .{ 0, 0 } });
                    try e.emit(k);
                    try jumps.append(e.gpa, e.here());
                    try e.insts.append(e.gpa, .{ .jmp = 0 });
                    e.insts.items[split_at] = .{ .split = .{ split_at + 1, e.here() } };
                }
                for (jumps.items) |j| e.insts.items[j] = .{ .jmp = e.here() };
            },
            .repeat => |r| {
                for (0..r.min) |_| try e.emit(r.sub);
                if (r.max) |max| {
                    var splits: std.ArrayList(u32) = .empty;
                    defer splits.deinit(e.gpa);
                    for (0..max - r.min) |_| {
                        try splits.append(e.gpa, e.here());
                        try e.insts.append(e.gpa, .{ .split = .{ 0, 0 } });
                        try e.emit(r.sub);
                    }
                    for (splits.items) |s| e.insts.items[s] = .{ .split = .{ s + 1, e.here() } };
                } else {
                    const loop = e.here();
                    try e.insts.append(e.gpa, .{ .split = .{ 0, 0 } });
                    try e.emit(r.sub);
                    try e.insts.append(e.gpa, .{ .jmp = loop });
                    e.insts.items[loop] = .{ .split = .{ loop + 1, e.here() } };
                }
            },
        }
    }
};

/// Compile an ECMA-262 pattern. The caller owns the result and frees it with `Regex.deinit`.
pub fn compile(gpa: Allocator, pattern: []const u8, options: Options) Error!Regex {
    if (pattern.len > options.max_pattern_bytes) {
        if (options.diagnostic) |d| d.offset = options.max_pattern_bytes;
        return error.RegexTooLarge;
    }
    var cps: std.ArrayList(u21) = .empty;
    defer cps.deinit(gpa);
    var offsets: std.ArrayList(usize) = .empty;
    defer offsets.deinit(gpa);
    var i: usize = 0;
    while (decodeAt(pattern, i)) |d| {
        if (d.len == 1 and pattern[i] >= 0x80) {
            if (options.diagnostic) |diag| diag.offset = i;
            return error.InvalidRegex;
        }
        try cps.append(gpa, d.cp);
        try offsets.append(gpa, i);
        i += d.len;
    }
    try offsets.append(gpa, pattern.len);

    var p: Parser = .{
        .gpa = gpa,
        .cps = cps.items,
        .offsets = offsets.items,
        .max_states = options.max_states,
        .diagnostic = options.diagnostic,
    };
    defer p.deinit();
    const root = try p.parseDisjunction(0);
    if (p.pos != cps.items.len) return p.fail(error.InvalidRegex);
    if (p.sizes.items[root] +| 1 > options.max_states) return p.fail(error.RegexTooLarge);

    var e: Emitter = .{ .gpa = gpa, .p = &p };
    defer e.insts.deinit(gpa);
    try e.insts.ensureTotalCapacity(gpa, @intCast(p.sizes.items[root] + 1));
    try e.emit(root);
    try e.insts.append(gpa, .match);

    const anchored = switch (p.nodes.items[root]) {
        .assert => |a| a == .begin,
        .concat => |span| blk: {
            const first = p.nodes.items[p.kids.items[span.start]];
            break :blk first == .assert and first.assert == .begin;
        },
        else => false,
    };
    const insts = try e.insts.toOwnedSlice(gpa);
    errdefer gpa.free(insts);
    const ranges = try p.ranges.toOwnedSlice(gpa);
    return .{ .insts = insts, .ranges = ranges, .anchored = anchored };
}

// -- Tests -----------------------------------------------------------------------------------

const testing = std.testing;

fn expectMatch(pattern: []const u8, input: []const u8, expected: bool) !void {
    var re = try compile(testing.allocator, pattern, .{});
    defer re.deinit(testing.allocator);
    const got = try re.isMatch(testing.allocator, input);
    if (got != expected) {
        std.debug.print("pattern \"{s}\" input \"{s}\": expected {}\n", .{ pattern, input, expected });
        return error.TestUnexpectedResult;
    }
}

const MatchCase = struct { []const u8, []const u8, bool };

fn expectCases(cases: []const MatchCase) !void {
    for (cases) |c| try expectMatch(c[0], c[1], c[2]);
}

test "literals, dot and unanchored search" {
    try expectCases(&.{
        .{ "abc", "xxabcxx", true },
        .{ "abc", "abx", false },
        .{ "", "", true },
        .{ "", "anything", true },
        .{ "a.c", "abc", true },
        .{ "a.c", "a\nc", false },
        .{ "a.c", "a\u{2028}c", false },
        .{ "a.c", "a\u{1F600}c", true },
        .{ "^.$", "\u{1F600}", true },
        .{ "^..$", "\u{1F600}", false },
        .{ "^\u{e9}$", "\u{e9}", true },
        .{ "}", "}", true },
        .{ "]", "]", true },
        .{ "a{", "a{", true },
        .{ "a{1", "a{1", true },
        .{ "a{,2}", "a{,2}", true },
    });
}

test "anchors and word boundaries" {
    try expectCases(&.{
        .{ "^abc$", "abc", true },
        .{ "^abc$", "abcd", false },
        .{ "^abc$", "xabc", false },
        .{ "^abc", "abc\n", true },
        .{ "abc$", "abc\n", false },
        .{ "^$", "", true },
        .{ "^$", "\n", false },
        .{ "a^b", "a^b", false },
        .{ "\\bfoo\\b", "a foo b", true },
        .{ "\\bfoo\\b", "afoo", false },
        .{ "\\Bfoo", "afoo", true },
        .{ "\\Bfoo", "foo", false },
        .{ "\\b", "", false },
        .{ "\\B", "", true },
        .{ "\\b", "\u{e9}", false },
    });
}

test "character classes and class escapes" {
    try expectCases(&.{
        .{ "^[a-c]+$", "abcabc", true },
        .{ "^[a-c]+$", "abcd", false },
        .{ "^[^a-c]+$", "xyz", true },
        .{ "^[^a-c]+$", "xaz", false },
        .{ "^[]$", "a", false },
        .{ "^[^]$", "\n", true },
        .{ "^[-a]+$", "-a-", true },
        .{ "^[a-]+$", "-a-", true },
        .{ "^[\\w-.]+$", "a-b.c", true },
        .{ "^[\\w-.]+$", "a b", false },
        .{ "^[\\d-z]+$", "1-z", true },
        .{ "^[\\d-z]+$", "y", false },
        .{ "^[\\b]$", "\x08", true },
        .{ "^[\\-]$", "-", true },
        .{ "^[\\]]$", "]", true },
        .{ "^\\d+$", "0123456789", true },
        .{ "^\\d$", "\u{0660}", false },
        .{ "^\\D$", "a", true },
        .{ "^\\w+$", "a_Z9", true },
        .{ "^\\w$", "\u{e9}", false },
        .{ "^\\W$", "\u{e9}", true },
        .{ "^\\s+$", " \t\n\r\x0b\x0c\u{a0}\u{1680}\u{2000}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}", true },
        .{ "^\\s$", "\u{180e}", false },
        .{ "^\\S$", "\u{3000}", false },
        .{ "^[\\s\\d]+$", " 1 2", true },
        .{ "^[^\\s]+$", "ab c", false },
        .{ "^[\\S]+$", "abc", true },
        .{ "^[\\u{1F600}-\\u{1F64F}]$", "\u{1F610}", true },
        .{ "^[\u{e0}-\u{ff}]$", "\u{e9}", true },
        .{ "^\\p{ASCII}+$", "abc", true },
        .{ "^\\p{ASCII}+$", "ab\u{e9}", false },
        .{ "^\\P{ASCII}$", "\u{e9}", true },
        .{ "^\\p{Any}$", "\n", true },
        .{ "^\\p{AHex}+$", "0aF", true },
        .{ "^[\\p{ASCII_Hex_Digit}]+$", "0aG", false },
    });
}

test "escapes" {
    try expectCases(&.{
        .{ "^\\t\\n\\r\\f\\v\\0$", "\t\n\r\x0c\x0b\x00", true },
        .{ "^\\x41\\u0042\\u{43}$", "ABC", true },
        .{ "^\\u{1F600}$", "\u{1F600}", true },
        .{ "^\\uD83D\\uDE00$", "\u{1F600}", true },
        .{ "^\\cJ$", "\n", true },
        .{ "^\\.\\*\\+\\?\\(\\)\\[\\]\\{\\}\\|\\^\\$\\\\\\/$", ".*+?()[]{}|^$\\/", true },
        .{ "^\\@\\-\\_$", "@-_", true },
        .{ "\\.", "a", false },
    });
}

test "groups, alternation and quantifiers" {
    try expectCases(&.{
        .{ "^(ab|cd)+$", "abcdab", true },
        .{ "^(ab|cd)+$", "abc", false },
        .{ "^(?:a|b|c)$", "c", true },
        .{ "^(?<year>\\d{4})-(?<month>\\d{2})$", "2026-09", true },
        .{ "^a|b$", "ax", true },
        .{ "^a|b$", "xb", true },
        .{ "^a|b$", "xa", false },
        .{ "^a*$", "", true },
        .{ "^a+$", "", false },
        .{ "^a?b$", "b", true },
        .{ "^a{3}$", "aaa", true },
        .{ "^a{3}$", "aa", false },
        .{ "^a{2,}$", "aaaaa", true },
        .{ "^a{2,}$", "a", false },
        .{ "^a{1,3}$", "aaa", true },
        .{ "^a{1,3}$", "aaaa", false },
        .{ "^a{0}$", "", true },
        .{ "^a{0,0}b$", "b", true },
        .{ "^a*?b+?c??$", "aabb", true },
        .{ "^a{1,2}?$", "aa", true },
        .{ "^()*$", "", true },
        .{ "^(a*)*$", "aaa", true },
        .{ "^(a*)+b$", "b", true },
        .{ "^(|a)+$", "aa", true },
        .{ "^(\\b|a)+$", "aa", true },
        .{ "^((a|b)*c)?d$", "abacd", true },
        .{ "^[0-9]{3}-[0-9]{4}$", "555-1234", true },
        .{ "^[0-9]{3}-[0-9]{4}$", "555-12345", false },
    });
}

test "compile errors" {
    const invalid = [_][]const u8{
        "(",      ")",    "a)",   "(?",    "(?x)",  "[",           "[a",   "[b-a]", "*",   "+a",  "a**", "a{2}{3}", "^*",    "$+",     "\\b?",
        "a{2,1}", "\\",   "\\x4", "\\u12", "\\u{}", "\\u{110000}", "\\c1", "\\a",   "\\q", "\\k", "\\p", "\\p{}",   "\\p{A", "(?<>a)", "(?<1a>a)",
        "(?<a",   "\xff",
    };
    for (invalid) |pattern| {
        if (compile(testing.allocator, pattern, .{})) |re| {
            var r = re;
            r.deinit(testing.allocator);
            std.debug.print("pattern \"{s}\" compiled\n", .{pattern});
            return error.TestUnexpectedResult;
        } else |err| try testing.expectEqual(error.InvalidRegex, err);
    }
    const unsupported = [_][]const u8{
        "(a)\\1", "\\k<n>",      "(?=a)",             "(?!a)",     "(?<=a)", "(?<!a)", "(?i:a)", "(?-i:a)", "\\01", "[\\1]",
        "\\p{L}", "\\p{Letter}", "\\P{Script=Greek}", "[\\p{Lu}]", "\\8",
    };
    for (unsupported) |pattern| {
        try testing.expectError(error.UnsupportedRegex, compile(testing.allocator, pattern, .{}));
    }
    var diag: Diagnostic = .{};
    try testing.expectError(error.UnsupportedRegex, compile(testing.allocator, "ab(?=c)", .{ .diagnostic = &diag }));
    try testing.expectEqual(4, diag.offset);
}

test "limits" {
    const gpa = testing.allocator;
    try testing.expectError(error.RegexTooLarge, compile(gpa, "abcd", .{ .max_pattern_bytes = 3 }));
    try testing.expectError(error.RegexTooLarge, compile(gpa, "a{5}", .{ .max_states = 5 }));
    var ok = try compile(gpa, "a{4}", .{ .max_states = 5 });
    ok.deinit(gpa);
    // Nested counted repetition grows by multiplication and fails before any allocation.
    try testing.expectError(error.RegexTooLarge, compile(gpa, "((a{1000}){1000}){1000}", .{}));
    try testing.expectError(error.RegexTooLarge, compile(gpa, "a{4294967295}", .{}));
    try testing.expectError(error.RegexTooLarge, compile(gpa, "(" ** (max_group_depth + 2) ++ ")" ** (max_group_depth + 2), .{}));
    var deep = try compile(gpa, "(" ** 100 ++ "a" ++ ")" ** 100, .{});
    deep.deinit(gpa);
}

test "pathological patterns run in linear time" {
    const gpa = testing.allocator;
    const patterns = [_][]const u8{ "(a*)*b", "(a|a)*b", "(a|aa)*c", "(x+x+)+y", "^(a+)+$", "(a?){30}a{30}" };
    const short = try gpa.alloc(u8, 5_000);
    defer gpa.free(short);
    const long = try gpa.alloc(u8, 10_000);
    defer gpa.free(long);
    @memset(short, 'a');
    @memset(long, 'a');
    for (patterns) |pattern| {
        var re = try compile(gpa, pattern, .{});
        defer re.deinit(gpa);
        const buffer = try gpa.alloc(u32, re.bufferLen());
        defer gpa.free(buffer);
        var work_short: u64 = 0;
        var work_long: u64 = 0;
        const m1 = re.run(buffer, short, &work_short);
        const m2 = re.run(buffer, long, &work_long);
        try testing.expectEqual(m1, m2);
        // Double the input, at most double the work (with a small margin for the ends).
        try testing.expect(work_long <= 2 * work_short + 4 * re.insts.len);
        // The work is bounded by the input length multiplied by the program size.
        try testing.expect(work_long <= (long.len + 1) * 3 * re.insts.len);
    }
    // The last pattern matches, the others do not.
    try expectMatch("(a?){30}a{30}", "a" ** 30, true);
    try expectMatch("^(a+)+$", "a" ** 64 ++ "b", false);
}

test "input that is not UTF-8 and encoded surrogates" {
    try expectCases(&.{
        .{ "^.$", "\xff", true },
        .{ "^\\uFFFD$", "\xc3", true },
        .{ "^..$", "\xe0\x80", true },
        .{ "^\\uD800$", "\xed\xa0\x80", true },
    });
}

test "a buffer can be reused" {
    const gpa = testing.allocator;
    var re = try compile(gpa, "^[a-z]+@[a-z]+\\.[a-z]{2,}$", .{});
    defer re.deinit(gpa);
    const buffer = try gpa.alloc(u32, re.bufferLen());
    defer gpa.free(buffer);
    try testing.expect(re.isMatchBuffer(buffer, "me@example.org"));
    try testing.expect(!re.isMatchBuffer(buffer, "me@example"));
    try testing.expect(re.isMatchBuffer(buffer, "a@b.cd"));
    try testing.expect(re.anchored);
}
