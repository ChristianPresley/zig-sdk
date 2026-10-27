//! The HPACK Huffman code (RFC 7541 section 5.2 and appendix B): encoding with the code
//! table and decoding with a binary trie built at compile time.
const std = @import("std");
const Allocator = std.mem.Allocator;
const tables = @import("tables.zig");

pub const Error = error{
    /// The padding is longer than seven bits or is not all ones, or the string decodes
    /// the end-of-string symbol.
    InvalidHuffman,
};

const eos = 256;

/// A trie node: for each bit, the index of the next node, or a leaf with a symbol.
const Node = struct {
    child: [2]u16 = .{ 0, 0 },
    symbol: i16 = -1,
};

const trie = build: {
    @setEvalBranchQuota(200_000);
    var nodes: [tables.huffman_codes.len * 30]Node = undefined;
    var count: usize = 1;
    nodes[0] = .{};
    for (tables.huffman_codes, 0..) |entry, sym| {
        var node: usize = 0;
        var i: u5 = entry.len;
        while (i > 0) {
            i -= 1;
            const bit: usize = (entry.code >> i) & 1;
            if (nodes[node].child[bit] == 0) {
                nodes[count] = .{};
                nodes[node].child[bit] = @intCast(count);
                count += 1;
            }
            node = nodes[node].child[bit];
        }
        nodes[node].symbol = @intCast(sym);
    }
    var out: [count]Node = undefined;
    @memcpy(&out, nodes[0..count]);
    break :build out;
};

/// The encoded size of `bytes`.
pub fn encodedLen(bytes: []const u8) usize {
    var bits: usize = 0;
    for (bytes) |b| bits += tables.huffman_codes[b].len;
    return (bits + 7) / 8;
}

/// Append the Huffman encoding of `bytes` to `out`.
pub fn encode(gpa: Allocator, out: *std.ArrayList(u8), bytes: []const u8) Allocator.Error!void {
    var acc: u64 = 0;
    var acc_bits: u6 = 0;
    for (bytes) |b| {
        const entry = tables.huffman_codes[b];
        acc = (acc << entry.len) | entry.code;
        acc_bits += entry.len;
        while (acc_bits >= 8) {
            acc_bits -= 8;
            try out.append(gpa, @truncate(acc >> acc_bits));
        }
    }
    if (acc_bits > 0) {
        // Pad with the most significant bits of the end-of-string symbol: all ones.
        const pad: u6 = 8 - acc_bits;
        acc = (acc << pad) | ((@as(u64, 1) << pad) - 1);
        try out.append(gpa, @truncate(acc));
    }
}

/// One step of the decoder: the effect of four bits in one state. A state is an inner node
/// of the trie. A code has five bits or more, thus four bits complete one symbol or less.
const Step = struct {
    /// The state after the four bits.
    next: u8,
    /// The symbol that the four bits complete, if `flags` has `step_emit`.
    symbol: u8,
    flags: u8,
};

/// The four bits complete a symbol.
const step_emit = 1;
/// The four bits complete the end-of-string symbol, or they are not a part of a code.
const step_fail = 2;
/// The bits since the last symbol are a correct padding: fewer than eight bits, all ones.
const step_accept = 4;

/// The steps for each state and each value of four bits.
const steps = build: {
    @setEvalBranchQuota(400_000);
    // The state of each inner node of the trie. The root is state 0.
    var state_of: [trie.len]u8 = undefined;
    var node_of: [256]u16 = undefined;
    var count: usize = 0;
    for (trie, 0..) |node, i| {
        if (node.symbol >= 0) continue;
        state_of[i] = @intCast(count);
        node_of[count] = @intCast(i);
        count += 1;
    }
    if (count != 256 or node_of[0] != 0) @compileError("unexpected Huffman trie");
    // The nodes that a correct padding can stop at: the root, then up to seven 1 bits.
    var accept: [trie.len]bool = @splat(false);
    var node: usize = 0;
    accept[0] = true;
    for (0..7) |_| {
        node = trie[node].child[1];
        accept[node] = true;
    }
    var out: [256][16]Step = undefined;
    for (0..256) |state| {
        for (0..16) |bits| {
            var at: usize = node_of[state];
            var step: Step = .{ .next = 0, .symbol = 0, .flags = 0 };
            var shift: usize = 4;
            while (shift > 0) {
                shift -= 1;
                at = trie[at].child[(bits >> shift) & 1];
                if (at == 0 or trie[at].symbol == eos) {
                    step.flags = step_fail;
                    break;
                }
                if (trie[at].symbol >= 0) {
                    step.symbol = @intCast(trie[at].symbol);
                    step.flags |= step_emit;
                    at = 0;
                }
            }
            if (step.flags & step_fail == 0) {
                step.next = state_of[at];
                if (accept[at]) step.flags |= step_accept;
            }
            out[state][bits] = step;
        }
    }
    break :build out;
};

/// The largest decoded size of `encoded_len` encoded bytes. The shortest code has five bits.
pub fn maxDecodedLen(encoded_len: usize) usize {
    return encoded_len / 5 * 8 + (encoded_len % 5) * 8 / 5;
}

/// Decode into `dest` and give the decoded size. `dest` must have `maxDecodedLen` bytes or
/// more.
pub fn decodeInto(dest: []u8, encoded: []const u8) Error!usize {
    var state: u8 = 0;
    var n: usize = 0;
    var flags: u8 = step_accept;
    for (encoded) |byte| {
        inline for (.{ 4, 0 }) |shift| {
            const step = steps[state][(byte >> shift) & 0xf];
            if (step.flags & step_fail != 0) return error.InvalidHuffman;
            if (step.flags & step_emit != 0) {
                dest[n] = step.symbol;
                n += 1;
            }
            state = step.next;
            flags = step.flags;
        }
    }
    // What remains must be a proper padding: fewer than eight bits, all ones.
    if (flags & step_accept == 0) return error.InvalidHuffman;
    return n;
}

/// Append the decoded bytes to `out`.
pub fn decode(gpa: Allocator, out: *std.ArrayList(u8), encoded: []const u8) (Allocator.Error || Error)!void {
    try out.ensureUnusedCapacity(gpa, maxDecodedLen(encoded.len));
    const n = try decodeInto(out.unusedCapacitySlice(), encoded);
    out.items.len += n;
}

/// The decoder of one bit at a time, for the tests: `decodeInto` must agree with it.
fn decodeBits(gpa: Allocator, out: *std.ArrayList(u8), encoded: []const u8) (Allocator.Error || Error)!void {
    var node: usize = 0;
    var depth: u8 = 0;
    var all_ones = true;
    for (encoded) |byte| {
        var i: u4 = 8;
        while (i > 0) {
            i -= 1;
            const bit: usize = (byte >> @intCast(i)) & 1;
            node = trie[node].child[bit];
            if (node == 0) return error.InvalidHuffman;
            depth += 1;
            all_ones = all_ones and bit == 1;
            if (trie[node].symbol >= 0) {
                if (trie[node].symbol == eos) return error.InvalidHuffman;
                try out.append(gpa, @intCast(trie[node].symbol));
                node = 0;
                depth = 0;
                all_ones = true;
            }
        }
    }
    if (depth > 7 or !all_ones) return error.InvalidHuffman;
}

test "round trip and the RFC example" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encode(gpa, &out, "www.example.com");
    try std.testing.expectEqualSlices(u8, &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, out.items);
    try std.testing.expectEqual(12, encodedLen("www.example.com"));
    var back: std.ArrayList(u8) = .empty;
    defer back.deinit(gpa);
    try decode(gpa, &back, out.items);
    try std.testing.expectEqualStrings("www.example.com", back.items);

    // Every byte value survives.
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    out.clearRetainingCapacity();
    back.clearRetainingCapacity();
    try encode(gpa, &out, &all);
    try decode(gpa, &back, out.items);
    try std.testing.expectEqualSlices(u8, &all, back.items);
}

test "invalid padding and end of string" {
    const gpa = std.testing.allocator;
    var back: std.ArrayList(u8) = .empty;
    defer back.deinit(gpa);
    // A full byte of ones is padding longer than seven bits.
    try std.testing.expectError(error.InvalidHuffman, decode(gpa, &back, &.{ 0xf1, 0xe3, 0xff }));
    // Padding with a zero bit.
    try std.testing.expectError(error.InvalidHuffman, decode(gpa, &back, &.{0xfe}));
    // The end-of-string symbol inside the string.
    try std.testing.expectError(error.InvalidHuffman, decode(gpa, &back, &.{ 0xff, 0xff, 0xff, 0xfc }));
}

test "the table decoder agrees with the bit decoder" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x7541);
    const random = prng.random();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var text: [64]u8 = undefined;
    for (0..20_000) |round| {
        input.clearRetainingCapacity();
        const len = random.uintLessThan(usize, 24);
        if (round % 2 == 0) {
            // Random bytes: most are not valid, at many places.
            for (0..len) |_| try input.append(gpa, random.int(u8));
        } else {
            // A valid string, then sometimes a change of one bit or one byte less.
            for (text[0..len]) |*c| c.* = if (random.boolean()) random.int(u8) else "abc019-:/"[random.uintLessThan(usize, 9)];
            try encode(gpa, &input, text[0..len]);
            if (input.items.len > 0 and random.uintLessThan(u8, 3) == 0) {
                const at = random.uintLessThan(usize, input.items.len);
                input.items[at] ^= @as(u8, 1) << random.int(u3);
            } else if (input.items.len > 0 and random.uintLessThan(u8, 4) == 0) {
                input.items.len -= 1;
            }
        }
        want.clearRetainingCapacity();
        got.clearRetainingCapacity();
        const a = decodeBits(gpa, &want, input.items);
        const b = decode(gpa, &got, input.items);
        if (a) |_| {
            try b;
            try std.testing.expectEqualSlices(u8, want.items, got.items);
        } else |e| try std.testing.expectError(e, b);
    }
    // The bound of `maxDecodedLen` holds for the shortest codes: '0' has five bits.
    input.clearRetainingCapacity();
    try encode(gpa, &input, "0" ** 40);
    try std.testing.expectEqual(25, input.items.len);
    try std.testing.expectEqual(40, maxDecodedLen(input.items.len));
    got.clearRetainingCapacity();
    try decode(gpa, &got, input.items);
    try std.testing.expectEqualStrings("0" ** 40, got.items);
}
