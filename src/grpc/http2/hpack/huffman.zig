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

/// Append the decoded bytes to `out`.
pub fn decode(gpa: Allocator, out: *std.ArrayList(u8), encoded: []const u8) (Allocator.Error || Error)!void {
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
    // What remains must be a proper padding: fewer than eight bits, all ones.
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
