//! PEM (RFC 7468) block iteration and decoding.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Block = struct {
    label: []const u8,
    /// The base64 text between the `BEGIN` and `END` lines.
    body: []const u8,

    /// Decode the body. The caller owns the result.
    pub fn decode(self: Block, gpa: Allocator) (Allocator.Error || error{InvalidEncoding})![]u8 {
        const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const max = decoder.calcSizeUpperBound(self.body.len);
        const out = try gpa.alloc(u8, max);
        errdefer gpa.free(out);
        const n = decoder.decode(out, self.body) catch return error.InvalidEncoding;
        return gpa.realloc(out, n) catch out[0..n];
    }
};

pub const Iterator = struct {
    rest: []const u8,

    pub fn init(text: []const u8) Iterator {
        return .{ .rest = text };
    }

    /// The next block, or null. The reader skips text outside blocks.
    pub fn next(self: *Iterator) ?Block {
        const begin = "-----BEGIN ";
        const start = std.mem.indexOf(u8, self.rest, begin) orelse return null;
        const label_start = start + begin.len;
        const label_end = std.mem.indexOfPos(u8, self.rest, label_start, "-----") orelse return null;
        const label = self.rest[label_start..label_end];
        const body_start = label_end + 5;
        var end_marker_buf: [80]u8 = undefined;
        const end_marker = std.fmt.bufPrint(&end_marker_buf, "-----END {s}-----", .{label}) catch return null;
        const body_end = std.mem.indexOfPos(u8, self.rest, body_start, end_marker) orelse return null;
        const block: Block = .{ .label = label, .body = self.rest[body_start..body_end] };
        self.rest = self.rest[body_end + end_marker.len ..];
        return block;
    }

    /// The next block with the given label.
    pub fn nextLabeled(self: *Iterator, label: []const u8) ?Block {
        while (self.next()) |b| if (std.mem.eql(u8, b.label, label)) return b;
        return null;
    }
};

test "iterate blocks" {
    const text =
        \\junk
        \\-----BEGIN CERTIFICATE-----
        \\aGVsbG8=
        \\-----END CERTIFICATE-----
        \\-----BEGIN PRIVATE KEY-----
        \\d29y
        \\bGQ=
        \\-----END PRIVATE KEY-----
    ;
    var it: Iterator = .init(text);
    const a = it.next().?;
    try std.testing.expectEqualStrings("CERTIFICATE", a.label);
    const da = try a.decode(std.testing.allocator);
    defer std.testing.allocator.free(da);
    try std.testing.expectEqualStrings("hello", da);
    const b = it.nextLabeled("PRIVATE KEY").?;
    const db = try b.decode(std.testing.allocator);
    defer std.testing.allocator.free(db);
    try std.testing.expectEqualStrings("world", db);
    try std.testing.expect(it.next() == null);
}
