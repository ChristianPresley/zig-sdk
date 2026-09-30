//! A bounded DER reader. Every length is checked against the input before a slice is made.
const std = @import("std");

pub const Error = error{ Truncated, InvalidLength, UnexpectedTag, Overflow };

pub const tag_integer: u8 = 0x02;
pub const tag_bit_string: u8 = 0x03;
pub const tag_octet_string: u8 = 0x04;
pub const tag_null: u8 = 0x05;
pub const tag_oid: u8 = 0x06;
pub const tag_sequence: u8 = 0x30;
pub const tag_set: u8 = 0x31;
pub const tag_context_0: u8 = 0xa0;
pub const tag_context_1: u8 = 0xa1;

pub const Element = struct {
    tag: u8,
    /// The content octets.
    content: []const u8,
    /// The complete encoding: identifier, length and content.
    raw: []const u8,

    /// Iterate the children of a constructed element.
    pub fn children(self: Element) Iterator {
        return .{ .rest = self.content };
    }

    pub fn expect(self: Element, tag: u8) Error!Element {
        if (self.tag != tag) return error.UnexpectedTag;
        return self;
    }

    /// Decode a small non-negative INTEGER.
    pub fn smallInt(self: Element) Error!u64 {
        if (self.tag != tag_integer) return error.UnexpectedTag;
        var bytes = self.content;
        if (bytes.len == 0) return error.InvalidLength;
        if (bytes[0] & 0x80 != 0) return error.Overflow;
        while (bytes.len > 1 and bytes[0] == 0) bytes = bytes[1..];
        if (bytes.len > 8) return error.Overflow;
        var v: u64 = 0;
        for (bytes) |b| v = (v << 8) | b;
        return v;
    }

    /// The content of a BIT STRING without the unused-bits octet, which must be zero.
    pub fn bitString(self: Element) Error![]const u8 {
        if (self.tag != tag_bit_string) return error.UnexpectedTag;
        if (self.content.len == 0 or self.content[0] != 0) return error.InvalidLength;
        return self.content[1..];
    }

    pub fn isOid(self: Element, oid: []const u8) bool {
        return self.tag == tag_oid and std.mem.eql(u8, self.content, oid);
    }
};

pub const Iterator = struct {
    rest: []const u8,

    pub fn next(self: *Iterator) Error!?Element {
        if (self.rest.len == 0) return null;
        const elem = try parse(self.rest);
        self.rest = self.rest[elem.raw.len..];
        return elem;
    }

    /// The next element, or `error.Truncated` when there is none.
    pub fn require(self: *Iterator) Error!Element {
        return (try self.next()) orelse error.Truncated;
    }
};

/// Parse the element at the start of `bytes`. Trailing bytes are permitted.
pub fn parse(bytes: []const u8) Error!Element {
    if (bytes.len < 2) return error.Truncated;
    const tag = bytes[0];
    if (tag & 0x1f == 0x1f) return error.UnexpectedTag; // multi-byte tags are not used by X.509 keys
    var header_len: usize = 2;
    var len: usize = bytes[1];
    if (len & 0x80 != 0) {
        const n = len & 0x7f;
        if (n == 0 or n > 4) return error.InvalidLength; // indefinite or unreasonably long
        if (bytes.len < 2 + n) return error.Truncated;
        len = 0;
        for (bytes[2 .. 2 + n]) |b| len = (len << 8) | b;
        if (len < 0x80) return error.InvalidLength; // not minimal
        header_len = 2 + n;
    }
    if (bytes.len - header_len < len) return error.Truncated;
    return .{
        .tag = tag,
        .content = bytes[header_len .. header_len + len],
        .raw = bytes[0 .. header_len + len],
    };
}

/// Parse one element that must fill `bytes` exactly.
pub fn parseExact(bytes: []const u8) Error!Element {
    const elem = try parse(bytes);
    if (elem.raw.len != bytes.len) return error.InvalidLength;
    return elem;
}

test "parse sequence with long length" {
    const inner = [_]u8{ 0x02, 0x01, 0x05 };
    var buf: [200]u8 = undefined;
    buf[0] = tag_sequence;
    buf[1] = 0x81;
    buf[2] = 0x81;
    @memset(buf[3..], 0);
    var i: usize = 3;
    while (i + 3 <= 3 + 0x81) : (i += 3) @memcpy(buf[i..][0..3], &inner);
    const elem = try parse(buf[0 .. 3 + 0x81]);
    try std.testing.expectEqual(tag_sequence, elem.tag);
    var it = elem.children();
    const first = (try it.next()).?;
    try std.testing.expectEqual(5, try first.smallInt());
    try std.testing.expectError(error.Truncated, parse(buf[0..10]));
    try std.testing.expectError(error.InvalidLength, parse(&[_]u8{ 0x30, 0x81, 0x05, 1, 2, 3, 4, 5 }));
    try std.testing.expectError(error.InvalidLength, parse(&[_]u8{ 0x30, 0x80 }));
}
