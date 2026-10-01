//! A bounded DER reader. The reader checks every length against the input before it makes a slice.
const std = @import("std");

pub const Error = error{ Truncated, InvalidLength, UnexpectedTag, Overflow };

pub const tag_integer: u8 = 0x02;
pub const tag_bit_string: u8 = 0x03;
pub const tag_octet_string: u8 = 0x04;
pub const tag_null: u8 = 0x05;
pub const tag_oid: u8 = 0x06;
pub const tag_sequence: u8 = 0x30;
pub const tag_set: u8 = 0x31;
pub const tag_utc_time: u8 = 0x17;
pub const tag_generalized_time: u8 = 0x18;
pub const tag_enumerated: u8 = 0x0a;
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

    /// Decode a small non-negative `INTEGER`.
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

    /// The content of a `BIT STRING` without the unused-bits octet, which must be zero.
    pub fn bitString(self: Element) Error![]const u8 {
        if (self.tag != tag_bit_string) return error.UnexpectedTag;
        if (self.content.len == 0 or self.content[0] != 0) return error.InvalidLength;
        return self.content[1..];
    }

    pub fn isOid(self: Element, oid: []const u8) bool {
        return self.tag == tag_oid and std.mem.eql(u8, self.content, oid);
    }

    /// True for a `UTCTime` or a `GeneralizedTime`.
    pub fn isTime(self: Element) bool {
        return self.tag == tag_utc_time or self.tag == tag_generalized_time;
    }

    /// Decode a `UTCTime` or a `GeneralizedTime` to seconds since the epoch. The time must
    /// be in UTC with seconds, as RFC 5280 section 4.1.2.5 tells. The function ignores a
    /// fraction of a second in a `GeneralizedTime`. A `UTCTime` year from 50 to 99 is in
    /// the 20th century.
    pub fn time(self: Element) Error!i64 {
        const s = self.content;
        var year: i64 = undefined;
        var rest: []const u8 = undefined;
        switch (self.tag) {
            tag_utc_time => {
                if (s.len != 13 or s[12] != 'Z') return error.InvalidLength;
                const yy = try digits(s[0..2]);
                year = if (yy >= 50) 1900 + yy else 2000 + yy;
                rest = s[2..12];
            },
            tag_generalized_time => {
                if (s.len < 15 or s[s.len - 1] != 'Z') return error.InvalidLength;
                if (s.len > 15) {
                    if (s.len < 17 or s[14] != '.') return error.InvalidLength;
                    _ = try digits(s[15 .. s.len - 1]);
                }
                year = try digits(s[0..4]);
                rest = s[4..14];
            },
            else => return error.UnexpectedTag,
        }
        const month = try digits(rest[0..2]);
        const day = try digits(rest[2..4]);
        const hour = try digits(rest[4..6]);
        const minute = try digits(rest[6..8]);
        const second = try digits(rest[8..10]);
        if (month < 1 or month > 12 or day < 1 or hour > 23 or minute > 59 or second > 59) return error.InvalidLength;
        const month_enum: std.time.epoch.Month = @enumFromInt(month);
        if (day > std.time.epoch.getDaysInMonth(@intCast(year), month_enum)) return error.InvalidLength;
        return daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
    }
};

/// The value of a run of decimal digits, at most 18 of them.
fn digits(text: []const u8) Error!i64 {
    if (text.len == 0 or text.len > 18) return error.InvalidLength;
    var v: i64 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return error.InvalidLength;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// The number of days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const year_of_era = y - era * 400;
    const month_from_march = @mod(month + 9, 12);
    const day_of_year = @divFloor(153 * month_from_march + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * 146097 + day_of_era - 719468;
}

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

/// Parse the element at the start of `bytes`. Trailing bytes can follow.
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

test "UTCTime and GeneralizedTime decode to seconds since the epoch" {
    const at = struct {
        fn f(tag: u8, text: []const u8) Error!i64 {
            return (Element{ .tag = tag, .content = text, .raw = text }).time();
        }
    }.f;
    try std.testing.expectEqual(1_800_000_000, try at(tag_generalized_time, "20270115080000Z"));
    try std.testing.expectEqual(1_800_000_000, try at(tag_utc_time, "270115080000Z"));
    try std.testing.expectEqual(1_800_000_000, try at(tag_generalized_time, "20270115080000.25Z"));
    try std.testing.expectEqual(0, try at(tag_utc_time, "700101000000Z"));
    try std.testing.expectEqual(951_782_400, try at(tag_generalized_time, "20000229000000Z"));
    try std.testing.expectEqual(-86400, try at(tag_utc_time, "691231000000Z"));
    try std.testing.expectError(error.InvalidLength, at(tag_generalized_time, "20270229000000Z"));
    try std.testing.expectError(error.InvalidLength, at(tag_generalized_time, "20271301000000Z"));
    try std.testing.expectError(error.InvalidLength, at(tag_generalized_time, "202701150800Z"));
    try std.testing.expectError(error.InvalidLength, at(tag_generalized_time, "20270115080000+0100"));
    try std.testing.expectError(error.InvalidLength, at(tag_utc_time, "2701150800Z"));
    try std.testing.expectError(error.InvalidLength, at(tag_generalized_time, "2027011508000aZ"));
    try std.testing.expectError(error.UnexpectedTag, at(tag_integer, "20270115080000Z"));
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
