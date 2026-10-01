//! Protocol Buffers wire format (the encoding specification): varints, field tags and the
//! length-delimited, fixed and varint field types. Only what the gRPC binding needs.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const WireType = enum(u3) {
    varint = 0,
    fixed64 = 1,
    length_delimited = 2,
    start_group = 3,
    end_group = 4,
    fixed32 = 5,
    _,
};

pub const Error = error{
    /// The input ended inside a value.
    Truncated,
    /// A varint has more than ten bytes, a tag has field number zero or a group appears.
    Malformed,
};

/// One field as it appears on the wire.
pub const Field = struct {
    number: u32,
    wire_type: WireType,
    /// The varint value, the fixed value, or the bytes of a length-delimited field.
    value: union(enum) {
        varint: u64,
        fixed64: u64,
        fixed32: u32,
        bytes: []const u8,
    },
};

/// Reads fields from a buffer.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn eof(self: *const Reader) bool {
        return self.pos >= self.buf.len;
    }

    pub fn varint(self: *Reader) Error!u64 {
        var result: u64 = 0;
        var shift: u6 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            if (self.pos >= self.buf.len) return error.Truncated;
            const b = self.buf[self.pos];
            self.pos += 1;
            if (i == 9 and b > 1) return error.Malformed;
            result |= @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) return result;
            shift +|= 7;
        }
        return error.Malformed;
    }

    /// Four little-endian bytes, for example one value of a packed `float` field.
    pub fn fixed32(self: *Reader) Error!u32 {
        if (self.buf.len - self.pos < 4) return error.Truncated;
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }

    /// Eight little-endian bytes, for example one value of a packed `double` field.
    pub fn fixed64(self: *Reader) Error!u64 {
        if (self.buf.len - self.pos < 8) return error.Truncated;
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .little);
        self.pos += 8;
        return v;
    }

    /// The next field, or null at the end.
    pub fn next(self: *Reader) Error!?Field {
        if (self.eof()) return null;
        const tag = try self.varint();
        if (tag > std.math.maxInt(u32)) return error.Malformed;
        const number: u32 = @intCast(tag >> 3);
        if (number == 0) return error.Malformed;
        const wire_type: WireType = @enumFromInt(@as(u3, @truncate(tag)));
        switch (wire_type) {
            .varint => return .{ .number = number, .wire_type = wire_type, .value = .{ .varint = try self.varint() } },
            .fixed64 => {
                if (self.buf.len - self.pos < 8) return error.Truncated;
                const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .little);
                self.pos += 8;
                return .{ .number = number, .wire_type = wire_type, .value = .{ .fixed64 = v } };
            },
            .fixed32 => {
                if (self.buf.len - self.pos < 4) return error.Truncated;
                const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .little);
                self.pos += 4;
                return .{ .number = number, .wire_type = wire_type, .value = .{ .fixed32 = v } };
            },
            .length_delimited => {
                const len = try self.varint();
                if (len > self.buf.len - self.pos) return error.Truncated;
                const bytes = self.buf[self.pos..][0..@intCast(len)];
                self.pos += @intCast(len);
                return .{ .number = number, .wire_type = wire_type, .value = .{ .bytes = bytes } };
            },
            .start_group, .end_group, _ => return error.Malformed,
        }
    }
};

/// Appends fields to a buffer.
pub const Writer = struct {
    out: *std.ArrayList(u8),
    gpa: Allocator,

    pub fn varint(self: Writer, value: u64) Allocator.Error!void {
        var v = value;
        while (v >= 0x80) : (v >>= 7) try self.out.append(self.gpa, @as(u8, @truncate(v)) | 0x80);
        try self.out.append(self.gpa, @intCast(v));
    }

    pub fn tag(self: Writer, number: u32, wire_type: WireType) Allocator.Error!void {
        try self.varint((@as(u64, number) << 3) | @intFromEnum(wire_type));
    }

    pub fn bytesField(self: Writer, number: u32, bytes: []const u8) Allocator.Error!void {
        try self.tag(number, .length_delimited);
        try self.varint(bytes.len);
        try self.out.appendSlice(self.gpa, bytes);
    }

    pub fn varintField(self: Writer, number: u32, value: u64) Allocator.Error!void {
        try self.tag(number, .varint);
        try self.varint(value);
    }

    /// Four little-endian bytes without a tag.
    pub fn fixed32(self: Writer, value: u32) Allocator.Error!void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, .little);
        try self.out.appendSlice(self.gpa, &buf);
    }

    /// Eight little-endian bytes without a tag.
    pub fn fixed64(self: Writer, value: u64) Allocator.Error!void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .little);
        try self.out.appendSlice(self.gpa, &buf);
    }

    /// Start a length-delimited field before the encoder knows its length. The function
    /// writes the tag and keeps five bytes for the length. Give the result to `endNested`.
    pub fn beginNested(self: Writer, number: u32) Allocator.Error!usize {
        try self.tag(number, .length_delimited);
        const start = self.out.items.len;
        try self.out.appendNTimes(self.gpa, 0, max_nested_prefix);
        return start;
    }

    /// End a field from `beginNested`: write its length and move its bytes next to the length.
    pub fn endNested(self: Writer, start: usize) error{MessageTooLarge}!void {
        const body_start = start + max_nested_prefix;
        const len = self.out.items.len - body_start;
        if (len > std.math.maxInt(u32)) return error.MessageTooLarge;
        var prefix: [max_nested_prefix]u8 = undefined;
        var n: usize = 0;
        var v: u64 = len;
        while (v >= 0x80) : (v >>= 7) {
            prefix[n] = @as(u8, @truncate(v)) | 0x80;
            n += 1;
        }
        prefix[n] = @intCast(v);
        n += 1;
        const items = self.out.items;
        @memcpy(items[start..][0..n], prefix[0..n]);
        if (n < max_nested_prefix) {
            std.mem.copyForwards(u8, items[start + n ..], items[body_start..]);
            self.out.shrinkRetainingCapacity(items.len - (max_nested_prefix - n));
        }
    }
};

/// The bytes that `beginNested` keeps for a length: enough for any length below 2^35.
const max_nested_prefix = 5;

/// The size of a varint on the wire.
pub fn varintLen(value: u64) usize {
    var n: usize = 1;
    var v = value;
    while (v >= 0x80) : (v >>= 7) n += 1;
    return n;
}

test "varints and fields round trip" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const w: Writer = .{ .out = &out, .gpa = gpa };
    try w.varintField(1, 300);
    try w.bytesField(2, "hello");
    try w.tag(3, .fixed32);
    try out.appendSlice(gpa, &.{ 1, 0, 0, 0 });
    try w.tag(4, .fixed64);
    try out.appendSlice(gpa, &.{ 2, 0, 0, 0, 0, 0, 0, 0 });
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0xac, 0x02 }, out.items[0..3]);

    var r: Reader = .init(out.items);
    const f1 = (try r.next()).?;
    try std.testing.expectEqual(1, f1.number);
    try std.testing.expectEqual(300, f1.value.varint);
    const f2 = (try r.next()).?;
    try std.testing.expectEqualStrings("hello", f2.value.bytes);
    try std.testing.expectEqual(1, (try r.next()).?.value.fixed32);
    try std.testing.expectEqual(2, (try r.next()).?.value.fixed64);
    try std.testing.expect((try r.next()) == null);
    try std.testing.expectEqual(2, varintLen(300));
    try std.testing.expectEqual(10, varintLen(std.math.maxInt(u64)));
}

test "nested fields get the shortest length prefix" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const w: Writer = .{ .out = &out, .gpa = gpa };
    const outer = try w.beginNested(1);
    try w.bytesField(2, "hi");
    const inner = try w.beginNested(3);
    try w.endNested(inner);
    try w.endNested(outer);
    try std.testing.expectEqualSlices(u8, &.{ 0x0a, 0x06, 0x12, 0x02, 'h', 'i', 0x1a, 0x00 }, out.items);
    // A body of 200 bytes needs two bytes of length.
    out.clearRetainingCapacity();
    const big = try w.beginNested(1);
    try out.appendNTimes(gpa, 'x', 200);
    try w.endNested(big);
    try std.testing.expectEqualSlices(u8, &.{ 0x0a, 0xc8, 0x01 }, out.items[0..3]);
    try std.testing.expectEqual(203, out.items.len);

    out.clearRetainingCapacity();
    try w.fixed32(1);
    try w.fixed64(2);
    try out.append(gpa, 9);
    var r: Reader = .init(out.items);
    try std.testing.expectEqual(1, try r.fixed32());
    try std.testing.expectEqual(2, try r.fixed64());
    try std.testing.expectError(error.Truncated, r.fixed32());
    try std.testing.expectError(error.Truncated, r.fixed64());
}

test "malformed input" {
    var truncated: Reader = .init(&.{ 0x0a, 0x05, 'h', 'i' });
    try std.testing.expectError(error.Truncated, truncated.next());
    var group: Reader = .init(&.{0x0b});
    try std.testing.expectError(error.Malformed, group.next());
    var zero: Reader = .init(&.{ 0x00, 0x00 });
    try std.testing.expectError(error.Malformed, zero.next());
    var long: Reader = .init(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 });
    try std.testing.expectError(error.Malformed, long.varint());
    var cut: Reader = .init(&.{ 0x80, 0x80 });
    try std.testing.expectError(error.Truncated, cut.varint());
}
