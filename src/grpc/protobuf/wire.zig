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
};

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
