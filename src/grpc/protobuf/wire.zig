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
        const wire_type: WireType = @fromBackingInt(@intCast(@as(u3, @truncate(tag))));
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
        var buf: [10]u8 = undefined;
        try self.out.appendSlice(self.gpa, buf[0..putVarint(&buf, value)]);
    }

    pub fn tag(self: Writer, number: u32, wire_type: WireType) Allocator.Error!void {
        try self.varint((@as(u64, number) << 3) | @backingInt(wire_type));
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
    /// writes the tag and keeps one byte for the length. Give the result to `endNested`.
    pub fn beginNested(self: Writer, number: u32) Allocator.Error!usize {
        try self.tag(number, .length_delimited);
        const start = self.out.items.len;
        // `endNested` writes the length into this byte.
        _ = try self.out.addOne(self.gpa);
        return start;
    }

    /// End a field from `beginNested`: write its length. Most fields have less than 128
    /// bytes, and their length fits in the byte that `beginNested` kept. For a longer field,
    /// the function moves the bytes of the field to make space for the length.
    pub fn endNested(self: Writer, start: usize) (Allocator.Error || error{MessageTooLarge})!void {
        const body_start = start + 1;
        const len = self.out.items.len - body_start;
        if (len < 0x80) {
            self.out.items[start] = @intCast(len);
            return;
        }
        if (len > std.math.maxInt(u32)) return error.MessageTooLarge;
        const n = varintLen(len);
        _ = try self.out.addManyAsSlice(self.gpa, n - 1);
        const items = self.out.items;
        @memmove(items[start + n ..][0..len], items[body_start..][0..len]);
        _ = putVarint(items[start..][0..n], len);
    }
};

/// Write `value` as a varint to the start of `buf`. Returns the count of bytes.
fn putVarint(buf: []u8, value: u64) usize {
    var n: usize = 0;
    var v = value;
    while (v >= 0x80) : (v >>= 7) {
        buf[n] = @as(u8, @truncate(v)) | 0x80;
        n += 1;
    }
    buf[n] = @intCast(v);
    return n + 1;
}

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

test "nested fields of random sizes and depths" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const random = prng.random();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    // The reference encoder keeps the body of each open field apart and appends it with its
    // length when the field ends.
    var bodies: [17]std.ArrayList(u8) = @splat(.empty);
    defer for (&bodies) |*b| b.deinit(gpa);
    for (0..300) |_| {
        out.clearRetainingCapacity();
        bodies[0].clearRetainingCapacity();
        // Bytes before the message, as the prefix of a gRPC message.
        try out.appendSlice(gpa, "abc");
        try bodies[0].appendSlice(gpa, "abc");
        const w: Writer = .{ .out = &out, .gpa = gpa };
        var starts: [16]usize = undefined;
        var numbers: [16]u32 = undefined;
        var depth: usize = 0;
        for (0..random.intRangeAtMost(usize, 1, 60)) |_| {
            const action = random.intRangeLessThan(u8, 0, 3);
            if (action == 0 and depth < starts.len) {
                numbers[depth] = random.intRangeAtMost(u32, 1, 3000);
                starts[depth] = try w.beginNested(numbers[depth]);
                depth += 1;
                bodies[depth].clearRetainingCapacity();
            } else if (action == 1 and depth > 0) {
                try w.endNested(starts[depth - 1]);
                const ref: Writer = .{ .out = &bodies[depth - 1], .gpa = gpa };
                try ref.bytesField(numbers[depth - 1], bodies[depth].items);
                depth -= 1;
            } else {
                const len = random.intRangeAtMost(usize, 0, 300);
                try out.appendNTimes(gpa, 'y', len);
                try bodies[depth].appendNTimes(gpa, 'y', len);
            }
        }
        while (depth > 0) : (depth -= 1) {
            try w.endNested(starts[depth - 1]);
            const ref: Writer = .{ .out = &bodies[depth - 1], .gpa = gpa };
            try ref.bytesField(numbers[depth - 1], bodies[depth].items);
        }
        try std.testing.expectEqualSlices(u8, bodies[0].items, out.items);
    }
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
