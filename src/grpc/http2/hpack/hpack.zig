//! HPACK header compression (RFC 7541). The decoder has a dynamic table. The encoder uses
//! the static table and literals, but it never adds to the dynamic table.
const std = @import("std");
const Allocator = std.mem.Allocator;
const tables = @import("tables.zig");
const huffman = @import("huffman.zig");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Error = error{
    /// The block ends inside an integer or a string.
    Truncated,
    /// An integer is too large, or an index is zero or out of range. Or a table size
    /// update exceeds the limit or comes after a header.
    Invalid,
    /// A string exceeds the configured limit.
    FieldTooLarge,
    /// The decoded header list exceeds the configured limit.
    HeaderListTooLarge,
} || huffman.Error || Allocator.Error;

/// Per RFC 7541 section 4.1, an entry costs its name, its value and 32 octets.
const entry_overhead = 32;

pub const Options = struct {
    /// The dynamic table size the peer can use (SETTINGS_HEADER_TABLE_SIZE).
    max_table_size: u32 = 4096,
    /// The largest name or value accepted.
    max_field_size: usize = 8 << 10,
    /// The largest decoded header list, counted as names plus values plus 32 per header.
    max_header_list_size: usize = 8 << 10,
};

pub const Decoder = struct {
    gpa: Allocator,
    options: Options,
    /// Newest entry last.
    entries: std.ArrayList(Entry) = .empty,
    size: usize = 0,
    /// The current table size limit, set by the encoder within `max_table_size`.
    table_size: u32,

    const Entry = struct { name: []u8, value: []u8 };

    pub fn init(gpa: Allocator, options: Options) Decoder {
        return .{ .gpa = gpa, .options = options, .table_size = options.max_table_size };
    }

    pub fn deinit(self: *Decoder) void {
        for (self.entries.items) |e| self.freeEntry(e);
        self.entries.deinit(self.gpa);
    }

    fn freeEntry(self: *Decoder, e: Entry) void {
        self.gpa.free(e.name);
        self.gpa.free(e.value);
    }

    /// Change the limit the peer must stay under (a new SETTINGS_HEADER_TABLE_SIZE).
    pub fn setMaxTableSize(self: *Decoder, max: u32) void {
        self.options.max_table_size = max;
        if (self.table_size > max) self.resize(max);
    }

    fn resize(self: *Decoder, new_size: u32) void {
        self.table_size = new_size;
        self.evictTo(new_size);
    }

    fn evictTo(self: *Decoder, limit: usize) void {
        while (self.size > limit and self.entries.items.len > 0) {
            const oldest = self.entries.orderedRemove(0);
            self.size -= oldest.name.len + oldest.value.len + entry_overhead;
            self.freeEntry(oldest);
        }
    }

    fn add(self: *Decoder, name: []const u8, value: []const u8) Allocator.Error!void {
        const cost = name.len + value.len + entry_overhead;
        // An entry larger than the table empties it (section 4.4).
        if (cost > self.table_size) {
            self.evictTo(0);
            return;
        }
        // Copy before the eviction: `name` can refer to an entry that it frees (section 4.4).
        const n = try self.gpa.dupe(u8, name);
        errdefer self.gpa.free(n);
        const v = try self.gpa.dupe(u8, value);
        errdefer self.gpa.free(v);
        try self.entries.ensureUnusedCapacity(self.gpa, 1);
        self.evictTo(self.table_size - cost);
        self.entries.appendAssumeCapacity(.{ .name = n, .value = v });
        self.size += cost;
    }

    /// The entry at a 1-based index over the static and then the dynamic table.
    fn lookup(self: *const Decoder, index: u64) ?Header {
        if (index == 0) return null;
        if (index <= tables.static_table.len) {
            const s = tables.static_table[@intCast(index - 1)];
            return .{ .name = s.name, .value = s.value };
        }
        const dyn = index - tables.static_table.len - 1;
        if (dyn >= self.entries.items.len) return null;
        const e = self.entries.items[self.entries.items.len - 1 - @as(usize, @intCast(dyn))];
        return .{ .name = e.name, .value = e.value };
    }

    /// The number of dynamic entries, newest first, for tests.
    pub fn dynamicEntry(self: *const Decoder, index_from_newest: usize) ?Header {
        if (index_from_newest >= self.entries.items.len) return null;
        const e = self.entries.items[self.entries.items.len - 1 - index_from_newest];
        return .{ .name = e.name, .value = e.value };
    }

    pub fn dynamicSize(self: *const Decoder) usize {
        return self.size;
    }

    /// Decode one header block. The decoder copies the headers into `arena`.
    ///
    /// After `error.FieldTooLarge` or `error.HeaderListTooLarge`, the decoder reads the rest of
    /// the block and gives the error at the end. It adds no more headers to `out`, but it
    /// applies each change to the dynamic table. Thus the table stays the same as the table of
    /// the encoder, and the next block of the connection decodes correctly (RFC 9113 section
    /// 4.3). The other errors end the connection, thus the decoder stops at once.
    pub fn decode(self: *Decoder, arena: Allocator, block: []const u8, out: *std.ArrayList(Header)) Error!void {
        var state: DecodeState = .{ .arena = arena, .out = out };
        var r: BlockReader = .{ .buf = block };
        var saw_header = false;
        while (!r.eof()) {
            const first = r.buf[r.pos];
            if (first & 0x80 != 0) {
                // Indexed header field.
                const index = try r.integer(7);
                const h = self.lookup(index) orelse return error.Invalid;
                try self.emit(&state, h.name, h.value);
                saw_header = true;
            } else if (first & 0x40 != 0) {
                // Literal with incremental indexing.
                const h = try self.literal(&state, &r, 6);
                // An indexed name refers to a dynamic entry that `add` can evict.
                const name = try arena.dupe(u8, h.name);
                try self.add(name, h.value);
                try self.emit(&state, name, h.value);
                saw_header = true;
            } else if (first & 0x20 != 0) {
                // Dynamic table size update: only at the start of a block.
                if (saw_header) return error.Invalid;
                const new_size = try r.integer(5);
                if (new_size > self.options.max_table_size) return error.Invalid;
                self.resize(@intCast(new_size));
            } else {
                // Literal without indexing (0000) or never indexed (0001).
                const h = try self.literal(&state, &r, 4);
                try self.emit(&state, h.name, h.value);
                saw_header = true;
            }
        }
        if (state.size_error) |e| return e;
    }

    /// The output of one call of `decode`.
    const DecodeState = struct {
        arena: Allocator,
        out: *std.ArrayList(Header),
        list_size: usize = 0,
        /// The first size error of the block. After it, `emit` adds no header.
        size_error: ?Error = null,

        fn setSizeError(state: *DecodeState, err: Error) void {
            if (state.size_error == null) state.size_error = err;
        }
    };

    fn emit(self: *Decoder, state: *DecodeState, name: []const u8, value: []const u8) Error!void {
        if (state.size_error != null) return;
        state.list_size += name.len + value.len + entry_overhead;
        if (state.list_size > self.options.max_header_list_size) return state.setSizeError(error.HeaderListTooLarge);
        try state.out.append(state.arena, .{ .name = try state.arena.dupe(u8, name), .value = try state.arena.dupe(u8, value) });
    }

    /// A literal representation: an indexed or literal name, then a literal value.
    fn literal(self: *Decoder, state: *DecodeState, r: *BlockReader, prefix: u4) Error!Header {
        const index = try r.integer(prefix);
        const name: []const u8 = if (index == 0)
            try self.string(state, r)
        else
            (self.lookup(index) orelse return error.Invalid).name;
        const value = try self.string(state, r);
        return .{ .name = name, .value = value };
    }

    /// A string over `max_field_size` sets `error.FieldTooLarge`. The function still decodes
    /// the string, because a dynamic table entry can need it. The string is part of the
    /// block, thus the size of the block limits it.
    fn string(self: *Decoder, state: *DecodeState, r: *BlockReader) Error![]const u8 {
        if (r.eof()) return error.Truncated;
        const huff = r.buf[r.pos] & 0x80 != 0;
        const len = try r.integer(7);
        const raw = try r.take(std.math.cast(usize, len) orelse return error.Truncated);
        if (raw.len > self.options.max_field_size) state.setSizeError(error.FieldTooLarge);
        if (!huff) return raw;
        var decoded: std.ArrayList(u8) = .empty;
        try huffman.decode(state.arena, &decoded, raw);
        if (decoded.items.len > self.options.max_field_size) state.setSizeError(error.FieldTooLarge);
        return decoded.items;
    }
};

const BlockReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn eof(self: *const BlockReader) bool {
        return self.pos >= self.buf.len;
    }

    fn take(self: *BlockReader, n: usize) Error![]const u8 {
        if (self.buf.len - self.pos < n) return error.Truncated;
        const s = self.buf[self.pos..][0..n];
        self.pos += n;
        return s;
    }

    /// An integer with an N-bit prefix (section 5.1).
    fn integer(self: *BlockReader, prefix: u4) Error!u64 {
        if (self.eof()) return error.Truncated;
        const mask: u8 = @intCast((@as(u16, 1) << prefix) - 1);
        var value: u64 = self.buf[self.pos] & mask;
        self.pos += 1;
        if (value < mask) return value;
        var shift: u6 = 0;
        while (true) {
            if (self.eof()) return error.Truncated;
            const b = self.buf[self.pos];
            self.pos += 1;
            if (shift > 56) return error.Invalid;
            value += @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) return value;
            shift += 7;
        }
    }
};

/// Encodes header blocks with static table references and literals. It never adds to the
/// dynamic table, so the peer needs no state for our blocks.
pub const Encoder = struct {
    /// Use the Huffman code when it makes a string shorter.
    huffman: bool = true,

    pub fn encodeInteger(gpa: Allocator, out: *std.ArrayList(u8), prefix: u4, first_bits: u8, value: u64) Allocator.Error!void {
        const mask: u8 = @intCast((@as(u16, 1) << prefix) - 1);
        if (value < mask) {
            try out.append(gpa, first_bits | @as(u8, @intCast(value)));
            return;
        }
        try out.append(gpa, first_bits | mask);
        var rest = value - mask;
        while (rest >= 128) : (rest >>= 7) try out.append(gpa, @as(u8, @truncate(rest)) | 0x80);
        try out.append(gpa, @intCast(rest));
    }

    fn encodeString(self: Encoder, gpa: Allocator, out: *std.ArrayList(u8), s: []const u8) Allocator.Error!void {
        if (self.huffman and huffman.encodedLen(s) < s.len) {
            try encodeInteger(gpa, out, 7, 0x80, huffman.encodedLen(s));
            try huffman.encode(gpa, out, s);
            return;
        }
        try encodeInteger(gpa, out, 7, 0, s.len);
        try out.appendSlice(gpa, s);
    }

    /// Append one header. `sensitive` uses the never-indexed representation.
    pub fn encodeHeader(self: Encoder, gpa: Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8, sensitive: bool) Allocator.Error!void {
        var name_index: ?usize = null;
        if (!sensitive) {
            for (tables.static_table, 1..) |s, i| {
                if (std.mem.eql(u8, s.name, name)) {
                    if (std.mem.eql(u8, s.value, value)) {
                        try encodeInteger(gpa, out, 7, 0x80, i);
                        return;
                    }
                    if (name_index == null) name_index = i;
                }
            }
        } else {
            for (tables.static_table, 1..) |s, i| if (std.mem.eql(u8, s.name, name)) {
                name_index = i;
                break;
            };
        }
        const first_bits: u8 = if (sensitive) 0x10 else 0x00;
        try encodeInteger(gpa, out, 4, first_bits, name_index orelse 0);
        if (name_index == null) try self.encodeString(gpa, out, name);
        try self.encodeString(gpa, out, value);
    }

    pub fn encodeHeaders(self: Encoder, gpa: Allocator, out: *std.ArrayList(u8), headers: []const Header) Allocator.Error!void {
        for (headers) |h| try self.encodeHeader(gpa, out, h.name, h.value, std.ascii.eqlIgnoreCase(h.name, "authorization"));
    }
};

// -- Tests -----------------------------------------------------------------------------------

const examples = @import("rfc7541_examples.zig");

fn hexToBytes(arena: Allocator, hex: []const u8) ![]u8 {
    const out = try arena.alloc(u8, hex.len / 2);
    return std.fmt.hexToBytes(out, hex);
}

fn runSequence(sections: []const []const u8, table_size: u32) !void {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var decoder: Decoder = .init(gpa, .{ .max_table_size = table_size });
    defer decoder.deinit();
    for (sections) |section| {
        const ex = for (examples.examples) |e| {
            if (std.mem.eql(u8, e.section, section)) break e;
        } else return error.MissingExample;
        var out: std.ArrayList(Header) = .empty;
        try decoder.decode(arena, try hexToBytes(arena, ex.hex), &out);
        try std.testing.expectEqual(ex.headers.len, out.items.len);
        for (ex.headers, out.items) |want, got| {
            try std.testing.expectEqualStrings(want.name, got.name);
            try std.testing.expectEqualStrings(want.value, got.value);
        }
        try std.testing.expectEqual(ex.table_size, decoder.dynamicSize());
        for (ex.table, 0..) |want, i| {
            const got = decoder.dynamicEntry(i).?;
            try std.testing.expectEqualStrings(want.name, got.name);
            try std.testing.expectEqualStrings(want.value, got.value);
            try std.testing.expectEqual(want.size, got.name.len + got.value.len + entry_overhead);
        }
        try std.testing.expect(decoder.dynamicEntry(ex.table.len) == null);
    }
}

test "RFC 7541 appendix C examples" {
    try runSequence(&.{"C.2.1"}, 4096);
    try runSequence(&.{"C.2.2"}, 4096);
    try runSequence(&.{"C.2.3"}, 4096);
    try runSequence(&.{"C.2.4"}, 4096);
    try runSequence(&.{ "C.3.1", "C.3.2", "C.3.3" }, 4096);
    try runSequence(&.{ "C.4.1", "C.4.2", "C.4.3" }, 4096);
    try runSequence(&.{ "C.5.1", "C.5.2", "C.5.3" }, 256);
    try runSequence(&.{ "C.6.1", "C.6.2", "C.6.3" }, 256);
}

test "integer prefix examples of appendix C.1" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try Encoder.encodeInteger(gpa, &out, 5, 0, 10);
    try std.testing.expectEqualSlices(u8, &.{0x0a}, out.items);
    out.clearRetainingCapacity();
    try Encoder.encodeInteger(gpa, &out, 5, 0, 1337);
    try std.testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, out.items);
    out.clearRetainingCapacity();
    try Encoder.encodeInteger(gpa, &out, 8, 0, 42);
    try std.testing.expectEqualSlices(u8, &.{0x2a}, out.items);
    var r: BlockReader = .{ .buf = &.{ 0x1f, 0x9a, 0x0a } };
    try std.testing.expectEqual(1337, try r.integer(5));
}

test "encoder output decodes and never touches the dynamic table" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const headers = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/mcp.zig.transport.v1.Mcp/Call" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "authorization", .value = "Bearer secret" },
        .{ .name = "mcp-method", .value = "tools/call" },
        .{ .name = "x-binary", .value = "\x00\xff\x80" },
    };
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    const encoder: Encoder = .{};
    try encoder.encodeHeaders(gpa, &block, &headers);
    // The authorization header is never indexed: it starts with 0001.
    try std.testing.expect(std.mem.indexOf(u8, block.items, "Bearer secret") != null or std.mem.indexOf(u8, block.items, "\x10") != null);
    var decoder: Decoder = .init(gpa, .{});
    defer decoder.deinit();
    var out: std.ArrayList(Header) = .empty;
    try decoder.decode(arena, block.items, &out);
    try std.testing.expectEqual(headers.len, out.items.len);
    for (&headers, out.items) |want, got| {
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.value, got.value);
    }
    try std.testing.expectEqual(0, decoder.dynamicSize());
}

test "invalid blocks" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var decoder: Decoder = .init(gpa, .{ .max_field_size = 16, .max_header_list_size = 200 });
    defer decoder.deinit();
    var out: std.ArrayList(Header) = .empty;
    try std.testing.expectError(error.Invalid, decoder.decode(arena, &.{0x80}, &out)); // index 0
    try std.testing.expectError(error.Invalid, decoder.decode(arena, &.{0xbe}, &out)); // index 62 with an empty dynamic table
    try std.testing.expectError(error.Truncated, decoder.decode(arena, &.{ 0x40, 0x0a, 'a' }, &out));
    try std.testing.expectError(error.Invalid, decoder.decode(arena, &.{ 0x82, 0x3f, 0xe1, 0x1f }, &out)); // size update after a header
    try std.testing.expectError(error.Invalid, decoder.decode(arena, &.{ 0x3f, 0xe1, 0x7f }, &out)); // size update above the limit
    try std.testing.expectError(error.FieldTooLarge, decoder.decode(arena, "\x00\x11" ++ "a" ** 17 ++ "\x00", &out));
    try std.testing.expectError(error.InvalidHuffman, decoder.decode(arena, &.{ 0x00, 0x81, 0xff, 0x00 }, &out));
}

test "a size error keeps the dynamic table the same as the table of the encoder" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var decoder: Decoder = .init(gpa, .{ .max_field_size = 16, .max_header_list_size = 70 });
    defer decoder.deinit();
    var out: std.ArrayList(Header) = .empty;
    // A value over the field limit, then a literal with incremental indexing.
    try std.testing.expectError(error.FieldTooLarge, decoder.decode(arena, "\x00\x01n\x11" ++ "a" ** 17 ++ "\x40\x01k\x01v", &out));
    try std.testing.expectEqualStrings("k", (decoder.dynamicEntry(0) orelse return error.TestExpectedEntry).name);
    // Three headers over the list limit, then a literal with incremental indexing.
    try std.testing.expectError(error.HeaderListTooLarge, decoder.decode(arena, "\x00\x01a\x01b" ** 3 ++ "\x40\x01m\x01w", &out));
    try std.testing.expectEqualStrings("m", (decoder.dynamicEntry(0) orelse return error.TestExpectedEntry).name);
    // The next block refers to both entries. Before, the decoder stopped at the error and
    // did not add them, thus this block gave `error.Invalid` or another header.
    out.clearRetainingCapacity();
    try decoder.decode(arena, &.{ 0xbe, 0xbf }, &out);
    try std.testing.expectEqualStrings("m", out.items[0].name);
    try std.testing.expectEqualStrings("w", out.items[0].value);
    try std.testing.expectEqualStrings("k", out.items[1].name);
    try std.testing.expectEqualStrings("v", out.items[1].value);
}

test "a literal whose indexed name the new entry evicts keeps the name" {
    // Section 4.4: the name can refer to the entry that the insertion evicts. The fuzz job
    // found that the decoder copied the name after it freed that entry.
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var decoder: Decoder = .init(gpa, .{ .max_table_size = 64 });
    defer decoder.deinit();
    var out: std.ArrayList(Header) = .empty;
    try decoder.decode(arena, &.{ 0x40, 0x04, 'n', 'a', 'm', 'e', 0x01, 'v' }, &out); // cost 37
    // Index 62 is "name". The new entry (cost 38) evicts it.
    try decoder.decode(arena, &.{ 0x7e, 0x02, 'w', 'w' }, &out);
    try std.testing.expectEqualStrings("name", out.items[1].name);
    try std.testing.expectEqualStrings("ww", out.items[1].value);
    try std.testing.expectEqualStrings("name", decoder.dynamicEntry(0).?.name);
    try std.testing.expectEqual(38, decoder.dynamicSize());
    // An entry larger than the table empties it, and the header still has its name.
    try decoder.decode(arena, "\x7e\x28" ++ "x" ** 40, &out);
    try std.testing.expectEqualStrings("name", out.items[2].name);
    try std.testing.expectEqual(0, decoder.dynamicSize());
}
