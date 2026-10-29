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
    /// The bytes of the dynamic table entries, oldest first, in `table[head..tail]`. A new
    /// entry goes at `tail`, and an eviction only moves `head`. Thus the bytes of an entry
    /// stay in place after its eviction, until a move. An insertion moves the live bytes to
    /// the start or to a larger buffer when the end has no space. Before a move, `pin` copies
    /// the strings of the fields of the block that refer to the table.
    table: []u8 = &.{},
    head: usize = 0,
    tail: usize = 0,
    /// The entries, oldest first, in `entries.items[first..]`.
    entries: std.ArrayList(Entry) = .empty,
    first: usize = 0,
    size: usize = 0,
    /// The current table size limit, set by the encoder within `max_table_size`.
    table_size: u32,
    /// The fields of the last block. The decoder keeps the memory for the next block.
    fields: std.ArrayList(Field) = .empty,
    /// The Huffman-decoded strings of the last block, and the copies that `pin` makes.
    scratch: std.ArrayList(u8) = .empty,
    /// The result of `decodeBlock`.
    view: std.ArrayList(Header) = .empty,

    /// The largest scratch buffer that the decoder keeps after a block, in units of
    /// `max_header_list_size`. A larger buffer, for example after a long Huffman string that
    /// gives `error.FieldTooLarge`, goes back to the allocator. The fields of a list under the
    /// limit need less.
    const scratch_keep_factor = 2;

    /// An entry at `table[offset..]`: the name, then the value.
    const Entry = struct { offset: usize, name_len: usize, value_len: usize };

    /// A string of a decoded field, and the location of its bytes. The struct is small,
    /// because the decoder copies it for each field.
    const Str = struct {
        /// The address of the bytes, or for `scratch` the start in `scratch`.
        at: usize,
        len: usize,
        where: Where,

        const Where = enum(u8) {
            /// The static table: always valid.
            static,
            /// The block: valid while the block stays the same.
            block,
            /// The dynamic table: valid until the next move of the table. See `pin`.
            table,
            /// The scratch buffer: valid until the next block. The offset stays valid when
            /// the buffer grows.
            scratch,
        };

        fn fixed(where: Where, s: []const u8) Str {
            return .{ .where = where, .at = @intFromPtr(s.ptr), .len = s.len };
        }

        /// The bytes of a string that is not in `scratch`.
        fn slice(s: Str) []const u8 {
            if (s.len == 0) return "";
            return @as([*]const u8, @ptrFromInt(s.at))[0..s.len];
        }
    };

    const Field = struct { name: Str, value: Str };

    pub fn init(gpa: Allocator, options: Options) Decoder {
        return .{ .gpa = gpa, .options = options, .table_size = options.max_table_size };
    }

    pub fn deinit(self: *Decoder) void {
        self.gpa.free(self.table);
        self.entries.deinit(self.gpa);
        self.fields.deinit(self.gpa);
        self.scratch.deinit(self.gpa);
        self.view.deinit(self.gpa);
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
        while (self.size > limit and self.first < self.entries.items.len) {
            const oldest = self.entries.items[self.first];
            self.first += 1;
            self.size -= oldest.name_len + oldest.value_len + entry_overhead;
            self.head = oldest.offset + oldest.name_len + oldest.value_len;
        }
        if (self.first == self.entries.items.len) {
            // The bytes stay until the next move, because a field can refer to them.
            self.entries.clearRetainingCapacity();
            self.first = 0;
        }
    }

    /// Copy the strings of the fields of the block that refer to the table to `scratch`. Call
    /// it before a move of the table bytes.
    fn pin(self: *Decoder) Allocator.Error!void {
        for (self.fields.items) |*f| {
            f.name = try self.keep(f.name);
            f.value = try self.keep(f.value);
        }
    }

    /// Move the live bytes to the start of the table. The caller calls `pin` first.
    fn compactBytes(self: *Decoder) void {
        for (self.entries.items[self.first..]) |*e| e.offset -= self.head;
        std.mem.copyForwards(u8, self.table, self.table[self.head..self.tail]);
        self.tail -= self.head;
        self.head = 0;
    }

    /// `name` and `value` must not be in the dynamic table, because the insertion can move
    /// the table. The function gets their bytes only after `pin`, because `pin` can move
    /// `scratch`.
    fn add(self: *Decoder, name_str: Str, value_str: Str) Allocator.Error!void {
        std.debug.assert(name_str.where != .table and value_str.where != .table);
        const cost = name_str.len + value_str.len + entry_overhead;
        // An entry larger than the table empties it (section 4.4).
        if (cost > self.table_size) {
            self.evictTo(0);
            return;
        }
        // Get the memory before the eviction. Thus an error leaves the table as it was. After
        // the eviction, the live bytes and the new entry need `table_size` bytes or less. Thus
        // a move to the start makes space at the end, and a move occurs at most one time for
        // each `table_size` bytes of new entries. The eviction does not change `tail`, thus
        // the need for a move is known before it.
        const len = name_str.len + value_str.len;
        const capacity = 2 * @as(usize, self.table_size);
        const grow = self.table.len < capacity;
        const move = grow or self.table.len - self.tail < len;
        if (move) try self.pin();
        if (grow) {
            const bigger = try self.gpa.alloc(u8, capacity);
            @memcpy(bigger[0 .. self.tail - self.head], self.table[self.head..self.tail]);
            for (self.entries.items[self.first..]) |*e| e.offset -= self.head;
            self.gpa.free(self.table);
            self.table = bigger;
            self.tail -= self.head;
            self.head = 0;
        }
        if (self.first > 0 and self.entries.items.len == self.entries.capacity) {
            // Move the live entries to the start of their list. Their offsets stay.
            const live = self.entries.items[self.first..];
            std.mem.copyForwards(Entry, self.entries.items, live);
            self.entries.items.len = live.len;
            self.first = 0;
        }
        try self.entries.ensureUnusedCapacity(self.gpa, 1);
        self.evictTo(self.table_size - cost);
        if (move) self.compactBytes();
        std.debug.assert(self.table.len - self.tail >= len);
        const name = self.bytes(name_str);
        const value = self.bytes(value_str);
        const at = self.table[self.tail..][0..len];
        @memcpy(at[0..name.len], name);
        @memcpy(at[name.len..], value);
        self.entries.appendAssumeCapacity(.{ .offset = self.tail, .name_len = name.len, .value_len = value.len });
        self.tail += len;
        self.size += cost;
    }

    fn entryHeader(self: *const Decoder, e: Entry) Header {
        const b = self.table[e.offset..][0 .. e.name_len + e.value_len];
        return .{ .name = b[0..e.name_len], .value = b[e.name_len..] };
    }

    /// The entry at a 1-based index over the static and then the dynamic table.
    fn lookup(self: *const Decoder, index: u64) ?Field {
        if (index == 0) return null;
        if (index <= tables.static_table.len) {
            const s = tables.static_table[@intCast(index - 1)];
            return .{ .name = .fixed(.static, s.name), .value = .fixed(.static, s.value) };
        }
        const dyn = index - tables.static_table.len - 1;
        const live = self.entries.items[self.first..];
        if (dyn >= live.len) return null;
        const h = self.entryHeader(live[live.len - 1 - @as(usize, @intCast(dyn))]);
        return .{ .name = .fixed(.table, h.name), .value = .fixed(.table, h.value) };
    }

    /// The dynamic entry at an index from the newest, for tests. The slices stay valid until
    /// the next decode.
    pub fn dynamicEntry(self: *const Decoder, index_from_newest: usize) ?Header {
        const live = self.entries.items[self.first..];
        if (index_from_newest >= live.len) return null;
        return self.entryHeader(live[live.len - 1 - index_from_newest]);
    }

    pub fn dynamicSize(self: *const Decoder) usize {
        return self.size;
    }

    /// Decode one header block and append the headers to `out`. The decoder copies the
    /// headers into `arena`.
    pub fn decode(self: *Decoder, arena: Allocator, block: []const u8, out: *std.ArrayList(Header)) Error!void {
        try out.appendSlice(arena, try self.decodeOwned(arena, block));
    }

    /// Decode one header block into one allocation from `arena`. The headers then stay valid
    /// as long as `arena`. A string of the static table stays in the static table.
    pub fn decodeOwned(self: *Decoder, arena: Allocator, block: []const u8) Error![]Header {
        defer self.trim();
        try self.decodeFields(block);
        const fields = self.fields.items;
        if (fields.len == 0) return &.{};
        var total = fields.len * @sizeOf(Header);
        for (fields) |f| total += copyLen(f.name) + copyLen(f.value);
        // The headers and their bytes in one allocation. The function writes all of it, thus
        // it does not fill it first, as `Allocator.alloc` does in a safe build.
        const raw = arena.rawAlloc(total, .of(Header), @returnAddress()) orelse return error.OutOfMemory;
        const headers: []Header = @as([*]Header, @ptrCast(@alignCast(raw)))[0..fields.len];
        var at = fields.len * @sizeOf(Header);
        for (headers, fields) |*h, f| {
            h.* = .{ .name = self.copyStr(raw, &at, f.name), .value = self.copyStr(raw, &at, f.value) };
        }
        std.debug.assert(at == total);
        return headers;
    }

    fn copyLen(s: Str) usize {
        return if (s.where == .static) 0 else s.len;
    }

    fn copyStr(self: *const Decoder, raw: [*]u8, at: *usize, s: Str) []const u8 {
        if (s.where == .static) return s.slice();
        const dest = raw[at.*..][0..s.len];
        @memcpy(dest, self.bytes(s));
        at.* += s.len;
        return dest;
    }

    /// Decode one header block without a copy. The headers refer to `block`, to the static
    /// table and to the memory of the decoder. They stay valid until the next call of a
    /// decode function or `deinit`, and while `block` stays the same.
    pub fn decodeBlock(self: *Decoder, block: []const u8) Error![]const Header {
        errdefer self.trim();
        try self.decodeFields(block);
        self.view.clearRetainingCapacity();
        try self.view.ensureUnusedCapacity(self.gpa, self.fields.items.len);
        for (self.fields.items) |f| self.view.appendAssumeCapacity(.{ .name = self.bytes(f.name), .value = self.bytes(f.value) });
        return self.view.items;
    }

    /// Give a large scratch buffer back to the allocator. The headers of `decodeBlock` refer
    /// to the buffer, thus call this function only after their use.
    pub fn trim(self: *Decoder) void {
        const keep_max = std.math.mul(usize, scratch_keep_factor, self.options.max_header_list_size) catch std.math.maxInt(usize);
        if (self.scratch.capacity > keep_max) self.scratch.clearAndFree(self.gpa);
    }

    fn bytes(self: *const Decoder, s: Str) []const u8 {
        return if (s.where == .scratch) self.scratch.items[s.at..][0..s.len] else s.slice();
    }

    /// Copy a string of the dynamic table to `scratch`, because the next move of the table
    /// can overwrite it.
    fn keep(self: *Decoder, s: Str) Allocator.Error!Str {
        if (s.where != .table) return s;
        const offset = self.scratch.items.len;
        try self.scratch.appendSlice(self.gpa, s.slice());
        return .{ .where = .scratch, .at = offset, .len = s.len };
    }

    /// Decode one header block into `fields`.
    ///
    /// After `error.FieldTooLarge` or `error.HeaderListTooLarge`, the decoder reads the rest of
    /// the block and gives the error at the end. It adds no more headers to `fields`, but it
    /// applies each change to the dynamic table. Thus the table stays the same as the table of
    /// the encoder, and the next block of the connection decodes correctly (RFC 9113 section
    /// 4.3). The other errors end the connection, thus the decoder stops at once.
    fn decodeFields(self: *Decoder, block: []const u8) Error!void {
        self.fields.clearRetainingCapacity();
        self.scratch.clearRetainingCapacity();
        var state: DecodeState = .{};
        var r: BlockReader = .{ .buf = block };
        var saw_header = false;
        while (!r.eof()) {
            const first = r.buf[r.pos];
            // After a size error, the block gives no headers. Thus the fields go, and each field
            // then gives its scratch bytes back, also the copies of `pin`. The scratch data
            // stays small, and no field keeps an offset past the end of `scratch`.
            const mark = self.scratch.items.len;
            defer if (state.size_error != null) {
                self.fields.clearRetainingCapacity();
                self.scratch.shrinkRetainingCapacity(mark);
            };
            if (first & 0x80 != 0) {
                // Indexed header field.
                const index = try r.integer(7);
                const f = self.lookup(index) orelse return error.Invalid;
                try self.emit(&state, f.name, f.value);
                saw_header = true;
            } else if (first & 0x40 != 0) {
                // Literal with incremental indexing.
                const f = try self.literal(&state, &r, 6);
                // An indexed name can refer to the entry that `add` evicts. A move of the table
                // can then overwrite it.
                const name = try self.keep(f.name);
                try self.add(name, f.value);
                try self.emit(&state, name, f.value);
                saw_header = true;
            } else if (first & 0x20 != 0) {
                // Dynamic table size update: only at the start of a block.
                if (saw_header) return error.Invalid;
                const new_size = try r.integer(5);
                if (new_size > self.options.max_table_size) return error.Invalid;
                self.resize(@intCast(new_size));
            } else {
                // Literal without indexing (0000) or never indexed (0001).
                const f = try self.literal(&state, &r, 4);
                try self.emit(&state, f.name, f.value);
                saw_header = true;
            }
        }
        if (state.size_error) |e| return e;
    }

    /// The state of one call of `decodeFields`.
    const DecodeState = struct {
        list_size: usize = 0,
        /// The first size error of the block. After it, `emit` adds no header.
        size_error: ?Error = null,

        fn setSizeError(state: *DecodeState, err: Error) void {
            if (state.size_error == null) state.size_error = err;
        }
    };

    /// Add a field to `fields`. A string of the dynamic table stays in the table until a move
    /// of the table. Then `pin` copies it. The copies stay under the limit of the header list.
    /// Thus a block of small indexes to large entries cannot make much scratch data.
    fn emit(self: *Decoder, state: *DecodeState, name: Str, value: Str) Error!void {
        if (state.size_error != null) return;
        state.list_size += name.len + value.len + entry_overhead;
        if (state.list_size > self.options.max_header_list_size) return state.setSizeError(error.HeaderListTooLarge);
        try self.fields.append(self.gpa, .{ .name = name, .value = value });
    }

    /// A literal representation: an indexed or literal name, then a literal value.
    fn literal(self: *Decoder, state: *DecodeState, r: *BlockReader, prefix: u4) Error!Field {
        const index = try r.integer(prefix);
        const name: Str = if (index == 0)
            try self.string(state, r)
        else
            (self.lookup(index) orelse return error.Invalid).name;
        const value = try self.string(state, r);
        return .{ .name = name, .value = value };
    }

    /// A string over `max_field_size` sets `error.FieldTooLarge`. The function still decodes
    /// the string, because a dynamic table entry can need it. The string is part of the
    /// block, thus the size of the block limits it.
    fn string(self: *Decoder, state: *DecodeState, r: *BlockReader) Error!Str {
        if (r.eof()) return error.Truncated;
        const huff = r.buf[r.pos] & 0x80 != 0;
        const len = try r.integer(7);
        const raw = try r.take(std.math.cast(usize, len) orelse return error.Truncated);
        if (raw.len > self.options.max_field_size) state.setSizeError(error.FieldTooLarge);
        if (!huff) return .fixed(.block, raw);
        const offset = self.scratch.items.len;
        try self.scratch.ensureUnusedCapacity(self.gpa, huffman.maxDecodedLen(raw.len));
        const n = try huffman.decodeInto(self.scratch.unusedCapacitySlice(), raw);
        self.scratch.items.len += n;
        if (n > self.options.max_field_size) state.setSizeError(error.FieldTooLarge);
        return .{ .where = .scratch, .at = offset, .len = n };
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
    try std.testing.expectError(error.FieldTooLarge, decoder.decode(arena, "\x00\x11" ++ @as([17]u8, @splat('a')) ++ "\x00", &out));
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
    try std.testing.expectError(error.FieldTooLarge, decoder.decode(arena, "\x00\x01n\x11" ++ @as([17]u8, @splat('a')) ++ "\x40\x01k\x01v", &out));
    try std.testing.expectEqualStrings("k", (decoder.dynamicEntry(0) orelse return error.TestExpectedEntry).name);
    // Three headers over the list limit, then a literal with incremental indexing.
    try std.testing.expectError(error.HeaderListTooLarge, decoder.decode(arena, ("\x00\x01a\x01b" ++ "\x00\x01a\x01b" ++ "\x00\x01a\x01b") ++ "\x40\x01m\x01w", &out));
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
    try decoder.decode(arena, "\x7e\x28" ++ @as([40]u8, @splat('x')), &out);
    try std.testing.expectEqualStrings("name", out.items[2].name);
    try std.testing.expectEqual(0, decoder.dynamicSize());
}

fn inside(outer: []const u8, inner: []const u8) bool {
    if (inner.len == 0) return false;
    const o = @intFromPtr(outer.ptr);
    const i = @intFromPtr(inner.ptr);
    return i >= o and i < o + outer.len;
}

test "decoded headers stay valid after eviction and after the next blocks" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var decoder: Decoder = .init(gpa, .{ .max_table_size = 96 });
    defer decoder.deinit();
    const encoder: Encoder = .{};

    // Block 1: a literal with incremental indexing and a Huffman value, then an indexed
    // reference to the new entry, a static entry and a literal without indexing.
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.append(gpa, 0x40);
    try encoder.encodeString(gpa, &block, "x-first");
    try encoder.encodeString(gpa, &block, "www.example.com");
    try block.append(gpa, 0xbe); // index 62: the new entry
    try block.append(gpa, 0x83); // :method POST
    try encoder.encodeHeader(gpa, &block, "x-plain", "\x01\x02", false);
    const first = try decoder.decodeOwned(arena, block.items);
    try std.testing.expectEqual(4, first.len);
    // No string refers to the block or to the memory of the decoder. The static entry stays
    // in the static table.
    for (first) |h| for ([_][]const u8{ h.name, h.value }) |str| {
        try std.testing.expect(!inside(block.items, str));
        try std.testing.expect(!inside(decoder.table, str));
        try std.testing.expect(!inside(decoder.scratch.allocatedSlice(), str));
    };
    try std.testing.expectEqual(@intFromPtr(tables.static_table[2].value.ptr), @intFromPtr(first[2].value.ptr));

    // The next blocks reuse the block buffer and the scratch buffer, and their entries evict
    // the entry of block 1 and move the table.
    var prng: std.Random.DefaultPrng = .init(1);
    const random = prng.random();
    for (0..200) |round| {
        @memset(block.items, 0xee);
        block.clearRetainingCapacity();
        var name_buf: [16]u8 = undefined;
        var value_buf: [40]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "x-{d}", .{round}) catch unreachable;
        const value = value_buf[0..random.uintLessThan(usize, value_buf.len)];
        random.bytes(value);
        try block.append(gpa, 0x40);
        try encoder.encodeString(gpa, &block, name);
        try encoder.encodeString(gpa, &block, value);
        try block.append(gpa, 0xbe);
        const got = try decoder.decodeOwned(arena, block.items);
        try std.testing.expectEqualStrings(name, got[0].name);
        try std.testing.expectEqualSlices(u8, value, got[1].value);
    }
    try std.testing.expect(decoder.dynamicEntry(0) != null);
    const want = [_]Header{
        .{ .name = "x-first", .value = "www.example.com" },
        .{ .name = "x-first", .value = "www.example.com" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = "x-plain", .value = "\x01\x02" },
    };
    for (want, first) |w, g| {
        try std.testing.expectEqualStrings(w.name, g.name);
        try std.testing.expectEqualStrings(w.value, g.value);
    }
}

test "a view of a block refers to the block and to the decoder" {
    const gpa = std.testing.allocator;
    var decoder: Decoder = .init(gpa, .{});
    defer decoder.deinit();
    // A literal name and value without Huffman, a Huffman value, and an indexed dynamic
    // entry.
    const block = "\x40\x01a\x01b" ++ "\x00\x01c\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff" ++ "\xbe";
    const view = try decoder.decodeBlock(block);
    try std.testing.expectEqual(3, view.len);
    try std.testing.expect(inside(block, view[0].name) and inside(block, view[0].value));
    try std.testing.expectEqualStrings("www.example.com", view[1].value);
    try std.testing.expect(inside(decoder.scratch.items, view[1].value));
    // The indexed entry stays in the table: no insertion moved the table after it.
    try std.testing.expect(inside(decoder.table, view[2].name));
    try std.testing.expectEqualStrings("a", view[2].name);
    try std.testing.expectEqualStrings("b", view[2].value);
}

test "the dynamic table agrees with a simple model under random insertions" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var decoder: Decoder = .init(gpa, .{ .max_table_size = 512, .max_header_list_size = 1 << 20, .max_field_size = 1 << 20 });
    defer decoder.deinit();
    const encoder: Encoder = .{ .huffman = false };
    // The model: the entries, newest first, and their size.
    var model: std.ArrayList(Header) = .empty;
    var model_size: usize = 0;
    var limit: usize = 512;
    var prng: std.Random.DefaultPrng = .init(0x4c);
    const random = prng.random();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    var want: std.ArrayList(Header) = .empty;
    var moves: usize = 0;
    for (0..3000) |_| {
        block.clearRetainingCapacity();
        want.clearRetainingCapacity();
        if (random.uintLessThan(u8, 20) == 0) {
            limit = random.uintLessThan(usize, 513);
            try Encoder.encodeInteger(gpa, &block, 5, 0x20, limit);
            while (model_size > limit) model_size -= removeOldest(&model);
        }
        // Up to 6 operations: a reference to an entry, or an insertion. A reference before
        // an insertion that moves the table must keep its bytes.
        const ops = 1 + random.uintLessThan(usize, 6);
        for (0..ops) |_| {
            if (model.items.len > 0 and random.boolean()) {
                const index = random.uintLessThan(usize, model.items.len);
                try Encoder.encodeInteger(gpa, &block, 7, 0x80, 62 + index);
                try want.append(arena, model.items[index]);
                continue;
            }
            var name_buf: [200]u8 = undefined;
            var value_buf: [300]u8 = undefined;
            const name = name_buf[0 .. 1 + random.uintLessThan(usize, name_buf.len - 1)];
            for (name) |*c| c.* = 'a' + random.uintLessThan(u8, 26);
            const value = value_buf[0..random.uintLessThan(usize, value_buf.len)];
            random.bytes(value);
            // A literal name, or the name of a dynamic entry that the insertion can evict.
            const by_index = model.items.len > 0 and random.boolean();
            const index = if (by_index) random.uintLessThan(usize, model.items.len) else 0;
            const new_name = if (by_index) model.items[index].name else name;
            try Encoder.encodeInteger(gpa, &block, 6, 0x40, if (by_index) 62 + index else 0);
            if (!by_index) try encoder.encodeString(gpa, &block, name);
            try encoder.encodeString(gpa, &block, value);
            const cost = new_name.len + value.len + entry_overhead;
            const owned: Header = .{ .name = try arena.dupe(u8, new_name), .value = try arena.dupe(u8, value) };
            try want.append(arena, owned);
            if (cost > limit) {
                model.clearRetainingCapacity();
                model_size = 0;
            } else {
                while (model_size + cost > limit) model_size -= removeOldest(&model);
                try model.insert(arena, 0, owned);
                model_size += cost;
            }
        }
        const table_before = decoder.table.ptr;
        const head_before = decoder.head;
        const got = try decoder.decodeOwned(arena, block.items);
        if (decoder.table.ptr != table_before or decoder.head < head_before) moves += 1;
        try std.testing.expectEqual(want.items.len, got.len);
        for (want.items, got) |w, g| {
            try std.testing.expectEqualStrings(w.name, g.name);
            try std.testing.expectEqualSlices(u8, w.value, g.value);
        }
        try std.testing.expectEqual(model_size, decoder.dynamicSize());
        for (model.items, 0..) |w, i| {
            const entry = decoder.dynamicEntry(i).?;
            try std.testing.expectEqualStrings(w.name, entry.name);
            try std.testing.expectEqualSlices(u8, w.value, entry.value);
        }
        try std.testing.expect(decoder.dynamicEntry(model.items.len) == null);
    }
    // The sequence moved the table many times. A reference before the move then needs the
    // copy of `pin`.
    try std.testing.expect(moves > 100);
}

fn removeOldest(model: *std.ArrayList(Header)) usize {
    const oldest = model.pop().?;
    return oldest.name.len + oldest.value.len + entry_overhead;
}

test "references to a large entry over the list limit do not grow the scratch buffer" {
    const gpa = std.testing.allocator;
    var decoder: Decoder = .init(gpa, .{ .max_table_size = 4096, .max_field_size = 4096, .max_header_list_size = 8 << 10 });
    defer decoder.deinit();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.append(gpa, 0x40);
    try Encoder.encodeInteger(gpa, &block, 7, 0, 1);
    try block.append(gpa, 'n');
    try Encoder.encodeInteger(gpa, &block, 7, 0, 4000);
    try block.appendNTimes(gpa, 'v', 4000);
    // 10,000 references of one byte each to the entry of 4,033 octets.
    try block.appendNTimes(gpa, 0xbe, 10_000);
    try std.testing.expectError(error.HeaderListTooLarge, decoder.decodeBlock(block.items));
    try std.testing.expect(decoder.scratch.items.len <= 8 << 10);
    // Literals with the name of the entry after the size error: the copies of the name go
    // back.
    block.clearRetainingCapacity();
    try block.appendNTimes(gpa, 0xbe, 3);
    for (0..1000) |_| try block.appendSlice(gpa, &.{ 0x0f, 0x2f, 0x00 }); // index 62, empty value
    try std.testing.expectError(error.HeaderListTooLarge, decoder.decodeBlock(block.items));
    try std.testing.expect(decoder.scratch.items.len <= 8 << 10);
}

test "a reference keeps its bytes when a later insertion of the block moves the table" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // A table of 64 octets has a buffer of 128. Each entry costs 60 and evicts the entry
    // before it, but its 28 bytes stay until a move.
    var decoder: Decoder = .init(gpa, .{ .max_table_size = 64 });
    defer decoder.deinit();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    for (0..10) |i| {
        try block.appendSlice(gpa, "\x40\x01n\x1b");
        try block.appendNTimes(gpa, 'a' + @as(u8, @intCast(i)), 27);
        try block.append(gpa, 0xbe);
    }
    const got = try decoder.decodeOwned(arena, block.items);
    try std.testing.expectEqual(20, got.len);
    for (0..10) |i| {
        const want = @as([27]u8, @splat('a' + @as(u8, @intCast(i))));
        try std.testing.expectEqualStrings("n", got[2 * i].name);
        try std.testing.expectEqualStrings(&want, got[2 * i].value);
        try std.testing.expectEqualStrings("n", got[2 * i + 1].name);
        try std.testing.expectEqualStrings(&want, got[2 * i + 1].value);
    }
    // The table moved, thus `pin` copied the earlier references.
    try std.testing.expect(decoder.scratch.items.len > 0);
}

test "a long Huffman string does not leave a large scratch buffer behind" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var decoder: Decoder = .init(gpa, .{});
    defer decoder.deinit();
    const keep_max = Decoder.scratch_keep_factor * decoder.options.max_header_list_size;
    // A literal without indexing with a Huffman value of 30,000 octets: over the field limit.
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try (Encoder{}).encodeHeader(gpa, &block, "x-long", &@as([30_000]u8, @splat('a')), false);
    try std.testing.expectError(error.FieldTooLarge, decoder.decodeOwned(arena, block.items));
    try std.testing.expect(decoder.scratch.capacity <= keep_max);
    try std.testing.expectError(error.FieldTooLarge, decoder.decodeBlock(block.items));
    try std.testing.expect(decoder.scratch.capacity <= keep_max);
    // A block under the limits keeps its small buffer for the next block.
    block.clearRetainingCapacity();
    try (Encoder{}).encodeHeader(gpa, &block, "x-short", "www.example.com", false);
    const got = try decoder.decodeOwned(arena, block.items);
    try std.testing.expectEqualStrings("www.example.com", got[0].value);
    try std.testing.expect(decoder.scratch.capacity > 0 and decoder.scratch.capacity <= keep_max);
}

test "a size error clears the fields of the block" {
    const gpa = std.testing.allocator;
    var decoder: Decoder = .init(gpa, .{ .max_field_size = 16, .max_header_list_size = 200 });
    defer decoder.deinit();
    // A header, then a value over the field limit, then a literal with incremental indexing.
    try std.testing.expectError(error.FieldTooLarge, decoder.decodeBlock("\x00\x01a\x01b" ++ "\x00\x01n\x11" ++ @as([17]u8, @splat('a')) ++ "\x40\x01k\x01v"));
    try std.testing.expectEqual(0, decoder.fields.items.len);
    try std.testing.expectEqualStrings("k", decoder.dynamicEntry(0).?.name);
}
