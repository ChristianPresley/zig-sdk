//! A small D-Bus client for the Secret Service backend of `KeychainTokenStorage`. It connects
//! to a bus at a Unix socket and authenticates with the SASL mechanism `EXTERNAL`. Then it sends
//! requests to the methods of objects and reads the responses. Each wait for the bus can have a
//! time limit. Thus the caller does not wait without end for a bus or a service that does not
//! answer.
//!
//! The client writes little-endian messages and reads messages in both byte orders. It has the
//! types that the Secret Service API needs: `y`, `b`, `u`, `s`, `o`, `g`, `v`, arrays, structs
//! and dictionary entries. It skips values of the other basic types. It does not pass file
//! descriptors.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.mcp_dbus);

pub const Error = error{
    OutOfMemory,
    /// The address has no transport that this client supports.
    UnsupportedAddress,
    /// The connection to the bus failed.
    ConnectFailed,
    /// The bus refused the authentication.
    AuthenticationFailed,
    /// The peer sent data that does not follow the D-Bus specification.
    ProtocolError,
    /// A message is larger than `max_message_bytes`.
    MessageTooLarge,
    /// The peer closed the connection.
    ConnectionClosed,
    /// The response is an error message. `Connection.error_name` has its name.
    CallFailed,
    /// The bus did not read a request or did not answer in the time limit. After this error the
    /// connection is not usable.
    Timeout,
    Canceled,
};

/// The time limit for an answer of the bus that `secret_service.Options` uses by default: 25
/// seconds. It is the same as the default of the reference implementation of D-Bus.
pub const default_timeout: Io.Duration = .fromSeconds(25);

/// The largest message that the client reads or writes.
pub const max_message_bytes = 4 << 20;
const max_header_fields_bytes = 64 << 10;
const max_depth = 32;

// -- Addresses ---------------------------------------------------------------------------------

/// A bus address that the client can connect to.
pub const Address = union(enum) {
    /// A Unix socket at a file system path.
    path: []const u8,
    /// A Unix socket in the abstract namespace of Linux, without the first zero byte.
    abstract: []const u8,
};

/// The first address of a D-Bus address list with the transport `unix` and the key `path` or
/// `abstract`. The function decodes the escapes of the value into `arena`.
pub fn parseAddress(arena: Allocator, text: []const u8) Error!Address {
    var entries = std.mem.splitScalar(u8, text, ';');
    while (entries.next()) |entry| {
        const colon = std.mem.indexOfScalar(u8, entry, ':') orelse continue;
        if (!std.mem.eql(u8, entry[0..colon], "unix")) continue;
        var pairs = std.mem.splitScalar(u8, entry[colon + 1 ..], ',');
        while (pairs.next()) |pair| {
            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
            const key = pair[0..eq];
            if (std.mem.eql(u8, key, "path")) return .{ .path = try unescape(arena, pair[eq + 1 ..]) };
            if (std.mem.eql(u8, key, "abstract")) return .{ .abstract = try unescape(arena, pair[eq + 1 ..]) };
        }
    }
    return error.UnsupportedAddress;
}

fn unescape(arena: Allocator, value: []const u8) Error![]u8 {
    const out = try arena.alloc(u8, value.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (value[i] == '%') {
            if (i + 2 >= value.len) return error.UnsupportedAddress;
            out[n] = std.fmt.parseInt(u8, value[i + 1 .. i + 3], 16) catch return error.UnsupportedAddress;
            i += 2;
        } else {
            out[n] = value[i];
        }
        n += 1;
    }
    return out[0..n];
}

// -- Marshalling -------------------------------------------------------------------------------

/// Writes values in the little-endian wire format. Offsets count from the start of the buffer,
/// so a body buffer starts at offset 0 of the body. That is correct, because the body of a
/// message starts at a multiple of 8.
pub const Encoder = struct {
    gpa: Allocator,
    buf: std.ArrayList(u8) = .empty,

    /// An encoder with room for `capacity` bytes. A buffer that does not grow leaves no copy of
    /// a secret in freed memory.
    pub fn initCapacity(gpa: Allocator, capacity: usize) Allocator.Error!Encoder {
        return .{ .gpa = gpa, .buf = try .initCapacity(gpa, capacity) };
    }

    /// Erase and free the buffer.
    pub fn deinit(self: *Encoder) void {
        std.crypto.secureZero(u8, self.buf.allocatedSlice());
        self.buf.deinit(self.gpa);
    }

    pub fn written(self: *const Encoder) []const u8 {
        return self.buf.items;
    }

    pub fn pad(self: *Encoder, alignment: usize) Allocator.Error!void {
        while (self.buf.items.len % alignment != 0) try self.buf.append(self.gpa, 0);
    }

    pub fn byte(self: *Encoder, value: u8) Allocator.Error!void {
        try self.buf.append(self.gpa, value);
    }

    pub fn uint32(self: *Encoder, value: u32) Allocator.Error!void {
        try self.pad(4);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, value, .little);
        try self.buf.appendSlice(self.gpa, &b);
    }

    pub fn boolean(self: *Encoder, value: bool) Allocator.Error!void {
        try self.uint32(@intFromBool(value));
    }

    /// A `s` or an `o` value.
    pub fn string(self: *Encoder, value: []const u8) Allocator.Error!void {
        try self.uint32(@intCast(value.len));
        try self.buf.appendSlice(self.gpa, value);
        try self.buf.append(self.gpa, 0);
    }

    pub fn signature(self: *Encoder, value: []const u8) Allocator.Error!void {
        std.debug.assert(value.len <= 255);
        try self.byte(@intCast(value.len));
        try self.buf.appendSlice(self.gpa, value);
        try self.buf.append(self.gpa, 0);
    }

    /// An `ay` value.
    pub fn bytes(self: *Encoder, value: []const u8) Allocator.Error!void {
        try self.uint32(@intCast(value.len));
        try self.buf.appendSlice(self.gpa, value);
    }

    pub const ArrayMark = struct { length_at: usize, start: usize };

    /// Start an array. Give the alignment of the element type: 8 for a struct or a dictionary
    /// entry, 4 for `s`, `o` or `u`, 1 for `y`.
    pub fn beginArray(self: *Encoder, element_alignment: usize) Allocator.Error!ArrayMark {
        try self.uint32(0);
        const length_at = self.buf.items.len - 4;
        try self.pad(element_alignment);
        return .{ .length_at = length_at, .start = self.buf.items.len };
    }

    /// End an array. The length does not count the padding before the first element.
    pub fn endArray(self: *Encoder, mark: ArrayMark) void {
        const len: u32 = @intCast(self.buf.items.len - mark.start);
        std.mem.writeInt(u32, self.buf.items[mark.length_at..][0..4], len, .little);
    }

    /// Start a struct or a dictionary entry.
    pub fn beginStruct(self: *Encoder) Allocator.Error!void {
        try self.pad(8);
    }

    /// An `a{ss}` value.
    pub fn stringDict(self: *Encoder, pairs: []const [2][]const u8) Allocator.Error!void {
        const mark = try self.beginArray(8);
        for (pairs) |p| {
            try self.beginStruct();
            try self.string(p[0]);
            try self.string(p[1]);
        }
        self.endArray(mark);
    }
};

/// Reads values of a body or of a header. Offsets count from the start of `data`.
pub const Decoder = struct {
    data: []const u8,
    pos: usize = 0,
    big: bool = false,

    fn alignTo(self: *Decoder, alignment: usize) Error!void {
        const p = std.mem.alignForward(usize, self.pos, alignment);
        if (p > self.data.len) return error.ProtocolError;
        for (self.data[self.pos..p]) |b| if (b != 0) return error.ProtocolError;
        self.pos = p;
    }

    fn take(self: *Decoder, n: usize) Error![]const u8 {
        if (n > self.data.len - self.pos) return error.ProtocolError;
        defer self.pos += n;
        return self.data[self.pos..][0..n];
    }

    pub fn atEnd(self: *const Decoder) bool {
        return self.pos == self.data.len;
    }

    pub fn byte(self: *Decoder) Error!u8 {
        return (try self.take(1))[0];
    }

    pub fn uint32(self: *Decoder) Error!u32 {
        try self.alignTo(4);
        return std.mem.readInt(u32, (try self.take(4))[0..4], if (self.big) .big else .little);
    }

    pub fn boolean(self: *Decoder) Error!bool {
        return switch (try self.uint32()) {
            0 => false,
            1 => true,
            else => error.ProtocolError,
        };
    }

    /// A `s` or an `o` value.
    pub fn string(self: *Decoder) Error![]const u8 {
        const len = try self.uint32();
        const s = try self.take(len);
        if ((try self.byte()) != 0) return error.ProtocolError;
        if (std.mem.indexOfScalar(u8, s, 0) != null) return error.ProtocolError;
        return s;
    }

    pub fn signature(self: *Decoder) Error![]const u8 {
        const len = try self.byte();
        const s = try self.take(len);
        if ((try self.byte()) != 0) return error.ProtocolError;
        return s;
    }

    /// An `ay` value.
    pub fn bytes(self: *Decoder) Error![]const u8 {
        const len = try self.uint32();
        return self.take(len);
    }

    /// Start an array and return the offset of its end.
    pub fn beginArray(self: *Decoder, element_alignment: usize) Error!usize {
        const len = try self.uint32();
        if (len > max_message_bytes) return error.ProtocolError;
        try self.alignTo(element_alignment);
        if (len > self.data.len - self.pos) return error.ProtocolError;
        return self.pos + len;
    }

    pub fn beginStruct(self: *Decoder) Error!void {
        try self.alignTo(8);
    }

    /// An `ao` value, in `arena`.
    pub fn objectPaths(self: *Decoder, arena: Allocator) Error![]const []const u8 {
        const end = try self.beginArray(4);
        var out: std.ArrayList([]const u8) = .empty;
        while (self.pos < end) try out.append(arena, try self.string());
        if (self.pos != end) return error.ProtocolError;
        return out.items;
    }

    /// Skip one value of the complete type `sig`.
    pub fn skip(self: *Decoder, sig: []const u8) Error!void {
        var rest = sig;
        try self.skipOne(&rest, 0);
        if (rest.len != 0) return error.ProtocolError;
    }

    fn skipOne(self: *Decoder, rest: *[]const u8, depth: usize) Error!void {
        if (depth > max_depth or rest.len == 0) return error.ProtocolError;
        const c = rest.*[0];
        rest.* = rest.*[1..];
        switch (c) {
            'y' => _ = try self.take(1),
            'b', 'u', 'i', 'h' => {
                try self.alignTo(4);
                _ = try self.take(4);
            },
            'n', 'q' => {
                try self.alignTo(2);
                _ = try self.take(2);
            },
            'x', 't', 'd' => {
                try self.alignTo(8);
                _ = try self.take(8);
            },
            's', 'o' => _ = try self.string(),
            'g' => _ = try self.signature(),
            'v' => {
                var inner = try self.signature();
                try self.skipOne(&inner, depth + 1);
                if (inner.len != 0) return error.ProtocolError;
            },
            'a' => {
                const len = try completeTypeLen(rest.*);
                const element = rest.*[0..len];
                rest.* = rest.*[len..];
                const end = try self.beginArray(alignmentOf(element[0]));
                while (self.pos < end) {
                    var e = element;
                    try self.skipOne(&e, depth + 1);
                }
                if (self.pos != end) return error.ProtocolError;
            },
            '(', '{' => {
                const close: u8 = if (c == '(') ')' else '}';
                try self.alignTo(8);
                while (rest.len > 0 and rest.*[0] != close) try self.skipOne(rest, depth + 1);
                if (rest.len == 0) return error.ProtocolError;
                rest.* = rest.*[1..];
            },
            else => return error.ProtocolError,
        }
    }
};

/// The length of the first complete type of `sig`.
pub fn completeTypeLen(sig: []const u8) Error!usize {
    var depth: usize = 0;
    for (sig, 0..) |c, i| {
        switch (c) {
            'a' => continue,
            '(', '{' => depth += 1,
            ')', '}' => {
                if (depth == 0) return error.ProtocolError;
                depth -= 1;
            },
            else => {},
        }
        if (depth == 0) return i + 1;
    }
    return error.ProtocolError;
}

/// The alignment of a type that starts with `c`.
pub fn alignmentOf(c: u8) usize {
    return switch (c) {
        'n', 'q' => 2,
        'b', 'u', 'i', 'h', 's', 'o', 'a' => 4,
        'x', 't', 'd', '(', '{' => 8,
        else => 1,
    };
}

// -- Messages ----------------------------------------------------------------------------------

pub const Kind = enum(u8) { method_call = 1, method_return = 2, error_reply = 3, signal = 4, _ };

/// The flag `NO_REPLY_EXPECTED` of a message.
pub const flag_no_reply = 0x1;

/// A message that `readMessage` read. The slices point into `raw`.
pub const Message = struct {
    kind: Kind,
    flags: u8 = 0,
    serial: u32,
    reply_serial: ?u32 = null,
    path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    destination: ?[]const u8 = null,
    sender: ?[]const u8 = null,
    signature: []const u8 = "",
    body: []const u8 = "",
    big: bool = false,
    /// The whole message.
    raw: []u8 = &.{},

    /// A decoder for the body.
    pub fn decoder(self: Message) Decoder {
        return .{ .data = self.body, .big = self.big };
    }

    /// Erase the message. Use it for a message with a secret.
    pub fn erase(self: Message) void {
        std.crypto.secureZero(u8, self.raw);
    }
};

/// The fields of a message to send.
pub const Outgoing = struct {
    kind: Kind = .method_call,
    flags: u8 = 0,
    path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    reply_serial: ?u32 = null,
    destination: ?[]const u8 = null,
    sender: ?[]const u8 = null,
    signature: []const u8 = "",
    body: []const u8 = "",
};

/// Write `message` with the serial number `serial`. The function does not flush.
pub fn writeMessage(gpa: Allocator, w: *Io.Writer, serial: u32, message: Outgoing) (Allocator.Error || Io.Writer.Error || error{MessageTooLarge})!void {
    if (message.body.len > max_message_bytes) return error.MessageTooLarge;
    var h: Encoder = .{ .gpa = gpa };
    defer h.deinit();
    try h.byte('l');
    try h.byte(@intFromEnum(message.kind));
    try h.byte(message.flags);
    try h.byte(1);
    try h.uint32(@intCast(message.body.len));
    try h.uint32(serial);
    const fields = try h.beginArray(8);
    if (message.path) |v| try headerField(&h, 1, "o", v);
    if (message.interface) |v| try headerField(&h, 2, "s", v);
    if (message.member) |v| try headerField(&h, 3, "s", v);
    if (message.error_name) |v| try headerField(&h, 4, "s", v);
    if (message.reply_serial) |v| {
        try h.beginStruct();
        try h.byte(5);
        try h.signature("u");
        try h.uint32(v);
    }
    if (message.destination) |v| try headerField(&h, 6, "s", v);
    if (message.sender) |v| try headerField(&h, 7, "s", v);
    if (message.signature.len > 0) try headerField(&h, 8, "g", message.signature);
    h.endArray(fields);
    try h.pad(8);
    try w.writeAll(h.written());
    try w.writeAll(message.body);
}

fn headerField(h: *Encoder, code: u8, sig: []const u8, value: []const u8) Allocator.Error!void {
    try h.beginStruct();
    try h.byte(code);
    try h.signature(sig);
    if (sig[0] == 'g') try h.signature(value) else try h.string(value);
}

pub const ReadError = Error || Io.Reader.Error;

/// Read one message into memory from `arena`.
pub fn readMessage(arena: Allocator, r: *Io.Reader) ReadError!Message {
    var fixed: [16]u8 = undefined;
    try r.readSliceAll(&fixed);
    const big = switch (fixed[0]) {
        'l' => false,
        'B' => true,
        else => return error.ProtocolError,
    };
    if (fixed[3] != 1) return error.ProtocolError;
    const endian: std.builtin.Endian = if (big) .big else .little;
    const body_len = std.mem.readInt(u32, fixed[4..8], endian);
    const serial = std.mem.readInt(u32, fixed[8..12], endian);
    const fields_len = std.mem.readInt(u32, fixed[12..16], endian);
    if (fields_len > max_header_fields_bytes or body_len > max_message_bytes) return error.MessageTooLarge;
    const header_end = std.mem.alignForward(usize, 16 + fields_len, 8);
    const raw = try arena.alloc(u8, header_end + body_len);
    @memcpy(raw[0..16], &fixed);
    try r.readSliceAll(raw[16..]);
    var m: Message = .{ .kind = @enumFromInt(fixed[1]), .flags = fixed[2], .serial = serial, .big = big, .raw = raw, .body = raw[header_end..] };
    if (serial == 0) return error.ProtocolError;
    var d: Decoder = .{ .data = raw[0..header_end], .pos = 12, .big = big };
    const end = try d.beginArray(8);
    while (d.pos < end) {
        try d.beginStruct();
        const code = try d.byte();
        const sig = try d.signature();
        const want: ?[]const u8 = switch (code) {
            1 => "o",
            2, 3, 4, 6, 7 => "s",
            5 => "u",
            8 => "g",
            else => null,
        };
        if (want) |w| if (!std.mem.eql(u8, w, sig)) return error.ProtocolError;
        switch (code) {
            1 => m.path = try d.string(),
            2 => m.interface = try d.string(),
            3 => m.member = try d.string(),
            4 => m.error_name = try d.string(),
            5 => m.reply_serial = try d.uint32(),
            6 => m.destination = try d.string(),
            7 => m.sender = try d.string(),
            8 => m.signature = try d.signature(),
            else => try d.skip(sig),
        }
    }
    if (d.pos != end) return error.ProtocolError;
    return m;
}

// -- Connection --------------------------------------------------------------------------------

/// A request to a method.
pub const Call = struct {
    destination: ?[]const u8 = null,
    path: []const u8,
    interface: ?[]const u8 = null,
    member: []const u8,
    signature: []const u8 = "",
    body: []const u8 = "",
};

/// A connection to a bus. Create it with `open`, and free it with `close`. After
/// `error.Timeout` or `error.Canceled`, the connection is not usable. Close it.
pub const Connection = struct {
    io: Io,
    gpa: Allocator,
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    read_buf: [8192]u8,
    write_buf: [8192]u8,
    /// The time limit for each wait for the bus. The connect and the authentication together
    /// have one limit. Each `call`, `send` and `receive` has its own limit. Null waits without
    /// a limit.
    timeout: ?Io.Duration,
    serial: u32 = 0,
    /// The unique name that `Hello` gave.
    unique_name: ?[]u8 = null,
    /// The name of the last error response.
    error_name: ?[]u8 = null,
    /// Signals that came before a call of `waitSignal`. The messages are in the memory of the
    /// caller.
    signals: std.ArrayList(Message) = .empty,

    /// Connect to `address`, authenticate with `EXTERNAL` and the user ID `user_id` (decimal
    /// digits), and call `Hello`. `timeout` is the time limit for each answer of the bus, and
    /// null waits without a limit. The connect and the authentication together have one time
    /// limit. When `io` cannot run a task concurrently, the waits can have no limit.
    pub fn open(io: Io, gpa: Allocator, address: Address, user_id: []const u8, timeout: ?Io.Duration) Error!*Connection {
        const end = deadline(io, timeout);
        const stream = try within(io, end, connect, .{ io, address, end });
        const self = gpa.create(Connection) catch |e| {
            stream.close(io);
            return e;
        };
        self.* = .{ .io = io, .gpa = gpa, .stream = stream, .reader = undefined, .writer = undefined, .read_buf = undefined, .write_buf = undefined, .timeout = timeout };
        self.reader = stream.reader(io, &self.read_buf);
        self.writer = stream.writer(io, &self.write_buf);
        errdefer self.close();
        try within(io, end, authenticate, .{ self, user_id });
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const reply = try self.call(arena_state.allocator(), .{
            .destination = "org.freedesktop.DBus",
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "Hello",
        });
        if (!std.mem.eql(u8, reply.signature, "s")) return error.ProtocolError;
        var d = reply.decoder();
        self.unique_name = try gpa.dupe(u8, try d.string());
        return self;
    }

    /// Close the connection, erase the buffers and free the memory.
    pub fn close(self: *Connection) void {
        const gpa = self.gpa;
        self.stream.close(self.io);
        std.crypto.secureZero(u8, &self.read_buf);
        std.crypto.secureZero(u8, &self.write_buf);
        if (self.unique_name) |n| gpa.free(n);
        if (self.error_name) |n| gpa.free(n);
        self.signals.deinit(gpa);
        gpa.destroy(self);
    }

    fn authenticate(self: *Connection, user_id: []const u8) Error!void {
        const w = &self.writer.interface;
        // The client sends one zero byte first. The initial response is the user ID in
        // hexadecimal digits.
        var hex_buf: [64]u8 = undefined;
        if (user_id.len * 2 > hex_buf.len) return error.AuthenticationFailed;
        for (user_id, 0..) |c, i| _ = std.fmt.bufPrint(hex_buf[i * 2 ..][0..2], "{x:0>2}", .{c}) catch unreachable;
        w.writeByte(0) catch return self.writeFailed();
        w.print("AUTH EXTERNAL {s}\r\n", .{hex_buf[0 .. user_id.len * 2]}) catch return self.writeFailed();
        w.flush() catch return self.writeFailed();
        while (true) {
            const line = try self.readLine();
            if (std.mem.startsWith(u8, line, "OK ")) break;
            if (std.mem.eql(u8, line, "DATA")) {
                w.writeAll("DATA\r\n") catch return self.writeFailed();
                w.flush() catch return self.writeFailed();
                continue;
            }
            if (std.mem.startsWith(u8, line, "REJECTED")) return error.AuthenticationFailed;
            return error.ProtocolError;
        }
        w.writeAll("BEGIN\r\n") catch return self.writeFailed();
        w.flush() catch return self.writeFailed();
    }

    /// One line of the authentication, without the line end.
    fn readLine(self: *Connection) Error![]const u8 {
        const line = self.reader.interface.takeDelimiterInclusive('\n') catch |e| return switch (e) {
            error.StreamTooLong => error.ProtocolError,
            else => self.readFailed(),
        };
        return std.mem.trimEnd(u8, line, "\r\n");
    }

    fn readFailed(self: *Connection) Error {
        if (self.reader.err) |e| if (e == error.Canceled) return error.Canceled;
        return error.ConnectionClosed;
    }

    fn writeFailed(self: *Connection) Error {
        if (self.writer.err) |e| if (e == error.Canceled) return error.Canceled;
        return error.ConnectionClosed;
    }

    fn nextSerial(self: *Connection) u32 {
        self.serial +%= 1;
        if (self.serial == 0) self.serial = 1;
        return self.serial;
    }

    /// Send a request to a method and do not wait for the response. Returns the serial number.
    /// The write of the request has the time limit of the connection, because a bus that does
    /// not read can block the write.
    pub fn send(self: *Connection, c: Call) Error!u32 {
        return within(self.io, deadline(self.io, self.timeout), sendNow, .{ self, c });
    }

    fn sendNow(self: *Connection, c: Call) Error!u32 {
        const serial = self.nextSerial();
        writeMessage(self.gpa, &self.writer.interface, serial, .{
            .path = c.path,
            .interface = c.interface,
            .member = c.member,
            .destination = c.destination,
            .signature = c.signature,
            .body = c.body,
        }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.MessageTooLarge => error.MessageTooLarge,
            error.WriteFailed => self.writeFailed(),
        };
        self.writer.interface.flush() catch return self.writeFailed();
        return serial;
    }

    /// Read the next message into `arena`. Wait at most the time limit of the connection.
    pub fn receive(self: *Connection, arena: Allocator) Error!Message {
        return within(self.io, deadline(self.io, self.timeout), takeMessage, .{ self, arena });
    }

    fn takeMessage(self: *Connection, arena: Allocator) Error!Message {
        return readMessage(arena, &self.reader.interface) catch |e| switch (e) {
            error.ReadFailed, error.EndOfStream => self.readFailed(),
            else => |err| err,
        };
    }

    /// Call a method and wait for its response. An error response gives `error.CallFailed`,
    /// and `error_name` has the name of the error. The connection keeps the signals that come
    /// before the response for `waitSignal`, so use one `arena` for the calls and the waits.
    /// The request and the response together have the time limit of the connection.
    pub fn call(self: *Connection, arena: Allocator, c: Call) Error!Message {
        return within(self.io, deadline(self.io, self.timeout), callNow, .{ self, arena, c });
    }

    fn callNow(self: *Connection, arena: Allocator, c: Call) Error!Message {
        const serial = try self.sendNow(c);
        while (true) {
            const m = try self.takeMessage(arena);
            switch (m.kind) {
                .method_return, .error_reply => if (m.reply_serial == serial) {
                    if (m.kind == .method_return) return m;
                    if (self.error_name) |n| self.gpa.free(n);
                    self.error_name = null;
                    self.error_name = try self.gpa.dupe(u8, m.error_name orelse "");
                    log.debug("{s} failed: {s}", .{ c.member, m.error_name orelse "" });
                    return error.CallFailed;
                },
                .signal => try self.signals.append(self.gpa, m),
                else => {},
            }
        }
    }

    /// Wait for a signal with the object path, the interface and the member. `timeout` is the
    /// time limit of the wait, and null waits without a limit. A signal can come from an action
    /// of the user, thus the wait does not use the time limit of the connection.
    pub fn waitSignal(self: *Connection, arena: Allocator, path: []const u8, interface: []const u8, member: []const u8, timeout: ?Io.Duration) Error!Message {
        for (self.signals.items, 0..) |m, i| if (signalMatches(m, path, interface, member)) {
            _ = self.signals.orderedRemove(i);
            return m;
        };
        return within(self.io, deadline(self.io, timeout), waitSignalNow, .{ self, arena, path, interface, member });
    }

    fn waitSignalNow(self: *Connection, arena: Allocator, path: []const u8, interface: []const u8, member: []const u8) Error!Message {
        while (true) {
            const m = try self.takeMessage(arena);
            if (m.kind == .signal and signalMatches(m, path, interface, member)) return m;
        }
    }
};

fn signalMatches(m: Message, path: []const u8, interface: []const u8, member: []const u8) bool {
    return std.mem.eql(u8, m.path orelse "", path) and std.mem.eql(u8, m.interface orelse "", interface) and std.mem.eql(u8, m.member orelse "", member);
}

/// The end of the time limit `timeout` from now, or null for no limit.
fn deadline(io: Io, timeout: ?Io.Duration) ?Io.Clock.Timestamp {
    const t = timeout orelse return null;
    return .fromNow(io, .{ .raw = t, .clock = .awake });
}

/// True after the first wait that has no limit because `io` cannot run a task concurrently.
var unlimited_wait_logged: std.atomic.Value(bool) = .init(false);

/// Run `function` with `args` and stop it at `end`. A null `end` runs the function on this
/// task without a limit. Else the function runs in its own task, and at `end` that task gets
/// a cancel. The function can stop in the middle of a message, thus the connection is not
/// usable after `error.Timeout`.
///
/// A cancel stops a blocked read on each system. On Windows, a shutdown of the socket does not
/// stop a blocked read. Also, a read on a Unix socket can stay blocked there after the peer
/// closes the connection.
///
/// When `io` cannot run a task concurrently, the function runs on this task without a limit.
/// The first time, the client writes a message about it to the log.
fn within(io: Io, end: ?Io.Clock.Timestamp, comptime function: anytype, args: anytype) @typeInfo(@TypeOf(function)).@"fn".return_type.? {
    const limit = end orelse return @call(.auto, function, args);
    const Args = @TypeOf(args);
    const Result = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
    const Task = struct {
        args: Args,
        result: Result = error.Canceled,
        done: Io.Event = .unset,

        fn run(t: *@This(), task_io: Io) void {
            t.result = @call(.auto, function, t.args);
            t.done.set(task_io);
        }
    };
    var task: Task = .{ .args = args };
    var future = io.concurrent(Task.run, .{ &task, io }) catch {
        if (!unlimited_wait_logged.swap(true, .monotonic)) {
            log.info("the Io cannot run a task concurrently, thus the D-Bus client waits without a time limit", .{});
        }
        return @call(.auto, function, args);
    };
    while (!task.done.isSet()) {
        task.done.waitTimeout(io, .{ .deadline = limit }) catch |e| switch (e) {
            // The wait can also end before the deadline.
            error.Timeout => if (Io.Clock.Timestamp.now(io, limit.clock).compare(.gte, limit)) break,
            error.Canceled => {
                future.cancel(io);
                // The function can end at the same time as the cancel. Then keep its result,
                // for example a socket that the caller must close, and give the cancel again to
                // the next cancelation point of this task.
                const value = task.result catch return error.Canceled;
                io.recancel();
                return value;
            },
        };
    }
    if (task.done.isSet()) {
        future.await(io);
        return task.result;
    }
    future.cancel(io);
    // The function can end at the same time as the cancel.
    if (task.result) |v| return v else |e| if (e != error.Canceled) return e;
    log.debug("the bus did not answer in the time limit", .{});
    return error.Timeout;
}

/// Connect to `address`. A connect to a path stops at the cancel of `within`. A connect to an
/// abstract name also stops at `end` by itself.
fn connect(io: Io, address: Address, end: ?Io.Clock.Timestamp) Error!Io.net.Stream {
    switch (address) {
        .path => |p| {
            if (!Io.net.has_unix_sockets) return error.UnsupportedAddress;
            const ua = Io.net.UnixAddress.init(p) catch return error.ConnectFailed;
            return ua.connect(io) catch |e| switch (e) {
                error.Canceled => error.Canceled,
                else => {
                    log.debug("could not connect to the bus at {s}: {t}", .{ p, e });
                    return error.ConnectFailed;
                },
            };
        },
        .abstract => |name| return connectAbstract(io, name, end),
    }
}

/// The longest pause between two tries of `connectAbstract`.
const max_connect_pause: Io.Duration = .fromMilliseconds(100);

/// The std library adds a zero byte to the end of each Unix socket path, which is wrong for an
/// abstract name. Thus this function connects with the system calls of Linux.
///
/// The connect does not block. While the queue of the listener is full, the function tries
/// again after a pause, until `end`. Linux gives no event when such a queue gets free space.
/// A cancel stops the pause.
fn connectAbstract(io: Io, name: []const u8, end: ?Io.Clock.Timestamp) Error!Io.net.Stream {
    if (builtin.os.tag != .linux) return error.UnsupportedAddress;
    const linux = std.os.linux;
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (name.len + 1 > addr.path.len) return error.ConnectFailed;
    @memcpy(addr.path[1..][0..name.len], name);
    const len: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + 1 + name.len);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return error.ConnectFailed;
    const fd: linux.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);
    var pause: Io.Duration = .fromMilliseconds(1);
    while (true) switch (linux.errno(linux.connect(fd, &addr, len))) {
        .SUCCESS => break,
        .INTR => try io.checkCancel(),
        // The queue of the listener is full.
        .AGAIN => {
            try pauseUntil(io, end, pause);
            pause = .fromNanoseconds(@min(2 * pause.nanoseconds, max_connect_pause.nanoseconds));
        },
        else => |e| {
            log.debug("could not connect to the bus at the abstract name {s}: errno {d}", .{ name, @intFromEnum(e) });
            return error.ConnectFailed;
        },
    };
    // The reader and the writer of the stream need a socket that blocks.
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return error.ConnectFailed;
    var o: linux.O = @bitCast(@as(u32, @truncate(flags)));
    o.NONBLOCK = false;
    if (linux.errno(linux.fcntl(fd, linux.F.SETFL, @as(u32, @bitCast(o)))) != .SUCCESS) return error.ConnectFailed;
    return .{ .socket = .{ .handle = fd, .address = .{ .ip4 = .loopback(0) } } };
}

/// Sleep for `pause`, but not past `end`. When `end` is already past, the function gives
/// `error.Timeout` at once. A null `end` has no limit.
fn pauseUntil(io: Io, end: ?Io.Clock.Timestamp, pause: Io.Duration) Error!void {
    const wake: Io.Clock.Timestamp = .fromNow(io, .{ .raw = pause, .clock = .awake });
    const limit = end orelse return wake.wait(io);
    if (Io.Clock.Timestamp.now(io, limit.clock).compare(.gte, limit)) return error.Timeout;
    return if (wake.compare(.lt, limit)) wake.wait(io) else limit.wait(io);
}

/// The effective user ID of the process as decimal digits in `buf`. Windows has no user ID.
pub fn userId(buf: *[16]u8) []const u8 {
    const uid: u32 = switch (builtin.os.tag) {
        .linux => std.os.linux.geteuid(),
        .windows => 0,
        else => std.c.geteuid(),
    };
    return std.fmt.bufPrint(buf, "{d}", .{uid}) catch unreachable;
}

test "address parsing" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("/run/user/1000/bus", (try parseAddress(arena, "unix:path=/run/user/1000/bus")).path);
    try std.testing.expectEqualStrings("/tmp/dbus-AbC", (try parseAddress(arena, "unix:abstract=/tmp/dbus-AbC,guid=0123")).abstract);
    try std.testing.expectEqualStrings("/a b/bus", (try parseAddress(arena, "tcp:host=localhost,port=1;unix:guid=1,path=%2fa%20b/bus")).path);
    try std.testing.expectError(error.UnsupportedAddress, parseAddress(arena, "tcp:host=localhost,port=1"));
    try std.testing.expectError(error.UnsupportedAddress, parseAddress(arena, "unix:tmpdir=/tmp"));
    try std.testing.expectError(error.UnsupportedAddress, parseAddress(arena, "unix:path=%2"));
    try std.testing.expectError(error.UnsupportedAddress, parseAddress(arena, ""));
}

test "marshalling round trip and alignment" {
    const gpa = std.testing.allocator;
    var e: Encoder = .{ .gpa = gpa };
    defer e.deinit();
    try e.byte(7);
    try e.string("abc");
    try e.string("/o");
    try e.signature("a{sv}");
    try e.boolean(true);
    try e.bytes(&.{ 1, 2, 3 });
    try e.stringDict(&.{ .{ "k1", "v1" }, .{ "k2", "v2" } });
    // A variant with an `a{ss}` value, then a struct `(oayays)`.
    try e.signature("a{ss}");
    try e.stringDict(&.{.{ "x", "y" }});
    try e.beginStruct();
    try e.string("/s");
    try e.bytes("");
    try e.bytes("secret");
    try e.string("text/plain");

    // The first values in the wire format: a byte, padding, a length and the text with a zero.
    try std.testing.expectEqualSlices(u8, &.{ 7, 0, 0, 0, 3, 0, 0, 0, 'a', 'b', 'c', 0 }, e.written()[0..12]);

    var d: Decoder = .{ .data = e.written() };
    try std.testing.expectEqual(7, try d.byte());
    try std.testing.expectEqualStrings("abc", try d.string());
    try std.testing.expectEqualStrings("/o", try d.string());
    try std.testing.expectEqualStrings("a{sv}", try d.signature());
    try std.testing.expect(try d.boolean());
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, try d.bytes());
    const end = try d.beginArray(8);
    try std.testing.expectEqual(0, d.pos % 8);
    try d.beginStruct();
    try std.testing.expectEqualStrings("k1", try d.string());
    try std.testing.expectEqualStrings("v1", try d.string());
    try d.beginStruct();
    try std.testing.expectEqualStrings("k2", try d.string());
    try std.testing.expectEqualStrings("v2", try d.string());
    try std.testing.expectEqual(end, d.pos);
    const inner = try d.signature();
    try d.skip(inner);
    try d.skip("(oayays)");
    try std.testing.expect(d.atEnd());

    // `skip` walks the same values as the reads above.
    var s: Decoder = .{ .data = e.written() };
    try s.skip("y");
    try s.skip("s");
    try s.skip("o");
    try s.skip("g");
    try s.skip("b");
    try s.skip("ay");
    try s.skip("a{ss}");
    try s.skip("v");
    try s.skip("(oayays)");
    try std.testing.expect(s.atEnd());

    try std.testing.expectEqual(5, try completeTypeLen("a{sv}u"));
    try std.testing.expectEqual(8, try completeTypeLen("(oayays)"));
    try std.testing.expectError(error.ProtocolError, completeTypeLen("(s"));
    var bad: Decoder = .{ .data = &.{ 9, 0, 0, 0, 1, 2 } };
    try std.testing.expectError(error.ProtocolError, bad.string());
}

test "a message survives a write and a read" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var body: Encoder = .{ .gpa = gpa };
    defer body.deinit();
    try body.string("plain");
    try body.signature("s");
    try body.string("");
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try writeMessage(gpa, &out.writer, 5, .{
        .path = "/org/freedesktop/secrets",
        .interface = "org.freedesktop.Secret.Service",
        .member = "OpenSession",
        .destination = "org.freedesktop.secrets",
        .signature = "sv",
        .body = body.written(),
    });
    try std.testing.expectEqual(0, (out.written().len - body.written().len) % 8);
    var r: Io.Reader = .fixed(out.written());
    const m = try readMessage(arena_state.allocator(), &r);
    try std.testing.expectEqual(Kind.method_call, m.kind);
    try std.testing.expectEqual(5, m.serial);
    try std.testing.expectEqualStrings("OpenSession", m.member.?);
    try std.testing.expectEqualStrings("org.freedesktop.secrets", m.destination.?);
    try std.testing.expectEqualStrings("sv", m.signature);
    var d = m.decoder();
    try std.testing.expectEqualStrings("plain", try d.string());
    try d.skip("v");
    try std.testing.expect(d.atEnd());

    // A big-endian message with a reply serial and two unknown header fields.
    const be = [_]u8{
        'B', 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 21, //
        5, 1, 'u', 0, 0, 0, 0, 3, //
        99, 1, 'y', 0, 42, 0, 0, 0, //
        98, 1, 'y', 0, 1,  0, 0, 0,
    };
    var r2: Io.Reader = .fixed(&be);
    const reply = try readMessage(arena_state.allocator(), &r2);
    try std.testing.expectEqual(Kind.method_return, reply.kind);
    try std.testing.expectEqual(9, reply.serial);
    try std.testing.expectEqual(3, reply.reply_serial.?);
}

test "d-bus client stops a wait and a pause of the connect at the deadline" {
    const io = std.testing.io;
    const Wait = struct {
        fn forever(event: *Io.Event, task_io: Io) Error!u32 {
            try event.wait(task_io);
            return 1;
        }

        fn atOnce(value: u32) Error!u32 {
            return value;
        }
    };
    const limit: Io.Duration = .fromMilliseconds(100);
    const long: Io.Duration = .fromSeconds(5);
    var never: Io.Event = .unset;
    var start: Io.Clock.Timestamp = .now(io, .awake);
    try std.testing.expectError(error.Timeout, within(io, deadline(io, limit), Wait.forever, .{ &never, io }));
    try std.testing.expect(start.untilNow(io).raw.nanoseconds >= limit.nanoseconds);
    try std.testing.expectEqual(7, try within(io, deadline(io, long), Wait.atOnce, .{7}));
    try std.testing.expectEqual(7, try within(io, null, Wait.atOnce, .{7}));

    // Without concurrency, the function runs on this task without a limit, and the client
    // writes a message to the log. Another test can set the flag first, thus clear it.
    var single: Io.Threaded = .init_single_threaded;
    unlimited_wait_logged.store(false, .monotonic);
    try std.testing.expectEqual(7, try within(single.io(), deadline(io, limit), Wait.atOnce, .{7}));
    try std.testing.expect(unlimited_wait_logged.load(.monotonic));

    // A pause of the connect to an abstract name stops at the deadline. After the deadline, it
    // gives `error.Timeout` at once.
    start = .now(io, .awake);
    const end = deadline(io, limit);
    while (true) {
        pauseUntil(io, end, long) catch |e| {
            try std.testing.expectEqual(error.Timeout, e);
            break;
        };
    }
    const waited = start.untilNow(io).raw.nanoseconds;
    try std.testing.expect(waited >= limit.nanoseconds and waited < long.nanoseconds);
    try pauseUntil(io, null, .fromMilliseconds(1));
}

test "d-bus client gives a cancel of the caller through a wait with a deadline" {
    const io = std.testing.io;
    const long: Io.Duration = .fromSeconds(5);
    const Wait = struct {
        // Set `started`, then wait for `event`.
        fn forever(started: *Io.Event, event: *Io.Event, task_io: Io) Error!u32 {
            started.set(task_io);
            try event.wait(task_io);
            return 1;
        }

        // Set `started`, then wait for `event` without a cancelation point.
        fn uncancelable(started: *Io.Event, event: *Io.Event, task_io: Io) Error!u32 {
            started.set(task_io);
            event.waitUncancelable(task_io);
            return 7;
        }

        fn callForever(started: *Io.Event, event: *Io.Event, task_io: Io, limit: Io.Duration) Error!u32 {
            return within(task_io, deadline(task_io, limit), forever, .{ started, event, task_io });
        }

        // Also record whether the next cancelation point after `within` gives the cancel.
        fn callUncancelable(started: *Io.Event, event: *Io.Event, task_io: Io, limit: Io.Duration, canceled_again: *bool) Error!u32 {
            const value = within(task_io, deadline(task_io, limit), uncancelable, .{ started, event, task_io });
            task_io.checkCancel() catch {
                canceled_again.* = true;
            };
            return value;
        }

        fn setAfter(event: *Io.Event, task_io: Io, pause: Io.Duration) void {
            task_io.sleep(pause, .awake) catch {};
            event.set(task_io);
        }
    };

    // A cancel of the caller before the deadline gives `error.Canceled`, not `error.Timeout`.
    var started: Io.Event = .unset;
    var never: Io.Event = .unset;
    const start: Io.Clock.Timestamp = .now(io, .awake);
    var caller = try io.concurrent(Wait.callForever, .{ &started, &never, io, long });
    defer _ = caller.cancel(io) catch 0;
    try started.wait(io);
    try std.testing.expectError(error.Canceled, caller.cancel(io));
    try std.testing.expect(start.untilNow(io).raw.nanoseconds < long.nanoseconds);

    // The function ends after the cancel of the caller. Then `within` keeps the result, for
    // example a socket that the caller must close, and gives the cancel again to the caller.
    var started_again: Io.Event = .unset;
    var free: Io.Event = .unset;
    var canceled_again = false;
    var uncancelable_caller = try io.concurrent(Wait.callUncancelable, .{ &started_again, &free, io, long, &canceled_again });
    defer {
        free.set(io);
        _ = uncancelable_caller.cancel(io) catch 0;
    }
    try started_again.wait(io);
    // The pause is long, thus the cancel comes before the function ends.
    var setter = try io.concurrent(Wait.setAfter, .{ &free, io, Io.Duration.fromMilliseconds(250) });
    defer setter.await(io);
    try std.testing.expectEqual(7, try uncancelable_caller.cancel(io));
    try std.testing.expect(canceled_again);
}
