//! The framing of RFC 6455 for the WebSocket transport in `websocket.zig`. It has the frame
//! headers, the mask, the close codes and the accept key of the handshake. Its reader joins
//! the fragments of a message.
//!
//! The reader obeys the rules of RFC 6455 section 5. It refuses the reserved bits, because
//! the transport negotiates no extension. It refuses unknown opcodes. It refuses a control
//! frame with more than 125 bytes or without the `FIN` bit. It refuses a length that does not
//! use the minimum number of bytes. A frame of a client must have a mask, and a frame of a
//! server must not.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// The value that RFC 6455 section 1.3 appends to the key of the client for the accept key.
pub const accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The length of `Sec-WebSocket-Key`: 16 random bytes in base64.
pub const key_len = 24;
/// The length of `Sec-WebSocket-Accept`: a SHA-1 digest in base64.
pub const accept_len = 28;
/// The largest payload of a control frame.
pub const max_control_payload = 125;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    /// True for close, ping and pong, and for the reserved control opcodes.
    pub fn isControl(op: Opcode) bool {
        return @intFromEnum(op) & 0x8 != 0;
    }

    /// True for the opcodes that RFC 6455 defines.
    pub fn isKnown(op: Opcode) bool {
        return switch (op) {
            .continuation, .text, .binary, .close, .ping, .pong => true,
            _ => false,
        };
    }
};

/// The status codes of a close frame (RFC 6455 section 7.4.1).
pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    /// Only for the API: a close frame without a code. It never goes on the wire.
    no_status = 1005,
    /// Only for the API: the connection ended without a close frame.
    abnormal = 1006,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
    _,
};

/// True when a peer can send `code` in a close frame. The codes 1004, 1005, 1006 and 1015
/// and the codes outside the defined ranges give false.
pub fn validCloseCode(code: u16) bool {
    return switch (code) {
        1000...1003, 1007...1014, 3000...4999 => true,
        else => false,
    };
}

/// The `Sec-WebSocket-Accept` value for the key of a client: the SHA-1 digest of the key
/// and `accept_guid`, in base64.
pub fn acceptKey(key: []const u8) [accept_len]u8 {
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(key);
    sha1.update(accept_guid);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    var out: [accept_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

/// True when `key` is base64 text of exactly 16 bytes, as RFC 6455 section 4.1 requires.
pub fn validKey(key: []const u8) bool {
    if (key.len != key_len) return false;
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(key) catch return false;
    if (size != 16) return false;
    var raw: [16]u8 = undefined;
    decoder.decode(&raw, key) catch return false;
    return true;
}

/// A new random key for the upgrade request of a client.
pub fn newKey(io: Io) error{EntropyUnavailable}![key_len]u8 {
    var raw: [16]u8 = undefined;
    io.randomSecure(&raw) catch return error.EntropyUnavailable;
    var out: [key_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &raw);
    return out;
}

/// True when the comma-separated header value `value` has `token`. The comparison ignores
/// case and the spaces around each item.
pub fn headerHasToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |item| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, item, " \t"), token)) return true;
    }
    return false;
}

/// XOR `bytes` with the mask. `offset` is the position of `bytes[0]` in the payload.
pub fn applyMask(mask: [4]u8, offset: usize, bytes: []u8) void {
    for (bytes, 0..) |*b, i| b.* ^= mask[(offset + i) % 4];
}

/// Masks for the frames of a client. RFC 6455 section 10.3 requires a new mask for each frame
/// that the server cannot predict. A ChaCha20 generator with a seed from the random source of
/// the system makes them.
pub const MaskSource = struct {
    csprng: std.Random.DefaultCsprng,

    pub fn init(io: Io) error{EntropyUnavailable}!MaskSource {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        io.randomSecure(&seed) catch return error.EntropyUnavailable;
        defer std.crypto.secureZero(u8, &seed);
        return .{ .csprng = .init(seed) };
    }

    pub fn next(self: *MaskSource) [4]u8 {
        var mask: [4]u8 = undefined;
        self.csprng.fill(&mask);
        return mask;
    }
};

/// Write the header of one frame. `mask` is the mask of a client frame, or null for a frame
/// of a server.
pub fn writeHeader(w: *Io.Writer, fin: bool, opcode: Opcode, len: u64, mask: ?[4]u8) Io.Writer.Error!void {
    var buf: [14]u8 = undefined;
    buf[0] = @as(u8, if (fin) 0x80 else 0) | @as(u8, @intFromEnum(opcode));
    const mask_bit: u8 = if (mask != null) 0x80 else 0;
    var n: usize = 2;
    if (len < 126) {
        buf[1] = mask_bit | @as(u8, @intCast(len));
    } else if (len <= 0xffff) {
        buf[1] = mask_bit | 126;
        std.mem.writeInt(u16, buf[2..4], @intCast(len), .big);
        n = 4;
    } else {
        buf[1] = mask_bit | 127;
        std.mem.writeInt(u64, buf[2..10], len, .big);
        n = 10;
    }
    if (mask) |m| {
        @memcpy(buf[n..][0..4], &m);
        n += 4;
    }
    try w.writeAll(buf[0..n]);
}

/// Write one frame with its payload. With a mask, the function writes a masked copy, so
/// `payload` does not change.
pub fn writeFrame(w: *Io.Writer, fin: bool, opcode: Opcode, payload: []const u8, mask: ?[4]u8) Io.Writer.Error!void {
    try writeHeader(w, fin, opcode, payload.len, mask);
    const m = mask orelse return w.writeAll(payload);
    var chunk: [4096]u8 = undefined;
    var i: usize = 0;
    while (i < payload.len) {
        const n = @min(chunk.len, payload.len - i);
        @memcpy(chunk[0..n], payload[i..][0..n]);
        applyMask(m, i, chunk[0..n]);
        try w.writeAll(chunk[0..n]);
        i += n;
    }
}

/// The payload of a close frame: the code and the reason. The function cuts a long reason at
/// a character boundary, so that the payload has at most 125 bytes.
pub fn closePayload(buf: *[max_control_payload]u8, code: CloseCode, reason: []const u8) []const u8 {
    std.mem.writeInt(u16, buf[0..2], @intFromEnum(code), .big);
    var len = @min(reason.len, max_control_payload - 2);
    while (len > 0 and len < reason.len and reason[len] & 0xc0 == 0x80) len -= 1;
    @memcpy(buf[2..][0..len], reason[0..len]);
    return buf[0 .. 2 + len];
}

/// One frame header as it is on the wire.
pub const Header = struct {
    fin: bool,
    opcode: Opcode,
    mask: ?[4]u8,
    len: u64,
};

pub const ReadError = error{
    /// The peer broke a rule of RFC 6455. The answer is the close code 1002.
    ProtocolError,
    /// A binary message. The binding carries text only. The answer is the close code 1003.
    UnsupportedData,
    /// A text message or a close reason is not valid UTF-8. The answer is the close code 1007.
    InvalidPayload,
    /// A frame or a message is larger than its limit. The answer is the close code 1009.
    MessageTooBig,
    EndOfStream,
    ReadFailed,
    OutOfMemory,
};

/// The close code that answers a read error, or null when the connection is gone.
pub fn closeCodeFor(err: ReadError) ?CloseCode {
    return switch (err) {
        error.ProtocolError => .protocol_error,
        error.UnsupportedData => .unsupported_data,
        error.InvalidPayload => .invalid_payload,
        error.MessageTooBig => .message_too_big,
        error.OutOfMemory => .internal_error,
        error.EndOfStream, error.ReadFailed => null,
    };
}

/// Read one frame header. The function checks the rules that apply to the two roles: the
/// reserved bits, the opcode, the control frames and the length encoding.
pub fn readHeader(in: *Io.Reader) ReadError!Header {
    const first = try in.takeArray(2);
    const b0 = first[0];
    const b1 = first[1];
    if (b0 & 0x70 != 0) return error.ProtocolError;
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0)));
    if (!opcode.isKnown()) return error.ProtocolError;
    const fin = b0 & 0x80 != 0;
    const masked = b1 & 0x80 != 0;
    var len: u64 = b1 & 0x7f;
    if (len == 126) {
        len = try in.takeInt(u16, .big);
        if (len < 126) return error.ProtocolError;
    } else if (len == 127) {
        len = try in.takeInt(u64, .big);
        if (len >> 63 != 0 or len <= 0xffff) return error.ProtocolError;
    }
    if (opcode.isControl() and (!fin or len > max_control_payload)) return error.ProtocolError;
    const mask: ?[4]u8 = if (masked) (try in.takeArray(4)).* else null;
    return .{ .fin = fin, .opcode = opcode, .mask = mask, .len = len };
}

/// The role of the endpoint that reads.
pub const Role = enum {
    /// The server reads the frames of a client. Each frame must have a mask.
    server,
    /// The client reads the frames of a server. No frame can have a mask.
    client,
};

/// A close frame of the peer.
pub const Close = struct {
    /// Null for a close frame without a payload.
    code: ?u16,
    reason: []const u8,
};

/// What `Reader.next` gives. The slices stay valid until the next call.
pub const Event = union(enum) {
    /// A complete text message, valid UTF-8.
    text: []const u8,
    ping: []const u8,
    pong: []const u8,
    close: Close,
};

/// Reads frames, joins the fragments of a message and checks the rules of the role. Control
/// frames between the fragments of a message come out at once.
pub const Reader = struct {
    in: *Io.Reader,
    gpa: Allocator,
    role: Role,
    max_frame_bytes: u64,
    max_message_bytes: usize,
    /// When set, each frame header stores the time of the awake clock here, in nanoseconds.
    activity: ?*std.atomic.Value(i64) = null,
    io: ?Io = null,
    message: std.ArrayList(u8) = .empty,
    /// The opcode of the message whose fragments arrive, or null between messages.
    fragmented: ?Opcode = null,
    /// True when `message` holds a message that `next` gave out.
    complete: bool = false,
    /// After `error.MessageTooBig` or `error.UnsupportedData`: the payload bytes of the frame
    /// that the reader did not read. `lingerUntilClose` discards them.
    unread: u64 = 0,
    control: [max_control_payload]u8 = undefined,

    pub fn deinit(self: *Reader) void {
        self.message.deinit(self.gpa);
    }

    /// Read until the next complete message or control frame.
    pub fn next(self: *Reader) ReadError!Event {
        if (self.complete) {
            self.message.clearRetainingCapacity();
            self.complete = false;
        }
        while (true) {
            const h = try readHeader(self.in);
            if (self.activity) |a| if (self.io) |io| a.store(nowNanoseconds(io), .release);
            switch (self.role) {
                .server => if (h.mask == null) return error.ProtocolError,
                .client => if (h.mask != null) return error.ProtocolError,
            }
            if (h.opcode.isControl()) {
                const payload = self.control[0..@intCast(h.len)];
                try readPayload(self.in, payload, h.mask);
                switch (h.opcode) {
                    .ping => return .{ .ping = payload },
                    .pong => return .{ .pong = payload },
                    .close => return .{ .close = try parseClose(payload) },
                    else => unreachable,
                }
            }
            switch (h.opcode) {
                .text, .binary => {
                    if (self.fragmented != null) return error.ProtocolError;
                    if (h.opcode == .binary) {
                        self.unread = h.len;
                        return error.UnsupportedData;
                    }
                    if (!h.fin) self.fragmented = h.opcode;
                },
                .continuation => if (self.fragmented == null) return error.ProtocolError,
                else => unreachable,
            }
            if (h.len > self.max_frame_bytes or h.len > self.max_message_bytes - self.message.items.len) {
                self.unread = h.len;
                return error.MessageTooBig;
            }
            const dest = try self.message.addManyAsSlice(self.gpa, @intCast(h.len));
            try readPayload(self.in, dest, h.mask);
            if (!h.fin) continue;
            self.fragmented = null;
            self.complete = true;
            if (!std.unicode.utf8ValidateSlice(self.message.items)) return error.InvalidPayload;
            return .{ .text = self.message.items };
        }
    }
};

/// Use this function after the close frame of this side. It reads until the close frame of
/// the peer or the end of the connection, and it discards the other frames. `unread` is
/// `Reader.unread`. After a header that is not valid, the function discards the bytes until
/// the end of the connection. The caller limits the time.
pub fn lingerUntilClose(in: *Io.Reader, unread: u64) void {
    in.discardAll64(unread) catch return;
    while (true) {
        const h = readHeader(in) catch |e| switch (e) {
            error.ProtocolError => {
                _ = in.discardRemaining() catch {};
                return;
            },
            else => return,
        };
        in.discardAll64(h.len) catch return;
        if (h.opcode == .close) return;
    }
}

fn readPayload(in: *Io.Reader, dest: []u8, mask: ?[4]u8) ReadError!void {
    try in.readSliceAll(dest);
    if (mask) |m| applyMask(m, 0, dest);
}

/// Check the payload of a close frame (RFC 6455 section 5.5.1 and 7.4).
pub fn parseClose(payload: []const u8) ReadError!Close {
    if (payload.len == 0) return .{ .code = null, .reason = "" };
    if (payload.len == 1) return error.ProtocolError;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!validCloseCode(code)) return error.ProtocolError;
    const reason = payload[2..];
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidPayload;
    return .{ .code = code, .reason = reason };
}

/// The time of the awake clock in nanoseconds, for the idle and ping timers.
pub fn nowNanoseconds(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
}

// -- Tests ----------------------------------------------------------------------------------------

const testing = std.testing;

test "the accept key of RFC 6455 section 1.3" {
    const accept = acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
    try testing.expect(validKey("dGhlIHNhbXBsZSBub25jZQ=="));
    // A key of another length, or text that is not base64, is not valid.
    try testing.expect(!validKey("dGhlIHNhbXBsZSBub25jZQ"));
    try testing.expect(!validKey("dGhlIHNhbXBsZSBub25jZQ=x"));
    try testing.expect(!validKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    const key = try newKey(testing.io);
    try testing.expect(validKey(&key));
}

test "header tokens ignore case and spaces" {
    try testing.expect(headerHasToken("keep-alive, Upgrade", "upgrade"));
    try testing.expect(headerHasToken("chat,  mcp ", "mcp"));
    try testing.expect(!headerHasToken("mcp-v2", "mcp"));
    try testing.expect(!headerHasToken("", "mcp"));
}

/// A reader of `bytes` in the role `role` with large limits.
fn testReader(in: *Io.Reader, role: Role) Reader {
    return .{ .in = in, .gpa = testing.allocator, .role = role, .max_frame_bytes = 1 << 20, .max_message_bytes = 1 << 20 };
}

test "RFC 6455 section 5.7: a single-frame unmasked text message" {
    const bytes = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var in: Io.Reader = .fixed(&bytes);
    var r = testReader(&in, .client);
    defer r.deinit();
    try testing.expectEqualStrings("Hello", (try r.next()).text);
    try testing.expectError(error.EndOfStream, r.next());
    // A server refuses the same frame, because it has no mask.
    var in2: Io.Reader = .fixed(&bytes);
    var s = testReader(&in2, .server);
    defer s.deinit();
    try testing.expectError(error.ProtocolError, s.next());
    // The writer gives the same bytes.
    var buf: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeFrame(&w, true, .text, "Hello", null);
    try testing.expectEqualSlices(u8, &bytes, w.buffered());
}

test "RFC 6455 section 5.7: a single-frame masked text message" {
    const bytes = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var in: Io.Reader = .fixed(&bytes);
    var r = testReader(&in, .server);
    defer r.deinit();
    try testing.expectEqualStrings("Hello", (try r.next()).text);
    // A client refuses a masked frame of a server.
    var in2: Io.Reader = .fixed(&bytes);
    var c = testReader(&in2, .client);
    defer c.deinit();
    try testing.expectError(error.ProtocolError, c.next());
    var buf: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeFrame(&w, true, .text, "Hello", .{ 0x37, 0xfa, 0x21, 0x3d });
    try testing.expectEqualSlices(u8, &bytes, w.buffered());
}

test "RFC 6455 section 5.7: a fragmented unmasked text message" {
    const bytes = [_]u8{ 0x01, 0x03, 0x48, 0x65, 0x6c, 0x80, 0x02, 0x6c, 0x6f };
    var in: Io.Reader = .fixed(&bytes);
    var r = testReader(&in, .client);
    defer r.deinit();
    try testing.expectEqualStrings("Hello", (try r.next()).text);
    var buf: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeFrame(&w, false, .text, "Hel", null);
    try writeFrame(&w, true, .continuation, "lo", null);
    try testing.expectEqualSlices(u8, &bytes, w.buffered());
}

test "RFC 6455 section 5.7: an unmasked ping and a masked pong" {
    const ping = [_]u8{ 0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var in: Io.Reader = .fixed(&ping);
    var r = testReader(&in, .client);
    defer r.deinit();
    try testing.expectEqualStrings("Hello", (try r.next()).ping);
    const pong = [_]u8{ 0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var in2: Io.Reader = .fixed(&pong);
    var s = testReader(&in2, .server);
    defer s.deinit();
    try testing.expectEqualStrings("Hello", (try s.next()).pong);
    var buf: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeFrame(&w, true, .pong, "Hello", .{ 0x37, 0xfa, 0x21, 0x3d });
    try testing.expectEqualSlices(u8, &pong, w.buffered());
}

test "RFC 6455 section 5.7: 256 bytes and 64 KiB in a single unmasked frame" {
    // The binary examples: the header encodes the length in 16 and in 64 bits.
    const short = [_]u8{ 0x82, 0x7E, 0x01, 0x00 };
    var in: Io.Reader = .fixed(&short);
    const h1 = try readHeader(&in);
    try testing.expectEqual(Opcode.binary, h1.opcode);
    try testing.expectEqual(256, h1.len);
    try testing.expect(h1.fin and h1.mask == null);
    const long = [_]u8{ 0x82, 0x7F, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00 };
    var in2: Io.Reader = .fixed(&long);
    const h2 = try readHeader(&in2);
    try testing.expectEqual(65536, h2.len);
    var buf: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeHeader(&w, true, .binary, 256, null);
    try testing.expectEqualSlices(u8, &short, w.buffered());
    w = .fixed(&buf);
    try writeHeader(&w, true, .binary, 65536, null);
    try testing.expectEqualSlices(u8, &long, w.buffered());

    // The binding carries text only: the reader refuses a binary message.
    var bin_in: Io.Reader = .fixed(&short);
    var r = testReader(&bin_in, .client);
    defer r.deinit();
    try testing.expectError(error.UnsupportedData, r.next());

    // The same lengths as text messages come through whole.
    const gpa = testing.allocator;
    for ([_]usize{ 256, 65536 }) |n| {
        var aw: Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        const payload = try gpa.alloc(u8, n);
        defer gpa.free(payload);
        @memset(payload, 'a');
        try writeFrame(&aw.writer, true, .text, payload, null);
        var text_in: Io.Reader = .fixed(aw.written());
        var tr = testReader(&text_in, .client);
        defer tr.deinit();
        try testing.expectEqual(n, (try tr.next()).text.len);
    }
}

test "a control frame between fragments comes out at once" {
    const bytes = [_]u8{ 0x01, 0x03, 0x48, 0x65, 0x6c, 0x89, 0x00, 0x80, 0x02, 0x6c, 0x6f };
    var in: Io.Reader = .fixed(&bytes);
    var r = testReader(&in, .client);
    defer r.deinit();
    try testing.expectEqualStrings("", (try r.next()).ping);
    try testing.expectEqualStrings("Hello", (try r.next()).text);
}

/// The error of the first event of `bytes` for a reader in the role `role`.
fn expectReadError(expected: ReadError, role: Role, bytes: []const u8) !void {
    var in: Io.Reader = .fixed(bytes);
    var r = testReader(&in, role);
    defer r.deinit();
    while (true) {
        _ = r.next() catch |e| return testing.expectEqual(expected, e);
    }
}

test "protocol violations give the right errors" {
    // A reserved bit without an extension.
    try expectReadError(error.ProtocolError, .client, &.{ 0xC1, 0x00 });
    // The reserved opcodes 3 and 0xB.
    try expectReadError(error.ProtocolError, .client, &.{ 0x83, 0x00 });
    try expectReadError(error.ProtocolError, .client, &.{ 0x8B, 0x00 });
    // A control frame without FIN, and one with 126 bytes.
    try expectReadError(error.ProtocolError, .client, &.{ 0x09, 0x00 });
    try expectReadError(error.ProtocolError, .client, &.{ 0x89, 0x7E, 0x00, 0x7E });
    // A continuation without a message, and a new message inside a fragmented one.
    try expectReadError(error.ProtocolError, .client, &.{ 0x80, 0x00 });
    try expectReadError(error.ProtocolError, .client, &.{ 0x01, 0x01, 'a', 0x81, 0x01, 'b' });
    // A length that does not use the minimum number of bytes, and a 64-bit length with the
    // most significant bit set.
    try expectReadError(error.ProtocolError, .client, &.{ 0x81, 0x7E, 0x00, 0x05 });
    try expectReadError(error.ProtocolError, .client, &.{ 0x81, 0x7F, 0, 0, 0, 0, 0, 0, 0xff, 0xff });
    try expectReadError(error.ProtocolError, .client, &.{ 0x81, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0 });
    // Invalid UTF-8 in a text message, also split across fragments, and a surrogate.
    try expectReadError(error.InvalidPayload, .client, &.{ 0x81, 0x02, 0xc3, 0x28 });
    try expectReadError(error.InvalidPayload, .client, &.{ 0x01, 0x01, 0xc3, 0x80, 0x01, 0x28 });
    try expectReadError(error.InvalidPayload, .client, &.{ 0x81, 0x03, 0xed, 0xa0, 0x80 });
    // A character split across two fragments is valid.
    var split_in: Io.Reader = .fixed(&.{ 0x01, 0x01, 0xc3, 0x80, 0x01, 0xa9 });
    var split = testReader(&split_in, .client);
    defer split.deinit();
    try testing.expectEqualStrings("é", (try split.next()).text);
    // Close frames: one byte, a code that is not valid, a reason that is not UTF-8.
    try expectReadError(error.ProtocolError, .client, &.{ 0x88, 0x01, 0x03 });
    try expectReadError(error.ProtocolError, .client, &.{ 0x88, 0x02, 0x03, 0xED });
    try expectReadError(error.ProtocolError, .client, &.{ 0x88, 0x02, 0x03, 0xEE });
    try expectReadError(error.InvalidPayload, .client, &.{ 0x88, 0x04, 0x03, 0xE8, 0xc3, 0x28 });
    try testing.expectEqual(CloseCode.protocol_error, closeCodeFor(error.ProtocolError).?);
    try testing.expectEqual(CloseCode.invalid_payload, closeCodeFor(error.InvalidPayload).?);
    try testing.expectEqual(CloseCode.message_too_big, closeCodeFor(error.MessageTooBig).?);
    try testing.expectEqual(CloseCode.unsupported_data, closeCodeFor(error.UnsupportedData).?);
    try testing.expect(closeCodeFor(error.EndOfStream) == null);
}

test "close frames carry a valid code and a reason" {
    var in: Io.Reader = .fixed(&.{ 0x88, 0x05, 0x03, 0xE9, 'b', 'y', 'e', 0x88, 0x00 });
    var r = testReader(&in, .client);
    defer r.deinit();
    const first = (try r.next()).close;
    try testing.expectEqual(1001, first.code.?);
    try testing.expectEqualStrings("bye", first.reason);
    try testing.expect((try r.next()).close.code == null);
    for ([_]u16{ 1000, 1003, 1007, 1011, 1014, 3000, 4999 }) |c| try testing.expect(validCloseCode(c));
    for ([_]u16{ 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000 }) |c| try testing.expect(!validCloseCode(c));
    // A long reason gets cut at a character boundary.
    var buf: [max_control_payload]u8 = undefined;
    const long = "é" ** 100;
    const payload = closePayload(&buf, .going_away, long);
    try testing.expect(payload.len <= max_control_payload);
    try testing.expect(std.unicode.utf8ValidateSlice(payload[2..]));
    try testing.expectEqual(1001, std.mem.readInt(u16, payload[0..2], .big));
}

test "limits of frames and messages" {
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeFrame(&aw.writer, true, .text, "x" ** 100, null);
    var in: Io.Reader = .fixed(aw.written());
    var r: Reader = .{ .in = &in, .gpa = testing.allocator, .role = .client, .max_frame_bytes = 99, .max_message_bytes = 1000 };
    defer r.deinit();
    try testing.expectError(error.MessageTooBig, r.next());
    // Two fragments of 60 bytes pass the frame limit but not a message limit of 100.
    aw.clearRetainingCapacity();
    try writeFrame(&aw.writer, false, .text, "x" ** 60, null);
    try writeFrame(&aw.writer, true, .continuation, "x" ** 60, null);
    var in2: Io.Reader = .fixed(aw.written());
    var r2: Reader = .{ .in = &in2, .gpa = testing.allocator, .role = .client, .max_frame_bytes = 99, .max_message_bytes = 100 };
    defer r2.deinit();
    try testing.expectError(error.MessageTooBig, r2.next());
}

test "masks differ between frames" {
    var source = try MaskSource.init(testing.io);
    const a = source.next();
    const b = source.next();
    try testing.expect(!std.mem.eql(u8, &a, &b));
}
