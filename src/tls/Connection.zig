//! The TLS 1.3 record layer (RFC 8446 section 5) for one connection: encryption and
//! decryption of records, alerts, key updates and the plaintext `reader` and `writer`.
//!
//! The handshake code owns a `Connection` while the keys are not yet set and hands it to the
//! application when the handshake is complete. Do not move the struct after the first use of
//! `reader` or `writer`, because both point back at it.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const suites = @import("suites.zig");
const codec = @import("handshake/codec.zig");

const Connection = @This();

/// The encrypted stream from the peer. Its buffer must hold one full record. The connection
/// decrypts each record in place in this buffer, so the buffer must be writable.
input: *Reader,
/// The encrypted stream to the peer. Its buffer must hold one full record.
output: *Writer,
/// Plaintext from the peer.
reader: Reader,
/// Plaintext to the peer.
writer: Writer,
read_keys: suites.DirectionKeys = .none,
write_keys: suites.DirectionKeys = .none,
role: Role,
handshake_complete: bool = false,
received_close_notify: bool = false,
sent_close_notify: bool = false,
/// Treat end of stream without `close_notify` as a normal end. Safe only when the
/// application layer verifies message lengths itself, as HTTP does.
allow_truncation_attacks: bool,
/// The last alert received, or the last fatal alert sent.
alert: ?tls.Alert = null,
/// Set when `reader` returned `error.ReadFailed` because of a TLS problem.
read_err: ?ReadError = null,
suite: ?suites.Suite = null,
group: u16 = 0,
/// The SHA-256 fingerprint of the peer leaf certificate, when the peer presented one.
peer_fingerprint: ?[32]u8 = null,
alpn_buf: [255]u8 = undefined,
alpn_len: u8 = 0,
server_name_buf: [255]u8 = undefined,
server_name_len: u8 = 0,
plaintext_ccs_seen: u8 = 0,
/// Decrypted application data that did not fit into the `reader` buffer. It points into the
/// buffer of `input`. The connection reads no record from `input` while this data remains.
pending: []u8 = &.{},
/// The padding of the encrypted records that this connection sends. Use `setPadding`.
padding: Padding = .none,
/// The random source of the `random` padding policy.
padding_rng: std.Random.ChaCha = .{ .state = @splat(0), .offset = 0 },

pub const Role = enum { server, client };

/// How the record layer pads the encrypted records that it sends (RFC 8446 section 5.4).
/// Padding adds zero bytes after the content type of the inner plaintext. It hides the length
/// of the content from an observer of the network, and costs bandwidth. The padding of all
/// encrypted records is the same: application data, handshake messages, key updates and
/// alerts. Padding stops at `max_padded_inner_len` bytes of inner plaintext.
pub const Padding = union(enum) {
    /// No padding. This is the default.
    none,
    /// Pad each inner plaintext to a multiple of this number of bytes. The inner plaintext
    /// is the content, the content type byte and the padding. The values 0 and 1 add no
    /// padding.
    block: u16,
    /// Add a random number of zero bytes to each record, from 0 to this number.
    random: u16,
};

/// The largest inner plaintext of an encrypted record: 2^14 bytes of content and the content
/// type byte (RFC 8446 section 5.4). Padding does not change this limit.
pub const max_inner_plaintext_len = tls.max_ciphertext_inner_record_len + 1;

/// Padding stops at an inner plaintext of 2^14 bytes, 1 byte below the limit. Only a record
/// with 2^14 bytes of content gets to the limit, and it has no padding. Some peers keep a
/// handshake record in a buffer of 2^14 bytes, such as the TLS client of the Zig standard
/// library. They accept every padded record.
pub const max_padded_inner_len = tls.max_ciphertext_inner_record_len;

pub const min_input_buffer_len = tls.max_ciphertext_record_len;
pub const min_output_buffer_len = tls.max_ciphertext_record_len;
pub const min_read_buffer_len = tls.max_ciphertext_len;

/// Records sent under one key generation before an automatic key update.
pub const key_update_threshold: u64 = 1 << 24;

pub const ReadError = error{
    /// The peer sent a fatal alert. The field `alert` holds it.
    TlsAlert,
    TlsBadRecordMac,
    TlsRecordOverflow,
    TlsUnexpectedMessage,
    TlsDecodeError,
    TlsIllegalParameter,
    TlsConnectionTruncated,
    TlsSequenceOverflow,
};

pub const RecordError = ReadError || error{ReadFailed};

pub const Record = struct {
    content_type: tls.ContentType,
    data: []u8,
};

pub fn init(input: *Reader, output: *Writer, role: Role, read_buffer: []u8, write_buffer: []u8, allow_truncation_attacks: bool) Connection {
    std.debug.assert(read_buffer.len >= min_read_buffer_len);
    return .{
        .input = input,
        .output = output,
        .reader = .{
            .buffer = read_buffer,
            .vtable = &.{ .stream = stream, .readVec = readVec },
            .seek = 0,
            .end = 0,
        },
        .writer = .{
            .buffer = write_buffer,
            .vtable = &.{ .drain = drain, .flush = flush },
        },
        .role = role,
        .allow_truncation_attacks = allow_truncation_attacks,
    };
}

/// The negotiated application protocol, or null.
pub fn alpn(self: *const Connection) ?[]const u8 {
    return if (self.alpn_len == 0) null else self.alpn_buf[0..self.alpn_len];
}

/// The server name the client asked for, or null.
pub fn serverName(self: *const Connection) ?[]const u8 {
    return if (self.server_name_len == 0) null else self.server_name_buf[0..self.server_name_len];
}

pub fn setAlpn(self: *Connection, name: []const u8) void {
    @memcpy(self.alpn_buf[0..name.len], name);
    self.alpn_len = @intCast(name.len);
}

pub fn setServerName(self: *Connection, name: []const u8) void {
    @memcpy(self.server_name_buf[0..name.len], name);
    self.server_name_len = @intCast(name.len);
}

/// Wipe all key material.
pub fn deinit(self: *Connection) void {
    self.read_keys.wipe();
    self.write_keys.wipe();
    crypto.secureZero(u8, &self.padding_rng.state);
}

/// Set the padding of the encrypted records that this connection sends from now on. The
/// `random` policy gets its seed from the secure random source of `io`.
pub fn setPadding(self: *Connection, io: std.Io, padding: Padding) error{EntropyUnavailable}!void {
    if (padding == .random) {
        var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
        defer crypto.secureZero(u8, &seed);
        io.randomSecure(&seed) catch return error.EntropyUnavailable;
        self.padding_rng = .init(seed);
    }
    self.padding = padding;
}

/// The number of zero bytes to add to an inner plaintext of `inner_len` bytes. The padded
/// inner plaintext stays at `max_padded_inner_len` bytes or less.
fn paddingLength(self: *Connection, inner_len: usize) usize {
    std.debug.assert(inner_len <= max_inner_plaintext_len);
    const room = max_padded_inner_len -| inner_len;
    const wanted: usize = switch (self.padding) {
        .none => 0,
        .block => |size| if (size <= 1) 0 else (size - inner_len % size) % size,
        .random => |most| self.padding_rng.random().uintAtMost(u16, most),
    };
    return @min(wanted, room);
}

pub fn eof(self: *const Connection) bool {
    return self.received_close_notify;
}

// -- Reading records -------------------------------------------------------------------------

/// Read one record. The function decrypts an encrypted record in place in the buffer of
/// `input`. The data that it returns is valid until the next read from `input`.
pub fn readRecord(self: *Connection) RecordError!Record {
    std.debug.assert(self.pending.len == 0);
    const input = self.input;
    const header = input.peek(tls.record_header_len) catch |e| switch (e) {
        error.EndOfStream => return error.TlsConnectionTruncated,
        error.ReadFailed => return error.ReadFailed,
    };
    const ct: tls.ContentType = @enumFromInt(header[0]);
    const len: usize = std.mem.readInt(u16, header[3..5], .big);
    switch (ct) {
        .change_cipher_spec, .alert, .handshake, .application_data => {},
        else => return error.TlsUnexpectedMessage,
    }
    const max_len: usize = if (self.read_keys == .none) tls.max_ciphertext_inner_record_len else tls.max_ciphertext_len;
    if (len > max_len) return error.TlsRecordOverflow;
    if (len == 0 and ct != .application_data) return error.TlsDecodeError;
    const record_end = tls.record_header_len + len;
    if (input.buffered().len < record_end) {
        input.rebase(record_end) catch |e| switch (e) {
            error.EndOfStream => {},
            error.ReadFailed => return error.ReadFailed,
        };
        while (input.buffered().len < record_end) {
            input.fillMore() catch |e| switch (e) {
                error.EndOfStream => return error.TlsConnectionTruncated,
                error.ReadFailed => return error.ReadFailed,
            };
        }
    }
    const ad = (input.takeArray(tls.record_header_len) catch unreachable).*;
    const body = input.take(len) catch unreachable;

    if (self.read_keys == .none) return .{ .content_type = ct, .data = body };
    if (!self.handshake_complete) {
        if (ct == .change_cipher_spec) {
            self.plaintext_ccs_seen += 1;
            if (self.plaintext_ccs_seen > 4) return error.TlsUnexpectedMessage;
            return .{ .content_type = ct, .data = body };
        }
        // A client without keys yet can only answer with a plaintext alert.
        if (ct == .alert) return .{ .content_type = ct, .data = body };
    }
    if (ct != .application_data) return error.TlsUnexpectedMessage;
    switch (self.read_keys) {
        .none => unreachable,
        inline else => |*keys| {
            const S = @TypeOf(keys.*).Suite;
            const tag_len = S.AEAD.tag_length;
            if (len < tag_len) return error.TlsBadRecordMac;
            const ciphertext = body[0 .. len - tag_len];
            // The inner plaintext has the length of the ciphertext. With its padding, it must
            // not exceed 2^14 + 1 bytes (section 5.4).
            if (ciphertext.len > max_inner_plaintext_len) return error.TlsRecordOverflow;
            const tag = body[len - tag_len ..][0..tag_len].*;
            // Every AEAD of `suites` reads each block before it writes the same block, so the
            // plaintext can replace the ciphertext. A test in `suites.zig` guards this.
            const out = ciphertext;
            S.AEAD.decrypt(out, ciphertext, tag, &ad, keys.nonce(), keys.key) catch return error.TlsBadRecordMac;
            keys.seq = std.math.add(u64, keys.seq, 1) catch return error.TlsSequenceOverflow;
            // Remove the padding: the last byte that is not zero is the content type. An
            // inner plaintext without such a byte is an unexpected message (section 5.4).
            var n = out.len;
            while (n > 0 and out[n - 1] == 0) n -= 1;
            if (n == 0) return error.TlsUnexpectedMessage;
            const inner: tls.ContentType = @enumFromInt(out[n - 1]);
            switch (inner) {
                .alert, .handshake, .application_data => {},
                else => return error.TlsUnexpectedMessage,
            }
            return .{ .content_type = inner, .data = out[0 .. n - 1] };
        },
    }
}

/// Copy pending data into the free space of the `reader` buffer. The function first moves
/// unread data to the start of the buffer when the free space at its end is too small.
/// Returns false when the buffer has no free space.
fn deliverPending(c: *Connection) bool {
    const r = &c.reader;
    if (r.buffer.len - r.end < c.pending.len and r.seek > 0) {
        const unread = r.buffer[r.seek..r.end];
        @memmove(r.buffer[0..unread.len], unread);
        r.seek = 0;
        r.end = unread.len;
    }
    const n = @min(c.pending.len, r.buffer.len - r.end);
    if (n == 0) return false;
    @memcpy(r.buffer[r.end..][0..n], c.pending[0..n]);
    r.end += n;
    c.pending = c.pending[n..];
    return true;
}

fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
    const c: *Connection = @alignCast(@fieldParentPtr("reader", r));
    if (c.pending.len == 0) try readIndirect(c);
    if (c.pending.len == 0 or deliverPending(c)) return 0;
    // The buffer is full of unread data. Give the new data to `w`.
    const n = try w.write(limit.slice(c.pending));
    c.pending = c.pending[n..];
    return n;
}

fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize {
    const c: *Connection = @alignCast(@fieldParentPtr("reader", r));
    if (c.pending.len == 0) try readIndirect(c);
    if (c.pending.len == 0 or deliverPending(c)) return 0;
    // The buffer is full of unread data. Give the new data to `data`.
    var total: usize = 0;
    for (data) |buf| {
        const n = @min(buf.len, c.pending.len);
        @memcpy(buf[0..n], c.pending[0..n]);
        c.pending = c.pending[n..];
        total += n;
    }
    return total;
}

/// Read and decrypt one record. Application data goes to `pending`. This function processes
/// other content and gives no data for it.
fn readIndirect(c: *Connection) Reader.Error!void {
    if (c.received_close_notify) return error.EndOfStream;
    const rec = c.readRecord() catch |e| switch (e) {
        error.ReadFailed => return error.ReadFailed,
        error.TlsConnectionTruncated => {
            if (c.allow_truncation_attacks) {
                c.received_close_notify = true;
                return error.EndOfStream;
            }
            return failRead(c, error.TlsConnectionTruncated);
        },
        else => |err| return failRead(c, err),
    };
    switch (rec.content_type) {
        .application_data => c.pending = rec.data,
        .alert => {
            if (rec.data.len != 2) return failRead(c, error.TlsDecodeError);
            const alert: tls.Alert = .{ .level = @enumFromInt(rec.data[0]), .description = @enumFromInt(rec.data[1]) };
            c.alert = alert;
            switch (alert.description) {
                .close_notify => {
                    c.received_close_notify = true;
                    return error.EndOfStream;
                },
                .user_canceled => {},
                else => return failRead(c, error.TlsAlert),
            }
        },
        .handshake => c.handlePostHandshake(rec.data) catch |e| switch (e) {
            error.WriteFailed => return error.ReadFailed,
            else => |err| return failRead(c, err),
        },
        else => return failRead(c, error.TlsUnexpectedMessage),
    }
}

fn failRead(c: *Connection, err: ReadError) error{ReadFailed} {
    c.read_err = err;
    return error.ReadFailed;
}

fn handlePostHandshake(c: *Connection, data: []const u8) (ReadError || error{WriteFailed})!void {
    var i: usize = 0;
    while (i < data.len) {
        if (data.len - i < 4) return error.TlsDecodeError;
        const msg_type: tls.HandshakeType = @enumFromInt(data[i]);
        const len = std.mem.readInt(u24, data[i + 1 ..][0..3], .big);
        i += 4;
        if (data.len - i < len) return error.TlsDecodeError; // messages that span records are not supported here
        const body = data[i .. i + len];
        i += len;
        switch (msg_type) {
            .key_update => {
                if (body.len != 1) return error.TlsDecodeError;
                const request: tls.KeyUpdateRequest = @enumFromInt(body[0]);
                switch (request) {
                    .update_requested => {
                        // Answer under the current keys, then rotate our own (section 4.6.3).
                        var buf: [8]u8 = undefined;
                        try c.writeRecord(.handshake, codec.keyUpdate(&buf, false));
                        try c.output.flush();
                        c.rotateWriteKeys();
                    },
                    .update_not_requested => {},
                    _ => return error.TlsIllegalParameter,
                }
                switch (c.read_keys) {
                    .none => return error.TlsUnexpectedMessage,
                    inline else => |*keys| keys.update(),
                }
            },
            .new_session_ticket => if (c.role != .client) return error.TlsUnexpectedMessage,
            else => return error.TlsUnexpectedMessage,
        }
    }
}

fn rotateWriteKeys(c: *Connection) void {
    switch (c.write_keys) {
        .none => {},
        inline else => |*keys| keys.update(),
    }
}

// -- Writing records -------------------------------------------------------------------------

/// Encrypt `bytes` as records of `content_type` into `out`. Returns the number of bytes that
/// it wrote and the number of bytes of `bytes` that it used. The rest did not fit.
fn encryptInto(c: *Connection, out: []u8, bytes: []const u8, content_type: tls.ContentType) struct { written: usize, consumed: usize } {
    var written: usize = 0;
    var consumed: usize = 0;
    switch (c.write_keys) {
        .none => while (true) {
            const n: usize = @min(bytes.len - consumed, tls.max_ciphertext_inner_record_len, out.len -| (tls.record_header_len + written));
            if (n == 0) return .{ .written = written, .consumed = consumed };
            const header = out[written..][0..tls.record_header_len];
            header[0] = @intFromEnum(content_type);
            std.mem.writeInt(u16, header[1..3], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
            std.mem.writeInt(u16, header[3..5], @intCast(n), .big);
            written += tls.record_header_len;
            @memcpy(out[written..][0..n], bytes[consumed..][0..n]);
            written += n;
            consumed += n;
        },
        inline else => |*keys| {
            const S = @TypeOf(keys.*).Suite;
            const overhead = tls.record_header_len + S.AEAD.tag_length + 1;
            var cleartext: [max_inner_plaintext_len]u8 = undefined;
            while (true) {
                // The content bytes that fit into `out` without padding.
                const space = out.len -| (overhead + written);
                const n: usize = @min(bytes.len - consumed, tls.max_ciphertext_inner_record_len, space);
                if (n == 0) return .{ .written = written, .consumed = consumed };
                var pad = c.paddingLength(n + 1);
                if (n + pad > space) {
                    // The padded record does not fit after the records before it. The caller
                    // gives a new buffer. An empty buffer of `min_output_buffer_len` bytes
                    // holds the largest record.
                    if (written > 0) return .{ .written = written, .consumed = consumed };
                    pad = space - n;
                }
                @memcpy(cleartext[0..n], bytes[consumed..][0..n]);
                cleartext[n] = @intFromEnum(content_type);
                @memset(cleartext[n + 1 ..][0..pad], 0);
                consumed += n;
                const inner_len = n + 1 + pad;
                const header = out[written..][0..tls.record_header_len];
                header[0] = @intFromEnum(tls.ContentType.application_data);
                std.mem.writeInt(u16, header[1..3], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
                std.mem.writeInt(u16, header[3..5], @intCast(inner_len + S.AEAD.tag_length), .big);
                written += tls.record_header_len;
                const ciphertext = out[written..][0..inner_len];
                written += inner_len;
                const tag = out[written..][0..S.AEAD.tag_length];
                written += S.AEAD.tag_length;
                S.AEAD.encrypt(ciphertext, tag, cleartext[0..inner_len], header, keys.nonce(), keys.key);
                keys.seq += 1;
            }
        },
    }
}

/// Write one message as records of `content_type` under the current write keys.
pub fn writeRecord(c: *Connection, content_type: tls.ContentType, bytes: []const u8) Writer.Error!void {
    var i: usize = 0;
    while (true) {
        const buf = try c.output.writableSliceGreedy(min_output_buffer_len);
        const r = c.encryptInto(buf, bytes[i..], content_type);
        c.output.advance(r.written);
        i += r.consumed;
        if (i >= bytes.len) return;
    }
}

/// Write a plaintext change_cipher_spec record (middlebox compatibility mode).
pub fn writeChangeCipherSpec(c: *Connection) Writer.Error!void {
    try c.output.writeAll(&.{ @intFromEnum(tls.ContentType.change_cipher_spec), 0x03, 0x03, 0x00, 0x01, 0x01 });
}

/// Send an alert and flush. The field `alert` also records a fatal alert.
pub fn sendAlert(c: *Connection, level: tls.Alert.Level, description: tls.Alert.Description) Writer.Error!void {
    if (level == .fatal) c.alert = .{ .level = level, .description = description };
    try c.writeRecord(.alert, &.{ @intFromEnum(level), @intFromEnum(description) });
    try c.output.flush();
}

/// Flush pending plaintext, then send `close_notify`.
pub fn end(c: *Connection) Writer.Error!void {
    try flush(&c.writer);
    if (c.sent_close_notify) return;
    c.sent_close_notify = true;
    try c.writeRecord(.alert, &tls.close_notify_alert);
    try c.output.flush();
}

/// Rotate our keys before the connection gets to the AEAD record limit (section 5.5).
fn maybeUpdateKeys(c: *Connection) Writer.Error!void {
    if (!c.handshake_complete) return;
    const seq = switch (c.write_keys) {
        .none => return,
        inline else => |*keys| keys.seq,
    };
    if (seq < key_update_threshold) return;
    try c.updateKeys();
}

/// Send a KeyUpdate and rotate our write keys. Flush pending plaintext first.
pub fn updateKeys(c: *Connection) Writer.Error!void {
    var buf: [8]u8 = undefined;
    try c.writeRecord(.handshake, codec.keyUpdate(&buf, false));
    c.rotateWriteKeys();
}

fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const c: *Connection = @alignCast(@fieldParentPtr("writer", w));
    try c.maybeUpdateKeys();
    var total_clear: usize = 0;
    done: {
        {
            const buf = w.buffered();
            const consumed = try c.writeApplicationData(buf);
            total_clear += consumed;
            if (consumed < buf.len) break :done;
        }
        for (data[0 .. data.len - 1]) |buf| {
            const consumed = try c.writeApplicationData(buf);
            total_clear += consumed;
            if (consumed < buf.len) break :done;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            const consumed = try c.writeApplicationData(last);
            total_clear += consumed;
            if (consumed < last.len) break :done;
        }
    }
    return w.consume(total_clear);
}

/// Encrypt as much of `bytes` as fits into the output buffer once.
fn writeApplicationData(c: *Connection, bytes: []const u8) Writer.Error!usize {
    if (bytes.len == 0) return 0;
    const buf = try c.output.writableSliceGreedy(min_output_buffer_len);
    const r = c.encryptInto(buf, bytes, .application_data);
    c.output.advance(r.written);
    return r.consumed;
}

fn flush(w: *Writer) Writer.Error!void {
    const c: *Connection = @alignCast(@fieldParentPtr("writer", w));
    try c.maybeUpdateKeys();
    var i: usize = 0;
    const buf = w.buffered();
    while (i < buf.len) i += try c.writeApplicationData(buf[i..]);
    w.end = 0;
    try c.output.flush();
}

test "encrypted record round trip" {
    const S = suites.Suite.Type(.AES_128_GCM_SHA256);
    const secret = [_]u8{3} ** S.digest_length;

    // Encrypt with the server write keys into an allocating writer.
    var unused_in: Reader = .fixed("");
    var sink: Writer.Allocating = .init(std.testing.allocator);
    defer sink.deinit();
    var read_buf: [min_read_buffer_len]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var c: Connection = .init(&unused_in, &sink.writer, .server, &read_buf, &write_buf, false);
    c.write_keys = suites.DirectionKeys.init(.AES_128_GCM_SHA256, secret);
    c.handshake_complete = true;
    try c.writer.writeAll("hello over tls");
    try c.writer.flush();
    try c.updateKeys();
    try c.end();
    const wire = sink.written();
    try std.testing.expect(wire.len > 14 + 5 + 16);
    try std.testing.expectEqual(@intFromEnum(tls.ContentType.application_data), wire[0]);

    // Decrypt on a peer with the matching read keys. The key update rotates them.
    var peer_in: Reader = .fixed(wire);
    var peer_sink: Writer.Allocating = .init(std.testing.allocator);
    defer peer_sink.deinit();
    var peer_read: [min_read_buffer_len]u8 = undefined;
    var peer_write: [64]u8 = undefined;
    var p: Connection = .init(&peer_in, &peer_sink.writer, .client, &peer_read, &peer_write, false);
    p.read_keys = suites.DirectionKeys.init(.AES_128_GCM_SHA256, secret);
    p.handshake_complete = true;
    var line: [64]u8 = undefined;
    const n = try p.reader.readSliceShort(&line);
    try std.testing.expectEqualStrings("hello over tls", line[0..n]);
    try std.testing.expect(p.eof());
    try std.testing.expectEqual(1, p.read_keys.AES_128_GCM_SHA256.seq); // rotated after key_update, then one record
}

/// Append one encrypted record with the inner plaintext `content`, `content_type` and
/// `padding` zero bytes to `wire`. The keys move to the next sequence number.
fn appendTestRecord(comptime S: type, gpa: std.mem.Allocator, keys: *suites.TrafficKeys(S), wire: *std.ArrayList(u8), content: []const u8, content_type: tls.ContentType, padding: usize) !void {
    const inner_len = content.len + 1 + padding;
    const inner = try gpa.alloc(u8, inner_len);
    defer gpa.free(inner);
    @memcpy(inner[0..content.len], content);
    inner[content.len] = @intFromEnum(content_type);
    @memset(inner[content.len + 1 ..], 0);
    try appendSealedRecord(S, gpa, keys, wire, inner);
}

/// Append one encrypted record with the raw inner plaintext `inner` to `wire`.
fn appendSealedRecord(comptime S: type, gpa: std.mem.Allocator, keys: *suites.TrafficKeys(S), wire: *std.ArrayList(u8), inner: []const u8) !void {
    const len = inner.len + S.AEAD.tag_length;
    const start = wire.items.len;
    try wire.resize(gpa, start + tls.record_header_len + len);
    const rec = wire.items[start..];
    rec[0] = @intFromEnum(tls.ContentType.application_data);
    std.mem.writeInt(u16, rec[1..3], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
    std.mem.writeInt(u16, rec[3..5], @intCast(len), .big);
    const body = rec[tls.record_header_len..];
    S.AEAD.encrypt(body[0..inner.len], body[inner.len..][0..S.AEAD.tag_length], inner, rec[0..tls.record_header_len], keys.nonce(), keys.key);
    keys.seq += 1;
}

test "a record that does not fit after unread data arrives in order" {
    // Regression: the decrypted record went into the free space of the reader buffer after
    // the unread data, and a full record did not fit there. Lines through
    // `peekDelimiterInclusive` keep unread data in the buffer, as an HTTP head does.
    const gpa = std.testing.allocator;
    const S = suites.Suite.Type(.AES_128_GCM_SHA256);
    const secret = [_]u8{5} ** S.digest_length;
    var keys: suites.TrafficKeys(S) = .fromSecret(secret);
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(gpa);

    const full = tls.max_ciphertext_inner_record_len;
    var big: [full]u8 = undefined;
    var parts: [6][]const u8 = undefined;
    // A few hundred bytes without a line end.
    parts[0] = "a" ** 300;
    // A full record with a line end inside.
    @memset(&big, 'b');
    big[16000] = '\n';
    parts[1] = try gpa.dupe(u8, &big);
    defer gpa.free(parts[1]);
    // A short record with the largest padding.
    parts[2] = "d" ** 100;
    // A full record with a line end inside.
    @memset(&big, 'e');
    big[15000] = '\n';
    parts[3] = try gpa.dupe(u8, &big);
    defer gpa.free(parts[3]);
    // A short record, then a full record without a line end: the buffer becomes full.
    parts[4] = "f" ** 300;
    @memset(&big, 'g');
    parts[5] = try gpa.dupe(u8, &big);
    defer gpa.free(parts[5]);
    for (parts, 0..) |part, i| {
        const padding: usize = if (i == 2) max_inner_plaintext_len - part.len - 1 else 0;
        try appendTestRecord(S, gpa, &keys, &wire, part, .application_data, padding);
        try expected.appendSlice(gpa, part);
    }
    try appendTestRecord(S, gpa, &keys, &wire, &tls.close_notify_alert, .alert, 0);

    // The input stream gives the records in pieces of an odd size.
    var input_buf: [min_input_buffer_len]u8 = undefined;
    const calls = [_]std.testing.Reader.Call{.{ .buffer = wire.items }};
    var input: std.testing.Reader = .init(&input_buf, &calls);
    input.artificial_limit = .limited(997);
    var sink: Writer.Allocating = .init(gpa);
    defer sink.deinit();
    var read_buf: [min_read_buffer_len]u8 = undefined;
    var write_buf: [64]u8 = undefined;
    var p: Connection = .init(&input.interface, &sink.writer, .server, &read_buf, &write_buf, false);
    defer p.deinit();
    p.read_keys = suites.DirectionKeys.init(.AES_128_GCM_SHA256, secret);
    p.handshake_complete = true;

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var too_long: usize = 0;
    while (true) {
        if (p.reader.peekDelimiterInclusive('\n')) |line| {
            try got.appendSlice(gpa, line);
            p.reader.toss(line.len);
        } else |e| switch (e) {
            error.StreamTooLong => {
                // The buffer is full and has no line end. Take all of it and go on.
                too_long += 1;
                const all = p.reader.buffered();
                try got.appendSlice(gpa, all);
                p.reader.toss(all.len);
            },
            error.EndOfStream => break,
            error.ReadFailed => return p.read_err.?,
        }
    }
    try got.appendSlice(gpa, p.reader.buffered());
    try std.testing.expectEqual(1, too_long);
    try std.testing.expect(p.eof());
    try std.testing.expectEqual(expected.items.len, got.items.len);
    try std.testing.expect(std.mem.eql(u8, expected.items, got.items));
}

test "the receive path removes padding and refuses bad inner plaintexts" {
    const gpa = std.testing.allocator;
    const S = suites.Suite.Type(.CHACHA20_POLY1305_SHA256);
    const secret = [_]u8{6} ** S.digest_length;
    const Case = struct { inner: []const u8, want: anyerror![]const u8 };
    var max_padded: [max_inner_plaintext_len]u8 = @splat(0);
    max_padded[0] = 'x';
    max_padded[1] = @intFromEnum(tls.ContentType.application_data);
    var over: [max_inner_plaintext_len + 1]u8 = @splat(0);
    over[0] = 'x';
    over[1] = @intFromEnum(tls.ContentType.application_data);
    const cases = [_]Case{
        // Padding after the content type goes away.
        .{ .inner = "ok\x17\x00\x00\x00", .want = "ok" },
        // The largest inner plaintext: one content byte and the most padding.
        .{ .inner = &max_padded, .want = "x" },
        // Only zeros: no content type (RFC 8446 section 5.4).
        .{ .inner = &([_]u8{0} ** 32), .want = error.TlsUnexpectedMessage },
        // No inner plaintext at all.
        .{ .inner = "", .want = error.TlsUnexpectedMessage },
        // One byte more than 2^14 + 1, also when the extra bytes are padding.
        .{ .inner = &over, .want = error.TlsRecordOverflow },
        // A content type that is not allowed in an encrypted record.
        .{ .inner = "x\x14", .want = error.TlsUnexpectedMessage },
    };
    for (cases) |case| {
        var keys: suites.TrafficKeys(S) = .fromSecret(secret);
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try appendSealedRecord(S, gpa, &keys, &wire, case.inner);
        var input: Reader = .fixed(wire.items);
        var sink: Writer.Allocating = .init(gpa);
        defer sink.deinit();
        var read_buf: [min_read_buffer_len]u8 = undefined;
        var write_buf: [64]u8 = undefined;
        var p: Connection = .init(&input, &sink.writer, .client, &read_buf, &write_buf, false);
        defer p.deinit();
        p.read_keys = suites.DirectionKeys.init(.CHACHA20_POLY1305_SHA256, secret);
        p.handshake_complete = true;
        if (case.want) |want| {
            const rec = try p.readRecord();
            try std.testing.expectEqual(tls.ContentType.application_data, rec.content_type);
            try std.testing.expectEqualStrings(want, rec.data);
        } else |want_err| {
            try std.testing.expectError(want_err, p.readRecord());
        }
    }
}

test "padding lengths of each policy" {
    var unused_in: Reader = .fixed("");
    var unused_out: Writer = .failing;
    var read_buf: [min_read_buffer_len]u8 = undefined;
    var write_buf: [64]u8 = undefined;
    var c: Connection = .init(&unused_in, &unused_out, .client, &read_buf, &write_buf, false);
    defer c.deinit();
    try std.testing.expectEqual(0, c.paddingLength(15));
    for ([_]u16{ 0, 1 }) |size| {
        c.padding = .{ .block = size };
        try std.testing.expectEqual(0, c.paddingLength(15));
    }
    c.padding = .{ .block = 64 };
    try std.testing.expectEqual(49, c.paddingLength(15));
    try std.testing.expectEqual(0, c.paddingLength(64));
    try std.testing.expectEqual(63, c.paddingLength(65));
    try std.testing.expectEqual(4, c.paddingLength(16380));
    // A full record has no room for padding.
    try std.testing.expectEqual(0, c.paddingLength(max_inner_plaintext_len));
    // The limit cuts the padding short.
    c.padding = .{ .block = 1000 };
    try std.testing.expectEqual(max_padded_inner_len - 16001, c.paddingLength(16001));
    c.padding = .{ .block = max_inner_plaintext_len };
    try std.testing.expectEqual(max_padded_inner_len - 15, c.paddingLength(15));
    try std.testing.expectEqual(0, c.paddingLength(max_padded_inner_len));
    try c.setPadding(std.testing.io, .{ .random = 0 });
    try std.testing.expectEqual(0, c.paddingLength(15));
    try c.setPadding(std.testing.io, .{ .random = 10 });
    var seen: [11]bool = @splat(false);
    for (0..2000) |_| {
        const n = c.paddingLength(15);
        try std.testing.expect(n <= 10);
        seen[n] = true;
    }
    for (seen) |s| try std.testing.expect(s);
    try std.testing.expectEqual(0, c.paddingLength(max_inner_plaintext_len));
}

test "padded records decrypt to their content and stay in the size limit" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const policies = [_]Padding{
        .{ .block = 64 },
        .{ .block = 4096 },
        .{ .block = max_inner_plaintext_len },
        .{ .block = 65535 },
        .{ .random = 300 },
        .{ .random = 65535 },
    };
    const message = try gpa.alloc(u8, 40000);
    defer gpa.free(message);
    // Zero bytes in the content stay: only the bytes after the content type are padding.
    for (message, 0..) |*b, i| b.* = @truncate(i % 251);
    inline for (.{ suites.Suite.AES_128_GCM_SHA256, suites.Suite.AEGIS_128L_SHA256, suites.Suite.AEGIS_256_SHA512 }) |suite| {
        const S = suites.Suite.Type(suite);
        const secret = [_]u8{4} ** S.digest_length;
        for (policies) |policy| {
            var unused_in: Reader = .fixed("");
            var sink: Writer.Allocating = .init(gpa);
            defer sink.deinit();
            var read_buf: [min_read_buffer_len]u8 = undefined;
            var write_buf: [1024]u8 = undefined;
            var c: Connection = .init(&unused_in, &sink.writer, .server, &read_buf, &write_buf, false);
            defer c.deinit();
            c.write_keys = suites.DirectionKeys.init(suite, secret);
            c.handshake_complete = true;
            try c.setPadding(io, policy);
            try c.writer.writeAll("hello over tls");
            try c.writer.flush();
            try c.writer.writeAll(message);
            try c.writer.flush();
            try c.end();

            // Read the records one at a time and check the padding of each.
            var peer_in: Reader = .fixed(sink.written());
            var peer_sink: Writer.Allocating = .init(gpa);
            defer peer_sink.deinit();
            var peer_read: [min_read_buffer_len]u8 = undefined;
            var peer_write: [64]u8 = undefined;
            var p: Connection = .init(&peer_in, &peer_sink.writer, .client, &peer_read, &peer_write, false);
            defer p.deinit();
            p.read_keys = suites.DirectionKeys.init(suite, secret);
            p.handshake_complete = true;
            var got: std.ArrayList(u8) = .empty;
            defer got.deinit(gpa);
            var total_padding: usize = 0;
            while (true) {
                const header = peer_in.buffered()[0..tls.record_header_len];
                const record_len = std.mem.readInt(u16, header[3..5], .big);
                try std.testing.expect(record_len <= tls.max_ciphertext_len);
                const inner_len = record_len - S.AEAD.tag_length;
                try std.testing.expect(inner_len <= max_inner_plaintext_len);
                const rec = try p.readRecord();
                const padding = inner_len - rec.data.len - 1;
                total_padding += padding;
                if (padding > 0) try std.testing.expect(inner_len <= max_padded_inner_len);
                switch (policy) {
                    .none => unreachable,
                    .block => |size| try std.testing.expect(inner_len % size == 0 or inner_len >= max_padded_inner_len),
                    .random => |most| try std.testing.expect(padding <= most),
                }
                if (rec.content_type == .alert) {
                    try std.testing.expectEqualSlices(u8, &tls.close_notify_alert, rec.data);
                    break;
                }
                try std.testing.expectEqual(tls.ContentType.application_data, rec.content_type);
                try got.appendSlice(gpa, rec.data);
            }
            try std.testing.expect(total_padding > 0);
            try std.testing.expectEqual(0, peer_in.buffered().len);
            try std.testing.expectEqualStrings("hello over tls", got.items[0..14]);
            try std.testing.expect(std.mem.eql(u8, message, got.items[14..]));
        }
    }
}

test "a padded record that does not fit waits for a new buffer" {
    const gpa = std.testing.allocator;
    const S = suites.Suite.Type(.AES_128_GCM_SHA256);
    const secret = [_]u8{8} ** S.digest_length;
    var unused_in: Reader = .fixed("");
    var unused_out: Writer = .failing;
    var read_buf: [min_read_buffer_len]u8 = undefined;
    var write_buf: [64]u8 = undefined;
    var c: Connection = .init(&unused_in, &unused_out, .client, &read_buf, &write_buf, false);
    defer c.deinit();
    c.write_keys = suites.DirectionKeys.init(.AES_128_GCM_SHA256, secret);
    c.padding = .{ .block = max_inner_plaintext_len };
    // A full record has no padding. A short record gets padding up to 2^14 bytes.
    const full_len = tls.record_header_len + max_inner_plaintext_len + S.AEAD.tag_length;
    const padded_len = tls.record_header_len + max_padded_inner_len + S.AEAD.tag_length;
    const bytes = try gpa.alloc(u8, tls.max_ciphertext_inner_record_len + 10);
    defer gpa.free(bytes);
    @memset(bytes, 'q');
    const wire = try gpa.alloc(u8, full_len + padded_len + min_output_buffer_len);
    defer gpa.free(wire);
    // The second record fits without padding, but not with it. It waits for the next buffer.
    const first = c.encryptInto(wire[0 .. full_len + padded_len - 1], bytes, .application_data);
    try std.testing.expectEqual(full_len, first.written);
    try std.testing.expectEqual(tls.max_ciphertext_inner_record_len, first.consumed);
    const second = c.encryptInto(wire[first.written..], bytes[first.consumed..], .application_data);
    try std.testing.expectEqual(padded_len, second.written);
    try std.testing.expectEqual(10, second.consumed);

    var peer_in: Reader = .fixed(wire[0 .. first.written + second.written]);
    var p: Connection = .init(&peer_in, &unused_out, .server, &read_buf, &write_buf, false);
    defer p.deinit();
    p.read_keys = suites.DirectionKeys.init(.AES_128_GCM_SHA256, secret);
    p.handshake_complete = true;
    try std.testing.expectEqual(tls.max_ciphertext_inner_record_len, (try p.readRecord()).data.len);
    try std.testing.expectEqualStrings("q" ** 10, (try p.readRecord()).data);
}
