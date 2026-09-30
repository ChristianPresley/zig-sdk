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

/// The encrypted stream from the peer. Its buffer must hold one full record.
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

pub const Role = enum { server, client };

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
}

pub fn eof(self: *const Connection) bool {
    return self.received_close_notify;
}

// -- Reading records -------------------------------------------------------------------------

/// Read one record. The function decrypts an encrypted record into the `reader` buffer after
/// its end. The data that it returns is valid until the next read.
pub fn readRecord(self: *Connection) RecordError!Record {
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
            if (len < tag_len + 1) return error.TlsBadRecordMac;
            const ciphertext = body[0 .. len - tag_len];
            const tag = body[len - tag_len ..][0..tag_len].*;
            rebaseReader(&self.reader, ciphertext.len);
            const out = self.reader.buffer[self.reader.end..][0..ciphertext.len];
            S.AEAD.decrypt(out, ciphertext, tag, &ad, keys.nonce(), keys.key) catch return error.TlsBadRecordMac;
            keys.seq = std.math.add(u64, keys.seq, 1) catch return error.TlsSequenceOverflow;
            var n = out.len;
            while (n > 0 and out[n - 1] == 0) n -= 1;
            if (n == 0) return error.TlsUnexpectedMessage;
            if (n - 1 > tls.max_ciphertext_inner_record_len) return error.TlsRecordOverflow;
            const inner: tls.ContentType = @enumFromInt(out[n - 1]);
            switch (inner) {
                .alert, .handshake, .application_data => {},
                else => return error.TlsUnexpectedMessage,
            }
            return .{ .content_type = inner, .data = out[0 .. n - 1] };
        },
    }
}

fn rebaseReader(r: *Reader, capacity: usize) void {
    if (r.buffer.len - r.end >= capacity) return;
    const data = r.buffer[r.seek..r.end];
    @memmove(r.buffer[0..data.len], data);
    r.seek = 0;
    r.end = data.len;
    std.debug.assert(r.buffer.len - r.end >= capacity);
}

fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
    _ = w;
    _ = limit;
    const c: *Connection = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize {
    _ = data;
    const c: *Connection = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

/// Decrypt one record into the reader buffer. Application data advances the buffer end.
/// This function processes other content and gives no bytes for it.
fn readIndirect(c: *Connection) Reader.Error!usize {
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
        .application_data => {
            c.reader.end += rec.data.len;
            return 0;
        },
        .alert => {
            if (rec.data.len != 2) return failRead(c, error.TlsDecodeError);
            const alert: tls.Alert = .{ .level = @enumFromInt(rec.data[0]), .description = @enumFromInt(rec.data[1]) };
            c.alert = alert;
            switch (alert.description) {
                .close_notify => {
                    c.received_close_notify = true;
                    return error.EndOfStream;
                },
                .user_canceled => return 0,
                else => return failRead(c, error.TlsAlert),
            }
        },
        .handshake => {
            c.handlePostHandshake(rec.data) catch |e| switch (e) {
                error.WriteFailed => return error.ReadFailed,
                else => |err| return failRead(c, err),
            };
            return 0;
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
            var cleartext: [tls.max_ciphertext_inner_record_len + 1]u8 = undefined;
            while (true) {
                const n: usize = @min(bytes.len - consumed, tls.max_ciphertext_inner_record_len, out.len -| (overhead + written));
                if (n == 0) return .{ .written = written, .consumed = consumed };
                @memcpy(cleartext[0..n], bytes[consumed..][0..n]);
                cleartext[n] = @intFromEnum(content_type);
                consumed += n;
                const inner_len = n + 1;
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
