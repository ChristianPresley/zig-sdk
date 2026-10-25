//! One HTTP/2 connection (RFC 9113) with its streams, for the gRPC binding. A read task
//! runs `run` and dispatches frames. Application tasks send on streams. Server push and
//! priorities are not in use. Flow control applies in both directions.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const frame = @import("frame.zig");
const hpack = @import("hpack/hpack.zig");

const Connection = @This();
pub const Header = hpack.Header;
const log = std.log.scoped(.mcp_http2);

pub const Role = enum { server, client };

pub const Options = struct {
    role: Role,
    /// Streams the peer can have open at the same time. Overflow: `REFUSED_STREAM`.
    max_concurrent_streams: u32 = 128,
    /// The receive window of each stream, advertised as the initial window size.
    initial_window_size: u32 = 1 << 20,
    /// The receive window of the whole connection.
    connection_window: u32 = 4 << 20,
    /// The largest frame the peer can send.
    max_frame_size: u32 = frame.default_max_frame_size,
    /// The largest decoded header list the peer can send. Overflow: `ENHANCE_YOUR_CALM`.
    max_header_list_size: u32 = 8 << 10,
    /// The largest header block under assembly across `CONTINUATION` frames.
    max_header_block_size: u32 = 32 << 10,
    /// Called from the read task when a stream the peer opened has all its request headers.
    /// See also `Stream.dispatchAtEnd`.
    on_stream: ?*const fn (userdata: ?*anyopaque, stream: *Stream) void = null,
    userdata: ?*anyopaque = null,
};

pub const Error = error{
    ReadFailed,
    WriteFailed,
    OutOfMemory,
    /// The connection is closed, or a `GOAWAY` closed it.
    Closed,
    /// The peer reset the stream. The code is in `Stream.reset`.
    StreamReset,
    /// The peer violated the protocol. The connection sent a `GOAWAY` and ended.
    ProtocolError,
} || Io.Cancelable;

/// The errors of the read task. A frame with a wrong length gives `FrameSizeError`
/// (RFC 9113 sections 4.2 and 6).
const ReadError = Error || error{FrameSizeError};

io: Io,
gpa: Allocator,
reader: *Io.Reader,
writer: *Io.Writer,
options: Options,
/// Guards every field below that changes after `init`, and the streams.
lock: Io.Mutex = .init,
/// Serializes writes to the socket.
write_lock: Io.Mutex = .init,
/// The writes that started and did not end. A write increments the count before it takes
/// `write_lock` and decrements it under `write_lock`. Only the write that sets the count to
/// zero flushes. Thus the frames of tasks that write at the same time go out together, in
/// a small number of TCP segments. On Linux the congestion window counts segments, not
/// bytes. With one segment for each frame, 32 calls at the same time used one more round
/// trip.
pending_writes: std.atomic.Value(u32) = .init(0),
/// The read task counts as a pending write while complete frames wait in the read buffer.
/// Thus the answers to a burst of frames go out together. Only the read task uses the field.
read_hold: bool = false,
/// The streams that a burst of frames opened. The read task gives them to `on_stream` at the
/// end of the burst, after the frames with their request data. Thus a handler does not wait
/// for its data, and the handlers of a burst start together. Only the read task uses the field.
held_streams: std.ArrayList(*Stream) = .empty,
/// The number of bursts of frames that the read task read. A burst is the frames that it reads
/// without a wait for the socket. Only the read task uses the field. See `burst`.
bursts: u32 = 0,
decoder: hpack.Decoder,
encoder: hpack.Encoder = .{},
peer: frame.Settings = .{},
streams: std.AutoHashMapUnmanaged(u31, *Stream) = .empty,
next_stream_id: u31,
last_peer_stream_id: u31 = 0,
peer_streams_open: u32 = 0,
/// The streams that `Stream.dispatchAtEnd` keeps from their owner. Guarded by `lock`.
unowned_streams: u32 = 0,
/// Bytes we can still send on the connection.
send_window: i64 = frame.default_initial_window,
/// Bytes the peer can still send on the connection.
recv_window: i64,
/// Consumed bytes that the connection did not credit to the peer yet.
recv_credit: u32 = 0,
closed: bool = false,
goaway_received: bool = false,
goaway_sent: bool = false,
frame_buf: []u8,
hb_active: bool = false,
hb_stream: u31 = 0,
hb_flags: u8 = 0,
hb_buf: std.ArrayList(u8) = .empty,
/// The ids of the last peer streams that this side reset. The next id goes to the index
/// `reset_ids_next % remembered_resets`.
reset_ids: [remembered_resets]u31 = @splat(0),
reset_ids_next: usize = 0,

/// The number of peer streams with a reset from this side that the connection remembers. The
/// peer can send frames on such a stream before it sees the reset. The connection ignores a
/// header block on a remembered stream (RFC 9113 section 5.1). For an older stream, the block
/// ends the connection, as for a stream id that the peer must not use.
pub const remembered_resets = 64;

pub fn init(gpa: Allocator, io: Io, reader: *Io.Reader, writer: *Io.Writer, options: Options) Allocator.Error!*Connection {
    const self = try gpa.create(Connection);
    errdefer gpa.destroy(self);
    const frame_buf = try gpa.alloc(u8, options.max_frame_size);
    errdefer gpa.free(frame_buf);
    self.* = .{
        .io = io,
        .gpa = gpa,
        .reader = reader,
        .writer = writer,
        .options = options,
        .decoder = .init(gpa, .{ .max_header_list_size = options.max_header_list_size }),
        .next_stream_id = if (options.role == .client) 1 else 2,
        .recv_window = frame.default_initial_window,
        .frame_buf = frame_buf,
    };
    return self;
}

/// Free everything. Every stream must be closed by its owner first.
pub fn deinit(self: *Connection) void {
    var it = self.streams.valueIterator();
    while (it.next()) |s| s.*.destroy();
    self.streams.deinit(self.gpa);
    self.decoder.deinit();
    self.hb_buf.deinit(self.gpa);
    self.held_streams.deinit(self.gpa);
    self.gpa.free(self.frame_buf);
    self.gpa.destroy(self);
}

/// Exchange the connection preface and our settings. The peer settings arrive in `run`.
pub fn handshake(self: *Connection) Error!void {
    if (self.options.role == .server) {
        const got = self.reader.takeArray(frame.preface.len) catch return error.ReadFailed;
        if (!std.mem.eql(u8, got, frame.preface)) return error.ProtocolError;
    } else {
        self.writer.writeAll(frame.preface) catch return error.WriteFailed;
    }
    var settings: [6 * 6]u8 = undefined;
    const list = [_]frame.Setting{
        .{ .id = @intFromEnum(frame.SettingId.header_table_size), .value = 4096 },
        .{ .id = @intFromEnum(frame.SettingId.enable_push), .value = 0 },
        .{ .id = @intFromEnum(frame.SettingId.max_concurrent_streams), .value = self.options.max_concurrent_streams },
        .{ .id = @intFromEnum(frame.SettingId.initial_window_size), .value = self.options.initial_window_size },
        .{ .id = @intFromEnum(frame.SettingId.max_frame_size), .value = self.options.max_frame_size },
        .{ .id = @intFromEnum(frame.SettingId.max_header_list_size), .value = self.options.max_header_list_size },
    };
    for (list, 0..) |s, i| settings[i * 6 ..][0..6].* = s.encode();
    // Raise the connection window from the default to ours. The two frames go out together.
    const raise = self.options.connection_window > frame.default_initial_window;
    try self.writeFrameFlush(.settings, 0, 0, &settings, !raise);
    if (raise) {
        const increment = self.options.connection_window - frame.default_initial_window;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, increment, .big);
        try self.writeFrame(.window_update, 0, 0, &payload);
        self.recv_window = self.options.connection_window;
    }
}

/// Read and dispatch frames until the peer closes the connection or breaks the protocol.
pub fn run(self: *Connection) void {
    _ = self.runUntilIdle(null);
}

/// The calls of `runUntilIdle` to the owner of the connection.
pub const IdleHooks = struct {
    userdata: ?*anyopaque,
    /// Called before a read of the socket while the connection is idle and the read buffer is
    /// empty. True ends the read: see `runUntilIdle`.
    idle: *const fn (userdata: ?*anyopaque) bool,
    /// Called before each other read of the socket that can wait: no complete frame is in the
    /// read buffer. For example, the connection has open streams, or a part of a frame came.
    waiting: *const fn (userdata: ?*anyopaque) void,
    /// Called after the read that followed a call of `idle` or `waiting` gave a frame.
    resumed: *const fn (userdata: ?*anyopaque) void,
};

/// The open streams with an owner. A stream that `Stream.dispatchAtEnd` keeps does not count.
/// Safe from any task.
pub fn ownedStreams(self: *Connection) usize {
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    return self.streams.count() - self.unowned_streams;
}

/// The end of `runUntilIdle`.
pub const Exit = enum {
    /// The connection ended. The read task has nothing more to do.
    closed,
    /// `on_idle` ended the read. The connection stays open, and a later call of
    /// `runUntilIdle` continues it.
    idle,
};

/// As `run`, but before each read of the socket with an empty read buffer while the
/// connection is idle, call `hooks.idle`. Idle means: no open stream with an owner, no header
/// block under assembly and no held stream. When `hooks.idle` gives true, the function returns `.idle`,
/// and no task reads the connection. The owner can then watch the socket without a task, and
/// call the function again when bytes arrive.
pub fn runUntilIdle(self: *Connection, hooks: ?IdleHooks) Exit {
    while (true) {
        var waited = false;
        // The read can wait for the socket: no complete frame is in the read buffer. A part of
        // a frame can wait there, and the rest can come late or never.
        if (hooks) |h| if (!self.frameBuffered()) {
            if (self.reader.bufferedLen() == 0 and self.isIdle()) {
                if (h.idle(h.userdata)) return .idle;
            } else {
                h.waiting(h.userdata);
            }
            waited = true;
        };
        self.readFrame() catch |e| {
            switch (e) {
                error.ProtocolError => self.sendGoaway(.protocol_error),
                error.FrameSizeError => self.sendGoaway(.frame_size_error),
                error.OutOfMemory => self.sendGoaway(.internal_error),
                else => {},
            }
            break;
        };
        if (waited) hooks.?.resumed(hooks.?.userdata);
    }
    self.setReadHold(false);
    self.terminate();
    return .closed;
}

/// The connection has no open stream with an owner and no partial header block, and the read
/// task holds no stream. A stream that waits for its request data (`Stream.dispatchAtEnd`)
/// has no owner: only the read task uses it. Only the read task calls this function.
fn isIdle(self: *Connection) bool {
    if (self.hb_active or self.read_hold or self.held_streams.items.len > 0) return false;
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    return !self.closed and self.streams.count() == self.unowned_streams;
}

/// The end of the hold of the read task flushes after each group of this many held streams.
/// The answers of a group then go out together, and an answer waits for the start of at most
/// this many other streams. On Linux a new connection can send 10 segments before the first
/// acknowledgment. Thus 8 keeps the answers of a large burst in a small number of segments.
/// With one flush for the whole burst, the median latency under a load of 64 calls was up to
/// 5 ms higher.
pub const held_streams_per_flush = 8;

/// Start or end the hold of the read task. See `read_hold`. The read task never holds while
/// it waits for the socket. The end of the hold gives the held streams to `on_stream` and
/// flushes after each `held_streams_per_flush` of them.
fn setReadHold(self: *Connection, hold: bool) void {
    if (hold == self.read_hold) return;
    self.read_hold = hold;
    if (hold) {
        self.beginWrite();
        return;
    }
    const held = self.held_streams.items;
    for (held, 1..) |s, i| {
        self.dispatch(s);
        if (i % held_streams_per_flush == 0 and i < held.len) {
            self.write_lock.lockUncancelable(self.io);
            self.endWriteLocked(true) catch {};
            self.write_lock.unlock(self.io);
            self.beginWrite();
        }
    }
    self.held_streams.clearRetainingCapacity();
    self.write_lock.lockUncancelable(self.io);
    defer self.write_lock.unlock(self.io);
    self.endWriteLocked(true) catch {};
}

/// The read buffer has one more complete frame.
pub fn frameBuffered(self: *Connection) bool {
    const buffered = self.reader.buffered();
    if (buffered.len < frame.header_len) return false;
    const header = frame.Header.parse(buffered[0..frame.header_len]);
    return buffered.len - frame.header_len >= header.length;
}

/// Send `GOAWAY` and accept no new streams. Existing streams finish. The read task
/// continues until the peer closes.
pub fn shutdown(self: *Connection) void {
    self.sendGoaway(.no_error);
}

fn terminate(self: *Connection) void {
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    self.closed = true;
    var it = self.streams.valueIterator();
    while (it.next()) |s| {
        s.*.conn_closed = true;
        s.*.cond.broadcast(self.io);
        s.*.notifyReset();
    }
}

pub fn isClosed(self: *Connection) bool {
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    return self.closed;
}

// -- Writing ---------------------------------------------------------------------------------

fn writeFrame(self: *Connection, kind: frame.Type, flags: u8, stream_id: u31, payload: []const u8) Error!void {
    return self.writeFrameFlush(kind, flags, stream_id, payload, true);
}

/// Write one frame. With `flush` false, the frame stays in the buffer until the next write
/// that flushes. See `pending_writes`.
fn writeFrameFlush(self: *Connection, kind: frame.Type, flags: u8, stream_id: u31, payload: []const u8, flush: bool) Error!void {
    self.beginWrite();
    self.write_lock.lockUncancelable(self.io);
    defer self.write_lock.unlock(self.io);
    const written = self.writeFrameLocked(kind, flags, stream_id, payload);
    try self.endWriteLocked(flush);
    return written;
}

/// Count a write that starts. Call before `write_lock`.
fn beginWrite(self: *Connection) void {
    _ = self.pending_writes.fetchAdd(1, .acq_rel);
}

/// Count a write that ended. Called under `write_lock`. When no other write is pending and
/// `flush` is true, flush the buffer.
fn endWriteLocked(self: *Connection, flush: bool) Error!void {
    const last = self.pending_writes.fetchSub(1, .acq_rel) == 1;
    if (last and flush) self.writer.flush() catch return error.WriteFailed;
}

/// Flush the buffer when no write is pending. A pending write flushes when it ends.
fn flushPending(self: *Connection) Error!void {
    self.beginWrite();
    self.write_lock.lockUncancelable(self.io);
    defer self.write_lock.unlock(self.io);
    try self.endWriteLocked(true);
}

fn writeFrameLocked(self: *Connection, kind: frame.Type, flags: u8, stream_id: u31, payload: []const u8) Error!void {
    const header: frame.Header = .{ .length = @intCast(payload.len), .type = kind, .flags = flags, .stream_id = stream_id };
    self.writer.writeAll(&header.encode()) catch return error.WriteFailed;
    self.writer.writeAll(payload) catch return error.WriteFailed;
}

fn sendGoaway(self: *Connection, code: frame.ErrorCode) void {
    self.lock.lockUncancelable(self.io);
    if (self.goaway_sent) {
        self.lock.unlock(self.io);
        return;
    }
    self.goaway_sent = true;
    const last = self.last_peer_stream_id;
    self.lock.unlock(self.io);
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], last, .big);
    std.mem.writeInt(u32, payload[4..8], @intFromEnum(code), .big);
    self.writeFrame(.goaway, 0, 0, &payload) catch {};
}

fn sendRst(self: *Connection, stream_id: u31, code: frame.ErrorCode) void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, @intFromEnum(code), .big);
    self.writeFrame(.rst_stream, 0, stream_id, &payload) catch {};
}

fn sendWindowUpdate(self: *Connection, stream_id: u31, increment: u32) void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment, .big);
    self.writeFrame(.window_update, 0, stream_id, &payload) catch {};
}

/// Send a `PING`. The function `run` receives the answer.
pub fn ping(self: *Connection, data: [8]u8) Error!void {
    try self.writeFrame(.ping, 0, 0, &data);
}

// -- Reading ---------------------------------------------------------------------------------

fn readFrame(self: *Connection) ReadError!void {
    // Without the hold, the last frame ended a burst, thus this frame starts the next one.
    if (!self.read_hold) self.bursts +%= 1;
    const header_bytes = self.reader.takeArray(frame.header_len) catch |e| switch (e) {
        error.EndOfStream => return error.Closed,
        error.ReadFailed => return error.ReadFailed,
    };
    const header = frame.Header.parse(header_bytes);
    if (header.length > self.options.max_frame_size) return error.FrameSizeError;
    const payload = self.frame_buf[0..header.length];
    self.reader.readSliceAll(payload) catch |e| switch (e) {
        error.EndOfStream => return error.Closed,
        error.ReadFailed => return error.ReadFailed,
    };
    // The hold ends after the last frame of the burst, thus the streams of that frame are
    // also held.
    const more = self.frameBuffered();
    if (more) self.setReadHold(true);
    defer if (!more) self.setReadHold(false);
    // A header block under assembly allows only its CONTINUATION frames.
    if (self.hb_active and (header.type != .continuation or header.stream_id != self.hb_stream)) return error.ProtocolError;
    switch (header.type) {
        .data => try self.onData(header, payload),
        .headers => try self.onHeaders(header, payload),
        .continuation => try self.onContinuation(header, payload),
        .priority => {
            if (header.stream_id == 0) return error.ProtocolError;
            if (header.length != 5) return error.FrameSizeError;
        },
        .rst_stream => try self.onRstStream(header, payload),
        .settings => try self.onSettings(header, payload),
        .push_promise => return error.ProtocolError,
        .ping => {
            if (header.stream_id != 0) return error.ProtocolError;
            if (header.length != 8) return error.FrameSizeError;
            if (!header.has(frame.Flags.ack)) try self.writeFrame(.ping, frame.Flags.ack, 0, payload);
        },
        .goaway => try self.onGoaway(header, payload),
        .window_update => try self.onWindowUpdate(header, payload),
        _ => {}, // unknown frame types are ignored
    }
}

fn onData(self: *Connection, header: frame.Header, payload: []const u8) Error!void {
    if (header.stream_id == 0) return error.ProtocolError;
    var data = payload;
    if (header.has(frame.Flags.padded)) {
        if (data.len == 0) return error.ProtocolError;
        const pad = data[0];
        if (pad >= data.len) return error.ProtocolError;
        data = data[1 .. data.len - pad];
    }
    var reply_conn_update: ?u32 = null;
    var reset: ?frame.ErrorCode = null;
    // A stream that `Stream.dispatchAtEnd` kept from its owner: it is complete now, or the
    // connection frees it after a reset.
    var ready: ?*Stream = null;
    var dropped: ?*Stream = null;
    {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        // The whole frame counts against the connection window, also for unknown streams.
        self.recv_window -= @intCast(header.length);
        if (self.recv_window < 0) return error.ProtocolError;
        self.recv_credit += header.length;
        if (self.recv_credit >= self.options.connection_window / 2) {
            reply_conn_update = self.recv_credit;
            self.recv_window += self.recv_credit;
            self.recv_credit = 0;
        }
        if (self.streams.get(header.stream_id)) |stream| {
            if (stream.end_stream or stream.reset != null) {
                reset = .stream_closed;
            } else {
                stream.recv_window -= @intCast(header.length);
                if (stream.recv_window < 0) {
                    reset = .flow_control_error;
                    stream.setReset(.flow_control_error);
                    if (stream.undispatched) dropped = self.dropLocked(stream);
                } else {
                    try stream.data.appendSlice(self.gpa, data);
                    if (header.has(frame.Flags.end_stream)) stream.end_stream = true;
                    stream.cond.broadcast(self.io);
                    if (stream.undispatched and (stream.end_stream or stream.data.items.len >= self.options.initial_window_size / 2)) {
                        stream.undispatched = false;
                        self.unowned_streams -= 1;
                        ready = stream;
                    }
                }
            }
        } else if (header.stream_id > self.last_peer_stream_id and self.options.role == .server) {
            return error.ProtocolError; // data on a stream that was never opened
        }
    }
    if (reply_conn_update) |inc| self.sendWindowUpdate(0, inc);
    if (reset) |code| self.sendRst(header.stream_id, code);
    if (dropped) |s| s.destroy();
    if (ready) |s| self.handOver(s);
}

fn onHeaders(self: *Connection, header: frame.Header, payload: []const u8) Error!void {
    if (header.stream_id == 0) return error.ProtocolError;
    var block = payload;
    if (header.has(frame.Flags.padded)) {
        if (block.len == 0) return error.ProtocolError;
        const pad = block[0];
        if (pad >= block.len) return error.ProtocolError;
        block = block[1 .. block.len - pad];
    }
    if (header.has(frame.Flags.priority)) {
        if (block.len < 5) return error.ProtocolError;
        block = block[5..];
    }
    self.hb_buf.clearRetainingCapacity();
    try self.hb_buf.appendSlice(self.gpa, block);
    self.hb_stream = header.stream_id;
    self.hb_flags = header.flags;
    if (header.has(frame.Flags.end_headers)) {
        try self.finishHeaderBlock();
    } else {
        self.hb_active = true;
    }
}

fn onContinuation(self: *Connection, header: frame.Header, payload: []const u8) Error!void {
    if (!self.hb_active or header.stream_id != self.hb_stream) return error.ProtocolError;
    if (self.hb_buf.items.len + payload.len > self.options.max_header_block_size) return error.ProtocolError;
    try self.hb_buf.appendSlice(self.gpa, payload);
    if (header.has(frame.Flags.end_headers)) {
        self.hb_active = false;
        try self.finishHeaderBlock();
    }
}

/// Decode the assembled block and hand it to the stream: request headers, response
/// headers or trailers.
fn finishHeaderBlock(self: *Connection) Error!void {
    const stream_id = self.hb_stream;
    const end_stream = self.hb_flags & frame.Flags.end_stream != 0;
    // The stream that this block opens. It goes to `on_stream`, or it is refused and freed.
    var opened: ?*Stream = null;
    var new_stream: ?*Stream = null;
    var refused: ?*Stream = null;
    var reset: ?frame.ErrorCode = null;
    // The trailers completed a stream that `Stream.dispatchAtEnd` kept from its owner.
    var ready: ?*Stream = null;
    {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        var stream = self.streams.get(stream_id);
        if (stream == null) {
            if (self.options.role != .server or stream_id % 2 == 0 or stream_id <= self.last_peer_stream_id) {
                // A response for a stream we do not know, a block on a stream that this side
                // reset, or a bad id: decode to keep the HPACK state in sync, then ignore or
                // refuse. The peer can send a block before it sees the reset (section 5.1).
                try self.decodeDiscard();
                if (self.options.role == .server and !self.wasResetHere(stream_id)) return error.ProtocolError;
                return;
            }
            self.last_peer_stream_id = stream_id;
            if (self.goaway_sent or self.peer_streams_open >= self.options.max_concurrent_streams) {
                try self.decodeDiscard();
                reset = .refused_stream;
                self.rememberReset(stream_id);
            } else {
                const s = try Stream.create(self, stream_id);
                errdefer s.destroy();
                try self.streams.put(self.gpa, stream_id, s);
                self.peer_streams_open += 1;
                stream = s;
                opened = s;
            }
        }
        if (stream) |s| decoded: {
            const arena = s.arena_state.allocator();
            var list: std.ArrayList(Header) = .empty;
            self.decoder.decode(arena, self.hb_buf.items, &list) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.HeaderListTooLarge, error.FieldTooLarge => {
                    // The reset goes out after the unlock, as on the other paths. The write
                    // lock comes before `lock` (see `sendHeaders`).
                    reset = .enhance_your_calm;
                    s.setReset(.enhance_your_calm);
                    // Trailers over the limit on a stream without an owner yet.
                    if (s.undispatched and opened == null) refused = self.dropLocked(s);
                    break :decoded;
                },
                else => return error.ProtocolError, // a compression error ends the connection
            };
            if (s.end_stream or s.reset != null) {
                reset = .stream_closed;
            } else if (!s.headers_done) {
                if (!validHeaders(list.items, false, self.options.role)) {
                    reset = .protocol_error;
                    s.setReset(.protocol_error);
                } else {
                    s.headers = list;
                    s.headers_done = true;
                    if (end_stream) s.end_stream = true;
                }
            } else {
                if (!validHeaders(list.items, true, self.options.role) or !end_stream) {
                    reset = .protocol_error;
                    s.setReset(.protocol_error);
                } else {
                    s.trailers = list;
                    s.trailers_done = true;
                    s.end_stream = true;
                }
            }
            s.cond.broadcast(self.io);
            if (s.undispatched and opened == null) {
                if (s.reset != null) {
                    refused = self.dropLocked(s);
                } else if (s.end_stream) {
                    s.undispatched = false;
                    self.unowned_streams -= 1;
                    ready = s;
                }
            }
        }
        // A stream that this block opened and refused gets no owner, because `on_stream` does
        // not run. Thus the connection frees it, as for `REFUSED_STREAM`. Else the stream counts
        // against `max_concurrent_streams` until the connection ends.
        if (opened) |s| {
            if (s.reset != null) {
                _ = self.streams.remove(stream_id);
                self.peer_streams_open -= 1;
                self.rememberReset(stream_id);
                refused = s;
            } else {
                new_stream = s;
            }
        }
    }
    self.hb_buf.clearRetainingCapacity();
    if (refused) |s| s.destroy();
    if (reset) |code| self.sendRst(stream_id, code);
    if (new_stream) |s| self.handOver(s);
    if (ready) |s| self.handOver(s);
}

/// Give a stream that the peer opened to `on_stream`, at once or at the end of the hold of
/// the read task. See `held_streams`.
fn handOver(self: *Connection, s: *Stream) void {
    if (!self.read_hold) return self.dispatch(s);
    self.held_streams.append(self.gpa, s) catch self.dispatch(s);
}

/// The number of the burst of frames that the read task reads now. The streams of a burst go
/// to `on_stream` with the same number. Only `on_stream` calls this function.
pub fn burst(self: *const Connection) u32 {
    return self.bursts;
}

/// Give a stream that the peer opened to `on_stream`.
fn dispatch(self: *Connection, s: *Stream) void {
    if (self.options.on_stream) |f| f(self.options.userdata, s);
}

/// Unregister a stream that has no owner yet, after its reset. Called under `lock`. The
/// caller frees the stream after the unlock.
fn dropLocked(self: *Connection, s: *Stream) *Stream {
    s.undispatched = false;
    self.unowned_streams -= 1;
    _ = self.streams.remove(s.id);
    self.peer_streams_open -|= 1;
    self.rememberReset(s.id);
    return s;
}

/// Remember `id`, a peer stream that this side reset. Called under `lock`.
fn rememberReset(self: *Connection, id: u31) void {
    self.reset_ids[self.reset_ids_next % remembered_resets] = id;
    self.reset_ids_next +%= 1;
}

/// This side reset the peer stream `id`, and the connection still remembers it. Called under
/// `lock`. No stream has the id 0, thus the empty places do not match.
fn wasResetHere(self: *const Connection, id: u31) bool {
    return std.mem.findScalar(u31, &self.reset_ids, id) != null;
}

/// Decode a block that goes nowhere, to keep the dynamic table in sync.
fn decodeDiscard(self: *Connection) Error!void {
    var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
    defer arena_state.deinit();
    var list: std.ArrayList(Header) = .empty;
    self.decoder.decode(arena_state.allocator(), self.hb_buf.items, &list) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HeaderListTooLarge, error.FieldTooLarge => {},
        else => return error.ProtocolError,
    };
}

/// The header field rules of RFC 9113 section 8.
fn validHeaders(headers: []const Header, trailers: bool, role: Role) bool {
    var pseudo_done = false;
    var has_method = false;
    var has_scheme = false;
    var has_path = false;
    var has_status = false;
    for (headers) |h| {
        if (h.name.len == 0) return false;
        for (h.name) |c| if (std.ascii.isUpper(c) or c == ' ' or c == 0) return false;
        if (h.name[0] == ':') {
            if (pseudo_done or trailers) return false;
            if (std.mem.eql(u8, h.name, ":method")) {
                if (has_method) return false;
                has_method = true;
            } else if (std.mem.eql(u8, h.name, ":scheme")) {
                if (has_scheme) return false;
                has_scheme = true;
            } else if (std.mem.eql(u8, h.name, ":path")) {
                if (has_path or h.value.len == 0) return false;
                has_path = true;
            } else if (std.mem.eql(u8, h.name, ":authority")) {} else if (std.mem.eql(u8, h.name, ":status")) {
                if (has_status) return false;
                has_status = true;
            } else return false;
            continue;
        }
        pseudo_done = true;
        for (h.value) |c| if (c == 0 or c == '\r' or c == '\n') return false;
        if (std.mem.eql(u8, h.name, "connection") or std.mem.eql(u8, h.name, "transfer-encoding") or std.mem.eql(u8, h.name, "upgrade") or std.mem.eql(u8, h.name, "keep-alive") or std.mem.eql(u8, h.name, "proxy-connection")) return false;
        if (std.mem.eql(u8, h.name, "te") and !std.mem.eql(u8, h.value, "trailers")) return false;
    }
    if (trailers) return true;
    return switch (role) {
        .server => has_method and has_scheme and has_path and !has_status,
        .client => has_status and !has_method and !has_scheme and !has_path,
    };
}

fn onRstStream(self: *Connection, header: frame.Header, payload: []const u8) ReadError!void {
    if (header.stream_id == 0) return error.ProtocolError;
    if (header.length != 4) return error.FrameSizeError;
    const code: frame.ErrorCode = @enumFromInt(std.mem.readInt(u32, payload[0..4], .big));
    var dropped: ?*Stream = null;
    defer if (dropped) |s| s.destroy();
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    if (self.streams.get(header.stream_id)) |s| {
        s.setReset(code);
        // A stream without an owner: no task closes it.
        if (s.undispatched) dropped = self.dropLocked(s);
    } else if (self.options.role == .server and header.stream_id > self.last_peer_stream_id) {
        return error.ProtocolError;
    }
}

fn onSettings(self: *Connection, header: frame.Header, payload: []const u8) ReadError!void {
    if (header.stream_id != 0) return error.ProtocolError;
    if (header.has(frame.Flags.ack)) {
        if (header.length != 0) return error.FrameSizeError;
        return;
    }
    if (header.length % 6 != 0) return error.FrameSizeError;
    {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        var i: usize = 0;
        while (i < payload.len) : (i += 6) {
            const setting: frame.Setting = .{ .id = std.mem.readInt(u16, payload[i..][0..2], .big), .value = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big) };
            const old_window = self.peer.initial_window_size;
            self.peer.apply(setting) catch return error.ProtocolError;
            if (@as(frame.SettingId, @enumFromInt(setting.id)) == .initial_window_size) {
                // The change applies to every open stream (section 6.9.2).
                const delta: i64 = @as(i64, self.peer.initial_window_size) - @as(i64, old_window);
                var it = self.streams.valueIterator();
                while (it.next()) |s| {
                    s.*.send_window += delta;
                    if (s.*.send_window > frame.max_window) return error.ProtocolError;
                    // A larger window gives credit to a send that waits.
                    if (delta > 0) s.*.cond.broadcast(self.io);
                }
            }
        }
    }
    try self.writeFrame(.settings, frame.Flags.ack, 0, &.{});
}

fn onGoaway(self: *Connection, header: frame.Header, payload: []const u8) Error!void {
    if (header.stream_id != 0 or header.length < 8) return error.ProtocolError;
    const last: u31 = @truncate(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
    const code: frame.ErrorCode = @enumFromInt(std.mem.readInt(u32, payload[4..8], .big));
    if (code != .no_error) log.warn("peer sent GOAWAY with {t}", .{code});
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    self.goaway_received = true;
    // Streams the peer never processed are lost.
    var it = self.streams.valueIterator();
    while (it.next()) |s| if (s.*.id > last and s.*.id % 2 == (if (self.options.role == .client) @as(u31, 1) else 0)) {
        s.*.setReset(.refused_stream);
    };
}

fn onWindowUpdate(self: *Connection, header: frame.Header, payload: []const u8) ReadError!void {
    if (header.length != 4) return error.FrameSizeError;
    const increment = std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff;
    if (increment == 0) {
        if (header.stream_id == 0) return error.ProtocolError;
        self.sendRst(header.stream_id, .protocol_error);
        return;
    }
    // A stream without an owner after its reset. It is freed after the unlock.
    var dropped: ?*Stream = null;
    defer if (dropped) |s| s.destroy();
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    if (header.stream_id == 0) {
        self.send_window += increment;
        if (self.send_window > frame.max_window) return error.ProtocolError;
        // The credit of the connection can continue a send on each stream.
        var it = self.streams.valueIterator();
        while (it.next()) |s| s.*.cond.broadcast(self.io);
    } else if (self.streams.get(header.stream_id)) |s| {
        s.send_window += increment;
        if (s.send_window > frame.max_window) {
            s.setReset(.flow_control_error);
            if (s.undispatched) dropped = self.dropLocked(s);
            self.lock.unlock(self.io);
            self.sendRst(header.stream_id, .flow_control_error);
            self.lock.lockUncancelable(self.io);
        } else {
            s.cond.broadcast(self.io);
        }
    }
}

// -- Streams ---------------------------------------------------------------------------------

/// Open a stream to the peer. The connection gives the id when the first header block goes
/// out, so that ids increase in wire order (section 5.1.1).
pub fn openStream(self: *Connection) Error!*Stream {
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    if (self.closed or self.goaway_received) return error.Closed;
    return Stream.create(self, 0);
}

/// Assign the next id and register the stream. Called under `write_lock`. A stream that got a
/// reset before this call gets no id, and its headers do not go out.
fn assignId(self: *Connection, s: *Stream) Error!void {
    self.lock.lockUncancelable(self.io);
    defer self.lock.unlock(self.io);
    if (self.closed or self.goaway_received) return error.Closed;
    // A `cancel` from another task before the id sends no reset, thus the peer must not see the
    // stream at all.
    try s.checkOpen();
    if (self.next_stream_id > frame.max_window - 2) return error.Closed;
    s.id = self.next_stream_id;
    try self.streams.put(self.gpa, s.id, s);
    self.next_stream_id += 2;
}

pub const Stream = struct {
    conn: *Connection,
    id: u31,
    arena_state: std.heap.ArenaAllocator,
    /// Signaled at each change of the stream: data, headers, trailers, a reset, `stopWaits` and
    /// more credit to send. The end of the connection also signals it. A change on another
    /// stream does not wake the waits on this stream.
    cond: Io.Condition = .init,
    /// The request or response headers, in the stream arena.
    headers: std.ArrayList(Header) = .empty,
    headers_done: bool = false,
    trailers: std.ArrayList(Header) = .empty,
    trailers_done: bool = false,
    data: std.ArrayList(u8) = .empty,
    read_pos: usize = 0,
    /// The peer sent END_STREAM.
    end_stream: bool = false,
    reset: ?frame.ErrorCode = null,
    conn_closed: bool = false,
    /// We sent END_STREAM.
    local_closed: bool = false,
    /// A call to `stopWaits` came. Each wait on the stream then gives `error.Canceled`.
    waits_stopped: bool = false,
    /// The hook of the owner. See `setOnReset`.
    on_reset: ?ResetHook = null,
    on_reset_userdata: ?*anyopaque = null,
    /// The hook ran. It runs once for the stream.
    reset_notified: bool = false,
    send_window: i64,
    recv_window: i64,
    recv_credit: u32 = 0,
    /// See `cork`. Only the task that sends on the stream uses the field.
    corked: bool = false,
    /// `dispatchAtEnd` keeps the stream from `on_stream`. Changed under `lock` by the read
    /// task only.
    undispatched: bool = false,

    fn create(conn: *Connection, id: u31) Allocator.Error!*Stream {
        const s = try conn.gpa.create(Stream);
        s.* = .{
            .conn = conn,
            .id = id,
            .arena_state = .init(conn.gpa),
            .send_window = conn.peer.initial_window_size,
            .recv_window = conn.options.initial_window_size,
        };
        return s;
    }

    fn destroy(self: *Stream) void {
        self.data.deinit(self.conn.gpa);
        self.arena_state.deinit();
        self.conn.gpa.destroy(self);
    }

    /// The stream arena, for the owner's own allocations.
    pub fn arena(self: *Stream) Allocator {
        return self.arena_state.allocator();
    }

    /// Unregister and free the stream. A stream the peer still has open is reset. After a
    /// complete response, the server resets with `no_error`, thus the client stops the request
    /// and keeps the response (RFC 9113 section 8.1). Other streams get `cancel`.
    pub fn close(self: *Stream) void {
        const conn = self.conn;
        var send_reset: ?frame.ErrorCode = null;
        {
            conn.lock.lockUncancelable(conn.io);
            defer conn.lock.unlock(conn.io);
            if (self.id != 0) {
                if (!self.end_stream and self.reset == null and !conn.closed) {
                    send_reset = if (conn.options.role == .server and self.local_closed) .no_error else .cancel;
                }
                if (conn.streams.remove(self.id) and self.id % 2 != (if (conn.options.role == .client) @as(u31, 1) else 0)) {
                    conn.peer_streams_open -|= 1;
                    // After a reset, the peer can still send frames on the stream.
                    if (send_reset != null or self.reset != null) conn.rememberReset(self.id);
                }
            }
        }
        if (send_reset) |code| conn.sendRst(self.id, code);
        self.destroy();
    }

    /// Reset the stream with `cancel`. Each task that waits on the stream wakes and sees the
    /// reset. The owner still calls `close`.
    pub fn cancel(self: *Stream) void {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        const already = self.reset != null or conn.closed or self.id == 0;
        self.setReset(.cancel);
        // A waiter can close the stream when it wakes, thus keep the id for the reset frame.
        const id = self.id;
        conn.lock.unlock(conn.io);
        if (!already) conn.sendRst(id, .cancel);
    }

    /// Stop the waits on the stream and send no reset. Each task that waits on the stream wakes
    /// and gets `error.Canceled`. A later wait also gets `error.Canceled` when it must block. The
    /// owner still calls `close`.
    ///
    /// To stop a task that waits on the stream, use this function, not `Future.cancel`. The
    /// condition of std can lose a cancel that comes together with a wake-up of the stream.
    /// The task then waits until the stream gets a reset or the connection ends.
    pub fn stopWaits(self: *Stream) void {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        self.waits_stopped = true;
        self.cond.broadcast(conn.io);
    }

    /// The hook of `setOnReset`.
    pub const ResetHook = *const fn (userdata: ?*anyopaque, stream: *Stream) void;

    /// Set the hook that the connection calls when the stream gets a reset or when the
    /// connection ends. The reset can come from the peer, from this side or from `cancel`. The
    /// hook runs once for the stream. When the stream already has a reset, or the connection
    /// already ended, the hook runs at once, in the task of the caller.
    ///
    /// Null removes the hook, and the hook then does not run. Remove the hook before its data
    /// goes out of scope. The hook does not run after `close`.
    ///
    /// The connection calls the hook under its lock, in the read task or in the task that
    /// called `cancel`. Thus the hook must not take the lock: it must not call a function of
    /// the stream or of the connection. It can read the fields of the stream. Set a flag or
    /// wake a task in the hook, and do the work in that task. A stream that has no id yet
    /// gets no call at the end of the connection.
    pub fn setOnReset(self: *Stream, hook: ?ResetHook, userdata: ?*anyopaque) void {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        self.on_reset = hook;
        self.on_reset_userdata = userdata;
        if (self.reset != null or self.conn_closed or conn.closed) self.notifyReset();
    }

    /// Run the hook of the owner, once. Called under `lock`.
    fn notifyReset(self: *Stream) void {
        const hook = self.on_reset orelse return;
        if (self.reset_notified) return;
        self.reset_notified = true;
        hook(self.on_reset_userdata, self);
    }

    /// Give the stream the reset `code` when it has none, wake its waits and run the hook of
    /// the owner. Called under `lock`.
    fn setReset(self: *Stream, code: frame.ErrorCode) void {
        if (self.reset == null) self.reset = code;
        self.cond.broadcast(self.conn.io);
        self.notifyReset();
    }

    /// Wait for the next change of the stream. Gives `error.Canceled` after `stopWaits`.
    /// Called under `lock`. The caller checks its condition again after each wake-up.
    fn wait(self: *Stream) Error!void {
        if (self.waits_stopped) return error.Canceled;
        const conn = self.conn;
        try self.cond.wait(conn.io, &conn.lock);
    }

    fn checkOpen(self: *const Stream) Error!void {
        if (self.reset) |code| return if (code == .refused_stream) error.Closed else error.StreamReset;
        if (self.conn_closed or self.conn.closed) return error.Closed;
    }

    /// The peer ended the stream, thus the response is complete. Then the stream got a reset
    /// from the peer or from this side, with any code. Thus the client drops the remaining part
    /// of the request (RFC 9113 section 8.1), and the response stays available. This applies
    /// only to the client. On the server, the same state tells that the client canceled.
    fn answered(self: *const Stream) bool {
        return self.conn.options.role == .client and self.end_stream and self.reset != null;
    }

    /// Keep the frames of the next sends in the buffer of the connection. Then `uncork` sends
    /// them together, for example the headers, the data and the trailers of one response. A
    /// send that waits for flow control credit first flushes the frames. A write of another
    /// task can also flush them. Call `uncork` soon, because the frames of other streams can
    /// also wait for it. Only the task that sends on the stream calls this function.
    pub fn cork(self: *Stream) void {
        self.corked = true;
    }

    /// End `cork` and send the frames that are in the buffer.
    pub fn uncork(self: *Stream) Error!void {
        if (!self.corked) return;
        self.corked = false;
        try self.conn.flushPending();
    }

    /// Send a header block. With `end_stream` no data follows. When the server already sent a
    /// complete response and the stream then got a reset, the client sends nothing and gets no
    /// error.
    pub fn sendHeaders(self: *Stream, headers: []const Header, end_stream: bool) Error!void {
        const conn = self.conn;
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(conn.gpa);
        try conn.encoder.encodeHeaders(conn.gpa, &block, headers);
        {
            conn.lock.lockUncancelable(conn.io);
            defer conn.lock.unlock(conn.io);
            if (self.answered()) {
                self.local_closed = true;
                return;
            }
            try self.checkOpen();
            if (end_stream) self.local_closed = true;
        }
        const max = conn.peer.max_frame_size;
        conn.beginWrite();
        conn.write_lock.lockUncancelable(conn.io);
        defer conn.write_lock.unlock(conn.io);
        var ended = false;
        defer if (!ended) conn.endWriteLocked(true) catch {};
        if (self.id == 0) try conn.assignId(self);
        var offset: usize = 0;
        var first = true;
        while (true) {
            const n = @min(block.items.len - offset, max);
            const last = offset + n == block.items.len;
            var flags: u8 = 0;
            if (last) flags |= frame.Flags.end_headers;
            if (first and end_stream) flags |= frame.Flags.end_stream;
            try conn.writeFrameLocked(if (first) .headers else .continuation, flags, self.id, block.items[offset..][0..n]);
            offset += n;
            first = false;
            if (last) break;
        }
        ended = true;
        try conn.endWriteLocked(!self.corked);
    }

    /// Send data. The call waits for flow control credit. With `end_stream` the send side closes.
    /// When the server sent a complete response and the stream then got a reset, the client
    /// stops the data and gets no error. The caller then reads the response.
    pub fn sendData(self: *Stream, bytes: []const u8, end_stream: bool) Error!void {
        const conn = self.conn;
        var offset: usize = 0;
        // A corked stream flushes its frames before it waits for credit. The peer can need
        // them before it gives credit.
        var flushed = !self.corked;
        while (true) {
            var n: usize = 0;
            {
                conn.lock.lockUncancelable(conn.io);
                defer conn.lock.unlock(conn.io);
                while (true) {
                    if (self.answered()) {
                        self.local_closed = true;
                        return;
                    }
                    try self.checkOpen();
                    const remaining = bytes.len - offset;
                    if (remaining == 0) break;
                    const credit = @min(self.send_window, conn.send_window);
                    if (credit > 0) {
                        n = @min(remaining, @as(usize, @intCast(credit)), conn.peer.max_frame_size);
                        self.send_window -= @intCast(n);
                        conn.send_window -= @intCast(n);
                        break;
                    }
                    if (!flushed) {
                        // The write lock comes before `lock` (see `sendHeaders`).
                        flushed = true;
                        conn.lock.unlock(conn.io);
                        const result = conn.flushPending();
                        conn.lock.lockUncancelable(conn.io);
                        try result;
                        continue;
                    }
                    try self.wait();
                }
                if (offset + n == bytes.len and end_stream) self.local_closed = true;
            }
            const last = offset + n == bytes.len;
            const flags: u8 = if (last and end_stream) frame.Flags.end_stream else 0;
            try conn.writeFrameFlush(.data, flags, self.id, bytes[offset..][0..n], !self.corked);
            flushed = !self.corked;
            offset += n;
            if (last) return;
        }
    }

    /// Send data as `sendData` does, but do not wait for flow control credit. When the
    /// windows have less credit than `bytes.len`, nothing goes out and the result is
    /// `error.WouldBlock`. Only the read task gets more credit from the peer. Thus the read
    /// task uses this function, because it must not wait for that credit.
    pub fn sendDataNoWait(self: *Stream, bytes: []const u8, end_stream: bool) (Error || error{WouldBlock})!void {
        const conn = self.conn;
        {
            conn.lock.lockUncancelable(conn.io);
            defer conn.lock.unlock(conn.io);
            if (self.answered()) {
                self.local_closed = true;
                return;
            }
            try self.checkOpen();
            if (@min(self.send_window, conn.send_window) < @as(i64, @intCast(bytes.len))) return error.WouldBlock;
            self.send_window -= @intCast(bytes.len);
            conn.send_window -= @intCast(bytes.len);
            if (end_stream) self.local_closed = true;
        }
        const max = conn.peer.max_frame_size;
        var offset: usize = 0;
        while (true) {
            const n = @min(bytes.len - offset, max);
            const last = offset + n == bytes.len;
            const flags: u8 = if (last and end_stream) frame.Flags.end_stream else 0;
            try conn.writeFrameFlush(.data, flags, self.id, bytes[offset..][0..n], last and !self.corked);
            offset += n;
            if (last) return;
        }
    }

    /// Give the stream to `on_stream` again when the request is complete: at END_STREAM, or
    /// when its data fills half of the stream window. Then the owner of a small request does
    /// not wait for its data. Also, the read task does not wake the owner for each frame.
    /// Only `on_stream` calls this function, in the read task. When the result is false, the
    /// request is complete, has that much data or has a reset, and the caller keeps the
    /// stream. A stream that gets a reset before the end has no owner, and the connection
    /// frees it.
    pub fn dispatchAtEnd(self: *Stream) bool {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        if (self.end_stream or self.reset != null or conn.closed) return false;
        if (self.data.items.len >= conn.options.initial_window_size / 2) return false;
        self.undispatched = true;
        conn.unowned_streams += 1;
        return true;
    }

    /// The peer ended its side of the stream: the request or the response is complete.
    pub fn peerEnded(self: *Stream) bool {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        return self.end_stream;
    }

    /// Wait until the request or response headers arrived.
    pub fn waitHeaders(self: *Stream) Error![]const Header {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        while (!self.headers_done) {
            try self.checkOpen();
            if (self.end_stream) return error.StreamReset;
            try self.wait();
        }
        return self.headers.items;
    }

    /// Read data. Returns zero at the end of the stream. The trailers are then available.
    pub fn read(self: *Stream, buf: []u8) Error!usize {
        const conn = self.conn;
        var credit: u32 = 0;
        const n = blk: {
            conn.lock.lockUncancelable(conn.io);
            defer conn.lock.unlock(conn.io);
            while (self.data.items.len == self.read_pos) {
                if (self.end_stream) break :blk 0;
                try self.checkOpen();
                try self.wait();
            }
            const available = self.data.items[self.read_pos..];
            const n = @min(buf.len, available.len);
            @memcpy(buf[0..n], available[0..n]);
            self.read_pos += n;
            if (self.read_pos == self.data.items.len) {
                self.data.clearRetainingCapacity();
                self.read_pos = 0;
            }
            self.recv_credit += @intCast(n);
            if (self.recv_credit >= conn.options.initial_window_size / 2 and !self.end_stream) {
                credit = self.recv_credit;
                self.recv_window += credit;
                self.recv_credit = 0;
            }
            break :blk n;
        };
        if (credit > 0) conn.sendWindowUpdate(self.id, credit);
        return n;
    }

    /// Wait until the peer ended the stream. The trailers, if any, are then available.
    pub fn waitEnd(self: *Stream) Error![]const Header {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        while (!self.end_stream) {
            try self.checkOpen();
            try self.wait();
        }
        return self.trailers.items;
    }

    /// Wait until the stream got a reset or the connection ended. The reset can come from the
    /// peer or from this side, for example from `cancel`. After `stopWaits`, the wait ends with
    /// `error.Canceled`.
    pub fn waitCancelled(self: *Stream) Error!void {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        while (self.reset == null and !self.conn_closed and !conn.closed) {
            try self.wait();
        }
    }

    pub fn wasReset(self: *Stream) ?frame.ErrorCode {
        const conn = self.conn;
        conn.lock.lockUncancelable(conn.io);
        defer conn.lock.unlock(conn.io);
        return self.reset;
    }
};

/// Find a header value.
pub fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.mem.eql(u8, h.name, name)) return h.value;
    return null;
}

test "header validation rules" {
    try std.testing.expect(validHeaders(&.{ .{ .name = ":method", .value = "POST" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/x" }, .{ .name = "te", .value = "trailers" } }, false, .server));
    try std.testing.expect(!validHeaders(&.{ .{ .name = ":method", .value = "POST" }, .{ .name = ":path", .value = "/x" } }, false, .server));
    try std.testing.expect(!validHeaders(&.{ .{ .name = "x", .value = "1" }, .{ .name = ":method", .value = "POST" } }, false, .server));
    try std.testing.expect(!validHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "Connection", .value = "close" } }, false, .client));
    try std.testing.expect(!validHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "connection", .value = "close" } }, false, .client));
    try std.testing.expect(validHeaders(&.{.{ .name = ":status", .value = "200" }}, false, .client));
    try std.testing.expect(validHeaders(&.{.{ .name = "grpc-status", .value = "0" }}, true, .client));
    try std.testing.expect(!validHeaders(&.{.{ .name = ":status", .value = "200" }}, true, .client));
}
