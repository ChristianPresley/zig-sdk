//! One HTTP/2 connection (RFC 9113) with its streams, for the gRPC binding. A read task
//! runs `run` and dispatches frames. Application tasks send on streams. Server push and
//! priorities are not in use. Flow control applies in both directions.
//!
//! No task holds a lock, and no send waits for another send. The read task owns the table of
//! streams and the state that the frames of the peer change. The other tasks give it their
//! changes in lock-free queues. One task at a time writes to the socket: the writer. A task
//! that finds the writer busy puts its frame in a queue, and the writer sends it. Each field
//! of a stream that two tasks use is atomic.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const frame = @import("frame.zig");
const hpack = @import("hpack/hpack.zig");
const Stack = @import("mcp").util.lockfree.Stack;

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
    /// The peer reset the stream. The code is in `Stream.wasReset`.
    StreamReset,
    /// The peer violated the protocol. The connection sent a `GOAWAY` and ended.
    ProtocolError,
} || Io.Cancelable;

/// The errors of the read task. A frame with a wrong length gives `FrameSizeError`
/// (RFC 9113 sections 4.2 and 6). A header block that HPACK cannot decode gives
/// `CompressionError` (RFC 9113 section 4.3).
const ReadError = Error || error{ FrameSizeError, EnhanceYourCalm, CompressionError };

io: Io,
gpa: Allocator,
reader: *Io.Reader,
writer: *Io.Writer,
options: Options,

// -- The writer. See `submit`.

/// True while a task is the writer. Only the writer writes to `writer`.
writer_busy: std.atomic.Value(bool) = .init(false),
/// The frames for the writer from the tasks that found the writer busy, the newest first.
out_queue: Stack(Out, "next") = .{},
/// The sends that started and did not end, and the hold of the read task. The writer flushes
/// only when the count is zero. Thus the frames of tasks that send at the same time go out
/// together, in a small number of TCP segments. On Linux the congestion window counts
/// segments, not bytes. With one segment for each frame, 32 calls at the same time used one
/// more round trip.
pending_writes: std.atomic.Value(u32) = .init(0),
/// Frames wait in the buffer of `writer` for a flush. Only the writer changes the flag.
flush_wanted: std.atomic.Value(bool) = .init(false),
/// A write to the socket failed. Each later send fails at once.
write_failed: std.atomic.Value(bool) = .init(false),
/// The bytes of the control frames in `out_queue`. The read task makes most of them, for
/// example the acknowledgments of `PING` frames. When a writer waits for a peer that does not
/// read, the queue can grow. Above `max_queued_control` the connection ends.
queued_control: std.atomic.Value(usize) = .init(0),
/// The id for the next stream of this side. Only the writer uses the field.
next_stream_id: u31,

// -- The read task. Only the read task uses these fields, unless the field tells otherwise.

/// The read task counts as a pending write while complete frames wait in the read buffer.
/// Thus the answers to a burst of frames go out together.
read_hold: bool = false,
/// The streams that a burst of frames opened. The read task gives them to `on_stream` at the
/// end of the burst, after the frames with their request data. Thus a handler does not wait
/// for its data, and the handlers of a burst start together.
held_streams: std.ArrayList(*Stream) = .empty,
/// The number of bursts of frames that the read task read. A burst is the frames that it reads
/// without a wait for the socket. See `burst`.
bursts: u32 = 0,
decoder: hpack.Decoder,
encoder: hpack.Encoder = .{},
/// The settings of the peer. The read task changes them. Other tasks read
/// `initial_window_size` and `max_frame_size` with an atomic load.
peer: frame.Settings = .{},
/// The streams with an id, by id. The other tasks give the read task their changes in
/// `registered` and `closed_streams`.
streams: std.AutoHashMapUnmanaged(u31, *Stream) = .empty,
/// The last stream that the peer opened. Other tasks read it with an atomic load.
last_peer_stream_id: u31 = 0,
peer_streams_open: u32 = 0,
/// Bytes the peer can still send on the connection.
recv_window: i64,
/// Consumed bytes that the connection did not credit to the peer yet.
recv_credit: u32 = 0,
frame_buf: []u8,
hb_active: bool = false,
hb_stream: u31 = 0,
hb_flags: u8 = 0,
hb_buf: std.ArrayList(u8) = .empty,
/// The ids of the last peer streams that this side reset. The next id goes to the index
/// `reset_ids_next % remembered_resets`.
reset_ids: [remembered_resets]u31 = @splat(0),
reset_ids_next: usize = 0,

// -- The state that all tasks share. It is atomic.

/// Bytes we can still send on the connection.
send_window: std.atomic.Value(i64) = .init(frame.default_initial_window),
closed: std.atomic.Value(bool) = .init(false),
goaway_received: std.atomic.Value(bool) = .init(false),
goaway_sent: std.atomic.Value(bool) = .init(false),
/// The open streams with an owner. See `ownedStreams`.
owned: std.atomic.Value(u32) = .init(0),
/// The streams of this side that got an id from the writer, for the table of the read task.
registered: Stack(Stream, "next_registered") = .{},
/// The streams that their owner closed, for the read task. The read task removes them from
/// the table.
closed_streams: Stack(Stream, "next_closed") = .{},
/// The streams that wait for credit of the connection. A `WINDOW_UPDATE` of the connection
/// wakes them.
credit_waiters: Stack(Stream, "next_credit") = .{},

/// The most bytes of control frames that wait for the writer. See `queued_control`.
pub const max_queued_control = 256 << 10;

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

/// Free everything. Every stream must be closed by its owner first, and no task sends.
pub fn deinit(self: *Connection) void {
    // Frames that no writer sent. The queue is empty unless a write failed.
    var out = self.out_queue.takeAll();
    while (out) |o| {
        out = o.next;
        o.free(self.gpa);
    }
    self.wakeCreditWaiters();
    self.syncQueues();
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
        .{ .id = @backingInt(frame.SettingId.header_table_size), .value = 4096 },
        .{ .id = @backingInt(frame.SettingId.enable_push), .value = 0 },
        .{ .id = @backingInt(frame.SettingId.max_concurrent_streams), .value = self.options.max_concurrent_streams },
        .{ .id = @backingInt(frame.SettingId.initial_window_size), .value = self.options.initial_window_size },
        .{ .id = @backingInt(frame.SettingId.max_frame_size), .value = self.options.max_frame_size },
        .{ .id = @backingInt(frame.SettingId.max_header_list_size), .value = self.options.max_header_list_size },
    };
    for (list, 0..) |s, i| settings[i * 6 ..][0..6].* = s.encode();
    // Raise the connection window from the default to ours. The two frames go out together.
    const raise = self.options.connection_window > frame.default_initial_window;
    try self.submit(.{ .kind = .settings, .payload = &settings, .flush = !raise });
    if (raise) {
        const increment = self.options.connection_window - frame.default_initial_window;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, increment, .big);
        try self.submit(.{ .kind = .window_update, .payload = &payload });
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
    return self.owned.load(.acquire);
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
                error.CompressionError => self.sendGoaway(.compression_error),
                error.EnhanceYourCalm => self.sendGoaway(.enhance_your_calm),
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
    // The streams that their owners closed leave the table now.
    self.syncQueues();
    if (self.closed.load(.acquire) or self.owned.load(.seq_cst) != 0) return false;
    // A close pushes its stream before the count drops. Thus the last close is in the queue
    // now, and the parked connection keeps no closed stream.
    self.syncQueues();
    return true;
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
        _ = self.pending_writes.fetchAdd(1, .seq_cst);
        return;
    }
    const held = self.held_streams.items;
    for (held, 1..) |s, i| {
        self.dispatch(s);
        if (i % held_streams_per_flush == 0 and i < held.len) {
            self.endPending() catch {};
            _ = self.pending_writes.fetchAdd(1, .seq_cst);
        }
    }
    self.held_streams.clearRetainingCapacity();
    self.endPending() catch {};
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
    self.closed.store(true, .seq_cst);
    self.syncQueues();
    var it = self.streams.valueIterator();
    while (it.next()) |s| s.*.markConnClosed();
    self.wakeCreditWaiters();
}

pub fn isClosed(self: *Connection) bool {
    return self.closed.load(.acquire);
}

/// Give the read task the changes of the other tasks: the streams that the writer gave an id,
/// and the streams that their owners closed. Only the read task calls this function, or
/// `deinit`.
fn syncQueues(self: *Connection) void {
    // First take the closed streams, then the registered streams. The writer registers a
    // stream before its owner can see its id. Thus the table has each closed stream with an id.
    var closed_list = self.closed_streams.takeAll();
    var reg = self.registered.takeAll();
    while (reg) |s| {
        reg = s.next_registered;
        self.streams.put(self.gpa, s.id, s) catch {
            // Without memory the read task cannot find the stream. It ends as at the end of
            // the connection. The reference of the table goes when the owner closes it.
            s.unregistered = true;
            s.markConnClosed();
            continue;
        };
        // A `SETTINGS` frame that changed the initial window after the creation of the stream
        // did not see the stream (section 6.9.2).
        _ = s.applyInitialWindow(@atomicLoad(u32, &self.peer.initial_window_size, .seq_cst));
    }
    while (closed_list) |s| {
        closed_list = s.next_closed;
        const id = s.id;
        if (s.unregistered) {
            s.release();
            continue;
        }
        const found = self.streams.get(id) orelse continue;
        if (found != s) continue;
        _ = self.streams.remove(id);
        if (self.isPeerStream(id)) {
            self.peer_streams_open -|= 1;
            // After a reset, the peer can still send frames on the stream.
            if (s.reset_on_close) self.rememberReset(id);
        }
        // The reference of the table.
        s.release();
    }
}

/// The id belongs to a stream that the peer opened.
fn isPeerStream(self: *const Connection, id: u31) bool {
    return id % 2 == (if (self.options.role == .client) @as(u31, 0) else 1);
}

// -- Writing ---------------------------------------------------------------------------------

/// One send to the writer.
const Send = struct {
    kind: frame.Type = .data,
    flags: u8 = 0,
    stream_id: u31 = 0,
    /// A stream of this side that can have no id yet. The writer takes the id of the stream
    /// when it writes the frame. A header block gives the stream its id.
    stream: ?*Stream = null,
    /// For a header block: the whole block. The writer splits it into frames.
    payload: []const u8 = &.{},
    /// Flush when no other send is pending. False keeps the frame in the buffer.
    flush: bool = true,
    /// No frame: only the flush.
    flush_only: bool = false,
};

/// A send that waits for the writer in `out_queue`. The payload follows the struct.
const Out = struct {
    next: ?*Out = null,
    kind: frame.Type,
    flags: u8,
    stream_id: u31,
    /// Holds a reference to the stream.
    stream: ?*Stream,
    flush: bool,
    flush_only: bool,
    len: usize,

    fn create(gpa: Allocator, s: Send) Allocator.Error!*Out {
        const bytes = try gpa.alignedAlloc(u8, .of(Out), @sizeOf(Out) + s.payload.len);
        const o: *Out = @ptrCast(bytes.ptr);
        o.* = .{
            .kind = s.kind,
            .flags = s.flags,
            .stream_id = s.stream_id,
            .stream = s.stream,
            .flush = s.flush,
            .flush_only = s.flush_only,
            .len = s.payload.len,
        };
        @memcpy(bytes[@sizeOf(Out)..], s.payload);
        if (s.stream) |st| st.retain();
        return o;
    }

    fn payload(o: *Out) []const u8 {
        const base: [*]u8 = @ptrCast(o);
        return base[@sizeOf(Out)..][0..o.len];
    }

    fn send(o: *Out) Send {
        return .{ .kind = o.kind, .flags = o.flags, .stream_id = o.stream_id, .stream = o.stream, .payload = o.payload(), .flush = o.flush, .flush_only = o.flush_only };
    }

    fn free(o: *Out, gpa: Allocator) void {
        if (o.stream) |st| st.release();
        const base: [*]align(@alignOf(Out)) u8 = @ptrCast(o);
        gpa.free(base[0 .. @sizeOf(Out) + o.len]);
    }
};

/// Send one frame, or a header block in frames, or only a flush. The task that finds the
/// writer free becomes the writer: it first writes the frames of the queue, then its own
/// frame. A task that finds the writer busy puts a copy of its frame in the queue, and the
/// writer writes it. Thus no send waits for another send. The frames of one task go out in
/// the order of its sends.
///
/// With `flush`, the writer flushes when no other send is pending. A pending send flushes
/// when it ends. Thus the frames of sends at the same time go out together.
fn submit(self: *Connection, s: Send) Error!void {
    if (self.write_failed.load(.acquire)) return error.WriteFailed;
    _ = self.pending_writes.fetchAdd(1, .seq_cst);
    if (self.tryTakeWriter()) {
        self.drainOut();
        var result: Error!void = {};
        if (!s.flush_only) result = self.emit(s);
        if (s.flush) self.flush_wanted.store(true, .monotonic);
        _ = self.pending_writes.fetchSub(1, .seq_cst);
        const released = self.releaseWriter();
        try result;
        return released;
    }
    const control = s.kind != .data and s.kind != .headers;
    if (control) _ = self.queued_control.fetchAdd(s.payload.len + frame.header_len, .monotonic);
    const o = Out.create(self.gpa, s) catch |e| {
        if (control) _ = self.queued_control.fetchSub(s.payload.len + frame.header_len, .monotonic);
        _ = self.pending_writes.fetchSub(1, .seq_cst);
        self.kick() catch {};
        return e;
    };
    self.out_queue.push(o);
    _ = self.pending_writes.fetchSub(1, .seq_cst);
    // The writer can stop between the push and here. Then this task writes the queue.
    self.kick() catch {};
}

/// End a pending write that wrote nothing, for example the hold of the read task. Flush when
/// it was the last pending write.
fn endPending(self: *Connection) Error!void {
    _ = self.pending_writes.fetchSub(1, .seq_cst);
    try self.kick();
}

/// Become the writer when it is free, and write the queue.
fn kick(self: *Connection) Error!void {
    if (!self.tryTakeWriter()) return;
    self.drainOut();
    try self.releaseWriter();
}

/// Make each later send fail at once, and wake the sends that wait for credit of the
/// connection. A wait for credit of a stream wakes at the end of the connection. After a failed
/// write, the read task soon ends: the socket has an error or is closed. The owner calls this
/// function before it closes the socket from another task. Then a send that did not start
/// yet does not write to the closed handle.
pub fn failWrites(self: *Connection) void {
    if (self.write_failed.swap(true, .seq_cst)) return;
    self.wakeCreditWaiters();
}

fn tryTakeWriter(self: *Connection) bool {
    return self.writer_busy.cmpxchgStrong(false, true, .seq_cst, .monotonic) == null;
}

/// Flush when no write is pending, and stop as the writer. Write the frames that came
/// meanwhile, and flush for a pending write that ended meanwhile. Only the writer calls this
/// function.
fn releaseWriter(self: *Connection) Error!void {
    var result: Error!void = {};
    while (true) {
        if (self.flush_wanted.load(.monotonic) and self.pending_writes.load(.seq_cst) == 0) {
            self.flush_wanted.store(false, .monotonic);
            if (!self.write_failed.load(.monotonic)) self.writer.flush() catch {
                self.failWrites();
                result = error.WriteFailed;
            };
        }
        self.writer_busy.store(false, .seq_cst);
        // A task that found the writer busy pushed its frame or ended its pending write before
        // its own check of `writer_busy`. Thus this check or that task sees the change.
        const flush_due = self.flush_wanted.load(.seq_cst) and self.pending_writes.load(.seq_cst) == 0;
        if (self.out_queue.isEmpty() and !flush_due) return result;
        if (!self.tryTakeWriter()) return result;
        self.drainOut();
    }
}

/// Write the frames of the queue, the oldest first. Only the writer calls this function.
fn drainOut(self: *Connection) void {
    var oldest_first = self.out_queue.takeAllInOrder();
    while (oldest_first) |o| {
        oldest_first = o.next;
        if (!o.flush_only) self.emit(o.send()) catch |e| {
            // The task of the send continued already. A stream that got no id, or a stream
            // after a failed write, ends as at the end of the connection. Thus its owner does
            // not wait.
            if (o.stream) |st| if (st.idWord() == 0 or e == error.WriteFailed) st.markConnClosed();
        };
        if (o.flush) self.flush_wanted.store(true, .monotonic);
        if (o.kind != .data and o.kind != .headers) _ = self.queued_control.fetchSub(o.len + frame.header_len, .monotonic);
        o.free(self.gpa);
    }
}

/// Write the frames of one send to the buffer. Only the writer calls this function.
fn emit(self: *Connection, s: Send) Error!void {
    if (self.write_failed.load(.monotonic)) return error.WriteFailed;
    var id = s.stream_id;
    if (id == 0) if (s.stream) |st| {
        id = if (s.kind == .headers) try self.assignId(st) else switch (st.idWord()) {
            // The header block of the stream did not go out: nothing of the stream goes out.
            // The data took credit of the connection, thus it goes back. Else the credit is
            // lost, and the sends of the other streams can wait for it forever.
            0, closed_before_id => {
                if (s.kind == .data and s.payload.len > 0) {
                    _ = self.send_window.fetchAdd(@intCast(s.payload.len), .seq_cst);
                    self.wakeCreditWaiters();
                }
                return;
            },
            else => |w| @intCast(w),
        };
    };
    errdefer self.failWrites();
    if (s.kind == .data) {
        // The peer can make its largest frame smaller after the send took its credit.
        const max = self.peerMaxFrameSize();
        var offset: usize = 0;
        while (true) {
            const n = @min(s.payload.len - offset, max);
            const last = offset + n == s.payload.len;
            try self.writeFrameRaw(.data, if (last) s.flags else s.flags & ~frame.Flags.end_stream, id, s.payload[offset..][0..n]);
            offset += n;
            if (last) return;
        }
    }
    if (s.kind != .headers) return self.writeFrameRaw(s.kind, s.flags, id, s.payload);
    // A stream that got its id now. Its headers always go out, because later frames of the
    // stream use the id. A `cancel` between `checkOpen` in `assignId` and the id saw no id, thus
    // it sent no reset. Then the writer sends the reset after the headers.
    defer if (s.stream_id == 0) if (s.stream) |st| {
        if (st.reset_word.load(.seq_cst) != 0 and st.claimReset()) {
            var code: [4]u8 = undefined;
            std.mem.writeInt(u32, &code, @backingInt(frame.ErrorCode.cancel), .big);
            self.writeFrameRaw(.rst_stream, 0, id, &code) catch self.failWrites();
        }
    };
    const max = self.peerMaxFrameSize();
    const block = s.payload;
    var offset: usize = 0;
    var first = true;
    while (true) {
        const n = @min(block.len - offset, max);
        const last = offset + n == block.len;
        var flags: u8 = 0;
        if (last) flags |= frame.Flags.end_headers;
        if (first) flags |= s.flags & frame.Flags.end_stream;
        try self.writeFrameRaw(if (first) .headers else .continuation, flags, id, block[offset..][0..n]);
        offset += n;
        first = false;
        if (last) return;
    }
}

fn writeFrameRaw(self: *Connection, kind: frame.Type, flags: u8, stream_id: u31, payload: []const u8) Error!void {
    const header: frame.Header = .{ .length = @intCast(payload.len), .type = kind, .flags = flags, .stream_id = stream_id };
    self.writer.writeAll(&header.encode()) catch return error.WriteFailed;
    self.writer.writeAll(payload) catch return error.WriteFailed;
}

/// The largest frame that the peer accepts. Safe from any task.
fn peerMaxFrameSize(self: *Connection) u32 {
    return @atomicLoad(u32, &self.peer.max_frame_size, .monotonic);
}

/// Flush the buffer when no write is pending. A pending write flushes when it ends.
fn flushPending(self: *Connection) Error!void {
    try self.submit(.{ .flush_only = true });
}

/// The `id_word` of a stream that closed before it got an id. The writer then sends nothing
/// for the stream.
const closed_before_id: u32 = 1 << 31;

/// Give the stream `s` of this side the next id, and register it for the read task. Only the
/// writer calls this function, thus the ids increase in wire order (section 5.1.1). A stream
/// that got a reset or closed before this call gets no id, and its headers do not go out.
fn assignId(self: *Connection, s: *Stream) Error!u31 {
    switch (s.idWord()) {
        0 => {},
        closed_before_id => return error.Closed,
        else => |w| return @intCast(w),
    }
    if (self.closed.load(.seq_cst) or self.goaway_received.load(.acquire)) return error.Closed;
    // A `cancel` from another task before the id sends no reset, thus the peer must not see the
    // stream at all.
    try s.checkOpen();
    if (self.next_stream_id > frame.max_window - 2) return error.Closed;
    const id = self.next_stream_id;
    // An id that the stream does not take stays unused. The peer accepts gaps.
    self.next_stream_id += 2;
    // The registration comes before the owner can see the id: see `syncQueues`.
    s.id = id;
    s.retain();
    self.registered.push(s);
    // A `SETTINGS` frame that came before the push did not see the stream: apply its window
    // before the headers and the data go out.
    _ = s.applyInitialWindow(@atomicLoad(u32, &self.peer.initial_window_size, .seq_cst));
    if (s.id_word.cmpxchgStrong(0, id, .seq_cst, .seq_cst) != null) {
        // The owner closed the stream meanwhile. The read task removes it again.
        self.closed_streams.push(s);
        return error.Closed;
    }
    // The end of the connection can come between the check above and the registration.
    if (self.closed.load(.seq_cst)) s.markConnClosed();
    // A `GOAWAY` that came before the registration did not see the stream. The peer ignores
    // the stream, thus it ends as the streams of `onGoaway` do.
    if (self.goaway_received.load(.seq_cst)) s.setReset(.refused_stream);
    return id;
}

fn sendGoaway(self: *Connection, code: frame.ErrorCode) void {
    // With the store and the load of `finishHeaderBlock`, all four operations are seq_cst.
    // Thus either the read task sees the flag and refuses the stream, or the `GOAWAY` names
    // the stream as processed.
    if (self.goaway_sent.swap(true, .seq_cst)) return;
    const last = @atomicLoad(u31, &self.last_peer_stream_id, .seq_cst);
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], last, .big);
    std.mem.writeInt(u32, payload[4..8], @backingInt(code), .big);
    self.submit(.{ .kind = .goaway, .payload = &payload }) catch {};
}

fn sendRst(self: *Connection, stream_id: u31, code: frame.ErrorCode) void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, @backingInt(code), .big);
    self.submit(.{ .kind = .rst_stream, .stream_id = stream_id, .payload = &payload }) catch {};
}

fn sendWindowUpdate(self: *Connection, stream_id: u31, increment: u32) void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment, .big);
    self.submit(.{ .kind = .window_update, .stream_id = stream_id, .payload = &payload }) catch {};
}

/// Send a `PING`. The function `run` receives the answer.
pub fn ping(self: *Connection, data: [8]u8) Error!void {
    try self.submit(.{ .kind = .ping, .payload = &data });
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
    // The changes of the other tasks since the last frame.
    self.syncQueues();
    // A peer that sends frames and does not read their answers.
    if (self.queued_control.load(.monotonic) > max_queued_control) return error.EnhanceYourCalm;
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
            if (!header.has(frame.Flags.ack)) try self.submit(.{ .kind = .ping, .flags = frame.Flags.ack, .payload = payload });
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
    // The whole frame counts against the connection window, also for unknown streams.
    self.recv_window -= @intCast(header.length);
    if (self.recv_window < 0) return error.ProtocolError;
    self.recv_credit += header.length;
    if (self.recv_credit >= self.options.connection_window / 2) {
        const increment = self.recv_credit;
        self.recv_window += increment;
        self.recv_credit = 0;
        self.sendWindowUpdate(0, increment);
    }
    const stream = self.streams.get(header.stream_id) orelse {
        // Data on a stream that was never opened.
        if (header.stream_id > self.last_peer_stream_id and self.options.role == .server) return error.ProtocolError;
        return;
    };
    if (stream.peerEnded() or stream.reset_word.load(.acquire) != 0) {
        self.sendRst(header.stream_id, .stream_closed);
        return;
    }
    const length: i64 = @intCast(header.length);
    if (stream.recv_window.fetchSub(length, .acq_rel) - length < 0) {
        stream.setReset(.flow_control_error);
        self.sendRst(header.stream_id, .flow_control_error);
        // A stream that `Stream.dispatchAtEnd` kept from its owner: the connection frees it.
        if (stream.undispatched) self.drop(stream);
        return;
    }
    try stream.pushData(data);
    const end = header.has(frame.Flags.end_stream);
    if (end) stream.setState(Stream.end_stream);
    stream.wake();
    if (stream.undispatched and (end or stream.received >= self.options.initial_window_size / 2)) {
        // The request is complete, or it has that much data: the stream gets its owner.
        stream.undispatched = false;
        _ = self.owned.fetchAdd(1, .seq_cst);
        self.handOver(stream);
    }
}

fn onHeaders(self: *Connection, header: frame.Header, payload: []const u8) ReadError!void {
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
    self.hb_stream = header.stream_id;
    self.hb_flags = header.flags;
    if (header.has(frame.Flags.end_headers)) {
        // A block in one frame decodes from the frame buffer, without a copy.
        try self.finishHeaderBlock(block);
    } else {
        self.hb_buf.clearRetainingCapacity();
        try self.hb_buf.appendSlice(self.gpa, block);
        self.hb_active = true;
    }
}

fn onContinuation(self: *Connection, header: frame.Header, payload: []const u8) ReadError!void {
    if (!self.hb_active or header.stream_id != self.hb_stream) return error.ProtocolError;
    if (self.hb_buf.items.len + payload.len > self.options.max_header_block_size) return error.ProtocolError;
    try self.hb_buf.appendSlice(self.gpa, payload);
    if (header.has(frame.Flags.end_headers)) {
        self.hb_active = false;
        defer self.hb_buf.clearRetainingCapacity();
        try self.finishHeaderBlock(self.hb_buf.items);
    }
}

/// Decode the assembled block and hand it to the stream: request headers, response
/// headers or trailers.
fn finishHeaderBlock(self: *Connection, block: []const u8) ReadError!void {
    const stream_id = self.hb_stream;
    const end_stream = self.hb_flags & frame.Flags.end_stream != 0;
    // The stream that this block opens. It goes to `on_stream`, or it is refused and freed.
    var opened: ?*Stream = null;
    const s = self.streams.get(stream_id) orelse s: {
        if (self.options.role != .server or stream_id % 2 == 0 or stream_id <= self.last_peer_stream_id) {
            // A response for a stream we do not know, a block on a stream that this side
            // reset, or a bad id: decode to keep the HPACK state in sync, then ignore or
            // refuse. The peer can send a block before it sees the reset (section 5.1).
            try self.decodeDiscard(block);
            if (self.options.role == .server and !self.wasResetHere(stream_id)) return error.ProtocolError;
            return;
        }
        @atomicStore(u31, &self.last_peer_stream_id, stream_id, .seq_cst);
        if (self.goaway_sent.load(.seq_cst) or self.peer_streams_open >= self.options.max_concurrent_streams) {
            try self.decodeDiscard(block);
            self.rememberReset(stream_id);
            self.sendRst(stream_id, .refused_stream);
            return;
        }
        const created = try Stream.create(self, stream_id);
        self.streams.put(self.gpa, stream_id, created) catch |e| {
            created.destroy();
            return e;
        };
        self.peer_streams_open += 1;
        opened = created;
        break :s created;
    };
    var reset: ?frame.ErrorCode = null;
    decoded: {
        // One allocation in the stream arena holds the headers and their bytes. Thus they
        // stay valid as long as the stream, after the next block and after the dynamic table
        // evicts their entries.
        const list = self.decoder.decodeOwned(s.arena_state.allocator(), block) catch |e| switch (e) {
            error.OutOfMemory => {
                if (opened != null) self.unregisterOpened(s);
                return error.OutOfMemory;
            },
            error.HeaderListTooLarge, error.FieldTooLarge => {
                reset = .enhance_your_calm;
                s.setReset(.enhance_your_calm);
                break :decoded;
            },
            else => {
                // A compression error ends the connection.
                if (opened != null) self.unregisterOpened(s);
                return error.CompressionError;
            },
        };
        const state = s.state.load(.acquire);
        if (state & Stream.end_stream != 0 or s.reset_word.load(.acquire) != 0) {
            reset = .stream_closed;
        } else if (state & Stream.headers_done == 0) {
            if (!validHeaders(list, false, self.options.role)) {
                reset = .protocol_error;
                s.setReset(.protocol_error);
            } else {
                s.headers = .fromOwnedSlice(list);
                s.setState(Stream.headers_done | if (end_stream) Stream.end_stream else 0);
            }
        } else {
            if (!validHeaders(list, true, self.options.role) or !end_stream) {
                reset = .protocol_error;
                s.setReset(.protocol_error);
            } else {
                s.trailers = .fromOwnedSlice(list);
                s.setState(Stream.trailers_done | Stream.end_stream);
            }
        }
        s.wake();
    }
    if (reset) |code| self.sendRst(stream_id, code);
    if (opened) |o| {
        // A stream that this block opened and refused gets no owner, because `on_stream` does
        // not run. Thus the connection frees it, as for `REFUSED_STREAM`. Else the stream counts
        // against `max_concurrent_streams` until the connection ends.
        if (o.reset_word.load(.acquire) != 0) {
            self.unregisterOpened(o);
            self.rememberReset(stream_id);
            return;
        }
        _ = self.owned.fetchAdd(1, .seq_cst);
        return self.handOver(o);
    }
    if (s.undispatched) {
        if (s.reset_word.load(.acquire) != 0) {
            // Trailers over the limit or with a wrong field, on a stream without an owner.
            self.drop(s);
        } else if (s.peerEnded()) {
            // The trailers completed a stream that `Stream.dispatchAtEnd` kept from its owner.
            s.undispatched = false;
            _ = self.owned.fetchAdd(1, .seq_cst);
            self.handOver(s);
        }
    }
}

/// Remove and free a stream that the current header block opened, before it has an owner.
fn unregisterOpened(self: *Connection, s: *Stream) void {
    _ = self.streams.remove(s.id);
    self.peer_streams_open -= 1;
    s.destroy();
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

/// Unregister and free a stream that has no owner yet, after its reset. Only the read task
/// calls this function.
fn drop(self: *Connection, s: *Stream) void {
    s.undispatched = false;
    _ = self.streams.remove(s.id);
    self.peer_streams_open -|= 1;
    self.rememberReset(s.id);
    // No other task has a reference: the stream has no owner.
    s.destroy();
}

/// Remember `id`, a peer stream that this side reset. Only the read task calls this function.
fn rememberReset(self: *Connection, id: u31) void {
    self.reset_ids[self.reset_ids_next % remembered_resets] = id;
    self.reset_ids_next +%= 1;
}

/// This side reset the peer stream `id`, and the connection still remembers it. No stream has
/// the id 0, thus the empty places do not match.
fn wasResetHere(self: *const Connection, id: u31) bool {
    return std.mem.findScalar(u31, &self.reset_ids, id) != null;
}

/// Decode a block that goes nowhere, to keep the dynamic table in sync. The headers stay in
/// the memory of the decoder until `trim`.
fn decodeDiscard(self: *Connection, block: []const u8) ReadError!void {
    _ = self.decoder.decodeBlock(block) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HeaderListTooLarge, error.FieldTooLarge => {},
        else => return error.CompressionError,
    };
    self.decoder.trim();
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
    const code: frame.ErrorCode = @fromBackingInt(@intCast(std.mem.readInt(u32, payload[0..4], .big)));
    if (self.streams.get(header.stream_id)) |s| {
        s.setReset(code);
        // A stream without an owner: no task closes it.
        if (s.undispatched) self.drop(s);
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
    var i: usize = 0;
    while (i < payload.len) : (i += 6) {
        const setting: frame.Setting = .{ .id = std.mem.readInt(u16, payload[i..][0..2], .big), .value = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big) };
        var next = self.peer;
        next.apply(setting) catch return error.ProtocolError;
        // Other tasks read these two fields.
        @atomicStore(u32, &self.peer.max_frame_size, next.max_frame_size, .release);
        @atomicStore(u32, &self.peer.initial_window_size, next.initial_window_size, .seq_cst);
        self.peer.header_table_size = next.header_table_size;
        self.peer.enable_push = next.enable_push;
        self.peer.max_concurrent_streams = next.max_concurrent_streams;
        self.peer.max_header_list_size = next.max_header_list_size;
        if (@as(frame.SettingId, @fromBackingInt(@intCast(setting.id))) == .initial_window_size) {
            // The change applies to every open stream (section 6.9.2), also to a stream that the
            // writer registered just now. A stream that the writer registers after the store
            // above applies the change itself (`assignId`). Each stream applies it once.
            self.syncQueues();
            var it = self.streams.valueIterator();
            while (it.next()) |s| {
                if (s.*.applyInitialWindow(next.initial_window_size) > frame.max_window) return error.ProtocolError;
            }
        }
    }
    try self.submit(.{ .kind = .settings, .flags = frame.Flags.ack });
}

fn onGoaway(self: *Connection, header: frame.Header, payload: []const u8) Error!void {
    if (header.stream_id != 0 or header.length < 8) return error.ProtocolError;
    const last: u31 = @truncate(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
    const code: frame.ErrorCode = @fromBackingInt(@intCast(std.mem.readInt(u32, payload[4..8], .big)));
    if (code != .no_error) log.warn("peer sent GOAWAY with {t}", .{code});
    self.goaway_received.store(true, .seq_cst);
    // A stream that the writer registered before the store above is in the table now. A later
    // one sees the flag in `assignId`.
    self.syncQueues();
    // Streams the peer never processed are lost.
    var it = self.streams.valueIterator();
    while (it.next()) |s| if (s.*.id > last and !self.isPeerStream(s.*.id)) {
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
    if (header.stream_id == 0) {
        if (self.send_window.fetchAdd(increment, .seq_cst) + increment > frame.max_window) return error.ProtocolError;
        // The credit of the connection can continue the sends that wait for it.
        self.wakeCreditWaiters();
    } else if (self.streams.get(header.stream_id)) |s| {
        if (s.send_window.fetchAdd(increment, .seq_cst) + increment > frame.max_window) {
            s.setReset(.flow_control_error);
            self.sendRst(header.stream_id, .flow_control_error);
            if (s.undispatched) self.drop(s);
        } else {
            s.wake();
        }
    }
}

/// Wake each stream that waits for credit of the connection.
fn wakeCreditWaiters(self: *Connection) void {
    var list = self.credit_waiters.takeAll();
    while (list) |s| {
        list = s.next_credit;
        s.in_credit_queue.store(false, .seq_cst);
        s.wake();
        s.release();
    }
}

// -- Streams ---------------------------------------------------------------------------------

/// Open a stream to the peer. The connection gives the id when the first header block goes
/// out, so that ids increase in wire order (section 5.1.1).
pub fn openStream(self: *Connection) Error!*Stream {
    if (self.closed.load(.acquire) or self.goaway_received.load(.acquire)) return error.Closed;
    const s = try Stream.create(self, 0);
    // Only the owner has a reference. The writer adds the reference of the table.
    s.refs.store(1, .monotonic);
    _ = self.owned.fetchAdd(1, .seq_cst);
    return s;
}

/// A part of the request or response data, in the queue of a stream. The bytes follow the
/// struct.
const Chunk = struct {
    next: std.atomic.Value(?*Chunk) = .init(null),
    len: usize = 0,
    /// The bytes that the owner read. Only the owner uses the field.
    pos: usize = 0,

    fn bytes(c: *Chunk) []u8 {
        const base: [*]u8 = @ptrCast(c);
        return base[@sizeOf(Chunk)..][0..c.len];
    }

    fn create(gpa: Allocator, data: []const u8) Allocator.Error!*Chunk {
        const mem = try gpa.alignedAlloc(u8, .of(Chunk), @sizeOf(Chunk) + data.len);
        const c: *Chunk = @ptrCast(mem.ptr);
        c.* = .{ .len = data.len };
        @memcpy(mem[@sizeOf(Chunk)..], data);
        return c;
    }

    fn free(c: *Chunk, gpa: Allocator) void {
        const base: [*]align(@alignOf(Chunk)) u8 = @ptrCast(c);
        gpa.free(base[0 .. @sizeOf(Chunk) + c.len]);
    }
};

pub const Stream = struct {
    conn: *Connection,
    /// The stream id. A stream of this side has the id 0 until the writer gives it an id.
    id: u31,
    /// The id when the stream has one, 0 before, and `closed_before_id` after a close without
    /// an id.
    id_word: std.atomic.Value(u32),
    /// The table of the read task, the owner, and each frame in the queue of the writer have
    /// a reference. The last `release` frees the stream.
    refs: std.atomic.Value(u32) = .init(2),
    /// Only the read task uses the arena: it decodes the header blocks into it.
    arena_state: std.heap.ArenaAllocator,
    /// The request or response headers, in the stream arena. Valid after `headers_done`.
    headers: std.ArrayList(Header) = .empty,
    /// The trailers. Valid after `trailers_done`.
    trailers: std.ArrayList(Header) = .empty,
    /// The bits `headers_done`, `trailers_done`, `end_stream`, `conn_closed` and `waits_stopped`.
    state: std.atomic.Value(u32) = .init(0),
    /// The reset code plus one, or zero without a reset. The first reset stays.
    reset_word: std.atomic.Value(u32) = .init(0),
    /// A reset frame for the stream goes out. Only one task sends it.
    reset_claimed: std.atomic.Value(bool) = .init(false),
    /// Each change of the stream increments the count, and a task that waits on the stream
    /// waits for the next increment. A change on another stream does not wake the waits on
    /// this stream.
    epoch: std.atomic.Value(u32) = .init(0),
    /// The tasks that wait on `epoch`.
    waiters: std.atomic.Value(u32) = .init(0),
    /// The data from the peer. The read task adds chunks after `data_tail`, and the owner reads
    /// them after `data_head`. The chunk at `data_head` is empty.
    data_stub: Chunk = .{},
    data_head: *Chunk = undefined,
    data_tail: *Chunk = undefined,
    /// The bytes of data that the read task received. Only the read task uses the field.
    received: usize = 0,
    send_window: std.atomic.Value(i64),
    /// The initial window of the peer that `send_window` contains. See `applyInitialWindow`.
    window_base: std.atomic.Value(u32),
    recv_window: std.atomic.Value(i64),
    /// Only the owner uses the field.
    recv_credit: u32 = 0,
    /// See `cork`. Only the owner uses the field.
    corked: bool = false,
    /// We sent END_STREAM. Only the owner uses the field.
    local_closed: bool = false,
    /// `dispatchAtEnd` keeps the stream from `on_stream`. Only the read task uses the field.
    undispatched: bool = false,
    /// The stream had a reset when its owner closed it. For the read task.
    reset_on_close: bool = false,
    /// The table has no place for the stream: the memory ran out. Only the read task uses the
    /// field.
    unregistered: bool = false,
    /// The hook of the owner. See `setOnReset`.
    on_reset: ?ResetHook = null,
    on_reset_userdata: ?*anyopaque = null,
    hook_state: std.atomic.Value(u32) = .init(hook_none),
    /// The stream is in `Connection.credit_waiters`.
    in_credit_queue: std.atomic.Value(bool) = .init(false),
    next_registered: ?*Stream = null,
    next_closed: ?*Stream = null,
    next_credit: ?*Stream = null,

    /// A bit of `state`: the request or response headers arrived.
    pub const headers_done: u32 = 1;
    /// A bit of `state`: the trailers arrived.
    pub const trailers_done: u32 = 2;
    /// A bit of `state`: the peer sent END_STREAM.
    pub const end_stream: u32 = 4;
    /// A bit of `state`: the connection ended.
    pub const conn_closed: u32 = 8;
    /// A bit of `state`: a call to `stopWaits` came. Each wait on the stream then gives
    /// `error.Canceled`.
    pub const waits_stopped: u32 = 16;

    const hook_none: u32 = 0;
    const hook_armed: u32 = 1;
    const hook_running: u32 = 2;
    /// The hook ran. It runs once for the stream.
    const hook_done: u32 = 3;

    fn create(conn: *Connection, id: u31) Allocator.Error!*Stream {
        const s = try conn.gpa.create(Stream);
        const window = @atomicLoad(u32, &conn.peer.initial_window_size, .acquire);
        s.* = .{
            .conn = conn,
            .id = id,
            .id_word = .init(id),
            .arena_state = .init(conn.gpa),
            .send_window = .init(window),
            .window_base = .init(window),
            .recv_window = .init(conn.options.initial_window_size),
        };
        s.data_head = &s.data_stub;
        s.data_tail = &s.data_stub;
        return s;
    }

    fn destroy(self: *Stream) void {
        const gpa = self.conn.gpa;
        var c: ?*Chunk = self.data_head;
        while (c) |chunk| {
            c = chunk.next.load(.acquire);
            if (chunk != &self.data_stub) chunk.free(gpa);
        }
        self.arena_state.deinit();
        gpa.destroy(self);
    }

    /// Change `send_window` from the initial window in `window_base` to `initial`. The read
    /// task and the writer can both apply the same change: the swap applies it once. The
    /// result is the new window. A larger window wakes a send that waits.
    fn applyInitialWindow(self: *Stream, initial: u32) i64 {
        const old = self.window_base.swap(initial, .seq_cst);
        const delta = @as(i64, initial) - @as(i64, old);
        const window = self.send_window.fetchAdd(delta, .seq_cst) + delta;
        if (delta > 0) self.wake();
        return window;
    }

    fn retain(self: *Stream) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    fn release(self: *Stream) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) self.destroy();
    }

    fn idWord(self: *const Stream) u32 {
        return self.id_word.load(.seq_cst);
    }

    /// Claim the one reset frame of the stream. True for the first task only.
    fn claimReset(self: *Stream) bool {
        return !self.reset_claimed.swap(true, .seq_cst);
    }

    fn setState(self: *Stream, bits: u32) void {
        _ = self.state.fetchOr(bits, .seq_cst);
    }

    /// The stream arena, for the owner's own allocations.
    pub fn arena(self: *Stream) Allocator {
        return self.arena_state.allocator();
    }

    /// The connection of the stream ended. Safe from any task.
    pub fn connClosed(self: *const Stream) bool {
        return self.state.load(.seq_cst) & conn_closed != 0;
    }

    /// Add data from the peer. Only the read task calls this function.
    fn pushData(self: *Stream, data: []const u8) Allocator.Error!void {
        if (data.len == 0) return;
        const c = try Chunk.create(self.conn.gpa, data);
        self.data_tail.next.store(c, .release);
        self.data_tail = c;
        self.received += data.len;
    }

    /// Unregister and free the stream. A stream the peer still has open is reset. After a
    /// complete response, the server resets with `no_error`, thus the client stops the request
    /// and keeps the response (RFC 9113 section 8.1). Other streams get `cancel`.
    pub fn close(self: *Stream) void {
        const conn = self.conn;
        // The hook does not run after `close`.
        self.disarmHook();
        var word = self.idWord();
        if (word == 0) {
            // A stream without an id never goes to the peer. The writer drops its frames.
            word = self.id_word.cmpxchgStrong(0, closed_before_id, .seq_cst, .seq_cst) orelse closed_before_id;
        }
        if (word != closed_before_id) {
            const id: u31 = @intCast(word);
            var send_reset: ?frame.ErrorCode = null;
            if (!self.peerEnded() and self.reset_word.load(.seq_cst) == 0 and !conn.closed.load(.acquire)) {
                send_reset = if (conn.options.role == .server and self.local_closed) .no_error else .cancel;
            }
            if (send_reset != null and !self.claimReset()) send_reset = null;
            self.reset_on_close = send_reset != null or self.reset_word.load(.seq_cst) != 0;
            if (send_reset) |code| conn.sendRst(id, code);
            // The read task removes the stream from the table and releases the reference of
            // the table. The push comes before the count drops: see `isIdle`.
            conn.closed_streams.push(self);
        }
        _ = conn.owned.fetchSub(1, .seq_cst);
        self.release();
    }

    /// Reset the stream with `cancel`. Each task that waits on the stream wakes and sees the
    /// reset. The owner still calls `close`.
    pub fn cancel(self: *Stream) void {
        const conn = self.conn;
        const already = self.reset_word.load(.seq_cst) != 0 or conn.closed.load(.acquire);
        self.setReset(.cancel);
        if (already) return;
        // Without an id, the writer keeps the headers from the peer. See `assignId`.
        const word = self.idWord();
        if (word == 0 or word == closed_before_id) return;
        if (!self.claimReset()) return;
        conn.sendRst(@intCast(word), .cancel);
    }

    /// Stop the waits on the stream and send no reset. Each task that waits on the stream wakes
    /// and gets `error.Canceled`. A later wait also gets `error.Canceled` when it must block. The
    /// owner still calls `close`.
    ///
    /// To stop a task that waits on the stream, use this function, not `Future.cancel`. A
    /// cancel can come together with a wake-up of the stream. The flag of this function then
    /// still stops the wait.
    pub fn stopWaits(self: *Stream) void {
        self.setState(waits_stopped);
        self.wake();
    }

    /// Wake each task that waits on the stream. The task then checks the stream again.
    pub fn wake(self: *Stream) void {
        _ = self.epoch.fetchAdd(1, .seq_cst);
        if (self.waiters.load(.seq_cst) != 0) self.conn.io.futexWake(u32, &self.epoch.raw, std.math.maxInt(u32));
    }

    /// Wait for a change of the stream after the count `seen` of `epoch`. The caller loads
    /// `seen` before it checks its condition, and checks the condition again after the wait.
    /// Gives `error.Canceled` after `stopWaits`.
    fn waitChange(self: *Stream, seen: u32) Error!void {
        if (self.state.load(.seq_cst) & waits_stopped != 0) return error.Canceled;
        _ = self.waiters.fetchAdd(1, .seq_cst);
        defer _ = self.waiters.fetchSub(1, .seq_cst);
        try self.conn.io.futexWait(u32, &self.epoch.raw, seen);
    }

    /// The connection ended: wake the waits and run the hook. Safe from any task.
    fn markConnClosed(self: *Stream) void {
        self.setState(conn_closed);
        self.wake();
        self.fireHook();
    }

    /// The hook of `setOnReset`.
    pub const ResetHook = *const fn (userdata: ?*anyopaque, stream: *Stream) void;

    /// Set the hook that the connection calls when the stream gets a reset or when the
    /// connection ends. The reset can come from the peer, from this side or from `cancel`. The
    /// hook runs once for the stream. When the stream already has a reset, or the connection
    /// already ended, the hook runs at once, in the task of the caller.
    ///
    /// Null removes the hook, and the hook then does not run. When the hook runs in another
    /// task at that time, the removal waits for its end. Remove the hook before its data goes
    /// out of scope. The hook does not run after `close`.
    ///
    /// The connection calls the hook in the read task, in the writer or in the task that
    /// called `cancel`. Thus the hook must not wait, and it must not call a function of the
    /// connection. It can read the stream with `wasReset` and `connClosed`. Set a flag or wake
    /// a task in the hook, and do the work in that task.
    pub fn setOnReset(self: *Stream, hook: ?ResetHook, userdata: ?*anyopaque) void {
        self.disarmHook();
        const h = hook orelse return;
        if (self.hook_state.load(.seq_cst) == hook_done) return;
        self.on_reset = h;
        self.on_reset_userdata = userdata;
        self.hook_state.store(hook_armed, .seq_cst);
        if (self.reset_word.load(.seq_cst) != 0 or self.connClosed() or self.conn.closed.load(.seq_cst)) self.fireHook();
    }

    /// Remove the hook. When it runs now, wait for its end.
    fn disarmHook(self: *Stream) void {
        while (self.hook_state.cmpxchgStrong(hook_armed, hook_none, .seq_cst, .seq_cst)) |state| switch (state) {
            hook_running => self.conn.io.futexWaitUncancelable(u32, &self.hook_state.raw, hook_running),
            else => return,
        };
    }

    /// Run the hook of the owner, once.
    fn fireHook(self: *Stream) void {
        if (self.hook_state.cmpxchgStrong(hook_armed, hook_running, .seq_cst, .seq_cst) != null) return;
        self.on_reset.?(self.on_reset_userdata, self);
        self.hook_state.store(hook_done, .seq_cst);
        self.conn.io.futexWake(u32, &self.hook_state.raw, std.math.maxInt(u32));
    }

    /// Give the stream the reset `code` when it has none, wake its waits and run the hook of
    /// the owner.
    fn setReset(self: *Stream, code: frame.ErrorCode) void {
        _ = self.reset_word.cmpxchgStrong(0, @backingInt(code) + 1, .seq_cst, .seq_cst);
        self.wake();
        self.fireHook();
    }

    fn checkOpen(self: *const Stream) Error!void {
        if (self.conn.write_failed.load(.acquire)) return error.Closed;
        const word = self.reset_word.load(.seq_cst);
        if (word != 0) return if (word - 1 == @backingInt(frame.ErrorCode.refused_stream)) error.Closed else error.StreamReset;
        if (self.connClosed() or self.conn.closed.load(.seq_cst)) return error.Closed;
    }

    /// The peer ended the stream, thus the response is complete. Then the stream got a reset
    /// from the peer or from this side, with any code. Thus the client drops the remaining part
    /// of the request (RFC 9113 section 8.1), and the response stays available. This applies
    /// only to the client. On the server, the same state tells that the client canceled.
    fn answered(self: *const Stream) bool {
        return self.conn.options.role == .client and self.peerEnded() and self.reset_word.load(.seq_cst) != 0;
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

    /// The target of a frame of the stream: the id, or zero when the stream has no id yet,
    /// and the stream. See `Send`. A frame in the queue of the writer then holds the stream,
    /// and a failed write ends the stream.
    fn target(self: *Stream) struct { u31, ?*Stream } {
        const word = self.idWord();
        if (word == 0 or word == closed_before_id) return .{ 0, self };
        return .{ @intCast(word), self };
    }

    /// Send a header block. With `end_stream` no data follows. When the server already sent a
    /// complete response and the stream then got a reset, the client sends nothing and gets no
    /// error.
    pub fn sendHeaders(self: *Stream, headers: []const Header, end_stream_flag: bool) Error!void {
        const conn = self.conn;
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(conn.gpa);
        try conn.encoder.encodeHeaders(conn.gpa, &block, headers);
        if (self.answered()) {
            self.local_closed = true;
            return;
        }
        try self.checkOpen();
        if (end_stream_flag) self.local_closed = true;
        const id, const stream = self.target();
        try conn.submit(.{
            .kind = .headers,
            .flags = if (end_stream_flag) frame.Flags.end_stream else 0,
            .stream_id = id,
            .stream = stream,
            .payload = block.items,
            .flush = !self.corked,
        });
    }

    /// Take credit to send at most `want` bytes from the windows of the stream and of the
    /// connection. With `all`, take `want` bytes or nothing. The result is the bytes taken.
    fn takeCredit(self: *Stream, want: usize, all: bool) usize {
        const conn = self.conn;
        const wanted: i64 = @intCast(want);
        var window = self.send_window.load(.seq_cst);
        var taken: i64 = 0;
        while (true) {
            if (window <= 0 or (all and window < wanted)) return 0;
            taken = @min(window, wanted);
            window = self.send_window.cmpxchgWeak(window, window - taken, .seq_cst, .seq_cst) orelse break;
        }
        var conn_window = conn.send_window.load(.seq_cst);
        var got: i64 = 0;
        while (true) {
            if (conn_window <= 0 or (all and conn_window < taken)) {
                got = 0;
                break;
            }
            got = @min(conn_window, taken);
            conn_window = conn.send_window.cmpxchgWeak(conn_window, conn_window - got, .seq_cst, .seq_cst) orelse break;
        }
        // Give back the credit of the stream that the connection did not have.
        if (got < taken) _ = self.send_window.fetchAdd(taken - got, .seq_cst);
        return @intCast(got);
    }

    /// Wait for credit after the count `seen` of `epoch`. The first call only joins the waits
    /// for credit of the connection, and the caller checks the credit once more. The credit
    /// can come between its last check and the join.
    fn waitCredit(self: *Stream, seen: u32) Error!void {
        // The window of the stream is short: a `WINDOW_UPDATE` of the stream or a `SETTINGS`
        // frame wakes the stream.
        if (self.send_window.load(.seq_cst) <= 0) return self.waitChange(seen);
        if (!self.in_credit_queue.swap(true, .seq_cst)) {
            self.retain();
            self.conn.credit_waiters.push(self);
            return;
        }
        try self.waitChange(seen);
    }

    /// Send data. The call waits for flow control credit. With `end_stream` the send side closes.
    /// When the server sent a complete response and the stream then got a reset, the client
    /// stops the data and gets no error. The caller then reads the response.
    pub fn sendData(self: *Stream, bytes: []const u8, end_stream_flag: bool) Error!void {
        const conn = self.conn;
        var offset: usize = 0;
        // A corked stream flushes its frames before it waits for credit. The peer can need
        // them before it gives credit.
        var flushed = !self.corked;
        while (true) {
            var n: usize = 0;
            while (true) {
                const seen = self.epoch.load(.seq_cst);
                if (self.answered()) {
                    self.local_closed = true;
                    return;
                }
                try self.checkOpen();
                const remaining = bytes.len - offset;
                if (remaining == 0) break;
                n = self.takeCredit(@min(remaining, conn.peerMaxFrameSize()), false);
                if (n > 0) break;
                if (!flushed) {
                    flushed = true;
                    try conn.flushPending();
                    continue;
                }
                try self.waitCredit(seen);
            }
            const last = offset + n == bytes.len;
            if (last and end_stream_flag) self.local_closed = true;
            const id, const stream = self.target();
            try conn.submit(.{
                .kind = .data,
                .flags = if (last and end_stream_flag) frame.Flags.end_stream else 0,
                .stream_id = id,
                .stream = stream,
                .payload = bytes[offset..][0..n],
                .flush = !self.corked,
            });
            flushed = !self.corked;
            offset += n;
            if (last) return;
        }
    }

    /// Send data as `sendData` does, but do not wait for flow control credit. When the
    /// windows have less credit than `bytes.len`, nothing goes out and the result is
    /// `error.WouldBlock`. Only the read task gets more credit from the peer. Thus the read
    /// task uses this function, because it must not wait for that credit.
    pub fn sendDataNoWait(self: *Stream, bytes: []const u8, end_stream_flag: bool) (Error || error{WouldBlock})!void {
        const conn = self.conn;
        if (self.answered()) {
            self.local_closed = true;
            return;
        }
        try self.checkOpen();
        if (bytes.len > 0 and self.takeCredit(bytes.len, true) == 0) return error.WouldBlock;
        if (end_stream_flag) self.local_closed = true;
        const max = conn.peerMaxFrameSize();
        const id, const stream = self.target();
        var offset: usize = 0;
        while (true) {
            const n = @min(bytes.len - offset, max);
            const last = offset + n == bytes.len;
            try conn.submit(.{
                .kind = .data,
                .flags = if (last and end_stream_flag) frame.Flags.end_stream else 0,
                .stream_id = id,
                .stream = stream,
                .payload = bytes[offset..][0..n],
                .flush = last and !self.corked,
            });
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
        if (self.peerEnded() or self.reset_word.load(.acquire) != 0 or conn.closed.load(.acquire)) return false;
        if (self.received >= conn.options.initial_window_size / 2) return false;
        self.undispatched = true;
        _ = conn.owned.fetchSub(1, .seq_cst);
        return true;
    }

    /// The peer ended its side of the stream: the request or the response is complete.
    pub fn peerEnded(self: *const Stream) bool {
        return self.state.load(.seq_cst) & end_stream != 0;
    }

    /// Wait until the request or response headers arrived.
    pub fn waitHeaders(self: *Stream) Error![]const Header {
        while (true) {
            const seen = self.epoch.load(.seq_cst);
            const state = self.state.load(.seq_cst);
            if (state & headers_done != 0) return self.headers.items;
            try self.checkOpen();
            if (state & end_stream != 0) return error.StreamReset;
            try self.waitChange(seen);
        }
    }

    /// Read data. Returns zero at the end of the stream. The trailers are then available.
    pub fn read(self: *Stream, buf: []u8) Error!usize {
        const conn = self.conn;
        while (true) {
            const seen = self.epoch.load(.seq_cst);
            // The end comes after the last data. Thus after the end, each chunk is visible.
            const ended = self.peerEnded();
            const n = self.takeData(buf);
            if (n > 0) {
                self.recv_credit += @intCast(n);
                if (self.recv_credit >= conn.options.initial_window_size / 2 and !self.peerEnded()) {
                    const credit = self.recv_credit;
                    _ = self.recv_window.fetchAdd(credit, .seq_cst);
                    self.recv_credit = 0;
                    const word = self.idWord();
                    if (word != 0 and word != closed_before_id) conn.sendWindowUpdate(@intCast(word), credit);
                }
                return n;
            }
            if (ended) return 0;
            try self.checkOpen();
            try self.waitChange(seen);
        }
    }

    /// Copy the data that waits to `buf`. Only the owner calls this function.
    fn takeData(self: *Stream, buf: []u8) usize {
        var n: usize = 0;
        while (n < buf.len) {
            const next = self.data_head.next.load(.acquire) orelse break;
            const available = next.bytes()[next.pos..];
            const k = @min(buf.len - n, available.len);
            @memcpy(buf[n..][0..k], available[0..k]);
            next.pos += k;
            n += k;
            if (next.pos == next.len) {
                // The chunk that the owner read becomes the empty chunk at `data_head`.
                const old = self.data_head;
                self.data_head = next;
                if (old != &self.data_stub) old.free(self.conn.gpa);
            }
        }
        return n;
    }

    /// Wait until the peer ended the stream. The trailers, if any, are then available.
    pub fn waitEnd(self: *Stream) Error![]const Header {
        while (true) {
            const seen = self.epoch.load(.seq_cst);
            if (self.peerEnded()) return self.trailers.items;
            try self.checkOpen();
            try self.waitChange(seen);
        }
    }

    /// Wait until the stream got a reset or the connection ended. The reset can come from the
    /// peer or from this side, for example from `cancel`. After `stopWaits`, the wait ends with
    /// `error.Canceled`.
    pub fn waitCancelled(self: *Stream) Error!void {
        while (true) {
            const seen = self.epoch.load(.seq_cst);
            if (self.reset_word.load(.seq_cst) != 0 or self.connClosed() or self.conn.closed.load(.seq_cst)) return;
            try self.waitChange(seen);
        }
    }

    /// The reset code of the stream, or null. Safe from any task.
    pub fn wasReset(self: *const Stream) ?frame.ErrorCode {
        const word = self.reset_word.load(.seq_cst);
        if (word == 0) return null;
        return @fromBackingInt(@intCast(word - 1));
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

/// A client connection on fixed buffers, for the tests of this file.
fn testClient(written: []u8, writer: *Io.Writer, reader: *Io.Reader) !*Connection {
    writer.* = .fixed(written);
    reader.* = .fixed("");
    const conn = try Connection.init(std.testing.allocator, std.testing.io, reader, writer, .{ .role = .client });
    try conn.handshake();
    return conn;
}

test "the data of a stream that closed before its headers went out gives its credit back" {
    var written: [4096]u8 = undefined;
    var writer: Io.Writer = undefined;
    var reader: Io.Reader = undefined;
    const conn = try testClient(&written, &writer, &reader);
    defer conn.deinit();
    const before = conn.send_window.load(.seq_cst);
    // A busy writer: the headers and the data wait in the queue.
    conn.writer_busy.store(true, .seq_cst);
    const s = try conn.openStream();
    try s.sendHeaders(&.{ .{ .name = ":method", .value = "POST" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/" } }, false);
    try s.sendData("the request", true);
    try std.testing.expectEqual(before - 11, conn.send_window.load(.seq_cst));
    // The close comes before the writer gives the stream an id: nothing of the stream goes out.
    s.close();
    conn.writer_busy.store(false, .seq_cst);
    try conn.kick();
    try std.testing.expectEqual(before, conn.send_window.load(.seq_cst));
}

test "a stream of this side gets a change of the initial window that came before its registration" {
    var written: [4096]u8 = undefined;
    var writer: Io.Writer = undefined;
    var reader: Io.Reader = undefined;
    const conn = try testClient(&written, &writer, &reader);
    defer conn.deinit();
    const s = try conn.openStream();
    defer s.close();
    try std.testing.expectEqual(frame.default_initial_window, s.send_window.load(.seq_cst));
    // The peer raises the initial window before the stream is in the table.
    var payload: [6]u8 = (frame.Setting{ .id = @backingInt(frame.SettingId.initial_window_size), .value = 100_000 }).encode();
    try conn.onSettings(.{ .length = 6, .type = .settings, .flags = 0, .stream_id = 0 }, &payload);
    try s.sendHeaders(&.{ .{ .name = ":method", .value = "POST" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/" } }, false);
    conn.syncQueues();
    try std.testing.expectEqual(100_000, s.send_window.load(.seq_cst));
}
