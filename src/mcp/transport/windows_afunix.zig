//! The end of the stream of a Unix socket on Windows. The Windows driver of Unix sockets
//! (afunix.sys) can lose the close of the peer. This occurs when a receive starts at about the
//! same time as the close. The receive then stays pending, but a poll of the socket shows the
//! disconnect. A lost close keeps the read of a connection blocked until a cancel.
//!
//! `pollBeforeRead` changes a stream reader: each read first waits in a poll (AFD_POLL) until
//! the socket has data or the connection ends. Thus the receive starts only when it can
//! complete at once. Each poll stops after `poll_period` and starts again, so a poll that
//! does not see the close also cannot wait forever.
const std = @import("std");
const Io = std.Io;
const windows = std.os.windows;

/// The longest time of one poll. When a poll does not see the close of the peer, the next
/// poll sees it after this time.
pub const poll_period: Io.Duration = .fromSeconds(1);

/// Make each read of `reader` wait in a poll first. Call it before the first read. The reader
/// must stay at the same address.
pub fn pollBeforeRead(reader: *Io.net.Stream.Reader) void {
    reader.interface.vtable = &vtable;
}

const std_vtable: *const Io.Reader.VTable = Io.net.Stream.Reader.init(undefined, undefined, &.{}).interface.vtable;

const vtable: Io.Reader.VTable = .{
    .stream = stream,
    .discard = std_vtable.discard,
    .readVec = readVec,
    .rebase = std_vtable.rebase,
};

fn stream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    try awaitReadable(io_r);
    return std_vtable.stream(io_r, io_w, limit);
}

fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
    try awaitReadable(io_r);
    return std_vtable.readVec(io_r, data);
}

fn awaitReadable(io_r: *Io.Reader) error{ReadFailed}!void {
    const r: *Io.net.Stream.Reader = @alignCast(@fieldParentPtr("interface", io_r));
    poll(r.io, r.stream.socket.handle, poll_period) catch |e| {
        r.err = e;
        return error.ReadFailed;
    };
}

// The events of AFD_POLL.
const poll_receive: u32 = 0x1;
const poll_disconnect: u32 = 0x8;
const poll_abort: u32 = 0x10;
const poll_local_close: u32 = 0x20;

const PollHandleInfo = extern struct {
    handle: windows.HANDLE,
    events: u32,
    status: windows.NTSTATUS,
};

const PollInfo = extern struct {
    /// A negative value is a relative time in units of 100 nanoseconds.
    timeout: i64,
    count: u32,
    exclusive: u32,
    handles: [1]PollHandleInfo,
};

/// Wait until the socket has data, the peer ended the connection, or the connection failed.
/// A poll that fails returns at once: the read after it reports the failure. Each poll
/// stops after `period` and starts again.
fn poll(io: Io, handle: windows.HANDLE, period: Io.Duration) Io.Cancelable!void {
    const timeout: i64 = @intCast(@divTrunc(period.nanoseconds, 100));
    while (true) {
        var info: PollInfo = .{
            .timeout = -timeout,
            .count = 1,
            .exclusive = 0,
            .handles = .{.{ .handle = handle, .events = poll_receive | poll_disconnect | poll_abort | poll_local_close, .status = .SUCCESS }},
        };
        const result = try io.operate(.{ .device_io_control = .{
            .file = .{ .handle = handle, .flags = .{ .nonblocking = true } },
            .code = windows.IOCTL.AFD.POLL,
            .in = std.mem.asBytes(&info),
            .out = std.mem.asBytes(&info),
        } });
        switch (result.device_io_control.u.Status) {
            // The time of the poll ended without an event.
            .TIMEOUT => continue,
            .SUCCESS => if (info.count == 0 or info.handles[0].events == 0) continue,
            else => {},
        }
        return;
    }
}

/// A connected pair of Unix sockets in a temporary directory.
const Pair = struct {
    tmp: std.testing.TmpDir,
    listener: Io.net.Server,
    client: Io.net.Stream,
    server: Io.net.Stream,
    client_open: bool,

    fn open(self: *Pair) !void {
        const io = std.testing.io;
        const gpa = std.testing.allocator;
        self.tmp = std.testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        const cwd = try std.process.currentPathAlloc(io, gpa);
        defer gpa.free(cwd);
        const path = try std.fs.path.resolve(gpa, &.{ cwd, ".zig-cache", "tmp", &self.tmp.sub_path, "s" });
        defer gpa.free(path);
        const address = try Io.net.UnixAddress.init(path);
        self.listener = try address.listen(io, .{});
        errdefer self.listener.deinit(io);
        self.client = try address.connect(io);
        errdefer self.client.close(io);
        self.server = try self.listener.accept(io);
        self.client_open = true;
    }

    fn closeClient(self: *Pair) void {
        if (!self.client_open) return;
        self.client.close(std.testing.io);
        self.client_open = false;
    }

    fn close(self: *Pair) void {
        const io = std.testing.io;
        self.closeClient();
        self.server.close(io);
        self.listener.deinit(io);
        self.tmp.cleanup();
    }

    fn send(self: *Pair, bytes: []const u8) !void {
        var buf: [64]u8 = undefined;
        var writer = self.client.writer(std.testing.io, &buf);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }
};

/// Polls the server side of a pair, then sets `done`.
fn pollTask(handle: windows.HANDLE, period: Io.Duration, done: *std.atomic.Value(bool)) Io.Cancelable!void {
    try poll(std.testing.io, handle, period);
    done.store(true, .release);
}

test "a poll that ends without an event starts again" {
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();
    var done: std.atomic.Value(bool) = .init(false);
    var future = try io.concurrent(pollTask, .{ pair.server.socket.handle, Io.Duration.fromMilliseconds(10), &done });
    // About ten polls end without an event in this time.
    try io.sleep(.fromMilliseconds(100), .awake);
    try std.testing.expect(!done.load(.acquire));
    try pair.send("x");
    try future.await(io);
    try std.testing.expect(done.load(.acquire));
}

test "a cancel stops a poll" {
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();
    var done: std.atomic.Value(bool) = .init(false);
    var future = try io.concurrent(pollTask, .{ pair.server.socket.handle, poll_period, &done });
    try io.sleep(.fromMilliseconds(20), .awake);
    try std.testing.expectError(error.Canceled, future.cancel(io));
    try std.testing.expect(!done.load(.acquire));
}

test "a reader that polls first reads the data and the end of the stream" {
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.open();
    defer pair.close();
    var buf: [16]u8 = undefined;
    var reader = pair.server.reader(io, &buf);
    pollBeforeRead(&reader);
    try pair.send("one\ntwo\n");
    pair.closeClient();
    try std.testing.expectEqualStrings("one", try reader.interface.takeDelimiterExclusive('\n'));
    reader.interface.toss(1);
    try std.testing.expectEqualStrings("two", try reader.interface.takeDelimiterExclusive('\n'));
    reader.interface.toss(1);
    try std.testing.expectError(error.EndOfStream, reader.interface.takeByte());
    // A discard reads through `stream`, which also polls first.
    try std.testing.expectError(error.EndOfStream, reader.interface.discardAll(1));
}
