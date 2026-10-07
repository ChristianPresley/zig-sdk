//! Loopback tests: an HTTP/2 client connection against a server connection over TCP.
const std = @import("std");
const Io = std.Io;
const Connection = @import("Connection.zig");
const frame = @import("frame.zig");
const Header = Connection.Header;

const buffer_len = 64 << 10;

/// The longest time that a test waits for the peer. A loopback peer answers in milliseconds.
/// Thus a longer wait tells of a defect, and the test fails.
pub const wait_limit: Io.Duration = .fromSeconds(10);

/// Reset a stream with `cancel` when a test waits for the peer for more than `wait_limit`.
/// The reset ends each wait on the stream. Thus a defect makes the test fail, and the test
/// binary continues with the next test.
pub const Watchdog = struct {
    stream: *Connection.Stream,
    fired: std.atomic.Value(bool) = .init(false),
    future: ?Io.Future(void) = null,

    /// Start the timer. Call `finish` before the stream closes.
    pub fn start(self: *Watchdog, io: Io) Io.ConcurrentError!void {
        self.future = try io.concurrent(run, .{ self, io });
    }

    /// Stop the timer. When the timer reset the stream, log an error and give `error.Timeout`.
    pub fn finish(self: *Watchdog, io: Io) error{Timeout}!void {
        if (self.future) |*f| f.cancel(io);
        self.future = null;
        if (!self.fired.load(.acquire)) return;
        std.log.err("no answer from the peer on stream {d} after {d} s", .{ self.stream.id, wait_limit.toSeconds() });
        return error.Timeout;
    }

    fn run(self: *Watchdog, io: Io) void {
        io.sleep(wait_limit, .awake) catch return;
        self.fired.store(true, .release);
        self.stream.cancel();
        // Also wake the waits here, thus a defect in the wake-up of `cancel` cannot stop the
        // test binary.
        const conn = self.stream.conn;
        conn.lock.lockUncancelable(conn.io);
        conn.cond.broadcast(conn.io);
        conn.lock.unlock(conn.io);
    }
};

/// Wait until the peer ended `stream` and the stream then got a reset, for at most
/// `wait_limit`. Return the code of the reset, or null when the connection ended first.
pub fn waitAnswer(io: Io, stream: *Connection.Stream) !?frame.ErrorCode {
    var watchdog: Watchdog = .{ .stream = stream };
    try watchdog.start(io);
    const result = waitEndAndReset(stream);
    try watchdog.finish(io);
    try result;
    return stream.wasReset();
}

fn waitEndAndReset(stream: *Connection.Stream) Connection.Error!void {
    _ = try stream.waitEnd();
    try stream.waitCancelled();
}

/// Wait until `event` is set, for at most `wait_limit`. Else log an error and give
/// `error.Timeout`.
fn waitSet(io: Io, event: *Io.Event) !void {
    const deadline: Io.Clock.Timestamp = .fromNow(io, .{ .raw = wait_limit, .clock = .awake });
    while (true) {
        event.waitTimeout(io, .{ .deadline = deadline }) catch |err| switch (err) {
            // A spurious wake-up also gives `error.Timeout`.
            error.Timeout => {
                if (event.isSet()) return;
                if (deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
                std.log.err("the event is not set after {d} s", .{wait_limit.toSeconds()});
                return error.Timeout;
            },
            error.Canceled => |e| return e,
        };
        return;
    }
}

/// One side of the loopback: the socket, its buffers and the connection.
const Side = struct {
    io: Io,
    gpa: std.mem.Allocator,
    stream: Io.net.Stream,
    in_buf: []u8,
    out_buf: []u8,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    conn: *Connection,
    run_future: ?Io.Future(void) = null,

    fn init(self: *Side, io: Io, gpa: std.mem.Allocator, stream: Io.net.Stream, options: Connection.Options) !void {
        self.io = io;
        self.gpa = gpa;
        self.stream = stream;
        self.in_buf = try gpa.alloc(u8, buffer_len);
        self.out_buf = try gpa.alloc(u8, buffer_len);
        self.reader = self.stream.reader(io, self.in_buf);
        self.writer = self.stream.writer(io, self.out_buf);
        self.conn = try Connection.init(gpa, io, &self.reader.interface, &self.writer.interface, options);
    }

    fn start(self: *Side) !void {
        try self.conn.handshake();
        self.run_future = try self.io.concurrent(Connection.run, .{self.conn});
    }

    /// Send no more data. The peer reads the end of the stream and closes its side.
    fn halfClose(self: *Side) void {
        self.conn.shutdown();
        self.stream.shutdown(self.io, .send) catch {};
    }

    /// Wait for the read task to see the end of the input.
    fn awaitRun(self: *Side) void {
        if (self.run_future) |*f| f.await(self.io);
        self.run_future = null;
    }

    /// Wait for the read task, then close and free.
    fn finish(self: *Side) void {
        self.awaitRun();
        self.stream.close(self.io);
        self.conn.deinit();
        self.gpa.free(self.in_buf);
        self.gpa.free(self.out_buf);
    }
};

/// The echo server: for every stream, answer 200 and echo the request body, then trailers.
/// On the path "/early", the server sends a complete response before it reads the request.
/// On the path "/early-cancel", the server sends the same response and then resets the stream
/// with `cancel`. The server of version 0.3.0 and some other servers do this.
///
/// On the path "/hold", the server reads the request, waits for the reset of the client and
/// then tries to answer. On the path "/wait", the server waits until the stream gets a reset.
/// The test resets the stream with `cancel` from its own task.
const EchoServer = struct {
    side: Side,
    group: Io.Group = .init,
    streams_seen: std.atomic.Value(u32) = .init(0),
    /// The result of the answer on "/hold". It is set when `hold_done` is set.
    hold_result: Connection.Error!void = {},
    hold_done: Io.Event = .unset,
    /// The stream of the path "/wait". It is set when `waiting` is set. It stays valid until
    /// the stream gets a reset.
    wait_stream: ?*Connection.Stream = null,
    waiting: Io.Event = .unset,
    /// The reset that ended the wait on "/wait". It is set when `wait_done` is set.
    wait_reset: ?frame.ErrorCode = null,
    wait_done: Io.Event = .unset,

    fn onStream(userdata: ?*anyopaque, stream: *Connection.Stream) void {
        const self: *EchoServer = @ptrCast(@alignCast(userdata.?));
        _ = self.streams_seen.fetchAdd(1, .monotonic);
        self.group.concurrent(self.side.io, handle, .{ self, stream }) catch stream.cancel();
    }

    fn handle(self: *EchoServer, stream: *Connection.Stream) void {
        defer stream.close();
        const headers = stream.waitHeaders() catch return;
        const path = Connection.findHeader(headers, ":path") orelse "";
        if (std.mem.eql(u8, path, "/refuse")) {
            stream.cancel();
            return;
        }
        if (std.mem.eql(u8, path, "/early")) {
            // `close` then resets the stream, because the request did not end.
            stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "grpc-status", .value = "12" } }, true) catch {};
            return;
        }
        if (std.mem.eql(u8, path, "/early-cancel")) {
            // The reset comes before `close`, thus `close` sends no second reset.
            stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "grpc-status", .value = "12" } }, true) catch return;
            stream.cancel();
            return;
        }
        if (std.mem.eql(u8, path, "/hold")) {
            defer self.hold_done.set(self.side.io);
            self.hold_result = holdAnswer(stream);
            return;
        }
        if (std.mem.eql(u8, path, "/wait")) {
            self.wait_stream = stream;
            self.waiting.set(self.side.io);
            stream.waitCancelled() catch {};
            self.wait_reset = stream.wasReset();
            self.wait_done.set(self.side.io);
            return;
        }
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.side.gpa);
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = stream.read(&buf) catch return;
            if (n == 0) break;
            body.appendSlice(self.side.gpa, buf[0..n]) catch return;
        }
        stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" } }, false) catch return;
        stream.sendData(body.items, false) catch return;
        var len_buf: [16]u8 = undefined;
        const len_text = std.fmt.bufPrint(&len_buf, "{d}", .{body.items.len}) catch unreachable;
        stream.sendHeaders(&.{ .{ .name = "grpc-status", .value = "0" }, .{ .name = "x-echo-length", .value = len_text } }, true) catch return;
    }

    /// Read the complete request, wait for the reset of the client, then send headers.
    fn holdAnswer(stream: *Connection.Stream) Connection.Error!void {
        var buf: [4096]u8 = undefined;
        while (try stream.read(&buf) != 0) {}
        try stream.waitCancelled();
        try stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" } }, false);
    }
};

const Pair = struct {
    listener: Io.net.Server,
    server: EchoServer,
    client: Side,
    accept_future: Io.Future(anyerror!void),

    fn start(self: *Pair, io: Io, gpa: std.mem.Allocator, client_options: Connection.Options) !void {
        self.listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{});
        errdefer self.listener.deinit(io);
        self.server = .{ .side = undefined };
        self.accept_future = try io.concurrent(acceptOne, .{ self, io, gpa });
        const address = Io.net.IpAddress.parse("127.0.0.1", self.listener.socket.address.getPort()) catch unreachable;
        const stream = try address.connect(io, .{ .mode = .stream });
        try self.client.init(io, gpa, stream, client_options);
        try self.client.start();
        try self.accept_future.await(io);
    }

    fn acceptOne(self: *Pair, io: Io, gpa: std.mem.Allocator) anyerror!void {
        const stream = try self.listener.accept(io);
        try self.server.side.init(io, gpa, stream, .{ .role = .server, .on_stream = EchoServer.onStream, .userdata = &self.server, .max_concurrent_streams = 4 });
        try self.server.side.start();
    }

    fn stop(self: *Pair) void {
        const io = self.client.io;
        // The client stops sending; the server sees the end, finishes and closes; then the
        // client sees the end too.
        self.client.halfClose();
        // The handlers close their streams, so they finish before the server connection
        // frees its streams. Before, a handler could close a freed stream.
        self.server.side.awaitRun();
        self.server.group.await(io) catch {};
        self.server.side.finish();
        self.client.finish();
        self.listener.deinit(io);
    }
};

/// Send `body` to `path` on a new stream and return the echo, for at most `wait_limit`.
fn request(pair: *Pair, path: []const u8, body: []const u8) ![]u8 {
    const gpa = pair.client.gpa;
    const stream = try pair.client.conn.openStream();
    defer stream.close();
    var watchdog: Watchdog = .{ .stream = stream };
    try watchdog.start(pair.client.io);
    const result = exchange(gpa, stream, path, body);
    watchdog.finish(pair.client.io) catch |err| {
        if (result) |out| gpa.free(out) else |_| {}
        return err;
    };
    return result;
}

fn exchange(gpa: std.mem.Allocator, stream: *Connection.Stream, path: []const u8, body: []const u8) ![]u8 {
    try stream.sendHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, false);
    try stream.sendData(body, true);
    const headers = try stream.waitHeaders();
    try std.testing.expectEqualStrings("200", Connection.findHeader(headers, ":status").?);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try stream.read(&buf);
        if (n == 0) break;
        try out.appendSlice(gpa, buf[0..n]);
    }
    const trailers = try stream.waitEnd();
    try std.testing.expectEqualStrings("0", Connection.findHeader(trailers, "grpc-status").?);
    return out.toOwnedSlice(gpa);
}

test "echo over a loopback connection, including a body larger than the windows" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.start(io, gpa, .{ .role = .client, .initial_window_size = 65535, .connection_window = 65535 });
    defer pair.stop();

    const small = try request(&pair, "/echo", "hello");
    defer gpa.free(small);
    try std.testing.expectEqualStrings("hello", small);

    // Larger than both windows and than one frame: flow control and chunking work.
    const big = try gpa.alloc(u8, 300_000);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @intCast(i % 251);
    const echoed = try request(&pair, "/echo", big);
    defer gpa.free(echoed);
    try std.testing.expectEqualSlices(u8, big, echoed);
    try std.testing.expectEqual(2, pair.server.streams_seen.load(.monotonic));
}

test "a reset stream fails the client side and the peer settings arrive" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.start(io, gpa, .{ .role = .client });
    defer pair.stop();
    const stream = try pair.client.conn.openStream();
    defer stream.close();
    try stream.sendHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/refuse" },
    }, true);
    try std.testing.expectError(error.StreamReset, stream.waitHeaders());
    try std.testing.expectEqual(frame.ErrorCode.cancel, stream.wasReset().?);
    // The server advertised its limit; the client learned it with the SETTINGS frame.
    try std.testing.expectEqual(4, pair.client.conn.peer.max_concurrent_streams.?);
}

test "a complete response before the end of the request stays readable after the reset" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.start(io, gpa, .{ .role = .client });
    defer pair.stop();
    const stream = try pair.client.conn.openStream();
    defer stream.close();
    try stream.sendHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/early" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, false);
    // The client sends its data only after the response and the reset arrived. The server
    // resets with NO_ERROR after a complete response (RFC 9113 section 8.1). The send then
    // stops without an error. Before, the server sent CANCEL and `sendData` returned
    // `error.StreamReset`, thus the caller lost the response.
    try std.testing.expectEqual(@as(?frame.ErrorCode, .no_error), try waitAnswer(io, stream));
    try stream.sendData("the request", true);
    const headers = try stream.waitHeaders();
    try std.testing.expectEqualStrings("12", Connection.findHeader(headers, "grpc-status").?);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(0, try stream.read(&buf));
    // The connection serves the next stream.
    const echoed = try request(&pair, "/echo", "next");
    defer gpa.free(echoed);
    try std.testing.expectEqualStrings("next", echoed);
}

test "a complete response before the end of the request stays readable after a CANCEL reset" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.start(io, gpa, .{ .role = .client });
    defer pair.stop();
    const stream = try pair.client.conn.openStream();
    defer stream.close();
    try stream.sendHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/early-cancel" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, false);
    // The server of version 0.3.0 and some other servers reset with CANCEL after a complete
    // response. The response comes before the reset, thus the client keeps it. The send
    // after the reset stops without an error, as after a reset with NO_ERROR.
    try std.testing.expectEqual(@as(?frame.ErrorCode, .cancel), try waitAnswer(io, stream));
    try stream.sendData("the request", true);
    const headers = try stream.waitHeaders();
    try std.testing.expectEqualStrings("200", Connection.findHeader(headers, ":status").?);
    try std.testing.expectEqualStrings("12", Connection.findHeader(headers, "grpc-status").?);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(0, try stream.read(&buf));
    // The connection serves the next stream.
    const echoed = try request(&pair, "/echo", "next");
    defer gpa.free(echoed);
    try std.testing.expectEqualStrings("next", echoed);
}

test "the server cannot answer after the client ended the request and reset the stream" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.start(io, gpa, .{ .role = .client });
    defer pair.stop();
    const stream = try pair.client.conn.openStream();
    defer stream.close();
    try stream.sendHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/hold" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, false);
    try stream.sendData("the request", true);
    stream.cancel();
    // On the server, a reset after the end of the request tells that the client canceled.
    // Thus a send fails, also when the request is complete.
    try waitSet(io, &pair.server.hold_done);
    try std.testing.expectError(error.StreamReset, pair.server.hold_result);
}

test "a cancel from another task wakes the task that waits on the stream" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.start(io, gpa, .{ .role = .client });
    defer pair.stop();
    const stream = try pair.client.conn.openStream();
    defer stream.close();
    try stream.sendHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/wait" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, false);
    // The handler waits in `waitCancelled`, and the client sends no more frames. Thus only the
    // wake-up of `cancel` ends the wait. Before, the wait continued until the next frame on the
    // connection or the end of the connection.
    try waitSet(io, &pair.server.waiting);
    pair.server.wait_stream.?.cancel();
    try waitSet(io, &pair.server.wait_done);
    try std.testing.expectEqual(@as(?frame.ErrorCode, .cancel), pair.server.wait_reset);
}

test "concurrent streams interleave" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pair: Pair = undefined;
    try pair.start(io, gpa, .{ .role = .client });
    defer pair.stop();
    const Job = struct {
        pair: *Pair,
        index: usize,
        result: anyerror!void = {},
        fn run(job: *@This()) void {
            job.result = job.runInner();
        }
        fn runInner(job: *@This()) !void {
            var body: [1000]u8 = undefined;
            @memset(&body, @intCast('a' + job.index));
            const echoed = try request(job.pair, "/echo", &body);
            defer job.pair.client.gpa.free(echoed);
            try std.testing.expectEqualSlices(u8, &body, echoed);
        }
    };
    var jobs: [3]Job = undefined;
    var group: Io.Group = .init;
    for (&jobs, 0..) |*job, i| {
        job.* = .{ .pair = &pair, .index = i };
        try group.concurrent(io, Job.run, .{job});
    }
    try group.await(io);
    for (jobs) |job| try job.result;
}

fn acceptServer(side: *Side, listener: *Io.net.Server, io: Io, gpa: std.mem.Allocator) anyerror!void {
    const stream = try listener.accept(io);
    try side.init(io, gpa, stream, .{ .role = .server });
    try side.start();
}

/// Send the preface, an empty `SETTINGS` frame and `bytes` from a raw socket to a server
/// connection. Return the error code of the `GOAWAY` frame that the server sends.
fn goawayCodeFor(bytes: []const u8) !frame.ErrorCode {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{});
    defer listener.deinit(io);
    var server: Side = undefined;
    var accept_future = try io.concurrent(acceptServer, .{ &server, &listener, io, gpa });
    const address = Io.net.IpAddress.parse("127.0.0.1", listener.socket.address.getPort()) catch unreachable;
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var in_buf: [1024]u8 = undefined;
    var out_buf: [1024]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    const settings: frame.Header = .{ .length = 0, .type = .settings, .flags = 0, .stream_id = 0 };
    try writer.interface.writeAll(frame.preface);
    try writer.interface.writeAll(&settings.encode());
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
    try accept_future.await(io);
    defer server.finish();
    while (true) {
        const header = frame.Header.parse(try reader.interface.takeArray(frame.header_len));
        if (header.type != .goaway) {
            try reader.interface.discardAll(header.length);
            continue;
        }
        const payload = try reader.interface.takeArray(8);
        return @enumFromInt(std.mem.readInt(u32, payload[4..8], .big));
    }
}

test "a frame larger than the maximum frame size gives GOAWAY with FRAME_SIZE_ERROR" {
    // The server reads the header and stops. It does not wait for the payload.
    const oversize: frame.Header = .{ .length = frame.default_max_frame_size + 1, .type = .data, .flags = 0, .stream_id = 1 };
    try std.testing.expectEqual(frame.ErrorCode.frame_size_error, try goawayCodeFor(&oversize.encode()));
}

test "a control frame with a wrong length gives GOAWAY with FRAME_SIZE_ERROR" {
    const ping: frame.Header = .{ .length = 4, .type = .ping, .flags = 0, .stream_id = 0 };
    try std.testing.expectEqual(frame.ErrorCode.frame_size_error, try goawayCodeFor(&(ping.encode() ++ [_]u8{0} ** 4)));
}

test "a PING frame on a stream gives GOAWAY with PROTOCOL_ERROR" {
    const ping: frame.Header = .{ .length = 8, .type = .ping, .flags = 0, .stream_id = 1 };
    try std.testing.expectEqual(frame.ErrorCode.protocol_error, try goawayCodeFor(&(ping.encode() ++ [_]u8{0} ** 8)));
}
