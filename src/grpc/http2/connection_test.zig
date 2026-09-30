//! Loopback tests: an HTTP/2 client connection against a server connection over TCP.
const std = @import("std");
const Io = std.Io;
const Connection = @import("Connection.zig");
const frame = @import("frame.zig");
const Header = Connection.Header;

const buffer_len = 64 << 10;

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

    /// Stop sending. The peer reads the end of the stream and closes its side.
    fn halfClose(self: *Side) void {
        self.conn.shutdown();
        self.stream.shutdown(self.io, .send) catch {};
    }

    /// Wait for the read task, then close and free.
    fn finish(self: *Side) void {
        if (self.run_future) |*f| f.await(self.io);
        self.stream.close(self.io);
        self.conn.deinit();
        self.gpa.free(self.in_buf);
        self.gpa.free(self.out_buf);
    }
};

/// The echo server: for every stream, answer 200 and echo the request body, then trailers.
const EchoServer = struct {
    side: Side,
    group: Io.Group = .init,
    streams_seen: std.atomic.Value(u32) = .init(0),

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
        self.server.side.finish();
        self.client.finish();
        self.server.group.await(io) catch {};
        self.listener.deinit(io);
    }
};

fn request(pair: *Pair, path: []const u8, body: []const u8) ![]u8 {
    const gpa = pair.client.gpa;
    const stream = try pair.client.conn.openStream();
    defer stream.close();
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
