//! Wake an accept loop that waits in `accept`. On Windows a cancel does not always wake a
//! blocked accept. Thus a server connects to its own listener one time before it cancels its
//! accept loop. The loop sees its stop flag after the accept and closes that connection.
const std = @import("std");
const Io = std.Io;

/// Connect to `address` one time and close the connection. An unspecified address becomes the
/// loopback address of the same family. The function ignores errors.
pub fn wakeIp(io: Io, address: Io.net.IpAddress) void {
    const target = loopbackFor(address);
    const stream = target.connect(io, .{ .mode = .stream }) catch return;
    stream.close(io);
}

/// Connect to the Unix socket at `path` one time and close the connection. The function
/// ignores errors.
pub fn wakeUnix(io: Io, path: []const u8) void {
    if (!Io.net.has_unix_sockets) return;
    const address = Io.net.UnixAddress.init(path) catch return;
    const stream = address.connect(io) catch return;
    stream.close(io);
}

/// Stop `future`, the task of an accept loop that listens on `address`, and wait for its end.
/// The function sets `stopping`, which the loop reads after each `accept`. The cancel runs in
/// its own task, and this function connects to the listener until the task ends. Thus the
/// loop wakes also when it waits in `accept`, and also when an inner call used up the cancel.
pub fn cancelAcceptLoop(io: Io, future: anytype, address: Io.net.IpAddress, stopping: *std.atomic.Value(bool)) void {
    cancelLoop(io, future, stopping, address, wakeIp);
}

/// `cancelAcceptLoop` for an accept loop that listens on the Unix socket at `path`.
pub fn cancelUnixAcceptLoop(io: Io, future: anytype, path: []const u8, stopping: *std.atomic.Value(bool)) void {
    cancelLoop(io, future, stopping, path, wakeUnix);
}

fn cancelLoop(io: Io, future: anytype, stopping: *std.atomic.Value(bool), target: anytype, comptime wakeFn: fn (Io, @TypeOf(target)) void) void {
    stopping.store(true, .release);
    const Canceller = struct {
        fn run(f: @TypeOf(future), done: *std.atomic.Value(bool), task_io: Io) void {
            _ = f.cancel(task_io);
            done.store(true, .release);
        }
    };
    var done: std.atomic.Value(bool) = .init(false);
    var canceller = io.concurrent(Canceller.run, .{ future, &done, io }) catch {
        _ = future.cancel(io);
        return;
    };
    while (!done.load(.acquire)) {
        wakeFn(io, target);
        io.sleep(.fromMilliseconds(5), .awake) catch break;
    }
    canceller.await(io);
}

fn loopbackFor(address: Io.net.IpAddress) Io.net.IpAddress {
    return switch (address) {
        .ip4 => |a| if (std.mem.allEqual(u8, &a.bytes, 0)) .{ .ip4 = .loopback(a.port) } else address,
        .ip6 => |a| if (std.mem.allEqual(u8, &a.bytes, 0)) .{ .ip6 = .loopback(a.port) } else address,
    };
}

test "an unspecified address becomes the loopback address" {
    const any4 = try Io.net.IpAddress.parse("0.0.0.0", 8080);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &loopbackFor(any4).ip4.bytes);
    try std.testing.expectEqual(8080, loopbackFor(any4).getPort());
    const any6 = try Io.net.IpAddress.parse("::", 9);
    try std.testing.expectEqual(1, loopbackFor(any6).ip6.bytes[15]);
    const fixed = try Io.net.IpAddress.parse("10.0.0.2", 1);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &loopbackFor(fixed).ip4.bytes);
}

test "wakeIp wakes a task that waits in accept" {
    const io = std.testing.io;
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer listener.deinit(io);
    const Loop = struct {
        fn run(l: *Io.net.Server) void {
            const stream = l.accept(std.testing.io) catch return;
            stream.close(std.testing.io);
        }
    };
    var future = try io.concurrent(Loop.run, .{&listener});
    wakeIp(io, listener.socket.address);
    future.await(io);
}

test "cancelAcceptLoop ends a loop that serves each connection and waits in accept" {
    const io = std.testing.io;
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer listener.deinit(io);
    const Loop = struct {
        fn run(l: *Io.net.Server, stop: *std.atomic.Value(bool)) void {
            while (!stop.load(.acquire)) {
                const stream = l.accept(std.testing.io) catch return;
                stream.close(std.testing.io);
            }
        }
    };
    for (0..20) |_| {
        var stopping: std.atomic.Value(bool) = .init(false);
        var future = try io.concurrent(Loop.run, .{ &listener, &stopping });
        cancelAcceptLoop(io, &future, listener.socket.address, &stopping);
    }
}
