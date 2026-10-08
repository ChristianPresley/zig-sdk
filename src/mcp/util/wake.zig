//! Wake an accept loop that waits in `accept`. On Windows a cancel does not always wake a
//! blocked accept. Thus a server connects to its own listener one time before it cancels its
//! accept loop. The loop sees its stop flag after the accept and closes that connection.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;

/// The longest wait of `wakeIp` for its connect on a POSIX system.
const connect_wait: Io.Duration = .fromMilliseconds(100);

/// Connect to `address` one time and close the connection. An unspecified address becomes the
/// loopback address of the same family. The function ignores errors.
///
/// On a POSIX system, the socket of the connect does not block. The function waits for the
/// connect in `poll`, for 100 ms or less. A signal can interrupt the wait, and the
/// function then waits again.
///
/// The connect of std blocks, and after a signal it connects again. In Zig 0.16.0, std can
/// send its cancel signal late, to a task that already saw its cancel. Such a task is
/// frequently the task that stops a server. On macOS, the second connect then gets `EISCONN`,
/// and a Debug build stops with a panic.
pub fn wakeIp(io: Io, address: Io.net.IpAddress) void {
    const target = loopbackFor(address);
    if (comptime posix_connect) return connectPosix(io, target);
    const stream = target.connect(io, .{ .mode = .stream }) catch return;
    stream.close(io);
}

/// True when `wakeIp` uses the POSIX system calls for its connect.
const posix_connect = switch (builtin.os.tag) {
    .windows, .wasi => false,
    else => true,
};

fn connectPosix(io: Io, target: Io.net.IpAddress) void {
    const no_socket_flags = Io.Threaded.socket_flags_unsupported;
    const flags: u32 = posix.SOCK.STREAM | if (no_socket_flags) 0 else posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    const family: u32 = switch (target) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const rc = posix.system.socket(family, flags, 0);
    if (posix.errno(rc) != .SUCCESS) return;
    const fd: posix.fd_t = @intCast(rc);
    defer _ = posix.system.close(fd);
    if (no_socket_flags) {
        if (posix.errno(posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC))) != .SUCCESS) return;
        const status = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
        if (posix.errno(status) != .SUCCESS) return;
        const nonblock: usize = @as(u32, @bitCast(posix.O{ .NONBLOCK = true }));
        if (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, @as(usize, @intCast(status)) | nonblock)) != .SUCCESS) return;
    }
    var storage: extern union {
        any: posix.sockaddr,
        in: posix.sockaddr.in,
        in6: posix.sockaddr.in6,
    } = undefined;
    const len: posix.socklen_t = switch (target) {
        .ip4 => |a| len: {
            storage = .{ .in = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes) } };
            break :len @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |a| len: {
            storage = .{ .in6 = .{
                .port = std.mem.nativeToBig(u16, a.port),
                .flowinfo = a.flow,
                .addr = a.bytes,
                .scope_id = a.interface.index,
            } };
            break :len @sizeOf(posix.sockaddr.in6);
        },
    };
    switch (posix.errno(posix.system.connect(fd, &storage.any, len))) {
        .SUCCESS => return,
        // The connect continues after the interrupt.
        .INPROGRESS, .INTR => {},
        else => return,
    }
    var fds = [1]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    const end = Io.Clock.Timestamp.fromNow(io, .{ .raw = connect_wait, .clock = .awake });
    while (true) {
        const left = end.durationFromNow(io).raw.toMilliseconds();
        if (left <= 0) return;
        switch (posix.errno(posix.system.poll(&fds, fds.len, @intCast(@min(left, std.math.maxInt(i32)))))) {
            .INTR => continue,
            // The connect is complete, failed, or did not end in time.
            else => return,
        }
    }
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

test "wakeIp connects also when signals interrupt it" {
    if (comptime !posix_connect or SignalTarget == void) return error.SkipZigTest;
    const io = std.testing.io;
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer listener.deinit(io);
    const Loop = struct {
        fn run(l: *Io.net.Server, accepted: *std.atomic.Value(u32), stop: *std.atomic.Value(bool)) void {
            while (!stop.load(.acquire)) {
                const stream = l.accept(std.testing.io) catch return;
                stream.close(std.testing.io);
                _ = accepted.fetchAdd(1, .monotonic);
            }
        }
    };
    var accepted: std.atomic.Value(u32) = .init(0);
    var stopping: std.atomic.Value(bool) = .init(false);
    var future = try io.concurrent(Loop.run, .{ &listener, &accepted, &stopping });
    defer cancelAcceptLoop(io, &future, listener.socket.address, &stopping);
    const rounds = 200;
    {
        var storm: SignalStorm = .{};
        try storm.start();
        defer storm.finish();
        for (0..rounds) |_| wakeIp(io, listener.socket.address);
    }
    // Each wake connected, thus the loop accepts each of them.
    const end = Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake });
    while (accepted.load(.monotonic) < rounds) {
        if (end.durationFromNow(io).raw.toNanoseconds() <= 0) return error.TestUnexpectedResult;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
}

/// Sends `SIGIO` to the thread that calls `start`, with a very short pause, until `finish`. Std
/// uses `SIGIO` to interrupt a blocked system call of a task that gets a cancel.
const SignalStorm = struct {
    stop: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
    old: posix.Sigaction = undefined,

    fn start(self: *SignalStorm) !void {
        // A handler without `SA_RESTART`, as the handler of `Io.Threaded`.
        const act: posix.Sigaction = .{ .handler = .{ .handler = ignore }, .mask = posix.sigemptyset(), .flags = 0 };
        posix.sigaction(.IO, &act, &self.old);
        errdefer posix.sigaction(.IO, &self.old, null);
        self.thread = try std.Thread.spawn(.{}, run, .{ self, SignalTarget.current() });
    }

    fn finish(self: *SignalStorm) void {
        self.stop.store(true, .release);
        self.thread.join();
        posix.sigaction(.IO, &self.old, null);
    }

    fn ignore(_: posix.SIG) callconv(.c) void {}

    fn run(self: *SignalStorm, target: SignalTarget) void {
        while (!self.stop.load(.acquire)) {
            target.signal();
            for (0..256) |_| std.atomic.spinLoopHint();
        }
    }
};

/// A thread that can get a signal, or void on a system without a test for it.
const SignalTarget = if (builtin.link_libc and posix_connect) struct {
    handle: std.c.pthread_t,

    fn current() SignalTarget {
        return .{ .handle = std.c.pthread_self() };
    }

    fn signal(t: SignalTarget) void {
        _ = std.c.pthread_kill(t.handle, .IO);
    }
} else if (builtin.os.tag == .linux) struct {
    pid: std.os.linux.pid_t,
    tid: std.os.linux.pid_t,

    fn current() SignalTarget {
        return .{ .pid = std.os.linux.getpid(), .tid = std.os.linux.gettid() };
    }

    fn signal(t: SignalTarget) void {
        _ = std.os.linux.tgkill(t.pid, t.tid, .IO);
    }
} else void;
