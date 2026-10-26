//! Readiness of parked sockets: one task waits for many idle connections, and no idle
//! connection holds a task. On Windows the task leaves one `IOCTL_AFD_POLL` request pending
//! for each socket, as wepoll does. The requests go to a helper AFD handle that sits on an
//! I/O completion port. The socket itself stays off the port, thus the reads of `std.Io`
//! do not change. On POSIX systems the task calls `poll` on the parked sockets and on a
//! wake pipe.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const windows = std.os.windows;
const posix = std.posix;

pub const is_windows = builtin.os.tag == .windows;

pub const Error = error{ SystemResources, Unexpected };

/// The readiness of one parked socket. Neither flag set: the wait ended for another reason,
/// and the owner arms the socket again.
pub const Event = struct {
    slot: *Slot,
    /// Bytes wait in the socket.
    readable: bool,
    /// The peer closed or reset the connection, or this side closed the socket.
    hangup: bool,
};

/// The state of one parked socket. The owner embeds it and keeps it in place while the
/// poll runs: on Windows, the kernel writes into it when the poll completes.
pub const Slot = if (is_windows) struct {
    handle: windows.HANDLE = undefined,
    iosb: windows.IO_STATUS_BLOCK = undefined,
    poll: PollOne = undefined,
} else struct {
    handle: posix.fd_t = undefined,
};

// AFD poll structures, as in ReactOS and wepoll.
const PollHandleInfo = extern struct { handle: windows.HANDLE, events: u32, status: windows.NTSTATUS };
const PollHeader = extern struct { timeout: i64, count: u32, exclusive: u32 };
const PollOne = extern struct { header: PollHeader, handle: PollHandleInfo };
const afd_receive: u32 = 0x0001;
const afd_disconnect: u32 = 0x0008;
const afd_abort: u32 = 0x0010;
const afd_local_close: u32 = 0x0020;
const afd_events = afd_receive | afd_disconnect | afd_abort | afd_local_close;

const OverlappedEntry = extern struct { key: usize, overlapped: ?*anyopaque, internal: usize, bytes: u32 };
extern "kernel32" fn CreateIoCompletionPort(file: windows.HANDLE, port: ?windows.HANDLE, key: usize, threads: u32) callconv(.winapi) ?windows.HANDLE;
extern "kernel32" fn GetQueuedCompletionStatusEx(port: windows.HANDLE, entries: [*]OverlappedEntry, count: u32, removed: *u32, timeout_ms: u32, alertable: c_int) callconv(.winapi) c_int;
extern "kernel32" fn PostQueuedCompletionStatus(port: windows.HANDLE, bytes: u32, key: usize, overlapped: ?*anyopaque) callconv(.winapi) c_int;
extern "kernel32" fn WaitForSingleObject(handle: windows.HANDLE, milliseconds: u32) callconv(.winapi) u32;

/// The result of `Poller.peekNow` and `Poller.sendNow`.
pub const Now = union(enum) {
    /// The count of bytes. Zero from `peekNow`: the peer closed the connection.
    done: usize,
    /// The operation must wait: no bytes, or no space in the send buffer.
    would_block,
    failed,
};

const helper_name = windows.AFD.DEVICE_NAME ++ [_]u16{ '\\', 'M', 'c', 'p', 'P', 'a', 'r', 'k' };

pub const Poller = struct {
    impl: Impl,

    const Impl = if (is_windows) struct {
        port: windows.HANDLE,
        helper: windows.HANDLE,
        /// The completions of one wait. A safe build fills an `undefined` array on the stack
        /// on each call, thus the array is here.
        entries: [256]OverlappedEntry = undefined,
    } else struct {
        gpa: std.mem.Allocator,
        wake_read: posix.fd_t,
        wake_write: posix.fd_t,
        fds: std.ArrayList(posix.pollfd) = .empty,
    };

    pub fn init(gpa: std.mem.Allocator) Error!Poller {
        if (is_windows) {
            const port = CreateIoCompletionPort(windows.INVALID_HANDLE_VALUE, null, 0, 1) orelse return error.SystemResources;
            errdefer windows.CloseHandle(port);
            var helper: windows.HANDLE = undefined;
            var iosb: windows.IO_STATUS_BLOCK = undefined;
            switch (windows.ntdll.NtCreateFile(
                &helper,
                .{ .STANDARD = .{ .SYNCHRONIZE = true }, .GENERIC = .{ .READ = true, .WRITE = true } },
                &.{ .ObjectName = @constCast(&windows.UNICODE_STRING.init(helper_name)) },
                &iosb,
                null,
                .{},
                .{ .READ = true, .WRITE = true },
                .OPEN,
                .{ .IO = .ASYNCHRONOUS },
                null,
                0,
            )) {
                .SUCCESS => {},
                .INSUFFICIENT_RESOURCES => return error.SystemResources,
                else => return error.Unexpected,
            }
            errdefer windows.CloseHandle(helper);
            if (CreateIoCompletionPort(helper, port, 1, 0) == null) return error.Unexpected;
            return .{ .impl = .{ .port = port, .helper = helper } };
        } else {
            var fds: [2]posix.fd_t = undefined;
            const rc = if (builtin.os.tag == .linux) posix.system.pipe2(&fds, .{ .CLOEXEC = true }) else posix.system.pipe(&fds);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .MFILE, .NFILE, .NOMEM => return error.SystemResources,
                else => return error.Unexpected,
            }
            // A wake must never block: the tasks write to the pipe under the lock of the parker.
            // A full pipe means that a wake waits already.
            const status = posix.system.fcntl(fds[1], posix.F.GETFL, @as(usize, 0));
            if (posix.errno(status) == .SUCCESS) {
                const nonblock: usize = @as(u32, @bitCast(posix.O{ .NONBLOCK = true }));
                _ = posix.system.fcntl(fds[1], posix.F.SETFL, @as(usize, @intCast(status)) | nonblock);
            }
            return .{ .impl = .{ .gpa = gpa, .wake_read = fds[0], .wake_write = fds[1] } };
        }
    }

    pub fn deinit(p: *Poller) void {
        if (is_windows) {
            windows.CloseHandle(p.impl.helper);
            windows.CloseHandle(p.impl.port);
        } else {
            _ = posix.system.close(p.impl.wake_read);
            _ = posix.system.close(p.impl.wake_write);
            p.impl.fds.deinit(p.impl.gpa);
        }
        p.* = undefined;
    }

    /// Watch `handle` for bytes, for a disconnect and for the close of the socket. On Windows
    /// the poll stays pending until one of them happens. `slot` must stay in place until the
    /// wait reports it. To end the poll, close the socket: a cancel of one poll makes the
    /// kernel walk every pending poll of the helper handle.
    pub fn arm(p: *Poller, slot: *Slot, handle: Io.net.Socket.Handle) Error!void {
        slot.handle = handle;
        if (!is_windows) return;
        slot.poll = .{
            .header = .{ .timeout = std.math.maxInt(i64), .count = 1, .exclusive = 0 },
            .handle = .{ .handle = handle, .events = afd_events, .status = .SUCCESS },
        };
        switch (windows.ntdll.NtDeviceIoControlFile(p.impl.helper, null, null, slot, &slot.iosb, windows.IOCTL.AFD.POLL, &slot.poll, @sizeOf(PollOne), &slot.poll, @sizeOf(PollOne))) {
            .PENDING, .SUCCESS => {},
            .INSUFFICIENT_RESOURCES => return error.SystemResources,
            else => return error.Unexpected,
        }
    }

    /// Wait for ready sockets, at most `timeout_ms` (negative: without a limit), and write
    /// them into `out`. `parked` is the set to watch on POSIX systems. Windows ignores it. The
    /// count is zero after a timeout or a wake.
    pub fn wait(p: *Poller, timeout_ms: i32, parked: []const *Slot, out: []Event) Error!usize {
        if (is_windows) {
            const entries = &p.impl.entries;
            const want: u32 = @intCast(@min(entries.len, out.len));
            var removed: u32 = 0;
            const timeout: u32 = if (timeout_ms < 0) std.math.maxInt(u32) else @intCast(timeout_ms);
            if (GetQueuedCompletionStatusEx(p.impl.port, entries, want, &removed, timeout, 0) == 0) return 0;
            var n: usize = 0;
            for (entries[0..removed]) |entry| {
                const slot: *Slot = @ptrCast(@alignCast(entry.overlapped orelse continue));
                const events: u32 = if (slot.poll.header.count == 0) 0 else slot.poll.handle.events;
                out[n] = .{
                    .slot = slot,
                    .readable = events & afd_receive != 0,
                    .hangup = events & (afd_disconnect | afd_abort | afd_local_close) != 0,
                };
                n += 1;
            }
            return n;
        } else {
            const fds = &p.impl.fds;
            fds.clearRetainingCapacity();
            fds.ensureTotalCapacity(p.impl.gpa, parked.len + 1) catch return error.SystemResources;
            fds.appendAssumeCapacity(.{ .fd = p.impl.wake_read, .events = posix.POLL.IN, .revents = 0 });
            for (parked) |slot| fds.appendAssumeCapacity(.{ .fd = slot.handle, .events = posix.POLL.IN, .revents = 0 });
            const ready = posix.poll(fds.items, timeout_ms) catch |e| switch (e) {
                error.SystemResources => return error.SystemResources,
                else => return error.Unexpected,
            };
            if (ready == 0) return 0;
            if (fds.items[0].revents != 0) {
                var drain: [64]u8 = undefined;
                _ = posix.system.read(p.impl.wake_read, &drain, drain.len);
            }
            var n: usize = 0;
            for (fds.items[1..], parked) |fd, slot| {
                if (fd.revents == 0 or n == out.len) continue;
                out[n] = .{
                    .slot = slot,
                    .readable = fd.revents & posix.POLL.IN != 0,
                    .hangup = fd.revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0,
                };
                n += 1;
            }
            return n;
        }
    }

    /// Make `peekNow` and `sendNow` possible on `handle`. On Windows this sets the AFD
    /// option `NONBLOCKING_MODE` of the socket. With it an AFD request without `AFD_OVERLAPPED`
    /// returns `STATUS_DEVICE_NOT_READY` and does not wait. The reads and writes of `std.Io`
    /// use `AFD_OVERLAPPED`, thus they wait as before. Call it one time for each socket.
    pub fn prepareNow(p: *Poller, handle: Io.net.Socket.Handle) bool {
        if (!is_windows) return true;
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.AFD.INFORMATION = .{ .InformationType = .NONBLOCKING_MODE, .Information = .{ .Ulong = 1 } };
        _ = p;
        var status = windows.ntdll.NtDeviceIoControlFile(handle, null, null, null, &iosb, windows.IOCTL.AFD.SET_INFORMATION, &info, @sizeOf(windows.AFD.INFORMATION), null, 0);
        // AFD completes this request at once. If it does not, the kernel writes into `iosb`
        // until the request ends, thus wait for the end.
        if (status == .PENDING) {
            // Without an event, the socket handle signals the end. No other request of the
            // connection runs now.
            _ = WaitForSingleObject(handle, std.math.maxInt(u32));
            status = iosb.u.Status;
        }
        return status == .SUCCESS;
    }

    /// Copy the bytes that wait in the socket into `buf`, without a wait, and leave them in
    /// the socket. Call `prepareNow` first.
    pub fn peekNow(p: *Poller, handle: Io.net.Socket.Handle, buf: []u8) Now {
        if (is_windows) {
            const bufs = [1]windows.AFD.WSABUF(.@"var"){.{ .len = @intCast(@min(buf.len, std.math.maxInt(u32))), .buf = buf.ptr }};
            var info: windows.AFD.RECV_INFO = .{ .BufferArray = &bufs, .BufferCount = 1, .AfdFlags = .{}, .TdiFlags = .{ .NORMAL = true, .PEEK = true } };
            return p.afdNow(handle, windows.IOCTL.AFD.RECEIVE, &info, @sizeOf(windows.AFD.RECV_INFO));
        }
        while (true) {
            const rc = posix.system.recvfrom(handle, buf.ptr, buf.len, posix.MSG.PEEK | posix.MSG.DONTWAIT, null, null);
            return switch (posix.errno(rc)) {
                .SUCCESS => .{ .done = @intCast(rc) },
                .INTR => continue,
                .AGAIN => .would_block,
                else => .failed,
            };
        }
    }

    /// Send a part of `data` without a wait. Call `prepareNow` first.
    pub fn sendNow(p: *Poller, handle: Io.net.Socket.Handle, data: []const u8) Now {
        if (is_windows) {
            const bufs = [1]windows.AFD.WSABUF(.@"const"){.{ .len = @intCast(@min(data.len, std.math.maxInt(u32))), .buf = data.ptr }};
            var info: windows.AFD.SEND_INFO = .{ .BufferArray = &bufs, .BufferCount = 1, .AfdFlags = .{}, .TdiFlags = .{} };
            return p.afdNow(handle, windows.IOCTL.AFD.SEND, &info, @sizeOf(windows.AFD.SEND_INFO));
        }
        const flags: u32 = posix.MSG.DONTWAIT | (if (@hasDecl(posix.MSG, "NOSIGNAL")) posix.MSG.NOSIGNAL else 0);
        while (true) {
            const rc = posix.system.sendto(handle, data.ptr, data.len, flags, null, 0);
            return switch (posix.errno(rc)) {
                .SUCCESS => .{ .done = @intCast(rc) },
                .INTR => continue,
                .AGAIN => .would_block,
                else => .failed,
            };
        }
    }

    /// One AFD request without `AFD_OVERLAPPED` (Windows).
    fn afdNow(p: *Poller, handle: windows.HANDLE, code: windows.CTL_CODE, info: *anyopaque, info_len: u32) Now {
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        _ = p;
        var status = windows.ntdll.NtDeviceIoControlFile(handle, null, null, null, &iosb, code, info, info_len, null, 0);
        if (status == .PENDING) {
            // The socket is not in the non-blocking mode after all. End the request, and wait
            // for its end: the kernel writes into `iosb` and the buffer until then.
            var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
            _ = windows.ntdll.NtCancelIoFileEx(handle, &iosb, &cancel_iosb);
            _ = WaitForSingleObject(handle, std.math.maxInt(u32));
            status = iosb.u.Status;
            // A cancel of a send can make AFD end the connection. Thus a cancelled request
            // without bytes fails, and the connection closes.
            if (status == .CANCELLED) return if (iosb.Information > 0) .{ .done = iosb.Information } else .failed;
        }
        return switch (status) {
            .SUCCESS => .{ .done = iosb.Information },
            .DEVICE_NOT_READY => .would_block,
            else => .failed,
        };
    }

    /// End a wait that runs. Safe from any task.
    pub fn wake(p: *Poller) void {
        if (is_windows) {
            _ = PostQueuedCompletionStatus(p.impl.port, 0, 0, null);
        } else {
            _ = posix.system.write(p.impl.wake_write, "w", 1);
        }
    }
};

fn drainAll(reader: *Io.net.Stream.Reader, want: usize, got: *usize) void {
    while (got.* < want) {
        reader.interface.fillMore() catch return;
        got.* += reader.interface.bufferedLen();
        reader.interface.tossBuffered();
    }
}

test "peekNow and sendNow do not wait, and the reads and writes of std still wait" {
    if (!is_windows and builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    var client = try server.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var conn = try server.accept(io);
    defer conn.close(io);
    var poller = try Poller.init(std.testing.allocator);
    defer poller.deinit();
    const h = conn.socket.handle;
    try std.testing.expect(poller.prepareNow(h));

    // No bytes: the peek returns at once.
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(Now.would_block, poller.peekNow(h, &buf));
    // Bytes: the peek copies them and leaves them in the socket.
    var cw = client.writer(io, &.{});
    try cw.interface.writeAll("hello");
    var tries: usize = 0;
    while (true) : (tries += 1) {
        switch (poller.peekNow(h, &buf)) {
            .done => |n| {
                try std.testing.expectEqualStrings("hello", buf[0..n]);
                break;
            },
            .would_block => {
                if (tries > 1000) return error.NoBytes;
                try io.sleep(.fromMilliseconds(1), .awake);
            },
            .failed => return error.PeekFailed,
        }
    }
    var rb: [16]u8 = undefined;
    var reader = conn.reader(io, &rb);
    try std.testing.expectEqualStrings("hello", try reader.interface.takeArray(5));

    // The client does not read: a send stops at a full buffer, without a wait.
    const big = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(big);
    @memset(big, 'x');
    var sent: usize = 0;
    var full = false;
    for (0..256) |_| switch (poller.sendNow(h, big)) {
        .done => |n| sent += n,
        .would_block => {
            full = true;
            break;
        },
        .failed => return error.SendFailed,
    };
    try std.testing.expect(full);
    // A write of std waits until the client reads.
    var db: [65536]u8 = undefined;
    var client_reader = client.reader(io, &db);
    var got: usize = 0;
    var drain = try io.concurrent(drainAll, .{ &client_reader, sent + 4, &got });
    var w = conn.writer(io, &.{});
    try w.interface.writeAll("tail");
    drain.await(io);
    try std.testing.expectEqual(sent + 4, got);
}
