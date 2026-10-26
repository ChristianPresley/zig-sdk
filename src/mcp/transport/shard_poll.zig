//! The readiness poller of one shard of the Streamable HTTP server (`http.zig`). One task
//! owns one poller and waits for the sockets of its connections. No other task uses the
//! poller, except `Poller.wake`, which is safe from any task.
//!
//! On Linux the poller is an `epoll` instance. Each socket is in it one time, edge-triggered,
//! for bytes and for the close by the peer. Thus a request costs no system call to arm the
//! socket again. Only while the owner waits for space in the send buffer, the set has the
//! socket for that event too.
//!
//! On Windows the poller is an I/O completion port and a helper AFD handle, as in wepoll. The
//! poller sends one `IOCTL_AFD_POLL` request for each wait on a socket. The socket itself
//! stays off the port, thus the reads and writes of `std.Io` do not change. On the other POSIX
//! systems the poller calls `poll` on an array that changes only when a socket comes or goes.
//!
//! `recvNow`, `peekNow` and `sendNow` read and write a socket without a wait.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const windows = std.os.windows;
const posix = std.posix;
const linux = std.os.linux;

pub const is_windows = builtin.os.tag == .windows;
pub const is_linux = builtin.os.tag == .linux;

pub const Error = error{ SystemResources, Unexpected };

/// The readiness of one socket.
pub const Event = struct {
    slot: *Slot,
    /// Bytes wait in the socket, or the peer closed its side.
    readable: bool,
    /// The send buffer has space.
    writable: bool,
    /// The peer closed or reset the connection, or this side closed the socket.
    hangup: bool,
};

/// What the owner of a socket waits for. On Linux the poller always reports bytes and the
/// close, and the owner ignores the events it does not need.
pub const Interest = struct {
    read: bool = false,
    write: bool = false,
    /// Windows: the poll for space in the send buffer does not complete at the end of the
    /// input of the peer. After that end, such a poll completes at once each time.
    no_end: bool = false,
};

/// The state of one socket in the poller. The owner embeds it. After the close of the
/// socket, the owner keeps it in place until `Slot.quiet` is true. On Windows, the kernel
/// writes into it until each poll ends.
pub const Slot = if (is_windows) struct {
    handle: windows.HANDLE = undefined,
    rx: WinPoll = .{},
    tx: WinPoll = .{},

    /// True when no poll of the socket is pending.
    pub fn quiet(s: *const @This()) bool {
        return !s.rx.pending and !s.tx.pending;
    }
} else if (is_linux) struct {
    handle: posix.fd_t = undefined,
    /// The `epoll` set has the socket for space in the send buffer too.
    out: bool = false,

    pub fn quiet(s: *const @This()) bool {
        _ = s;
        return true;
    }
} else struct {
    handle: posix.fd_t = undefined,
    /// The position in the `poll` array, or `no_index`.
    index: u32 = no_index,

    pub fn quiet(s: *const @This()) bool {
        _ = s;
        return true;
    }
};

const no_index = std.math.maxInt(u32);

/// The events of each socket in the `epoll` set (Linux).
const linux_events: u32 = if (is_linux) linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.ET else 0;

// AFD poll structures, as in ReactOS and wepoll.
const PollHandleInfo = extern struct { handle: windows.HANDLE, events: u32, status: windows.NTSTATUS };
const PollHeader = extern struct { timeout: i64, count: u32, exclusive: u32 };
const PollOne = extern struct { header: PollHeader, handle: PollHandleInfo };
const afd_receive: u32 = 0x0001;
const afd_send: u32 = 0x0004;
const afd_disconnect: u32 = 0x0008;
const afd_abort: u32 = 0x0010;
const afd_local_close: u32 = 0x0020;
const afd_end = afd_disconnect | afd_abort | afd_local_close;

/// One `IOCTL_AFD_POLL` request of a socket (Windows).
const WinPoll = struct {
    iosb: windows.IO_STATUS_BLOCK = undefined,
    info: PollOne = undefined,
    pending: bool = false,
    slot: *Slot = undefined,
};

const OverlappedEntry = extern struct { key: usize, overlapped: ?*anyopaque, internal: usize, bytes: u32 };
extern "kernel32" fn CreateIoCompletionPort(file: windows.HANDLE, port: ?windows.HANDLE, key: usize, threads: u32) callconv(.winapi) ?windows.HANDLE;
extern "kernel32" fn GetQueuedCompletionStatusEx(port: windows.HANDLE, entries: [*]OverlappedEntry, count: u32, removed: *u32, timeout_ms: u32, alertable: c_int) callconv(.winapi) c_int;
extern "kernel32" fn PostQueuedCompletionStatus(port: windows.HANDLE, bytes: u32, key: usize, overlapped: ?*anyopaque) callconv(.winapi) c_int;
extern "kernel32" fn WaitForSingleObject(handle: windows.HANDLE, milliseconds: u32) callconv(.winapi) u32;

/// The result of `Poller.recvNow`, `Poller.peekNow` and `Poller.sendNow`.
pub const Now = union(enum) {
    /// The count of bytes. Zero from `recvNow` or `peekNow`: the peer closed the connection.
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
    } else if (is_linux) struct {
        epfd: i32,
        wake_fd: i32,
    } else struct {
        gpa: std.mem.Allocator,
        wake_read: posix.fd_t,
        wake_write: posix.fd_t,
        /// The wake pipe at index 0, then one entry for each socket.
        fds: std.ArrayList(posix.pollfd) = .empty,
        /// The slot of each entry of `fds` after the first.
        slots: std.ArrayList(*Slot) = .empty,
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
        } else if (is_linux) {
            const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .MFILE, .NFILE, .NOMEM => return error.SystemResources,
                else => return error.Unexpected,
            }
            const epfd: i32 = @intCast(rc);
            errdefer _ = linux.close(epfd);
            const wrc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
            switch (linux.errno(wrc)) {
                .SUCCESS => {},
                .MFILE, .NFILE, .NOMEM => return error.SystemResources,
                else => return error.Unexpected,
            }
            const wake_fd: i32 = @intCast(wrc);
            errdefer _ = linux.close(wake_fd);
            // Level-triggered: the wait drains the counter after each wake.
            var ev: linux.epoll_event = .{ .events = linux.EPOLL.IN, .data = .{ .ptr = 0 } };
            switch (linux.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, wake_fd, &ev))) {
                .SUCCESS => {},
                .NOMEM, .NOSPC => return error.SystemResources,
                else => return error.Unexpected,
            }
            return .{ .impl = .{ .epfd = epfd, .wake_fd = wake_fd } };
        } else {
            var fds: [2]posix.fd_t = undefined;
            switch (posix.errno(posix.system.pipe(&fds))) {
                .SUCCESS => {},
                .MFILE, .NFILE, .NOMEM => return error.SystemResources,
                else => return error.Unexpected,
            }
            // A wake must never block. A full pipe means that a wake waits already.
            for (fds) |fd| {
                _ = posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC));
                const status = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
                if (posix.errno(status) == .SUCCESS) {
                    const nonblock: usize = @as(u32, @bitCast(posix.O{ .NONBLOCK = true }));
                    _ = posix.system.fcntl(fd, posix.F.SETFL, @as(usize, @intCast(status)) | nonblock);
                }
            }
            var p: Poller = .{ .impl = .{ .gpa = gpa, .wake_read = fds[0], .wake_write = fds[1] } };
            p.impl.fds.append(gpa, .{ .fd = fds[0], .events = posix.POLL.IN, .revents = 0 }) catch {
                _ = posix.system.close(fds[0]);
                _ = posix.system.close(fds[1]);
                return error.SystemResources;
            };
            return p;
        }
    }

    pub fn deinit(p: *Poller) void {
        if (is_windows) {
            windows.CloseHandle(p.impl.helper);
            windows.CloseHandle(p.impl.port);
        } else if (is_linux) {
            _ = linux.close(p.impl.wake_fd);
            _ = linux.close(p.impl.epfd);
        } else {
            _ = posix.system.close(p.impl.wake_read);
            _ = posix.system.close(p.impl.wake_write);
            p.impl.fds.deinit(p.impl.gpa);
            p.impl.slots.deinit(p.impl.gpa);
        }
        p.* = undefined;
    }

    /// Add the socket `handle` to the poller. On Linux the socket is then in the `epoll` set
    /// for all events, edge-triggered. Thus after each event the owner must read, or write,
    /// until the operation would block, or keep in mind that it must do so later. `slot` must
    /// stay in place until the close of the socket, and on Windows until `Slot.quiet`.
    pub fn add(p: *Poller, slot: *Slot, handle: Io.net.Socket.Handle) Error!void {
        slot.* = .{};
        slot.handle = handle;
        if (is_windows) {
            slot.rx.slot = slot;
            slot.tx.slot = slot;
        } else if (is_linux) {
            var ev: linux.epoll_event = .{ .events = linux_events, .data = .{ .ptr = @intFromPtr(slot) } };
            switch (linux.errno(linux.epoll_ctl(p.impl.epfd, linux.EPOLL.CTL_ADD, handle, &ev))) {
                .SUCCESS => {},
                .NOMEM, .NOSPC => return error.SystemResources,
                else => return error.Unexpected,
            }
        } else {
            const gpa = p.impl.gpa;
            p.impl.slots.ensureUnusedCapacity(gpa, 1) catch return error.SystemResources;
            p.impl.fds.append(gpa, .{ .fd = handle, .events = 0, .revents = 0 }) catch return error.SystemResources;
            p.impl.slots.appendAssumeCapacity(slot);
            slot.index = @intCast(p.impl.slots.items.len - 1);
        }
    }

    /// Remove the socket of `slot` from the poller. Call it before the close of the socket.
    /// On Linux the close removes the socket from the `epoll` set. On Windows, the close ends
    /// the pending polls, and their completions arrive later.
    pub fn remove(p: *Poller, slot: *Slot) void {
        if (is_windows or is_linux) return;
        const i = slot.index;
        if (i == no_index) return;
        _ = p.impl.fds.swapRemove(i + 1);
        _ = p.impl.slots.swapRemove(i);
        if (i < p.impl.slots.items.len) p.impl.slots.items[i].index = i;
        slot.index = no_index;
    }

    /// Remove the socket of `slot` from the poller while it stays open, for the poller of
    /// another task. On Windows no poll of the socket can be pending (`Slot.quiet`).
    pub fn detach(p: *Poller, slot: *Slot) void {
        if (is_windows) return;
        if (is_linux) {
            _ = linux.epoll_ctl(p.impl.epfd, linux.EPOLL.CTL_DEL, slot.handle, null);
            return;
        }
        p.remove(slot);
    }

    /// Wait for `interest` on the socket of `slot`. On Windows this sends a poll request when
    /// none of the same kind is pending. A pending poll stays: it completes at its event.
    pub fn want(p: *Poller, slot: *Slot, interest: Interest) Error!void {
        if (is_windows) {
            if (interest.read and !slot.rx.pending) try p.armWindows(&slot.rx, afd_receive | afd_end);
            if (interest.write and !slot.tx.pending) try p.armWindows(&slot.tx, afd_send | if (interest.no_end) afd_abort | afd_local_close else afd_end);
        } else if (is_linux) {
            // Edge-triggered: the set has the socket for bytes and the close at all times.
            if (interest.write == slot.out) return;
            var ev: linux.epoll_event = .{
                .events = if (interest.write) linux_events | linux.EPOLL.OUT else linux_events,
                .data = .{ .ptr = @intFromPtr(slot) },
            };
            switch (linux.errno(linux.epoll_ctl(p.impl.epfd, linux.EPOLL.CTL_MOD, slot.handle, &ev))) {
                .SUCCESS => slot.out = interest.write,
                .NOMEM, .NOSPC => return error.SystemResources,
                else => return error.Unexpected,
            }
        } else {
            if (slot.index == no_index) return;
            var events: i16 = 0;
            if (interest.read) events |= posix.POLL.IN;
            if (interest.write) events |= posix.POLL.OUT;
            // `poll` reports a hangup also without interest. A negative descriptor mutes it.
            const fd = &p.impl.fds.items[slot.index + 1];
            fd.fd = if (events == 0) -1 else slot.handle;
            fd.events = events;
        }
    }

    fn armWindows(p: *Poller, poll: *WinPoll, events: u32) Error!void {
        poll.info = .{
            .header = .{ .timeout = std.math.maxInt(i64), .count = 1, .exclusive = 0 },
            .handle = .{ .handle = poll.slot.handle, .events = events, .status = .SUCCESS },
        };
        switch (windows.ntdll.NtDeviceIoControlFile(p.impl.helper, null, null, poll, &poll.iosb, windows.IOCTL.AFD.POLL, &poll.info, @sizeOf(PollOne), &poll.info, @sizeOf(PollOne))) {
            .PENDING, .SUCCESS => poll.pending = true,
            .INSUFFICIENT_RESOURCES => return error.SystemResources,
            else => return error.Unexpected,
        }
    }

    /// Wait for events, at most `timeout_ms` (negative: without a limit), and write them into
    /// `out`. The count is zero after a timeout or a wake.
    pub fn wait(p: *Poller, timeout_ms: i32, out: []Event) Error!usize {
        if (is_windows) {
            var entries: [256]OverlappedEntry = undefined;
            const want_count: u32 = @intCast(@min(entries.len, out.len));
            var removed: u32 = 0;
            const timeout: u32 = if (timeout_ms < 0) std.math.maxInt(u32) else @intCast(timeout_ms);
            if (GetQueuedCompletionStatusEx(p.impl.port, &entries, want_count, &removed, timeout, 0) == 0) return 0;
            var n: usize = 0;
            for (entries[0..removed]) |entry| {
                const poll: *WinPoll = @ptrCast(@alignCast(entry.overlapped orelse continue));
                poll.pending = false;
                // A poll that failed, or ended without an event, reports "readable" or
                // "writable". The owner then reads or writes, and sees the state itself.
                if (poll.iosb.u.Status != .SUCCESS or poll.info.header.count == 0) {
                    const is_tx = poll == &poll.slot.tx;
                    out[n] = .{ .slot = poll.slot, .readable = !is_tx, .writable = is_tx, .hangup = false };
                    n += 1;
                    continue;
                }
                const events = poll.info.handle.events;
                out[n] = .{
                    .slot = poll.slot,
                    .readable = events & afd_receive != 0,
                    .writable = events & afd_send != 0,
                    .hangup = events & afd_end != 0,
                };
                n += 1;
            }
            return n;
        } else if (is_linux) {
            var evs: [256]linux.epoll_event = undefined;
            const max: u32 = @intCast(@min(evs.len, out.len));
            const rc = linux.epoll_wait(p.impl.epfd, &evs, max, timeout_ms);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => return 0,
                else => return error.Unexpected,
            }
            var n: usize = 0;
            for (evs[0..rc]) |ev| {
                if (ev.data.ptr == 0) {
                    var count: u64 = 0;
                    _ = linux.read(p.impl.wake_fd, std.mem.asBytes(&count), 8);
                    continue;
                }
                out[n] = .{
                    .slot = @ptrFromInt(ev.data.ptr),
                    .readable = ev.events & linux.EPOLL.IN != 0,
                    .writable = ev.events & linux.EPOLL.OUT != 0,
                    .hangup = ev.events & (linux.EPOLL.RDHUP | linux.EPOLL.HUP | linux.EPOLL.ERR) != 0,
                };
                n += 1;
            }
            return n;
        } else {
            const fds = p.impl.fds.items;
            const ready = posix.poll(fds, timeout_ms) catch |e| switch (e) {
                error.SystemResources => return error.SystemResources,
                else => return error.Unexpected,
            };
            if (ready == 0) return 0;
            if (fds[0].revents != 0) {
                var drain: [64]u8 = undefined;
                _ = posix.system.read(p.impl.wake_read, &drain, drain.len);
            }
            var n: usize = 0;
            for (fds[1..], p.impl.slots.items) |fd, slot| {
                if (fd.revents == 0) continue;
                if (n == out.len) break;
                out[n] = .{
                    .slot = slot,
                    .readable = fd.revents & posix.POLL.IN != 0,
                    .writable = fd.revents & posix.POLL.OUT != 0,
                    .hangup = fd.revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0,
                };
                n += 1;
            }
            return n;
        }
    }

    /// End a wait that runs, or the next wait. Safe from any task.
    pub fn wake(p: *Poller) void {
        if (is_windows) {
            _ = PostQueuedCompletionStatus(p.impl.port, 0, 0, null);
        } else if (is_linux) {
            const one: u64 = 1;
            _ = linux.write(p.impl.wake_fd, std.mem.asBytes(&one), 8);
        } else {
            _ = posix.system.write(p.impl.wake_write, "w", 1);
        }
    }

    /// Make `recvNow`, `peekNow` and `sendNow` possible on `handle`. On Windows this sets the
    /// AFD option `NONBLOCKING_MODE` of the socket. With it an AFD request without
    /// `AFD_OVERLAPPED` returns `STATUS_DEVICE_NOT_READY` and does not wait. The reads and
    /// writes of `std.Io` use `AFD_OVERLAPPED`, thus they wait as before. Call it one time for
    /// each socket.
    pub fn prepareNow(handle: Io.net.Socket.Handle) bool {
        if (!is_windows) return true;
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.AFD.INFORMATION = .{ .InformationType = .NONBLOCKING_MODE, .Information = .{ .Ulong = 1 } };
        var status = windows.ntdll.NtDeviceIoControlFile(handle, null, null, null, &iosb, windows.IOCTL.AFD.SET_INFORMATION, &info, @sizeOf(windows.AFD.INFORMATION), null, 0);
        // AFD completes this request at once. If it does not, the kernel writes into `iosb`
        // until the request ends, thus wait for the end. Without an event, the socket handle
        // signals the end. No other request of the connection runs now.
        if (status == .PENDING) {
            _ = WaitForSingleObject(handle, std.math.maxInt(u32));
            status = iosb.u.Status;
        }
        return status == .SUCCESS;
    }

    /// Move the bytes that wait in the socket into `buf`, without a wait. Call `prepareNow`
    /// first.
    pub fn recvNow(handle: Io.net.Socket.Handle, buf: []u8) Now {
        return receive(handle, buf, false);
    }

    /// Copy the bytes that wait in the socket into `buf`, without a wait, and leave them in
    /// the socket. Call `prepareNow` first.
    pub fn peekNow(handle: Io.net.Socket.Handle, buf: []u8) Now {
        return receive(handle, buf, true);
    }

    fn receive(handle: Io.net.Socket.Handle, buf: []u8, peek: bool) Now {
        if (is_windows) {
            const bufs = [1]windows.AFD.WSABUF(.@"var"){.{ .len = @intCast(@min(buf.len, std.math.maxInt(u32))), .buf = buf.ptr }};
            var info: windows.AFD.RECV_INFO = .{ .BufferArray = &bufs, .BufferCount = 1, .AfdFlags = .{}, .TdiFlags = .{ .NORMAL = true, .PEEK = peek } };
            return afdNow(handle, windows.IOCTL.AFD.RECEIVE, &info, @sizeOf(windows.AFD.RECV_INFO));
        }
        // Off Linux, `MSG_DONTWAIT` does not always stop a wait (macOS). A socket that is
        // readable has bytes or the end of the input: then the receive returns at once.
        if (!is_linux and !pollNow(handle, posix.POLL.IN)) return .would_block;
        const flags: u32 = posix.MSG.DONTWAIT | (if (peek) @as(u32, posix.MSG.PEEK) else 0);
        while (true) {
            const rc = posix.system.recvfrom(handle, buf.ptr, buf.len, flags, null, null);
            return switch (posix.errno(rc)) {
                .SUCCESS => .{ .done = @intCast(rc) },
                .INTR => continue,
                .AGAIN => .would_block,
                else => .failed,
            };
        }
    }

    /// Send a part of `data` without a wait. Call `prepareNow` first.
    pub fn sendNow(handle: Io.net.Socket.Handle, data: []const u8) Now {
        if (is_windows) {
            const bufs = [1]windows.AFD.WSABUF(.@"const"){.{ .len = @intCast(@min(data.len, std.math.maxInt(u32))), .buf = data.ptr }};
            var info: windows.AFD.SEND_INFO = .{ .BufferArray = &bufs, .BufferCount = 1, .AfdFlags = .{}, .TdiFlags = .{} };
            return afdNow(handle, windows.IOCTL.AFD.SEND, &info, @sizeOf(windows.AFD.SEND_INFO));
        }
        // Off Linux, `MSG_DONTWAIT` does not always stop a wait (macOS), and a send on a socket
        // that blocks waits until all its bytes are in the send buffer. Thus the send takes
        // only the free space of a writable socket: on macOS `SO_SNDBUF` less `SO_NWRITE`,
        // elsewhere `SO_SNDLOWAT`, which `POLLOUT` guarantees.
        var len = data.len;
        if (!is_linux) {
            if (!pollNow(handle, posix.POLL.OUT)) return .would_block;
            len = @min(len, freeSendSpace(handle));
            if (len == 0) return .would_block;
        }
        const flags: u32 = posix.MSG.DONTWAIT | (if (@hasDecl(posix.MSG, "NOSIGNAL")) posix.MSG.NOSIGNAL else 0);
        while (true) {
            const rc = posix.system.sendto(handle, data.ptr, len, flags, null, 0);
            return switch (posix.errno(rc)) {
                .SUCCESS => .{ .done = @intCast(rc) },
                .INTR => continue,
                .AGAIN => .would_block,
                else => .failed,
            };
        }
    }

    /// True when `poll` reports `events` (or an error or a hangup) on `handle` now (POSIX).
    fn pollNow(handle: Io.net.Socket.Handle, events: i16) bool {
        var fds = [1]posix.pollfd{.{ .fd = handle, .events = events, .revents = 0 }};
        while (true) {
            const rc = posix.system.poll(&fds, 1, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => return rc > 0 and fds[0].revents != 0,
                .INTR => continue,
                else => return false,
            }
        }
    }

    /// The bytes that a send to the writable socket `handle` can take without a wait (POSIX
    /// systems other than Linux).
    fn freeSendSpace(handle: Io.net.Socket.Handle) usize {
        if (@hasDecl(posix.SO, "NWRITE")) {
            const size = sockOption(handle, posix.SO.SNDBUF) orelse 0;
            const queued = sockOption(handle, posix.SO.NWRITE) orelse size;
            if (size > queued) return size - queued;
        }
        return sockOption(handle, posix.SO.SNDLOWAT) orelse 2048;
    }

    fn sockOption(handle: Io.net.Socket.Handle, name: u32) ?usize {
        var value: c_int = 0;
        var len: posix.socklen_t = @sizeOf(c_int);
        if (posix.errno(posix.system.getsockopt(handle, posix.SOL.SOCKET, name, @ptrCast(&value), &len)) != .SUCCESS) return null;
        return if (value > 0) @intCast(value) else null;
    }

    /// One AFD request without `AFD_OVERLAPPED` (Windows).
    fn afdNow(handle: windows.HANDLE, code: windows.CTL_CODE, info: *anyopaque, info_len: u32) Now {
        var iosb: windows.IO_STATUS_BLOCK = undefined;
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
};

fn drainAll(reader: *Io.net.Stream.Reader, want: usize, got: *usize) void {
    while (got.* < want) {
        reader.interface.fillMore() catch return;
        got.* += reader.interface.bufferedLen();
        reader.interface.tossBuffered();
    }
}

test "recvNow, peekNow and sendNow do not wait, and the reads and writes of std still wait" {
    const io = std.testing.io;
    var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    var client = try server.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    var conn = try server.accept(io);
    defer conn.close(io);
    const h = conn.socket.handle;
    try std.testing.expect(Poller.prepareNow(h));

    // No bytes: the peek and the receive return at once.
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(Now.would_block, Poller.peekNow(h, &buf));
    try std.testing.expectEqual(Now.would_block, Poller.recvNow(h, &buf));
    // Bytes: the peek copies them and leaves them in the socket.
    var cw = client.writer(io, &.{});
    try cw.interface.writeAll("hello");
    var tries: usize = 0;
    while (true) : (tries += 1) {
        switch (Poller.peekNow(h, &buf)) {
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
    // The receive takes the bytes.
    switch (Poller.recvNow(h, &buf)) {
        .done => |n| try std.testing.expectEqualStrings("hello", buf[0..n]),
        else => return error.RecvFailed,
    }
    try std.testing.expectEqual(Now.would_block, Poller.recvNow(h, &buf));

    // The client does not read: a send stops at a full buffer, without a wait.
    const big = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(big);
    @memset(big, 'x');
    var sent: usize = 0;
    var full = false;
    for (0..256) |_| switch (Poller.sendNow(h, big)) {
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

test "the poller reports bytes, the close by the peer and a wake" {
    const io = std.testing.io;
    var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    var client = try server.socket.address.connect(io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) client.close(io);
    var conn = try server.accept(io);
    defer conn.close(io);
    const h = conn.socket.handle;
    try std.testing.expect(Poller.prepareNow(h));

    var poller = try Poller.init(std.testing.allocator);
    defer poller.deinit();
    var slot: Slot = .{};
    try poller.add(&slot, h);
    defer poller.remove(&slot);
    try poller.want(&slot, .{ .read = true });
    var events: [8]Event = undefined;

    // A wake ends a wait without a limit, and gives no event.
    poller.wake();
    try std.testing.expectEqual(0, try poller.wait(-1, &events));

    var cw = client.writer(io, &.{});
    try cw.interface.writeAll("x");
    var readable = false;
    for (0..100) |_| {
        const n = try poller.wait(1000, &events);
        for (events[0..n]) |ev| {
            try std.testing.expectEqual(&slot, ev.slot);
            if (ev.readable) readable = true;
        }
        if (readable) break;
    }
    try std.testing.expect(readable);
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(Now{ .done = 1 }, Poller.recvNow(h, &buf));

    try poller.want(&slot, .{ .read = true });
    client.close(io);
    client_open = false;
    var ended = false;
    for (0..100) |_| {
        const n = try poller.wait(1000, &events);
        for (events[0..n]) |ev| if (ev.readable or ev.hangup) {
            ended = true;
        };
        if (ended) break;
    }
    try std.testing.expect(ended);
    try std.testing.expectEqual(Now{ .done = 0 }, Poller.recvNow(h, &buf));
}
