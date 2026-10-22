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

const helper_name = windows.AFD.DEVICE_NAME ++ [_]u16{ '\\', 'M', 'c', 'p', 'P', 'a', 'r', 'k' };

pub const Poller = struct {
    impl: Impl,

    const Impl = if (is_windows) struct {
        port: windows.HANDLE,
        helper: windows.HANDLE,
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
    /// wait reports it.
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
            var entries: [256]OverlappedEntry = undefined;
            const want: u32 = @intCast(@min(entries.len, out.len));
            var removed: u32 = 0;
            const timeout: u32 = if (timeout_ms < 0) std.math.maxInt(u32) else @intCast(timeout_ms);
            if (GetQueuedCompletionStatusEx(p.impl.port, &entries, want, &removed, timeout, 0) == 0) return 0;
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

    /// Cancel the pending poll of `slot`. True when a completion still arrives for the slot,
    /// as on Windows: the slot must stay in place until then. POSIX systems have nothing
    /// pending, and the slot is free at once.
    pub fn cancel(p: *Poller, slot: *Slot) bool {
        if (!is_windows) return false;
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        _ = windows.ntdll.NtCancelIoFileEx(p.impl.helper, &slot.iosb, &iosb);
        return true;
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
