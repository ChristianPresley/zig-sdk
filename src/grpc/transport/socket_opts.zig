//! The TCP socket options that `std.Io.net` does not expose. The gRPC server and client
//! disable the Nagle algorithm on each connection. The server writes a response in three
//! parts: the response headers, the data and the trailers. Without the option, the Nagle
//! algorithm holds the second and the third part until the client acknowledges the first.
//! On Linux, each call then took about 40 ms on a loopback connection.
//!
//! On a POSIX system, the functions use `setsockopt` and `getsockopt`. On Windows, a socket
//! of std is a handle of the AFD driver and not a socket of Winsock. Thus the functions use
//! the socket option control code of AFD, as std does for `reuse_address`.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;
const windows = std.os.windows;
const ws2_32 = windows.ws2_32;

const log = std.log.scoped(.mcp_grpc);

pub const Error = error{OptionRejected} || Io.Cancelable;

/// The value of `TCP_NODELAY` on this system. Std has the constant for Linux, macOS and
/// Windows. On the other systems the value is 1, as on every BSD.
const tcp_nodelay: u32 = switch (builtin.os.tag) {
    .windows => ws2_32.TCP.NODELAY,
    else => if (posix.TCP != void) posix.TCP.NODELAY else 1,
};

/// Disable the Nagle algorithm on `socket`, a connected TCP socket: set `TCP_NODELAY`. A
/// failure gives `error.OptionRejected` after a message at debug level in the scope
/// `mcp_grpc`. On Windows, a cancel of the task gives `error.Canceled`.
pub fn setNoDelay(io: Io, socket: Io.net.Socket) Error!void {
    var value: u32 = 1;
    return control(io, socket, .set, &value);
}

/// Read `TCP_NODELAY` of `socket`. True when the Nagle algorithm is off. On macOS, the kernel
/// gives the flag bit of the option and not 1. Thus the result is a boolean.
pub fn getNoDelay(io: Io, socket: Io.net.Socket) Error!bool {
    var value: u32 = 0;
    try control(io, socket, .get, &value);
    return value != 0;
}

const Mode = enum { set, get };

fn control(io: Io, socket: Io.net.Socket, mode: Mode, value: *u32) Error!void {
    switch (builtin.os.tag) {
        .windows => {
            var info: windows.AFD.SOCKOPT_INFO = .{
                .mode = switch (mode) {
                    .set => .set,
                    .get => .get,
                },
                .level = ws2_32.IPPROTO.TCP,
                .optname = tcp_nodelay,
                .optval = value,
                .optlen = @sizeOf(u32),
            };
            // The driver writes the value of a get to the output buffer of the control code.
            const result = try io.operate(.{ .device_io_control = .{
                .file = .{ .handle = socket.handle, .flags = .{ .nonblocking = true } },
                .code = windows.IOCTL.AFD.SOCKOPT,
                .in = std.mem.asBytes(&info),
                .out = if (mode == .get) std.mem.asBytes(value) else &.{},
            } });
            switch (result.device_io_control.u.Status) {
                .SUCCESS => {},
                else => |status| {
                    log.debug("TCP_NODELAY {t} failed: NTSTATUS 0x{x}", .{ mode, @intFromEnum(status) });
                    return error.OptionRejected;
                },
            }
        },
        else => {
            const bytes: *[4]u8 = @ptrCast(value);
            const rc = switch (mode) {
                .set => posix.system.setsockopt(socket.handle, posix.IPPROTO.TCP, tcp_nodelay, bytes, bytes.len),
                .get => blk: {
                    var len: posix.socklen_t = bytes.len;
                    break :blk posix.system.getsockopt(socket.handle, posix.IPPROTO.TCP, tcp_nodelay, bytes, &len);
                },
            };
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                else => |e| {
                    log.debug("TCP_NODELAY {t} failed: {t}", .{ mode, e });
                    return error.OptionRejected;
                },
            }
        },
    }
}

test "TCP_NODELAY is off on a new socket and on after setNoDelay" {
    const io = std.testing.io;
    const loopback = @import("mcp").util.loopback;
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try loopback.listen(io, address, .{});
    defer server.deinit(io);
    const client = try loopback.connect(io, server.socket.address);
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    try std.testing.expect(!try getNoDelay(io, client.socket));
    try setNoDelay(io, client.socket);
    try std.testing.expect(try getNoDelay(io, client.socket));

    try std.testing.expect(!try getNoDelay(io, accepted.socket));
    try setNoDelay(io, accepted.socket);
    try std.testing.expect(try getNoDelay(io, accepted.socket));
}
