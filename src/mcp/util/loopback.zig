//! Connect to a loopback address and listen on it, with more tries after an error that can
//! go away. The tests use these functions for their own sockets.
//!
//! On Windows, Zig 0.16.0 binds the socket of a connect to a free local port before the
//! connect. When many connections to the same server are in TIME_WAIT, the connect can then
//! fail with the status ADDRESS_ALREADY_EXISTS. When no local port is free, a connect or a
//! listen fails with the status TOO_MANY_ADDRESSES. Std gives both as `error.Unexpected`. A
//! new try usually gets another port.
const std = @import("std");
const Io = std.Io;

/// The most tries of `connect` and `listen`. The wait before the second try is 10 ms, and
/// each wait after it is two times longer.
pub const max_tries = 5;

/// Connect to `address` as a stream. After `error.Unexpected` or `error.AddressUnavailable`,
/// try again, at most `max_tries` times in total.
///
/// Use this function only for a server that listens. On Windows, std also gives a refused
/// connect as `error.Unexpected`. Thus a refused connect uses all tries there.
pub fn connect(io: Io, address: Io.net.IpAddress) Io.net.IpAddress.ConnectError!Io.net.Stream {
    var tries: u6 = 1;
    while (true) : (tries += 1) {
        return address.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
            error.Unexpected, error.AddressUnavailable => {
                if (tries == max_tries) return err;
                try wait(io, tries);
                continue;
            },
            else => return err,
        };
    }
}

/// Listen on `address`. After `error.Unexpected` or `error.AddressUnavailable`, try again, at
/// most `max_tries` times in total. The other errors come at once.
pub fn listen(io: Io, address: Io.net.IpAddress, options: Io.net.IpAddress.ListenOptions) Io.net.IpAddress.ListenError!Io.net.Server {
    var tries: u6 = 1;
    while (true) : (tries += 1) {
        return address.listen(io, options) catch |err| switch (err) {
            error.Unexpected, error.AddressUnavailable => {
                if (tries == max_tries) return err;
                try wait(io, tries);
                continue;
            },
            else => return err,
        };
    }
}

fn wait(io: Io, tries: u6) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(@as(i64, 10) << (tries - 1)), .awake);
}

test "connect and listen on a loopback address" {
    const io = std.testing.io;
    var listener = try listen(io, try Io.net.IpAddress.parse("127.0.0.1", 0), .{});
    defer listener.deinit(io);
    const stream = try connect(io, listener.socket.address);
    stream.close(io);
    const accepted = try listener.accept(io);
    accepted.close(io);
}
