//! Loopback tests: the SDK TLS server against the std TLS client.
const std = @import("std");
const Io = std.Io;
const tls = @import("tls.zig");
const StdClient = std.crypto.tls.Client;

const Echo = struct {
    server: tls.Server,
    listener: Io.net.Server,
    io: Io,
    alpn: ?[]const u8 = null,
    result: anyerror!void = {},
    alert: std.crypto.tls.Alert = undefined,

    /// Accept one connection, run the handshake and echo one line.
    fn serve(self: *Echo) void {
        self.result = self.serveInner();
    }

    fn serveInner(self: *Echo) !void {
        var stream = try self.listener.accept(self.io);
        defer stream.close(self.io);
        var in_buf: [tls.Connection.min_input_buffer_len]u8 = undefined;
        var out_buf: [tls.Connection.min_output_buffer_len]u8 = undefined;
        var reader = stream.reader(self.io, &in_buf);
        var writer = stream.writer(self.io, &out_buf);
        var read_buf: [tls.Connection.min_read_buffer_len]u8 = undefined;
        var write_buf: [4096]u8 = undefined;
        var conn = try self.server.accept(&reader.interface, &writer.interface, .{
            .io = self.io,
            .read_buffer = &read_buf,
            .write_buffer = &write_buf,
            .alert = &self.alert,
        });
        defer conn.deinit();
        if (conn.alpn()) |a| self.alpn = a;
        const line = try conn.reader.takeDelimiterExclusive('\n');
        try conn.writer.print("echo: {s}\n", .{line});
        try conn.writer.flush();
        // Read until the client closes.
        _ = conn.reader.takeDelimiterExclusive('\n') catch |e| switch (e) {
            error.EndOfStream => {},
            else => return e,
        };
        try conn.end();
    }
};

fn loadChain(gpa: std.mem.Allocator, io: Io, name: []const u8, key: []const u8) !tls.CertChain {
    var cert_path_buf: [128]u8 = undefined;
    var key_path_buf: [128]u8 = undefined;
    const cert_path = try std.fmt.bufPrint(&cert_path_buf, "test/fixtures/tls/pem/{s}", .{name});
    const key_path = try std.fmt.bufPrint(&key_path_buf, "test/fixtures/tls/pem/{s}", .{key});
    return tls.CertChain.loadFiles(gpa, io, cert_path, key_path);
}

fn roundTrip(gpa: std.mem.Allocator, io: Io, chain: *const tls.CertChain, config_alpn: []const []const u8) !void {
    const chains = [_]*const tls.CertChain{chain};
    var echo: Echo = .{
        .server = try tls.Server.init(.{ .chains = &chains, .alpn = config_alpn }),
        .listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{}),
        .io = io,
    };
    defer echo.listener.deinit(io);
    const port = echo.listener.socket.address.getPort();
    var future = try io.concurrent(Echo.serve, .{&echo});
    defer _ = future.cancel(io);

    const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    var stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var in_buf: [StdClient.min_buffer_len]u8 = undefined;
    var out_buf: [StdClient.min_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    var entropy: [StdClient.Options.entropy_len]u8 = undefined;
    try io.randomSecure(&entropy);
    var read_buf: [tls.Connection.min_read_buffer_len]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var client = try StdClient.init(&reader.interface, &writer.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = Io.Clock.real.now(io),
        .allow_truncation_attacks = true,
    });
    try std.testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_3, client.tls_version);
    try client.writer.writeAll("hello\n");
    try client.writer.flush();
    try writer.interface.flush();
    const line = try client.reader.takeDelimiterExclusive('\n');
    try std.testing.expectEqualStrings("echo: hello", line);
    try client.end();
    try writer.interface.flush();
    future.await(io);
    try echo.result;
    _ = gpa;
}

test "handshake and echo with the std client for every key type" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_][2][]const u8{
        .{ "p256.crt", "p256.key" },
        .{ "p384.crt", "p384.key" },
        // Ed25519 is covered by the openssl interop test: the std client cannot verify it.
        .{ "chain.crt", "chain-leaf.key" },
    };
    for (cases) |case| {
        var chain = try loadChain(gpa, io, case[0], case[1]);
        defer chain.deinit();
        try roundTrip(gpa, io, &chain, &.{});
    }
}

test "every cipher suite negotiates" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    for (tls.suites.default_suites) |suite| {
        const chains = [_]*const tls.CertChain{&chain};
        var echo: Echo = .{
            .server = try tls.Server.init(.{ .chains = &chains, .cipher_suites = &.{suite} }),
            .listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{}),
            .io = io,
        };
        defer echo.listener.deinit(io);
        const port = echo.listener.socket.address.getPort();
        var future = try io.concurrent(Echo.serve, .{&echo});
        defer _ = future.cancel(io);
        const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
        var stream = try address.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var in_buf: [StdClient.min_buffer_len]u8 = undefined;
        var out_buf: [StdClient.min_buffer_len]u8 = undefined;
        var reader = stream.reader(io, &in_buf);
        var writer = stream.writer(io, &out_buf);
        var entropy: [StdClient.Options.entropy_len]u8 = undefined;
        try io.randomSecure(&entropy);
        var read_buf: [tls.Connection.min_read_buffer_len]u8 = undefined;
        var write_buf: [1024]u8 = undefined;
        var client = try StdClient.init(&reader.interface, &writer.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &read_buf,
            .write_buffer = &write_buf,
            .entropy = &entropy,
            .realtime_now = Io.Clock.real.now(io),
            .allow_truncation_attacks = true,
        });
        try std.testing.expectEqualStrings(@tagName(suite), @tagName(client.application_cipher));
        try client.writer.writeAll("suite\n");
        try client.writer.flush();
        try writer.interface.flush();
        const line = try client.reader.takeDelimiterExclusive('\n');
        try std.testing.expectEqualStrings("echo: suite", line);
        try client.end();
        try writer.interface.flush();
        future.await(io);
        try echo.result;
    }
}

test "a TLS 1.2 client hello is refused with protocol_version" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    const chains = [_]*const tls.CertChain{&chain};
    var echo: Echo = .{
        .server = try tls.Server.init(.{ .chains = &chains }),
        .listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{}),
        .io = io,
    };
    defer echo.listener.deinit(io);
    const port = echo.listener.socket.address.getPort();
    var future = try io.concurrent(Echo.serve, .{&echo});
    defer _ = future.cancel(io);
    const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    var stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var out_buf: [512]u8 = undefined;
    var writer = stream.writer(io, &out_buf);
    // A minimal TLS 1.2-only ClientHello: no supported_versions extension.
    const hello = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x2d, 0x01, 0x00, 0x00, 0x29, 0x03, 0x03 } ++ [_]u8{0} ** 32 ++
        [_]u8{ 0x00, 0x00, 0x02, 0xc0, 0x2f, 0x01, 0x00 };
    try writer.interface.writeAll(&hello);
    try writer.interface.flush();
    var in_buf: [512]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    const alert = try reader.interface.takeArray(7);
    try std.testing.expectEqual(0x15, alert[0]); // alert record
    try std.testing.expectEqual(2, alert[5]); // fatal
    try std.testing.expectEqual(@intFromEnum(std.crypto.tls.Alert.Description.missing_extension), alert[6]);
    future.await(io);
    try std.testing.expectError(error.TlsMissingExtension, echo.result);
}
