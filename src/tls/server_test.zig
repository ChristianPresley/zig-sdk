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
    /// Run the handshake only, then wait for the client to close.
    handshake_only: bool = false,
    /// The group the server negotiated.
    group: u16 = 0,
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
        self.group = conn.group;
        if (self.handshake_only) {
            _ = conn.reader.discardRemaining() catch {};
            conn.end() catch {};
            return;
        }
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
    return roundTripGroups(gpa, io, chain, config_alpn, tls.key_share.default_groups, null);
}

/// One echo with the std client. The test compares `expect_group` with the server group.
fn roundTripGroups(gpa: std.mem.Allocator, io: Io, chain: *const tls.CertChain, config_alpn: []const []const u8, groups: []const tls.key_share.Group, expect_group: ?tls.key_share.Group) !void {
    const chains = [_]*const tls.CertChain{chain};
    var echo: Echo = .{
        .server = try tls.Server.init(.{ .chains = &chains, .alpn = config_alpn, .groups = groups }),
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
    if (expect_group) |g| try std.testing.expectEqual(g.wire(), echo.group);
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
        .{ "rsa2048.crt", "rsa2048.key" },
        .{ "rsa3072.crt", "rsa3072-pkcs1.key" },
    };
    for (cases) |case| {
        var chain = try loadChain(gpa, io, case[0], case[1]);
        defer chain.deinit();
        try roundTrip(gpa, io, &chain, &.{});
    }
}

/// One echo between the std client and an SDK server with `config`. The std client offers
/// every TLS 1.3 suite, the AEGIS suites first. Returns the name of the suite that the std
/// client negotiated.
fn stdClientEcho(io: Io, config: tls.server.Config, message: []const u8) ![]const u8 {
    var echo: Echo = .{
        .server = try tls.Server.init(config),
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
    const suite = @tagName(client.application_cipher);
    try client.writer.print("{s}\n", .{message});
    try client.writer.flush();
    try writer.interface.flush();
    const line = try client.reader.takeDelimiterExclusive('\n');
    try std.testing.expect(std.mem.startsWith(u8, line, "echo: "));
    try std.testing.expectEqualStrings(message, line["echo: ".len..]);
    try client.end();
    try writer.interface.flush();
    future.await(io);
    try echo.result;
    return suite;
}

test "every cipher suite negotiates" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    const chains = [_]*const tls.CertChain{&chain};
    // The AEGIS suites too: the std client is a second implementation of them.
    for (std.enums.values(tls.Suite)) |suite| {
        const got = try stdClientEcho(io, .{ .chains = &chains, .cipher_suites = &.{suite} }, "suite");
        try std.testing.expectEqualStrings(@tagName(suite), got);
    }
}

test "AEGIS is off by default and on with the option" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    const chains = [_]*const tls.CertChain{&chain};
    // The std client offers AEGIS first. The default server takes its own first choice.
    const default = try stdClientEcho(io, .{ .chains = &chains }, "default");
    try std.testing.expectEqualStrings(@tagName(tls.suites.default_suites[0]), default);
    try std.testing.expect(std.mem.indexOf(u8, default, "AEGIS") == null);
    // With the AEGIS list, the server takes the first suite of that list.
    const with_aegis = try stdClientEcho(io, .{ .chains = &chains, .cipher_suites = tls.suites.default_suites_with_aegis }, "aegis");
    try std.testing.expectEqualStrings(@tagName(tls.suites.default_suites_with_aegis[0]), with_aegis);
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

test "the std client negotiates X25519MLKEM768" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "rsa2048.crt", "rsa2048.key");
    defer chain.deinit();
    // The std client sends a hybrid share. The server prefers it by default.
    try roundTripGroups(gpa, io, &chain, &.{}, tls.key_share.default_groups, .x25519_mlkem768);
    // Without the hybrid group the server takes a classical share.
    try roundTripGroups(gpa, io, &chain, &.{}, &.{ .secp384r1, .x25519 }, .secp384r1);
}

/// The major and minor version of OpenSSL, or null when it is absent or is LibreSSL.
fn opensslVersion(io: Io, gpa: std.mem.Allocator) ?[2]u32 {
    const result = std.process.run(gpa, io, .{ .argv = &.{ "openssl", "version" }, .stdout_limit = .limited(256), .stderr_limit = .limited(256) }) catch return null;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return null;
    const prefix = "OpenSSL ";
    if (!std.mem.startsWith(u8, result.stdout, prefix)) return null;
    var parts = std.mem.splitScalar(u8, result.stdout[prefix.len..], '.');
    const major = std.fmt.parseInt(u32, parts.next() orelse return null, 10) catch return null;
    const minor = std.fmt.parseInt(u32, parts.next() orelse return null, 10) catch return null;
    return .{ major, minor };
}

/// Run `openssl s_client` with `extra` arguments against the SDK server and return its
/// output. The server result and group are in `echo`.
fn opensslClient(gpa: std.mem.Allocator, io: Io, chain: *const tls.CertChain, groups: []const tls.key_share.Group, extra: []const []const u8, echo: *Echo) ![]u8 {
    const chains = [_]*const tls.CertChain{chain};
    echo.* = .{
        .server = try tls.Server.init(.{ .chains = &chains, .groups = groups }),
        .listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{}),
        .io = io,
        .handshake_only = true,
    };
    defer echo.listener.deinit(io);
    const port = echo.listener.socket.address.getPort();
    var future = try io.concurrent(Echo.serve, .{echo});
    defer _ = future.cancel(io);
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{port});
    var argv_buf: [32][]const u8 = undefined;
    const base = [_][]const u8{ "openssl", "s_client", "-connect", target, "-tls1_3", "-servername", "localhost" };
    @memcpy(argv_buf[0..base.len], &base);
    @memcpy(argv_buf[base.len..][0..extra.len], extra);
    // s_client reads its stdin until end of file. A pipe that is closed at once ends the session.
    var child = try std.process.spawn(io, .{
        .argv = argv_buf[0 .. base.len + extra.len],
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
        .create_no_window = true,
    });
    child.stdin.?.close(io);
    child.stdin = null;
    var out_buf: [4096]u8 = undefined;
    var out_reader = child.stdout.?.reader(io, &out_buf);
    const out = try out_reader.interface.allocRemaining(gpa, .limited(1 << 20));
    errdefer gpa.free(out);
    _ = try child.wait(io);
    future.await(io);
    return out;
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing \"{s}\" in:\n{s}\n", .{ needle, haystack });
        return error.TestExpectedEqual;
    }
}

test "interop: openssl s_client with RSA-PSS and X25519MLKEM768" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const version = opensslVersion(io, gpa) orelse return error.SkipZigTest;
    const has_mlkem = version[0] > 3 or (version[0] == 3 and version[1] >= 5);
    var chain = try loadChain(gpa, io, "rsa2048.crt", "rsa2048.key");
    defer chain.deinit();
    var echo: Echo = undefined;

    // Every RSA-PSS hash, chosen by the client.
    for ([_][2][]const u8{
        .{ "rsa_pss_rsae_sha256", "Peer signing digest: SHA256" },
        .{ "rsa_pss_rsae_sha384", "Peer signing digest: SHA384" },
        .{ "rsa_pss_rsae_sha512", "Peer signing digest: SHA512" },
    }) |case| {
        const out = try opensslClient(gpa, io, &chain, tls.key_share.default_groups, &.{ "-sigalgs", case[0], "-CAfile", "test/fixtures/tls/pem/rsa2048.crt", "-verify_return_error" }, &echo);
        defer gpa.free(out);
        try echo.result;
        try expectContains(out, "Verify return code: 0 (ok)");
        // OpenSSL 3.5 names the scheme. Older versions name the algorithm.
        if (std.mem.indexOf(u8, out, "RSA-PSS") == null) try expectContains(out, case[0]);
        try expectContains(out, case[1]);
    }
    // A client that offers only PKCS#1 v1.5 gets no RSA signature: TLS 1.3 forbids it.
    {
        const out = try opensslClient(gpa, io, &chain, tls.key_share.default_groups, &.{ "-sigalgs", "rsa_pkcs1_sha256" }, &echo);
        defer gpa.free(out);
        try std.testing.expectError(error.TlsHandshakeFailure, echo.result);
    }
    if (!has_mlkem) return;

    var chain3072 = try loadChain(gpa, io, "rsa3072.crt", "rsa3072.key");
    defer chain3072.deinit();
    // The hybrid group in the first flight.
    {
        const out = try opensslClient(gpa, io, &chain3072, tls.key_share.default_groups, &.{ "-groups", "X25519MLKEM768:X25519" }, &echo);
        defer gpa.free(out);
        try echo.result;
        try std.testing.expectEqual(tls.key_share.Group.x25519_mlkem768.wire(), echo.group);
        try expectContains(out, "Negotiated TLS1.3 group: X25519MLKEM768");
    }
    // The client sends an X25519 share first. The server asks for the hybrid group.
    {
        const out = try opensslClient(gpa, io, &chain3072, tls.key_share.default_groups, &.{ "-groups", "X25519:X25519MLKEM768" }, &echo);
        defer gpa.free(out);
        try echo.result;
        try std.testing.expectEqual(tls.key_share.Group.x25519_mlkem768.wire(), echo.group);
    }
}
