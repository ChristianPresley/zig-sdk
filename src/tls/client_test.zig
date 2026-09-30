//! Loopback tests: the SDK TLS client against the SDK TLS server, and against
//! `openssl s_server` when it is installed.
const std = @import("std");
const Io = std.Io;
const tls = @import("tls.zig");

const Echo = struct {
    server: tls.Server,
    listener: Io.net.Server,
    io: Io,
    alpn: ?[]const u8 = null,
    result: anyerror!void = {},
    alert: std.crypto.tls.Alert = undefined,

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
        _ = conn.reader.takeDelimiterExclusive('\n') catch |e| switch (e) {
            error.EndOfStream => {},
            else => return e,
        };
        try conn.end();
    }
};

fn fixture(buf: []u8, name: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "test/fixtures/tls/pem/{s}", .{name}) catch unreachable;
}

fn loadChain(gpa: std.mem.Allocator, io: Io, name: []const u8, key: []const u8) !tls.CertChain {
    var cert_path_buf: [128]u8 = undefined;
    var key_path_buf: [128]u8 = undefined;
    return tls.CertChain.loadFiles(gpa, io, fixture(&cert_path_buf, name), fixture(&key_path_buf, key));
}

const ClientSetup = struct {
    host: []const u8 = "localhost",
    trust: tls.Trust,
    alpn: []const []const u8 = &.{},
    groups: []const tls.key_share.Group = tls.key_share.default_groups,
    identity: ?*const tls.CertChain = null,
};

const ServerSetup = struct {
    alpn: []const []const u8 = &.{},
    groups: []const tls.key_share.Group = tls.key_share.default_groups,
    client_auth: tls.server.ClientAuth = .none,
    client_trust: ?tls.Trust = null,
};

/// One handshake and echo between the SDK client and the SDK server. Returns the client
/// error, if any. The server result is in `echo`.
fn roundTrip(io: Io, chain: *const tls.CertChain, server_setup: ServerSetup, client_setup: ClientSetup, echo_out: *Echo) !?[]const u8 {
    const chains = [_]*const tls.CertChain{chain};
    echo_out.* = .{
        .server = try tls.Server.init(.{ .chains = &chains, .alpn = server_setup.alpn, .groups = server_setup.groups, .client_auth = server_setup.client_auth, .client_trust = server_setup.client_trust }),
        .listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{}),
        .io = io,
    };
    defer echo_out.listener.deinit(io);
    const port = echo_out.listener.socket.address.getPort();
    var future = try io.concurrent(Echo.serve, .{echo_out});
    defer _ = future.cancel(io);

    const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    var stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var in_buf: [tls.Connection.min_input_buffer_len]u8 = undefined;
    var out_buf: [tls.Connection.min_output_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    var read_buf: [tls.Connection.min_read_buffer_len]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var alert: std.crypto.tls.Alert = undefined;
    var conn = tls.connect(&reader.interface, &writer.interface, .{
        .io = io,
        .host = client_setup.host,
        .trust = client_setup.trust,
        .alpn = client_setup.alpn,
        .groups = client_setup.groups,
        .identity = client_setup.identity,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .alert = &alert,
        .allow_truncation_attacks = true,
    }) catch |e| {
        writer.interface.flush() catch {};
        future.await(io);
        return e;
    };
    defer conn.deinit();
    try conn.writer.writeAll("hello\n");
    try conn.writer.flush();
    try writer.interface.flush();
    const line = try conn.reader.takeDelimiterExclusive('\n');
    try std.testing.expectEqualStrings("echo: hello", line);
    try conn.end();
    try writer.interface.flush();
    future.await(io);
    try echo_out.result;
    return conn.alpn();
}

test "handshake with every self-signed key type" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_][2][]const u8{
        .{ "p256.crt", "p256.key" },
        .{ "p384.crt", "p384.key" },
        .{ "ed25519.crt", "ed25519.key" },
    };
    for (cases) |case| {
        var chain = try loadChain(gpa, io, case[0], case[1]);
        defer chain.deinit();
        var echo: Echo = undefined;
        const alpn = try roundTrip(io, &chain, .{ .alpn = &.{ "h2", "http/1.1" } }, .{ .trust = .self_signed, .alpn = &.{"http/1.1"} }, &echo);
        try std.testing.expectEqualStrings("http/1.1", alpn.?);
        try std.testing.expectEqualStrings("http/1.1", echo.alpn.?);
    }
}

test "a chain verifies against the CA set, by name and by address" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "chain.crt", "chain-leaf.key");
    defer chain.deinit();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    var echo: Echo = undefined;
    _ = try roundTrip(io, &chain, .{}, .{ .trust = .{ .ca_set = &set }, .host = "localhost" }, &echo);
    _ = try roundTrip(io, &chain, .{}, .{ .trust = .{ .ca_set = &set }, .host = "127.0.0.1" }, &echo);
    // The leaf alone, without the intermediate, is the same chain here: the CA signs it.
    var leaf_only = try loadChain(gpa, io, "chain-leaf.crt", "chain-leaf.key");
    defer leaf_only.deinit();
    _ = try roundTrip(io, &leaf_only, .{}, .{ .trust = .{ .ca_set = &set } }, &echo);
}

test "certificate problems end the handshake with an alert" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "chain.crt", "chain-leaf.key");
    defer chain.deinit();
    var self_signed = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer self_signed.deinit();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    var echo: Echo = undefined;

    try std.testing.expectError(error.TlsCertificateHostMismatch, roundTrip(io, &chain, .{}, .{ .trust = .{ .ca_set = &set }, .host = "example.com" }, &echo));
    try std.testing.expectError(error.TlsAlert, echo.result);
    try std.testing.expectEqual(std.crypto.tls.Alert.Description.bad_certificate, echo.alert.description);

    try std.testing.expectError(error.TlsCertificateIssuerNotFound, roundTrip(io, &self_signed, .{}, .{ .trust = .{ .ca_set = &set } }, &echo));
    try std.testing.expectEqual(std.crypto.tls.Alert.Description.unknown_ca, echo.alert.description);

    try std.testing.expectError(error.TlsCertificateNotVerified, roundTrip(io, &chain, .{}, .{ .trust = .self_signed }, &echo));
    try std.testing.expectError(error.TlsCertificateNotVerified, roundTrip(io, &chain, .{}, .{ .trust = .{ .pinned_leaf = self_signed.certs[0] } }, &echo));
    _ = try roundTrip(io, &chain, .{}, .{ .trust = .{ .pinned_leaf = chain.certs[0] }, .host = "anything.invalid" }, &echo);
}

test "hello retry request when the server wants another group" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    var echo: Echo = undefined;
    // The client shares x25519 first; the server only takes P-384.
    _ = try roundTrip(io, &chain, .{ .groups = &.{.secp384r1} }, .{ .trust = .self_signed, .groups = &.{ .x25519, .secp384r1 } }, &echo);
    // No common group: the server refuses.
    try std.testing.expectError(error.TlsAlert, roundTrip(io, &chain, .{ .groups = &.{.secp384r1} }, .{ .trust = .self_signed, .groups = &.{.x25519} }, &echo));
    try std.testing.expectError(error.TlsHandshakeFailure, echo.result);
}

test "mutual authentication with client certificates" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server_chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer server_chain.deinit();
    var identity = try loadChain(gpa, io, "chain-leaf.crt", "chain-leaf.key");
    defer identity.deinit();
    var self_signed = try loadChain(gpa, io, "ed25519.crt", "ed25519.key");
    defer self_signed.deinit();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    var echo: Echo = undefined;

    // Required and presented: both sides see the peer.
    _ = try roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed, .identity = &identity }, &echo);
    // Required and absent: the server refuses with certificate_required. The client has
    // already sent its Finished, so it sees the alert or the closed socket afterwards.
    const absent = roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed }, &echo);
    try std.testing.expect(std.meta.isError(absent));
    try std.testing.expectError(error.TlsCertificateRequired, echo.result);
    // Optional and absent: fine.
    _ = try roundTrip(io, &server_chain, .{ .client_auth = .optional, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed }, &echo);
    // Presented but not trusted: the server refuses with unknown_ca.
    const untrusted = roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed, .identity = &self_signed }, &echo);
    try std.testing.expect(std.meta.isError(untrusted));
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, echo.result);
    // An Ed25519 identity under a self-signed policy.
    _ = try roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .self_signed }, .{ .trust = .self_signed, .identity = &self_signed }, &echo);
}

test "every cipher suite negotiates with the SDK client" {
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
        var in_buf: [tls.Connection.min_input_buffer_len]u8 = undefined;
        var out_buf: [tls.Connection.min_output_buffer_len]u8 = undefined;
        var reader = stream.reader(io, &in_buf);
        var writer = stream.writer(io, &out_buf);
        var read_buf: [tls.Connection.min_read_buffer_len]u8 = undefined;
        var write_buf: [1024]u8 = undefined;
        var conn = try tls.connect(&reader.interface, &writer.interface, .{
            .io = io,
            .host = "localhost",
            .trust = .self_signed,
            .read_buffer = &read_buf,
            .write_buffer = &write_buf,
            .allow_truncation_attacks = true,
        });
        defer conn.deinit();
        try std.testing.expectEqual(suite, conn.suite.?);
        try conn.writer.writeAll("suite\n");
        try conn.writer.flush();
        try writer.interface.flush();
        const line = try conn.reader.takeDelimiterExclusive('\n');
        try std.testing.expectEqualStrings("echo: suite", line);
        try conn.end();
        try writer.interface.flush();
        future.await(io);
        try echo.result;
    }
}

/// True when `openssl` runs on this machine.
fn haveOpenssl(io: Io, gpa: std.mem.Allocator) bool {
    var child = std.process.spawn(io, .{ .argv = &.{ "openssl", "version" }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch return false;
    const term = child.wait(io) catch return false;
    _ = gpa;
    return term == .exited and term.exited == 0;
}

test "interop: the SDK client talks to openssl s_server" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    if (!haveOpenssl(io, gpa)) return error.SkipZigTest;
    // Pick a free port by binding and releasing it.
    const port = blk: {
        var probe = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{});
        defer probe.deinit(io);
        break :blk probe.socket.address.getPort();
    };
    var port_buf: [8]u8 = undefined;
    const port_text = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    var child = try std.process.spawn(io, .{
        .argv = &.{ "openssl", "s_server", "-accept", port_text, "-cert", "test/fixtures/tls/pem/chain.crt", "-key", "test/fixtures/tls/pem/chain-leaf.key", "-tls1_3", "-alpn", "http/1.1", "-rev", "-naccept", "1" },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
        .create_no_window = true,
    });
    defer {
        child.kill(io);
    }
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");

    // Wait for the listener.
    const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    var stream: Io.net.Stream = undefined;
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        stream = address.connect(io, .{ .mode = .stream }) catch {
            if (attempts > 100) return error.OpensslDidNotListen;
            try io.sleep(.fromMilliseconds(50), .awake);
            continue;
        };
        break;
    }
    defer stream.close(io);
    var in_buf: [tls.Connection.min_input_buffer_len]u8 = undefined;
    var out_buf: [tls.Connection.min_output_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    var read_buf: [tls.Connection.min_read_buffer_len]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var conn = try tls.connect(&reader.interface, &writer.interface, .{
        .io = io,
        .host = "localhost",
        .trust = .{ .ca_set = &set },
        .alpn = &.{"http/1.1"},
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .allow_truncation_attacks = true,
    });
    defer conn.deinit();
    try std.testing.expectEqualStrings("http/1.1", conn.alpn().?);
    try conn.writer.writeAll("hello\n");
    try conn.writer.flush();
    try writer.interface.flush();
    const line = try conn.reader.takeDelimiterExclusive('\n');
    try std.testing.expectEqualStrings("olleh", std.mem.trimEnd(u8, line, "\r"));
    conn.end() catch {};
    writer.interface.flush() catch {};
}
