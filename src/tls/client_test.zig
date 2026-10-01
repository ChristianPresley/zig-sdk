//! Loopback tests: the SDK TLS client against the SDK TLS server, and against
//! `openssl s_server` when it is installed.
const std = @import("std");
const Io = std.Io;
const tls = @import("tls.zig");

const Echo = struct {
    server: tls.Server,
    listener: Io.net.Server,
    io: Io,
    /// A copy of the negotiated protocol: the connection lives only inside `serveInner`.
    alpn_buf: [32]u8 = undefined,
    alpn_len: u8 = 0,
    /// The group the server negotiated.
    group: u16 = 0,
    /// The suite the server negotiated.
    suite: ?tls.Suite = null,
    /// The padding policy of the server connection.
    padding: tls.Padding = .none,
    /// Echo a second line after a key update in each direction.
    key_update: bool = false,
    result: anyerror!void = {},
    alert: std.crypto.tls.Alert = undefined,

    fn alpn(self: *const Echo) ?[]const u8 {
        return if (self.alpn_len == 0) null else self.alpn_buf[0..self.alpn_len];
    }

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
        self.suite = conn.suite;
        self.padding = conn.padding;
        if (conn.alpn()) |a| {
            @memcpy(self.alpn_buf[0..a.len], a);
            self.alpn_len = @intCast(a.len);
        }
        const line = try conn.reader.takeDelimiterExclusive('\n');
        try conn.writer.print("echo: {s}\n", .{line});
        try conn.writer.flush();
        if (self.key_update) {
            // The client sends a key update before its second line. The first read left the
            // line end in the buffer.
            conn.reader.toss(1);
            const before = trafficSecret(&conn.read_keys);
            const again = try conn.reader.takeDelimiterExclusive('\n');
            if (std.mem.eql(u8, &before, &trafficSecret(&conn.read_keys))) return error.TestNoKeyUpdate;
            try conn.updateKeys();
            try conn.writer.print("echo: {s}\n", .{again});
            try conn.writer.flush();
        }
        _ = conn.reader.takeDelimiterExclusive('\n') catch |e| switch (e) {
            error.EndOfStream => {},
            else => return e,
        };
        try conn.end();
    }
};

/// A copy of the traffic secret of `keys`. A key update changes it.
fn trafficSecret(keys: *const tls.suites.DirectionKeys) [64]u8 {
    var out: [64]u8 = @splat(0);
    switch (keys.*) {
        .none => {},
        inline else => |*k| @memcpy(out[0..k.secret.len], &k.secret),
    }
    return out;
}

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
    cipher_suites: []const tls.Suite = tls.suites.default_suites,
    identities: []const *const tls.CertChain = &.{},
    identity_fallback: @FieldType(tls.ClientOptions, "identity_fallback") = .first,
    send_ca_names: bool = false,
    /// The group both sides must negotiate.
    expect_group: ?tls.key_share.Group = null,
    /// The suite both sides must negotiate.
    expect_suite: ?tls.Suite = null,
    /// Send a second line after a key update. The server answers with a key update too.
    key_update: bool = false,
    padding: tls.Padding = .none,
};

const ServerSetup = struct {
    alpn: []const []const u8 = &.{},
    groups: []const tls.key_share.Group = tls.key_share.default_groups,
    cipher_suites: []const tls.Suite = tls.suites.default_suites,
    padding: tls.Padding = .none,
    client_auth: tls.server.ClientAuth = .none,
    client_trust: ?tls.Trust = null,
    send_client_ca_names: bool = true,
    /// The chains of the server. Null takes the one chain argument of `roundTrip`.
    chains: ?[]const *const tls.CertChain = null,
};

/// One handshake and echo between the SDK client and the SDK server. Returns the client
/// error, if any. The server result is in `echo`. The client checks `expect_alpn`.
fn roundTrip(io: Io, chain: *const tls.CertChain, server_setup: ServerSetup, client_setup: ClientSetup, echo_out: *Echo, expect_alpn: ?[]const u8) !void {
    const one = [_]*const tls.CertChain{chain};
    echo_out.* = .{
        .server = try tls.Server.init(.{
            .chains = server_setup.chains orelse &one,
            .alpn = server_setup.alpn,
            .groups = server_setup.groups,
            .cipher_suites = server_setup.cipher_suites,
            .padding = server_setup.padding,
            .client_auth = server_setup.client_auth,
            .client_trust = server_setup.client_trust,
            .send_client_ca_names = server_setup.send_client_ca_names,
        }),
        .listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{}),
        .io = io,
        .key_update = client_setup.key_update,
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
        .cipher_suites = client_setup.cipher_suites,
        .padding = client_setup.padding,
        .identity = client_setup.identity,
        .identities = client_setup.identities,
        .identity_fallback = client_setup.identity_fallback,
        .send_ca_names = client_setup.send_ca_names,
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
    if (client_setup.key_update) {
        const before = trafficSecret(&conn.read_keys);
        try conn.updateKeys();
        try conn.writer.writeAll("again\n");
        try conn.writer.flush();
        // The first read left the line end in the buffer.
        conn.reader.toss(1);
        const again = try conn.reader.takeDelimiterExclusive('\n');
        try std.testing.expectEqualStrings("echo: again", again);
        // The key update of the server changed the read keys of the client.
        try std.testing.expect(!std.mem.eql(u8, &before, &trafficSecret(&conn.read_keys)));
    }
    if (client_setup.expect_group) |g| try std.testing.expectEqual(g.wire(), conn.group);
    if (client_setup.expect_suite) |s| try std.testing.expectEqual(s, conn.suite.?);
    try std.testing.expectEqual(client_setup.padding, conn.padding);
    if (expect_alpn) |want| {
        try std.testing.expectEqualStrings(want, conn.alpn() orelse "");
    } else {
        try std.testing.expect(conn.alpn() == null);
    }
    try conn.end();
    try writer.interface.flush();
    future.await(io);
    try echo_out.result;
    if (client_setup.expect_group) |g| try std.testing.expectEqual(g.wire(), echo_out.group);
    if (client_setup.expect_suite) |s| try std.testing.expectEqual(s, echo_out.suite.?);
    try std.testing.expectEqual(server_setup.padding, echo_out.padding);
}

test "handshake with every self-signed key type" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_][2][]const u8{
        .{ "p256.crt", "p256.key" },
        .{ "p384.crt", "p384.key" },
        .{ "ed25519.crt", "ed25519.key" },
        .{ "rsa2048.crt", "rsa2048.key" },
        .{ "rsa3072.crt", "rsa3072-pkcs1.key" },
        // An id-RSASSA-PSS key that signs its own certificate with RSASSA-PSS.
        .{ "rsa-pss.crt", "rsa-pss.key" },
    };
    for (cases) |case| {
        var chain = try loadChain(gpa, io, case[0], case[1]);
        defer chain.deinit();
        var echo: Echo = undefined;
        try roundTrip(io, &chain, .{ .alpn = &.{ "h2", "http/1.1" } }, .{ .trust = .self_signed, .alpn = &.{"http/1.1"} }, &echo, "http/1.1");
        try std.testing.expectEqualStrings("http/1.1", echo.alpn().?);
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
    try roundTrip(io, &chain, .{}, .{ .trust = .{ .ca_set = &set }, .host = "localhost" }, &echo, null);
    try roundTrip(io, &chain, .{}, .{ .trust = .{ .ca_set = &set }, .host = "127.0.0.1" }, &echo, null);
    // The leaf alone, without the intermediate, is the same chain here: the CA signs it.
    var leaf_only = try loadChain(gpa, io, "chain-leaf.crt", "chain-leaf.key");
    defer leaf_only.deinit();
    try roundTrip(io, &leaf_only, .{}, .{ .trust = .{ .ca_set = &set } }, &echo, null);
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

    try std.testing.expectError(error.TlsCertificateHostMismatch, roundTrip(io, &chain, .{}, .{ .trust = .{ .ca_set = &set }, .host = "example.com" }, &echo, null));
    try std.testing.expectError(error.TlsAlert, echo.result);
    try std.testing.expectEqual(std.crypto.tls.Alert.Description.bad_certificate, echo.alert.description);

    try std.testing.expectError(error.TlsCertificateIssuerNotFound, roundTrip(io, &self_signed, .{}, .{ .trust = .{ .ca_set = &set } }, &echo, null));
    try std.testing.expectEqual(std.crypto.tls.Alert.Description.unknown_ca, echo.alert.description);

    try std.testing.expectError(error.TlsCertificateNotVerified, roundTrip(io, &chain, .{}, .{ .trust = .self_signed }, &echo, null));
    try std.testing.expectError(error.TlsCertificateNotVerified, roundTrip(io, &chain, .{}, .{ .trust = .{ .pinned_leaf = self_signed.certs[0] } }, &echo, null));
    try roundTrip(io, &chain, .{}, .{ .trust = .{ .pinned_leaf = chain.certs[0] }, .host = "anything.invalid" }, &echo, null);
}

test "hello retry request when the server wants another group" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    var echo: Echo = undefined;
    // The client shares x25519 first; the server only takes P-384.
    try roundTrip(io, &chain, .{ .groups = &.{.secp384r1} }, .{ .trust = .self_signed, .groups = &.{ .x25519, .secp384r1 } }, &echo, null);
    // No common group: the server refuses.
    try std.testing.expectError(error.TlsAlert, roundTrip(io, &chain, .{ .groups = &.{.secp384r1} }, .{ .trust = .self_signed, .groups = &.{.x25519} }, &echo, null));
    try std.testing.expectError(error.TlsHandshakeFailure, echo.result);
}

test "the hybrid group is the default and wins over classical groups" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    var echo: Echo = undefined;
    // Both sides on the defaults: X25519MLKEM768 in the first flight.
    try roundTrip(io, &chain, .{}, .{ .trust = .self_signed, .expect_group = .x25519_mlkem768 }, &echo, null);
    // A server without the hybrid group takes the fallback X25519 share of the client.
    try roundTrip(io, &chain, .{ .groups = &.{ .x25519, .secp256r1 } }, .{ .trust = .self_signed, .expect_group = .x25519 }, &echo, null);
    // A client without the hybrid group gets a classical group.
    try roundTrip(io, &chain, .{}, .{ .trust = .self_signed, .groups = &.{ .secp256r1, .x25519 }, .expect_group = .secp256r1 }, &echo, null);
    // Only the hybrid group on both sides.
    try roundTrip(io, &chain, .{ .groups = &.{.x25519_mlkem768} }, .{ .trust = .self_signed, .groups = &.{.x25519_mlkem768}, .expect_group = .x25519_mlkem768 }, &echo, null);
}

test "hello retry request to the hybrid group" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "rsa2048.crt", "rsa2048.key");
    defer chain.deinit();
    var echo: Echo = undefined;
    // The client shares X25519 only. The server takes only the hybrid group.
    try roundTrip(io, &chain, .{ .groups = &.{.x25519_mlkem768} }, .{ .trust = .self_signed, .groups = &.{ .x25519, .x25519_mlkem768 }, .expect_group = .x25519_mlkem768 }, &echo, null);
    // The server prefers the hybrid group to the X25519 share of the client and asks for it.
    try roundTrip(io, &chain, .{}, .{ .trust = .self_signed, .groups = &.{ .x25519, .x25519_mlkem768 }, .expect_group = .x25519_mlkem768 }, &echo, null);
    // From the hybrid group to P-384.
    try roundTrip(io, &chain, .{ .groups = &.{.secp384r1} }, .{ .trust = .self_signed, .groups = &.{ .x25519_mlkem768, .secp384r1 }, .expect_group = .secp384r1 }, &echo, null);
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
    try roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed, .identity = &identity }, &echo, null);
    // Required and absent: the server refuses with certificate_required. The client has
    // already sent its Finished, so it sees the alert or the closed socket afterwards.
    const absent = roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed }, &echo, null);
    try std.testing.expect(std.meta.isError(absent));
    try std.testing.expectError(error.TlsCertificateRequired, echo.result);
    // Optional and absent: fine.
    try roundTrip(io, &server_chain, .{ .client_auth = .optional, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed }, &echo, null);
    // Presented but not trusted: the server refuses with unknown_ca.
    const untrusted = roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed, .identity = &self_signed }, &echo, null);
    try std.testing.expect(std.meta.isError(untrusted));
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, echo.result);
    // An Ed25519 identity under a self-signed policy.
    try roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .self_signed }, .{ .trust = .self_signed, .identity = &self_signed }, &echo, null);
    // An RSA identity signs with RSA-PSS.
    var rsa_identity = try loadChain(gpa, io, "rsa2048.crt", "rsa2048.key");
    defer rsa_identity.deinit();
    try roundTrip(io, &server_chain, .{ .client_auth = .required, .client_trust = .self_signed }, .{ .trust = .self_signed, .identity = &rsa_identity }, &echo, null);
}

test "RSA-PSS certificates on the server and on the client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var ca_chain = try loadChain(gpa, io, "rsa-pss.crt", "rsa-pss.key");
    defer ca_chain.deinit();
    var leaf_chain = try loadChain(gpa, io, "rsa-pss-sha256.crt", "rsa-pss-sha256.key");
    defer leaf_chain.deinit();
    var p256 = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer p256.deinit();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/rsa-pss.crt");
    var echo: Echo = undefined;

    // The server leaf key signs with rsa_pss_pss_sha256 only. The CA signs the leaf with
    // RSASSA-PSS and SHA-384.
    try roundTrip(io, &leaf_chain, .{}, .{ .trust = .{ .ca_set = &set } }, &echo, null);
    try roundTrip(io, &leaf_chain, .{}, .{ .trust = .{ .ca_set = &set }, .host = "127.0.0.1" }, &echo, null);
    // The same leaf as a client certificate, and the self-signed CA as a client certificate.
    try roundTrip(io, &p256, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed, .identity = &leaf_chain }, &echo, null);
    try roundTrip(io, &p256, .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } }, .{ .trust = .self_signed, .identity = &ca_chain }, &echo, null);
    try roundTrip(io, &p256, .{ .client_auth = .required, .client_trust = .self_signed }, .{ .trust = .self_signed, .identity = &ca_chain }, &echo, null);
    // The leaf is not self-signed.
    const refused = roundTrip(io, &p256, .{ .client_auth = .required, .client_trust = .self_signed }, .{ .trust = .self_signed, .identity = &leaf_chain }, &echo, null);
    try std.testing.expect(std.meta.isError(refused));
    try std.testing.expectError(error.TlsCertificateNotVerified, echo.result);
}

test "the server names its trusted authorities and the client chooses a chain" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server_chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer server_chain.deinit();
    var self_signed = try loadChain(gpa, io, "ed25519.crt", "ed25519.key");
    defer self_signed.deinit();
    var ca_signed = try loadChain(gpa, io, "chain-leaf.crt", "chain-leaf.key");
    defer ca_signed.deinit();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    var echo: Echo = undefined;
    const required: ServerSetup = .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } };

    // The server names the test CA. The client takes the second chain, which leads to it.
    try roundTrip(io, &server_chain, required, .{ .trust = .self_signed, .identities = &.{ &self_signed, &ca_signed } }, &echo, null);
    // `identity` comes first, then `identities`.
    try roundTrip(io, &server_chain, required, .{ .trust = .self_signed, .identity = &self_signed, .identities = &.{&ca_signed} }, &echo, null);
    try roundTrip(io, &server_chain, required, .{ .trust = .self_signed, .identity = &ca_signed, .identities = &.{&self_signed} }, &echo, null);
    // Without names the client takes the first chain, which the server does not trust.
    var no_names = required;
    no_names.send_client_ca_names = false;
    const refused = roundTrip(io, &server_chain, no_names, .{ .trust = .self_signed, .identities = &.{ &self_signed, &ca_signed } }, &echo, null);
    try std.testing.expect(std.meta.isError(refused));
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, echo.result);

    // The server trusts only the RSA-PSS CA: no chain of the client leads to it.
    var pss_set: tls.CaSet = .init(gpa);
    defer pss_set.deinit();
    try pss_set.addFile(io, "test/fixtures/tls/pem/rsa-pss.crt");
    const pss_required: ServerSetup = .{ .client_auth = .required, .client_trust = .{ .ca_set = &pss_set } };
    // The fallback `first` sends the first chain anyway.
    const first = roundTrip(io, &server_chain, pss_required, .{ .trust = .self_signed, .identities = &.{ &self_signed, &ca_signed } }, &echo, null);
    try std.testing.expect(std.meta.isError(first));
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, echo.result);
    // The fallback `none` sends an empty certificate list.
    const none = roundTrip(io, &server_chain, pss_required, .{ .trust = .self_signed, .identities = &.{ &self_signed, &ca_signed }, .identity_fallback = .none }, &echo, null);
    try std.testing.expect(std.meta.isError(none));
    try std.testing.expectError(error.TlsCertificateRequired, echo.result);
    var optional = pss_required;
    optional.client_auth = .optional;
    try roundTrip(io, &server_chain, optional, .{ .trust = .self_signed, .identities = &.{ &self_signed, &ca_signed }, .identity_fallback = .none }, &echo, null);
}

test "a certificate request with many authority names" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server_chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer server_chain.deinit();
    var self_signed = try loadChain(gpa, io, "ed25519.crt", "ed25519.key");
    defer self_signed.deinit();
    var ca_signed = try loadChain(gpa, io, "chain-leaf.crt", "chain-leaf.key");
    defer ca_signed.deinit();
    var ca_buf: [128]u8 = undefined;
    const ca_text = try std.Io.Dir.cwd().readFileAlloc(io, fixture(&ca_buf, "ca.crt"), gpa, .limited(1 << 16));
    defer gpa.free(ca_text);
    var it: tls.pem.Iterator = .init(ca_text);
    const ca = try it.nextLabeled("CERTIFICATE").?.decode(gpa);
    defer gpa.free(ca);
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    var echo: Echo = undefined;
    const setup: ServerSetup = .{ .client_auth = .required, .client_trust = .{ .ca_set = &set } };
    const client: ClientSetup = .{ .trust = .self_signed, .identities = &.{ &self_signed, &ca_signed } };

    // 500 names of 30 bytes: a CertificateRequest of nearly 15 KiB, far more than the other
    // handshake messages of the server.
    for (0..500) |_| try set.addDer(ca);
    try roundTrip(io, &server_chain, setup, client, &echo, null);
    // 600 names do not fit: the server sends none, and the client takes the first chain.
    for (0..100) |_| try set.addDer(ca);
    const refused = roundTrip(io, &server_chain, setup, client, &echo, null);
    try std.testing.expect(std.meta.isError(refused));
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, echo.result);
}

test "the client names its trusted authorities and the server chooses a chain" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var self_signed = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer self_signed.deinit();
    var ca_signed = try loadChain(gpa, io, "chain.crt", "chain-leaf.key");
    defer ca_signed.deinit();
    var pss_signed = try loadChain(gpa, io, "rsa-pss-sha256.crt", "rsa-pss-sha256.key");
    defer pss_signed.deinit();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    var pss_set: tls.CaSet = .init(gpa);
    defer pss_set.deinit();
    try pss_set.addFile(io, "test/fixtures/tls/pem/rsa-pss.crt");
    var echo: Echo = undefined;
    const chains = [_]*const tls.CertChain{ &self_signed, &ca_signed, &pss_signed };
    const server: ServerSetup = .{ .chains = &chains };

    // The default chain is self-signed. The names of the client select the other chains.
    try roundTrip(io, undefined, server, .{ .trust = .{ .ca_set = &set }, .send_ca_names = true }, &echo, null);
    try roundTrip(io, undefined, server, .{ .trust = .{ .ca_set = &pss_set }, .send_ca_names = true }, &echo, null);
    // Without names the server takes the default chain, which the client does not trust.
    try std.testing.expectError(error.TlsCertificateIssuerNotFound, roundTrip(io, undefined, server, .{ .trust = .{ .ca_set = &set } }, &echo, null));
    // A policy without anchors sends no names.
    try roundTrip(io, undefined, server, .{ .trust = .self_signed, .send_ca_names = true }, &echo, null);
    // The names also go in the second ClientHello after a HelloRetryRequest.
    var retry = server;
    retry.groups = &.{.secp384r1};
    try roundTrip(io, undefined, retry, .{ .trust = .{ .ca_set = &set }, .send_ca_names = true, .groups = &.{ .x25519, .secp384r1 }, .expect_group = .secp384r1 }, &echo, null);
    // The server name comes first: a chain for another host does not count.
    try std.testing.expectError(error.TlsCertificateHostMismatch, roundTrip(io, undefined, server, .{ .trust = .{ .ca_set = &set }, .send_ca_names = true, .host = "example.com" }, &echo, null));
}

test "every cipher suite negotiates with the SDK client, with a key update" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    var echo: Echo = undefined;
    // The AEGIS suites need the option on both sides.
    for (std.enums.values(tls.Suite)) |suite| {
        try roundTrip(io, &chain, .{ .cipher_suites = &.{suite} }, .{
            .trust = .self_signed,
            .cipher_suites = tls.suites.default_suites_with_aegis,
            .expect_suite = suite,
            .key_update = true,
        }, &echo, null);
    }
    // A P-384 chain and a HelloRetryRequest with each AEGIS suite.
    var p384 = try loadChain(gpa, io, "p384.crt", "p384.key");
    defer p384.deinit();
    for ([_]tls.Suite{ .AEGIS_128L_SHA256, .AEGIS_256_SHA512 }) |suite| {
        try roundTrip(io, &p384, .{ .cipher_suites = &.{suite}, .groups = &.{.secp384r1} }, .{
            .trust = .self_signed,
            .cipher_suites = &.{ .AES_128_GCM_SHA256, suite },
            .groups = &.{ .x25519, .secp384r1 },
            .expect_suite = suite,
            .expect_group = .secp384r1,
        }, &echo, null);
    }
}

test "AEGIS is off by default in the client and the server" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    var echo: Echo = undefined;
    // A server with AEGIS first still finds a default suite of a default client.
    try roundTrip(io, &chain, .{ .cipher_suites = tls.suites.default_suites_with_aegis }, .{ .trust = .self_signed, .expect_suite = tls.suites.default_suites[0] }, &echo, null);
    // A default server does not take AEGIS from a client that offers it first.
    try roundTrip(io, &chain, .{}, .{ .trust = .self_signed, .cipher_suites = &.{ .AEGIS_128L_SHA256, .AEGIS_256_SHA512, .CHACHA20_POLY1305_SHA256 }, .expect_suite = .CHACHA20_POLY1305_SHA256 }, &echo, null);
    // AEGIS on both sides: the server preference wins.
    try roundTrip(io, &chain, .{ .cipher_suites = &.{ .AEGIS_256_SHA512, .AEGIS_128L_SHA256 } }, .{ .trust = .self_signed, .cipher_suites = tls.suites.default_suites_with_aegis, .expect_suite = .AEGIS_256_SHA512 }, &echo, null);
    // A client with only AEGIS and a default server: no common suite.
    try std.testing.expectError(error.TlsAlert, roundTrip(io, &chain, .{}, .{ .trust = .self_signed, .cipher_suites = &.{.AEGIS_128L_SHA256} }, &echo, null));
    try std.testing.expectError(error.TlsHandshakeFailure, echo.result);
}

test "record padding in both directions between the SDK client and server" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var chain = try loadChain(gpa, io, "p256.crt", "p256.key");
    defer chain.deinit();
    var echo: Echo = undefined;
    const policies = [_]tls.Padding{ .none, .{ .block = 256 }, .{ .block = tls.Connection.max_inner_plaintext_len }, .{ .random = 1024 } };
    for (policies) |policy| {
        // The same policy on both sides, with a key update in each direction.
        try roundTrip(io, &chain, .{ .padding = policy }, .{ .trust = .self_signed, .padding = policy, .key_update = true }, &echo, null);
        // A different policy on each side.
        try roundTrip(io, &chain, .{ .padding = policy }, .{ .trust = .self_signed, .padding = .{ .random = 64 } }, &echo, null);
        try roundTrip(io, &chain, .{}, .{ .trust = .self_signed, .padding = policy }, &echo, null);
    }
    // Padding on the client certificate flight, after a HelloRetryRequest, with AEGIS-256.
    var identity = try loadChain(gpa, io, "chain-leaf.crt", "chain-leaf.key");
    defer identity.deinit();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    try roundTrip(io, &chain, .{
        .padding = .{ .block = 512 },
        .cipher_suites = &.{.AEGIS_256_SHA512},
        .groups = &.{.secp384r1},
        .client_auth = .required,
        .client_trust = .{ .ca_set = &set },
    }, .{
        .trust = .self_signed,
        .identity = &identity,
        .padding = .{ .random = 255 },
        .cipher_suites = tls.suites.default_suites_with_aegis,
        .groups = &.{ .x25519, .secp384r1 },
        .expect_suite = .AEGIS_256_SHA512,
        .expect_group = .secp384r1,
        .key_update = true,
    }, &echo, null);
}

/// True when OpenSSL runs on this machine. The tests skip LibreSSL: its `s_server` has no `-rev`.
fn haveOpenssl(io: Io, gpa: std.mem.Allocator) bool {
    return opensslVersion(io, gpa) != null;
}

/// The major and minor version of OpenSSL, or null when it is absent or is LibreSSL.
pub fn opensslVersion(io: Io, gpa: std.mem.Allocator) ?[2]u32 {
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

/// True when OpenSSL has X25519MLKEM768: version 3.5 or later.
pub fn opensslHasMlkem(io: Io, gpa: std.mem.Allocator) bool {
    const v = opensslVersion(io, gpa) orelse return false;
    return v[0] > 3 or (v[0] == 3 and v[1] >= 5);
}

test "interop: the SDK client talks to openssl s_server" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    if (!haveOpenssl(io, gpa)) return error.SkipZigTest;
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    try opensslServerRoundTrip(io, &.{ "-cert", "test/fixtures/tls/pem/chain.crt", "-key", "test/fixtures/tls/pem/chain-leaf.key" }, .{ .ca_set = &set }, tls.key_share.default_groups, null, .none);
}

test "interop: the SDK client and openssl s_server with RSA and X25519MLKEM768" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    if (!opensslHasMlkem(io, gpa)) return error.SkipZigTest;
    const rsa_cert = [_][]const u8{ "-cert", "test/fixtures/tls/pem/rsa3072.crt", "-key", "test/fixtures/tls/pem/rsa3072.key" };
    // The hybrid group in the first flight.
    try opensslServerRoundTrip(io, &(rsa_cert ++ [_][]const u8{ "-groups", "X25519MLKEM768" }), .self_signed, tls.key_share.default_groups, .x25519_mlkem768, .none);
    // A HelloRetryRequest from X25519 to the hybrid group.
    try opensslServerRoundTrip(io, &(rsa_cert ++ [_][]const u8{ "-groups", "X25519MLKEM768" }), .self_signed, &.{ .x25519, .x25519_mlkem768 }, .x25519_mlkem768, .none);
    // Each RSA-PSS hash.
    for ([_][]const u8{ "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512" }) |sigalg| {
        try opensslServerRoundTrip(io, &(rsa_cert ++ [_][]const u8{ "-sigalgs", sigalg }), .self_signed, tls.key_share.default_groups, null, .none);
    }
}

test "interop: openssl s_server removes the padding of the SDK client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    if (!haveOpenssl(io, gpa)) return error.SkipZigTest;
    const cert = [_][]const u8{ "-cert", "test/fixtures/tls/pem/p256.crt", "-key", "test/fixtures/tls/pem/p256.key" };
    // The padding covers the Finished message of the client and its application data.
    for ([_]tls.Padding{ .{ .block = 4096 }, .{ .block = tls.Connection.max_inner_plaintext_len }, .{ .random = 1024 } }) |policy| {
        try opensslServerRoundTrip(io, &cert, .self_signed, tls.key_share.default_groups, null, policy);
    }
}

test "interop: the SDK client chooses the chain for the CA names of openssl s_server" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    if (!haveOpenssl(io, gpa)) return error.SkipZigTest;
    var self_signed = try loadChain(gpa, io, "ed25519.crt", "ed25519.key");
    defer self_signed.deinit();
    var ca_signed = try loadChain(gpa, io, "chain-leaf.crt", "chain-leaf.key");
    defer ca_signed.deinit();
    // The leaf of the RSA-PSS CA has no extended key usage, so OpenSSL accepts it as a client
    // certificate. The leaf of the test CA permits server authentication only.
    var pss_signed = try loadChain(gpa, io, "rsa-pss-sha256.crt", "rsa-pss-sha256.key");
    defer pss_signed.deinit();
    // s_server sends the names of its CA file. It requires and verifies the client
    // certificate, so the handshake fails with another chain.
    try opensslServer(io, &.{ "-cert", "test/fixtures/tls/pem/p256.crt", "-key", "test/fixtures/tls/pem/p256.key", "-Verify", "1", "-CAfile", "test/fixtures/tls/pem/rsa-pss.crt", "-verify_return_error" }, .{ .trust = .self_signed, .identities = &.{ &self_signed, &ca_signed, &pss_signed } });
}

test "interop: the SDK client and openssl s_server with RSA-PSS keys" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    if (!haveOpenssl(io, gpa)) return error.SkipZigTest;
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/rsa-pss.crt");
    // The self-signed RSA-PSS CA as the server certificate, for each hash.
    const ca_cert = [_][]const u8{ "-cert", "test/fixtures/tls/pem/rsa-pss.crt", "-key", "test/fixtures/tls/pem/rsa-pss.key" };
    for ([_][]const u8{ "rsa_pss_pss_sha256", "rsa_pss_pss_sha384", "rsa_pss_pss_sha512" }) |sigalg| {
        try opensslServer(io, &(ca_cert ++ [_][]const u8{ "-sigalgs", sigalg }), .{ .trust = .{ .ca_set = &set } });
    }
    try opensslServer(io, &ca_cert, .{ .trust = .self_signed });
    // The restricted leaf as the server certificate.
    try opensslServer(io, &.{ "-cert", "test/fixtures/tls/pem/rsa-pss-sha256.crt", "-key", "test/fixtures/tls/pem/rsa-pss-sha256.key" }, .{ .trust = .{ .ca_set = &set } });
    // The restricted leaf as a client certificate. The server requires and verifies it.
    var identity = try loadChain(gpa, io, "rsa-pss-sha256.crt", "rsa-pss-sha256.key");
    defer identity.deinit();
    try opensslServer(io, &.{ "-cert", "test/fixtures/tls/pem/p256.crt", "-key", "test/fixtures/tls/pem/p256.key", "-Verify", "1", "-CAfile", "test/fixtures/tls/pem/rsa-pss.crt", "-verify_return_error" }, .{ .trust = .self_signed, .identity = &identity });
}

/// Run `openssl s_server` with `extra` arguments, connect the SDK client and check an echo.
fn opensslServerRoundTrip(io: Io, extra: []const []const u8, trust: tls.Trust, groups: []const tls.key_share.Group, expect_group: ?tls.key_share.Group, padding: tls.Padding) !void {
    return opensslServer(io, extra, .{ .trust = trust, .groups = groups, .expect_group = expect_group, .padding = padding });
}

/// Run `openssl s_server` with `extra` arguments, connect the SDK client with `setup` and
/// check an echo. The client always offers the protocol "http/1.1".
fn opensslServer(io: Io, extra: []const []const u8, setup: ClientSetup) !void {
    // Pick a free port by binding and releasing it.
    const port = blk: {
        var probe = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{});
        defer probe.deinit(io);
        break :blk probe.socket.address.getPort();
    };
    var port_buf: [8]u8 = undefined;
    const port_text = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    var argv_buf: [32][]const u8 = undefined;
    const base = [_][]const u8{ "openssl", "s_server", "-accept", port_text, "-tls1_3", "-alpn", "http/1.1", "-rev", "-naccept", "1" };
    @memcpy(argv_buf[0..base.len], &base);
    @memcpy(argv_buf[base.len..][0..extra.len], extra);
    var child = try std.process.spawn(io, .{
        .argv = argv_buf[0 .. base.len + extra.len],
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
        .create_no_window = true,
    });
    defer {
        child.kill(io);
    }

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
        .host = setup.host,
        .trust = setup.trust,
        .alpn = &.{"http/1.1"},
        .groups = setup.groups,
        .identity = setup.identity,
        .padding = setup.padding,
        .identities = setup.identities,
        .identity_fallback = setup.identity_fallback,
        .send_ca_names = setup.send_ca_names,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .allow_truncation_attacks = true,
    });
    defer conn.deinit();
    try std.testing.expectEqualStrings("http/1.1", conn.alpn().?);
    if (setup.expect_group) |g| try std.testing.expectEqual(g.wire(), conn.group);
    try conn.writer.writeAll("hello\n");
    try conn.writer.flush();
    try writer.interface.flush();
    const line = try conn.reader.takeDelimiterExclusive('\n');
    try std.testing.expectEqualStrings("olleh", std.mem.trimEnd(u8, line, "\r"));
    conn.end() catch {};
    writer.interface.flush() catch {};
}
