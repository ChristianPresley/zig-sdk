//! HTTPS tests for the Streamable HTTP server over the in-tree TLS 1.3 server. The std TLS
//! client always runs. The `curl` and `openssl s_client` tests run when the tools are installed.
const std = @import("std");
const Io = std.Io;
const mcp = @import("../../mcp.zig");
const tls = mcp.tls;
const types = mcp.types;
const RequestContext = mcp.RequestContext;
const HttpServer = mcp.transport.http.Server;
const StdClient = std.crypto.tls.Client;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;
const discover_body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{" ++ meta_none ++ "}}";

fn add(ctx: *RequestContext, args: struct { a: i64, b: i64 }) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

const Fixture = struct {
    server: mcp.Server,
    chain: tls.CertChain,
    tls_server: tls.Server,
    transport: HttpServer,
    future: Io.Future(void),
    chains: [1]*const tls.CertChain,
    /// Set before `start` to ask for client certificates.
    client_auth: tls.server.ClientAuth = .none,
    client_trust: ?tls.Trust = null,

    fn blank() Fixture {
        return .{ .server = undefined, .chain = undefined, .tls_server = undefined, .transport = undefined, .future = undefined, .chains = undefined };
    }

    fn start(self: *Fixture, cert: []const u8, key: []const u8) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.chain = try tls.CertChain.loadFiles(gpa, io, cert, key);
        errdefer self.chain.deinit();
        self.chains = .{&self.chain};
        self.tls_server = try tls.Server.init(.{ .chains = &self.chains, .alpn = &.{"http/1.1"}, .client_auth = self.client_auth, .client_trust = self.client_trust });
        self.server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "https-test", .version = "1" } });
        errdefer self.server.deinit();
        try self.server.addTool(.{ .name = "add" }, add);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .tls = &self.tls_server });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
    }

    fn serveIgnoringErrors(t: *HttpServer) void {
        t.serve() catch {};
    }

    fn stop(self: *Fixture) void {
        const io = std.testing.io;
        self.transport.shutdown();
        self.future.await(io);
        self.transport.deinit();
        self.server.deinit();
        self.chain.deinit();
    }

    fn port(self: *const Fixture) u16 {
        return self.transport.bound_port;
    }
};

/// One HTTPS `POST` through the std TLS client. Returns the response head and body text.
fn postWithStdClient(gpa: std.mem.Allocator, io: Io, port: u16, body: []const u8) ![]u8 {
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
    var write_buf: [4096]u8 = undefined;
    var client = try StdClient.init(&reader.interface, &writer.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = Io.Clock.real.now(io),
        .allow_truncation_attacks = true,
    });
    try client.writer.print(
        "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\n" ++
            "mcp-protocol-version: 2026-07-28\r\nmcp-method: server/discover\r\nconnection: close\r\ncontent-length: {d}\r\n\r\n{s}",
        .{ body.len, body },
    );
    try client.writer.flush();
    try writer.interface.flush();
    const reply = try client.reader.allocRemaining(gpa, .limited(1 << 20));
    return reply;
}

test "https discover through the std tls client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = .blank();
    try f.start("test/fixtures/tls/pem/p256.crt", "test/fixtures/tls/pem/p256.key");
    defer f.stop();
    const reply = try postWithStdClient(gpa, io, f.port(), discover_body);
    defer gpa.free(reply);
    try std.testing.expect(std.mem.startsWith(u8, reply, "HTTP/1.1 200"));
    try std.testing.expect(std.mem.indexOf(u8, reply, "\"supportedVersions\":[\"2026-07-28\"]") != null);
}

/// Run a command and return its stdout, or null when the tool is not installed.
fn runTool(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) !?[]u8 {
    const result = std.process.run(gpa, io, .{ .argv = argv, .stdout_limit = .limited(1 << 20), .stderr_limit = .limited(1 << 20) }) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer gpa.free(result.stderr);
    return result.stdout;
}

test "https discover through curl" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const probe = (try runTool(gpa, io, &.{ "curl", "--version" })) orelse return error.SkipZigTest;
    defer gpa.free(probe);
    // The SecureTransport backend of the macOS curl has no TLS 1.3.
    if (std.mem.indexOf(u8, probe, "SecureTransport") != null) return error.SkipZigTest;
    var f: Fixture = .blank();
    try f.start("test/fixtures/tls/pem/p256.crt", "test/fixtures/tls/pem/p256.key");
    defer f.stop();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/mcp", .{f.port()});
    const out = (try runTool(gpa, io, &.{
        "curl",                             "-s",   "-k",                                          "--tlsv1.3",
        "-X",                               "POST", url,                                           "-H",
        "content-type: application/json",   "-H",   "accept: application/json, text/event-stream", "-H",
        "mcp-protocol-version: 2026-07-28", "-H",   "mcp-method: server/discover",                 "--data-binary",
        discover_body,
    })) orelse return error.SkipZigTest;
    defer gpa.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"supportedVersions\":[\"2026-07-28\"]") != null);
}

test "openssl s_client verifies the chain and negotiates alpn" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const probe = (try runTool(gpa, io, &.{ "openssl", "version" })) orelse return error.SkipZigTest;
    gpa.free(probe);
    var f: Fixture = .blank();
    try f.start("test/fixtures/tls/pem/ed25519.crt", "test/fixtures/tls/pem/ed25519.key");
    defer f.stop();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{f.port()});
    // s_client reads its stdin until end of file; a pipe that is closed at once ends the session.
    var child = try std.process.spawn(io, .{
        .argv = &.{ "openssl", "s_client", "-connect", target, "-tls1_3", "-alpn", "http/1.1", "-CAfile", "test/fixtures/tls/pem/ed25519.crt", "-verify_return_error", "-servername", "localhost" },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    child.stdin.?.close(io);
    child.stdin = null;
    var out_buf: [4096]u8 = undefined;
    var out_reader = child.stdout.?.reader(io, &out_buf);
    const out = try out_reader.interface.allocRemaining(gpa, .limited(1 << 20));
    defer gpa.free(out);
    _ = try child.wait(io);
    try std.testing.expect(std.mem.indexOf(u8, out, "ALPN protocol: http/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Verify return code: 0 (ok)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "TLSv1.3") != null);
}

test "openssl s_client with a group that needs a hello retry request" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const probe = (try runTool(gpa, io, &.{ "openssl", "version" })) orelse return error.SkipZigTest;
    gpa.free(probe);
    var f: Fixture = .blank();
    try f.start("test/fixtures/tls/pem/p384.crt", "test/fixtures/tls/pem/p384.key");
    defer f.stop();
    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{f.port()});
    // The client sends a key share only for X448, which the server does not support, and
    // lists P-384 second. The handshake can only succeed through a HelloRetryRequest for P-384.
    var child = try std.process.spawn(io, .{
        .argv = &.{ "openssl", "s_client", "-connect", target, "-tls1_3", "-groups", "X448:P-384", "-CAfile", "test/fixtures/tls/pem/p384.crt", "-verify_return_error" },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    child.stdin.?.close(io);
    child.stdin = null;
    var out_buf: [4096]u8 = undefined;
    var out_reader = child.stdout.?.reader(io, &out_buf);
    const out = try out_reader.interface.allocRemaining(gpa, .limited(1 << 20));
    defer gpa.free(out);
    _ = try child.wait(io);
    try std.testing.expect(std.mem.indexOf(u8, out, "Verify return code: 0 (ok)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Cipher is TLS_") != null);
}

// -- The MCP client over HTTPS ---------------------------------------------------------------

fn discoverAndAdd(gpa: std.mem.Allocator, io: Io, url: []const u8, setup: mcp.transport.HttpClient.TlsSetup) !void {
    const http_client = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url, .tls = setup });
    defer http_client.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(http_client.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const disc = try client.discover(arena, .{ .timeout = .fromSeconds(10) });
    try std.testing.expect(disc.capabilities.tools != null);
    const sum = try client.callTool(arena, "add", .{ .a = 20, .b = 22 }, .{ .timeout = .fromSeconds(10) });
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);
}

test "the MCP client over HTTPS with the SDK TLS client" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = .blank();
    try f.start("test/fixtures/tls/pem/chain.crt", "test/fixtures/tls/pem/chain-leaf.key");
    defer f.stop();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/mcp", .{f.port()});

    try discoverAndAdd(gpa, io, url, .{ .trust = .{ .ca_set = &set } });
    try discoverAndAdd(gpa, io, url, .{ .trust = .{ .ca_set = &set }, .server_name = "localhost" });
    try discoverAndAdd(gpa, io, url, .{ .trust = .{ .pinned_leaf = f.chain.certs[0] } });

    // A certificate the client does not trust: no request gets through.
    const untrusted = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url, .tls = .{ .trust = .self_signed } });
    defer untrusted.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(untrusted.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    try std.testing.expectError(error.TransportFailed, client.discover(arena_state.allocator(), .{ .retry = .never }));
}

test "the MCP client over HTTPS with a client certificate" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");
    var f: Fixture = .blank();
    f.client_auth = .required;
    f.client_trust = .{ .ca_set = &set };
    try f.start("test/fixtures/tls/pem/p256.crt", "test/fixtures/tls/pem/p256.key");
    defer f.stop();
    var identity = try tls.CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/chain-leaf.crt", "test/fixtures/tls/pem/chain-leaf.key");
    defer identity.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/mcp", .{f.port()});
    try discoverAndAdd(gpa, io, url, .{ .trust = .self_signed, .identity = &identity });
}
