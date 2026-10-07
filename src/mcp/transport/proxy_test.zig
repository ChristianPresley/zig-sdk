//! The HTTP client transport through a `CONNECT` proxy. `TestProxy` is a small proxy on a
//! loopback port. The tests of the OAuth fetcher use it too.
const std = @import("std");
const Io = std.Io;
const http = std.http;
const mcp = @import("../../mcp.zig");
const tls = mcp.tls;
const types = mcp.types;
const proxy = mcp.transport.proxy;
const http1 = mcp.transport.http1;
const HttpServer = mcp.transport.http.Server;
const HttpClient = mcp.transport.HttpClient;

/// A `CONNECT` proxy on a loopback port for the tests. It serves one connection at a time. It
/// records the target and the `proxy-authorization` header of each request. For each host name,
/// it connects to the port of the target at 127.0.0.1. Then it answers 200 and copies the bytes
/// in both directions. With `refuse`, it answers with that status and opens no tunnel.
///
/// `stop` wakes the accept loop as `util.wake` tells. A tunnel ends when the server closes its
/// connection after the response. The copy from the client then stops with a cancel, or when
/// the client closes its side. Thus no read waits after the test.
pub const TestProxy = struct {
    io: Io,
    listener: Io.net.Server,
    stopping: std.atomic.Value(bool) = .init(false),
    future: Io.Future(void),
    refuse: ?http.Status,
    lock: Io.Mutex = .init,
    arena_state: std.heap.ArenaAllocator,
    /// The targets of the requests, in order.
    targets: std.ArrayList([]const u8) = .empty,
    /// The `proxy-authorization` value of the last request, or null.
    authorization: ?[]const u8 = null,
    /// The number of tunnels that the proxy opened.
    tunnels: std.atomic.Value(u32) = .init(0),

    pub fn start(self: *TestProxy, refuse: ?http.Status) !void {
        const io = std.testing.io;
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.* = .{
            .io = io,
            .listener = try address.listen(io, .{ .reuse_address = true }),
            .future = undefined,
            .refuse = refuse,
            .arena_state = .init(std.testing.allocator),
        };
        errdefer {
            self.listener.deinit(io);
            self.arena_state.deinit();
        }
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    pub fn stop(self: *TestProxy) void {
        mcp.util.wake.cancelAcceptLoop(self.io, &self.future, self.listener.socket.address, &self.stopping);
        self.listener.deinit(self.io);
        self.arena_state.deinit();
    }

    pub fn port(self: *const TestProxy) u16 {
        return self.listener.socket.address.getPort();
    }

    /// The URL of the proxy in `buf`, with `user_info` and `@` before the host when it is not
    /// empty.
    pub fn url(self: *const TestProxy, buf: []u8, user_info: []const u8) []const u8 {
        const at = if (user_info.len > 0) "@" else "";
        return std.fmt.bufPrint(buf, "http://{s}{s}127.0.0.1:{d}", .{ user_info, at, self.port() }) catch unreachable;
    }

    /// True when a request asked for a tunnel to `target`.
    pub fn sawTarget(self: *TestProxy, target: []const u8) bool {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.targets.items) |t| if (std.mem.eql(u8, t, target)) return true;
        return false;
    }

    /// The `proxy-authorization` value of the last request, in `arena`.
    pub fn lastAuthorization(self: *TestProxy, arena: std.mem.Allocator) !?[]const u8 {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        return if (self.authorization) |a| try arena.dupe(u8, a) else null;
    }

    fn record(self: *TestProxy, target: []const u8, authorization: ?[]const u8) !void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const arena = self.arena_state.allocator();
        try self.targets.append(arena, try arena.dupe(u8, target));
        self.authorization = if (authorization) |a| try arena.dupe(u8, a) else null;
    }

    fn acceptLoop(self: *TestProxy) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            if (self.stopping.load(.acquire)) return;
            self.serve(stream) catch {};
        }
    }

    fn serve(self: *TestProxy, client: Io.net.Stream) !void {
        const io = self.io;
        var in_buf: [8192]u8 = undefined;
        var out_buf: [512]u8 = undefined;
        var reader = client.reader(io, &in_buf);
        var writer = client.writer(io, &out_buf);
        var head_reader: http.Reader = .{ .in = &reader.interface, .interface = undefined, .state = .ready, .max_head_len = in_buf.len };
        const head = try head_reader.receiveHead();
        var lines = std.mem.splitSequence(u8, head, "\r\n");
        var words = std.mem.splitScalar(u8, lines.first(), ' ');
        const method = words.first();
        const target = words.next() orelse return answer(&writer.interface, .bad_request);
        var authorization: ?[]const u8 = null;
        while (lines.next()) |line| {
            const colon = std.mem.findScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(line[0..colon], "proxy-authorization")) authorization = std.mem.trim(u8, line[colon + 1 ..], " ");
        }
        try self.record(target, authorization);
        if (!std.mem.eql(u8, method, "CONNECT")) return answer(&writer.interface, .method_not_allowed);
        if (self.refuse) |status| return answer(&writer.interface, status);
        const colon = std.mem.findScalarLast(u8, target, ':') orelse return answer(&writer.interface, .bad_request);
        const target_port = std.fmt.parseInt(u16, target[colon + 1 ..], 10) catch return answer(&writer.interface, .bad_request);
        const upstream_address = try Io.net.IpAddress.parse("127.0.0.1", target_port);
        const upstream = upstream_address.connect(io, .{ .mode = .stream }) catch return answer(&writer.interface, .bad_gateway);
        defer upstream.close(io);
        try writer.interface.writeAll("HTTP/1.1 200 Connection established\r\n\r\n");
        try writer.interface.flush();
        _ = self.tunnels.fetchAdd(1, .monotonic);
        // A second task copies the bytes of the client to the server, first the bytes after the
        // head. The task reads `reader`, thus this function waits for its end.
        var forward = try io.concurrent(copy, .{ io, &reader.interface, upstream });
        copyStream(io, upstream, client);
        // The server closed its side after its response. The client sends nothing more that
        // the server reads, thus the cancel loses no request.
        _ = forward.cancel(io);
    }

    fn answer(w: *Io.Writer, status: http.Status) !void {
        try w.print("HTTP/1.1 {d} {s}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n", .{ @intFromEnum(status), status.phrase() orelse "" });
        try w.flush();
    }

    fn copyStream(io: Io, from: Io.net.Stream, to: Io.net.Stream) void {
        var buf: [16 * 1024]u8 = undefined;
        var reader = from.reader(io, &buf);
        copy(io, &reader.interface, to);
    }

    /// Copy the bytes of `from` to `to` until the end of `from`. Then end the output of `to`.
    fn copy(io: Io, from: *Io.Reader, to: Io.net.Stream) void {
        var buf: [16 * 1024]u8 = undefined;
        var writer = to.writer(io, &buf);
        while (true) {
            if (from.bufferedLen() == 0) from.fillMore() catch break;
            writer.interface.writeAll(from.buffered()) catch break;
            from.tossBuffered();
            writer.interface.flush() catch break;
        }
        to.shutdown(io, .send) catch {};
    }
};

fn add(ctx: *mcp.RequestContext, args: struct { a: i64, b: i64 }) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

/// An MCP server with the tool `add` on a loopback port, over HTTPS with a certificate of the
/// test CA for `localhost`, or over HTTP.
const Upstream = struct {
    server: mcp.Server,
    chain: tls.CertChain,
    chains: [1]*const tls.CertChain,
    tls_server: tls.Server,
    transport: HttpServer,
    future: Io.Future(void),
    secure: bool,

    fn start(self: *Upstream, secure: bool, allowed_hosts: []const []const u8) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.secure = secure;
        if (secure) {
            self.chain = try tls.CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/chain.crt", "test/fixtures/tls/pem/chain-leaf.key");
            self.chains = .{&self.chain};
            self.tls_server = try tls.Server.init(.{ .chains = &self.chains, .alpn = &.{"http/1.1"} });
        }
        errdefer if (secure) self.chain.deinit();
        self.server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "proxy-test", .version = "1" } });
        errdefer self.server.deinit();
        try self.server.addTool(.{ .name = "add" }, add);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .tls = if (secure) &self.tls_server else null, .allowed_hosts = allowed_hosts });
        errdefer self.transport.deinit();
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
    }

    fn serveIgnoringErrors(t: *HttpServer) void {
        t.serve() catch {};
    }

    fn stop(self: *Upstream) void {
        self.transport.shutdown();
        self.future.await(std.testing.io);
        self.transport.deinit();
        self.server.deinit();
        if (self.secure) self.chain.deinit();
    }

    fn port(self: *const Upstream) u16 {
        return self.transport.bound_port;
    }
};

/// Discover the server and call `add` through a client with `options`.
fn discoverAndAdd(options: HttpClient.Options) !void {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const http_client = try HttpClient.init(io, gpa, options);
    defer http_client.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(http_client.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const disc = try client.discover(arena, .{ .timeout = .fromSeconds(10), .retry = .never });
    try std.testing.expect(disc.capabilities.tools != null);
    const sum = try client.callTool(arena, "add", .{ .a = 20, .b = 22 }, .{ .timeout = .fromSeconds(10), .retry = .never });
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);
}

test "the HTTP client reaches an HTTPS server through a CONNECT proxy with Basic credentials" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var upstream: Upstream = undefined;
    try upstream.start(true, &.{});
    defer upstream.stop();
    var p: TestProxy = undefined;
    try p.start(null);
    defer p.stop();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/mcp", .{upstream.port()});
    var proxy_buf: [96]u8 = undefined;
    // The user "us@er" and the password "p:ss", with a percent sign for each reserved character.
    const proxy_url = p.url(&proxy_buf, "us%40er:p%3Ass");
    try discoverAndAdd(.{
        .url = url,
        .tls = .{ .trust = .{ .ca_set = &set } },
        .proxy = .{ .explicit = .{ .url = proxy_url, .loopback = true } },
    });

    var target_buf: [32]u8 = undefined;
    try std.testing.expect(p.sawTarget(try std.fmt.bufPrint(&target_buf, "localhost:{d}", .{upstream.port()})));
    // The TLS handshake and the requests went through the tunnels: one for each request.
    try std.testing.expect(p.tunnels.load(.monotonic) >= 2);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    // Base64 of "us@er:p:ss".
    try std.testing.expectEqualStrings("Basic dXNAZXI6cDpzcw==", (try p.lastAuthorization(arena_state.allocator())).?);

    // Without `loopback`, the explicit proxy does not get a loopback host.
    const before = p.tunnels.load(.monotonic);
    try discoverAndAdd(.{
        .url = url,
        .tls = .{ .trust = .{ .ca_set = &set } },
        .proxy = .{ .explicit = .{ .url = proxy_url } },
    });
    try std.testing.expectEqual(before, p.tunnels.load(.monotonic));
}

test "the HTTP client takes the proxy from the environment for https and http URLs" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // The `.test` names exist only for the proxy, which connects to 127.0.0.1. Thus a request
    // that does not go through the proxy fails.
    var secure: Upstream = undefined;
    try secure.start(true, &.{"mcp.test"});
    defer secure.stop();
    var plain: Upstream = undefined;
    try plain.start(false, &.{ "plain.test", "127.0.0.1" });
    defer plain.stop();
    var p: TestProxy = undefined;
    try p.start(null);
    defer p.stop();
    var set: tls.CaSet = .init(gpa);
    defer set.deinit();
    try set.addFile(io, "test/fixtures/tls/pem/ca.crt");

    var proxy_buf: [64]u8 = undefined;
    const proxy_url = p.url(&proxy_buf, "");
    var env: std.process.Environ.Map = .init(gpa);
    defer env.deinit();
    try env.put("HTTPS_PROXY", proxy_url);
    try env.put("HTTP_PROXY", proxy_url);
    try env.put("NO_PROXY", "other.test");

    var url_buf: [64]u8 = undefined;
    var target_buf: [32]u8 = undefined;
    // The certificate names `localhost`, thus the client checks it against that name.
    try discoverAndAdd(.{
        .url = try std.fmt.bufPrint(&url_buf, "https://mcp.test:{d}/mcp", .{secure.port()}),
        .tls = .{ .trust = .{ .ca_set = &set }, .server_name = "localhost" },
        .proxy = .{ .environment = &env },
    });
    try std.testing.expect(p.sawTarget(try std.fmt.bufPrint(&target_buf, "mcp.test:{d}", .{secure.port()})));

    // An http URL also goes through a tunnel.
    try discoverAndAdd(.{
        .url = try std.fmt.bufPrint(&url_buf, "http://plain.test:{d}/mcp", .{plain.port()}),
        .proxy = .{ .environment = &env },
    });
    try std.testing.expect(p.sawTarget(try std.fmt.bufPrint(&target_buf, "plain.test:{d}", .{plain.port()})));

    // A loopback host gets a direct connection.
    const before = p.tunnels.load(.monotonic);
    try discoverAndAdd(.{
        .url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/mcp", .{plain.port()}),
        .proxy = .{ .environment = &env },
    });
    try std.testing.expectEqual(before, p.tunnels.load(.monotonic));
}

test "a proxy that refuses the tunnel or that is not there gives a clear error" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var p: TestProxy = undefined;
    try p.start(.proxy_auth_required);
    defer p.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var proxy_buf: [64]u8 = undefined;
    const proxy_url = p.url(&proxy_buf, "");

    // The connection gives `error.ProxyRefused`, and the log has the status.
    const through = try proxy.parseUrl(arena, proxy_url);
    try std.testing.expectError(error.ProxyRefused, http1.Connection.openThrough(io, gpa, through, "mcp.test", 443, null));
    try std.testing.expect(p.sawTarget("mcp.test:443"));
    try std.testing.expect(try p.lastAuthorization(arena) == null);
    try std.testing.expectEqual(0, p.tunnels.load(.monotonic));

    // The client gives `error.TransportFailed`. No byte goes to a server.
    const http_client = try HttpClient.init(io, gpa, .{
        .url = "https://mcp.test:8443/mcp",
        .tls = .{ .trust = .self_signed },
        .proxy = .{ .explicit = .{ .url = proxy_url } },
    });
    defer http_client.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(http_client.transport());
    try std.testing.expectError(error.TransportFailed, client.discover(arena, .{ .retry = .never }));
    try std.testing.expect(p.sawTarget("mcp.test:8443"));

    // A proxy that does not listen: the connection fails, and the log names the proxy.
    var closed_address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var closed = try closed_address.listen(io, .{});
    const closed_port = closed.socket.address.getPort();
    closed.deinit(io);
    try std.testing.expectError(error.ConnectFailed, http1.Connection.openThrough(io, gpa, .{ .host = "127.0.0.1", .port = closed_port }, "mcp.test", 443, null));
}

test "a proxy URL that the client cannot use stops init" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    try std.testing.expectError(error.InvalidProxy, HttpClient.init(io, gpa, .{
        .url = "https://mcp.test/mcp",
        .tls = .{ .trust = .self_signed },
        .proxy = .{ .explicit = .{ .url = "https://proxy.test:3128" } },
    }));
    var env: std.process.Environ.Map = .init(gpa);
    defer env.deinit();
    try env.put("ALL_PROXY", "socks5://proxy.test:1080");
    try std.testing.expectError(error.InvalidProxy, HttpClient.init(io, gpa, .{
        .url = "https://mcp.test/mcp",
        .tls = .{ .trust = .self_signed },
        .proxy = .{ .environment = &env },
    }));
    // The same variable does not matter for a host of NO_PROXY.
    try env.put("NO_PROXY", ".test");
    const direct = try HttpClient.init(io, gpa, .{
        .url = "https://mcp.test/mcp",
        .tls = .{ .trust = .self_signed },
        .proxy = .{ .environment = &env },
    });
    defer direct.deinit();
    try std.testing.expect(direct.route == null);
}
