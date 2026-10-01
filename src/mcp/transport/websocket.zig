//! The WebSocket transport: MCP on connections of RFC 6455. It is a custom transport under the
//! rules of the specification for custom transports. It keeps the JSON-RPC message format, the
//! message patterns and the metadata model of each request.
//!
//! The binding rules:
//!
//! - The client opens a connection with an HTTP/1.1 upgrade request (`GET`) on the path of the
//!   endpoint, `/mcp` by default. The request offers the subprotocol `mcp` in
//!   `Sec-WebSocket-Protocol`. The server refuses a request without it with the status 400.
//!   The server accepts no extension.
//! - Each text message carries exactly one JSON-RPC message in UTF-8. A binary message closes
//!   the connection with the code 1003. An endpoint sends each message in one frame, and it
//!   accepts a message in fragments.
//! - One connection carries many requests at the same time. A response has the id of its
//!   request. The notifications of a request, such as progress, go on the same connection with
//!   the progress token. The events of a listen stream carry the subscription id.
//! - The client cancels a request with `notifications/cancelled`, as on stdio. The server sends
//!   `notifications/cancelled` only when it ends a listen stream.
//! - The server sends no requests. A multi round-trip request is a new request with the
//!   answers, as on the other transports.
//! - Each request carries the protocol version and the client capabilities in `_meta`, as on
//!   every transport. The server reads all metadata from the message. The binding has no
//!   `Mcp-*` headers, because one upgrade request carries many messages. The specification
//!   makes the message the source of truth and the mirror into headers optional.
//! - The server checks the access token one time, at the upgrade. A challenge answers the
//!   upgrade with its HTTP status and its `WWW-Authenticate` headers.
//! - The upgrade is an HTTP request. Thus the resource of the token and the `htu` claim of a
//!   DPoP proof use the `http` or `https` form of the URL. The `htm` claim is `GET`.
//! - When the token expires, the server closes the connection with the code 1008. The client
//!   then connects again with a new token.
//!
//! The close codes of the binding:
//!
//! - 1000: the client closes the connection.
//! - 1001: the server stops, or no frame came for `limits.websocket.idle_timeout`.
//! - 1002: the peer broke a rule of RFC 6455.
//! - 1003: the peer sent a binary message.
//! - 1007: a text message or a close reason is not valid UTF-8.
//! - 1008: the access token of the connection expired.
//! - 1009: a frame or a message is larger than its limit.
//! - 1011: the endpoint has no memory for the message.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const Transport = @import("Transport.zig");
const ws = @import("ws_frame.zig");
const stdio = @import("stdio.zig");
const http_server = @import("http.zig");
const http1 = @import("http1.zig");
const router_mod = @import("router.zig");
const Router = router_mod.Router;
const tls = @import("../../tls/tls.zig");
const resource_server = @import("../auth/resource_server.zig");
const Principal = resource_server.Principal;
const auth_common = @import("../auth/common.zig");
const AuthProvider = auth_common.Provider;
const OAuthClient = @import("../auth/oauth_client.zig").Client;
const dpop = @import("../auth/dpop.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;
const message = @import("../jsonrpc/message.zig");
const types = @import("../protocol/types.zig");
const Limits = @import("../Limits.zig");
const McpServer = @import("../server/Server.zig");
const wake = @import("../util/wake.zig");

const log = std.log.scoped(.mcp_websocket);

/// The frame codec of RFC 6455.
pub const frame = ws;

/// The subprotocol of the binding in `Sec-WebSocket-Protocol`.
pub const subprotocol = "mcp";

// ---------------------------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------------------------

pub const Options = struct {
    /// Address to bind. The default is loopback only.
    address: []const u8 = "127.0.0.1",
    port: u16 = 3001,
    /// The path of the upgrade request.
    path: []const u8 = "/mcp",
    /// Origins that the server accepts in an `Origin` header. Empty means loopback origins
    /// only. A request without `Origin`, for example from a client that is not a browser,
    /// passes this check.
    allowed_origins: []const []const u8 = &.{},
    /// Hosts accepted in the `Host` header. Empty means loopback names plus the bound address.
    allowed_hosts: []const []const u8 = &.{},
    /// Serve `wss` with this TLS 1.3 server. Null serves plain `ws`. With ALPN, the server
    /// accepts only `http/1.1`.
    tls: ?*const tls.Server = null,
    /// Check the access token of each upgrade request, and serve the protected resource
    /// metadata at `/.well-known/oauth-protected-resource` and the path. The `resource` of the
    /// resource server is the `http` or `https` form of the URL, such as `https://host/mcp`
    /// for `wss://host/mcp`.
    auth: ?*const resource_server.ResourceServer = null,
    /// The clock of the token expiry check, in Unix seconds. Null uses the real clock.
    clock: ?*const fn () i64 = null,
};

/// Serves one MCP server on WebSocket connections. Each connection behaves as one stdio peer.
pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    options: Options,
    limits: Limits,
    listener: ?Io.net.Server = null,
    bound_port: u16 = 0,
    group: Io.Group = .init,
    closing: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    connections: std.ArrayList(*Conn) = .empty,
    connections_lock: Io.Mutex = .init,

    pub fn init(io: Io, gpa: Allocator, server: *McpServer, options: Options) Server {
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .limits = server.options.limits,
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener) |*l| l.deinit(self.io);
        self.connections.deinit(self.gpa);
        self.* = undefined;
    }

    /// Bind the listen socket. After this call `bound_port` has the port (useful with port 0).
    pub fn bind(self: *Server) !void {
        var address = try Io.net.IpAddress.parse(self.options.address, self.options.port);
        self.listener = try address.listen(self.io, .{ .reuse_address = self.limits.http.reuse_address });
        self.bound_port = self.listener.?.socket.address.getPort();
    }

    /// Accept connections until a call to `shutdown`. Then close each connection with the
    /// code 1001 and wait for the end of the connections.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        var accept_future = try self.io.concurrent(acceptLoop, .{self});
        self.stop_event.wait(self.io) catch {};
        // On Windows a cancel can miss an accept that waits. The wake connection ends it.
        wake.cancelAcceptLoop(self.io, &accept_future, self.listener.?.socket.address, &self.closing);
        self.server.shutdownSubscriptions(self.io);
        self.wakeAll();
        self.group.await(self.io) catch {};
    }

    /// Stop the accept loop, end the listen streams and close the connections. Another task
    /// can call this function.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .release);
        self.server.shutdownSubscriptions(self.io);
        self.wakeAll();
        self.stop_event.set(self.io);
    }

    /// The number of open connections, with the connections in the handshake.
    pub fn connectionCount(self: *Server) usize {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        return self.connections.items.len;
    }

    fn wakeAll(self: *Server) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items) |c| c.wake.set(self.io);
    }

    fn acceptLoop(self: *Server) void {
        while (!self.closing.load(.acquire)) {
            const stream = self.listener.?.accept(self.io) catch |e| switch (e) {
                error.SocketNotListening, error.Canceled => break,
                else => {
                    log.warn("accept failed: {t}", .{e});
                    continue;
                },
            };
            // The connection of `wake` or a peer that came during the shutdown.
            if (self.closing.load(.acquire)) {
                stream.close(self.io);
                break;
            }
            const conn = self.admit(stream) orelse {
                stream.close(self.io);
                continue;
            };
            self.group.concurrent(self.io, Conn.run, .{conn}) catch {
                self.untrack(conn);
                conn.free();
                stream.close(self.io);
            };
        }
    }

    /// Track a new connection. Return null when the server is full or stops.
    fn admit(self: *Server, stream: Io.net.Stream) ?*Conn {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        if (self.closing.load(.acquire)) return null;
        if (self.connections.items.len >= self.limits.websocket.max_connections) {
            log.warn("refused a connection: {d} connections are open", .{self.connections.items.len});
            return null;
        }
        const conn = Conn.create(self, stream) catch return null;
        self.connections.append(self.gpa, conn) catch {
            conn.free();
            return null;
        };
        return conn;
    }

    fn untrack(self: *Server, conn: *Conn) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.connections.swapRemove(i);
                return;
            }
        }
    }

    fn unixNow(self: *const Server) i64 {
        if (self.options.clock) |f| return f();
        return Io.Clock.Timestamp.now(self.io, .real).raw.toSeconds();
    }
};

/// Why a connection ends.
const EndReason = enum {
    none,
    /// The peer sent a close frame, and the server answered it.
    peer_closed,
    /// The connection ended without a close frame.
    peer_gone,
    /// The peer broke a rule. The server sent a close frame with the code.
    failed,
    /// The upgrade did not succeed. The server sent an HTTP response, or nothing.
    handshake_failed,
    handshake_timeout,
    shutdown,
    idle,
    expired,
};

/// One connection. The connection task supervises the timers, and a reader task reads the
/// handshake and the frames.
const Conn = struct {
    owner: *Server,
    stream: Io.net.Stream,
    arena_state: std.heap.ArenaAllocator,
    in_buf: []u8,
    out_buf: []u8,
    tls_read_buf: []u8,
    tls_write_buf: []u8,
    socket_reader: Io.net.Stream.Reader = undefined,
    socket_writer: Io.net.Stream.Writer = undefined,
    tls_conn: tls.Connection = undefined,
    tls_active: bool = false,
    in: *Io.Reader = undefined,
    out: *Io.Writer = undefined,
    write_lock: Io.Mutex = .init,
    /// Set when this side sent its close frame. The server then sends no more frames.
    close_sent: std.atomic.Value(bool) = .init(false),
    /// Set after a failed write. Guarded by `write_lock`.
    broken: bool = false,
    peer: stdio.Server = undefined,
    peer_ready: bool = false,
    /// The `exp` of the access token of the upgrade, in Unix seconds.
    expires_at: ?i64 = null,
    upgraded: std.atomic.Value(bool) = .init(false),
    /// Set when the reader sent a close frame for an error and waits for the answer.
    lingering: std.atomic.Value(bool) = .init(false),
    reader_done: std.atomic.Value(bool) = .init(false),
    reader_reason: EndReason = .none,
    /// The time of the last frame from the peer, from the awake clock in nanoseconds.
    last_rx: std.atomic.Value(i64) = .init(0),
    /// Wakes the connection task for a new state.
    wake: Io.Event = .unset,

    fn create(owner: *Server, stream: Io.net.Stream) Allocator.Error!*Conn {
        const gpa = owner.gpa;
        const conn = try gpa.create(Conn);
        errdefer gpa.destroy(conn);
        const in_buf = try gpa.alloc(u8, @max(owner.limits.http.max_head_bytes + 4096, tls.Connection.min_input_buffer_len));
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, tls.Connection.min_output_buffer_len);
        errdefer gpa.free(out_buf);
        const secure = owner.options.tls != null;
        const tls_read_buf = try gpa.alloc(u8, if (secure) tls.Connection.min_read_buffer_len else 0);
        errdefer gpa.free(tls_read_buf);
        const tls_write_buf = try gpa.alloc(u8, if (secure) 16 << 10 else 0);
        conn.* = .{
            .owner = owner,
            .stream = stream,
            .arena_state = .init(gpa),
            .in_buf = in_buf,
            .out_buf = out_buf,
            .tls_read_buf = tls_read_buf,
            .tls_write_buf = tls_write_buf,
        };
        return conn;
    }

    /// Free the memory of the connection. The caller closes the stream.
    fn free(conn: *Conn) void {
        const gpa = conn.owner.gpa;
        if (conn.tls_active) conn.tls_conn.deinit();
        gpa.free(conn.tls_write_buf);
        gpa.free(conn.tls_read_buf);
        gpa.free(conn.out_buf);
        gpa.free(conn.in_buf);
        conn.arena_state.deinit();
        gpa.destroy(conn);
    }

    fn run(conn: *Conn) Io.Cancelable!void {
        const self = conn.owner;
        const io = self.io;
        defer {
            self.untrack(conn);
            conn.stream.close(io);
            conn.free();
        }
        conn.last_rx.store(ws.nowNanoseconds(io), .release);
        var reader = io.concurrent(readTask, .{conn}) catch return;
        const reason = conn.supervise();
        conn.finish(reason, &reader);
    }

    /// Watch the timers until the connection ends, and send the pings.
    fn supervise(conn: *Conn) EndReason {
        const self = conn.owner;
        const io = self.io;
        const limits = self.limits.websocket;
        const handshake_ns = nanoseconds(limits.handshake_timeout);
        const ping_ns = nanoseconds(limits.ping_interval);
        const idle_ns = nanoseconds(limits.idle_timeout);
        const started = ws.nowNanoseconds(io);
        var last_ping = started;
        while (true) {
            if (conn.reader_done.load(.acquire)) return conn.reader_reason;
            if (conn.lingering.load(.acquire)) {
                conn.awaitReader(self.limits.shutdown_grace);
                return .failed;
            }
            if (self.closing.load(.acquire)) return .shutdown;
            const now = ws.nowNanoseconds(io);
            var wait: i64 = std.time.ns_per_s;
            if (!conn.upgraded.load(.acquire)) {
                if (handshake_ns > 0) {
                    const left = started +| handshake_ns -| now;
                    if (left <= 0) return .handshake_timeout;
                    wait = @min(wait, left);
                }
            } else {
                const rx = conn.last_rx.load(.acquire);
                if (idle_ns > 0) {
                    const left = rx +| idle_ns -| now;
                    if (left <= 0) return .idle;
                    wait = @min(wait, left);
                }
                if (ping_ns > 0) {
                    const due = @max(rx, last_ping) +| ping_ns;
                    if (now >= due) {
                        conn.sendControl(.ping, "");
                        last_ping = now;
                        wait = @min(wait, ping_ns);
                    } else wait = @min(wait, due - now);
                }
                if (conn.expires_at) |exp| {
                    const left_s = exp -| self.unixNow();
                    if (left_s <= 0) return .expired;
                    wait = @min(wait, left_s *| std.time.ns_per_s);
                }
            }
            conn.wake.waitTimeout(io, .{ .duration = .{ .raw = .fromNanoseconds(@max(wait, 1)), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return .shutdown,
            };
            conn.wake.reset();
        }
    }

    /// End the connection. For a close by the server, the requests end first, so that a
    /// listen stream sends its result before the close frame.
    fn finish(conn: *Conn, reason: EndReason, reader: *Io.Future(void)) void {
        const self = conn.owner;
        const io = self.io;
        const grace = self.limits.shutdown_grace;
        const Close = struct { code: ws.CloseCode, text: []const u8 };
        const close: ?Close = switch (reason) {
            .shutdown => .{ .code = .going_away, .text = McpServer.shutdown_reason },
            .idle => .{ .code = .going_away, .text = "idle timeout" },
            .expired => .{ .code = .policy_violation, .text = "access token expired" },
            else => null,
        };
        if (close) |c| if (conn.upgraded.load(.acquire)) {
            conn.peer.stopAdmission();
            conn.peer.cancelAll(c.text, reason == .shutdown);
            conn.peer.awaitInFlight(grace);
            conn.sendClose(c.code, c.text);
            // RFC 6455 section 7.1.1: wait for the close frame of the peer.
            conn.awaitReader(grace);
        };
        reader.cancel(io);
        if (conn.peer_ready) {
            conn.peer.stopAdmission();
            conn.peer.cancelAll(stdio.Server.connection_closed_reason, false);
            conn.peer.awaitInFlight(grace);
            conn.peer.deinit();
            conn.peer_ready = false;
        }
        if (conn.tls_active) conn.tls_conn.end() catch {};
    }

    /// Wait for the end of the reader task, at most `grace`.
    fn awaitReader(conn: *Conn, grace: Io.Duration) void {
        const io = conn.owner.io;
        const deadline = ws.nowNanoseconds(io) +| nanoseconds(grace);
        while (!conn.reader_done.load(.acquire)) {
            const left = deadline - ws.nowNanoseconds(io);
            if (left <= 0) return;
            conn.wake.waitTimeout(io, .{ .duration = .{ .raw = .fromNanoseconds(left), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return,
            };
            conn.wake.reset();
        }
    }

    fn readTask(conn: *Conn) void {
        const io = conn.owner.io;
        conn.reader_reason = conn.readAll();
        conn.reader_done.store(true, .release);
        conn.wake.set(io);
    }

    fn readAll(conn: *Conn) EndReason {
        const self = conn.owner;
        const io = self.io;
        conn.startStreams() catch return .handshake_failed;
        const principal = conn.handshake() catch return .handshake_failed;
        conn.peer = .initSink(io, self.gpa, self.server, .{ .ptr = conn, .write = sinkWrite });
        conn.peer.kind = .websocket;
        // The rate limits count the IP address of a client without a principal, as on HTTP.
        conn.peer.peer = .{ .address = conn.stream.socket.address };
        conn.peer.context = principal;
        conn.peer.on_close = .cancel_requests;
        conn.peer.when_full = .{ .reject = self.limits.websocket.max_in_flight_requests };
        if (principal) |p| conn.expires_at = p.expires_at;
        conn.peer_ready = true;
        conn.last_rx.store(ws.nowNanoseconds(io), .release);
        conn.upgraded.store(true, .release);
        // The connection task changes from the handshake timer to the ping timer.
        conn.wake.set(io);
        return conn.frameLoop();
    }

    /// Prepare the socket streams, and run the TLS handshake for `wss`.
    fn startStreams(conn: *Conn) !void {
        const self = conn.owner;
        const io = self.io;
        conn.socket_reader = conn.stream.reader(io, conn.in_buf);
        conn.socket_writer = conn.stream.writer(io, conn.out_buf);
        conn.in = &conn.socket_reader.interface;
        conn.out = &conn.socket_writer.interface;
        const tls_server = self.options.tls orelse return;
        conn.tls_conn = try tls_server.accept(conn.in, conn.out, .{
            .io = io,
            .read_buffer = conn.tls_read_buf,
            .write_buffer = conn.tls_write_buf,
            // The close handshake of RFC 6455 ends a connection, not the TLS alert.
            .allow_truncation_attacks = true,
        });
        conn.tls_active = true;
        // The upgrade is an HTTP/1.1 request. A client that negotiated another protocol
        // gets nothing.
        if (conn.tls_conn.alpn()) |alpn| if (!std.mem.eql(u8, alpn, "http/1.1")) return error.WrongProtocol;
        conn.in = &conn.tls_conn.reader;
        conn.out = &conn.tls_conn.writer;
    }

    const HandshakeError = error{ Rejected, ReadFailed, WriteFailed, OutOfMemory };

    /// Read the upgrade request and answer it. Returns the principal of the access token, or
    /// null without authorization. A refused request gets its HTTP response and
    /// `error.Rejected`.
    fn handshake(conn: *Conn) HandshakeError!?*Principal {
        const self = conn.owner;
        const arena = conn.arena_state.allocator();
        var reader: http.Reader = .{
            .in = conn.in,
            .interface = undefined,
            .state = .ready,
            .max_head_len = @min(self.limits.http.max_head_bytes, conn.in.buffer.len),
        };
        const bytes = reader.receiveHead() catch |e| switch (e) {
            error.HttpHeadersOversize => {
                try conn.respond(431, &.{}, "The request head is too large.");
                return error.Rejected;
            },
            else => return error.ReadFailed,
        };
        const parsed = http.Server.Request.Head.parse(bytes) catch {
            try conn.respond(400, &.{}, "The request head is not valid.");
            return error.Rejected;
        };
        const head = try UpgradeHead.read(arena, parsed, bytes);

        // The protected resource metadata lives at the path-inserted well-known location.
        if (self.options.auth) |auth| {
            const prm_path = try std.mem.concat(arena, u8, &.{ "/.well-known/oauth-protected-resource", self.options.path });
            if (std.mem.eql(u8, head.path, prm_path)) {
                if (head.method != .GET) {
                    try conn.respond(405, &.{.{ .name = "allow", .value = "GET" }}, "");
                } else {
                    try conn.respondBody(200, &.{}, "application/json", try auth.metadataJson(arena));
                }
                return error.Rejected;
            }
        }
        if (!std.mem.eql(u8, head.path, self.options.path)) {
            try conn.respond(404, &.{}, "Not Found");
            return error.Rejected;
        }
        if (head.method != .GET) {
            try conn.respond(405, &.{.{ .name = "allow", .value = "GET" }}, "The endpoint accepts WebSocket upgrades only.");
            return error.Rejected;
        }
        if (head.version != .@"HTTP/1.1") {
            try conn.respond(400, &.{}, "The upgrade needs HTTP/1.1.");
            return error.Rejected;
        }
        // DNS rebinding protection, as on the HTTP server.
        if (head.origin) |origin| if (!http_server.originInList(self.options.allowed_origins, origin)) {
            try conn.respond(403, &.{}, "Origin not allowed");
            return error.Rejected;
        };
        if (head.host_count != 1) {
            try conn.respond(400, &.{}, "The request must have one Host header.");
            return error.Rejected;
        }
        if (!http_server.hostInList(self.options.allowed_hosts, self.options.address, head.host.?)) {
            try conn.respond(403, &.{}, "Host not allowed");
            return error.Rejected;
        }
        // RFC 6455 section 4.2.1 and 4.2.2.
        if (!ws.headerHasToken(head.upgrade, "websocket")) {
            try conn.respond(426, &upgrade_required_headers, "The endpoint accepts WebSocket upgrades only.");
            return error.Rejected;
        }
        if (!ws.headerHasToken(head.connection, "upgrade")) {
            try conn.respond(400, &.{}, "The Connection header must have the token Upgrade.");
            return error.Rejected;
        }
        if (!std.mem.eql(u8, std.mem.trim(u8, head.ws_version, " \t"), "13")) {
            try conn.respond(426, &upgrade_required_headers, "The server supports WebSocket version 13 only.");
            return error.Rejected;
        }
        const key = head.key orelse "";
        if (head.key_count != 1 or !ws.validKey(key)) {
            try conn.respond(400, &.{}, "The Sec-WebSocket-Key header is not valid.");
            return error.Rejected;
        }
        if (!ws.headerHasToken(head.protocols, subprotocol)) {
            try conn.respond(400, &.{}, "The upgrade must offer the subprotocol mcp.");
            return error.Rejected;
        }
        // Authorization comes before the upgrade.
        var principal: ?*Principal = null;
        if (self.options.auth) |auth| {
            var decision = try auth.authorizeRequest(arena, .{ .authorization = head.authorization, .dpop = head.dpop, .method = "GET" });
            // The server closes a connection when its token expires. Thus it also refuses a
            // token that a verifier with a clock skew accepts after its expiry.
            if (decision == .ok) if (decision.ok.expires_at) |exp| if (exp <= self.unixNow()) {
                const dpop_scheme = std.ascii.startsWithIgnoreCase(head.authorization orelse "", "dpop ");
                decision = .{ .challenge = try auth.invalidToken(arena, dpop_scheme, "The access token expired") };
            };
            switch (decision) {
                .ok => |p| {
                    const owned = try arena.create(Principal);
                    owned.* = p;
                    principal = owned;
                },
                .challenge => |c| {
                    var buf: [3]http.Header = undefined;
                    try conn.respondBody(c.status, c.headers(&buf), "application/json", c.body);
                    return error.Rejected;
                },
            }
        }
        const accept = ws.acceptKey(key);
        const w = conn.out;
        w.print("HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {s}\r\nsec-websocket-protocol: {s}\r\n\r\n", .{ &accept, subprotocol }) catch return error.WriteFailed;
        w.flush() catch return error.WriteFailed;
        return principal;
    }

    /// The headers of a 426 response: the protocol and its version (RFC 9110 section 15.5.22
    /// and RFC 6455 section 4.4).
    const upgrade_required_headers = [_]http.Header{
        .{ .name = "upgrade", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };

    fn respond(conn: *Conn, status: u16, headers: []const http.Header, body: []const u8) error{WriteFailed}!void {
        return conn.respondBody(status, headers, "text/plain; charset=utf-8", body);
    }

    /// Write one HTTP response and end the connection after it.
    fn respondBody(conn: *Conn, status: u16, headers: []const http.Header, content_type: []const u8, body: []const u8) error{WriteFailed}!void {
        const w = conn.out;
        const phrase = (@as(http.Status, @enumFromInt(status))).phrase() orelse "";
        w.print("HTTP/1.1 {d} {s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: close\r\n", .{ status, phrase, content_type, body.len }) catch return error.WriteFailed;
        for (headers) |h| w.print("{s}: {s}\r\n", .{ h.name, h.value }) catch return error.WriteFailed;
        w.writeAll("\r\n") catch return error.WriteFailed;
        w.writeAll(body) catch return error.WriteFailed;
        w.flush() catch return error.WriteFailed;
    }

    /// Read frames until the connection ends. Each text message goes to the stdio engine.
    fn frameLoop(conn: *Conn) EndReason {
        const self = conn.owner;
        const limits = self.limits.websocket;
        var reader: ws.Reader = .{
            .in = conn.in,
            .gpa = self.gpa,
            .role = .server,
            .max_frame_bytes = limits.max_frame_bytes,
            .max_message_bytes = limits.max_message_bytes,
            .activity = &conn.last_rx,
            .io = self.io,
        };
        defer reader.deinit();
        while (true) {
            const event = reader.next() catch |e| {
                const code = ws.closeCodeFor(e) orelse return .peer_gone;
                log.debug("closed a connection with code {d}: {t}", .{ @intFromEnum(code), e });
                conn.sendClose(code, closeReason(e));
                // Read until the answer of the peer, so that the end of the TCP connection
                // does not discard the close frame. The connection task limits the time.
                conn.lingering.store(true, .release);
                conn.wake.set(self.io);
                ws.lingerUntilClose(conn.in, reader.unread);
                return .failed;
            };
            switch (event) {
                // RFC 6455 section 5.5.1: after its close frame, the server discards data.
                .text => |text| if (!conn.close_sent.load(.acquire)) {
                    conn.peer.receive(text) catch {
                        conn.sendClose(.internal_error, "out of memory");
                        return .failed;
                    };
                },
                .ping => |payload| conn.sendControl(.pong, payload),
                .pong => {},
                .close => |c| {
                    conn.answerClose(c.code);
                    return .peer_closed;
                },
            }
        }
    }

    /// The sink of the stdio engine: one text frame for each message.
    fn sinkWrite(ptr: *anyopaque, io: Io, text: []const u8) Transport.SendError!void {
        const conn: *Conn = @ptrCast(@alignCast(ptr));
        // A text message must be UTF-8. A frame that is not stays on this side.
        if (!std.unicode.utf8ValidateSlice(text)) {
            log.warn("dropped an outgoing message that is not valid UTF-8", .{});
            return error.WriteFailed;
        }
        conn.write_lock.lockUncancelable(io);
        defer conn.write_lock.unlock(io);
        if (conn.close_sent.load(.acquire) or conn.broken) return error.Closed;
        conn.writeLocked(.text, text) catch return error.WriteFailed;
    }

    fn writeLocked(conn: *Conn, opcode: ws.Opcode, payload: []const u8) error{WriteFailed}!void {
        ws.writeFrame(conn.out, true, opcode, payload, null) catch {
            conn.broken = true;
            return error.WriteFailed;
        };
        conn.out.flush() catch {
            conn.broken = true;
            return error.WriteFailed;
        };
    }

    fn sendControl(conn: *Conn, opcode: ws.Opcode, payload: []const u8) void {
        const io = conn.owner.io;
        conn.write_lock.lockUncancelable(io);
        defer conn.write_lock.unlock(io);
        if (conn.close_sent.load(.acquire) or conn.broken) return;
        conn.writeLocked(opcode, payload) catch {};
    }

    fn sendClose(conn: *Conn, code: ws.CloseCode, reason: []const u8) void {
        var buf: [ws.max_control_payload]u8 = undefined;
        conn.sendClosePayload(ws.closePayload(&buf, code, reason));
    }

    /// Answer the close frame of the peer with the same code, or with an empty payload.
    fn answerClose(conn: *Conn, code: ?u16) void {
        var buf: [ws.max_control_payload]u8 = undefined;
        const payload: []const u8 = if (code) |c| ws.closePayload(&buf, @enumFromInt(c), "") else "";
        conn.sendClosePayload(payload);
    }

    fn sendClosePayload(conn: *Conn, payload: []const u8) void {
        const io = conn.owner.io;
        conn.write_lock.lockUncancelable(io);
        defer conn.write_lock.unlock(io);
        if (conn.close_sent.load(.acquire) or conn.broken) return;
        conn.close_sent.store(true, .release);
        conn.writeLocked(.close, payload) catch {};
    }
};

/// The parts of the upgrade request that the server checks, copied out of the read buffer.
const UpgradeHead = struct {
    method: http.Method,
    version: http.Version,
    path: []const u8,
    host: ?[]const u8 = null,
    host_count: u8 = 0,
    origin: ?[]const u8 = null,
    /// The values of the `Upgrade` headers, joined with commas.
    upgrade: []const u8 = "",
    /// The values of the `Connection` headers, joined with commas.
    connection: []const u8 = "",
    key: ?[]const u8 = null,
    key_count: u8 = 0,
    ws_version: []const u8 = "",
    /// The values of the `Sec-WebSocket-Protocol` headers, joined with commas.
    protocols: []const u8 = "",
    authorization: ?[]const u8 = null,
    /// The values of the `DPoP` headers.
    dpop: []const []const u8 = &.{},

    fn read(arena: Allocator, parsed: http.Server.Request.Head, bytes: []const u8) Allocator.Error!UpgradeHead {
        const target = parsed.target;
        const path_end = std.mem.findScalar(u8, target, '?') orelse target.len;
        var head: UpgradeHead = .{ .method = parsed.method, .version = parsed.version, .path = try arena.dupe(u8, target[0..path_end]) };
        var proofs: std.ArrayList([]const u8) = .empty;
        var it = http.HeaderIterator.init(bytes);
        while (it.next()) |h| {
            const value = try arena.dupe(u8, h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "host")) {
                head.host = value;
                head.host_count +|= 1;
            } else if (std.ascii.eqlIgnoreCase(h.name, "origin")) {
                head.origin = value;
            } else if (std.ascii.eqlIgnoreCase(h.name, "upgrade")) {
                head.upgrade = try join(arena, head.upgrade, value);
            } else if (std.ascii.eqlIgnoreCase(h.name, "connection")) {
                head.connection = try join(arena, head.connection, value);
            } else if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-key")) {
                head.key = value;
                head.key_count +|= 1;
            } else if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-version")) {
                head.ws_version = value;
            } else if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-protocol")) {
                head.protocols = try join(arena, head.protocols, value);
            } else if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
                head.authorization = value;
            } else if (std.ascii.eqlIgnoreCase(h.name, dpop.header_name)) {
                try proofs.append(arena, value);
            }
        }
        head.dpop = proofs.items;
        return head;
    }

    fn join(arena: Allocator, a: []const u8, b: []const u8) Allocator.Error![]const u8 {
        if (a.len == 0) return b;
        return std.mem.concat(arena, u8, &.{ a, ", ", b });
    }
};

/// The reason text of the close frame that answers a read error.
fn closeReason(err: ws.ReadError) []const u8 {
    return switch (err) {
        error.ProtocolError => "protocol error",
        error.UnsupportedData => "binary messages are not part of the binding",
        error.InvalidPayload => "invalid UTF-8",
        error.MessageTooBig => "message too big",
        error.OutOfMemory => "out of memory",
        error.EndOfStream, error.ReadFailed => "",
    };
}

fn nanoseconds(d: Io.Duration) i64 {
    if (d.nanoseconds <= 0) return 0;
    return @intCast(@min(d.nanoseconds, std.math.maxInt(i64)));
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

/// The host, port and path of a `ws` or `wss` URL, and its `http` or `https` form.
pub const Target = struct {
    host: []const u8,
    port: u16,
    secure: bool,
    /// The path and the query of the upgrade request.
    path: []const u8,
    /// The value of the `Host` header.
    host_header: []const u8,
    /// The `http` or `https` form of the URL. The authorization uses it for the DPoP proofs,
    /// the challenges and the discovery of the metadata.
    http_url: []const u8,

    /// Parse a `ws` or `wss` URL. A URL with a fragment is not valid (RFC 6455 section 3).
    pub fn parse(arena: Allocator, url: []const u8) error{ OutOfMemory, InvalidUrl }!Target {
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        const secure = std.ascii.eqlIgnoreCase(uri.scheme, "wss");
        if (!secure and !std.ascii.eqlIgnoreCase(uri.scheme, "ws")) return error.InvalidUrl;
        if (uri.fragment != null) return error.InvalidUrl;
        const http_url = try std.mem.concat(arena, u8, &.{ if (secure) "https" else "http", url[uri.scheme.len..] });
        const t = try http1.Target.parse(arena, http_url);
        return .{ .host = t.host, .port = t.port, .secure = secure, .path = t.path, .host_header = t.host_header, .http_url = http_url };
    }
};

pub const ClientOptions = struct {
    /// A `ws` or `wss` URL, such as `ws://127.0.0.1:3001/mcp`.
    url: []const u8,
    /// Headers added to each upgrade request, for example `authorization`.
    extra_headers: []const http.Header = &.{},
    /// The `Origin` header of the upgrade request. Null sends no `Origin`.
    origin: ?[]const u8 = null,
    /// Answers 401 and 403 challenges at the upgrade with OAuth 2.1. Null sends no credentials.
    auth: ?*OAuthClient = null,
    /// Answers challenges with another flow, for example `ClientCredentials`. It has priority
    /// over `auth`.
    auth_provider: ?AuthProvider = null,
    /// The trust policy and identity for `wss` URLs. Null uses the system trust store.
    tls: ?http1.TlsSetup = null,
    /// The client obeys `limits.websocket` and `limits.shutdown_grace`.
    limits: Limits = .{},
    /// How often a request that waits checks for cancellation and its deadline.
    poll_interval: Io.Duration = .fromMilliseconds(50),
    /// Receives notifications that belong to no request in flight.
    on_notification: ?router_mod.NotificationFn = null,
    userdata: ?*anyopaque = null,
};

/// Connects to a WebSocket server and speaks MCP on one connection. Concurrent requests share
/// the connection. A reader task routes the messages to the requests in flight. When the
/// connection is gone, the next request opens a new one.
pub const Client = struct {
    io: Io,
    gpa: Allocator,
    options: ClientOptions,
    /// Owns the parts of `target`.
    arena_state: std.heap.ArenaAllocator,
    target: Target,
    /// The system trust store, loaded for `wss` URLs without an explicit `tls` option.
    system_bundle: ?std.crypto.Certificate.Bundle = null,
    router: Router,
    /// Guards `link` and the reference counts of the links.
    lock: Io.Mutex = .init,
    /// Lets one task at a time open a connection.
    connect_lock: Io.Mutex = .init,
    link: ?*Link = null,
    next_generation: u32 = 1,
    /// The generation of the open connection, or 0 when no connection is open.
    live: std.atomic.Value(u32) = .init(0),
    closed: std.atomic.Value(bool) = .init(false),
    /// The HTTP status of the last upgrade that the server refused, or 0.
    last_status: std.atomic.Value(u16) = .init(0),

    pub const InitError = error{ OutOfMemory, InvalidUrl, TrustStoreUnavailable };

    pub const ConnectError = error{
        OutOfMemory,
        /// `close` ended the client.
        Closed,
        ConnectFailed,
        TlsFailed,
        /// The response to the upgrade broke a rule of RFC 6455 or of the binding.
        HandshakeFailed,
        /// The server refused the upgrade. `last_status` has the HTTP status.
        HttpStatus,
        EntropyUnavailable,
    } || Io.Cancelable;

    /// Make a client. The first request opens the connection.
    pub fn init(io: Io, gpa: Allocator, options: ClientOptions) InitError!*Client {
        const self = try gpa.create(Client);
        errdefer gpa.destroy(self);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .options = options,
            .arena_state = .init(gpa),
            .target = undefined,
            .router = .init(io, gpa),
        };
        errdefer self.arena_state.deinit();
        self.target = try Target.parse(self.arena_state.allocator(), options.url);
        if (self.target.secure and options.tls == null) {
            var bundle: std.crypto.Certificate.Bundle = .empty;
            errdefer bundle.deinit(gpa);
            bundle.rescan(gpa, io, Io.Clock.real.now(io)) catch return error.TrustStoreUnavailable;
            self.system_bundle = bundle;
        }
        return self;
    }

    /// Close the connection and free the client.
    pub fn deinit(self: *Client) void {
        self.close();
        if (self.system_bundle) |*b| b.deinit(self.gpa);
        self.router.deinit();
        self.arena_state.deinit();
        self.gpa.destroy(self);
    }

    pub fn transport(self: *Client) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Open the connection now. Without this call, the first request opens it.
    pub fn connect(self: *Client) ConnectError!void {
        _ = try self.ensureLink();
    }

    /// True when a connection is open.
    pub fn isConnected(self: *const Client) bool {
        return self.live.load(.acquire) != 0;
    }

    /// Send a close frame with the code 1000 and wait at most `limits.shutdown_grace` for the
    /// server to close the connection. After this call, each request fails with
    /// `error.Closed`.
    pub fn close(self: *Client) void {
        const io = self.io;
        self.closed.store(true, .release);
        self.connect_lock.lockUncancelable(io);
        defer self.connect_lock.unlock(io);
        if (self.detach()) |old| {
            if (!old.dead.load(.acquire)) {
                old.sendClose(.normal, "");
                // RFC 6455 section 7.1.1: the server closes the TCP connection first.
                old.waitReader(self.options.limits.shutdown_grace);
            }
            self.teardown(old);
        }
        self.router.wakeAll();
    }

    /// Close the connection without a close frame, as after a network failure. The next
    /// request opens a new connection. Tests use it.
    pub fn dropConnection(self: *Client) void {
        const io = self.io;
        self.connect_lock.lockUncancelable(io);
        defer self.connect_lock.unlock(io);
        if (self.detach()) |old| self.teardown(old);
        self.router.wakeAll();
    }

    const vtable: Transport.ClientTransport.VTable = .{
        .kind = .websocket,
        .exchange = exchange,
        .notify = notify,
        .credential = credential,
    };

    /// The bearer token of the auth provider, else the `authorization` header of
    /// `extra_headers`, else null.
    fn credential(ptr: *anyopaque, arena: Allocator) Allocator.Error!?[]const u8 {
        const self: *Client = @ptrCast(@alignCast(ptr));
        if (self.authProvider()) |auth| if (auth.token(arena)) |token| return token;
        for (self.options.extra_headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "authorization")) return h.value;
        return null;
    }

    fn authProvider(self: *Client) ?AuthProvider {
        if (self.options.auth_provider) |p| return p;
        if (self.options.auth) |a| return a.provider();
        return null;
    }

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        // A text message must be UTF-8. The server closes the connection for one that is not.
        if (!std.unicode.utf8ValidateSlice(ex.frame)) return error.InvalidRequest;
        const gen = try self.linkFor(io, ex);
        var pending: Router.Pending = .{ .id = ex.id, .generation = gen };
        defer pending.deinit(self.gpa);
        try self.router.register(&pending);
        defer self.router.unregister(&pending);
        self.send(gen, ex.frame) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Canceled => error.Canceled,
            error.Closed => error.Closed,
            error.WriteFailed => error.WriteFailed,
        };
        const deadline: ?Io.Clock.Timestamp = ex.timeout.toTimestamp(io);
        while (true) {
            if (try self.drain(io, &pending, ex)) return;
            if (ex.cancel.isCancelled()) {
                self.sendCancelled(gen, ex.id, ex.cancel.reason);
                return error.Canceled;
            }
            if (deadline) |d| {
                if (Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw.nanoseconds <= 0) {
                    self.sendCancelled(gen, ex.id, "timeout");
                    return error.Timeout;
                }
            }
            if (self.live.load(.acquire) != gen) {
                // A response that arrived before the end of the connection still counts.
                if (try self.drain(io, &pending, ex)) return;
                return error.Closed;
            }
            pending.event.waitTimeout(io, .{ .duration = .{ .raw = self.options.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return error.Canceled,
            };
            pending.event.reset();
        }
    }

    /// Deliver the frames that arrived. True after the response.
    fn drain(self: *Client, io: Io, pending: *Router.Pending, ex: *Transport.Exchange) Transport.ExchangeError!bool {
        while (self.router.takeFrame(pending)) |f| {
            defer self.gpa.free(f);
            const is_response = router_mod.frameIsResponse(f);
            ex.sink.deliver(io, f) catch return error.InvalidFrame;
            if (is_response) return true;
        }
        return false;
    }

    fn notify(ptr: *anyopaque, io: Io, text: []const u8) Transport.SendError!void {
        _ = io;
        const self: *Client = @ptrCast(@alignCast(ptr));
        if (!std.unicode.utf8ValidateSlice(text)) return error.WriteFailed;
        const gen = self.ensureLink() catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Canceled => error.Canceled,
            error.Closed => error.Closed,
            else => error.WriteFailed,
        };
        return self.send(gen, text);
    }

    fn sendCancelled(self: *Client, gen: u32, id: RequestId, reason: ?[]const u8) void {
        var buf: [512]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        var aw: Io.Writer.Allocating = .init(fba.allocator());
        message.writeNotification(&aw.writer, "notifications/cancelled", types.CancelledNotificationParams{ .requestId = id, .reason = reason }) catch return;
        self.send(gen, aw.written()) catch {};
    }

    /// Write one text message on the connection of generation `gen`.
    fn send(self: *Client, gen: u32, text: []const u8) Transport.SendError!void {
        const link = self.acquire(gen) orelse return error.Closed;
        defer self.release(link);
        return link.write(.text, text);
    }

    fn acquire(self: *Client, gen: u32) ?*Link {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const link = self.link orelse return null;
        if (link.generation != gen or link.dead.load(.acquire)) return null;
        _ = link.refs.fetchAdd(1, .acq_rel);
        return link;
    }

    fn release(self: *Client, link: *Link) void {
        _ = self;
        _ = link.refs.fetchSub(1, .acq_rel);
    }

    /// Take the link out of the client. The caller tears it down.
    fn detach(self: *Client) ?*Link {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const link = self.link orelse return null;
        self.link = null;
        self.live.store(0, .release);
        return link;
    }

    /// Stop the tasks of a detached link, close its connection and free it.
    fn teardown(self: *Client, link: *Link) void {
        const io = self.io;
        while (link.refs.load(.acquire) != 0) io.sleep(.fromMilliseconds(1), .awake) catch {};
        link.markDead();
        if (link.reader_future) |*f| f.cancel(io);
        link.keepalive_wake.set(io);
        if (link.keepalive_future) |*f| f.cancel(io);
        link.conn.close();
        self.gpa.destroy(link);
    }

    const ConnectTask = struct {
        client: *Client,
        result: ConnectError!u32 = error.Closed,
        done: Io.Event = .unset,

        fn run(t: *ConnectTask) void {
            t.result = t.client.ensureLink();
            t.done.set(t.client.io);
        }
    };

    /// The generation of an open connection. A new connection opens in a task, so that the
    /// cancellation and the deadline of the request can stop it.
    fn linkFor(self: *Client, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!u32 {
        const live = self.live.load(.acquire);
        if (live != 0) return live;
        var task: ConnectTask = .{ .client = self };
        var future = io.concurrent(ConnectTask.run, .{&task}) catch return self.mapConnect(self.ensureLink(), ex);
        const deadline = ex.timeout.toTimestamp(io);
        while (!task.done.isSet()) {
            task.done.waitTimeout(io, .{ .duration = .{ .raw = self.options.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => {
                    future.cancel(io);
                    return error.Canceled;
                },
            };
            if (task.done.isSet()) break;
            if (ex.cancel.isCancelled()) {
                future.cancel(io);
                return error.Canceled;
            }
            if (deadline) |d| if (Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw.nanoseconds <= 0) {
                future.cancel(io);
                return error.Timeout;
            };
        }
        future.await(io);
        return self.mapConnect(task.result, ex);
    }

    fn mapConnect(self: *Client, result: ConnectError!u32, ex: *Transport.Exchange) Transport.ExchangeError!u32 {
        return result catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Canceled => error.Canceled,
            error.Closed => error.Closed,
            error.HttpStatus => {
                ex.http_status = self.last_status.load(.acquire);
                return error.HttpStatus;
            },
            error.ConnectFailed, error.TlsFailed, error.HandshakeFailed, error.EntropyUnavailable => error.WriteFailed,
        };
    }

    /// Return the generation of the open connection. Open a new one when it is gone.
    fn ensureLink(self: *Client) ConnectError!u32 {
        const io = self.io;
        if (self.closed.load(.acquire)) return error.Closed;
        const live = self.live.load(.acquire);
        if (live != 0) return live;
        try self.connect_lock.lock(io);
        defer self.connect_lock.unlock(io);
        if (self.closed.load(.acquire)) return error.Closed;
        const again = self.live.load(.acquire);
        if (again != 0) return again;
        if (self.detach()) |old| self.teardown(old);
        const link = try self.openLink();
        self.lock.lockUncancelable(io);
        self.link = link;
        self.live.store(link.generation, .release);
        self.lock.unlock(io);
        // The tasks start after the link is public, so that the end of the reader always
        // clears `live`.
        link.reader_future = io.concurrent(Link.readerLoop, .{link}) catch {
            link.markDead();
            return error.ConnectFailed;
        };
        link.keepalive_future = io.concurrent(Link.keepaliveLoop, .{link}) catch null;
        return link.generation;
    }

    const Challenge = struct {
        status: u16,
        www_authenticate: ?[]const u8,
        dpop_nonce: ?[]const u8,
    };

    const Upgrade = union(enum) {
        link: *Link,
        challenge: Challenge,
    };

    /// The largest number of new proofs with a new nonce for one connection.
    const max_nonce_retries = 2;

    /// Open a connection. Answer authorization challenges until the attempt limit of the
    /// provider.
    fn openLink(self: *Client) ConnectError!*Link {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var attempt: u8 = 0;
        var nonce_retries: u8 = 0;
        while (true) {
            const challenge = switch (try self.upgrade(arena)) {
                .link => |l| return l,
                .challenge => |c| c,
            };
            const auth = self.authProvider() orelse {
                self.last_status.store(challenge.status, .release);
                return error.HttpStatus;
            };
            // RFC 9449 section 9: the server wants a proof with its nonce. The token is good,
            // so send the upgrade again with a new proof and do not get a new token.
            if (challenge.dpop_nonce != null and auth.acceptsDpopNonce() and nonce_retries < max_nonce_retries) {
                const parsed = try auth_common.parseChallenge(arena, challenge.www_authenticate orelse "");
                if (parsed.wantsDpopNonce()) {
                    nonce_retries += 1;
                    continue;
                }
            }
            attempt +|= 1;
            auth.handleChallenge(arena, self.target.http_url, challenge.status, challenge.www_authenticate, attempt) catch |e| {
                log.warn("the authorization provider failed for status {d}: {t}", .{ challenge.status, e });
                self.last_status.store(challenge.status, .release);
                return error.HttpStatus;
            };
        }
    }

    /// One upgrade request on a new connection.
    fn upgrade(self: *Client, arena: Allocator) ConnectError!Upgrade {
        const io = self.io;
        const secure: ?http1.TlsSetup = if (!self.target.secure) null else self.options.tls orelse .{ .trust = .{ .bundle = &self.system_bundle.? } };
        const conn = http1.Connection.open(io, self.gpa, self.target.host, self.target.port, secure) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Canceled => error.Canceled,
            error.TlsFailed => {
                log.warn("TLS handshake with {s} failed", .{self.target.host});
                return error.TlsFailed;
            },
            error.ConnectFailed => error.ConnectFailed,
        };
        var keep = false;
        defer if (!keep) conn.close();
        if (conn.alpn()) |p| if (!std.mem.eql(u8, p, "http/1.1")) return error.HandshakeFailed;
        const key = try ws.newKey(io);
        var headers: std.ArrayList(http1.Header) = .empty;
        if (self.options.origin) |o| try headers.append(arena, .{ .name = "origin", .value = o });
        if (self.authProvider()) |auth| if (auth.credentials(arena, "GET", self.target.http_url)) |c| {
            try headers.append(arena, .{ .name = "authorization", .value = try c.authorization(arena) });
            if (c.proof) |p| try headers.append(arena, .{ .name = dpop.header_name, .value = p });
        };
        try headers.appendSlice(arena, self.options.extra_headers);
        // A token or a header value with CR or LF must not add a header.
        http1.checkHead("GET", self.target.path, self.target.host_header, headers.items) catch return error.ConnectFailed;
        const w = conn.writer;
        w.print("GET {s} HTTP/1.1\r\nhost: {s}\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: {s}\r\nsec-websocket-version: 13\r\nsec-websocket-protocol: {s}\r\n", .{ self.target.path, self.target.host_header, &key, subprotocol }) catch return error.ConnectFailed;
        for (headers.items) |h| w.print("{s}: {s}\r\n", .{ h.name, h.value }) catch return error.ConnectFailed;
        w.writeAll("\r\n") catch return error.ConnectFailed;
        conn.flush() catch return error.ConnectFailed;

        const response = conn.receiveHead() catch return error.HandshakeFailed;
        const status: u16 = @intFromEnum(response.head.status);
        var nonce: ?[]const u8 = null;
        var www: ?[]const u8 = null;
        var upgrade_value: []const u8 = "";
        var connection_value: []const u8 = "";
        var accept: ?[]const u8 = null;
        var protocol: ?[]const u8 = null;
        var protocol_count: u8 = 0;
        var extensions = false;
        var it = response.head.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, dpop.nonce_header_name)) nonce = try arena.dupe(u8, h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) {
                www = if (www) |prev| try std.mem.concat(arena, u8, &.{ prev, ", ", h.value }) else try arena.dupe(u8, h.value);
            }
            if (std.ascii.eqlIgnoreCase(h.name, "upgrade")) upgrade_value = try UpgradeHead.join(arena, upgrade_value, try arena.dupe(u8, h.value));
            if (std.ascii.eqlIgnoreCase(h.name, "connection")) connection_value = try UpgradeHead.join(arena, connection_value, try arena.dupe(u8, h.value));
            if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-accept")) accept = try arena.dupe(u8, h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-protocol")) {
                protocol = try arena.dupe(u8, h.value);
                protocol_count +|= 1;
            }
            if (std.ascii.eqlIgnoreCase(h.name, "sec-websocket-extensions")) extensions = true;
        }
        // RFC 9449 section 8.2 and 9: a server can give a new nonce with any response.
        if (nonce) |n| if (self.authProvider()) |auth| auth.rememberDpopNonce(self.target.http_url, n);
        if (status == 401 or status == 403) return .{ .challenge = .{ .status = status, .www_authenticate = www, .dpop_nonce = nonce } };
        if (status != 101) {
            self.last_status.store(status, .release);
            return error.HttpStatus;
        }
        // RFC 6455 section 4.1: the checks of the response of the server.
        const expected = ws.acceptKey(&key);
        const accepted = if (accept) |a| std.mem.eql(u8, std.mem.trim(u8, a, " \t"), &expected) else false;
        const agreed = protocol_count == 1 and std.mem.eql(u8, std.mem.trim(u8, protocol.?, " \t"), subprotocol);
        if (!ws.headerHasToken(upgrade_value, "websocket") or !ws.headerHasToken(connection_value, "upgrade") or !accepted or !agreed or extensions) {
            log.warn("the server at {s} sent an upgrade response that is not valid", .{self.target.host});
            return error.HandshakeFailed;
        }
        const link = try self.gpa.create(Link);
        errdefer self.gpa.destroy(link);
        link.* = .{
            .client = self,
            .conn = conn,
            .generation = self.next_generation,
            .masks = try ws.MaskSource.init(io),
            .last_rx = .init(ws.nowNanoseconds(io)),
        };
        self.next_generation +%= 1;
        if (self.next_generation == 0) self.next_generation = 1;
        keep = true;
        return .{ .link = link };
    }
};

/// One connection of a client.
const Link = struct {
    client: *Client,
    conn: *http1.Connection,
    generation: u32,
    write_lock: Io.Mutex = .init,
    masks: ws.MaskSource,
    /// Set when the client sent its close frame.
    close_sent: std.atomic.Value(bool) = .init(false),
    /// Set after a failed write. Guarded by `write_lock`.
    broken: bool = false,
    /// Set when the connection can carry no more requests.
    dead: std.atomic.Value(bool) = .init(false),
    /// The tasks that write on the link at this moment.
    refs: std.atomic.Value(u32) = .init(0),
    /// The time of the last frame from the server, from the awake clock in nanoseconds.
    last_rx: std.atomic.Value(i64),
    reader_done: std.atomic.Value(bool) = .init(false),
    keepalive_wake: Io.Event = .unset,
    reader_future: ?Io.Future(void) = null,
    keepalive_future: ?Io.Future(void) = null,

    /// Mark the link as gone and wake the requests that wait on it.
    fn markDead(link: *Link) void {
        link.dead.store(true, .release);
        _ = link.client.live.cmpxchgStrong(link.generation, 0, .acq_rel, .acquire);
        link.client.router.wakeAll();
    }

    /// Write one frame with a new mask.
    fn write(link: *Link, opcode: ws.Opcode, payload: []const u8) Transport.SendError!void {
        const io = link.client.io;
        link.write_lock.lockUncancelable(io);
        defer link.write_lock.unlock(io);
        if (link.close_sent.load(.acquire) or link.broken) return error.Closed;
        link.writeLocked(opcode, payload) catch return error.WriteFailed;
    }

    fn writeLocked(link: *Link, opcode: ws.Opcode, payload: []const u8) error{WriteFailed}!void {
        ws.writeFrame(link.conn.writer, true, opcode, payload, link.masks.next()) catch return link.fail();
        link.conn.flush() catch return link.fail();
    }

    fn fail(link: *Link) error{WriteFailed} {
        link.broken = true;
        link.markDead();
        return error.WriteFailed;
    }

    fn sendControl(link: *Link, opcode: ws.Opcode, payload: []const u8) void {
        link.write(opcode, payload) catch {};
    }

    fn sendClose(link: *Link, code: ws.CloseCode, reason: []const u8) void {
        var buf: [ws.max_control_payload]u8 = undefined;
        link.sendClosePayload(ws.closePayload(&buf, code, reason));
    }

    fn answerClose(link: *Link, code: ?u16) void {
        var buf: [ws.max_control_payload]u8 = undefined;
        const payload: []const u8 = if (code) |c| ws.closePayload(&buf, @enumFromInt(c), "") else "";
        link.sendClosePayload(payload);
    }

    fn sendClosePayload(link: *Link, payload: []const u8) void {
        const io = link.client.io;
        link.write_lock.lockUncancelable(io);
        defer link.write_lock.unlock(io);
        if (link.close_sent.load(.acquire) or link.broken) return;
        link.close_sent.store(true, .release);
        link.writeLocked(.close, payload) catch {};
    }

    /// Wait until the reader saw the end of the connection, at most `grace`.
    fn waitReader(link: *Link, grace: Io.Duration) void {
        const io = link.client.io;
        const deadline = ws.nowNanoseconds(io) +| nanoseconds(grace);
        while (!link.reader_done.load(.acquire)) {
            if (ws.nowNanoseconds(io) >= deadline) return;
            io.sleep(.fromMilliseconds(5), .awake) catch return;
        }
    }

    fn readerLoop(link: *Link) void {
        const client = link.client;
        const io = client.io;
        defer {
            link.reader_done.store(true, .release);
            link.markDead();
            link.keepalive_wake.set(io);
        }
        const limits = client.options.limits.websocket;
        var reader: ws.Reader = .{
            .in = link.conn.reader,
            .gpa = client.gpa,
            .role = .client,
            .max_frame_bytes = limits.max_frame_bytes,
            .max_message_bytes = limits.max_message_bytes,
            .activity = &link.last_rx,
            .io = io,
        };
        defer reader.deinit();
        while (true) {
            const event = reader.next() catch |e| {
                if (ws.closeCodeFor(e)) |code| {
                    log.debug("closed the connection with code {d}: {t}", .{ @intFromEnum(code), e });
                    link.sendClose(code, closeReason(e));
                    link.markDead();
                    // Wait for the answer of the server. The teardown limits the time.
                    ws.lingerUntilClose(link.conn.reader, reader.unread);
                }
                return;
            };
            switch (event) {
                .text => |text| if (!link.close_sent.load(.acquire)) {
                    var arena_state: std.heap.ArenaAllocator = .init(client.gpa);
                    defer arena_state.deinit();
                    client.router.deliver(arena_state.allocator(), text, client.options.on_notification, client.options.userdata);
                },
                .ping => |payload| link.sendControl(.pong, payload),
                .pong => {},
                .close => |c| {
                    if (!link.close_sent.load(.acquire)) if (c.code) |code| {
                        log.debug("the server closed the connection with code {d}: {s}", .{ code, c.reason });
                    };
                    link.answerClose(c.code);
                    link.markDead();
                    // RFC 6455 section 7.1.1: the server closes the TCP connection first.
                    _ = link.conn.reader.discardRemaining() catch {};
                    return;
                },
            }
        }
    }

    /// Send pings and close an idle connection, as the server does.
    fn keepaliveLoop(link: *Link) void {
        const client = link.client;
        const io = client.io;
        const limits = client.options.limits.websocket;
        const ping_ns = nanoseconds(limits.ping_interval);
        const idle_ns = nanoseconds(limits.idle_timeout);
        if (ping_ns == 0 and idle_ns == 0) return;
        var last_ping = ws.nowNanoseconds(io);
        while (!link.dead.load(.acquire)) {
            const now = ws.nowNanoseconds(io);
            const rx = link.last_rx.load(.acquire);
            var wait: i64 = std.time.ns_per_s;
            if (idle_ns > 0) {
                const left = rx +| idle_ns -| now;
                if (left <= 0) {
                    link.sendClose(.going_away, "idle timeout");
                    link.markDead();
                    return;
                }
                wait = @min(wait, left);
            }
            if (ping_ns > 0) {
                const due = @max(rx, last_ping) +| ping_ns;
                if (now >= due) {
                    link.sendControl(.ping, "");
                    last_ping = now;
                    wait = @min(wait, ping_ns);
                } else wait = @min(wait, due - now);
            }
            link.keepalive_wake.waitTimeout(io, .{ .duration = .{ .raw = .fromNanoseconds(@max(wait, 1)), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return,
            };
            link.keepalive_wake.reset();
        }
    }
};

test {
    std.testing.refAllDecls(@This());
}

test "ws and wss URLs give the http form for the authorization" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const plain = try Target.parse(arena, "ws://127.0.0.1:3001/mcp?x=1");
    try std.testing.expect(!plain.secure);
    try std.testing.expectEqual(3001, plain.port);
    try std.testing.expectEqualStrings("/mcp?x=1", plain.path);
    try std.testing.expectEqualStrings("127.0.0.1:3001", plain.host_header);
    try std.testing.expectEqualStrings("http://127.0.0.1:3001/mcp?x=1", plain.http_url);
    const secure = try Target.parse(arena, "WSS://mcp.example.com/mcp");
    try std.testing.expect(secure.secure);
    try std.testing.expectEqual(443, secure.port);
    try std.testing.expectEqualStrings("mcp.example.com", secure.host_header);
    try std.testing.expectEqualStrings("https://mcp.example.com/mcp", secure.http_url);
    try std.testing.expectError(error.InvalidUrl, Target.parse(arena, "http://127.0.0.1/mcp"));
    try std.testing.expectError(error.InvalidUrl, Target.parse(arena, "ws://127.0.0.1/mcp#frag"));
}
