//! The Streamable HTTP transport (server side): one `POST` endpoint, JSON or SSE responses,
//! long-lived listen streams, header mirroring, `Origin` and `Host` validation.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;

const Transport = @import("Transport.zig");
const envelope = @import("envelope.zig");
const tls = @import("../../tls/tls.zig");
const resource_server = @import("../auth/resource_server.zig");
const sse = @import("sse.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;
const message = @import("../jsonrpc/message.zig");
const json = @import("../json.zig");
const types = @import("../protocol/types.zig");
const errors = @import("../protocol/errors.zig");
const meta_mod = @import("../protocol/meta.zig");
const version = @import("../protocol/version.zig");
const methods = @import("../protocol/methods.zig");
const Limits = @import("../Limits.zig");
const McpServer = @import("../server/Server.zig");

const log = std.log.scoped(.mcp_http);
const wake = @import("../util/wake.zig");

pub const ResponseMode = enum { auto, sse, json };

pub const Options = struct {
    /// Address to bind. The default is loopback only.
    address: []const u8 = "127.0.0.1",
    port: u16 = 3000,
    /// The MCP endpoint path.
    path: []const u8 = "/mcp",
    response_mode: ResponseMode = .auto,
    /// Origins that the server accepts in an `Origin` header. Empty means loopback only.
    allowed_origins: []const []const u8 = &.{},
    /// Hosts accepted in the `Host` header. Empty means loopback names plus the bound address.
    allowed_hosts: []const []const u8 = &.{},
    /// Send an SSE comment on each listen stream every `limits.http.sse_keepalive`.
    keepalive: bool = true,
    /// Serve HTTPS with this TLS 1.3 server. Null serves plaintext HTTP.
    tls: ?*const tls.Server = null,
    /// Require a bearer token on the endpoint and serve the protected resource metadata.
    auth: ?*const resource_server.ResourceServer = null,
};

pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    options: Options,
    limits: Limits,
    listener: ?Io.net.Server = null,
    bound_port: u16 = 0,
    group: Io.Group = .init,
    permits: Io.Semaphore,
    closing: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    connections: std.ArrayList(*Connection) = .empty,
    connections_lock: Io.Mutex = .init,

    pub fn init(io: Io, gpa: Allocator, server: *McpServer, options: Options) Server {
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .limits = server.options.limits,
            .permits = .{ .permits = server.options.limits.http.max_connections },
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener) |*l| l.deinit(self.io);
        self.connections.deinit(self.gpa);
        self.* = undefined;
    }

    fn track(self: *Server, conn: *Connection) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        self.connections.append(self.gpa, conn) catch {};
    }

    fn untrack(self: *Server, conn: *Connection) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.connections.swapRemove(i);
                return;
            }
        }
    }

    /// Bind the listen socket. After this call `bound_port` has the port (useful with port 0).
    pub fn bind(self: *Server) !void {
        var address = try Io.net.IpAddress.parse(self.options.address, self.options.port);
        self.listener = try address.listen(self.io, .{ .reuse_address = self.limits.http.reuse_address });
        self.bound_port = self.listener.?.socket.address.getPort();
    }

    /// Accept connections until a call to `shutdown`. A cancel also ends `serve`. After a
    /// cancel, the server accepts no more connections.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        var accept_future = try self.io.concurrent(acceptLoop, .{self});
        self.stop_event.wait(self.io) catch {};
        // On Windows a cancel can miss an accept that waits. The wake connection ends it.
        wake.cancelAcceptLoop(self.io, &accept_future, self.listener.?.socket.address, &self.closing);
        self.server.shutdownSubscriptions(self.io);
        self.group.await(self.io) catch {};
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
            self.permits.waitUncancelable(self.io);
            const conn = self.gpa.create(Connection) catch {
                self.permits.post(self.io);
                var s = stream;
                s.close(self.io);
                continue;
            };
            conn.* = .{ .owner = self, .stream = stream };
            self.track(conn);
            self.group.concurrent(self.io, Connection.run, .{conn}) catch {
                self.untrack(conn);
                self.permits.post(self.io);
                var s = stream;
                s.close(self.io);
                self.gpa.destroy(conn);
            };
        }
    }

    /// Accept no more connections and end active streams. Safe to call from another task.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .release);
        self.stop_event.set(self.io);
        self.server.shutdownSubscriptions(self.io);
        // The connection tasks stop the connections that wait for the next request at once,
        // and the busy connections after `limits.shutdown_grace`.
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items) |c| c.wake.set(self.io);
    }

    fn originAllowed(self: *Server, origin: []const u8) bool {
        return originInList(self.options.allowed_origins, origin);
    }

    fn hostAllowed(self: *Server, host: []const u8) bool {
        return hostInList(self.options.allowed_hosts, self.options.address, host);
    }
};

/// The `Origin` check of DNS rebinding protection. True when `origin` is in `allowed`. An
/// empty `allowed` accepts loopback origins only. The WebSocket server uses it too.
pub fn originInList(allowed: []const []const u8, origin: []const u8) bool {
    if (allowed.len > 0) {
        for (allowed) |o| if (std.ascii.eqlIgnoreCase(o, origin)) return true;
        return false;
    }
    return isLoopbackOrigin(origin);
}

/// The `Host` check of DNS rebinding protection. True when the name of `host` is in `allowed`.
/// An empty `allowed` accepts loopback names and `bound_address`. The port does not count.
pub fn hostInList(allowed: []const []const u8, bound_address: []const u8, host: []const u8) bool {
    const name = stripPort(host);
    if (allowed.len > 0) {
        for (allowed) |h| if (std.ascii.eqlIgnoreCase(stripPort(h), name)) return true;
        return false;
    }
    if (isLoopbackName(name)) return true;
    return std.ascii.eqlIgnoreCase(name, bound_address);
}

fn stripPort(host: []const u8) []const u8 {
    if (host.len > 0 and host[0] == '[') {
        const close = std.mem.findScalar(u8, host, ']') orelse return host;
        return host[0 .. close + 1];
    }
    if (std.mem.findScalar(u8, host, ':')) |i| return host[0..i];
    return host;
}

fn isLoopbackName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "localhost") or std.mem.eql(u8, name, "127.0.0.1") or std.mem.eql(u8, name, "[::1]") or std.mem.eql(u8, name, "::1");
}

fn isLoopbackOrigin(origin: []const u8) bool {
    const rest = if (std.mem.startsWith(u8, origin, "http://")) origin[7..] else if (std.mem.startsWith(u8, origin, "https://")) origin[8..] else return false;
    return isLoopbackName(stripPort(rest));
}

/// The awake clock in nanoseconds.
fn nowNanoseconds(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
}

/// A duration in nanoseconds, from 0 to the maximum of `i64`.
fn nanoseconds(d: Io.Duration) i64 {
    if (d.nanoseconds <= 0) return 0;
    return @intCast(@min(d.nanoseconds, std.math.maxInt(i64)));
}

/// The response to a request that did not arrive in its time limit (RFC 9110 section 15.5.9).
const request_timeout_response = "HTTP/1.1 408 Request Timeout\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// One connection. The connection task supervises the time limits. A worker task does the
/// TLS handshake, reads the requests and runs the handlers. On a timeout, the connection
/// task cancels the worker task: on Windows, a shutdown of the socket does not stop a read.
const Connection = struct {
    owner: *Server,
    stream: Io.net.Stream,
    /// The time limit of the read that the worker does now: an awake time in nanoseconds,
    /// `busy`, `unlimited` or `expired`. Only the worker changes a value other than
    /// `expired`. Only the connection task sets `expired`.
    deadline: std.atomic.Value(i64) = .init(busy),
    /// What the worker waits for. Only the worker uses it.
    phase: Phase = .busy,
    worker_done: std.atomic.Value(bool) = .init(false),
    /// Wakes the connection task for a new deadline, the end of the worker or the shutdown.
    wake: Io.Event = .unset,

    const Phase = enum {
        /// The TLS handshake or a request head.
        head,
        /// The first byte of the next request.
        idle,
        /// The rest of a request body.
        body,
        busy,
    };

    /// The worker runs a handler or writes a response. No time limit applies.
    const busy: i64 = 0;
    /// The worker waits for bytes from the client, without a time limit.
    const unlimited: i64 = std.math.maxInt(i64);
    /// The time limit passed, or the server stops. The worker must stop.
    const expired: i64 = -1;

    fn run(conn: *Connection) Io.Cancelable!void {
        const self = conn.owner;
        defer {
            self.untrack(conn);
            conn.stream.close(self.io);
            self.permits.post(self.io);
            self.gpa.destroy(conn);
        }
        var worker = self.io.concurrent(work, .{conn}) catch return;
        conn.supervise(&worker);
    }

    /// Watch the time limit of the worker until the worker ends. Cancel the worker when the
    /// limit passes. At the shutdown, cancel a worker that waits for bytes at once, and a
    /// busy worker after `limits.shutdown_grace`.
    fn supervise(conn: *Connection, worker: *Io.Future(void)) void {
        const self = conn.owner;
        const io = self.io;
        var shutdown_end: ?i64 = null;
        while (!conn.worker_done.load(.acquire)) {
            const now = nowNanoseconds(io);
            var wait: i64 = 60 * std.time.ns_per_s;
            const d = conn.deadline.load(.acquire);
            if (d == expired) break;
            if (self.closing.load(.acquire)) {
                if (d != busy) {
                    if (conn.expire(d)) break;
                    continue;
                }
                const end = shutdown_end orelse now +| nanoseconds(self.limits.shutdown_grace);
                shutdown_end = end;
                if (now >= end) {
                    conn.deadline.store(expired, .release);
                    break;
                }
                wait = @min(wait, end - now);
            } else if (d != busy and d != unlimited) {
                if (now >= d) {
                    if (conn.expire(d)) break;
                    continue;
                }
                wait = @min(wait, d - now);
            }
            conn.wake.waitTimeout(io, .{ .duration = .{ .raw = .fromNanoseconds(@max(wait, 1)), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => {
                    conn.deadline.store(expired, .release);
                    break;
                },
            };
            conn.wake.reset();
        }
        if (conn.deadline.load(.acquire) == expired) worker.cancel(io) else worker.await(io);
    }

    /// Mark the deadline `d` as passed. False when the worker changed the deadline first.
    fn expire(conn: *Connection, d: i64) bool {
        return conn.deadline.cmpxchgStrong(d, expired, .acq_rel, .acquire) == null;
    }

    /// Set the time limit of the next read to `limit` from now. Zero means no limit. False
    /// when the connection expired: the worker must stop.
    fn startTimer(conn: *Connection, phase: Phase, limit: Io.Duration) bool {
        conn.phase = phase;
        const ns = nanoseconds(limit);
        const io = conn.owner.io;
        const value = if (ns == 0) unlimited else @max(nowNanoseconds(io) +| ns, 1);
        if (!conn.setDeadline(value)) return false;
        if (value != unlimited) conn.wake.set(io);
        return true;
    }

    /// As `startTimer`, but keep a time limit that runs already.
    fn continueTimer(conn: *Connection, phase: Phase, limit: Io.Duration) bool {
        const d = conn.deadline.load(.acquire);
        if (d == expired) return false;
        if (d != busy) return true;
        return conn.startTimer(phase, limit);
    }

    /// Remove the time limit while the worker is busy. False when the connection expired.
    fn stopTimer(conn: *Connection) bool {
        conn.phase = .busy;
        return conn.setDeadline(busy);
    }

    fn setDeadline(conn: *Connection, value: i64) bool {
        var cur = conn.deadline.load(.acquire);
        while (cur != expired) {
            cur = conn.deadline.cmpxchgWeak(cur, value, .acq_rel, .acquire) orelse return true;
        }
        return false;
    }

    fn timedOut(conn: *Connection) bool {
        return conn.deadline.load(.acquire) == expired;
    }

    /// Tell the client about a request head or body that did not arrive in time. The server
    /// closes an idle connection without a response (RFC 9112 section 9.6), and sends nothing
    /// at the shutdown.
    fn sendTimeout(conn: *Connection, out: *Io.Writer) void {
        if (conn.phase != .head and conn.phase != .body) return;
        if (conn.owner.closing.load(.acquire)) return;
        out.writeAll(request_timeout_response) catch return;
        out.flush() catch {};
    }

    fn work(conn: *Connection) void {
        const io = conn.owner.io;
        defer {
            conn.worker_done.store(true, .release);
            conn.wake.set(io);
        }
        conn.serve() catch {};
    }

    /// Read and handle requests until the connection ends. The TLS handshake and the head of
    /// the first request obey `limits.http.head_timeout`. The wait for the next request obeys
    /// `limits.http.idle_timeout`, and its head obeys `head_timeout` from its first byte.
    fn serve(conn: *Connection) Io.Cancelable!void {
        const self = conn.owner;
        if (!conn.startTimer(.head, self.limits.http.head_timeout)) return;
        const read_buf = self.gpa.alloc(u8, @max(self.limits.http.max_head_bytes + 4096, tls.Connection.min_input_buffer_len)) catch return;
        defer self.gpa.free(read_buf);
        const write_buf = self.gpa.alloc(u8, tls.Connection.min_output_buffer_len) catch return;
        defer self.gpa.free(write_buf);
        var reader = conn.stream.reader(self.io, read_buf);
        var writer = conn.stream.writer(self.io, write_buf);

        // With TLS, the HTTP server reads and writes plaintext through the TLS connection.
        var tls_conn: tls.Connection = undefined;
        var tls_active = false;
        var tls_read_buf: []u8 = &.{};
        var tls_write_buf: []u8 = &.{};
        defer if (tls_active) {
            tls_conn.end() catch {};
            tls_conn.deinit();
            self.gpa.free(tls_read_buf);
            self.gpa.free(tls_write_buf);
        };
        if (self.options.tls) |tls_server| {
            tls_read_buf = self.gpa.alloc(u8, tls.Connection.min_read_buffer_len) catch return;
            tls_write_buf = self.gpa.alloc(u8, 16 * 1024) catch {
                self.gpa.free(tls_read_buf);
                return;
            };
            tls_conn = tls_server.accept(&reader.interface, &writer.interface, .{
                .io = self.io,
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .allow_truncation_attacks = true,
            }) catch {
                self.gpa.free(tls_read_buf);
                self.gpa.free(tls_write_buf);
                return;
            };
            tls_active = true;
        }
        const in: *Io.Reader = if (tls_active) &tls_conn.reader else &reader.interface;
        const out: *Io.Writer = if (tls_active) &tls_conn.writer else &writer.interface;
        var http_server: http.Server = .init(in, out);
        var first = true;
        while (!self.closing.load(.acquire)) {
            if (!first) {
                // Wait for the first byte of the next request. A time limit that runs already
                // (from the end of the last handler) continues.
                if (!conn.continueTimer(.idle, self.limits.http.idle_timeout)) return;
                _ = in.peekByte() catch return;
                if (!conn.startTimer(.head, self.limits.http.head_timeout)) return;
            }
            first = false;
            var request = http_server.receiveHead() catch |e| switch (e) {
                error.HttpConnectionClosing => return,
                error.HttpHeadersOversize => {
                    out.writeAll("HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                    out.flush() catch {};
                    return;
                },
                else => {
                    if (conn.timedOut()) conn.sendTimeout(out);
                    return;
                },
            };
            if (!conn.stopTimer()) return;
            const keep_alive = handleRequest(conn, &request, &reader) catch |err| switch (err) {
                error.OutOfMemory => false,
                else => false,
            };
            if (conn.timedOut()) {
                conn.sendTimeout(out);
                return;
            }
            if (!keep_alive or !request.head.keep_alive) return;
        }
    }
};

/// Everything the transport needs from the request head, copied before the body is read.
const Head = struct {
    method: http.Method,
    path: []const u8,
    content_type: ?[]const u8 = null,
    accept: ?[]const u8 = null,
    origin: ?[]const u8 = null,
    host: ?[]const u8 = null,
    authorization: ?[]const u8 = null,
    /// The values of the `DPoP` headers.
    dpop: []const []const u8 = &.{},
    content_length: ?u64 = null,
    envelope_headers: envelope.Headers = .{},
};

fn copyHead(arena: Allocator, request: *http.Server.Request) !Head {
    const target = request.head.target;
    const path_end = std.mem.findScalar(u8, target, '?') orelse target.len;
    var head: Head = .{
        .method = request.head.method,
        .path = try arena.dupe(u8, target[0..path_end]),
        .content_length = request.head.content_length,
    };
    var params: std.ArrayList(envelope.Headers.Param) = .empty;
    var proofs: std.ArrayList([]const u8) = .empty;
    var it = request.iterateHeaders();
    while (it.next()) |h| {
        var name_buf: [128]u8 = undefined;
        if (h.name.len > name_buf.len) continue;
        const name = std.ascii.lowerString(&name_buf, h.name);
        const value = try arena.dupe(u8, h.value);
        if (std.mem.eql(u8, name, "content-type")) head.content_type = value;
        if (std.mem.eql(u8, name, "accept")) head.accept = value;
        if (std.mem.eql(u8, name, "origin")) head.origin = value;
        if (std.mem.eql(u8, name, "host")) head.host = value;
        if (std.mem.eql(u8, name, "authorization")) head.authorization = value;
        if (std.mem.eql(u8, name, "dpop")) try proofs.append(arena, value);
        if (std.mem.eql(u8, name, envelope.header_protocol_version)) head.envelope_headers.protocol_version = value;
        if (std.mem.eql(u8, name, envelope.header_method)) head.envelope_headers.method = value;
        if (std.mem.eql(u8, name, envelope.header_name)) head.envelope_headers.name = value;
        if (std.mem.startsWith(u8, name, envelope.header_param_prefix)) {
            try params.append(arena, .{ .name = try arena.dupe(u8, name[envelope.header_param_prefix.len..]), .value = value });
        }
    }
    head.envelope_headers.params = params.items;
    head.dpop = proofs.items;
    return head;
}

fn acceptsBoth(accept: []const u8) bool {
    return std.mem.find(u8, accept, "application/json") != null and std.mem.find(u8, accept, "text/event-stream") != null or std.mem.find(u8, accept, "*/*") != null;
}

const json_headers = [_]http.Header{.{ .name = "content-type", .value = "application/json" }};

fn statusForCode(code: i64) http.Status {
    return switch (code) {
        -32700, -32600, -32602, -32020, -32021, -32022 => .bad_request,
        -32601 => .not_found,
        @intFromEnum(errors.Code.rate_limited) => .too_many_requests,
        else => .ok,
    };
}

/// The value of `Retry-After` for an error with `data.retryAfterMs`: whole seconds, rounded
/// up, at least 1 (RFC 9110 section 10.2.3). Null when the error has no such field.
fn retryAfterSeconds(err: Value) ?u64 {
    const data = err.object.get("data") orelse return null;
    if (data != .object) return null;
    const ms = data.object.get("retryAfterMs") orelse return null;
    if (ms != .integer or ms.integer < 0) return null;
    const ms_u: u64 = @intCast(ms.integer);
    return @max(1, ms_u / std.time.ms_per_s + @intFromBool(ms_u % std.time.ms_per_s != 0));
}

/// Handle one request on a connection. Returns whether the connection can carry one more request.
/// `socket` is the reader of the socket. It detects a disconnect while a handler runs.
fn handleRequest(conn: *Connection, request: *http.Server.Request, socket: *Io.net.Stream.Reader) !bool {
    const self = conn.owner;
    var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const head = try copyHead(arena, request);

    // Router. The protected resource metadata lives at the path-inserted well-known location.
    if (self.options.auth) |auth| {
        const prm_path = try std.mem.concat(arena, u8, &.{ "/.well-known/oauth-protected-resource", self.options.path });
        if (std.mem.eql(u8, head.path, prm_path)) {
            if (head.method != .GET) {
                try request.respond("", .{ .status = .method_not_allowed, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "allow", .value = "GET" }} });
                return true;
            }
            const doc = try auth.metadataJson(arena);
            try request.respond(doc, .{ .status = .ok, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }} });
            return true;
        }
    }
    if (!std.mem.eql(u8, head.path, self.options.path)) {
        try request.respond("Not Found", .{ .status = .not_found, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "content-type", .value = "text/plain" }} });
        return true;
    }
    if (head.method != .POST) {
        try request.respond("", .{ .status = .method_not_allowed, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "allow", .value = "POST" }} });
        return true;
    }
    // Origin and Host validation (DNS rebinding protection).
    if (head.origin) |origin| {
        if (!self.originAllowed(origin)) {
            try respondErrorOptions(request, .forbidden, null, errors.invalidRequest("Origin not allowed"), false);
            return false;
        }
    }
    if (head.host) |host| {
        if (!self.hostAllowed(host)) {
            try respondErrorOptions(request, .forbidden, null, errors.invalidRequest("Host not allowed"), false);
            return false;
        }
    }
    // Authorization comes before any look at the body.
    var principal: ?*resource_server.Principal = null;
    if (self.options.auth) |auth| {
        switch (try auth.authorizeRequest(arena, .{ .authorization = head.authorization, .dpop = head.dpop, .method = @tagName(head.method) })) {
            .ok => |p| {
                const owned = try arena.create(resource_server.Principal);
                owned.* = p;
                principal = owned;
            },
            .challenge => |c| {
                var buf: [3]http.Header = undefined;
                var headers: std.ArrayList(http.Header) = .empty;
                try headers.appendSlice(arena, c.headers(&buf));
                try headers.append(arena, .{ .name = "content-type", .value = "application/json" });
                try request.respond(c.body, .{
                    .status = @enumFromInt(c.status),
                    .keep_alive = request.head.keep_alive,
                    .extra_headers = headers.items,
                });
                return true;
            },
        }
    }
    if (head.content_type) |ct| {
        if (!std.ascii.startsWithIgnoreCase(ct, "application/json")) {
            try request.respond("", .{ .status = .unsupported_media_type, .keep_alive = request.head.keep_alive });
            return true;
        }
    }
    if (self.options.response_mode != .json) {
        if (head.accept) |accept| {
            if (!acceptsBoth(accept)) {
                try request.respond("", .{ .status = .not_acceptable, .keep_alive = request.head.keep_alive });
                return true;
            }
        }
    }
    if (head.content_length) |len| {
        if (len > self.limits.http.max_body_bytes) {
            try request.respond("", .{ .status = .payload_too_large, .keep_alive = false });
            return false;
        }
    }
    // Body. A request without Content-Length and without Transfer-Encoding has an empty
    // body (RFC 9112 section 6.3). Without this, std reads the connection until EOF.
    if (request.head.transfer_encoding == .none and request.head.content_length == null) {
        request.head.content_length = 0;
    }
    // The body obeys `limits.http.idle_timeout` from the end of the head.
    if (!conn.startTimer(.body, self.limits.http.idle_timeout)) return false;
    var body_buf: [4096]u8 = undefined;
    const body_reader = request.readerExpectNone(&body_buf);
    const body = body_reader.allocRemaining(arena, .limited(self.limits.http.max_body_bytes)) catch |e| switch (e) {
        error.StreamTooLong => {
            try request.respond("", .{ .status = .payload_too_large, .keep_alive = false });
            return false;
        },
        error.OutOfMemory => return error.OutOfMemory,
        error.ReadFailed => return false,
    };
    if (!conn.stopTimer()) return false;
    const msg = jsonrpc.Message.parseMaxDepth(arena, body, self.limits.json_max_depth) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Syntax => {
            try respondError(request, .bad_request, null, errors.parseError("Parse error"));
            return true;
        },
        error.Invalid, error.InvalidId => {
            try respondError(request, .bad_request, null, errors.invalidRequest("Invalid Request"));
            return true;
        },
    };
    switch (msg) {
        .notification => {
            try request.respond("", .{ .status = .accepted, .keep_alive = request.head.keep_alive });
            return true;
        },
        .response, .error_response => {
            try respondError(request, .bad_request, null, errors.invalidRequest("Clients must not send responses"));
            return true;
        },
        .request => |req| return handleRpcRequest(conn, request, socket, arena, head, req, principal),
    }
}

fn respondError(request: *http.Server.Request, status: http.Status, id: ?RequestId, err: errors.RpcError) !void {
    try respondErrorOptions(request, status, id, err, true);
}

fn respondErrorOptions(request: *http.Server.Request, status: http.Status, id: ?RequestId, err: errors.RpcError, keep_alive: bool) !void {
    var buf: [2048]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var aw: Io.Writer.Allocating = .init(fba.allocator());
    message.writeErrorResponse(&aw.writer, id, err.toWire()) catch return;
    try request.respond(aw.written(), .{ .status = status, .keep_alive = keep_alive and request.head.keep_alive, .extra_headers = &json_headers });
}

fn handleRpcRequest(conn: *Connection, request: *http.Server.Request, socket: *Io.net.Stream.Reader, arena: Allocator, head: Head, req: jsonrpc.Message.Request, principal: ?*resource_server.Principal) !bool {
    const self = conn.owner;
    // Header presence, mirror validation and version support run before dispatch on HTTP.
    const schema = if (std.mem.eql(u8, req.method, "tools/call")) toolSchema(self, req.params) else null;
    if (try envelope.verify(arena, head.envelope_headers, req.method, req.params, schema)) |rejection| {
        // A legacy client without headers gets a clear version message.
        if (head.envelope_headers.protocol_version == null and std.mem.eql(u8, req.method, "initialize")) {
            const err = try errors.unsupportedProtocolVersion(arena, &version.supported_versions, "unknown");
            try respondError(request, .bad_request, req.id, err);
            return true;
        }
        try respondError(request, .bad_request, req.id, errors.headerMismatch(rejection.message));
        return true;
    }
    if (!std.mem.eql(u8, head.envelope_headers.protocol_version.?, version.version)) {
        const err = try errors.unsupportedProtocolVersion(arena, &version.supported_versions, head.envelope_headers.protocol_version.?);
        try respondError(request, .bad_request, req.id, err);
        return true;
    }

    var token: Transport.CancelToken = .{};
    var exchange: Exchange = .{
        .owner = self,
        .request = request,
        .arena = arena,
        .id = req.id,
        .token = &token,
        .long_lived = std.mem.eql(u8, req.method, "subscriptions/listen"),
        .force_sse = self.options.response_mode == .sse,
    };
    // A disconnect of the client cancels the request, also while the handler does not write.
    var watch: Watch = .{ .socket = socket, .token = &token, .id = req.id };
    var watcher: ?Io.Future(void) = self.io.concurrent(Watch.run, .{ &watch, self.io }) catch null;
    self.server.handle(self.io, .{
        .kind = .streamable_http,
        .arena = arena,
        .message = .{ .request = req },
        .responder = .{ .ptr = &exchange, .vtable = &exchange_vtable },
        .cancel = &token,
        .context = principal,
        .peer = .{ .address = socket.stream.socket.address },
    });
    if (exchange.keepalive_future) |*f| {
        exchange.keepalive_stop.store(true, .release);
        _ = f.cancel(self.io);
    }
    if (!exchange.done) {
        // The handler ended without a response (cancelled): close the stream.
        if (exchange.body_writer) |*bw| bw.end() catch {} else request.respond("", .{ .status = .service_unavailable }) catch {};
    }
    // The connection of a canceled request does not carry one more request.
    const reuse = exchange.reusable and !token.isCancelled() and request.head.keep_alive;
    // The watch can wait for the next request, thus the idle time limit starts now.
    const idle = reuse and conn.startTimer(.idle, self.limits.http.idle_timeout);
    if (watcher) |*w| watch.stop(self.io, w, idle);
    return reuse;
}

/// The cancellation reason of a request whose client closed the connection.
pub const disconnect_reason = "client disconnected";

/// Reads the socket of one request while its handler runs. The end of the connection
/// cancels the request. The task reads only into the free space at the end of the buffer of
/// `socket`. Thus the bytes of the request head stay in place, and the next request on the
/// connection uses the bytes that arrive.
const Watch = struct {
    socket: *Io.net.Stream.Reader,
    token: *Transport.CancelToken,
    id: RequestId,
    /// Set when the handler returned. After that, the watch ends at the next read.
    handler_done: std.atomic.Value(bool) = .init(false),
    /// Set when bytes from the client arrived while the handler ran.
    saw_data: std.atomic.Value(bool) = .init(false),

    fn run(self: *Watch, io: Io) void {
        const r = &self.socket.interface;
        while (r.end < r.buffer.len) {
            if (self.token.isCancelled() or self.handler_done.load(.acquire)) return;
            r.fillMore() catch |e| {
                if (e == error.ReadFailed) if (self.socket.err) |err| if (err == error.Canceled) return;
                if (self.handler_done.load(.acquire)) return;
                log.debug("the client of request {f} disconnected", .{self.id});
                self.token.cancel(io, disconnect_reason);
                return;
            };
            if (self.handler_done.load(.acquire)) return;
            self.saw_data.store(true, .release);
        }
    }

    /// End the watch. For a connection that carries one more request, wait until the read
    /// ends at the next bytes from the client. A canceled read can lose the bytes that
    /// arrive at the same time. For a connection that closes, cancel the read.
    fn stop(self: *Watch, io: Io, future: *Io.Future(void), reuse: bool) void {
        self.handler_done.store(true, .release);
        if (reuse and !self.saw_data.load(.acquire)) future.await(io) else future.cancel(io);
    }
};

fn toolSchema(self: *Server, params: ?Value) ?Value {
    const p = params orelse return null;
    const name = json.getString(p, "name") orelse return null;
    for (self.server.tools.items) |t| if (std.mem.eql(u8, t.def.name, name)) return t.def.inputSchema;
    return null;
}

/// The response side of one HTTP request.
const Exchange = struct {
    owner: *Server,
    request: *http.Server.Request,
    arena: Allocator,
    id: RequestId,
    token: *Transport.CancelToken,
    long_lived: bool,
    force_sse: bool,
    body_writer: ?http.BodyWriter = null,
    done: bool = false,
    reusable: bool = true,
    write_lock: Io.Mutex = .init,
    keepalive_future: ?Io.Future(void) = null,
    keepalive_stop: std.atomic.Value(bool) = .init(false),

    const sse_headers = [_]http.Header{
        .{ .name = "content-type", .value = sse.content_type },
        .{ .name = "cache-control", .value = "no-cache, no-transform" },
        .{ .name = "x-accel-buffering", .value = "no" },
    };

    fn startSse(self: *Exchange) Transport.SendError!void {
        if (self.body_writer != null) return;
        self.body_writer = self.request.respondStreaming(&.{}, .{ .respond_options = .{ .status = .ok, .keep_alive = false, .extra_headers = &sse_headers } }) catch return error.WriteFailed;
        self.reusable = false;
        if (self.long_lived and self.owner.options.keepalive) {
            self.keepalive_future = self.owner.io.concurrent(keepaliveLoop, .{self}) catch null;
        }
    }

    fn keepaliveLoop(self: *Exchange) void {
        const io = self.owner.io;
        while (!self.keepalive_stop.load(.acquire)) {
            io.sleep(self.owner.limits.http.sse_keepalive, .awake) catch return;
            if (self.keepalive_stop.load(.acquire)) return;
            self.write_lock.lockUncancelable(io);
            defer self.write_lock.unlock(io);
            if (self.done) return;
            const bw = &(self.body_writer orelse return);
            sse.writeComment(&bw.writer, "keepalive") catch return;
            bw.flush() catch return;
        }
    }

    fn writeSse(self: *Exchange, frame: []const u8) Transport.SendError!void {
        const bw = &self.body_writer.?;
        sse.writeEvent(&bw.writer, frame) catch return error.WriteFailed;
        bw.flush() catch return error.WriteFailed;
    }
};

const exchange_vtable: Transport.Responder.VTable = .{
    .notify = exchangeNotify,
    .finish = exchangeFinish,
    .abort = exchangeAbort,
};

fn exchangeNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.write_lock.lockUncancelable(io);
    defer self.write_lock.unlock(io);
    if (self.done) return error.Closed;
    // After a cancellation by the client, the server sends nothing more for the request.
    if (self.token.isCancelledByPeer()) return error.Closed;
    try self.startSse();
    try self.writeSse(frame);
}

fn exchangeFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.write_lock.lockUncancelable(io);
    defer self.write_lock.unlock(io);
    if (self.done) return error.Closed;
    if (self.token.isCancelledByPeer()) return error.Closed;
    self.done = true;
    if (self.body_writer != null or self.force_sse or self.long_lived) {
        try self.startSse();
        try self.writeSse(frame);
        const bw = &self.body_writer.?;
        bw.end() catch return error.WriteFailed;
        return;
    }
    // JSON mode: the HTTP status follows the error code for status-bearing codes. A rate
    // limit error also gets `Retry-After`.
    var status: http.Status = .ok;
    var retry_after: ?u64 = null;
    if (json.parseTree(self.arena, frame)) |tree| {
        if (tree == .object) {
            if (tree.object.get("error")) |e| {
                if (e == .object) {
                    if (e.object.get("code")) |c| if (c == .integer) {
                        status = statusForCode(c.integer);
                        if (status == .too_many_requests) retry_after = retryAfterSeconds(e);
                    };
                }
            }
        }
    } else |_| {}
    var headers: [2]http.Header = .{ json_headers[0], undefined };
    var count: usize = 1;
    var seconds_buf: [20]u8 = undefined;
    if (retry_after) |s| {
        headers[1] = .{ .name = "retry-after", .value = std.fmt.bufPrint(&seconds_buf, "{d}", .{s}) catch unreachable };
        count = 2;
    }
    self.request.respond(frame, .{ .status = status, .keep_alive = self.request.head.keep_alive, .extra_headers = headers[0..count] }) catch return error.WriteFailed;
}

fn exchangeAbort(ptr: *anyopaque, io: Io) void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.write_lock.lockUncancelable(io);
    defer self.write_lock.unlock(io);
    if (self.done) return;
    self.done = true;
    if (self.body_writer) |*bw| {
        bw.end() catch {};
    } else {
        self.request.respond("", .{ .status = .service_unavailable }) catch {};
    }
    self.reusable = false;
}

test "a rate limit error maps to status 429 and Retry-After in whole seconds" {
    try std.testing.expectEqual(http.Status.too_many_requests, statusForCode(-31429));
    try std.testing.expectEqual(http.Status.bad_request, statusForCode(-32602));
    try std.testing.expectEqual(http.Status.ok, statusForCode(-32603));
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cases = [_]struct { text: []const u8, seconds: ?u64 }{
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":1}}", .seconds = 1 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":1000}}", .seconds = 1 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":1001}}", .seconds = 2 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":0}}", .seconds = 1 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":-5}}", .seconds = null },
        .{ .text = "{\"code\":-31429,\"message\":\"m\"}", .seconds = null },
    };
    for (cases) |c| try std.testing.expectEqual(c.seconds, retryAfterSeconds(try json.parseTree(arena, c.text)));
}

test {
    std.testing.refAllDecls(@This());
}
