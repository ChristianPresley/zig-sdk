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
    /// Answer a request-scoped stream with SSE even when the handler sends no notification.
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

    /// Accept connections until a call to `shutdown`.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        var accept_future = try self.io.concurrent(acceptLoop, .{self});
        self.stop_event.wait(self.io) catch {};
        _ = accept_future.cancel(self.io);
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
        // Unblock connection tasks that wait for the next request.
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items) |c| c.stream.shutdown(self.io, .both) catch {};
    }

    fn originAllowed(self: *Server, origin: []const u8) bool {
        if (self.options.allowed_origins.len > 0) {
            for (self.options.allowed_origins) |o| if (std.ascii.eqlIgnoreCase(o, origin)) return true;
            return false;
        }
        return isLoopbackOrigin(origin);
    }

    fn hostAllowed(self: *Server, host: []const u8) bool {
        const name = stripPort(host);
        if (self.options.allowed_hosts.len > 0) {
            for (self.options.allowed_hosts) |h| if (std.ascii.eqlIgnoreCase(stripPort(h), name)) return true;
            return false;
        }
        if (isLoopbackName(name)) return true;
        return std.ascii.eqlIgnoreCase(name, self.options.address);
    }
};

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

const Connection = struct {
    owner: *Server,
    stream: Io.net.Stream,

    fn run(conn: *Connection) Io.Cancelable!void {
        const self = conn.owner;
        defer {
            self.untrack(conn);
            conn.stream.close(self.io);
            self.permits.post(self.io);
            self.gpa.destroy(conn);
        }
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
        while (!self.closing.load(.acquire)) {
            var request = http_server.receiveHead() catch |e| switch (e) {
                error.HttpConnectionClosing => return,
                error.HttpHeadersOversize => {
                    out.writeAll("HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                    out.flush() catch {};
                    return;
                },
                else => return,
            };
            const keep_alive = handleRequest(self, &request) catch |err| switch (err) {
                error.OutOfMemory => false,
                else => false,
            };
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
        if (std.mem.eql(u8, name, envelope.header_protocol_version)) head.envelope_headers.protocol_version = value;
        if (std.mem.eql(u8, name, envelope.header_method)) head.envelope_headers.method = value;
        if (std.mem.eql(u8, name, envelope.header_name)) head.envelope_headers.name = value;
        if (std.mem.startsWith(u8, name, envelope.header_param_prefix)) {
            try params.append(arena, .{ .name = try arena.dupe(u8, name[envelope.header_param_prefix.len..]), .value = value });
        }
    }
    head.envelope_headers.params = params.items;
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
        else => .ok,
    };
}

/// Handle one request on a connection. Returns whether the connection can carry one more request.
fn handleRequest(self: *Server, request: *http.Server.Request) !bool {
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
        switch (try auth.authorize(arena, head.authorization)) {
            .ok => |p| {
                const owned = try arena.create(resource_server.Principal);
                owned.* = p;
                principal = owned;
            },
            .challenge => |c| {
                try request.respond(c.body, .{
                    .status = @enumFromInt(c.status),
                    .keep_alive = request.head.keep_alive,
                    .extra_headers = &.{ .{ .name = "www-authenticate", .value = c.www_authenticate }, .{ .name = "content-type", .value = "application/json" } },
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
    const msg = jsonrpc.Message.parse(arena, body) catch |e| switch (e) {
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
        .request => |req| return handleRpcRequest(self, request, arena, head, req, principal),
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

fn handleRpcRequest(self: *Server, request: *http.Server.Request, arena: Allocator, head: Head, req: jsonrpc.Message.Request, principal: ?*resource_server.Principal) !bool {
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
        .long_lived = std.mem.eql(u8, req.method, "subscriptions/listen"),
        .force_sse = self.options.response_mode == .sse,
    };
    self.server.handle(self.io, .{
        .kind = .streamable_http,
        .arena = arena,
        .message = .{ .request = req },
        .responder = .{ .ptr = &exchange, .vtable = &exchange_vtable },
        .cancel = &token,
        .context = principal,
    });
    if (exchange.keepalive_future) |*f| {
        exchange.keepalive_stop.store(true, .release);
        _ = f.cancel(self.io);
    }
    if (!exchange.done) {
        // The handler ended without a response (cancelled): close the stream.
        if (exchange.body_writer) |*bw| bw.end() catch {} else request.respond("", .{ .status = .service_unavailable }) catch {};
    }
    return exchange.reusable;
}

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
    try self.startSse();
    try self.writeSse(frame);
}

fn exchangeFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.write_lock.lockUncancelable(io);
    defer self.write_lock.unlock(io);
    if (self.done) return error.Closed;
    self.done = true;
    if (self.body_writer != null or self.force_sse or self.long_lived) {
        try self.startSse();
        try self.writeSse(frame);
        const bw = &self.body_writer.?;
        bw.end() catch return error.WriteFailed;
        return;
    }
    // JSON mode: the HTTP status follows the error code for status-bearing codes.
    var status: http.Status = .ok;
    if (json.parseTree(self.arena, frame)) |tree| {
        if (tree == .object) {
            if (tree.object.get("error")) |e| {
                if (e == .object) {
                    if (e.object.get("code")) |c| if (c == .integer) {
                        status = statusForCode(c.integer);
                    };
                }
            }
        }
    } else |_| {}
    self.request.respond(frame, .{ .status = status, .keep_alive = self.request.head.keep_alive, .extra_headers = &json_headers }) catch return error.WriteFailed;
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

test {
    std.testing.refAllDecls(@This());
}
