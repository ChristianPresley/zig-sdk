//! The gRPC server transport: one HTTP/2 listener, one `Call` per JSON-RPC request. The
//! request metadata mirrors the Streamable HTTP headers. A JSON-RPC error that ends a call
//! before any message travels in the trailers. With `bindings.typed`, the listener also
//! serves the typed service of `typed_server.zig`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("mcp");
const Transport = mcp.transport.Transport;
const envelope = mcp.transport.envelope;
const jsonrpc = mcp.jsonrpc;
const RequestId = jsonrpc.RequestId;
const errors = mcp.protocol.errors;
const version = mcp.protocol.version;
const json = mcp.json;
const tls = mcp.tls;
const resource_server = mcp.auth.resource_server;
const Connection = @import("../http2/Connection.zig");
const Stream = Connection.Stream;
const Header = Connection.Header;
const lpm = @import("../grpc/lpm.zig");
const status = @import("../grpc/status.zig");
const timeout = @import("../grpc/timeout.zig");
const messages = @import("../protobuf/messages.zig");
const codec = @import("../protobuf/codec.zig");
const service = @import("../typed/service.zig");
const typed_server = @import("typed_server.zig");

const log = std.log.scoped(.mcp_grpc);

pub const call_path = "/mcp.zig.transport.v1.Mcp/Call";
pub const content_type = "application/grpc+proto";
pub const header_error_code = "mcp-error-code";
pub const header_error_bin = "mcp-error-bin";

/// The services that the server answers. A call to a service that is off ends with
/// `UNIMPLEMENTED`.
pub const Bindings = struct {
    /// The JSON-RPC tunnel `mcp.zig.transport.v1.Mcp`.
    tunnel: bool = true,
    /// The typed service `model_context_protocol.Mcp` of the Google Cloud proto files.
    typed: bool = false,
};

pub const Options = struct {
    /// Address to bind. The default is loopback only.
    address: []const u8 = "127.0.0.1",
    port: u16 = 50051,
    /// Serve over TLS with ALPN `h2`. Null serves cleartext HTTP/2 with prior knowledge.
    tls: ?*const tls.Server = null,
    /// Require a bearer token on every call.
    auth: ?*const resource_server.ResourceServer = null,
    /// The largest request message. Overflow: `RESOURCE_EXHAUSTED`.
    max_message_bytes: usize = 4 << 20,
    /// Open connections. Overflow: the accept loop waits.
    max_connections: u32 = 256,
    /// The services of the server. The default is the tunnel only.
    bindings: Bindings = .{},
    /// The nesting depth and the element count of a request message of the typed binding.
    /// Overflow: `INVALID_ARGUMENT`.
    typed_limits: codec.Limits = .{},
};

pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *mcp.Server,
    options: Options,
    listener: ?Io.net.Server = null,
    bound_port: u16 = 0,
    group: Io.Group = .init,
    permits: Io.Semaphore,
    closing: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    connections: std.ArrayList(*Conn) = .empty,
    connections_lock: Io.Mutex = .init,

    pub fn init(io: Io, gpa: Allocator, server: *mcp.Server, options: Options) Server {
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .permits = .{ .permits = options.max_connections },
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener) |*l| l.deinit(self.io);
        self.connections.deinit(self.gpa);
        self.* = undefined;
    }

    fn track(self: *Server, conn: *Conn) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        self.connections.append(self.gpa, conn) catch {};
    }

    fn untrack(self: *Server, conn: *Conn) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items, 0..) |c, i| if (c == conn) {
            _ = self.connections.swapRemove(i);
            return;
        };
    }

    /// Bind the listen socket. After this call `bound_port` has the port.
    pub fn bind(self: *Server) !void {
        var address = try Io.net.IpAddress.parse(self.options.address, self.options.port);
        self.listener = try address.listen(self.io, .{});
        self.bound_port = self.listener.?.socket.address.getPort();
    }

    /// Accept connections until a call to `shutdown`.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        var accept_future = try self.io.concurrent(acceptLoop, .{self});
        self.stop_event.wait(self.io) catch {};
        mcp.util.wake.wakeIp(self.io, self.listener.?.socket.address);
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
            // The connection of `wake` or a peer that came during the shutdown.
            if (self.closing.load(.acquire)) {
                stream.close(self.io);
                break;
            }
            self.permits.waitUncancelable(self.io);
            const conn = self.gpa.create(Conn) catch {
                stream.close(self.io);
                self.permits.post(self.io);
                continue;
            };
            conn.* = .{ .owner = self, .stream = stream };
            self.track(conn);
            self.group.concurrent(self.io, Conn.run, .{conn}) catch {
                self.untrack(conn);
                stream.close(self.io);
                self.permits.post(self.io);
                self.gpa.destroy(conn);
            };
        }
    }

    /// Accept no more connections and end the open connections. Safe to call from another task.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .release);
        self.stop_event.set(self.io);
        self.server.shutdownSubscriptions(self.io);
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items) |c| {
            if (c.h2_ready.load(.acquire)) c.h2.shutdown();
            c.stream.shutdown(self.io, .both) catch {};
        }
    }
};

const Conn = struct {
    owner: *Server,
    stream: Io.net.Stream,
    group: Io.Group = .init,
    h2: *Connection = undefined,
    h2_ready: std.atomic.Value(bool) = .init(false),

    fn run(conn: *Conn) Io.Cancelable!void {
        const self = conn.owner;
        const io = self.io;
        defer {
            self.untrack(conn);
            conn.stream.close(io);
            self.permits.post(io);
            self.gpa.destroy(conn);
        }
        const in_buf = self.gpa.alloc(u8, tls.Connection.min_input_buffer_len) catch return;
        defer self.gpa.free(in_buf);
        const out_buf = self.gpa.alloc(u8, tls.Connection.min_output_buffer_len) catch return;
        defer self.gpa.free(out_buf);
        var reader = conn.stream.reader(io, in_buf);
        var writer = conn.stream.writer(io, out_buf);

        var tls_conn: tls.Connection = undefined;
        var tls_active = false;
        var tls_read_buf: []u8 = &.{};
        var tls_write_buf: []u8 = &.{};
        defer if (tls_active) {
            tls_conn.end() catch {};
            writer.interface.flush() catch {};
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
                .io = io,
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .allow_truncation_attacks = true,
            }) catch {
                self.gpa.free(tls_read_buf);
                self.gpa.free(tls_write_buf);
                return;
            };
            tls_active = true;
            // A client that negotiated another protocol gets no HTTP/2.
            if (tls_conn.alpn()) |alpn| if (!std.mem.eql(u8, alpn, "h2")) return;
        }
        const in: *Io.Reader = if (tls_active) &tls_conn.reader else &reader.interface;
        const out: *Io.Writer = if (tls_active) &tls_conn.writer else &writer.interface;
        conn.h2 = Connection.init(self.gpa, io, in, out, .{
            .role = .server,
            .on_stream = onStream,
            .userdata = conn,
            .max_concurrent_streams = self.server.options.limits.max_in_flight_requests,
        }) catch return;
        defer conn.h2.deinit();
        conn.h2_ready.store(true, .release);
        defer conn.h2_ready.store(false, .release);
        conn.h2.handshake() catch return;
        conn.h2.run();
        conn.group.await(io) catch {};
    }

    fn onStream(userdata: ?*anyopaque, stream: *Stream) void {
        const conn: *Conn = @ptrCast(@alignCast(userdata.?));
        conn.group.concurrent(conn.owner.io, handleStream, .{ conn, stream }) catch {
            stream.cancel();
            stream.close();
        };
    }
};

fn handleStream(conn: *Conn, stream: *Stream) void {
    defer stream.close();
    handleStreamInner(conn, stream) catch |e| switch (e) {
        error.OutOfMemory => log.warn("out of memory on a call", .{}),
        else => {},
    };
}

fn handleStreamInner(conn: *Conn, stream: *Stream) !void {
    const self = conn.owner;
    var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const headers = try stream.waitHeaders();

    const method = Connection.findHeader(headers, ":method") orelse "";
    const path = Connection.findHeader(headers, ":path") orelse "";
    const ct = Connection.findHeader(headers, "content-type") orelse "";
    if (!std.mem.eql(u8, method, "POST")) return respondHttp(stream, "405");
    if (!std.ascii.startsWithIgnoreCase(ct, "application/grpc")) return respondHttp(stream, "415");
    const typed_rpc: ?service.Rpc = if (self.options.bindings.typed) service.Rpc.fromPath(path) else null;
    const tunnel_call = self.options.bindings.tunnel and std.mem.eql(u8, path, call_path);
    if (!tunnel_call and typed_rpc == null) return trailersOnly(stream, arena, .unimplemented, "Unknown service or method", null, null);
    if (Connection.findHeader(headers, "grpc-encoding")) |encoding| {
        if (!std.mem.eql(u8, encoding, "identity")) return trailersOnly(stream, arena, .unimplemented, "Compression is not supported", null, null);
    }

    // Authorization comes before any look at the message.
    var principal: ?*resource_server.Principal = null;
    if (self.options.auth) |auth| {
        switch (try auth.authorize(arena, Connection.findHeader(headers, "authorization"))) {
            .ok => |p| {
                const owned = try arena.create(resource_server.Principal);
                owned.* = p;
                principal = owned;
            },
            .challenge => |c| return challenge(stream, arena, c),
        }
    }
    if (typed_rpc) |rpc| return typed_server.handleCall(self, stream, arena, headers, rpc, principal);

    // The mirrored request metadata.
    var env: envelope.Headers = .{};
    var params: std.ArrayList(envelope.Headers.Param) = .empty;
    for (headers) |h| {
        if (std.mem.eql(u8, h.name, envelope.header_protocol_version)) env.protocol_version = h.value;
        if (std.mem.eql(u8, h.name, envelope.header_method)) env.method = h.value;
        if (std.mem.eql(u8, h.name, envelope.header_name)) env.name = h.value;
        if (std.mem.startsWith(u8, h.name, envelope.header_param_prefix)) {
            try params.append(arena, .{ .name = h.name[envelope.header_param_prefix.len..], .value = h.value });
        }
    }
    env.params = params.items;
    var deadline: ?Io.Duration = null;
    if (Connection.findHeader(headers, "grpc-timeout")) |t| {
        deadline = timeout.parse(t) catch return trailersOnly(stream, arena, .invalid_argument, "Invalid grpc-timeout", null, null);
    }

    // The one request message.
    const payload = lpm.read(stream, self.gpa, self.options.max_message_bytes) catch |e| switch (e) {
        error.MessageTooLarge => return trailersOnly(stream, arena, .resource_exhausted, "Message too large", null, null),
        error.Compressed => return trailersOnly(stream, arena, .unimplemented, "Compression is not supported", null, null),
        error.Truncated => return trailersOnly(stream, arena, .invalid_argument, "Truncated message", null, null),
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    } orelse return trailersOnly(stream, arena, .invalid_argument, "The call carried no message", null, null);
    defer self.gpa.free(payload);
    const text = messages.decodeJsonRpcMessage(payload) catch return trailersOnly(stream, arena, .invalid_argument, "The message is not a JsonRpcMessage", null, null);
    const msg = jsonrpc.Message.parseMaxDepth(arena, text, self.server.options.limits.json_max_depth) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Syntax => return rpcErrorOnly(stream, arena, errors.parseError("Parse error"), null),
        error.Invalid, error.InvalidId => return rpcErrorOnly(stream, arena, errors.invalidRequest("Invalid Request"), null),
    };
    switch (msg) {
        // A notification is accepted and dropped, as on Streamable HTTP.
        .notification => return trailersOnly(stream, arena, .ok, null, null, null),
        .response, .error_response => return rpcErrorOnly(stream, arena, errors.invalidRequest("Clients must not send responses"), null),
        .request => |req| try handleRequest(conn, stream, arena, env, deadline, req, principal),
    }
}

fn handleRequest(conn: *Conn, stream: *Stream, arena: Allocator, env: envelope.Headers, deadline: ?Io.Duration, req: jsonrpc.Message.Request, principal: ?*resource_server.Principal) !void {
    const self = conn.owner;
    const io = self.io;
    const schema = toolSchema(self, req.params);
    if (try envelope.verify(arena, env, req.method, req.params, schema)) |rejection| {
        if (env.protocol_version == null and std.mem.eql(u8, req.method, "initialize")) {
            const err = try errors.unsupportedProtocolVersion(arena, &version.supported_versions, "unknown");
            return rpcErrorOnly(stream, arena, err, req.id);
        }
        return rpcErrorOnly(stream, arena, errors.headerMismatch(rejection.message), req.id);
    }
    if (!std.mem.eql(u8, env.protocol_version.?, version.version)) {
        const err = try errors.unsupportedProtocolVersion(arena, &version.supported_versions, env.protocol_version.?);
        return rpcErrorOnly(stream, arena, err, req.id);
    }

    var token: Transport.CancelToken = .{};
    var watcher: ?Io.Future(void) = io.concurrent(watchCancel, .{ stream, &token, io }) catch null;
    defer if (watcher) |*w| {
        _ = w.cancel(io);
    };

    var exchange: Exchange = .{ .stream = stream, .gpa = self.gpa, .arena = arena };
    var deadline_future: ?Io.Future(void) = null;
    if (deadline) |d| deadline_future = io.concurrent(deadlineTask, .{ io, d, &token, &exchange }) catch null;
    defer if (deadline_future) |*f| {
        _ = f.cancel(io);
    };
    self.server.handle(io, .{
        .kind = .grpc,
        .arena = arena,
        .message = .{ .request = req },
        .responder = .{ .ptr = &exchange, .vtable = &exchange_vtable },
        .cancel = &token,
        .context = principal,
        .peer = .{ .address = conn.stream.socket.address },
    });
    if (!exchange.done) {
        // The handler ended without a response: the request was cancelled.
        const code: status.Code = if (exchange.deadline_hit) .deadline_exceeded else .cancelled;
        if (exchange.started) {
            stream.sendHeaders(&.{.{ .name = "grpc-status", .value = code.wire() }}, true) catch {};
        } else {
            trailersOnly(stream, arena, code, "The request was cancelled", null, req.id) catch {};
        }
    }
}

/// Cancel the request when the client resets the stream or the connection goes away.
fn watchCancel(stream: *Stream, token: *Transport.CancelToken, io: Io) void {
    stream.waitCancelled() catch return;
    token.cancel(io, "stream reset");
}

fn deadlineTask(io: Io, duration: Io.Duration, token: *Transport.CancelToken, exchange: *Exchange) void {
    io.sleep(duration, .awake) catch return;
    exchange.deadline_hit = true;
    token.cancel(io, "deadline exceeded");
}

fn toolSchema(self: *Server, params: ?Value) ?Value {
    const p = params orelse return null;
    const name = json.getString(p, "name") orelse return null;
    for (self.server.tools.items) |t| if (std.mem.eql(u8, t.def.name, name)) return t.def.inputSchema;
    return null;
}

// -- Responses -------------------------------------------------------------------------------

fn respondHttp(stream: *Stream, status_text: []const u8) !void {
    try stream.sendHeaders(&.{ .{ .name = ":status", .value = status_text }, .{ .name = "content-length", .value = "0" } }, true);
}

/// End the call with headers only: a status, and with `err` the JSON-RPC error as well.
pub fn trailersOnly(stream: *Stream, arena: Allocator, code: status.Code, message_text: ?[]const u8, err: ?errors.RpcError, id: ?RequestId) !void {
    var list: std.ArrayList(Header) = .empty;
    try list.append(arena, .{ .name = ":status", .value = "200" });
    try list.append(arena, .{ .name = "content-type", .value = content_type });
    try list.append(arena, .{ .name = "grpc-status", .value = code.wire() });
    if (message_text) |m| try list.append(arena, .{ .name = "grpc-message", .value = try status.encodeMessage(arena, m) });
    if (err) |e| {
        try list.append(arena, .{ .name = header_error_code, .value = try std.fmt.allocPrint(arena, "{d}", .{e.code}) });
        var aw: Io.Writer.Allocating = .init(arena);
        jsonrpc.message.writeErrorResponse(&aw.writer, id, e.toWire()) catch return error.OutOfMemory;
        const encoder = std.base64.standard.Encoder;
        const out = try arena.alloc(u8, encoder.calcSize(aw.written().len));
        try list.append(arena, .{ .name = header_error_bin, .value = encoder.encode(out, aw.written()) });
    }
    try stream.sendHeaders(list.items, true);
}

/// End the call with headers only for a JSON-RPC error that the server finds before the
/// handler runs. The status comes from the error code.
fn rpcErrorOnly(stream: *Stream, arena: Allocator, err: errors.RpcError, id: ?RequestId) !void {
    return trailersOnly(stream, arena, status.forJsonRpcCode(err.code), err.message, err, id);
}

fn challenge(stream: *Stream, arena: Allocator, c: resource_server.Challenge) !void {
    const code: status.Code = switch (c.status) {
        401 => .unauthenticated,
        403 => .permission_denied,
        else => .invalid_argument,
    };
    var buf: [3]std.http.Header = undefined;
    var headers: std.ArrayList(Header) = .empty;
    try headers.appendSlice(arena, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = content_type },
        .{ .name = "grpc-status", .value = code.wire() },
        .{ .name = "grpc-message", .value = try status.encodeMessage(arena, "Authorization required") },
    });
    for (c.headers(&buf)) |h| try headers.append(arena, .{ .name = h.name, .value = h.value });
    try stream.sendHeaders(headers.items, true);
}

/// The responder of one call.
const Exchange = struct {
    stream: *Stream,
    gpa: Allocator,
    arena: Allocator,
    started: bool = false,
    done: bool = false,
    /// Set by the deadline task before it cancels the request.
    deadline_hit: bool = false,

    fn ensureHeaders(self: *Exchange) Transport.SendError!void {
        if (self.started) return;
        self.stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = content_type } }, false) catch |e| return mapSend(e);
        self.started = true;
    }

    fn sendMessage(self: *Exchange, frame: []const u8) Transport.SendError!void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        try messages.encodeJsonRpcMessage(self.gpa, &out, frame);
        lpm.write(self.stream, self.gpa, out.items, false) catch |e| return mapSend(e);
    }
};

fn mapSend(e: anyerror) Transport.SendError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.Closed, error.StreamReset => error.Closed,
        else => error.WriteFailed,
    };
}

const exchange_vtable: Transport.Responder.VTable = .{
    .notify = exchangeNotify,
    .finish = exchangeFinish,
    .abort = exchangeAbort,
};

fn exchangeNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    _ = io;
    const ex: *Exchange = @ptrCast(@alignCast(ptr));
    if (ex.done) return error.Closed;
    try ex.ensureHeaders();
    try ex.sendMessage(frame);
}

fn exchangeFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    _ = io;
    const ex: *Exchange = @ptrCast(@alignCast(ptr));
    if (ex.done) return error.Closed;
    try ex.ensureHeaders();
    try ex.sendMessage(frame);
    ex.stream.sendHeaders(&.{.{ .name = "grpc-status", .value = status.Code.ok.wire() }}, true) catch |e| return mapSend(e);
    ex.done = true;
}

fn exchangeAbort(ptr: *anyopaque, io: Io) void {
    _ = io;
    const ex: *Exchange = @ptrCast(@alignCast(ptr));
    if (ex.done) return;
    ex.done = true;
    const code: status.Code = if (ex.deadline_hit) .deadline_exceeded else .cancelled;
    if (ex.started) {
        ex.stream.sendHeaders(&.{.{ .name = "grpc-status", .value = code.wire() }}, true) catch {};
    } else {
        trailersOnly(ex.stream, ex.arena, code, "The request was cancelled", null, null) catch {};
    }
}
