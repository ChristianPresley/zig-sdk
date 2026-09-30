//! The gRPC client transport: one HTTP/2 connection to a server, one `Call` per request.
//! The channel reconnects when the connection is gone.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("mcp");
const Transport = mcp.transport.Transport;
const envelope = mcp.transport.envelope;
const tool_headers = mcp.transport.tool_headers;
const http1 = mcp.transport.http1;
const methods = mcp.protocol.methods;
const version = mcp.protocol.version;
const json = mcp.json;
const tls = mcp.tls;
const Connection = @import("../http2/Connection.zig");
const Stream = Connection.Stream;
const Header = Connection.Header;
const lpm = @import("../grpc/lpm.zig");
const status = @import("../grpc/status.zig");
const timeout = @import("../grpc/timeout.zig");
const messages = @import("../protobuf/messages.zig");
const grpc_server = @import("grpc_server.zig");

const log = std.log.scoped(.mcp_grpc_client);

pub const Options = struct {
    host: []const u8,
    port: u16,
    /// TLS with ALPN `h2`. Null connects with cleartext prior knowledge.
    tls: ?http1.TlsSetup = null,
    /// The `:authority` of every call. Null uses `host:port`.
    authority: ?[]const u8 = null,
    /// Metadata added to every call, for example `authorization`.
    extra_metadata: []const Header = &.{},
    /// The largest response message. Overflow: the call fails.
    max_message_bytes: usize = 4 << 20,
    /// How often a call checks for cancellation and its deadline.
    poll_interval: Io.Duration = .fromMilliseconds(50),
};

pub const ConnectError = error{ OutOfMemory, ConnectFailed, TlsFailed, ProtocolError } || Io.Cancelable;

pub const Channel = struct {
    io: Io,
    gpa: Allocator,
    options: Options,
    tool_headers: tool_headers.Map,
    lock: Io.Mutex = .init,
    link: ?*Link = null,

    /// One connection with its buffers.
    const Link = struct {
        stream: Io.net.Stream,
        in_buf: []u8,
        out_buf: []u8,
        tls_read_buf: []u8,
        tls_write_buf: []u8,
        reader: Io.net.Stream.Reader,
        writer: Io.net.Stream.Writer,
        tls_conn: ?tls.Connection = null,
        h2: *Connection,
        run_future: ?Io.Future(void) = null,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) Allocator.Error!*Channel {
        const self = try gpa.create(Channel);
        self.* = .{ .io = io, .gpa = gpa, .options = options, .tool_headers = .init(gpa, io) };
        return self;
    }

    pub fn deinit(self: *Channel) void {
        self.close();
        self.tool_headers.deinit();
        self.gpa.destroy(self);
    }

    pub fn transport(self: *Channel) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Connect now. Calls connect on demand when this was not called.
    pub fn connect(self: *Channel) ConnectError!void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        _ = try self.ensureLinkLocked();
    }

    /// End the connection gracefully.
    pub fn close(self: *Channel) void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.closeLinkLocked();
    }

    /// The negotiated application protocol of the current connection, when TLS is in use.
    pub fn alpn(self: *Channel) ?[]const u8 {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const link = self.link orelse return null;
        const c = &(link.tls_conn orelse return null);
        return c.alpn();
    }

    fn ensureLinkLocked(self: *Channel) ConnectError!*Link {
        if (self.link) |link| {
            if (!link.h2.isClosed()) return link;
            self.closeLinkLocked();
        }
        const link = try self.openLink();
        self.link = link;
        return link;
    }

    fn openLink(self: *Channel) ConnectError!*Link {
        const io = self.io;
        const gpa = self.gpa;
        const link = try gpa.create(Link);
        errdefer gpa.destroy(link);
        const in_buf = try gpa.alloc(u8, tls.Connection.min_input_buffer_len);
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, tls.Connection.min_output_buffer_len);
        errdefer gpa.free(out_buf);
        const secure = self.options.tls != null;
        const tls_read_buf = try gpa.alloc(u8, if (secure) tls.Connection.min_read_buffer_len else 0);
        errdefer gpa.free(tls_read_buf);
        const tls_write_buf = try gpa.alloc(u8, if (secure) 16 << 10 else 0);
        errdefer gpa.free(tls_write_buf);
        const stream = connectStream(io, self.options.host, self.options.port) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return error.ConnectFailed,
        };
        errdefer stream.close(io);
        link.* = .{
            .stream = stream,
            .in_buf = in_buf,
            .out_buf = out_buf,
            .tls_read_buf = tls_read_buf,
            .tls_write_buf = tls_write_buf,
            .reader = undefined,
            .writer = undefined,
            .h2 = undefined,
        };
        link.reader = link.stream.reader(io, link.in_buf);
        link.writer = link.stream.writer(io, link.out_buf);
        var in: *Io.Reader = &link.reader.interface;
        var out: *Io.Writer = &link.writer.interface;
        if (self.options.tls) |setup| {
            link.tls_conn = tls.connect(&link.reader.interface, &link.writer.interface, .{
                .io = io,
                .host = setup.server_name orelse self.options.host,
                .trust = setup.trust,
                .alpn = &.{"h2"},
                .identity = setup.identity,
                .read_buffer = link.tls_read_buf,
                .write_buffer = link.tls_write_buf,
                .allow_truncation_attacks = true,
            }) catch {
                link.writer.interface.flush() catch {};
                return error.TlsFailed;
            };
            in = &link.tls_conn.?.reader;
            out = &link.tls_conn.?.writer;
        }
        errdefer if (link.tls_conn) |*c| c.deinit();
        link.h2 = try Connection.init(gpa, io, in, out, .{ .role = .client });
        errdefer link.h2.deinit();
        link.h2.handshake() catch return error.ProtocolError;
        link.run_future = io.concurrent(Connection.run, .{link.h2}) catch return error.ProtocolError;
        return link;
    }

    fn connectStream(io: Io, host: []const u8, port: u16) !Io.net.Stream {
        if (Io.net.IpAddress.parse(host, port)) |address| {
            return address.connect(io, .{ .mode = .stream });
        } else |_| {}
        const name = Io.net.HostName.init(host) catch return error.ConnectFailed;
        return name.connect(io, port, .{ .mode = .stream });
    }

    fn closeLinkLocked(self: *Channel) void {
        const link = self.link orelse return;
        self.link = null;
        const io = self.io;
        link.h2.shutdown();
        if (link.tls_conn) |*c| {
            c.end() catch {};
            link.writer.interface.flush() catch {};
        }
        link.stream.shutdown(io, .send) catch {};
        if (link.run_future) |*f| f.await(io);
        if (link.tls_conn) |*c| c.deinit();
        link.h2.deinit();
        link.stream.close(io);
        self.gpa.free(link.tls_write_buf);
        self.gpa.free(link.tls_read_buf);
        self.gpa.free(link.out_buf);
        self.gpa.free(link.in_buf);
        self.gpa.destroy(link);
    }

    const vtable: Transport.ClientTransport.VTable = .{
        .kind = .grpc,
        .exchange = exchange,
        .notify = notify,
    };

    const Task = struct {
        channel: *Channel,
        ex: *Transport.Exchange,
        arena: Allocator,
        done: Io.Event = .unset,
        result: Transport.ExchangeError!void = {},

        fn run(t: *Task) void {
            t.result = t.channel.perform(t.arena, t.ex);
            t.done.set(t.channel.io);
        }
    };

    /// Run the call in a task so that cancellation and the deadline can interrupt it.
    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Channel = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        var task: Task = .{ .channel = self, .ex = ex, .arena = arena_state.allocator() };
        var future = io.concurrent(Task.run, .{&task}) catch return self.perform(task.arena, ex);
        const deadline = ex.timeout.toTimestamp(io);
        var stop: ?Transport.ExchangeError = null;
        while (true) {
            task.done.waitTimeout(io, .{ .duration = .{ .raw = self.options.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => {
                    stop = error.Canceled;
                    break;
                },
            };
            if (task.done.isSet()) break;
            if (ex.cancel.isCancelled()) {
                stop = error.Canceled;
                break;
            }
            if (deadline) |d| if (Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw.nanoseconds <= 0) {
                stop = error.Timeout;
                break;
            };
        }
        if (stop) |err| {
            _ = future.cancel(io);
            return err;
        }
        future.await(io);
        return task.result;
    }

    /// A notification travels as a call the server answers with an empty stream.
    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = io;
        const self: *Channel = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const msg = mcp.jsonrpc.Message.parse(arena, frame) catch return error.WriteFailed;
        const method_name = msg.method() orelse return error.WriteFailed;
        const link = self.acquireLink() catch return error.WriteFailed;
        const stream = link.h2.openStream() catch return error.Closed;
        defer stream.close();
        var headers: std.ArrayList(Header) = .empty;
        try self.callHeaders(arena, &headers, method_name, null, null);
        stream.sendHeaders(headers.items, false) catch return error.WriteFailed;
        var out: std.ArrayList(u8) = .empty;
        try messages.encodeJsonRpcMessage(arena, &out, frame);
        lpm.write(stream, self.gpa, out.items, true) catch return error.WriteFailed;
        _ = stream.waitEnd() catch return error.WriteFailed;
    }

    fn acquireLink(self: *Channel) ConnectError!*Link {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        return self.ensureLinkLocked();
    }

    /// The pseudo-headers and the metadata of one call.
    fn callHeaders(self: *Channel, arena: Allocator, headers: *std.ArrayList(Header), method_name: []const u8, params: ?Value, deadline: ?Io.Duration) Allocator.Error!void {
        const authority = self.options.authority orelse try std.fmt.allocPrint(arena, "{s}:{d}", .{ self.options.host, self.options.port });
        try headers.append(arena, .{ .name = ":method", .value = "POST" });
        try headers.append(arena, .{ .name = ":scheme", .value = if (self.options.tls != null) "https" else "http" });
        try headers.append(arena, .{ .name = ":path", .value = grpc_server.call_path });
        try headers.append(arena, .{ .name = ":authority", .value = authority });
        try headers.append(arena, .{ .name = "content-type", .value = grpc_server.content_type });
        try headers.append(arena, .{ .name = "te", .value = "trailers" });
        try headers.append(arena, .{ .name = "user-agent", .value = "zig-sdk-mcp/" ++ version.version });
        if (deadline) |d| {
            const buf = try arena.alloc(u8, 9);
            try headers.append(arena, .{ .name = "grpc-timeout", .value = timeout.format(buf[0..9], d) });
        }
        try headers.append(arena, .{ .name = envelope.header_protocol_version, .value = version.version });
        try headers.append(arena, .{ .name = envelope.header_method, .value = method_name });
        if (params) |p| if (p == .object) {
            const key: ?[]const u8 = if (methods.Method.fromName(method_name)) |m| switch (m.headerNameSource()) {
                .none => null,
                .name => "name",
                .uri => "uri",
                .task_id => "taskId",
            } else if (envelope.isTaskMethod(method_name)) "taskId" else null;
            if (key) |k| if (json.getString(p, k)) |value| {
                try headers.append(arena, .{ .name = envelope.header_name, .value = try envelope.encodeValue(arena, value) });
            };
            if (std.mem.eql(u8, method_name, "tools/call")) {
                if (json.getString(p, "name")) |tool| if (p.object.get("arguments")) |arguments| {
                    try self.tool_headers.appendParamHeaders(arena, headers, tool, arguments, true);
                };
            }
        };
        for (self.options.extra_metadata) |h| try headers.append(arena, h);
    }

    fn perform(self: *Channel, arena: Allocator, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const io = self.io;
        const link = self.acquireLink() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            else => return error.WriteFailed,
        };
        const stream = link.h2.openStream() catch return error.Closed;
        defer stream.close();
        var remaining: ?Io.Duration = null;
        if (ex.timeout.toTimestamp(io)) |d| {
            const left = Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw;
            remaining = if (left.nanoseconds > 0) left else .{ .nanoseconds = 1 };
        }
        var headers: std.ArrayList(Header) = .empty;
        try self.callHeaders(arena, &headers, ex.method, ex.params, remaining);
        stream.sendHeaders(headers.items, false) catch |e| return mapStream(e);
        var out: std.ArrayList(u8) = .empty;
        try messages.encodeJsonRpcMessage(arena, &out, ex.frame);
        lpm.write(stream, self.gpa, out.items, true) catch |e| return mapStream(e);

        const response_headers = stream.waitHeaders() catch |e| return mapStream(e);
        const status_text = Connection.findHeader(response_headers, ":status") orelse "0";
        ex.http_status = std.fmt.parseInt(u16, status_text, 10) catch 0;
        if (ex.http_status != 200) return error.HttpStatus;
        if (Connection.findHeader(response_headers, "grpc-status")) |gs| {
            return self.finishStatus(io, arena, ex, response_headers, gs, false);
        }
        var delivered = false;
        while (true) {
            const payload = lpm.read(stream, self.gpa, self.options.max_message_bytes) catch |e| switch (e) {
                error.Compressed, error.MessageTooLarge, error.Truncated => return error.InvalidFrame,
                else => |other| return mapStream(other),
            } orelse break;
            defer self.gpa.free(payload);
            const text = messages.decodeJsonRpcMessage(payload) catch return error.InvalidFrame;
            var frame: []const u8 = text;
            if (std.mem.eql(u8, ex.method, "tools/list")) {
                if (self.tool_headers.learn(arena, text) catch null) |rewritten| frame = rewritten;
            }
            ex.sink.deliver(io, frame) catch return error.InvalidFrame;
            delivered = true;
        }
        const trailers = stream.waitEnd() catch |e| return mapStream(e);
        const gs = Connection.findHeader(trailers, "grpc-status") orelse return error.InvalidFrame;
        return self.finishStatus(io, arena, ex, trailers, gs, delivered);
    }

    /// Interpret the status of a finished call.
    fn finishStatus(self: *Channel, io: Io, arena: Allocator, ex: *Transport.Exchange, trailers: []const Header, gs: []const u8, delivered: bool) Transport.ExchangeError!void {
        _ = self;
        const code = status.Code.fromWire(gs) orelse return error.InvalidFrame;
        if (code == .ok) {
            if (!delivered) return error.InvalidFrame;
            return;
        }
        if (Connection.findHeader(trailers, "grpc-message")) |m| {
            log.debug("call ended with {t}: {s}", .{ code, status.decodeMessage(arena, m) catch m });
        }
        if (!delivered) if (Connection.findHeader(trailers, grpc_server.header_error_bin)) |bin| {
            const decoder = std.base64.standard.Decoder;
            const len = decoder.calcSizeForSlice(bin) catch return error.InvalidFrame;
            const frame = try arena.alloc(u8, len);
            decoder.decode(frame, bin) catch return error.InvalidFrame;
            ex.sink.deliver(io, frame) catch return error.InvalidFrame;
            return;
        };
        return switch (code) {
            .unavailable => error.Closed,
            .deadline_exceeded => error.Timeout,
            .cancelled => error.Canceled,
            .unauthenticated => {
                ex.http_status = 401;
                return error.HttpStatus;
            },
            .permission_denied => {
                ex.http_status = 403;
                return error.HttpStatus;
            },
            else => error.ReadFailed,
        };
    }
};

fn mapStream(e: anyerror) Transport.ExchangeError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.Closed => error.Closed,
        error.StreamReset => error.ReadFailed,
        error.WriteFailed => error.WriteFailed,
        else => error.ReadFailed,
    };
}
