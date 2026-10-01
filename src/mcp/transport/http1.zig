//! A small HTTP/1.1 client connection: one TCP or TLS stream, one request, one response.
//! The Streamable HTTP client opens one connection per request, so there is no pool and
//! no reuse. The TLS side is the SDK client in `src/tls/`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const tls = @import("../../tls/tls.zig");

pub const Header = http.Header;

/// How to secure the connection.
pub const TlsSetup = struct {
    trust: tls.Trust,
    /// The certificate chain to present when the server asks for one.
    identity: ?*const tls.CertChain = null,
    /// The name to verify the server certificate against. Null uses the connection host.
    server_name: ?[]const u8 = null,
    /// The cipher suites in preference order, for example `tls.suites.default_suites_with_aegis`.
    cipher_suites: []const tls.Suite = tls.suites.default_suites,
    /// The padding of the encrypted records that the client sends.
    padding: tls.Padding = .none,
    /// The revocation checks of the server certificate. The default makes none.
    revocation: tls.Revocation = .{},
};

pub const OpenError = error{
    OutOfMemory,
    ConnectFailed,
    TlsFailed,
    Canceled,
};

pub const max_head_len = 16 << 10;

pub const Connection = struct {
    io: Io,
    gpa: Allocator,
    stream: Io.net.Stream,
    socket_reader: Io.net.Stream.Reader,
    socket_writer: Io.net.Stream.Writer,
    tls_conn: ?tls.Connection = null,
    /// The plaintext side of the stream.
    reader: *Io.Reader,
    writer: *Io.Writer,
    http_reader: http.Reader,
    in_buf: []u8,
    out_buf: []u8,
    tls_read_buf: []u8,
    tls_write_buf: []u8,
    transfer_buf: []u8,
    /// The alert that ended a failed TLS handshake, when there was one.
    tls_alert: ?std.crypto.tls.Alert = null,

    /// Connect to `host:port`, with a TLS handshake when `secure` is set.
    pub fn open(io: Io, gpa: Allocator, host: []const u8, port: u16, secure: ?TlsSetup) OpenError!*Connection {
        const self = try gpa.create(Connection);
        errdefer gpa.destroy(self);
        const in_buf = try gpa.alloc(u8, tls.Connection.min_input_buffer_len);
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, tls.Connection.min_output_buffer_len);
        errdefer gpa.free(out_buf);
        const tls_read_buf = try gpa.alloc(u8, if (secure != null) tls.Connection.min_read_buffer_len else 0);
        errdefer gpa.free(tls_read_buf);
        const tls_write_buf = try gpa.alloc(u8, if (secure != null) 8 << 10 else 0);
        errdefer gpa.free(tls_write_buf);
        const transfer_buf = try gpa.alloc(u8, 8 << 10);
        errdefer gpa.free(transfer_buf);

        const stream = connectStream(io, host, port) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return error.ConnectFailed,
        };
        errdefer stream.close(io);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .stream = stream,
            .socket_reader = undefined,
            .socket_writer = undefined,
            .reader = undefined,
            .writer = undefined,
            .http_reader = undefined,
            .in_buf = in_buf,
            .out_buf = out_buf,
            .tls_read_buf = tls_read_buf,
            .tls_write_buf = tls_write_buf,
            .transfer_buf = transfer_buf,
        };
        self.socket_reader = self.stream.reader(io, self.in_buf);
        self.socket_writer = self.stream.writer(io, self.out_buf);
        if (secure) |setup| {
            var alert: std.crypto.tls.Alert = undefined;
            self.tls_conn = tls.connect(&self.socket_reader.interface, &self.socket_writer.interface, .{
                .io = io,
                .host = setup.server_name orelse host,
                .trust = setup.trust,
                .alpn = &.{"http/1.1"},
                .identity = setup.identity,
                .cipher_suites = setup.cipher_suites,
                .padding = setup.padding,
                .revocation = setup.revocation,
                .read_buffer = self.tls_read_buf,
                .write_buffer = self.tls_write_buf,
                .alert = &alert,
                // HTTP delimits its messages, so a missing close_notify is an ordinary end.
                .allow_truncation_attacks = true,
            }) catch |e| {
                self.socket_writer.interface.flush() catch {};
                if (e == error.TlsAlert or alert.level == .fatal) self.tls_alert = alert;
                return error.TlsFailed;
            };
            self.reader = &self.tls_conn.?.reader;
            self.writer = &self.tls_conn.?.writer;
        } else {
            self.reader = &self.socket_reader.interface;
            self.writer = &self.socket_writer.interface;
        }
        self.http_reader = .{ .in = self.reader, .interface = undefined, .state = .ready, .max_head_len = max_head_len };
        return self;
    }

    fn connectStream(io: Io, host: []const u8, port: u16) !Io.net.Stream {
        if (Io.net.IpAddress.parse(host, port)) |address| {
            return address.connect(io, .{ .mode = .stream });
        } else |_| {}
        const name = Io.net.HostName.init(host) catch return error.ConnectFailed;
        return name.connect(io, port, .{ .mode = .stream });
    }

    /// Send the TLS close_notify when there is a TLS connection, close the socket and free the buffers.
    pub fn close(self: *Connection) void {
        const io = self.io;
        if (self.tls_conn) |*c| {
            c.end() catch {};
            self.socket_writer.interface.flush() catch {};
            c.deinit();
        }
        self.stream.close(io);
        self.gpa.free(self.transfer_buf);
        self.gpa.free(self.tls_write_buf);
        self.gpa.free(self.tls_read_buf);
        self.gpa.free(self.out_buf);
        self.gpa.free(self.in_buf);
        self.gpa.destroy(self);
    }

    /// The negotiated application protocol, when TLS is in use.
    pub fn alpn(self: *const Connection) ?[]const u8 {
        const c = &(self.tls_conn orelse return null);
        return c.alpn();
    }

    /// Send one request with a complete body. The connection closes after the response.
    /// A GET request without a body has no `content-length` header.
    pub fn send(self: *Connection, method: []const u8, target: []const u8, host: []const u8, headers: []const Header, body: []const u8) Io.Writer.Error!void {
        const w = self.writer;
        try w.print("{s} {s} HTTP/1.1\r\nhost: {s}\r\nconnection: close\r\n", .{ method, target, host });
        if (body.len > 0 or !std.mem.eql(u8, method, "GET")) try w.print("content-length: {d}\r\n", .{body.len});
        for (headers) |h| try w.print("{s}: {s}\r\n", .{ h.name, h.value });
        try w.writeAll("\r\n");
        try w.writeAll(body);
        try self.flush();
    }

    /// Flush the plaintext writer and the socket.
    pub fn flush(self: *Connection) Io.Writer.Error!void {
        try self.writer.flush();
        if (self.tls_conn != null) try self.socket_writer.interface.flush();
    }

    pub const Response = struct {
        head: http.Client.Response.Head,
        /// The raw head, valid until the body is read.
        bytes: []const u8,
    };

    pub const ReceiveError = http.Reader.HeadError || http.Client.Response.Head.ParseError;

    /// Read and parse the response head.
    pub fn receiveHead(self: *Connection) ReceiveError!Response {
        const bytes = try self.http_reader.receiveHead();
        const head = try http.Client.Response.Head.parse(bytes);
        return .{ .head = head, .bytes = bytes };
    }

    /// The body reader for the received head. Read it before the connection closes.
    pub fn bodyReader(self: *Connection, response: *const Response) *Io.Reader {
        return self.http_reader.bodyReader(self.transfer_buf, response.head.transfer_encoding, response.head.content_length);
    }
};

/// The host, port and request target of a URL, for `Connection.open` and `send`.
pub const Target = struct {
    host: []const u8,
    port: u16,
    secure: bool,
    /// Path and query.
    path: []const u8,
    /// The `host` header value: the host with the port when it is not the default.
    host_header: []const u8,

    pub fn parse(arena: Allocator, url: []const u8) error{ OutOfMemory, InvalidUrl }!Target {
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        const secure = std.ascii.eqlIgnoreCase(uri.scheme, "https");
        if (!secure and !std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.InvalidUrl;
        const host_component = uri.host orelse return error.InvalidUrl;
        const host = host_component.toRawMaybeAlloc(arena) catch return error.InvalidUrl;
        if (host.len == 0) return error.InvalidUrl;
        const port: u16 = uri.port orelse if (secure) 443 else 80;
        var path: std.ArrayList(u8) = .empty;
        const raw_path = uri.path.percent_encoded;
        try path.appendSlice(arena, if (raw_path.len == 0) "/" else raw_path);
        if (uri.query) |q| {
            try path.append(arena, '?');
            try path.appendSlice(arena, q.percent_encoded);
        }
        const default_port = port == (if (secure) @as(u16, 443) else @as(u16, 80));
        const host_header = if (default_port) host else try std.fmt.allocPrint(arena, "{s}:{d}", .{ host, port });
        return .{ .host = host, .port = port, .secure = secure, .path = try path.toOwnedSlice(arena), .host_header = host_header };
    }
};

test "url targets" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const plain = try Target.parse(arena, "http://127.0.0.1:8080/mcp?x=1");
    try std.testing.expectEqualStrings("127.0.0.1", plain.host);
    try std.testing.expectEqual(8080, plain.port);
    try std.testing.expect(!plain.secure);
    try std.testing.expectEqualStrings("/mcp?x=1", plain.path);
    try std.testing.expectEqualStrings("127.0.0.1:8080", plain.host_header);
    const secure = try Target.parse(arena, "https://mcp.example.com");
    try std.testing.expectEqual(443, secure.port);
    try std.testing.expect(secure.secure);
    try std.testing.expectEqualStrings("/", secure.path);
    try std.testing.expectEqualStrings("mcp.example.com", secure.host_header);
    try std.testing.expectError(error.InvalidUrl, Target.parse(arena, "ftp://x/"));
    try std.testing.expectError(error.InvalidUrl, Target.parse(arena, "http:///nohost"));
}
