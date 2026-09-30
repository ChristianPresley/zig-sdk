//! The icon fetcher against a loopback HTTPS server on the SDK TLS server. The server records
//! the request headers and answers by path: images, redirects, oversize bodies and delays.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const mcp = @import("../../mcp.zig");
const tls = mcp.tls;
const icons = mcp.icons;
const types = mcp.types;

const IconServer = struct {
    chain: tls.CertChain,
    chains: [1]*const tls.CertChain,
    tls_server: tls.Server,
    listener: Io.net.Server,
    port: u16,
    future: Io.Future(void),
    ca: tls.CaSet,
    requests: std.atomic.Value(u32) = .init(0),
    /// The header names of the last request, lowercase and joined with commas.
    header_names: [512]u8 = undefined,
    header_names_len: usize = 0,
    /// The `accept` value of the last request.
    accept: [128]u8 = undefined,
    accept_len: usize = 0,

    fn start(self: *IconServer) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.* = .{ .chain = undefined, .chains = undefined, .tls_server = undefined, .listener = undefined, .port = 0, .future = undefined, .ca = .init(gpa) };
        errdefer self.ca.deinit();
        try self.ca.addFile(io, "test/fixtures/tls/pem/ca.crt");
        self.chain = try tls.CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/chain.crt", "test/fixtures/tls/pem/chain-leaf.key");
        errdefer self.chain.deinit();
        self.chains = .{&self.chain};
        self.tls_server = try tls.Server.init(.{ .chains = &self.chains, .alpn = &.{"http/1.1"} });
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.listener = try address.listen(io, .{});
        errdefer self.listener.deinit(io);
        self.port = self.listener.socket.address.getPort();
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    fn stop(self: *IconServer) void {
        const io = std.testing.io;
        _ = self.future.cancel(io);
        self.listener.deinit(io);
        self.chain.deinit();
        self.ca.deinit();
    }

    fn url(self: *const IconServer, buf: []u8, path: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "https://127.0.0.1:{d}{s}", .{ self.port, path }) catch unreachable;
    }

    fn tlsSetup(self: *const IconServer) icons.TlsSetup {
        return .{ .trust = .{ .ca_set = &self.ca } };
    }

    fn headerNames(self: *const IconServer) []const u8 {
        return self.header_names[0..self.header_names_len];
    }

    fn acceptLoop(self: *IconServer) void {
        const io = std.testing.io;
        while (true) {
            const stream = self.listener.accept(io) catch return;
            defer stream.close(io);
            self.serveOne(stream) catch |e| switch (e) {
                error.Canceled => return,
                else => {},
            };
        }
    }

    fn serveOne(self: *IconServer, stream: Io.net.Stream) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        const read_buf = try gpa.alloc(u8, tls.Connection.min_input_buffer_len);
        defer gpa.free(read_buf);
        const write_buf = try gpa.alloc(u8, tls.Connection.min_output_buffer_len);
        defer gpa.free(write_buf);
        const tls_read = try gpa.alloc(u8, tls.Connection.min_read_buffer_len);
        defer gpa.free(tls_read);
        const tls_write = try gpa.alloc(u8, 16 << 10);
        defer gpa.free(tls_write);
        var reader = stream.reader(io, read_buf);
        var writer = stream.writer(io, write_buf);
        var conn = try self.tls_server.accept(&reader.interface, &writer.interface, .{
            .io = io,
            .read_buffer = tls_read,
            .write_buffer = tls_write,
            .allow_truncation_attacks = true,
        });
        defer {
            conn.end() catch {};
            writer.interface.flush() catch {};
            conn.deinit();
        }
        var server: http.Server = .init(&conn.reader, &conn.writer);
        var request = try server.receiveHead();
        self.record(&request);
        const target = request.head.target;
        const out = &conn.writer;

        var location_buf: [128]u8 = undefined;
        if (std.mem.eql(u8, target, "/icon.png")) {
            try request.respond(icons.test_png, .{ .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "image/png" }} });
        } else if (std.mem.eql(u8, target, "/octet.png")) {
            try request.respond(icons.test_png, .{ .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "application/octet-stream" }} });
        } else if (std.mem.eql(u8, target, "/icon.svg")) {
            try request.respond("<svg xmlns=\"http://www.w3.org/2000/svg\"/>", .{ .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "image/svg+xml" }} });
        } else if (std.mem.eql(u8, target, "/mismatch")) {
            try request.respond(icons.test_gif, .{ .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "image/png" }} });
        } else if (redirectTarget(target)) |next| {
            const location = switch (next) {
                .same => "/icon.png",
                .loop => "/loop",
                .cross => std.fmt.bufPrint(&location_buf, "https://localhost:{d}/icon.png", .{self.port}) catch unreachable,
                .downgrade => std.fmt.bufPrint(&location_buf, "http://127.0.0.1:{d}/icon.png", .{self.port}) catch unreachable,
                .scheme => "javascript:alert(1)",
            };
            try request.respond("", .{ .status = .found, .keep_alive = false, .extra_headers = &.{.{ .name = "location", .value = location }} });
        } else if (std.mem.eql(u8, target, "/big")) {
            // The declared length is over the limit.
            try out.writeAll("HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncontent-length: 2000000\r\nconnection: close\r\n\r\n");
            try out.writeAll(icons.test_png);
        } else if (std.mem.eql(u8, target, "/stream")) {
            // No declared length: the fetcher stops the read at the limit.
            try out.writeAll("HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n");
            var chunk: [64 << 10]u8 = undefined;
            @memset(&chunk, 0);
            @memcpy(chunk[0..icons.test_png.len], icons.test_png);
            for (0..20) |_| {
                try out.print("{x}\r\n", .{chunk.len});
                try out.writeAll(&chunk);
                try out.writeAll("\r\n");
                try out.flush();
                try writer.interface.flush();
            }
            try out.writeAll("0\r\n\r\n");
        } else if (std.mem.eql(u8, target, "/slow")) {
            try io.sleep(.fromSeconds(3), .awake);
            try request.respond(icons.test_png, .{ .keep_alive = false });
        } else {
            try request.respond("", .{ .status = .not_found, .keep_alive = false });
        }
        try out.flush();
        try writer.interface.flush();
    }

    const Redirect = enum { same, loop, cross, downgrade, scheme };

    fn redirectTarget(target: []const u8) ?Redirect {
        if (std.mem.eql(u8, target, "/redirect")) return .same;
        if (std.mem.eql(u8, target, "/loop")) return .loop;
        if (std.mem.eql(u8, target, "/cross")) return .cross;
        if (std.mem.eql(u8, target, "/downgrade")) return .downgrade;
        if (std.mem.eql(u8, target, "/scheme")) return .scheme;
        return null;
    }

    fn record(self: *IconServer, request: *const http.Server.Request) void {
        var n: usize = 0;
        var it = request.iterateHeaders();
        while (it.next()) |h| {
            if (n > 0 and n < self.header_names.len) {
                self.header_names[n] = ',';
                n += 1;
            }
            for (h.name) |c| if (n < self.header_names.len) {
                self.header_names[n] = std.ascii.toLower(c);
                n += 1;
            };
            if (std.ascii.eqlIgnoreCase(h.name, "accept")) {
                const len = @min(h.value.len, self.accept.len);
                @memcpy(self.accept[0..len], h.value[0..len]);
                self.accept_len = len;
            }
        }
        self.header_names_len = n;
        _ = self.requests.fetchAdd(1, .release);
    }
};

fn fetchPath(s: *IconServer, arena: Allocator, path: []const u8, options: icons.FetchOptions) icons.Error!icons.Image {
    var buf: [96]u8 = undefined;
    var server_buf: [96]u8 = undefined;
    var o = options;
    if (o.server_url == null) o.server_url = s.url(&server_buf, "/mcp");
    if (o.tls == null) o.tls = s.tlsSetup();
    return icons.fetch(std.testing.io, std.testing.allocator, arena, .{ .src = s.url(&buf, path) }, o);
}

test "icon fetch over https: headers, redirects and limits" {
    var s: IconServer = undefined;
    try s.start();
    defer s.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const image = try fetchPath(&s, arena, "/icon.png", .{});
    try std.testing.expectEqual(icons.Format.png, image.format);
    try std.testing.expectEqualStrings(icons.test_png, image.bytes);
    try std.testing.expectEqual(@as(?u32, 1), image.width);
    // Only these headers go out: no cookie, no authorization, no content-length on a GET.
    try std.testing.expectEqualStrings("host,connection,accept,accept-encoding", s.headerNames());
    try std.testing.expectEqualStrings("image/png, image/jpeg", s.accept[0..s.accept_len]);
    try std.testing.expectEqual(1, s.requests.load(.acquire));

    // A generic content type with the icon mimeType.
    var buf: [96]u8 = undefined;
    var server_buf: [96]u8 = undefined;
    const octet = try icons.fetch(std.testing.io, std.testing.allocator, arena, .{ .src = s.url(&buf, "/octet.png"), .mimeType = "image/png" }, .{
        .server_url = s.url(&server_buf, "/mcp"),
        .tls = s.tlsSetup(),
    });
    try std.testing.expectEqual(icons.Format.png, octet.format);

    // A same-origin redirect is followed.
    _ = try fetchPath(&s, arena, "/redirect", .{});
    try std.testing.expectEqual(4, s.requests.load(.acquire));
    // A redirect to another origin or scheme is refused before any connection.
    try std.testing.expectError(error.RedirectRefused, fetchPath(&s, arena, "/cross", .{}));
    try std.testing.expectError(error.RedirectRefused, fetchPath(&s, arena, "/downgrade", .{}));
    try std.testing.expectError(error.RedirectRefused, fetchPath(&s, arena, "/scheme", .{}));
    try std.testing.expectEqual(7, s.requests.load(.acquire));
    // The hop limit: the first request and three redirects, then the fourth redirect fails.
    try std.testing.expectError(error.TooManyRedirects, fetchPath(&s, arena, "/loop", .{}));
    try std.testing.expectEqual(11, s.requests.load(.acquire));
    try std.testing.expectError(error.TooManyRedirects, fetchPath(&s, arena, "/loop", .{ .max_redirect_hops = 0 }));

    // Content checks.
    try std.testing.expectError(error.MimeMismatch, fetchPath(&s, arena, "/mismatch", .{}));
    try std.testing.expectError(error.FormatNotAllowed, fetchPath(&s, arena, "/icon.svg", .{}));
    try std.testing.expectError(error.TooLarge, fetchPath(&s, arena, "/big", .{}));
    try std.testing.expectError(error.TooLarge, fetchPath(&s, arena, "/stream", .{}));
    try std.testing.expectError(error.HttpStatus, fetchPath(&s, arena, "/missing", .{}));

    // The origin rule applies before any connection.
    const before = s.requests.load(.acquire);
    try std.testing.expectError(error.OriginNotAllowed, fetchPath(&s, arena, "/icon.png", .{ .server_url = "https://127.0.0.1:1/mcp" }));
    try std.testing.expectError(error.OriginNotAllowed, fetchPath(&s, arena, "/icon.png", .{ .server_url = "http://127.0.0.1/mcp" }));
    try std.testing.expectEqual(before, s.requests.load(.acquire));
    // A trusted origin passes without a server URL.
    var origin_buf: [64]u8 = undefined;
    const origin = std.fmt.bufPrint(&origin_buf, "https://127.0.0.1:{d}", .{s.port}) catch unreachable;
    _ = try icons.fetch(std.testing.io, std.testing.allocator, arena, .{ .src = s.url(&buf, "/icon.png") }, .{
        .policy = .{ .trusted_origins = &.{origin} },
        .tls = s.tlsSetup(),
    });

    // A certificate that the client does not trust.
    try std.testing.expectError(error.TlsFailed, fetchPath(&s, arena, "/icon.png", .{ .tls = .{ .trust = .self_signed } }));
}

test "icon fetch timeout" {
    var s: IconServer = undefined;
    try s.start();
    defer s.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.Timeout, fetchPath(&s, arena_state.allocator(), "/slow", .{ .limits = .{ .timeout = .fromMilliseconds(200) } }));
}

const HookState = struct {
    calls: u32 = 0,

    fn decode(userdata: ?*anyopaque, arena: Allocator, image: icons.Image) anyerror!icons.Image {
        _ = arena;
        const self: *HookState = @ptrCast(@alignCast(userdata.?));
        self.calls += 1;
        if (image.format == .svg and std.mem.indexOf(u8, image.bytes, "<script") != null) return error.Unsafe;
        return image;
    }
};

test "Client.fetchIcon: policy, limits and the decoder hook" {
    var s: IconServer = undefined;
    try s.start();
    defer s.stop();
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server_buf: [96]u8 = undefined;
    const server_url = s.url(&server_buf, "/mcp");
    var png_buf: [96]u8 = undefined;
    var svg_buf: [96]u8 = undefined;
    const png_icon: types.Icon = .{ .src = s.url(&png_buf, "/icon.png"), .sizes = &.{"16x16"} };
    const svg_icon: types.Icon = .{ .src = s.url(&svg_buf, "/icon.svg"), .mimeType = "image/svg+xml", .sizes = &.{"any"} };
    const list = [_]types.Icon{ png_icon, svg_icon };

    // Without the hook, SVG stays off even when the policy turns it on.
    var plain: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .icons = .{ .formats = .{ .svg = true } } });
    defer plain.deinit();
    try std.testing.expectError(error.FormatNotAllowed, plain.fetchIcon(arena, svg_icon, .{ .server_url = server_url, .tls = s.tlsSetup() }));
    try std.testing.expectEqualStrings(png_icon.src, plain.selectIcon(&list, .{ .size = 64 }, server_url).?.src);
    const png = try plain.fetchIcon(arena, png_icon, .{ .server_url = server_url, .tls = s.tlsSetup() });
    try std.testing.expectEqual(icons.Format.png, png.format);

    // With the hook, SVG passes and the hook sees every image.
    var state: HookState = .{};
    var hooked: mcp.Client = .init(gpa, io, .{
        .info = .{ .name = "cli", .version = "1" },
        .icons = .{ .formats = .{ .svg = true } },
        .hooks = .{ .icon_decoder = HookState.decode, .userdata = &state },
    });
    defer hooked.deinit();
    try std.testing.expectEqualStrings(svg_icon.src, hooked.selectIcon(&list, .{ .size = 64 }, server_url).?.src);
    const svg = try hooked.fetchIcon(arena, svg_icon, .{ .server_url = server_url, .tls = s.tlsSetup() });
    try std.testing.expectEqual(icons.Format.svg, svg.format);
    _ = try hooked.fetchIcon(arena, png_icon, .{ .server_url = server_url, .tls = s.tlsSetup() });
    try std.testing.expectEqual(2, state.calls);
    try std.testing.expectError(error.DecoderFailed, hooked.fetchIcon(arena, .{ .src = "data:image/svg+xml,%3Csvg%3E%3Cscript%2F%3E%3C%2Fsvg%3E" }, .{}));

    // The client limits apply.
    var small: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" }, .limits = .{ .icon = .{ .max_bytes = 16 } } });
    defer small.deinit();
    try std.testing.expectError(error.TooLarge, small.fetchIcon(arena, png_icon, .{ .server_url = server_url, .tls = s.tlsSetup() }));
}
