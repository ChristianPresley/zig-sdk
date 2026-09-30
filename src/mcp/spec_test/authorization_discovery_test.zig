//! Tests for the authorization server discovery, client registration and security rules of the specification.
//! A mock authorization server on a loopback port records the requests of the OAuth client.
const std = @import("std");
const Io = std.Io;
const http = std.http;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const json = mcp.json;
const types = mcp.types;
const OAuthClient = mcp.auth.OAuthClient;

const redirect_uri = "http://127.0.0.1:41893/callback";

// -- Mock protected resource and authorization server ------------------------------------------

const StateMode = enum { echo, wrong, missing };

const Config = struct {
    /// The path of the protected resource metadata.
    prm_path: []const u8 = "/.well-known/oauth-protected-resource/mcp",
    /// The path part of the issuer identifier.
    issuer_path: []const u8 = "",
    /// The path of the authorization server metadata.
    metadata_path: []const u8 = "/.well-known/oauth-authorization-server",
    /// Replaces the `issuer` value of the metadata document.
    metadata_issuer: ?[]const u8 = null,
    /// The raw JSON of `code_challenge_methods_supported`. Null omits the field.
    pkce_methods: ?[]const u8 = "[\"S256\"]",
    cimd_supported: bool = false,
    registration_status: http.Status = .created,
    /// The `client_id` of a successful registration.
    client_id: []const u8 = "dcr-client",
    state_mode: StateMode = .echo,
    /// The `resource` of the metadata at `prm_path`.
    prm_resource: PrmResource = .server,
    /// Also serve metadata at the root location, with the origin as `resource`.
    root_prm: bool = false,
};

const PrmResource = enum {
    /// The server URL.
    server,
    /// The origin, as metadata at the root location names it.
    origin,
    /// The server URL with an uppercase scheme.
    server_uppercase,
};

const Mock = struct {
    io: Io,
    gpa: Allocator,
    config: Config,
    listener: Io.net.Server,
    stopping: std.atomic.Value(bool) = .init(false),
    future: Io.Future(void),
    base: []u8,
    issuer: []u8,
    stopped: bool = false,
    lock: Io.Mutex = .init,
    /// One `METHOD /path` entry per request, in order.
    log: std.ArrayList([]u8) = .empty,
    register_body: ?[]u8 = null,
    authorize_query: ?[]u8 = null,
    token_body: ?[]u8 = null,
    /// Replaces the issuer in `authorization_servers` of the protected resource metadata.
    prm_issuer: ?[]const u8 = null,

    fn start(self: *Mock, config: Config) !void {
        const io = std.testing.io;
        const gpa = std.testing.allocator;
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .config = config,
            .listener = try address.listen(io, .{ .reuse_address = true }),
            .future = undefined,
            .base = undefined,
            .issuer = undefined,
        };
        self.base = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}", .{self.listener.socket.address.getPort()});
        self.issuer = try std.mem.concat(gpa, u8, &.{ self.base, config.issuer_path });
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    /// Stops the server. The recorded requests stay readable until `deinit`.
    fn stop(self: *Mock) void {
        if (self.stopped) return;
        self.stopped = true;
        mcp.util.wake.cancelAcceptLoop(self.io, &self.future, self.listener.socket.address, &self.stopping);
        self.listener.deinit(self.io);
    }

    fn deinit(self: *Mock) void {
        self.stop();
        for (self.log.items) |entry| self.gpa.free(entry);
        self.log.deinit(self.gpa);
        for ([_]?[]u8{ self.register_body, self.authorize_query, self.token_body }) |b| if (b) |x| self.gpa.free(x);
        self.gpa.free(self.issuer);
        self.gpa.free(self.base);
    }

    fn acceptLoop(self: *Mock) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch return;
            if (self.stopping.load(.acquire)) {
                stream.close(self.io);
                return;
            }
            self.serveConnection(stream);
        }
    }

    fn serveConnection(self: *Mock, stream: Io.net.Stream) void {
        defer stream.close(self.io);
        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [4096]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        var writer = stream.writer(self.io, &write_buf);
        var server: http.Server = .init(&reader.interface, &writer.interface);
        var request = server.receiveHead() catch return;
        self.handle(&request) catch {};
    }

    fn keep(self: *Mock, slot: *?[]u8, text: []const u8) !void {
        if (slot.*) |old| self.gpa.free(old);
        slot.* = try self.gpa.dupe(u8, text);
    }

    fn handle(self: *Mock, request: *http.Server.Request) !void {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const method = request.head.method;
        const target = try arena.dupe(u8, request.head.target);
        if (request.head.transfer_encoding == .none and request.head.content_length == null) request.head.content_length = 0;
        var body_buf: [4096]u8 = undefined;
        const body = try request.readerExpectNone(&body_buf).allocRemaining(arena, .limited(1 << 16));
        const path_end = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
        const path = target[0..path_end];
        const query = if (path_end < target.len) target[path_end + 1 ..] else "";

        self.lock.lockUncancelable(self.io);
        {
            defer self.lock.unlock(self.io);
            try self.log.append(self.gpa, try std.fmt.allocPrint(self.gpa, "{s} {s}", .{ @tagName(method), path }));
            if (std.mem.eql(u8, path, "/register")) try self.keep(&self.register_body, body);
            if (std.mem.eql(u8, path, "/authorize")) try self.keep(&self.authorize_query, query);
            if (std.mem.eql(u8, path, "/token")) try self.keep(&self.token_body, body);
        }

        const c = self.config;
        const json_type = [_]http.Header{.{ .name = "content-type", .value = "application/json" }};
        const as_issuer = blk: {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            break :blk try arena.dupe(u8, self.prm_issuer orelse self.issuer);
        };
        if (method == .GET and std.mem.eql(u8, path, c.prm_path)) {
            const resource = switch (c.prm_resource) {
                .server => try std.fmt.allocPrint(arena, "{s}/mcp", .{self.base}),
                .origin => self.base,
                .server_uppercase => try std.fmt.allocPrint(arena, "HTTP{s}/mcp", .{self.base["http".len..]}),
            };
            const doc = try std.fmt.allocPrint(arena, "{{\"resource\":\"{s}\",\"authorization_servers\":[\"{s}\"]}}", .{ resource, as_issuer });
            return request.respond(doc, .{ .keep_alive = false, .extra_headers = &json_type });
        }
        if (method == .GET and c.root_prm and std.mem.eql(u8, path, "/.well-known/oauth-protected-resource")) {
            const doc = try std.fmt.allocPrint(arena, "{{\"resource\":\"{s}\",\"authorization_servers\":[\"{s}\"]}}", .{ self.base, as_issuer });
            return request.respond(doc, .{ .keep_alive = false, .extra_headers = &json_type });
        }
        if (method == .GET and std.mem.eql(u8, path, c.metadata_path)) {
            var aw: Io.Writer.Allocating = .init(arena);
            const w = &aw.writer;
            try w.print("{{\"issuer\":\"{s}\",\"authorization_endpoint\":\"{s}/authorize\",\"token_endpoint\":\"{s}/token\",\"registration_endpoint\":\"{s}/register\"", .{ c.metadata_issuer orelse self.issuer, self.base, self.base, self.base });
            try w.writeAll(",\"response_types_supported\":[\"code\"],\"token_endpoint_auth_methods_supported\":[\"none\"]");
            if (c.pkce_methods) |m| try w.print(",\"code_challenge_methods_supported\":{s}", .{m});
            try w.print(",\"client_id_metadata_document_supported\":{s}}}", .{if (c.cimd_supported) "true" else "false"});
            return request.respond(aw.written(), .{ .keep_alive = false, .extra_headers = &json_type });
        }
        if (method == .POST and std.mem.eql(u8, path, "/register")) {
            const reply = if (c.registration_status == .created)
                try std.fmt.allocPrint(arena, "{{\"client_id\":\"{s}\"}}", .{c.client_id})
            else
                "{\"error\":\"invalid_redirect_uri\",\"error_description\":\"The redirect URI is not allowed\"}";
            return request.respond(reply, .{ .status = c.registration_status, .keep_alive = false, .extra_headers = &json_type });
        }
        if (method == .GET and std.mem.eql(u8, path, "/authorize")) {
            const state = queryParam(arena, query, "state") orelse "";
            const location = switch (c.state_mode) {
                .echo => try std.fmt.allocPrint(arena, "{s}?code=code-1&state={s}", .{ redirect_uri, state }),
                .wrong => try std.fmt.allocPrint(arena, "{s}?code=code-1&state=forged", .{redirect_uri}),
                .missing => try std.fmt.allocPrint(arena, "{s}?code=code-1", .{redirect_uri}),
            };
            return request.respond("", .{ .status = .found, .keep_alive = false, .extra_headers = &.{.{ .name = "location", .value = location }} });
        }
        if (method == .POST and std.mem.eql(u8, path, "/token")) {
            return request.respond("{\"access_token\":\"tok-1\",\"token_type\":\"Bearer\",\"expires_in\":3600}", .{ .keep_alive = false, .extra_headers = &json_type });
        }
        return request.respond("Not Found", .{ .status = .not_found, .keep_alive = false });
    }

    /// The recorded requests. Call it after `stop`.
    fn requests(self: *const Mock) []const []const u8 {
        return self.log.items;
    }

    fn sawRequest(self: *const Mock, entry: []const u8) bool {
        for (self.log.items) |e| if (std.mem.eql(u8, e, entry)) return true;
        return false;
    }
};

/// The decoded value of one parameter of a query string or a form body.
fn queryParam(arena: Allocator, query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (!std.mem.eql(u8, pair[0..eq], name)) continue;
        const buf = arena.dupe(u8, pair[eq + 1 ..]) catch return null;
        for (buf) |*ch| if (ch.* == '+') {
            ch.* = ' ';
        };
        return std.Uri.percentDecodeInPlace(buf);
    }
    return null;
}

/// Runs one challenge through a new OAuth client. Returns a copy of the token.
fn runChallenge(mock: *Mock, arena: Allocator, options: OAuthClient.Options, hint: bool) OAuthClient.Error![]const u8 {
    var client: OAuthClient = .init(std.testing.io, std.testing.allocator, options);
    defer client.deinit();
    const server_url = try std.fmt.allocPrint(arena, "{s}/mcp", .{mock.base});
    const header: ?[]const u8 = if (hint) try std.fmt.allocPrint(arena, "Bearer resource_metadata=\"{s}{s}\"", .{ mock.base, mock.config.prm_path }) else null;
    const token = try client.handleChallenge(arena, server_url, 401, header, 1);
    return arena.dupe(u8, token);
}

fn expectRequests(mock: *const Mock, expected: []const []const u8) !void {
    const got = mock.requests();
    if (got.len != expected.len) {
        std.debug.print("expected {d} requests, got {d}:\n", .{ expected.len, got.len });
        for (got) |g| std.debug.print("  {s}\n", .{g});
        return error.TestUnexpectedResult;
    }
    for (expected, got) |e, g| try std.testing.expectEqualStrings(e, g);
}

const http_options: OAuthClient.Options = .{ .allow_http = true };

// -- Authorization server discovery --------------------------------------------------------------

test "client tries the three well-known locations in order for an issuer with a path" {
    var mock: Mock = undefined;
    try mock.start(.{ .issuer_path = "/tenant1", .metadata_path = "/tenant1/.well-known/openid-configuration" });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const token = try runChallenge(&mock, arena_state.allocator(), http_options, true);
    mock.stop();
    try std.testing.expectEqualStrings("tok-1", token);
    try expectRequests(&mock, &.{
        "GET /.well-known/oauth-protected-resource/mcp",
        "GET /.well-known/oauth-authorization-server/tenant1",
        "GET /.well-known/openid-configuration/tenant1",
        "GET /tenant1/.well-known/openid-configuration",
        "POST /register",
        "GET /authorize",
        "POST /token",
    });
}

test "client uses openid configuration with path insertion for an issuer with a path" {
    var mock: Mock = undefined;
    try mock.start(.{ .issuer_path = "/tenant1", .metadata_path = "/.well-known/openid-configuration/tenant1" });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const token = try runChallenge(&mock, arena_state.allocator(), http_options, true);
    mock.stop();
    try std.testing.expectEqualStrings("tok-1", token);
    try expectRequests(&mock, &.{
        "GET /.well-known/oauth-protected-resource/mcp",
        "GET /.well-known/oauth-authorization-server/tenant1",
        "GET /.well-known/openid-configuration/tenant1",
        "POST /register",
        "GET /authorize",
        "POST /token",
    });
}

test "client without a challenge URL falls back to well-known resource and server metadata in order" {
    var mock: Mock = undefined;
    try mock.start(.{ .prm_path = "/.well-known/oauth-protected-resource", .metadata_path = "/.well-known/openid-configuration" });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const token = try runChallenge(&mock, arena_state.allocator(), http_options, false);
    mock.stop();
    try std.testing.expectEqualStrings("tok-1", token);
    try expectRequests(&mock, &.{
        "GET /.well-known/oauth-protected-resource/mcp",
        "GET /.well-known/oauth-protected-resource",
        "GET /.well-known/oauth-authorization-server",
        "GET /.well-known/openid-configuration",
        "POST /register",
        "GET /authorize",
        "POST /token",
    });
}

test "client rejects authorization server metadata whose issuer differs from the queried issuer" {
    var mock: Mock = undefined;
    try mock.start(.{ .metadata_issuer = "https://honest.example" });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.IssuerMismatch, runChallenge(&mock, arena_state.allocator(), http_options, true));
    mock.stop();
    // No endpoint of the rejected document is used.
    try expectRequests(&mock, &.{
        "GET /.well-known/oauth-protected-resource/mcp",
        "GET /.well-known/oauth-authorization-server",
    });
}

// -- Client registration ---------------------------------------------------------------------------

test "client registers dynamically with application_type native and its redirect URI" {
    var mock: Mock = undefined;
    try mock.start(.{});
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // A metadata document URL is configured, but the server does not support it.
    var options = http_options;
    options.registration = .{ .client_metadata_url = "https://client.example/meta.json" };
    _ = try runChallenge(&mock, arena, options, true);
    mock.stop();
    try std.testing.expect(mock.sawRequest("POST /register"));
    const reg = try json.parseTree(arena, mock.register_body.?);
    try std.testing.expectEqualStrings("native", reg.object.get("application_type").?.string);
    const uris = reg.object.get("redirect_uris").?.array.items;
    try std.testing.expectEqual(1, uris.len);
    try std.testing.expectEqualStrings(redirect_uri, uris[0].string);
    try std.testing.expectEqualStrings("dcr-client", queryParam(arena, mock.authorize_query.?, "client_id").?);
}

test "client prefers pre-registered credentials over metadata documents and registration" {
    var mock: Mock = undefined;
    try mock.start(.{ .cimd_supported = true });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var options = http_options;
    options.registration = .{ .pre_registered = &.{.{ .client_id = "pre-client" }} };
    _ = try runChallenge(&mock, arena, options, true);
    mock.stop();
    try std.testing.expect(!mock.sawRequest("POST /register"));
    try std.testing.expectEqualStrings("pre-client", queryParam(arena, mock.authorize_query.?, "client_id").?);
    try std.testing.expectEqualStrings("pre-client", queryParam(arena, mock.token_body.?, "client_id").?);
}

test "client uses its metadata document URL as client_id when the server supports it" {
    var mock: Mock = undefined;
    try mock.start(.{ .cimd_supported = true });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var options = http_options;
    options.registration = .{ .client_metadata_url = "https://client.example/meta.json" };
    _ = try runChallenge(&mock, arena, options, true);
    mock.stop();
    try std.testing.expect(!mock.sawRequest("POST /register"));
    try std.testing.expectEqualStrings("https://client.example/meta.json", queryParam(arena, mock.authorize_query.?, "client_id").?);
}

test "client returns an error when dynamic registration fails" {
    var mock: Mock = undefined;
    try mock.start(.{ .registration_status = .bad_request });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.RegistrationFailed, runChallenge(&mock, arena_state.allocator(), http_options, true));
    mock.stop();
    try expectRequests(&mock, &.{
        "GET /.well-known/oauth-protected-resource/mcp",
        "GET /.well-known/oauth-authorization-server",
        "POST /register",
    });
}

test "client keeps the error of a rejected registration for the application" {
    var mock: Mock = undefined;
    try mock.start(.{ .registration_status = .bad_request });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var client: OAuthClient = .init(std.testing.io, std.testing.allocator, http_options);
    defer client.deinit();
    const server_url = try std.fmt.allocPrint(arena, "{s}/mcp", .{mock.base});
    try std.testing.expectError(error.RegistrationFailed, client.handleChallenge(arena, server_url, 401, null, 1));
    mock.stop();
    const failure = (try client.lastFailure(arena)).?;
    try std.testing.expectEqual(OAuthClient.Failure.Step.registration, failure.step);
    try std.testing.expectEqual(400, failure.status);
    try std.testing.expectEqualStrings("invalid_redirect_uri", failure.code.?);
    try std.testing.expectEqualStrings("The redirect URI is not allowed", failure.description.?);
}

test "client registers with application_type web when the application sets it" {
    var mock: Mock = undefined;
    try mock.start(.{});
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var options = http_options;
    options.application_type = .web;
    options.redirect_uri = "https://app.example.com/callback";
    _ = try runChallenge(&mock, arena, options, true);
    mock.stop();
    const reg = try json.parseTree(arena, mock.register_body.?);
    try std.testing.expectEqualStrings("web", reg.object.get("application_type").?.string);
    try std.testing.expectEqualStrings("https://app.example.com/callback", reg.object.get("redirect_uris").?.array.items[0].string);
}

test "client refuses a metadata document URL without https or without a path" {
    for ([_][]const u8{ "http://client.example/meta.json", "https://client.example", "https://client.example/" }) |url| {
        var mock: Mock = undefined;
        try mock.start(.{ .cimd_supported = true });
        defer mock.deinit();
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        var options = http_options;
        options.registration = .{ .client_metadata_url = url };
        try std.testing.expectError(error.InvalidClientMetadataUrl, runChallenge(&mock, arena_state.allocator(), options, true));
        mock.stop();
        try std.testing.expect(!mock.sawRequest("POST /register"));
        try std.testing.expect(!mock.sawRequest("GET /authorize"));
    }
}

// -- Authorization server binding ------------------------------------------------------------------

/// Two authorization servers. `a` also serves the protected resource metadata. `move` points
/// the metadata to `b`.
const Pair = struct {
    a: Mock,
    b: Mock,

    fn start(self: *Pair) !void {
        try self.a.start(.{ .client_id = "dcr-a" });
        errdefer self.a.deinit();
        try self.b.start(.{ .client_id = "dcr-b" });
    }

    fn deinit(self: *Pair) void {
        self.a.deinit();
        self.b.deinit();
    }

    fn move(self: *Pair) void {
        self.a.lock.lockUncancelable(self.a.io);
        defer self.a.lock.unlock(self.a.io);
        self.a.prm_issuer = self.b.issuer;
    }

    fn challenge(self: *Pair, client: *OAuthClient, arena: Allocator) OAuthClient.Error![]const u8 {
        const server_url = try std.fmt.allocPrint(arena, "{s}/mcp", .{self.a.base});
        return client.handleChallenge(arena, server_url, 401, null, 1);
    }
};

test "client registers again and keeps no credentials of the old authorization server after a change" {
    var pair: Pair = undefined;
    try pair.start();
    defer pair.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var client: OAuthClient = .init(std.testing.io, std.testing.allocator, http_options);
    defer client.deinit();
    _ = try pair.challenge(&client, arena);
    pair.move();
    _ = try pair.challenge(&client, arena);
    pair.a.stop();
    pair.b.stop();
    try std.testing.expectEqualStrings("dcr-a", queryParam(arena, pair.a.authorize_query.?, "client_id").?);
    // The client registers with the new server and sends only the new client_id to it.
    try std.testing.expect(pair.b.sawRequest("POST /register"));
    try std.testing.expectEqualStrings("dcr-b", queryParam(arena, pair.b.authorize_query.?, "client_id").?);
    try std.testing.expectEqualStrings("dcr-b", queryParam(arena, pair.b.token_body.?, "client_id").?);
}

test "client uses the pre-registered credentials of each issuer and fails for an unknown issuer" {
    var pair: Pair = undefined;
    try pair.start();
    defer pair.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // One entry for each authorization server: separate state per issuer.
    const both = [_]OAuthClient.Credentials{
        .{ .issuer = pair.a.issuer, .client_id = "pre-a" },
        .{ .issuer = pair.b.issuer, .client_id = "pre-b" },
    };
    var options = http_options;
    options.registration = .{ .pre_registered = &both };
    var client: OAuthClient = .init(std.testing.io, std.testing.allocator, options);
    defer client.deinit();
    _ = try pair.challenge(&client, arena);
    try std.testing.expectEqualStrings("pre-a", queryParam(arena, pair.a.authorize_query.?, "client_id").?);
    pair.move();
    _ = try pair.challenge(&client, arena);
    try std.testing.expectEqualStrings("pre-b", queryParam(arena, pair.b.authorize_query.?, "client_id").?);

    // Only credentials for the old server: an error, and nothing goes to the new server.
    {
        pair.a.lock.lockUncancelable(pair.a.io);
        defer pair.a.lock.unlock(pair.a.io);
        pair.a.prm_issuer = null;
    }
    const only_a = [_]OAuthClient.Credentials{.{ .issuer = pair.a.issuer, .client_id = "pre-a" }};
    options.registration = .{ .pre_registered = &only_a };
    var strict: OAuthClient = .init(std.testing.io, std.testing.allocator, options);
    defer strict.deinit();
    _ = try pair.challenge(&strict, arena);
    const b_requests = pair.b.requests().len;
    pair.move();
    try std.testing.expectError(error.IssuerNotRegistered, pair.challenge(&strict, arena));
    try std.testing.expect(strict.currentToken() == null);
    pair.a.stop();
    pair.b.stop();
    // The new server got only the metadata request: no authorization and no token request.
    try std.testing.expectEqual(b_requests + 1, pair.b.requests().len);
    try std.testing.expectEqualStrings("GET /.well-known/oauth-authorization-server", pair.b.requests()[b_requests]);
}

test "client binds pre-registered credentials without an issuer to the first authorization server" {
    var pair: Pair = undefined;
    try pair.start();
    defer pair.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var options = http_options;
    options.registration = .{ .pre_registered = &.{.{ .client_id = "pre-any" }} };
    var client: OAuthClient = .init(std.testing.io, std.testing.allocator, options);
    defer client.deinit();
    _ = try pair.challenge(&client, arena);
    _ = try pair.challenge(&client, arena);
    pair.move();
    try std.testing.expectError(error.IssuerNotRegistered, pair.challenge(&client, arena));
    pair.a.stop();
    pair.b.stop();
    try std.testing.expect(!pair.b.sawRequest("GET /authorize"));
    try std.testing.expect(!pair.b.sawRequest("POST /token"));
}

// -- Security considerations -----------------------------------------------------------------------

test "client sends the resource parameter and an S256 PKCE challenge in authorization and token requests" {
    var mock: Mock = undefined;
    try mock.start(.{});
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    _ = try runChallenge(&mock, arena, http_options, true);
    mock.stop();
    const resource = try std.fmt.allocPrint(arena, "{s}/mcp", .{mock.base});
    const q = mock.authorize_query.?;
    try std.testing.expectEqualStrings("code", queryParam(arena, q, "response_type").?);
    try std.testing.expectEqualStrings(resource, queryParam(arena, q, "resource").?);
    try std.testing.expectEqualStrings(redirect_uri, queryParam(arena, q, "redirect_uri").?);
    try std.testing.expectEqualStrings("S256", queryParam(arena, q, "code_challenge_method").?);
    try std.testing.expect(queryParam(arena, q, "state").?.len > 0);
    const challenge = queryParam(arena, q, "code_challenge").?;
    const t = mock.token_body.?;
    try std.testing.expectEqualStrings("authorization_code", queryParam(arena, t, "grant_type").?);
    try std.testing.expectEqualStrings(resource, queryParam(arena, t, "resource").?);
    // The verifier hashes to the challenge (RFC 7636 S256).
    const verifier = queryParam(arena, t, "code_verifier").?;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    var encoded: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&encoded, &digest);
    try std.testing.expectEqualStrings(&encoded, challenge);
}

test "client sends the most specific resource that the server declares" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    {
        // Metadata at the path-inserted and at the root location: the client reads the
        // path-inserted document first and sends the server URL.
        var mock: Mock = undefined;
        try mock.start(.{ .root_prm = true });
        defer mock.deinit();
        _ = try runChallenge(&mock, arena, http_options, false);
        mock.stop();
        try std.testing.expect(!mock.sawRequest("GET /.well-known/oauth-protected-resource"));
        const resource = try std.fmt.allocPrint(arena, "{s}/mcp", .{mock.base});
        try std.testing.expectEqualStrings(resource, queryParam(arena, mock.authorize_query.?, "resource").?);
        try std.testing.expectEqualStrings(resource, queryParam(arena, mock.token_body.?, "resource").?);
    }
    {
        // Metadata only at the root location: the identifier of the server is its origin
        // (RFC 9728 section 3.3), so the client sends the origin.
        var mock: Mock = undefined;
        try mock.start(.{ .prm_path = "/.well-known/oauth-protected-resource", .prm_resource = .origin });
        defer mock.deinit();
        _ = try runChallenge(&mock, arena, http_options, false);
        mock.stop();
        try std.testing.expectEqualStrings(mock.base, queryParam(arena, mock.authorize_query.?, "resource").?);
        try std.testing.expectEqualStrings(mock.base, queryParam(arena, mock.token_body.?, "resource").?);
    }
}

test "client accepts a metadata resource with an uppercase scheme and host" {
    var mock: Mock = undefined;
    try mock.start(.{ .prm_resource = .server_uppercase });
    defer mock.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    _ = try runChallenge(&mock, arena, http_options, true);
    mock.stop();
    const resource = queryParam(arena, mock.authorize_query.?, "resource").?;
    try std.testing.expect(std.mem.startsWith(u8, resource, "HTTP://"));
    try std.testing.expect(mcp.auth.common.uriEql(resource, try std.fmt.allocPrint(arena, "{s}/mcp", .{mock.base})));
}

test "client refuses to proceed when the metadata does not offer S256 PKCE" {
    const cases = [_]Config{
        // OAuth metadata without code_challenge_methods_supported.
        .{ .pkce_methods = null },
        // OpenID Connect Discovery metadata without code_challenge_methods_supported.
        .{ .pkce_methods = null, .metadata_path = "/.well-known/openid-configuration" },
        // Only the plain method.
        .{ .pkce_methods = "[\"plain\"]" },
    };
    for (cases) |config| {
        var mock: Mock = undefined;
        try mock.start(config);
        defer mock.deinit();
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        try std.testing.expectError(error.PkceUnsupported, runChallenge(&mock, arena_state.allocator(), http_options, true));
        mock.stop();
        try std.testing.expect(!mock.sawRequest("POST /register"));
        try std.testing.expect(!mock.sawRequest("GET /authorize"));
    }
}

test "client discards an authorization response with a wrong or missing state" {
    for ([_]StateMode{ .wrong, .missing }) |mode| {
        var mock: Mock = undefined;
        try mock.start(.{ .state_mode = mode });
        defer mock.deinit();
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        try std.testing.expectError(error.StateMismatch, runChallenge(&mock, arena_state.allocator(), http_options, true));
        mock.stop();
        try std.testing.expect(mock.sawRequest("GET /authorize"));
        try std.testing.expect(!mock.sawRequest("POST /token"));
    }
}

test "client refuses plain http metadata, registration, authorization and token endpoints by default" {
    for ([_]bool{ true, false }) |hint| {
        var mock: Mock = undefined;
        try mock.start(.{});
        defer mock.deinit();
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        try std.testing.expectError(error.InsecureEndpoint, runChallenge(&mock, arena_state.allocator(), .{}, hint));
        mock.stop();
        // The client sends no request at all, not even for the metadata.
        try expectRequests(&mock, &.{});
    }
}

test "client refuses a redirect URI that is not https or a loopback URI" {
    for ([_][]const u8{ "http://app.example.com/callback", "com.example.app:/callback", "http://localhost.example.com/cb" }) |uri| {
        var mock: Mock = undefined;
        try mock.start(.{});
        defer mock.deinit();
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        var options = http_options;
        options.redirect_uri = uri;
        try std.testing.expectError(error.InvalidRedirectUri, runChallenge(&mock, arena_state.allocator(), options, true));
        mock.stop();
        try expectRequests(&mock, &.{});
    }
    // Loopback and https redirect URIs are accepted.
    for ([_][]const u8{ "http://localhost:3000/callback", "http://[::1]:3000/callback", "https://app.example.com/callback" }) |uri| {
        var mock: Mock = undefined;
        try mock.start(.{});
        defer mock.deinit();
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var options = http_options;
        options.redirect_uri = uri;
        _ = try runChallenge(&mock, arena, options, true);
        mock.stop();
        try std.testing.expectEqualStrings(uri, queryParam(arena, mock.authorize_query.?, "redirect_uri").?);
    }
}

// -- Resource server -------------------------------------------------------------------------------

const secret = "g3b-auth-test-secret-with-32-bytes!!";
var handler_calls: std.atomic.Value(u32) = .init(0);

fn fixedNow() i64 {
    return 1000;
}

fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    _ = handler_calls.fetchAdd(1, .monotonic);
    const p = ctx.principal() orelse return error.NoPrincipal;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{p.subject orelse "?"}) };
}

const call_whoami = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"whoami\"}}";

fn postWhoami(client: *http.Client, arena: Allocator, base: []const u8, token: []const u8) !struct { status: http.Status, body: []u8 } {
    const url = try std.mem.concat(arena, u8, &.{ base, "/mcp" });
    const headers = [_]http.Header{
        .{ .name = "accept", .value = "application/json, text/event-stream" },
        .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
        .{ .name = "mcp-method", .value = "tools/call" },
        .{ .name = "mcp-name", .value = "whoami" },
        .{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", token }) },
    };
    var req = try client.request(.POST, try std.Uri.parse(url), .{
        .redirect_behavior = .unhandled,
        .extra_headers = &headers,
        .headers = .{ .content_type = .{ .override = "application/json" }, .accept_encoding = .{ .override = "identity" } },
    });
    defer req.deinit();
    try req.sendBodyComplete(try arena.dupe(u8, call_whoami));
    var redirect_buf: [256]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    const status = response.head.status;
    var transfer: [4096]u8 = undefined;
    const text = try response.reader(&transfer).allocRemaining(arena, .limited(1 << 20));
    return .{ .status = status, .body = text };
}

fn serveIgnoringErrors(t: *mcp.transport.http.Server) void {
    t.serve() catch {};
}

test "http server rejects tokens for another audience or without an audience before the handler runs" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "g3b-auth", .version = "1" } });
    defer server.deinit();
    try server.addToolJson(.{ .name = "whoami" }, whoami);
    const keys = [_]mcp.auth.jwt.Key{.{ .alg = .HS256, .material = .{ .secret = secret } }};
    var jv: mcp.auth.JwtVerifier = .{ .options = .{ .keys = &keys, .audience = "http://127.0.0.1/mcp" }, .clock = .{ .fixed = fixedNow } };
    const rs: mcp.auth.ResourceServer = .{
        .resource = "http://127.0.0.1/mcp",
        .resource_metadata_url = "http://127.0.0.1/.well-known/oauth-protected-resource/mcp",
        .authorization_servers = &.{"http://127.0.0.1:9/as"},
        .verifier = jv.verifier(),
    };
    var transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = 0, .auth = &rs });
    try transport.bind();
    var future = try io.concurrent(serveIgnoringErrors, .{&transport});
    defer {
        transport.shutdown();
        future.await(io);
        transport.deinit();
    }
    var client: http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{transport.bound_port});

    handler_calls.store(0, .monotonic);
    const bad_tokens = [_][]const u8{
        try mcp.auth.jwt.signHs256(arena, "{\"sub\":\"mallory\",\"aud\":\"http://other.example/mcp\",\"exp\":2000}", secret, null),
        try mcp.auth.jwt.signHs256(arena, "{\"sub\":\"mallory\",\"exp\":2000}", secret, null),
    };
    for (bad_tokens) |token| {
        const reply = try postWhoami(&client, arena, base, token);
        try std.testing.expectEqual(http.Status.unauthorized, reply.status);
        try std.testing.expect(std.mem.indexOf(u8, reply.body, "\"result\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, reply.body, "mallory") == null);
    }
    try std.testing.expectEqual(0, handler_calls.load(.monotonic));

    // A token for this server reaches the handler.
    const good = try mcp.auth.jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"http://127.0.0.1/mcp\",\"exp\":2000}", secret, null);
    const ok = try postWhoami(&client, arena, base, good);
    try std.testing.expectEqual(http.Status.ok, ok.status);
    try std.testing.expect(std.mem.indexOf(u8, ok.body, "alice") != null);
    try std.testing.expectEqual(1, handler_calls.load(.monotonic));
}
