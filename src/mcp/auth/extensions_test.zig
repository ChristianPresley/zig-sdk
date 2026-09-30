//! The authorization extensions end to end. An MCP client with `ClientCredentials` or
//! `EnterpriseClient` calls the loopback MCP server. A fake authorization server and a fake
//! IdP issue the tokens. The fake authorization server checks ID-JAGs with `IdJagValidator`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const mcp = @import("../../mcp.zig");
const json = mcp.json;
const types = mcp.types;
const jwt = mcp.auth.jwt;
const common = mcp.auth.common;
const enterprise = mcp.auth.enterprise;
const HttpServer = mcp.transport.http.Server;
const HttpClient = mcp.transport.HttpClient;

const rs_secret = "extension-test-resource-secret-32!";
const cc_client_id = "cc-client";
const cc_client_secret = "cc-secret";
const mcp_client_id = "mcp-client";
const mcp_client_secret = "mcp-secret";
const idp_client_id = "idp-client";
const idp_client_secret = "idp-secret";
const id_token = "id-token-of-alice";

fn now(io: Io) i64 {
    return Io.Clock.Timestamp.now(io, .real).raw.toSeconds();
}

/// A fake authorization server and IdP on one loopback port. The authorization server issuer
/// is the origin. The IdP issuer is the origin with the path `/idp`.
const FakeAuth = struct {
    const Mode = enum { client_secret_basic, private_key_jwt, enterprise };

    io: Io,
    mode: Mode,
    listener: Io.net.Server,
    stopping: std.atomic.Value(bool) = .init(false),
    future: Io.Future(void),
    base: []u8,
    idp_issuer: []u8,
    /// The canonical URI of the MCP server.
    resource: []const u8 = "",
    expires_in: i64 = 3600,
    /// The public key of the client for `private_key_jwt`.
    client_key: [97]u8 = undefined,
    client_key_len: usize = 0,
    /// The key that the IdP signs ID-JAGs with.
    idp_key: jwt.SigningKey,
    token_requests: u32 = 0,
    exchange_requests: u32 = 0,
    /// The first problem that a check found, for the test to report.
    failure: ?[]const u8 = null,

    fn start(self: *FakeAuth, mode: Mode) !void {
        const io = std.testing.io;
        const gpa = std.testing.allocator;
        const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        self.* = .{
            .io = io,
            .mode = mode,
            .listener = undefined,
            .future = undefined,
            .base = undefined,
            .idp_issuer = undefined,
            .idp_key = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{5} ** 32) },
        };
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.listener = try address.listen(io, .{ .reuse_address = true });
        const port = self.listener.socket.address.getPort();
        self.base = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}", .{port});
        self.idp_issuer = try std.fmt.allocPrint(gpa, "{s}/idp", .{self.base});
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    fn stop(self: *FakeAuth) void {
        const gpa = std.testing.allocator;
        mcp.util.wake.cancelAcceptLoop(self.io, &self.future, self.listener.socket.address, &self.stopping);
        self.listener.deinit(self.io);
        gpa.free(self.base);
        gpa.free(self.idp_issuer);
    }

    fn fail(self: *FakeAuth, why: []const u8) void {
        if (self.failure == null) self.failure = why;
    }

    fn acceptLoop(self: *FakeAuth) void {
        while (!self.stopping.load(.acquire)) {
            var stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            if (self.stopping.load(.acquire)) return;
            self.serveOne(stream) catch {};
        }
    }

    fn serveOne(self: *FakeAuth, stream: Io.net.Stream) !void {
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var read_buf: [8192]u8 = undefined;
        var write_buf: [8192]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        var writer = stream.writer(self.io, &write_buf);
        var server: http.Server = .init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        const target = try arena.dupe(u8, request.head.target);
        var authorization: ?[]const u8 = null;
        var it = request.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
            authorization = try arena.dupe(u8, h.value);
        };
        var body: []const u8 = "";
        if (request.head.method == .POST) {
            var body_buf: [1024]u8 = undefined;
            body = try request.readerExpectNone(&body_buf).allocRemaining(arena, .limited(1 << 16));
        }
        const reply = try self.route(arena, target, authorization, body);
        try request.respond(reply.body, .{
            .status = reply.status,
            .keep_alive = false,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
        });
    }

    const Reply = struct { status: http.Status = .ok, body: []const u8 };

    fn route(self: *FakeAuth, arena: Allocator, target: []const u8, authorization: ?[]const u8, body: []const u8) !Reply {
        if (std.mem.eql(u8, target, "/.well-known/oauth-authorization-server")) {
            const methods = switch (self.mode) {
                .client_secret_basic, .enterprise => "[\"client_secret_basic\"]",
                .private_key_jwt => "[\"private_key_jwt\"]",
            };
            const grant = if (self.mode == .enterprise) enterprise.grant_type_jwt_bearer else "client_credentials";
            return .{ .body = try std.fmt.allocPrint(arena,
                \\{{"issuer":"{s}","token_endpoint":"{s}/token","token_endpoint_auth_methods_supported":{s},"token_endpoint_auth_signing_alg_values_supported":["ES256"],"grant_types_supported":["{s}"],"authorization_grant_profiles_supported":["{s}"]}}
            , .{ self.base, self.base, methods, grant, enterprise.grant_profile }) };
        }
        if (std.mem.eql(u8, target, "/.well-known/oauth-authorization-server/idp")) {
            return .{ .body = try std.fmt.allocPrint(arena,
                \\{{"issuer":"{s}","token_endpoint":"{s}/token","token_endpoint_auth_methods_supported":["client_secret_post"],"grant_types_supported":["{s}"]}}
            , .{ self.idp_issuer, self.idp_issuer, enterprise.grant_type_token_exchange }) };
        }
        const form = try common.parseForm(arena, body);
        if (std.mem.eql(u8, target, "/idp/token")) return self.idpToken(arena, form);
        if (std.mem.eql(u8, target, "/token")) return self.asToken(arena, form, authorization);
        return .{ .status = .not_found, .body = "{}" };
    }

    fn oauthError(code: []const u8) Reply {
        return .{ .status = .bad_request, .body = if (std.mem.eql(u8, code, "invalid_client")) "{\"error\":\"invalid_client\"}" else "{\"error\":\"invalid_grant\"}" };
    }

    fn expect(self: *FakeAuth, form: std.StringHashMapUnmanaged([]const u8), key: []const u8, want: ?[]const u8) bool {
        const got = form.get(key);
        if (want == null and got == null) return true;
        if (want != null and got != null and std.mem.eql(u8, want.?, got.?)) return true;
        self.fail(key);
        return false;
    }

    fn checkBasic(self: *FakeAuth, arena: Allocator, authorization: ?[]const u8, id: []const u8, secret: []const u8) !bool {
        const want = try common.basicCredentials(arena, id, secret);
        if (authorization != null and std.mem.eql(u8, authorization.?, want)) return true;
        self.fail("basic credentials");
        return false;
    }

    /// Issue an access token for the MCP server, as an HS256 JWT.
    fn accessToken(self: *FakeAuth, arena: Allocator, subject: []const u8, scope: ?[]const u8) !Reply {
        const t = now(self.io);
        const payload = try std.fmt.allocPrint(arena, "{{\"sub\":{f},\"aud\":{f},\"exp\":{d},\"scope\":{f}}}", .{ std.json.fmt(subject, .{}), std.json.fmt(self.resource, .{}), t + 3600, std.json.fmt(scope orelse "", .{}) });
        const token = try jwt.signHs256(arena, payload, rs_secret, null);
        return .{ .body = try std.fmt.allocPrint(arena, "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":{d}}}", .{ token, self.expires_in }) };
    }

    fn asToken(self: *FakeAuth, arena: Allocator, form: std.StringHashMapUnmanaged([]const u8), authorization: ?[]const u8) !Reply {
        self.token_requests += 1;
        switch (self.mode) {
            .client_secret_basic => {
                if (!self.expect(form, "grant_type", "client_credentials")) return oauthError("invalid_grant");
                if (!self.expect(form, "resource", self.resource)) return oauthError("invalid_grant");
                if (!self.expect(form, "client_id", null)) return oauthError("invalid_client");
                if (!try self.checkBasic(arena, authorization, cc_client_id, cc_client_secret)) return oauthError("invalid_client");
                return self.accessToken(arena, cc_client_id, form.get("scope"));
            },
            .private_key_jwt => {
                if (!self.expect(form, "grant_type", "client_credentials")) return oauthError("invalid_grant");
                if (!self.expect(form, "resource", self.resource)) return oauthError("invalid_grant");
                if (!self.expect(form, "client_id", null)) return oauthError("invalid_client");
                if (!self.expect(form, "client_assertion_type", common.client_assertion_type_jwt)) return oauthError("invalid_client");
                const keys = [_]jwt.Key{.{ .alg = .ES256, .material = .{ .p256 = self.client_key[0..self.client_key_len] } }};
                const claims = jwt.verify(arena, form.get("client_assertion") orelse "", .{ .keys = &keys, .issuer = cc_client_id, .audience = self.base }, now(self.io)) catch {
                    self.fail("client assertion");
                    return oauthError("invalid_client");
                };
                if (!std.mem.eql(u8, claims.subject orelse "", cc_client_id) or claims.jwt_id == null or claims.expires_at == null) {
                    self.fail("client assertion claims");
                    return oauthError("invalid_client");
                }
                return self.accessToken(arena, cc_client_id, form.get("scope"));
            },
            .enterprise => {
                if (!self.expect(form, "grant_type", enterprise.grant_type_jwt_bearer)) return oauthError("invalid_grant");
                if (!try self.checkBasic(arena, authorization, mcp_client_id, mcp_client_secret)) return oauthError("invalid_client");
                var buf: [97]u8 = undefined;
                const trusted = [_]enterprise.TrustedIssuer{.{ .issuer = self.idp_issuer, .keys = &.{self.idp_key.verificationKey(&buf, null)} }};
                const validator: enterprise.IdJagValidator = .{ .issuer = self.base, .trusted_issuers = &trusted, .resources = &.{self.resource} };
                const grant = validator.validate(arena, form.get("assertion") orelse "", mcp_client_id, now(self.io)) catch |e| {
                    self.fail(@errorName(e));
                    return .{ .status = .bad_request, .body = try enterprise.errorResponse(arena, e) };
                };
                const scope = try std.mem.join(arena, " ", grant.scopes);
                return self.accessToken(arena, grant.subject, scope);
            },
        }
    }

    fn idpToken(self: *FakeAuth, arena: Allocator, form: std.StringHashMapUnmanaged([]const u8)) !Reply {
        self.exchange_requests += 1;
        if (!self.expect(form, "grant_type", enterprise.grant_type_token_exchange)) return oauthError("invalid_grant");
        if (!self.expect(form, "requested_token_type", enterprise.token_type_id_jag)) return oauthError("invalid_grant");
        if (!self.expect(form, "audience", self.base)) return oauthError("invalid_grant");
        if (!self.expect(form, "resource", self.resource)) return oauthError("invalid_grant");
        if (!self.expect(form, "subject_token", id_token)) return oauthError("invalid_grant");
        if (!self.expect(form, "subject_token_type", "urn:ietf:params:oauth:token-type:id_token")) return oauthError("invalid_grant");
        if (!self.expect(form, "client_id", idp_client_id)) return oauthError("invalid_client");
        if (!self.expect(form, "client_secret", idp_client_secret)) return oauthError("invalid_client");
        const t = now(self.io);
        const payload = try std.fmt.allocPrint(arena, "{{\"jti\":\"j-{d}\",\"iss\":{f},\"sub\":\"alice\",\"aud\":{f},\"resource\":{f},\"client_id\":\"{s}\",\"exp\":{d},\"iat\":{d},\"scope\":{f}}}", .{
            self.exchange_requests,
            std.json.fmt(self.idp_issuer, .{}),
            std.json.fmt(self.base, .{}),
            std.json.fmt(self.resource, .{}),
            mcp_client_id,
            t + 300,
            t,
            std.json.fmt(form.get("scope") orelse "", .{}),
        });
        const grant = try jwt.sign(arena, &self.idp_key, payload, .{ .typ = enterprise.jwt_type });
        return .{ .body = try std.fmt.allocPrint(arena, "{{\"issued_token_type\":\"{s}\",\"access_token\":\"{s}\",\"token_type\":\"N_A\",\"expires_in\":300}}", .{ enterprise.token_type_id_jag, grant }) };
    }
};

/// Answers with the subject of the principal.
fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const p = ctx.principal() orelse return error.NoPrincipal;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{p.subject orelse "?"}) };
}

/// The MCP server as a resource server that trusts the fake authorization server.
const McpFixture = struct {
    server: mcp.Server,
    keys: [1]jwt.Key,
    jv: mcp.auth.JwtVerifier,
    rs: mcp.auth.ResourceServer,
    transport: HttpServer,
    future: Io.Future(void),
    url: []u8,
    resource_metadata_url: []u8,
    authorization_servers: [1][]const u8,

    fn start(self: *McpFixture, auth: *FakeAuth) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.server = try mcp.Server.init(gpa, io, .{
            .info = .{ .name = "ext-test", .version = "1" },
            .authorization_extensions = .{ .client_credentials = true, .enterprise_managed = true },
        });
        try self.server.addToolJson(.{ .name = "whoami" }, whoami);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .auth = &self.rs });
        try self.transport.bind();
        self.url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/mcp", .{self.transport.bound_port});
        self.resource_metadata_url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/.well-known/oauth-protected-resource/mcp", .{self.transport.bound_port});
        self.keys = .{.{ .alg = .HS256, .material = .{ .secret = rs_secret } }};
        self.jv = .{ .options = .{ .keys = &self.keys, .audience = self.url }, .clock = .{ .io = io } };
        self.authorization_servers = .{auth.base};
        self.rs = .{
            .resource = self.url,
            .resource_metadata_url = self.resource_metadata_url,
            .authorization_servers = &self.authorization_servers,
            .scopes_supported = &.{"mcp:read"},
            .verifier = self.jv.verifier(),
        };
        auth.resource = self.url;
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
    }

    fn serveIgnoringErrors(t: *HttpServer) void {
        t.serve() catch {};
    }

    fn stop(self: *McpFixture) void {
        const gpa = std.testing.allocator;
        self.transport.shutdown();
        self.future.await(std.testing.io);
        self.transport.deinit();
        self.server.deinit();
        gpa.free(self.url);
        gpa.free(self.resource_metadata_url);
    }

    /// Call `whoami` through an MCP client with the given provider. Returns the subject.
    fn whoamiWith(self: *McpFixture, arena: Allocator, provider: mcp.auth.Provider, extension: []const u8) ![]const u8 {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        const transport = try HttpClient.init(io, gpa, .{ .url = self.url, .auth_provider = provider });
        defer transport.deinit();
        var client: mcp.Client = .init(gpa, io, .{
            .info = .{ .name = "ext-client", .version = "1" },
            .capabilities = try mcp.auth.withExtension(arena, .{}, extension),
        });
        defer client.deinit();
        client.connect(transport.transport());
        const result = try client.callTool(arena, "whoami", null, .{});
        return result.content[0].text.text;
    }
};

test "client credentials: client_secret_basic with a cached token" {
    var auth: FakeAuth = undefined;
    try auth.start(.client_secret_basic);
    defer auth.stop();
    var fixture: McpFixture = undefined;
    try fixture.start(&auth);
    defer fixture.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cc: mcp.auth.ClientCredentials = .init(std.testing.io, std.testing.allocator, .{
        .client = .{ .client_secret = .{ .client_id = cc_client_id, .client_secret = cc_client_secret } },
        .allow_http = true,
    });
    defer cc.deinit();
    const ext = mcp.auth.client_credentials.extension_id;
    try std.testing.expectEqualStrings(cc_client_id, try fixture.whoamiWith(arena, cc.provider(), ext));
    try std.testing.expectEqualStrings(cc_client_id, try fixture.whoamiWith(arena, cc.provider(), ext));
    if (auth.failure) |f| std.debug.print("fake authorization server: {s}\n", .{f});
    try std.testing.expect(auth.failure == null);
    try std.testing.expectEqual(1, auth.token_requests);
    try std.testing.expectEqualStrings("mcp:read", cc.scope.?);
}

test "client credentials: private_key_jwt and renewal before expiry" {
    var auth: FakeAuth = undefined;
    try auth.start(.private_key_jwt);
    defer auth.stop();
    var fixture: McpFixture = undefined;
    try fixture.start(&auth);
    defer fixture.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const key: jwt.SigningKey = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{8} ** 32) };
    const point = key.es256.public_key.toUncompressedSec1();
    @memcpy(auth.client_key[0..point.len], &point);
    auth.client_key_len = point.len;
    // The token lives 30 seconds, less than the margin: every request gets a new token first.
    auth.expires_in = 30;

    var cc: mcp.auth.ClientCredentials = .init(std.testing.io, std.testing.allocator, .{
        .client = .{ .private_key_jwt = .{ .client_id = cc_client_id, .key = &key, .kid = "k1" } },
        .allow_http = true,
    });
    defer cc.deinit();
    const ext = mcp.auth.client_credentials.extension_id;
    // The challenge gets the first token, and the retry of the request renews it.
    try std.testing.expectEqualStrings(cc_client_id, try fixture.whoamiWith(arena, cc.provider(), ext));
    try std.testing.expectEqual(2, auth.token_requests);
    try std.testing.expectEqualStrings(cc_client_id, try fixture.whoamiWith(arena, cc.provider(), ext));
    try std.testing.expectEqual(3, auth.token_requests);
    if (auth.failure) |f| std.debug.print("fake authorization server: {s}\n", .{f});
    try std.testing.expect(auth.failure == null);

    // A key that the server does not accept stops the flow with the server error code.
    auth.expires_in = 3600;
    const other: jwt.SigningKey = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{4} ** 32) };
    var bad: mcp.auth.ClientCredentials = .init(std.testing.io, std.testing.allocator, .{
        .client = .{ .private_key_jwt = .{ .client_id = cc_client_id, .key = &other } },
        .allow_http = true,
    });
    defer bad.deinit();
    try std.testing.expectError(error.TokenRequestFailed, bad.handleChallenge(arena, fixture.url, 401, null, 1));
    try std.testing.expectEqualStrings("invalid_client", bad.last_error.?);
}

test "enterprise-managed authorization: token exchange, JWT bearer grant and validation" {
    var auth: FakeAuth = undefined;
    try auth.start(.enterprise);
    defer auth.stop();
    var fixture: McpFixture = undefined;
    try fixture.start(&auth);
    defer fixture.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var ema: mcp.auth.EnterpriseClient = .init(std.testing.io, std.testing.allocator, .{
        .idp = .{ .issuer = auth.idp_issuer, .client = .{ .client_secret = .{ .client_id = idp_client_id, .client_secret = idp_client_secret } } },
        .assertion = .{ .static = .{ .token = id_token } },
        .client = .{ .client_secret = .{ .client_id = mcp_client_id, .client_secret = mcp_client_secret } },
        .require_grant_profile = true,
        .allow_http = true,
    });
    defer ema.deinit();
    const ext = enterprise.extension_id;
    try std.testing.expectEqualStrings("alice", try fixture.whoamiWith(arena, ema.provider(), ext));
    try std.testing.expectEqualStrings("alice", try fixture.whoamiWith(arena, ema.provider(), ext));
    if (auth.failure) |f| std.debug.print("fake authorization server: {s}\n", .{f});
    try std.testing.expect(auth.failure == null);
    try std.testing.expectEqual(1, auth.exchange_requests);
    try std.testing.expectEqual(1, auth.token_requests);

    // A client id that the ID-JAG does not name: the server refuses the grant.
    var wrong: mcp.auth.EnterpriseClient = .init(std.testing.io, std.testing.allocator, .{
        .idp = .{ .token_endpoint = try std.fmt.allocPrint(arena, "{s}/token", .{auth.idp_issuer}), .client = .{ .client_secret = .{ .client_id = idp_client_id, .client_secret = idp_client_secret, .method = .client_secret_post } } },
        .assertion = .{ .static = .{ .token = id_token } },
        .client = .{ .client_secret = .{ .client_id = "intruder", .client_secret = mcp_client_secret } },
        .allow_http = true,
    });
    defer wrong.deinit();
    try std.testing.expectError(error.TokenRequestFailed, wrong.handleChallenge(arena, fixture.url, 401, null, 1));
}

test "id-jag validation rules" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const key: jwt.SigningKey = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{6} ** 32) };
    var buf: [97]u8 = undefined;
    const trusted = [_]enterprise.TrustedIssuer{.{ .issuer = "https://idp.example", .keys = &.{key.verificationKey(&buf, null)} }};
    const Replay = struct {
        seen_jti: ?[]const u8 = null,
        fn seen(userdata: ?*anyopaque, issuer: []const u8, jti: []const u8, expires_at: i64) bool {
            _ = issuer;
            _ = expires_at;
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.seen_jti) |s| if (std.mem.eql(u8, s, jti)) return true;
            self.seen_jti = jti;
            return false;
        }
    };
    var replay: Replay = .{};
    const v: enterprise.IdJagValidator = .{
        .issuer = "https://as.example/",
        .trusted_issuers = &trusted,
        .resources = &.{"https://mcp.example/"},
        .replay = .{ .userdata = &replay, .seen = Replay.seen },
    };
    const good = "{\"jti\":\"1\",\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"email\":\"u@example.com\",\"aud\":\"https://as.example/\",\"resource\":\"https://mcp.example/\",\"client_id\":\"c1\",\"exp\":1300,\"iat\":1000,\"scope\":\"chat.read chat.history\"}";
    const token = try jwt.sign(arena, &key, good, .{ .typ = enterprise.jwt_type });
    const grant = try v.validate(arena, token, "c1", 1100);
    try std.testing.expectEqualStrings("U1", grant.subject);
    try std.testing.expectEqualStrings("u@example.com", grant.email.?);
    try std.testing.expectEqual(2, grant.scopes.len);
    try std.testing.expectEqualStrings("https://mcp.example/", grant.resources[0]);
    try std.testing.expectError(error.Replayed, v.validate(arena, token, "c1", 1100));

    const Case = struct { payload: []const u8, typ: ?[]const u8 = enterprise.jwt_type, client: []const u8 = "c1", now: i64 = 1100, err: enterprise.ValidateError };
    const cases = [_]Case{
        .{ .payload = good, .typ = "JWT", .err = error.TypeMismatch },
        .{ .payload = good, .typ = null, .err = error.TypeMismatch },
        .{ .payload = good, .client = "c2", .err = error.ClientMismatch },
        .{ .payload = good, .now = 1400, .err = error.Expired },
        .{ .payload = "{\"jti\":\"2\",\"iss\":\"https://evil.example\",\"sub\":\"U1\",\"aud\":\"https://as.example/\",\"client_id\":\"c1\",\"exp\":1300,\"iat\":1000}", .err = error.UntrustedIssuer },
        .{ .payload = "{\"jti\":\"3\",\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"aud\":[\"https://as.example/\",\"https://other/\"],\"client_id\":\"c1\",\"exp\":1300,\"iat\":1000}", .err = error.AudienceMismatch },
        .{ .payload = "{\"jti\":\"4\",\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"aud\":\"https://as.example\",\"client_id\":\"c1\",\"exp\":1300,\"iat\":1000}", .err = error.AudienceMismatch },
        .{ .payload = "{\"jti\":\"5\",\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"aud\":\"https://as.example/\",\"exp\":1300,\"iat\":1000}", .err = error.Malformed },
        .{ .payload = "{\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"aud\":\"https://as.example/\",\"client_id\":\"c1\",\"exp\":1300,\"iat\":1000}", .err = error.Malformed },
        .{ .payload = "{\"jti\":\"6\",\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"aud\":\"https://as.example/\",\"resource\":\"https://other.example/\",\"client_id\":\"c1\",\"exp\":1300,\"iat\":1000}", .err = error.ResourceMismatch },
        .{ .payload = "{\"jti\":\"7\",\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"aud\":\"https://as.example/\",\"client_id\":\"c1\",\"exp\":9000,\"iat\":1000}", .err = error.LifetimeTooLong },
    };
    for (cases) |case| {
        const t = try jwt.sign(arena, &key, case.payload, .{ .typ = case.typ });
        try std.testing.expectError(case.err, v.validate(arena, t, case.client, case.now));
        const body = try enterprise.errorResponse(arena, case.err);
        try std.testing.expectEqualStrings("invalid_grant", json.getString(try json.parseTree(arena, body), "error").?);
    }
    // An array `aud` with one element is valid.
    const one = try jwt.sign(arena, &key, "{\"jti\":\"8\",\"iss\":\"https://idp.example\",\"sub\":\"U1\",\"aud\":[\"https://as.example/\"],\"client_id\":\"c1\",\"exp\":1300,\"iat\":1000}", .{ .typ = enterprise.jwt_type });
    _ = try v.validate(arena, one, "c1", 1100);
}

test "the server advertises the authorization extensions" {
    var server = try mcp.Server.init(std.testing.allocator, std.testing.io, .{
        .info = .{ .name = "s", .version = "1" },
        .authorization_extensions = .{ .client_credentials = true, .enterprise_managed = true },
    });
    defer server.deinit();
    const ext = server.options.capabilities.extensions.?.object;
    try std.testing.expect(ext.get(mcp.auth.client_credentials.extension_id) != null);
    try std.testing.expect(ext.get(enterprise.extension_id) != null);
}
