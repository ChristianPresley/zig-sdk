//! The authorization server end to end. MCP clients with `OAuthClient`, `ClientCredentials`,
//! `EnterpriseClient` and `WorkloadIdentity` get tokens from `AuthorizationServer`. They call an
//! MCP server whose `ResourceServer` verifies the JWTs with the JWK set of the authorization
//! server. The tests of the error cases call `handle` directly.
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
const dpop = mcp.auth.dpop;
const enterprise = mcp.auth.enterprise;
const workload_identity = mcp.auth.workload_identity;
const as_mod = mcp.auth.authorization_server;
const AuthorizationServer = mcp.auth.AuthorizationServer;
const HttpServer = mcp.transport.http.Server;
const HttpClient = mcp.transport.HttpClient;
const tls = mcp.tls;
const TestProxy = @import("../transport/proxy_test.zig").TestProxy;

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const cc_secret = "cc-secret-0123456789abcdef";
const ema_secret = "ema-secret-0123456789abcdef";
const workload_issuer = "https://workload.example.org";
const workload_subject = "spiffe://example.org/ns/prod/sa/agent";

fn es256(seed: u8) jwt.SigningKey {
    return .{ .es256 = Ecdsa.KeyPair.generateDeterministic([_]u8{seed} ** 32) catch unreachable };
}

fn realNow(io: Io) i64 {
    return Io.Clock.Timestamp.now(io, .real).raw.toSeconds();
}

/// A JWK set with the public key of `key` and the `kid`.
fn jwksOf(arena: Allocator, key: *const jwt.SigningKey, kid: []const u8) ![]const u8 {
    const jwk = try jwt.publicJwk(arena, key);
    return std.fmt.allocPrint(arena, "{{\"keys\":[{{\"kid\":\"{s}\",{s}]}}", .{ kid, jwk[1..] });
}

/// Answers with the subject and the client of the principal.
fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const p = ctx.principal() orelse return error.NoPrincipal;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}|{s}", .{ p.subject orelse "?", p.client_id orelse "?" }) };
}

/// A small loopback HTTP server for the client metadata document and the fake IdP. It answers
/// one request on each connection, over TLS when `tls_server` is set.
const TinyServer = struct {
    io: Io,
    listener: Io.net.Server,
    stopping: std.atomic.Value(bool) = .init(false),
    future: Io.Future(void),
    tls_server: ?*const tls.Server,
    ctx: *anyopaque,
    handler: *const fn (ctx: *anyopaque, arena: Allocator, target: []const u8, body: []const u8) anyerror![]const u8,
    requests: std.atomic.Value(u32) = .init(0),

    fn start(self: *TinyServer, tls_server: ?*const tls.Server, ctx: *anyopaque, handler: *const fn (ctx: *anyopaque, arena: Allocator, target: []const u8, body: []const u8) anyerror![]const u8) !void {
        const io = std.testing.io;
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.* = .{ .io = io, .listener = try address.listen(io, .{ .reuse_address = true }), .future = undefined, .tls_server = tls_server, .ctx = ctx, .handler = handler };
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    fn port(self: *const TinyServer) u16 {
        return self.listener.socket.address.getPort();
    }

    fn stop(self: *TinyServer) void {
        mcp.util.wake.cancelAcceptLoop(self.io, &self.future, self.listener.socket.address, &self.stopping);
        self.listener.deinit(self.io);
    }

    fn acceptLoop(self: *TinyServer) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            if (self.stopping.load(.acquire)) return;
            self.serveOne(stream) catch {};
        }
    }

    fn serveOne(self: *TinyServer, stream: Io.net.Stream) !void {
        const gpa = std.testing.allocator;
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const read_buf = try arena.alloc(u8, tls.Connection.min_input_buffer_len);
        const write_buf = try arena.alloc(u8, tls.Connection.min_output_buffer_len);
        var reader = stream.reader(self.io, read_buf);
        var writer = stream.writer(self.io, write_buf);
        var tls_conn: tls.Connection = undefined;
        var tls_active = false;
        defer if (tls_active) {
            tls_conn.end() catch {};
            tls_conn.deinit();
        };
        if (self.tls_server) |ts| {
            tls_conn = try ts.accept(&reader.interface, &writer.interface, .{
                .io = self.io,
                .read_buffer = try arena.alloc(u8, tls.Connection.min_read_buffer_len),
                .write_buffer = try arena.alloc(u8, 16 * 1024),
                .allow_truncation_attacks = true,
            });
            tls_active = true;
        }
        const in: *Io.Reader = if (tls_active) &tls_conn.reader else &reader.interface;
        const out: *Io.Writer = if (tls_active) &tls_conn.writer else &writer.interface;
        var server: http.Server = .init(in, out);
        var request = try server.receiveHead();
        _ = self.requests.fetchAdd(1, .monotonic);
        const target = try arena.dupe(u8, request.head.target);
        if (request.head.transfer_encoding == .none and request.head.content_length == null) request.head.content_length = 0;
        var body_buf: [1024]u8 = undefined;
        const body = try request.readerExpectNone(&body_buf).allocRemaining(arena, .limited(1 << 16));
        const reply = try self.handler(self.ctx, arena, target, body);
        try request.respond(reply, .{ .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }} });
    }
};

/// The parts of a test world: an MCP server, the authorization server, and optional helpers.
const Features = struct {
    /// The MCP server accepts DPoP-bound tokens.
    dpop_policy: bool = false,
    /// The authorization server requires a DPoP nonce.
    as_nonce: bool = false,
    /// An HTTPS server with a client ID metadata document.
    cimd: bool = false,
    /// A fake IdP that issues ID-JAGs.
    idp: bool = false,
    /// The MCP server and the authorization server use HTTPS at `localhost`. The certificate
    /// comes from the test CA, and `World.ca_bundle` has that CA.
    https: bool = false,
};

const World = struct {
    arena_state: std.heap.ArenaAllocator,
    // The MCP server.
    server: mcp.Server,
    transport: HttpServer,
    mcp_future: Io.Future(void),
    jv: mcp.auth.JwtVerifier,
    rs: mcp.auth.ResourceServer,
    dpop_policy: mcp.auth.DpopPolicy,
    mcp_url: []const u8,
    issuers: [1][]const u8,
    // The authorization server.
    as: AuthorizationServer,
    as_future: Io.Future(void),
    issuer: []const u8,
    keys: [2]jwt.SigningKey,
    signing: [2]as_mod.SigningKey,
    resources: [1]as_mod.Resource,
    resource_uris: [1][]const u8,
    auto: as_mod.AutoApprove,
    nonces: dpop.NonceIssuer,
    id_jag: enterprise.IdJagValidator,
    trusted_idps: [1]enterprise.TrustedIssuer,
    idp_keys: [1]jwt.Key,
    idp_key_buf: [97]u8,
    workload: workload_identity.WorkloadJwtValidator,
    trusted_workloads: [1]workload_identity.TrustedIssuer,
    workload_keys: [1]jwt.Key,
    workload_key_buf: [97]u8,
    workload_audiences: [1][]const u8,
    clients: [4]as_mod.ClientRegistration,
    // The helpers.
    features: Features,
    /// The proxy of the HTTP client transport of `call`.
    proxy: mcp.transport.proxy.Config,
    /// The test CA. It is empty without the `https` feature.
    ca_bundle: std.crypto.Certificate.Bundle,
    chain: tls.CertChain,
    chains: [1]*const tls.CertChain,
    tls_server: tls.Server,
    cimd: TinyServer,
    cimd_url: []const u8,
    cimd_doc: []const u8,
    idp: TinyServer,
    idp_issuer: []const u8,
    idp_key: jwt.SigningKey,
    idp_count: std.atomic.Value(u32),

    const client_key_seed = 43;
    const client_kid = "cc-key";

    fn start(self: *World, features: Features) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        self.features = features;
        self.proxy = .none;
        self.arena_state = .init(gpa);
        errdefer self.arena_state.deinit();
        const arena = self.arena_state.allocator();
        self.idp_count = .init(0);

        // The certificate of the HTTPS parts names `localhost`, and the test CA signs it.
        const with_tls = features.cimd or features.https;
        if (with_tls) {
            self.chain = try tls.CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/chain-leaf.crt", "test/fixtures/tls/pem/chain-leaf.key");
            self.chains = .{&self.chain};
            self.tls_server = try tls.Server.init(.{ .chains = &self.chains, .alpn = &.{"http/1.1"} });
        }
        errdefer if (with_tls) self.chain.deinit();
        self.ca_bundle = .empty;
        errdefer self.ca_bundle.deinit(gpa);
        if (features.https) try self.ca_bundle.addCertsFromFilePath(gpa, io, Io.Clock.real.now(io), Io.Dir.cwd(), "test/fixtures/tls/pem/ca.crt");
        const base = if (features.https) "https://localhost" else "http://127.0.0.1";
        const server_tls: ?*const tls.Server = if (features.https) &self.tls_server else null;

        // The MCP server binds first: the authorization server needs its URL.
        self.server = try mcp.Server.init(gpa, io, .{
            .info = .{ .name = "as-test", .version = "1" },
            .authorization_extensions = .{ .client_credentials = true, .enterprise_managed = true, .dpop = true, .workload_identity = true },
        });
        errdefer self.server.deinit();
        try self.server.addToolJson(.{ .name = "whoami" }, whoami);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .auth = &self.rs, .tls = server_tls });
        errdefer self.transport.deinit();
        try self.transport.bind();
        self.mcp_url = try std.fmt.allocPrint(arena, "{s}:{d}/mcp", .{ base, self.transport.bound_port });

        self.idp_key = es256(44);
        if (features.idp) {
            try self.idp.start(null, self, idpReply);
            self.idp_issuer = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{self.idp.port()});
        }
        errdefer if (features.idp) self.idp.stop();
        if (features.cimd) {
            try self.cimd.start(&self.tls_server, self, cimdReply);
            self.cimd_url = try std.fmt.allocPrint(arena, "https://localhost:{d}/client.json", .{self.cimd.port()});
            self.cimd_doc = try std.fmt.allocPrint(arena,
                \\{{"client_id":"{s}","client_name":"CIMD test client","redirect_uris":["http://127.0.0.1:41893/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}}
            , .{self.cimd_url});
        }
        errdefer if (features.cimd) self.cimd.stop();

        // The authorization server binds before `init`: the issuer has the port.
        var address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        const listener = try address.listen(io, .{ .reuse_address = true });
        self.issuer = try std.fmt.allocPrint(arena, "{s}:{d}", .{ base, listener.socket.address.getPort() });
        self.keys = .{ es256(41), es256(42) };
        // The second key is an old key: the JWK set keeps it, the server signs with the first.
        self.signing = .{ .{ .key = &self.keys[0], .kid = "as-key-2" }, .{ .key = &self.keys[1], .kid = "as-key-1" } };
        self.resources = .{.{ .uri = self.mcp_url }};
        self.resource_uris = .{self.mcp_url};
        self.auto = .{ .subject = "alice" };
        self.nonces = try .init(io);
        self.idp_keys = .{self.idp_key.verificationKey(&self.idp_key_buf, null)};
        self.trusted_idps = .{.{ .issuer = if (features.idp) self.idp_issuer else "https://idp.invalid", .keys = &self.idp_keys }};
        self.id_jag = .{ .issuer = self.issuer, .trusted_issuers = &self.trusted_idps, .resources = &self.resource_uris };
        const workload_key = es256(45);
        self.workload_keys = .{workload_key.verificationKey(&self.workload_key_buf, "wl-1")};
        self.trusted_workloads = .{.{ .issuer = workload_issuer, .keys = &self.workload_keys }};
        self.workload_audiences = .{try std.fmt.allocPrint(arena, "{s}/token", .{self.issuer})};
        self.workload = .{ .audiences = &self.workload_audiences, .trusted_issuers = &self.trusted_workloads };
        const client_key = es256(client_key_seed);
        self.clients = .{
            .{ .client_id = "pre-client", .client_name = "Pre-registered", .redirect_uris = &.{"http://127.0.0.1/callback"} },
            .{ .client_id = "cc-secret", .client_secret = cc_secret, .grant_types = .{ .client_credentials = true } },
            .{ .client_id = "cc-jwt", .jwks = try jwksOf(arena, &client_key, client_kid), .grant_types = .{ .client_credentials = true } },
            .{ .client_id = "ema-client", .client_secret = ema_secret, .grant_types = .{ .jwt_bearer = true } },
        };
        self.as = AuthorizationServer.init(io, gpa, .{
            .issuer = self.issuer,
            .signing_keys = &self.signing,
            .resources = &self.resources,
            .scopes_supported = &.{ "mcp:read", "mcp:write", "offline_access" },
            .authorizer = self.auto.authorizer(),
            .clients = &self.clients,
            .grants = .{ .id_jag = &self.id_jag, .workload = &self.workload },
            .dpop = .{ .nonce = if (features.as_nonce) &self.nonces else null },
            .dynamic_registration = .{},
            .client_metadata = .{ .allow_private_addresses = true, .ca_file = "test/fixtures/tls/pem/ca.crt" },
            .allow_http = true,
        }) catch |e| {
            var l = listener;
            l.deinit(io);
            return e;
        };
        errdefer self.as.deinit();
        try self.as.listen(.{ .listener = listener, .tls = server_tls });
        self.as_future = try io.concurrent(serveAs, .{&self.as});
        errdefer {
            self.as.shutdown();
            self.as_future.await(io);
        }

        // The MCP server verifies the tokens with the JWK set that it reads from the server.
        var fetcher: common.Fetcher = .init(io, gpa, 1 << 16, true);
        defer fetcher.deinit();
        if (features.https) fetcher.ca_bundle = &self.ca_bundle;
        const reply = try fetcher.fetch(arena, .GET, try std.fmt.allocPrint(arena, "{s}/jwks", .{self.issuer}), null, null, &.{});
        try std.testing.expectEqual(200, reply.status);
        const keys = try jwt.parseJwks(arena, reply.body);
        try std.testing.expectEqual(2, keys.len);
        self.jv = .{ .options = .{ .keys = keys, .issuer = self.issuer, .audience = self.mcp_url, .token_type = as_mod.access_token_type }, .clock = .{ .io = io } };
        self.issuers = .{self.issuer};
        self.dpop_policy = .{ .io = io };
        self.rs = .{
            .resource = self.mcp_url,
            .resource_metadata_url = try std.fmt.allocPrint(arena, "{s}:{d}/.well-known/oauth-protected-resource/mcp", .{ base, self.transport.bound_port }),
            .authorization_servers = &self.issuers,
            .scopes_supported = &.{"mcp:read"},
            .required_scopes = &.{"mcp:read"},
            .verifier = self.jv.verifier(),
            .dpop = if (features.dpop_policy) &self.dpop_policy else null,
        };
        self.mcp_future = try io.concurrent(serveMcp, .{&self.transport});
    }

    fn serveAs(as: *AuthorizationServer) void {
        as.serve() catch {};
    }

    fn serveMcp(t: *HttpServer) void {
        t.serve() catch {};
    }

    fn stop(self: *World) void {
        const io = std.testing.io;
        self.transport.shutdown();
        self.mcp_future.await(io);
        self.as.shutdown();
        self.as_future.await(io);
        self.as.deinit();
        self.transport.deinit();
        self.server.deinit();
        if (self.features.cimd) self.cimd.stop();
        if (self.features.cimd or self.features.https) self.chain.deinit();
        self.ca_bundle.deinit(std.testing.allocator);
        if (self.features.idp) self.idp.stop();
        self.arena_state.deinit();
    }

    fn cimdReply(ctx: *anyopaque, arena: Allocator, target: []const u8, body: []const u8) anyerror![]const u8 {
        _ = arena;
        _ = body;
        const self: *World = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, target, "/client.json")) return self.cimd_doc;
        return "{}";
    }

    /// The token exchange of the fake IdP: an ID-JAG for alice.
    fn idpReply(ctx: *anyopaque, arena: Allocator, target: []const u8, body: []const u8) anyerror![]const u8 {
        const self: *World = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, target, "/token")) return "{}";
        const form = try common.parseForm(arena, body);
        if (!std.mem.eql(u8, form.get("audience") orelse "", self.issuer)) return error.WrongAudience;
        const t = realNow(std.testing.io);
        const n = self.idp_count.fetchAdd(1, .monotonic);
        const payload = try std.fmt.allocPrint(arena, "{{\"jti\":\"idjag-{d}\",\"iss\":{f},\"sub\":\"alice\",\"aud\":{f},\"resource\":{f},\"client_id\":\"ema-client\",\"exp\":{d},\"iat\":{d},\"scope\":\"mcp:read\"}}", .{
            n,
            std.json.fmt(self.idp_issuer, .{}),
            std.json.fmt(self.issuer, .{}),
            std.json.fmt(self.mcp_url, .{}),
            t + 300,
            t,
        });
        const grant = try jwt.sign(arena, &self.idp_key, payload, .{ .typ = enterprise.jwt_type });
        return std.fmt.allocPrint(arena, "{{\"issued_token_type\":\"{s}\",\"access_token\":\"{s}\",\"token_type\":\"N_A\",\"expires_in\":300}}", .{ enterprise.token_type_id_jag, grant });
    }

    /// Call `whoami` through an MCP client with `provider`. Returns `subject|client_id`.
    fn call(self: *World, arena: Allocator, provider: mcp.auth.Provider, extension: ?[]const u8) ![]const u8 {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        const transport = try HttpClient.init(io, gpa, .{
            .url = self.mcp_url,
            .auth_provider = provider,
            .tls = if (self.features.https) .{ .trust = .{ .bundle = &self.ca_bundle } } else null,
            .proxy = self.proxy,
        });
        defer transport.deinit();
        var client: mcp.Client = .init(gpa, io, .{
            .info = .{ .name = "as-test-client", .version = "1" },
            .capabilities = if (extension) |e| try mcp.auth.withExtension(arena, .{}, e) else .{},
        });
        defer client.deinit();
        client.connect(transport.transport());
        const result = try client.callTool(arena, "whoami", null, .{});
        return result.content[0].text.text;
    }
};

test "authorization code flow: a pre-registered public client gets a bearer JWT" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{});
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const credentials = [_]mcp.auth.OAuthClient.Credentials{.{ .issuer = world.issuer, .client_id = "pre-client" }};
    var oauth: mcp.auth.OAuthClient = .init(io, gpa, .{
        .registration = .{ .pre_registered = &credentials },
        .allow_http = true,
    });
    defer oauth.deinit();
    try std.testing.expectEqualStrings("alice|pre-client", try world.call(arena, oauth.provider(), null));
    try std.testing.expectEqualStrings("alice|pre-client", try world.call(arena, oauth.provider(), null));
    try std.testing.expect(!oauth.token_dpop);

    // The token is a JWT of RFC 9068 that the first key signs.
    const token = oauth.currentToken().?;
    const header = try json.parseTree(arena, try decodeSegment(arena, token[0..std.mem.indexOfScalar(u8, token, '.').?]));
    try std.testing.expectEqualStrings("at+jwt", json.getString(header, "typ").?);
    try std.testing.expectEqualStrings("as-key-2", json.getString(header, "kid").?);
    const claims = try jwt.decodePayloadUnverified(arena, token);
    try std.testing.expectEqualStrings(world.issuer, json.getString(claims, "iss").?);
    try std.testing.expectEqualStrings(world.mcp_url, json.getString(claims, "aud").?);
    try std.testing.expectEqualStrings("pre-client", json.getString(claims, "client_id").?);
    try std.testing.expectEqualStrings("mcp:read offline_access", json.getString(claims, "scope").?);
    try std.testing.expect(json.getString(claims, "jti") != null);
    try std.testing.expect(claims.object.get("cnf") == null);
    // A short lifetime: 900 seconds by default.
    try std.testing.expectEqual(@as(i64, 900), jwt.integerClaim(claims, "exp").? - jwt.integerClaim(claims, "iat").?);
}

fn decodeSegment(arena: Allocator, text: []const u8) ![]u8 {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const out = try arena.alloc(u8, try dec.calcSizeForSlice(text));
    try dec.decode(out, text);
    return out;
}

test "authorization code flow: dynamic registration with DPoP-bound tokens and nonces" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{ .dpop_policy = true, .as_nonce = true });
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var prover: dpop.Prover = try .generate(io, gpa);
    defer prover.deinit();
    var oauth: mcp.auth.OAuthClient = .init(io, gpa, .{
        .registration = .dynamic,
        .allow_http = true,
        .dpop = &prover,
        .dpop_bound_access_tokens = true,
    });
    defer oauth.deinit();
    const who = try world.call(arena, oauth.provider(), dpop.extension_id);
    try std.testing.expect(std.mem.startsWith(u8, who, "alice|"));
    try std.testing.expect(oauth.token_dpop);
    const claims = try jwt.decodePayloadUnverified(arena, oauth.currentToken().?);
    try std.testing.expectEqualStrings(prover.jkt, json.getString(claims.object.get("cnf").?, "jkt").?);
    try std.testing.expectEqualStrings(who, try world.call(arena, oauth.provider(), dpop.extension_id));
}

test "authorization code flow: a client ID metadata document over HTTPS" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{ .cimd = true, .dpop_policy = true });
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var oauth: mcp.auth.OAuthClient = .init(io, gpa, .{
        .registration = .{ .client_metadata_url = world.cimd_url },
        .allow_http = true,
    });
    defer oauth.deinit();
    const who = try world.call(arena, oauth.provider(), null);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "alice|{s}", .{world.cimd_url}), who);
    // The authorization request and the token request read the document from the cache.
    try std.testing.expectEqual(1, world.cimd.requests.load(.monotonic));

    // The same document with DPoP.
    var prover: dpop.Prover = try .generate(io, gpa);
    defer prover.deinit();
    var bound: mcp.auth.OAuthClient = .init(io, gpa, .{
        .registration = .{ .client_metadata_url = world.cimd_url },
        .allow_http = true,
        .dpop = &prover,
    });
    defer bound.deinit();
    try std.testing.expectEqualStrings(who, try world.call(arena, bound.provider(), dpop.extension_id));
    try std.testing.expect(bound.token_dpop);
}

test "authorization code flow over HTTPS with the CA of the ca_bundle option" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{ .https = true });
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expect(std.mem.startsWith(u8, world.issuer, "https://localhost:"));
    try std.testing.expect(std.mem.startsWith(u8, world.mcp_url, "https://localhost:"));

    // The CA store of the system does not have the test CA. Thus a client without the option
    // does not trust the metadata host.
    var plain: mcp.auth.OAuthClient = .init(io, gpa, .{});
    defer plain.deinit();
    try std.testing.expectError(error.NoResourceMetadata, plain.handleChallenge(arena, world.mcp_url, 401, null, 1));

    // With the bundle, the discovery, the registration, the authorization and the token
    // request use https. The client does not accept http for them.
    var oauth: mcp.auth.OAuthClient = .init(io, gpa, .{ .ca_bundle = &world.ca_bundle });
    defer oauth.deinit();
    const who = try world.call(arena, oauth.provider(), null);
    try std.testing.expect(std.mem.startsWith(u8, who, "alice|"));
    try std.testing.expectEqualStrings(world.issuer, oauth.issuer.?);
    try std.testing.expectEqualStrings(who, try world.call(arena, oauth.provider(), null));
}

test "the fetcher verifies a server against its ca_bundle only, and the HTTP client of std never gets the bundle" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{ .https = true });
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const url = try std.fmt.allocPrint(arena, "{s}/jwks", .{world.issuer});
    const bytes = world.ca_bundle.bytes.items;
    const certs = world.ca_bundle.map.count();

    var fetcher: common.Fetcher = .init(io, gpa, 1 << 16, false);
    defer fetcher.deinit();
    fetcher.ca_bundle = &world.ca_bundle;
    try std.testing.expectEqual(200, (try fetcher.fetch(arena, .GET, url, null, null, &.{})).status);
    // The HTTP client of std has no bundle, and it did not load the CA store of the system.
    try std.testing.expectEqual(0, fetcher.http_client.ca_bundle.bytes.items.len);
    try std.testing.expect(fetcher.http_client.now == null);
    // On Windows, the TLS client of std replaces the bundle of its HTTP client with the CA
    // store of the system, and frees the old bundle. Do the same here: the bundle of the
    // option stays valid, and `World.stop` frees it one time.
    var replaced: std.crypto.Certificate.Bundle = .empty;
    std.mem.swap(std.crypto.Certificate.Bundle, &fetcher.http_client.ca_bundle, &replaced);
    replaced.deinit(gpa);
    try std.testing.expectEqual(200, (try fetcher.fetch(arena, .GET, url, null, null, &.{})).status);
    try std.testing.expectEqual(bytes.ptr, world.ca_bundle.bytes.items.ptr);
    try std.testing.expectEqual(bytes.len, world.ca_bundle.bytes.items.len);
    try std.testing.expectEqual(certs, world.ca_bundle.map.count());

    // A bundle without the test CA: the TLS handshake fails. The fetcher does not use the CA
    // store of the system then.
    var other: std.crypto.Certificate.Bundle = .empty;
    defer other.deinit(gpa);
    try other.addCertsFromFilePath(gpa, io, Io.Clock.real.now(io), Io.Dir.cwd(), "test/fixtures/tls/pem/rev-root.crt");
    var refusing: common.Fetcher = .init(io, gpa, 1 << 16, false);
    defer refusing.deinit();
    refusing.ca_bundle = &other;
    try std.testing.expectError(error.TlsFailed, refusing.fetch(arena, .GET, url, null, null, &.{}));
    try std.testing.expectEqual(0, refusing.http_client.ca_bundle.bytes.items.len);
}

/// The `host:port` part of an `https` URL, in `arena`.
fn authority(arena: Allocator, url: []const u8) ![]const u8 {
    const rest = url["https://".len..];
    return arena.dupe(u8, rest[0 .. std.mem.findScalar(u8, rest, '/') orelse rest.len]);
}

test "authorization code flow over HTTPS through a CONNECT proxy" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{ .https = true });
    defer world.stop();
    var p: TestProxy = undefined;
    try p.start(null);
    defer p.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var proxy_buf: [96]u8 = undefined;
    // The hosts are `localhost`, thus the test needs `loopback`.
    const through: mcp.transport.proxy.Config = .{ .explicit = .{ .url = p.url(&proxy_buf, "agent:s3cret"), .loopback = true } };

    // The fetcher of the OAuth client and the HTTP client transport use the same proxy. The
    // discovery, the registration, the authorization, the token request and the MCP requests
    // go through it. The SDK TLS client verifies each server against the bundle.
    world.proxy = through;
    var oauth: mcp.auth.OAuthClient = .init(io, gpa, .{ .ca_bundle = &world.ca_bundle, .proxy = through });
    defer oauth.deinit();
    const who = try world.call(arena, oauth.provider(), null);
    try std.testing.expect(std.mem.startsWith(u8, who, "alice|"));
    try std.testing.expect(p.sawTarget(try authority(arena, world.issuer)));
    try std.testing.expect(p.sawTarget(try authority(arena, world.mcp_url)));
    try std.testing.expectEqualStrings("Basic YWdlbnQ6czNjcmV0", (try p.lastAuthorization(arena)).?);

    // A fetch through the proxy takes one tunnel.
    var fetcher: common.Fetcher = .init(io, gpa, 1 << 16, false);
    defer fetcher.deinit();
    fetcher.ca_bundle = &world.ca_bundle;
    fetcher.proxy = through;
    const tunnels = p.tunnels.load(.monotonic);
    const jwks = try fetcher.fetch(arena, .GET, try std.fmt.allocPrint(arena, "{s}/jwks", .{world.issuer}), null, null, &.{});
    try std.testing.expectEqual(200, jwks.status);
    try std.testing.expectEqual(2, (try jwt.parseJwks(arena, jwks.body)).len);
    try std.testing.expectEqual(tunnels + 1, p.tunnels.load(.monotonic));

    // Without the bundle, the TLS client of std speaks through the tunnel with the CA store of
    // the system, which does not have the test CA.
    var system: common.Fetcher = .init(io, gpa, 1 << 16, false);
    defer system.deinit();
    system.proxy = through;
    if (system.fetch(arena, .GET, try std.fmt.allocPrint(arena, "{s}/jwks", .{world.issuer}), null, null, &.{})) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectEqual(tunnels + 2, p.tunnels.load(.monotonic));

    // A proxy that refuses the tunnel: the fetch fails with `error.ProxyRefused`, and the
    // client finds no metadata.
    var refusing: TestProxy = undefined;
    try refusing.start(.forbidden);
    defer refusing.stop();
    var refused_buf: [64]u8 = undefined;
    const refused: mcp.transport.proxy.Config = .{ .explicit = .{ .url = refusing.url(&refused_buf, ""), .loopback = true } };
    fetcher.proxy = refused;
    try std.testing.expectError(error.ProxyRefused, fetcher.fetch(arena, .GET, try std.fmt.allocPrint(arena, "{s}/jwks", .{world.issuer}), null, null, &.{}));
    var blocked: mcp.auth.OAuthClient = .init(io, gpa, .{ .ca_bundle = &world.ca_bundle, .proxy = refused });
    defer blocked.deinit();
    try std.testing.expectError(error.NoResourceMetadata, blocked.handleChallenge(arena, world.mcp_url, 401, null, 1));
    try std.testing.expect(refusing.sawTarget(try authority(arena, world.mcp_url)));
}

test "client credentials: a client secret and private_key_jwt" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{ .dpop_policy = true });
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ext = mcp.auth.client_credentials.extension_id;

    var secret: mcp.auth.ClientCredentials = .init(io, gpa, .{
        .client = .{ .client_secret = .{ .client_id = "cc-secret", .client_secret = cc_secret } },
        .allow_http = true,
    });
    defer secret.deinit();
    try std.testing.expectEqualStrings("cc-secret|cc-secret", try world.call(arena, secret.provider(), ext));

    const key = es256(World.client_key_seed);
    var signed: mcp.auth.ClientCredentials = .init(io, gpa, .{
        .client = .{ .private_key_jwt = .{ .client_id = "cc-jwt", .key = &key, .kid = World.client_kid } },
        .allow_http = true,
    });
    defer signed.deinit();
    try std.testing.expectEqualStrings("cc-jwt|cc-jwt", try world.call(arena, signed.provider(), ext));

    // With DPoP.
    var prover: dpop.Prover = try .generate(io, gpa);
    defer prover.deinit();
    var bound: mcp.auth.ClientCredentials = .init(io, gpa, .{
        .client = .{ .private_key_jwt = .{ .client_id = "cc-jwt", .key = &key, .kid = World.client_kid } },
        .allow_http = true,
        .dpop = &prover,
    });
    defer bound.deinit();
    try std.testing.expectEqualStrings("cc-jwt|cc-jwt", try world.call(arena, bound.provider(), ext));
    try std.testing.expect(bound.token_dpop);

    // A wrong secret.
    var wrong: mcp.auth.ClientCredentials = .init(io, gpa, .{
        .client = .{ .client_secret = .{ .client_id = "cc-secret", .client_secret = "not-the-secret-0123456789" } },
        .allow_http = true,
    });
    defer wrong.deinit();
    try std.testing.expectError(error.TokenRequestFailed, wrong.handleChallenge(arena, world.mcp_url, 401, null, 1));
    try std.testing.expectEqualStrings("invalid_client", wrong.last_error.?);
}

test "JWT bearer grant: an ID-JAG of an enterprise IdP" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{ .idp = true });
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var ema: mcp.auth.EnterpriseClient = .init(io, gpa, .{
        .idp = .{
            .token_endpoint = try std.fmt.allocPrint(arena, "{s}/token", .{world.idp_issuer}),
            .client = .{ .client_secret = .{ .client_id = "idp-client", .client_secret = "idp-secret", .method = .client_secret_post } },
        },
        .assertion = .{ .static = .{ .token = "id-token-of-alice" } },
        .client = .{ .client_secret = .{ .client_id = "ema-client", .client_secret = ema_secret } },
        .require_grant_profile = true,
        .allow_http = true,
    });
    defer ema.deinit();
    try std.testing.expectEqualStrings("alice|ema-client", try world.call(arena, ema.provider(), enterprise.extension_id));

    // Another client with the ID-JAG of ema-client: the server refuses it.
    var intruder: mcp.auth.EnterpriseClient = .init(io, gpa, .{
        .idp = .{
            .token_endpoint = try std.fmt.allocPrint(arena, "{s}/token", .{world.idp_issuer}),
            .client = .{ .client_secret = .{ .client_id = "idp-client", .client_secret = "idp-secret", .method = .client_secret_post } },
        },
        .assertion = .{ .static = .{ .token = "id-token-of-alice" } },
        .client = .{ .client_secret = .{ .client_id = "cc-secret", .client_secret = cc_secret } },
        .allow_http = true,
    });
    defer intruder.deinit();
    try std.testing.expectError(error.TokenRequestFailed, intruder.handleChallenge(arena, world.mcp_url, 401, null, 1));
    try std.testing.expectEqualStrings("unauthorized_client", intruder.last_error.?);
}

test "JWT bearer grant: a workload JWT" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var world: World = undefined;
    try world.start(.{});
    defer world.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const key = es256(45);
    const t = realNow(io);
    const claims = "{{\"iss\":\"{s}\",\"sub\":\"{s}\",\"aud\":\"{s}\",\"jti\":\"{s}\",\"exp\":{d},\"iat\":{d}}}";
    const good = try jwt.sign(arena, &key, try std.fmt.allocPrint(arena, claims, .{ workload_issuer, workload_subject, world.as.tokenEndpoint(), "w1", t + 300, t }), .{ .kid = "wl-1" });
    var wi: mcp.auth.WorkloadIdentity = .init(io, gpa, .{ .assertion = .{ .static = good }, .allow_http = true });
    defer wi.deinit();
    const ext = workload_identity.extension_id;
    try std.testing.expectEqualStrings(workload_subject ++ "|" ++ workload_subject, try world.call(arena, wi.provider(), ext));

    // The same JWT a second time: the server saw its `jti`.
    var again: mcp.auth.WorkloadIdentity = .init(io, gpa, .{ .assertion = .{ .static = good }, .allow_http = true });
    defer again.deinit();
    try std.testing.expectError(error.TokenRequestFailed, again.handleChallenge(arena, world.mcp_url, 401, null, 1));
    try std.testing.expectEqualStrings("invalid_grant", again.last_error.?);
}

// -- Error cases with `handle` -------------------------------------------------------------------

const as_issuer = "https://as.example";
const rs_uri = "https://mcp.example/mcp";
const redirect = "http://127.0.0.1:5000/callback";
const verifier = "the-pkce-verifier-of-the-tests-0123456789-abcdefghij";

fn fixedNow() i64 {
    return 1_800_000_000;
}

fn challengeOf(buf: *[43]u8, v: []const u8) []const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(v, &digest, .{});
    return std.base64.url_safe_no_pad.Encoder.encode(buf, &digest);
}

/// An authorization server without a listener.
const Direct = struct {
    as: AuthorizationServer,
    keys: [1]jwt.SigningKey,
    signing: [1]as_mod.SigningKey,
    client_jwks: []const u8,
    jwks_buf: [512]u8,
    clients: [5]as_mod.ClientRegistration,

    const Patch = struct {
        authorizer: ?as_mod.Authorizer = null,
        dynamic_registration: ?as_mod.DynamicRegistration = null,
        nonce: ?*const dpop.NonceIssuer = null,
    };

    fn init(self: *Direct, patch: Patch) !void {
        self.keys = .{es256(51)};
        self.signing = .{.{ .key = &self.keys[0], .kid = "k1" }};
        const client_key = es256(52);
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const jwk = try jwt.publicJwk(arena_state.allocator(), &client_key);
        self.client_jwks = try std.fmt.bufPrint(&self.jwks_buf, "{{\"keys\":[{{\"kid\":\"c\",{s}]}}", .{jwk[1..]});
        self.clients = .{
            .{ .client_id = "public", .redirect_uris = &.{redirect} },
            .{ .client_id = "confidential", .client_secret = "confidential-secret-0123", .redirect_uris = &.{redirect}, .grant_types = .{ .authorization_code = true, .refresh_token = true, .client_credentials = true } },
            .{ .client_id = "signer", .jwks = self.client_jwks, .grant_types = .{ .client_credentials = true } },
            .{ .client_id = "reader", .redirect_uris = &.{redirect}, .scopes = &.{"mcp:read"} },
            .{ .client_id = "dpop-only", .redirect_uris = &.{redirect}, .dpop_bound_access_tokens = true },
        };
        self.as = try AuthorizationServer.init(std.testing.io, std.testing.allocator, .{
            .issuer = as_issuer,
            .signing_keys = &self.signing,
            .resources = &.{ .{ .uri = rs_uri }, .{ .uri = "https://files.example/mcp", .scopes = &.{"mcp:read"} } },
            .scopes_supported = &.{ "mcp:read", "mcp:write" },
            .default_scopes = &.{"mcp:read"},
            .authorizer = patch.authorizer orelse .{ .decide = approveBob },
            .clients = &self.clients,
            .dynamic_registration = patch.dynamic_registration,
            .dpop = .{ .nonce = patch.nonce },
            .clock = fixedNow,
        });
    }

    fn approveBob(userdata: ?*anyopaque, arena: Allocator, request: *const as_mod.AuthorizationRequest) anyerror!as_mod.Decision {
        _ = userdata;
        _ = arena;
        _ = request;
        return .{ .approve = .{ .subject = "bob" } };
    }

    fn deinit(self: *Direct) void {
        self.as.deinit();
    }

    fn get(self: *Direct, arena: Allocator, target: []const u8) !as_mod.Response {
        const req: as_mod.Request = .{ .method = .GET, .target = target };
        return (try self.as.handle(arena, &req)).?;
    }

    fn post(self: *Direct, arena: Allocator, target: []const u8, body: []const u8, extra: []const http.Header) !as_mod.Response {
        var headers: std.ArrayList(http.Header) = .empty;
        try headers.append(arena, .{ .name = "content-type", .value = "application/x-www-form-urlencoded" });
        try headers.appendSlice(arena, extra);
        const req: as_mod.Request = .{ .method = .POST, .target = target, .headers = headers.items, .body = body };
        return (try self.as.handle(arena, &req)).?;
    }

    /// An authorization request with PKCE for `client`. `extra` adds query fields.
    fn authorize(self: *Direct, arena: Allocator, client: []const u8, extra: []const u8) !as_mod.Response {
        var buf: [43]u8 = undefined;
        const target = try std.fmt.allocPrint(arena, "/authorize?response_type=code&client_id={s}&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&state=s1&code_challenge={s}&code_challenge_method=S256{s}", .{ client, challengeOf(&buf, verifier), extra });
        return self.get(arena, target);
    }

    /// The code of a successful authorization request.
    fn code(self: *Direct, arena: Allocator, client: []const u8, extra: []const u8) ![]const u8 {
        const resp = try self.authorize(arena, client, extra);
        try std.testing.expectEqual(http.Status.found, resp.status);
        const loc = headerOf(resp, "location").?;
        const q = try common.parseQuery(arena, loc);
        try std.testing.expectEqualStrings("s1", q.get("state").?);
        try std.testing.expectEqualStrings(as_issuer, q.get("iss").?);
        return q.get("code").?;
    }

    fn exchange(self: *Direct, arena: Allocator, client: []const u8, the_code: []const u8, the_verifier: []const u8, extra: []const http.Header) !as_mod.Response {
        const body = try std.fmt.allocPrint(arena, "grant_type=authorization_code&client_id={s}&code={s}&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&code_verifier={s}", .{ client, the_code, the_verifier });
        return self.post(arena, "/token", body, extra);
    }

    fn refresh(self: *Direct, arena: Allocator, client: []const u8, token: []const u8, extra: []const u8, headers: []const http.Header) !as_mod.Response {
        const body = try std.fmt.allocPrint(arena, "grant_type=refresh_token&client_id={s}&refresh_token={s}{s}", .{ client, token, extra });
        return self.post(arena, "/token", body, headers);
    }
};

fn headerOf(resp: as_mod.Response, name: []const u8) ?[]const u8 {
    for (resp.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

/// The `error` of a JSON error response.
fn errorOf(arena: Allocator, resp: as_mod.Response) ![]const u8 {
    const tree = try json.parseTree(arena, resp.body);
    return json.getString(tree, "error") orelse "";
}

fn field(arena: Allocator, resp: as_mod.Response, name: []const u8) !?[]const u8 {
    const tree = try json.parseTree(arena, resp.body);
    return json.getString(tree, name);
}

/// The `error` of the redirect of an authorization response.
fn redirectError(arena: Allocator, resp: as_mod.Response) !?[]const u8 {
    const loc = headerOf(resp, "location") orelse return null;
    const q = try common.parseQuery(arena, loc);
    // An error response also has the issuer (RFC 9207 section 2).
    if (q.get("error") != null) try std.testing.expectEqualStrings(as_issuer, q.get("iss").?);
    return q.get("error");
}

test "metadata and the JWK set" {
    var d: Direct = undefined;
    try d.init(.{ .dynamic_registration = .{} });
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{ "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration" }) |path| {
        const resp = try d.get(arena, path);
        try std.testing.expectEqual(http.Status.ok, resp.status);
        try std.testing.expectEqualStrings("application/json", headerOf(resp, "content-type").?);
        const doc = try json.parseTree(arena, resp.body);
        try std.testing.expectEqualStrings(as_issuer, json.getString(doc, "issuer").?);
        try std.testing.expectEqualStrings(as_issuer ++ "/authorize", json.getString(doc, "authorization_endpoint").?);
        try std.testing.expectEqualStrings(as_issuer ++ "/token", json.getString(doc, "token_endpoint").?);
        try std.testing.expectEqualStrings(as_issuer ++ "/jwks", json.getString(doc, "jwks_uri").?);
        try std.testing.expectEqualStrings(as_issuer ++ "/register", json.getString(doc, "registration_endpoint").?);
        try std.testing.expect(doc.object.get("authorization_response_iss_parameter_supported").?.bool);
        try std.testing.expect(doc.object.get("client_id_metadata_document_supported").?.bool);
        const methods = try common.stringList(arena, doc, "code_challenge_methods_supported");
        try std.testing.expectEqual(1, methods.len);
        try std.testing.expectEqualStrings("S256", methods[0]);
        const grants = try common.stringList(arena, doc, "grant_types_supported");
        try std.testing.expect(common.listContains(grants, "authorization_code") and common.listContains(grants, "refresh_token") and common.listContains(grants, "client_credentials"));
        try std.testing.expect(!common.listContains(grants, enterprise.grant_type_jwt_bearer));
        try std.testing.expect(common.listContains(try common.stringList(arena, doc, "dpop_signing_alg_values_supported"), "ES256"));
        try std.testing.expect(common.listContains(try common.stringList(arena, doc, "token_endpoint_auth_methods_supported"), "private_key_jwt"));
    }
    try std.testing.expect((try d.as.handle(arena, &.{ .method = .GET, .target = "/other" })) == null);
    try std.testing.expectEqual(http.Status.method_not_allowed, (try d.post(arena, "/jwks", "", &.{})).status);
    const keys = try jwt.parseJwks(arena, (try d.get(arena, "/jwks")).body);
    try std.testing.expectEqual(1, keys.len);
    try std.testing.expectEqualStrings("k1", keys[0].kid.?);
    try std.testing.expectEqual(jwt.Algorithm.ES256, keys[0].alg);

    // A symmetric key, an issuer with a slash at the end and an insecure issuer are refused.
    var hs: jwt.SigningKey = .{ .hs256 = "a-shared-secret-of-thirty-two-b!" };
    const resources = [_]as_mod.Resource{.{ .uri = rs_uri }};
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.SymmetricKey, AuthorizationServer.init(io, gpa, .{ .issuer = as_issuer, .signing_keys = &.{.{ .key = &hs, .kid = "h" }}, .resources = &resources }));
    try std.testing.expectError(error.InvalidIssuer, AuthorizationServer.init(io, gpa, .{ .issuer = as_issuer ++ "/", .signing_keys = &d.signing, .resources = &resources }));
    try std.testing.expectError(error.InsecureUrl, AuthorizationServer.init(io, gpa, .{ .issuer = "http://as.example", .signing_keys = &d.signing, .resources = &resources, .allow_http = true }));
    try std.testing.expectError(error.NoResource, AuthorizationServer.init(io, gpa, .{ .issuer = as_issuer, .signing_keys = &d.signing, .resources = &.{} }));
    try std.testing.expectError(error.InvalidClient, AuthorizationServer.init(io, gpa, .{ .issuer = as_issuer, .signing_keys = &d.signing, .resources = &resources, .clients = &.{.{ .client_id = "c", .client_secret = "short" }} }));
}

test "PKCE: S256 only, and the verifier must match" {
    var d: Direct = undefined;
    try d.init(.{});
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A missing challenge and the method plain.
    const missing = try d.get(arena, "/authorize?response_type=code&client_id=public&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&state=s1");
    try std.testing.expectEqualStrings("invalid_request", (try redirectError(arena, missing)).?);
    const plain = try d.get(arena, "/authorize?response_type=code&client_id=public&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&state=s1&code_challenge=" ++ verifier ++ "&code_challenge_method=plain");
    try std.testing.expectEqualStrings("invalid_request", (try redirectError(arena, plain)).?);
    const no_method = try d.get(arena, "/authorize?response_type=code&client_id=public&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&code_challenge=abc");
    try std.testing.expectEqualStrings("invalid_request", (try redirectError(arena, no_method)).?);

    // A wrong verifier.
    const c = try d.code(arena, "public", "");
    const wrong = try d.exchange(arena, "public", c, "another-verifier-of-the-tests-0123456789-abcdefghij", &.{});
    try std.testing.expectEqual(http.Status.bad_request, wrong.status);
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, wrong));
    try std.testing.expectEqualStrings("no-store", headerOf(wrong, "cache-control").?);

    // A good exchange: the token response.
    const c2 = try d.code(arena, "public", "");
    const ok = try d.exchange(arena, "public", c2, verifier, &.{});
    try std.testing.expectEqual(http.Status.ok, ok.status);
    try std.testing.expectEqualStrings("no-store", headerOf(ok, "cache-control").?);
    try std.testing.expectEqualStrings("Bearer", (try field(arena, ok, "token_type")).?);
    try std.testing.expectEqualStrings("mcp:read", (try field(arena, ok, "scope")).?);
    try std.testing.expect((try field(arena, ok, "refresh_token")) != null);
    // The resource server accepts the token.
    var buf: [97]u8 = undefined;
    const keys = [_]jwt.Key{d.keys[0].verificationKey(&buf, "k1")};
    const claims = try jwt.verify(arena, (try field(arena, ok, "access_token")).?, .{ .keys = &keys, .issuer = as_issuer, .audience = rs_uri, .token_type = as_mod.access_token_type }, fixedNow());
    try std.testing.expectEqualStrings("bob", claims.subject.?);
    try std.testing.expectEqualStrings("public", claims.client_id.?);
}

test "a code that comes a second time revokes the refresh token of its grant" {
    var d: Direct = undefined;
    try d.init(.{});
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const c = try d.code(arena, "public", "");
    const first = try d.exchange(arena, "public", c, verifier, &.{});
    try std.testing.expectEqual(http.Status.ok, first.status);
    const rt = (try field(arena, first, "refresh_token")).?;
    const second = try d.exchange(arena, "public", c, verifier, &.{});
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, second));
    const after = try d.refresh(arena, "public", rt, "", &.{});
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, after));

    // A code of another client.
    const c3 = try d.code(arena, "public", "");
    const stolen = try d.exchange(arena, "reader", c3, verifier, &.{});
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, stolen));
}

test "redirect URIs: exact match, any loopback port, never a redirect to an unknown URI" {
    var d: Direct = undefined;
    try d.init(.{});
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buf: [43]u8 = undefined;
    const challenge = challengeOf(&buf, verifier);
    const evil = try d.get(arena, try std.fmt.allocPrint(arena, "/authorize?response_type=code&client_id=public&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&code_challenge={s}&code_challenge_method=S256", .{challenge}));
    try std.testing.expectEqual(http.Status.bad_request, evil.status);
    try std.testing.expect(headerOf(evil, "location") == null);
    try std.testing.expectEqualStrings("text/plain; charset=utf-8", headerOf(evil, "content-type").?);
    const other_path = try d.get(arena, try std.fmt.allocPrint(arena, "/authorize?response_type=code&client_id=public&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback%2Fx&code_challenge={s}&code_challenge_method=S256", .{challenge}));
    try std.testing.expect(headerOf(other_path, "location") == null);
    const unknown = try d.get(arena, "/authorize?response_type=code&client_id=nobody&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback");
    try std.testing.expect(headerOf(unknown, "location") == null);
    const twice = try d.get(arena, "/authorize?response_type=code&client_id=public&client_id=public");
    try std.testing.expect(headerOf(twice, "location") == null);

    // Another loopback port is the same redirect URI (RFC 8252 section 7.3).
    const port = try d.get(arena, try std.fmt.allocPrint(arena, "/authorize?response_type=code&client_id=public&redirect_uri=http%3A%2F%2F127.0.0.1%3A61000%2Fcallback&state=p&code_challenge={s}&code_challenge_method=S256", .{challenge}));
    try std.testing.expectEqual(http.Status.found, port.status);
    try std.testing.expect(std.mem.startsWith(u8, headerOf(port, "location").?, "http://127.0.0.1:61000/callback?code="));

    // The token request must name the same redirect URI.
    const c = try d.code(arena, "public", "");
    const body = try std.fmt.allocPrint(arena, "grant_type=authorization_code&client_id=public&code={s}&redirect_uri=http%3A%2F%2F127.0.0.1%3A5001%2Fcallback&code_verifier={s}", .{ c, verifier });
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, try d.post(arena, "/token", body, &.{})));
}

test "resources and scopes" {
    var d: Direct = undefined;
    try d.init(.{});
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const unknown = try d.authorize(arena, "public", "&resource=https%3A%2F%2Fother.example%2Fmcp");
    try std.testing.expectEqual(http.Status.found, unknown.status);
    const q = try common.parseQuery(arena, headerOf(unknown, "location").?);
    try std.testing.expectEqualStrings("invalid_target", q.get("error").?);
    try std.testing.expectEqualStrings("s1", q.get("state").?);
    try std.testing.expectEqualStrings(as_issuer, q.get("iss").?);
    const two = try d.authorize(arena, "public", "&resource=https%3A%2F%2Fmcp.example%2Fmcp&resource=https%3A%2F%2Ffiles.example%2Fmcp");
    try std.testing.expectEqualStrings("invalid_target", (try redirectError(arena, two)).?);

    // The second resource permits mcp:read only.
    const files_write = try d.authorize(arena, "public", "&resource=https%3A%2F%2Ffiles.example%2Fmcp&scope=mcp%3Awrite");
    try std.testing.expectEqualStrings("invalid_scope", (try redirectError(arena, files_write)).?);
    const unknown_scope = try d.authorize(arena, "public", "&scope=admin");
    try std.testing.expectEqualStrings("invalid_scope", (try redirectError(arena, unknown_scope)).?);
    // The client reader can get mcp:read only.
    const reader_write = try d.authorize(arena, "reader", "&scope=mcp%3Awrite");
    try std.testing.expectEqualStrings("invalid_scope", (try redirectError(arena, reader_write)).?);

    // The token is for the resource of the request. The token request cannot change it.
    const c = try d.code(arena, "public", "&resource=https%3A%2F%2Ffiles.example%2Fmcp&scope=mcp%3Aread");
    const body = try std.fmt.allocPrint(arena, "grant_type=authorization_code&client_id=public&code={s}&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&code_verifier={s}&resource=https%3A%2F%2Fmcp.example%2Fmcp", .{ c, verifier });
    try std.testing.expectEqualStrings("invalid_target", try errorOf(arena, try d.post(arena, "/token", body, &.{})));
    const c2 = try d.code(arena, "public", "&resource=https%3A%2F%2Ffiles.example%2Fmcp");
    const ok = try d.exchange(arena, "public", c2, verifier, &.{});
    const claims = try jwt.decodePayloadUnverified(arena, (try field(arena, ok, "access_token")).?);
    try std.testing.expectEqualStrings("https://files.example/mcp", json.getString(claims, "aud").?);

    // Client credentials: an unknown resource.
    const cc = try d.post(arena, "/token", "grant_type=client_credentials&client_id=confidential&client_secret=confidential-secret-0123&resource=https%3A%2F%2Fother.example%2Fmcp", &.{});
    try std.testing.expectEqualStrings("invalid_target", try errorOf(arena, cc));
}

test "refresh tokens: rotation, narrower scopes and reuse detection" {
    var d: Direct = undefined;
    try d.init(.{});
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const c = try d.code(arena, "public", "&scope=mcp%3Aread%20mcp%3Awrite");
    const first = try d.exchange(arena, "public", c, verifier, &.{});
    const rt1 = (try field(arena, first, "refresh_token")).?;
    // A narrower scope is fine, a larger one is not. The token stays valid after the error.
    try std.testing.expectEqualStrings("invalid_scope", try errorOf(arena, try d.refresh(arena, "public", rt1, "&scope=mcp%3Aread%20admin", &.{})));
    try std.testing.expectEqualStrings("invalid_target", try errorOf(arena, try d.refresh(arena, "public", rt1, "&resource=https%3A%2F%2Ffiles.example%2Fmcp", &.{})));
    const rt2 = rt1;
    const narrow = try d.refresh(arena, "public", rt2, "&scope=mcp%3Aread", &.{});
    try std.testing.expectEqual(http.Status.ok, narrow.status);
    try std.testing.expectEqualStrings("mcp:read", (try field(arena, narrow, "scope")).?);
    const rt3 = (try field(arena, narrow, "refresh_token")).?;
    try std.testing.expect(!std.mem.eql(u8, rt2, rt3));
    // The new token keeps the scopes of the grant.
    const wide = try d.refresh(arena, "public", rt3, "", &.{});
    try std.testing.expectEqualStrings("mcp:read mcp:write", (try field(arena, wide, "scope")).?);
    const rt4 = (try field(arena, wide, "refresh_token")).?;

    // The old token rt2 comes again: the server revokes the family, also rt4.
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, try d.refresh(arena, "public", rt2, "", &.{})));
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, try d.refresh(arena, "public", rt4, "", &.{})));
    // A token of another client and an unknown token.
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, try d.refresh(arena, "public", "unknown-token", "", &.{})));
}

test "client authentication: secrets, assertions and their replay" {
    var d: Direct = undefined;
    try d.init(.{});
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const good_basic = try common.basicCredentials(arena, "confidential", "confidential-secret-0123");
    const ok = try d.post(arena, "/token", "grant_type=client_credentials", &.{.{ .name = "authorization", .value = good_basic }});
    try std.testing.expectEqual(http.Status.ok, ok.status);
    try std.testing.expectEqualStrings("mcp:read", (try field(arena, ok, "scope")).?);
    try std.testing.expect((try field(arena, ok, "refresh_token")) == null);

    const bad_basic = try common.basicCredentials(arena, "confidential", "wrong-secret-0123456789");
    const bad = try d.post(arena, "/token", "grant_type=client_credentials", &.{.{ .name = "authorization", .value = bad_basic }});
    try std.testing.expectEqual(http.Status.unauthorized, bad.status);
    try std.testing.expectEqualStrings("invalid_client", try errorOf(arena, bad));
    try std.testing.expect(headerOf(bad, "www-authenticate") != null);
    const bad_post = try d.post(arena, "/token", "grant_type=client_credentials&client_id=confidential&client_secret=nope", &.{});
    try std.testing.expectEqualStrings("invalid_client", try errorOf(arena, bad_post));
    // A confidential client without its secret.
    try std.testing.expectEqualStrings("invalid_client", try errorOf(arena, try d.post(arena, "/token", "grant_type=client_credentials&client_id=confidential", &.{})));
    // Two methods in one request.
    const two = try d.post(arena, "/token", "grant_type=client_credentials&client_id=confidential&client_secret=confidential-secret-0123", &.{.{ .name = "authorization", .value = good_basic }});
    try std.testing.expectEqualStrings("invalid_request", try errorOf(arena, two));
    // A public client cannot use the client credentials grant.
    try std.testing.expectEqualStrings("unauthorized_client", try errorOf(arena, try d.post(arena, "/token", "grant_type=client_credentials&client_id=public", &.{})));
    try std.testing.expectEqualStrings("unsupported_grant_type", try errorOf(arena, try d.post(arena, "/token", "grant_type=password&client_id=public", &.{})));
    try std.testing.expectEqualStrings("invalid_request", try errorOf(arena, try d.post(arena, "/token", "grant_type=client_credentials&grant_type=client_credentials", &.{})));

    // private_key_jwt: the jti is single use.
    const key = es256(52);
    const assertion = try common.clientAssertion(std.testing.io, arena, &key, "c", "signer", as_issuer, fixedNow(), 60);
    const form = try std.fmt.allocPrint(arena, "grant_type=client_credentials&client_assertion_type={s}&client_assertion={s}", .{ "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer", assertion });
    const signed = try d.post(arena, "/token", form, &.{});
    try std.testing.expectEqual(http.Status.ok, signed.status);
    const replay = try d.post(arena, "/token", form, &.{});
    try std.testing.expectEqualStrings("invalid_client", try errorOf(arena, replay));
    try std.testing.expectEqualStrings("The client assertion was used before", (try field(arena, replay, "error_description")).?);
    // The token endpoint URL is a valid audience too, another URL is not.
    const to_endpoint = try common.clientAssertion(std.testing.io, arena, &key, "c", "signer", as_issuer ++ "/token", fixedNow(), 60);
    try std.testing.expectEqual(http.Status.ok, (try d.post(arena, "/token", try std.fmt.allocPrint(arena, "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={s}", .{to_endpoint}), &.{})).status);
    const elsewhere = try common.clientAssertion(std.testing.io, arena, &key, "c", "signer", "https://other.example", fixedNow(), 60);
    try std.testing.expectEqualStrings("invalid_client", try errorOf(arena, try d.post(arena, "/token", try std.fmt.allocPrint(arena, "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={s}", .{elsewhere}), &.{})));
    // A long lifetime and another key.
    const long = try common.clientAssertion(std.testing.io, arena, &key, "c", "signer", as_issuer, fixedNow(), 86_400);
    try std.testing.expectEqualStrings("invalid_client", try errorOf(arena, try d.post(arena, "/token", try std.fmt.allocPrint(arena, "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={s}", .{long}), &.{})));
    const other_key = es256(53);
    const forged = try common.clientAssertion(std.testing.io, arena, &other_key, "c", "signer", as_issuer, fixedNow(), 60);
    try std.testing.expectEqualStrings("invalid_client", try errorOf(arena, try d.post(arena, "/token", try std.fmt.allocPrint(arena, "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={s}", .{forged}), &.{})));
}

test "DPoP: bound codes, bound refresh tokens, nonces and a proof of another key" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const nonces: dpop.NonceIssuer = try .init(io);
    var d: Direct = undefined;
    try d.init(.{ .nonce = &nonces });
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var key_a: dpop.Prover = try .init(io, gpa, es256(61));
    defer key_a.deinit();
    key_a.clock = fixedNow;
    var key_b: dpop.Prover = try .init(io, gpa, es256(62));
    defer key_b.deinit();
    key_b.clock = fixedNow;
    const token_url = as_issuer ++ "/token";

    // The code is bound to key A with `dpop_jkt`.
    const c = try d.code(arena, "public", try std.fmt.allocPrint(arena, "&dpop_jkt={s}", .{key_a.jkt}));
    // The first proof has no nonce: the server sends one.
    const no_nonce = try d.exchange(arena, "public", c, verifier, &.{.{ .name = "DPoP", .value = try key_b.proof(arena, "POST", token_url, null) }});
    try std.testing.expectEqualStrings("use_dpop_nonce", try errorOf(arena, no_nonce));
    const nonce = headerOf(no_nonce, "dpop-nonce").?;
    try key_a.rememberNonce(token_url, nonce);
    try key_b.rememberNonce(token_url, nonce);
    // Key B cannot use the code of key A. The failed request used the code.
    const stolen = try d.exchange(arena, "public", c, verifier, &.{.{ .name = "DPoP", .value = try key_b.proof(arena, "POST", token_url, null) }});
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, stolen));
    // A proof for another URL.
    const c1 = try d.code(arena, "public", try std.fmt.allocPrint(arena, "&dpop_jkt={s}", .{key_a.jkt}));
    const wrong_url = try d.exchange(arena, "public", c1, verifier, &.{.{ .name = "DPoP", .value = try key_a.proof(arena, "POST", "https://as.example/other", null) }});
    try std.testing.expectEqualStrings("invalid_dpop_proof", try errorOf(arena, wrong_url));
    // Key A gets a DPoP-bound token and a refresh token that is bound to key A.
    const c2 = try d.code(arena, "public", try std.fmt.allocPrint(arena, "&dpop_jkt={s}", .{key_a.jkt}));
    const ok = try d.exchange(arena, "public", c2, verifier, &.{.{ .name = "DPoP", .value = try key_a.proof(arena, "POST", token_url, null) }});
    try std.testing.expectEqual(http.Status.ok, ok.status);
    try std.testing.expectEqualStrings("DPoP", (try field(arena, ok, "token_type")).?);
    const claims = try jwt.decodePayloadUnverified(arena, (try field(arena, ok, "access_token")).?);
    try std.testing.expectEqualStrings(key_a.jkt, json.getString(claims.object.get("cnf").?, "jkt").?);
    const rt = (try field(arena, ok, "refresh_token")).?;
    const without = try d.refresh(arena, "public", rt, "", &.{});
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, without));

    const c3 = try d.code(arena, "public", "");
    const ok3 = try d.exchange(arena, "public", c3, verifier, &.{.{ .name = "DPoP", .value = try key_a.proof(arena, "POST", token_url, null) }});
    const rt3 = (try field(arena, ok3, "refresh_token")).?;
    const by_b = try d.refresh(arena, "public", rt3, "", &.{.{ .name = "DPoP", .value = try key_b.proof(arena, "POST", token_url, null) }});
    try std.testing.expectEqualStrings("invalid_grant", try errorOf(arena, by_b));
    const c4 = try d.code(arena, "public", "");
    const ok4 = try d.exchange(arena, "public", c4, verifier, &.{.{ .name = "DPoP", .value = try key_a.proof(arena, "POST", token_url, null) }});
    const by_a = try d.refresh(arena, "public", (try field(arena, ok4, "refresh_token")).?, "", &.{.{ .name = "DPoP", .value = try key_a.proof(arena, "POST", token_url, null) }});
    try std.testing.expectEqual(http.Status.ok, by_a.status);
    try std.testing.expectEqualStrings("DPoP", (try field(arena, by_a, "token_type")).?);

    // A client that registered DPoP-bound tokens needs a proof.
    const c5 = try d.code(arena, "dpop-only", "");
    try std.testing.expectEqualStrings("invalid_dpop_proof", try errorOf(arena, try d.exchange(arena, "dpop-only", c5, verifier, &.{})));
    // Two proofs.
    const p = try key_a.proof(arena, "POST", token_url, null);
    const c6 = try d.code(arena, "public", "");
    try std.testing.expectEqualStrings("invalid_dpop_proof", try errorOf(arena, try d.exchange(arena, "public", c6, verifier, &.{ .{ .name = "DPoP", .value = p }, .{ .name = "DPoP", .value = p } })));
}

test "consent: deny, a page of the application, and the consent token" {
    const Consent = struct {
        server: ?*AuthorizationServer = null,
        fn decide(userdata: ?*anyopaque, arena: Allocator, request: *const as_mod.AuthorizationRequest) anyerror!as_mod.Decision {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            const session = "session-of-carol";
            if (request.http.method == .GET) {
                var buf: [as_mod.AuthorizationServer.consent_token_len]u8 = undefined;
                const token = self.server.?.consentToken(&buf, session, request);
                const page = try std.fmt.allocPrint(arena, "<form method=\"post\">{s}<input name=\"consent\" value=\"{s}\"></form>", .{ try request.hiddenFields(arena), token });
                return .{ .respond = .{ .status = .ok, .headers = &.{.{ .name = "content-type", .value = "text/html" }}, .body = page } };
            }
            const token = request.param("consent") orelse return .deny;
            if (!self.server.?.checkConsentToken(session, request, token)) return .deny;
            if (!std.mem.eql(u8, request.param("decision") orelse "", "allow")) return .deny;
            return .{ .approve = .{ .subject = "carol", .scopes = &.{"mcp:read"} } };
        }
    };
    var consent: Consent = .{};
    var d: Direct = undefined;
    try d.init(.{ .authorizer = .{ .userdata = &consent, .decide = Consent.decide } });
    defer d.deinit();
    consent.server = &d.as;
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const page = try d.authorize(arena, "public", "&scope=mcp%3Aread%20mcp%3Awrite");
    try std.testing.expectEqual(http.Status.ok, page.status);
    try std.testing.expect(std.mem.indexOf(u8, page.body, "<input type=\"hidden\" name=\"client_id\" value=\"public\">") != null);
    // The form comes back with the parameters, the consent token and the answer.
    const start = std.mem.indexOf(u8, page.body, "name=\"consent\" value=\"").? + "name=\"consent\" value=\"".len;
    const token = page.body[start..][0..as_mod.AuthorizationServer.consent_token_len];
    var buf: [43]u8 = undefined;
    const params = try std.fmt.allocPrint(arena, "response_type=code&client_id=public&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&state=s1&code_challenge={s}&code_challenge_method=S256&scope=mcp%3Aread%20mcp%3Awrite", .{challengeOf(&buf, verifier)});
    const allow = try d.post(arena, "/authorize", try std.fmt.allocPrint(arena, "{s}&consent={s}&decision=allow", .{ params, token }), &.{});
    try std.testing.expectEqual(http.Status.see_other, allow.status);
    const q = try common.parseQuery(arena, headerOf(allow, "location").?);
    const ok = try d.exchange(arena, "public", q.get("code").?, verifier, &.{});
    try std.testing.expectEqualStrings("mcp:read", (try field(arena, ok, "scope")).?);
    const claims = try jwt.decodePayloadUnverified(arena, (try field(arena, ok, "access_token")).?);
    try std.testing.expectEqualStrings("carol", json.getString(claims, "sub").?);
    // A form from another site has no valid token, and another scope breaks the token.
    const forged = try d.post(arena, "/authorize", try std.fmt.allocPrint(arena, "{s}&consent=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&decision=allow", .{params}), &.{});
    try std.testing.expectEqualStrings("access_denied", (try redirectError(arena, forged)).?);
    const other_scope = try d.post(arena, "/authorize", try std.fmt.allocPrint(arena, "{s}%20&consent={s}&decision=allow", .{ params[0 .. params.len - "%20mcp%3Awrite".len], token }), &.{});
    try std.testing.expectEqualStrings("access_denied", (try redirectError(arena, other_scope)).?);
}

test "dynamic registration" {
    var d: Direct = undefined;
    try d.init(.{ .dynamic_registration = .{ .initial_access_token = "initial-token" } });
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const register = struct {
        fn call(dd: *Direct, a: Allocator, body: []const u8, token: ?[]const u8) !as_mod.Response {
            var headers: std.ArrayList(http.Header) = .empty;
            try headers.append(a, .{ .name = "content-type", .value = "application/json" });
            if (token) |t| try headers.append(a, .{ .name = "authorization", .value = try std.fmt.allocPrint(a, "Bearer {s}", .{t}) });
            const req: as_mod.Request = .{ .method = .POST, .target = "/register", .headers = headers.items, .body = body };
            return (try dd.as.handle(a, &req)).?;
        }
    }.call;
    const public = "{\"client_name\":\"Tool\",\"redirect_uris\":[\"http://127.0.0.1/callback\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"token_endpoint_auth_method\":\"none\"}";
    try std.testing.expectEqual(http.Status.unauthorized, (try register(&d, arena, public, null)).status);
    try std.testing.expectEqual(http.Status.unauthorized, (try register(&d, arena, public, "wrong")).status);
    const created = try register(&d, arena, public, "initial-token");
    try std.testing.expectEqual(http.Status.created, created.status);
    const id = (try field(arena, created, "client_id")).?;
    try std.testing.expect((try field(arena, created, "client_secret")) == null);
    _ = try d.code(arena, id, "");

    const confidential = try register(&d, arena, "{\"redirect_uris\":[\"https://app.example.com/cb\"]}", "initial-token");
    try std.testing.expectEqualStrings("client_secret_basic", (try field(arena, confidential, "token_endpoint_auth_method")).?);
    const secret = (try field(arena, confidential, "client_secret")).?;
    try std.testing.expect(secret.len >= 43);

    const insecure = try register(&d, arena, "{\"redirect_uris\":[\"http://app.example.com/cb\"],\"token_endpoint_auth_method\":\"none\"}", "initial-token");
    try std.testing.expectEqualStrings("invalid_redirect_uri", try errorOf(arena, insecure));
    const implicit = try register(&d, arena, "{\"redirect_uris\":[\"https://a.example/cb\"],\"response_types\":[\"token\"]}", "initial-token");
    try std.testing.expectEqualStrings("invalid_client_metadata", try errorOf(arena, implicit));
    const cc = try register(&d, arena, "{\"grant_types\":[\"client_credentials\"]}", "initial-token");
    try std.testing.expectEqualStrings("invalid_client_metadata", try errorOf(arena, cc));
    const no_keys = try register(&d, arena, "{\"redirect_uris\":[\"https://a.example/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"}", "initial-token");
    try std.testing.expectEqualStrings("invalid_client_metadata", try errorOf(arena, no_keys));
}

test "client ID metadata documents: no fetch from a loopback address without the test option" {
    var d: Direct = undefined;
    try d.init(.{});
    defer d.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [43]u8 = undefined;
    for ([_][]const u8{ "https%3A%2F%2Flocalhost%3A1%2Fclient.json", "https%3A%2F%2F127.0.0.1%3A1%2Fclient.json", "https%3A%2F%2F%5B%3A%3A1%5D%3A1%2Fclient.json", "https%3A%2F%2F10.0.0.1%2Fclient.json" }) |client_id| {
        const resp = try d.get(arena, try std.fmt.allocPrint(arena, "/authorize?response_type=code&client_id={s}&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&code_challenge={s}&code_challenge_method=S256", .{ client_id, challengeOf(&buf, verifier) }));
        try std.testing.expectEqual(http.Status.bad_request, resp.status);
        try std.testing.expect(headerOf(resp, "location") == null);
    }
}
