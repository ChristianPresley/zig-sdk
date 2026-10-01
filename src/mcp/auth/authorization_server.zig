//! An OAuth 2.1 authorization server for MCP deployments. The server issues JWT access tokens
//! (RFC 9068) for the MCP servers of the deployment. The resource server helpers of the SDK
//! verify them with the JWK set of the server.
//!
//! The server has these endpoints:
//!
//! - The authorization server metadata (RFC 8414), also at the OpenID Connect path.
//! - The authorization endpoint: the authorization code flow with PKCE S256 and the issuer in
//!   the response (RFC 9207). The application authenticates the user and asks for consent in a
//!   callback.
//! - The token endpoint: the grants `authorization_code`, `refresh_token`,
//!   `client_credentials` and the JWT bearer grant with ID-JAGs or workload JWTs. DPoP-bound
//!   tokens (RFC 9449) are available for each grant.
//! - The JWK set of the signing keys.
//! - Dynamic client registration (RFC 7591), when the application enables it.
//!
//! Clients are pre-registered, registered dynamically, or identified by a client ID metadata
//! document. The application runs the server on its own listener with `listen` and `serve`,
//! or calls `handle` from its own HTTP server.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const json = @import("../json.zig");
const common = @import("common.zig");
const jwt = @import("jwt.zig");
const dpop = @import("dpop.zig");
const enterprise = @import("enterprise.zig");
const workload_identity = @import("workload_identity.zig");
const store_mod = @import("authorization_store.zig");
const client_metadata = @import("client_metadata.zig");
const tls = @import("../../tls/tls.zig");
const wake = @import("../util/wake.zig");

const log = std.log.scoped(.mcp_auth);
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Store = store_mod.Store;
pub const MemoryStore = store_mod.MemoryStore;
pub const Client = store_mod.Client;
pub const AuthMethod = store_mod.AuthMethod;
pub const GrantTypes = store_mod.GrantTypes;

/// The JOSE `typ` header of the access tokens (RFC 9068 section 2.1). A `JwtVerifier` checks it
/// when its option `token_type` has this value.
pub const access_token_type = "at+jwt";
/// The grant type of the JWT bearer grant (RFC 7523 section 2.1).
pub const grant_type_jwt_bearer = enterprise.grant_type_jwt_bearer;

/// A key that signs access tokens. The key must be asymmetric.
pub const SigningKey = struct {
    key: *const jwt.SigningKey,
    /// The `kid` of the key in the JWK set and in the token headers.
    kid: []const u8,
};

/// Make a new random P-256 key (ES256) for access tokens. Call `deinit` on the key to erase it.
pub fn generateSigningKey(io: Io) error{EntropyUnavailable}!jwt.SigningKey {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    while (true) {
        var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        io.randomSecure(&seed) catch return error.EntropyUnavailable;
        const kp = Ecdsa.KeyPair.generateDeterministic(seed) catch continue;
        return .{ .es256 = kp };
    }
}

/// A protected resource: an MCP server that accepts the tokens of this server.
pub const Resource = struct {
    /// The canonical URI of the MCP server, for example `https://mcp.example.com/mcp`. It is
    /// the `aud` claim of the tokens.
    uri: []const u8,
    /// The scopes that tokens for this resource can have. Empty permits each scope of the server.
    scopes: []const []const u8 = &.{},
};

/// A client that the application registers.
pub const ClientRegistration = struct {
    client_id: []const u8,
    /// The secret of a confidential client. The server keeps only its SHA-256 hash. The secret
    /// must have 16 bytes or more of random data.
    client_secret: ?[]const u8 = null,
    /// Null takes `client_secret_basic` for a client with a secret, `private_key_jwt` for a
    /// client with keys, else `none`.
    auth_method: ?AuthMethod = null,
    redirect_uris: []const []const u8 = &.{},
    grant_types: GrantTypes = .{ .authorization_code = true, .refresh_token = true },
    /// The scopes that the client can get. Empty permits each scope of the server.
    scopes: []const []const u8 = &.{},
    /// The keys of `private_key_jwt`: a JWK set as JSON text.
    jwks: ?[]const u8 = null,
    /// The keys of `private_key_jwt`: the https URL of a JWK set.
    jwks_uri: ?[]const u8 = null,
    client_name: ?[]const u8 = null,
    dpop_bound_access_tokens: bool = false,
};

/// One parameter of a request.
pub const Param = struct { name: []const u8, value: []const u8 };

/// An HTTP request to the server.
pub const Request = struct {
    method: http.Method,
    /// The request target: the path and the query.
    target: []const u8,
    headers: []const http.Header = &.{},
    body: []const u8 = "",
    /// Data of the application for the authorizer, for example the sign-in state of the user.
    context: ?*anyopaque = null,

    /// The path without the query.
    pub fn path(self: *const Request) []const u8 {
        return self.target[0 .. std.mem.indexOfScalar(u8, self.target, '?') orelse self.target.len];
    }

    /// The query without the `?`, or an empty text.
    pub fn query(self: *const Request) []const u8 {
        const q = std.mem.indexOfScalar(u8, self.target, '?') orelse return "";
        return self.target[q + 1 ..];
    }

    /// The value of the first header with `name`. The comparison ignores case.
    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    /// The number of headers with `name`.
    pub fn headerCount(self: *const Request, name: []const u8) usize {
        var n: usize = 0;
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) n += 1;
        }
        return n;
    }
};

/// The response to a request. The slices live in the arena of the call.
pub const Response = struct {
    status: http.Status = .ok,
    /// The headers, without `content-length`.
    headers: []const http.Header = &.{},
    body: []const u8 = "",
};

/// An authorization request that the server checked: the client, the redirect URI, PKCE, the
/// resource and the scopes are valid. The slices live in the arena of the call.
pub const AuthorizationRequest = struct {
    client_id: []const u8,
    /// The `client_name` of the client. It is text from the client: escape it in HTML.
    client_name: ?[]const u8,
    redirect_uri: []const u8,
    /// The host of the redirect URI. Show it to the user.
    redirect_host: []const u8,
    /// The requested scopes, or the default scopes of the server.
    scopes: []const []const u8,
    resource: []const u8,
    state: ?[]const u8,
    code_challenge: []const u8,
    /// All parameters of the request, also the fields of a consent form.
    params: []const Param,
    http: *const Request,

    /// The value of a parameter or form field, for example the answer of a consent form.
    pub fn param(self: *const AuthorizationRequest, name: []const u8) ?[]const u8 {
        for (self.params) |p| if (std.mem.eql(u8, p.name, name)) return p.value;
        return null;
    }

    /// The OAuth parameters of the request as hidden fields of an HTML form. A consent form
    /// sends them back to the authorization endpoint with `POST`.
    pub fn hiddenFields(self: *const AuthorizationRequest, arena: Allocator) Allocator.Error![]const u8 {
        var aw: Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        for (self.params) |p| {
            if (!isOAuthParameter(p.name)) continue;
            w.writeAll("<input type=\"hidden\" name=\"") catch return error.OutOfMemory;
            htmlEscape(w, p.name) catch return error.OutOfMemory;
            w.writeAll("\" value=\"") catch return error.OutOfMemory;
            htmlEscape(w, p.value) catch return error.OutOfMemory;
            w.writeAll("\">\n") catch return error.OutOfMemory;
        }
        return aw.written();
    }
};

/// The parameters of an authorization request that `hiddenFields` keeps.
const oauth_parameters = [_][]const u8{ "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "resource", "dpop_jkt", "response_mode" };

fn isOAuthParameter(name: []const u8) bool {
    for (oauth_parameters) |p| if (std.mem.eql(u8, p, name)) return true;
    return false;
}

/// Write `text` with the HTML escapes of `&`, `<`, `>`, `"` and `'`.
pub fn htmlEscape(w: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    for (text) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&#39;"),
        else => try w.writeByte(c),
    };
}

/// The approval of an authorization request.
pub const Approval = struct {
    /// The user: the `sub` claim of the tokens.
    subject: []const u8,
    /// The granted scopes. Null grants the requested scopes. The server drops scopes that it
    /// does not offer.
    scopes: ?[]const []const u8 = null,
    /// The Unix seconds of the authentication of the user. Null uses the current time.
    auth_time: ?i64 = null,
};

/// What the application decides about an authorization request.
pub const Decision = union(enum) {
    /// The application authenticated the user, and the user gave consent. The server
    /// redirects with a code.
    approve: Approval,
    /// The user or the policy refused. The server redirects with `access_denied`.
    deny,
    /// Send this response, for example a sign-in page, a consent page or a redirect to an
    /// identity provider. The page sends the user back to the authorization endpoint later.
    respond: Response,
};

/// The callback of the application for the authorization endpoint. User authentication and
/// consent are the job of the application. The server calls `decide` for each valid request
/// to the endpoint, with `GET` and with `POST`.
pub const Authorizer = struct {
    userdata: ?*anyopaque = null,
    decide: *const fn (userdata: ?*anyopaque, arena: Allocator, request: *const AuthorizationRequest) anyerror!Decision,
};

/// An authorizer that approves each request for one fixed subject, without consent. Use it
/// for tests and development only.
pub const AutoApprove = struct {
    subject: []const u8,

    pub fn authorizer(self: *const AutoApprove) Authorizer {
        return .{ .userdata = @constCast(self), .decide = decide };
    }

    fn decide(userdata: ?*anyopaque, arena: Allocator, request: *const AuthorizationRequest) anyerror!Decision {
        _ = arena;
        _ = request;
        const self: *const AutoApprove = @ptrCast(@alignCast(userdata.?));
        return .{ .approve = .{ .subject = self.subject } };
    }
};

/// The grants of the token endpoint.
pub const Grants = struct {
    authorization_code: bool = true,
    refresh_token: bool = true,
    client_credentials: bool = true,
    /// Validates the ID-JAGs of the JWT bearer grant (Enterprise-Managed Authorization). Null
    /// refuses ID-JAGs. Without a replay check, the server records the `jti` values.
    id_jag: ?*const enterprise.IdJagValidator = null,
    /// Validates the workload JWTs of the JWT bearer grant. Null refuses workload JWTs. Without
    /// a replay check, the server records the `jti` values.
    workload: ?*const workload_identity.WorkloadJwtValidator = null,
};

/// DPoP at the token endpoint (RFC 9449).
pub const DpopOptions = struct {
    /// Accept DPoP proofs and issue DPoP-bound tokens. When false, the server ignores the
    /// `DPoP` header and issues bearer tokens.
    enabled: bool = true,
    /// Refuse token requests without a proof.
    required: bool = false,
    algorithms: []const jwt.Algorithm = &dpop.default_algorithms,
    /// Require a nonce of this issuer in each proof.
    nonce: ?*const dpop.NonceIssuer = null,
};

/// Dynamic client registration (RFC 7591).
pub const DynamicRegistration = struct {
    /// Require this bearer token on each registration request. Null accepts all requests.
    initial_access_token: ?[]const u8 = null,
    /// Permit the grant type `client_credentials` for clients with a secret or keys.
    allow_client_credentials: bool = false,
};

/// The limits of the input.
pub const Limits = struct {
    max_body_bytes: usize = 64 * 1024,
    max_parameter_bytes: usize = 8 * 1024,
    max_parameters: usize = 64,
    max_scopes: usize = 64,
    max_state_bytes: usize = 1024,
};

pub const Options = struct {
    /// The issuer identifier: an https URL without a query, a fragment or a slash at the end.
    issuer: []const u8,
    /// The keys that sign access tokens. The first key signs. The JWK set has all keys, so a
    /// key rotation can keep the old key until its tokens expire.
    signing_keys: []const SigningKey,
    /// The MCP servers that the server issues tokens for. A request without `resource` gets
    /// the first one.
    resources: []const Resource,
    /// The scopes that clients can request.
    scopes_supported: []const []const u8 = &.{},
    /// The scopes of a request without `scope`.
    default_scopes: []const []const u8 = &.{},
    /// Decides about the authorization requests. Null offers no authorization endpoint and
    /// no authorization code grant.
    authorizer: ?Authorizer = null,
    /// The clients to register at the start.
    clients: []const ClientRegistration = &.{},
    grants: Grants = .{},
    dpop: DpopOptions = .{},
    /// Dynamic client registration. MCP deprecates it in favor of client ID metadata
    /// documents. Null disables it.
    dynamic_registration: ?DynamicRegistration = null,
    /// Client ID metadata documents: a `client_id` that is an https URL names its metadata
    /// document. Null disables them. The options also apply to `jwks_uri` of clients.
    client_metadata: ?client_metadata.Options = .{},
    /// The store of clients, codes and refresh tokens. Null uses a `MemoryStore`.
    store: ?Store = null,
    /// The limits of the `MemoryStore`.
    memory_limits: store_mod.Limits = .{},
    access_token_lifetime_seconds: i64 = 900,
    /// The lifetime of a grant family. A rotation does not extend it.
    refresh_token_lifetime_seconds: i64 = 30 * 86_400,
    code_lifetime_seconds: i64 = 60,
    /// Issue a refresh token to a client with the grant type `refresh_token`.
    issue_refresh_tokens: bool = true,
    /// The longest lifetime of a client assertion: `exp` minus the current time.
    max_assertion_lifetime_seconds: i64 = 600,
    clock_skew_seconds: i64 = 60,
    limits: Limits = .{},
    /// Accept an `http` issuer and `http` resources with a loopback host. Tests only.
    allow_http: bool = false,
    /// The clock. Null uses the real clock.
    clock: common.Clock = null,
};

/// The options of the listener of the server.
pub const ListenOptions = struct {
    /// The address to bind. The default is loopback only.
    address: []const u8 = "127.0.0.1",
    /// The port. Zero takes a free port: read `bound_port` after `listen`.
    port: u16 = 0,
    /// Serve HTTPS with this TLS 1.3 server. Null serves plain HTTP.
    tls: ?*const tls.Server = null,
    max_connections: usize = 64,
    /// The largest request head.
    max_head_bytes: usize = 16 * 1024,
    /// The most requests on one connection.
    max_requests_per_connection: usize = 100,
    /// A listen socket that is open already. The server takes it instead of a new socket at
    /// `address` and `port`. Use it when the issuer needs the port before `init`.
    listener: ?Io.net.Server = null,
};

pub const InitError = error{
    OutOfMemory,
    /// The issuer is not an absolute URL, or it has a query, a fragment or a slash at the end.
    InvalidIssuer,
    /// The issuer or a resource does not use https, and `allow_http` does not apply.
    InsecureUrl,
    NoSigningKey,
    /// A signing key is HS256. The JWK set cannot publish a symmetric key.
    SymmetricKey,
    /// Two signing keys have the same `kid`, or a `kid` is empty.
    InvalidKeyId,
    NoResource,
    InvalidResource,
    /// A scope has a character that RFC 6749 section 3.3 does not permit.
    InvalidScope,
    /// A client registration is not valid.
    InvalidClient,
    EntropyUnavailable,
    StoreFull,
    StoreFailed,
};

pub const RegisterError = error{
    OutOfMemory,
    /// The registration is not valid, for example a short secret or a redirect URI without
    /// https.
    InvalidClient,
    StoreFull,
    StoreFailed,
};

/// The OAuth error codes of the endpoints.
const Code = enum {
    invalid_request,
    invalid_client,
    invalid_grant,
    unauthorized_client,
    unsupported_grant_type,
    invalid_scope,
    invalid_target,
    access_denied,
    unsupported_response_type,
    server_error,
    temporarily_unavailable,
    invalid_dpop_proof,
    use_dpop_nonce,
    invalid_redirect_uri,
    invalid_client_metadata,
    invalid_token,
};

pub const AuthorizationServer = struct {
    io: Io,
    gpa: Allocator,
    options: Options,
    store: Store,
    memory: ?*MemoryStore = null,
    fetcher: *client_metadata.Fetcher,
    /// The texts that `init` makes: the URLs, the paths and the documents.
    arena: std.heap.ArenaAllocator,
    urls: Urls,
    metadata: []const u8,
    jwks: []const u8,
    /// The key of the consent tokens.
    consent_key: [HmacSha256.key_length]u8,
    // The listener.
    listen_options: ListenOptions = .{},
    listener: ?Io.net.Server = null,
    bound_port: u16 = 0,
    group: Io.Group = .init,
    permits: Io.Semaphore = .{ .permits = 0 },
    closing: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    connections: std.ArrayList(*Connection) = .empty,
    connections_lock: Io.Mutex = .init,

    const Urls = struct {
        issuer: []const u8,
        authorization_endpoint: []const u8,
        token_endpoint: []const u8,
        jwks_uri: []const u8,
        registration_endpoint: []const u8,
        authorization_path: []const u8,
        token_path: []const u8,
        jwks_path: []const u8,
        registration_path: []const u8,
        metadata_path: []const u8,
        openid_path: []const u8,
        openid_path_suffix: []const u8,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) InitError!AuthorizationServer {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena_state.deinit();
        const arena = arena_state.allocator();

        try checkOptions(options);
        const urls = try makeUrls(arena, options.issuer);

        var self: AuthorizationServer = .{
            .io = io,
            .gpa = gpa,
            .options = options,
            .store = undefined,
            .fetcher = undefined,
            .arena = undefined,
            .urls = urls,
            .metadata = "",
            .jwks = "",
            .consent_key = undefined,
        };
        io.randomSecure(&self.consent_key) catch return error.EntropyUnavailable;
        self.jwks = try jwksDocument(arena, options.signing_keys);
        self.metadata = try metadataDocument(arena, &self);

        self.fetcher = try gpa.create(client_metadata.Fetcher);
        errdefer gpa.destroy(self.fetcher);
        self.fetcher.* = .init(io, gpa, options.client_metadata orelse .{});
        errdefer self.fetcher.deinit();
        if (options.store) |s| {
            self.store = s;
        } else {
            const mem = try gpa.create(MemoryStore);
            mem.* = .init(io, gpa, options.memory_limits);
            self.memory = mem;
            self.store = mem.store();
        }
        errdefer if (self.memory) |m| {
            m.deinit();
            gpa.destroy(m);
        };
        for (options.clients) |c| self.registerClient(c) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidClient => error.InvalidClient,
            error.StoreFull => error.StoreFull,
            error.StoreFailed => error.StoreFailed,
        };
        if (options.authorizer) |a| if (a.decide == &AutoApprove.decide) {
            log.warn("the authorization server approves each request without consent: use this for tests only", .{});
        };
        self.arena = arena_state;
        return self;
    }

    pub fn deinit(self: *AuthorizationServer) void {
        if (self.listener) |*l| l.deinit(self.io);
        self.connections.deinit(self.gpa);
        self.fetcher.deinit();
        self.gpa.destroy(self.fetcher);
        if (self.memory) |m| {
            m.deinit();
            self.gpa.destroy(m);
        }
        std.crypto.secureZero(u8, &self.consent_key);
        self.arena.deinit();
        self.* = undefined;
    }

    fn now(self: *const AuthorizationServer) i64 {
        return common.now(self.io, self.options.clock);
    }

    /// The issuer identifier.
    pub fn issuer(self: *const AuthorizationServer) []const u8 {
        return self.urls.issuer;
    }

    /// The URL of the token endpoint. The audience of a workload JWT must name it.
    pub fn tokenEndpoint(self: *const AuthorizationServer) []const u8 {
        return self.urls.token_endpoint;
    }

    /// The authorization server metadata document (RFC 8414).
    pub fn metadataJson(self: *const AuthorizationServer) []const u8 {
        return self.metadata;
    }

    /// The JWK set of the signing keys.
    pub fn jwksJson(self: *const AuthorizationServer) []const u8 {
        return self.jwks;
    }

    /// The verification keys of the access tokens, in `arena`. An MCP server in the same
    /// process can give them to a `JwtVerifier`.
    pub fn verificationKeys(self: *const AuthorizationServer, arena: Allocator) Allocator.Error![]const jwt.Key {
        return jwt.parseJwks(arena, self.jwks) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed => unreachable,
        };
    }

    /// Register a client, or replace the client with the same `client_id`.
    pub fn registerClient(self: *AuthorizationServer, registration: ClientRegistration) RegisterError!void {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const r = registration;
        if (r.client_id.len == 0 or r.client_id.len > 512) return error.InvalidClient;
        if (r.redirect_uris.len > client_metadata.max_redirect_uris) return error.InvalidClient;
        for (r.redirect_uris) |u| if (!common.validRedirectUri(u)) return error.InvalidClient;
        for (r.scopes) |s| if (!validScopeToken(s)) return error.InvalidClient;
        const method: AuthMethod = r.auth_method orelse if (r.client_secret != null)
            .client_secret_basic
        else if (r.jwks != null or r.jwks_uri != null)
            .private_key_jwt
        else
            .none;
        var client: Client = .{
            .client_id = r.client_id,
            .auth_method = method,
            .redirect_uris = r.redirect_uris,
            .grant_types = r.grant_types,
            .scopes = r.scopes,
            .client_name = r.client_name,
            .dpop_bound_access_tokens = r.dpop_bound_access_tokens,
            .issued_at = self.now(),
        };
        if (method.hasSecret()) {
            const secret = r.client_secret orelse return error.InvalidClient;
            if (secret.len < 16) return error.InvalidClient;
            client.secret_hash = store_mod.hashSecret(secret);
        } else if (r.client_secret != null) return error.InvalidClient;
        if (method == .private_key_jwt) {
            if ((r.jwks == null) == (r.jwks_uri == null)) return error.InvalidClient;
            if (r.jwks) |text| _ = jwt.parseJwks(arena, text) catch return error.InvalidClient;
            if (r.jwks_uri) |uri| if (!std.ascii.startsWithIgnoreCase(uri, "https://")) return error.InvalidClient;
            client.jwks = r.jwks;
            client.jwks_uri = r.jwks_uri;
        }
        if (client.grant_types.authorization_code and client.redirect_uris.len == 0) return error.InvalidClient;
        if (client.grant_types.client_credentials and method == .none) return error.InvalidClient;
        self.store.putClient(&client) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.StoreFull => error.StoreFull,
            else => error.StoreFailed,
        };
    }

    /// True when `target` names an endpoint of the server.
    pub fn isEndpoint(self: *const AuthorizationServer, target: []const u8) bool {
        const p = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
        const u = &self.urls;
        if (std.mem.eql(u8, p, u.metadata_path) or std.mem.eql(u8, p, u.openid_path) or std.mem.eql(u8, p, u.openid_path_suffix)) return true;
        if (std.mem.eql(u8, p, u.jwks_path) or std.mem.eql(u8, p, u.token_path)) return true;
        if (self.options.authorizer != null and std.mem.eql(u8, p, u.authorization_path)) return true;
        if (self.options.dynamic_registration != null and std.mem.eql(u8, p, u.registration_path)) return true;
        return false;
    }

    /// Answer one request. Returns null when the path is not an endpoint of the server. The
    /// response is in `arena`. Safe to call from more than one task.
    pub fn handle(self: *AuthorizationServer, arena: Allocator, request: *const Request) Allocator.Error!?Response {
        if (!self.isEndpoint(request.target)) return null;
        const p = request.path();
        const u = &self.urls;
        if (std.mem.eql(u8, p, u.metadata_path) or std.mem.eql(u8, p, u.openid_path) or std.mem.eql(u8, p, u.openid_path_suffix)) {
            return try documentResponse(arena, request, self.metadata);
        }
        if (std.mem.eql(u8, p, u.jwks_path)) return try documentResponse(arena, request, self.jwks);
        if (std.mem.eql(u8, p, u.token_path)) return try self.tokenEndpointResponse(arena, request);
        if (std.mem.eql(u8, p, u.authorization_path)) return try self.authorizationEndpoint(arena, request);
        return try self.registrationEndpoint(arena, request);
    }

    // -- Authorization endpoint -------------------------------------------------------------

    fn authorizationEndpoint(self: *AuthorizationServer, arena: Allocator, request: *const Request) Allocator.Error!Response {
        const text: []const u8 = switch (request.method) {
            .GET => request.query(),
            .POST => blk: {
                if (!isFormContent(request)) return errorPage(arena, .bad_request, .invalid_request, "The request body must be a form");
                if (request.body.len > self.options.limits.max_body_bytes) return errorPage(arena, .payload_too_large, .invalid_request, "The request body is too large");
                break :blk request.body;
            },
            else => return methodNotAllowed(arena, "GET, POST"),
        };
        const params = parseParams(arena, text, self.options.limits) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return errorPage(arena, .bad_request, .invalid_request, "The parameters are malformed or too large"),
        };
        // Without a valid client and redirect URI, the server must not redirect (RFC 6749
        // section 4.1.2.1).
        if (params.count("client_id") > 1 or params.count("redirect_uri") > 1) return errorPage(arena, .bad_request, .invalid_request, "A parameter occurs more than once");
        const client_id = params.get("client_id") orelse return errorPage(arena, .bad_request, .invalid_request, "The client_id parameter is missing");
        const client = (try self.findClient(arena, client_id)) orelse return errorPage(arena, .bad_request, .invalid_client, "The client is not known");
        const given_redirect = params.get("redirect_uri");
        const redirect_uri: []const u8 = if (given_redirect) |r| blk: {
            for (client.redirect_uris) |registered| if (redirectMatches(registered, r)) break :blk r;
            return errorPage(arena, .bad_request, .invalid_request, "The redirect_uri is not registered for the client");
        } else if (client.redirect_uris.len == 1) client.redirect_uris[0] else {
            return errorPage(arena, .bad_request, .invalid_request, "The redirect_uri parameter is missing");
        };

        // From here on, errors go to the redirect URI of the client.
        const state = params.get("state");
        if (state) |s| if (s.len > self.options.limits.max_state_bytes) {
            return self.redirectError(arena, request, redirect_uri, null, .invalid_request, "The state parameter is too long");
        };
        const r = Redirect{ .server = self, .arena = arena, .request = request, .uri = redirect_uri, .state = state };
        if (params.duplicateName(&.{"resource"}) != null) return r.fail(.invalid_request, "A parameter occurs more than once");
        const response_type = params.get("response_type") orelse return r.fail(.invalid_request, "The response_type parameter is missing");
        if (!std.mem.eql(u8, response_type, "code")) return r.fail(.unsupported_response_type, "The server offers the response type code only");
        if (params.get("response_mode")) |mode| if (!std.mem.eql(u8, mode, "query")) return r.fail(.invalid_request, "The server offers the response mode query only");
        if (!self.options.grants.authorization_code or !client.grant_types.authorization_code) return r.fail(.unauthorized_client, "The client cannot use the authorization code grant");
        // PKCE with S256 is required. The method plain gives no protection (RFC 7636).
        const method = params.get("code_challenge_method") orelse return r.fail(.invalid_request, "The code_challenge_method parameter must be S256");
        if (!std.mem.eql(u8, method, "S256")) return r.fail(.invalid_request, "The code_challenge_method parameter must be S256");
        const challenge = params.get("code_challenge") orelse return r.fail(.invalid_request, "The code_challenge parameter is missing");
        if (!isBase64Url(challenge, 43)) return r.fail(.invalid_request, "The code_challenge parameter is not an S256 challenge");
        const resource = self.resolveResource(params) catch return r.fail(.invalid_target, "The server does not issue tokens for this resource");
        const scopes = self.requestedScopes(arena, params.get("scope"), &client, resource) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return r.fail(.invalid_scope, "The scope is not valid for the client or the resource"),
        };
        var dpop_jkt: ?[]const u8 = null;
        if (self.options.dpop.enabled) if (params.get("dpop_jkt")) |jkt| {
            if (!isBase64Url(jkt, 43)) return r.fail(.invalid_request, "The dpop_jkt parameter is not a JWK thumbprint");
            dpop_jkt = jkt;
        };

        const areq: AuthorizationRequest = .{
            .client_id = client.client_id,
            .client_name = client.client_name,
            .redirect_uri = redirect_uri,
            .redirect_host = (common.splitUri(redirect_uri) orelse unreachable).host(),
            .scopes = scopes,
            .resource = resource.uri,
            .state = state,
            .code_challenge = challenge,
            .params = params.items,
            .http = request,
        };
        const authorizer = self.options.authorizer.?;
        const decision = authorizer.decide(authorizer.userdata, arena, &areq) catch |e| {
            log.warn("the authorizer failed: {t}", .{e});
            return r.fail(.server_error, "The server cannot decide about the request");
        };
        const approval = switch (decision) {
            .respond => |resp| return resp,
            .deny => return r.fail(.access_denied, "The request was denied"),
            .approve => |a| a,
        };
        if (approval.subject.len == 0) return r.fail(.server_error, "The server cannot decide about the request");
        const granted = try self.grantedScopes(arena, approval.scopes orelse scopes, &client, resource);
        const t = self.now();
        var code_bytes: [32]u8 = undefined;
        var family: store_mod.FamilyId = undefined;
        self.io.randomSecure(&code_bytes) catch return r.fail(.server_error, "The server has no random data");
        self.io.randomSecure(&family) catch return r.fail(.server_error, "The server has no random data");
        const code = try common.base64Url(arena, &code_bytes);
        const hash = store_mod.hashSecret(code);
        const record: store_mod.CodeRecord = .{
            .client_id = client.client_id,
            .redirect_uri = redirect_uri,
            .redirect_uri_given = given_redirect != null,
            .code_challenge = challenge,
            .resource = resource.uri,
            .scope = try std.mem.join(arena, " ", granted),
            .subject = approval.subject,
            .dpop_jkt = dpop_jkt,
            .family = family,
            .auth_time = approval.auth_time orelse t,
            .expires_at = t + self.options.code_lifetime_seconds,
        };
        self.store.putCode(&hash, &record, t) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return r.fail(.temporarily_unavailable, "The server cannot store the code"),
        };
        return r.success(code);
    }

    fn redirectError(self: *AuthorizationServer, arena: Allocator, request: *const Request, uri: []const u8, state: ?[]const u8, code: Code, description: []const u8) Allocator.Error!Response {
        const r = Redirect{ .server = self, .arena = arena, .request = request, .uri = uri, .state = state };
        return r.fail(code, description);
    }

    /// The redirect to the client with the authorization response (RFC 6749 section 4.1.2
    /// and RFC 9207).
    const Redirect = struct {
        server: *AuthorizationServer,
        arena: Allocator,
        request: *const Request,
        uri: []const u8,
        state: ?[]const u8,

        fn success(self: Redirect, code: []const u8) Allocator.Error!Response {
            return self.send(&.{ .{ .name = "code", .value = code }, .{ .name = "state", .value = self.state orelse "" } });
        }

        fn fail(self: Redirect, code: Code, description: []const u8) Allocator.Error!Response {
            return self.send(&.{
                .{ .name = "error", .value = @tagName(code) },
                .{ .name = "error_description", .value = description },
                .{ .name = "state", .value = self.state orelse "" },
            });
        }

        fn send(self: Redirect, fields: []const Param) Allocator.Error!Response {
            var aw: Io.Writer.Allocating = .init(self.arena);
            const w = &aw.writer;
            w.writeAll(self.uri) catch return error.OutOfMemory;
            var first = std.mem.indexOfScalar(u8, self.uri, '?') == null;
            for (fields) |f| {
                // An empty state means that the request had none.
                if (std.mem.eql(u8, f.name, "state") and self.state == null) continue;
                if (first) w.writeByte('?') catch return error.OutOfMemory;
                try common.formField(w, f.name, f.value, first);
                first = false;
            }
            try common.formField(w, "iss", self.server.urls.issuer, false);
            const headers = try self.arena.alloc(http.Header, 2);
            headers[0] = .{ .name = "location", .value = aw.written() };
            headers[1] = .{ .name = "cache-control", .value = "no-store" };
            // After a form, 303 makes the browser use GET for the redirect.
            return .{ .status = if (self.request.method == .POST) .see_other else .found, .headers = headers };
        }
    };

    // -- Token endpoint ---------------------------------------------------------------------

    fn tokenEndpointResponse(self: *AuthorizationServer, arena: Allocator, request: *const Request) Allocator.Error!Response {
        if (request.method != .POST) return methodNotAllowed(arena, "POST");
        if (!isFormContent(request)) return oauthError(arena, .bad_request, .invalid_request, "The request body must be a form", &.{});
        if (request.body.len > self.options.limits.max_body_bytes) return oauthError(arena, .payload_too_large, .invalid_request, "The request body is too large", &.{});
        const params = parseParams(arena, request.body, self.options.limits) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return oauthError(arena, .bad_request, .invalid_request, "The parameters are malformed or too large", &.{}),
        };
        if (params.duplicateName(&.{"resource"}) != null) return oauthError(arena, .bad_request, .invalid_request, "A parameter occurs more than once", &.{});
        const grant_type = params.get("grant_type") orelse return oauthError(arena, .bad_request, .invalid_request, "The grant_type parameter is missing", &.{});
        const t = self.now();

        // The proof comes first: a retry after `use_dpop_nonce` sends the same code, refresh
        // token and client assertion again.
        var proof: ?dpop.Proof = null;
        if (self.options.dpop.enabled) {
            const count = request.headerCount(dpop.header_name);
            if (count > 1) return oauthError(arena, .bad_request, .invalid_dpop_proof, "The request has more than one DPoP header", &.{});
            if (count == 1) {
                proof = dpop.verifyProof(arena, request.header(dpop.header_name).?, .{ .method = "POST", .uri = self.urls.token_endpoint }, .{
                    .algorithms = self.options.dpop.algorithms,
                    .nonce = self.options.dpop.nonce,
                }, t) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.UseNonce => return self.nonceError(arena, t),
                    else => return oauthError(arena, .bad_request, .invalid_dpop_proof, dpop.describe(e), &.{}),
                };
            } else if (self.options.dpop.required) {
                return oauthError(arena, .bad_request, .invalid_dpop_proof, "The server requires a DPoP proof", &.{});
            }
        }

        const caller = switch (try self.authenticate(arena, request, params, t)) {
            .ok => |c| c,
            .fail => |resp| return resp,
        };
        if (caller.client) |c| if (c.dpop_bound_access_tokens and proof == null) {
            return oauthError(arena, .bad_request, .invalid_dpop_proof, "The client must send a DPoP proof", &.{});
        };
        const ctx: GrantContext = .{ .arena = arena, .params = params, .caller = caller, .proof = proof, .now = t };
        const outcome = if (std.mem.eql(u8, grant_type, "authorization_code"))
            try self.authorizationCodeGrant(ctx)
        else if (std.mem.eql(u8, grant_type, "refresh_token"))
            try self.refreshTokenGrant(ctx)
        else if (std.mem.eql(u8, grant_type, "client_credentials"))
            try self.clientCredentialsGrant(ctx)
        else if (std.mem.eql(u8, grant_type, grant_type_jwt_bearer))
            try self.jwtBearerGrant(ctx)
        else
            GrantOutcome{ .fail = try oauthError(arena, .bad_request, .unsupported_grant_type, "The server does not offer this grant type", &.{}) };
        return switch (outcome) {
            .fail => |resp| resp,
            .issue => |issue| self.issueTokens(ctx, issue),
        };
    }

    fn nonceError(self: *AuthorizationServer, arena: Allocator, t: i64) Allocator.Error!Response {
        const issuer_of_nonces = self.options.dpop.nonce orelse return oauthError(arena, .bad_request, .invalid_dpop_proof, "The DPoP proof has no valid nonce", &.{});
        const buf = try arena.create([dpop.NonceIssuer.encoded_len]u8);
        const nonce = issuer_of_nonces.issue(self.io, buf, t) catch return oauthError(arena, .internal_server_error, .server_error, "The server has no random data", &.{});
        return oauthError(arena, .bad_request, .use_dpop_nonce, "The DPoP proof must carry the nonce of the server", &.{.{ .name = dpop.nonce_header_name, .value = nonce }});
    }

    const Caller = struct {
        /// Null for a request without a client, for example a workload JWT grant.
        client: ?Client,
    };

    const AuthOutcome = union(enum) { ok: Caller, fail: Response };

    /// Client authentication at the token endpoint (RFC 6749 section 2.3, RFC 7523 section 3).
    fn authenticate(self: *AuthorizationServer, arena: Allocator, request: *const Request, params: Params, t: i64) Allocator.Error!AuthOutcome {
        const basic: ?[]const u8 = if (request.header("authorization")) |h| if (startsWithScheme(h, "Basic")) std.mem.trim(u8, h[6..], " \t") else null else null;
        const secret_param = params.get("client_secret");
        const assertion = params.get("client_assertion");
        const assertion_type = params.get("client_assertion_type");
        const id_param = params.get("client_id");
        const methods = @as(u8, @intFromBool(basic != null)) + @intFromBool(secret_param != null) + @intFromBool(assertion != null or assertion_type != null);
        if (methods > 1) return .{ .fail = try oauthError(arena, .bad_request, .invalid_request, "The client uses more than one authentication method", &.{}) };

        if (basic) |encoded| {
            const pair = decodeBasic(arena, encoded) catch return .{ .fail = try invalidClient(arena, true, "The Basic credentials are malformed") };
            if (id_param) |id| if (!std.mem.eql(u8, id, pair.id)) return .{ .fail = try oauthError(arena, .bad_request, .invalid_request, "The client_id parameter is not the client of the credentials", &.{}) };
            // Some clients send the parts without the form encoding: try the raw id too.
            const found = (try self.findClient(arena, pair.id)) orelse if (!std.mem.eql(u8, pair.id, pair.raw_id)) try self.findClient(arena, pair.raw_id) else null;
            const client = found orelse return .{ .fail = try invalidClient(arena, true, "The client authentication failed") };
            if (!client.auth_method.hasSecret() or !secretOk(client, pair.secret, pair.raw_secret)) return .{ .fail = try invalidClient(arena, true, "The client authentication failed") };
            return .{ .ok = .{ .client = client } };
        }
        if (secret_param) |secret| {
            const id = id_param orelse return .{ .fail = try invalidClient(arena, false, "The client_id parameter is missing") };
            const client = (try self.findClient(arena, id)) orelse return .{ .fail = try invalidClient(arena, false, "The client authentication failed") };
            if (!client.auth_method.hasSecret() or !secretOk(client, secret, secret)) return .{ .fail = try invalidClient(arena, false, "The client authentication failed") };
            return .{ .ok = .{ .client = client } };
        }
        if (assertion != null or assertion_type != null) {
            const at = assertion_type orelse return .{ .fail = try invalidClient(arena, false, "The client_assertion_type parameter is missing") };
            if (!std.mem.eql(u8, at, common.client_assertion_type_jwt)) return .{ .fail = try invalidClient(arena, false, "The client assertion type is not supported") };
            const a = assertion orelse return .{ .fail = try invalidClient(arena, false, "The client_assertion parameter is missing") };
            const client = self.verifyClientAssertion(arena, a, id_param, t) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    log.debug("a client assertion failed: {t}", .{e});
                    return .{ .fail = try invalidClient(arena, false, assertionDescription(e)) };
                },
            };
            return .{ .ok = .{ .client = client } };
        }
        if (id_param) |id| {
            const client = (try self.findClient(arena, id)) orelse return .{ .fail = try invalidClient(arena, false, "The client is not known") };
            if (client.auth_method != .none) return .{ .fail = try invalidClient(arena, false, "The client must authenticate") };
            return .{ .ok = .{ .client = client } };
        }
        return .{ .ok = .{ .client = null } };
    }

    const AssertionError = error{
        OutOfMemory,
        Malformed,
        UnknownClient,
        WrongMethod,
        KeysUnavailable,
        BadSignature,
        WrongAudience,
        Expired,
        LifetimeTooLong,
        MissingJti,
        Replayed,
    };

    fn assertionDescription(err: AssertionError) []const u8 {
        return switch (err) {
            error.OutOfMemory => "The server is out of memory",
            error.Malformed => "The client assertion is malformed or lacks a required claim",
            error.UnknownClient, error.WrongMethod => "The client authentication failed",
            error.KeysUnavailable => "The keys of the client are not available",
            error.BadSignature => "The client assertion signature is not valid",
            error.WrongAudience => "The client assertion audience is not this server",
            error.Expired => "The client assertion expired",
            error.LifetimeTooLong => "The client assertion lifetime is too long",
            error.MissingJti => "The client assertion has no jti claim",
            error.Replayed => "The client assertion was used before",
        };
    }

    /// Check a `private_key_jwt` assertion (RFC 7523 section 3). The `jti` is single use.
    fn verifyClientAssertion(self: *AuthorizationServer, arena: Allocator, assertion: []const u8, id_param: ?[]const u8, t: i64) AssertionError!Client {
        const unverified = jwt.decodePayloadUnverified(arena, assertion) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed => error.Malformed,
        };
        const iss = json.getString(unverified, "iss") orelse return error.Malformed;
        if (id_param) |id| if (!std.mem.eql(u8, id, iss)) return error.Malformed;
        const client = (try self.findClient(arena, iss)) orelse return error.UnknownClient;
        if (client.auth_method != .private_key_jwt) return error.WrongMethod;
        const keys = try self.clientKeys(arena, &client, t);
        const claims = jwt.verify(arena, assertion, .{ .keys = keys, .issuer = client.client_id, .clock_skew_seconds = self.options.clock_skew_seconds }, t) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Expired => error.Expired,
            error.UnsupportedAlgorithm, error.UnknownKey, error.BadSignature => error.BadSignature,
            else => error.Malformed,
        };
        const sub = claims.subject orelse return error.Malformed;
        if (!std.mem.eql(u8, sub, client.client_id)) return error.Malformed;
        // The audience is the issuer identifier or the token endpoint of this server.
        var audience_ok = false;
        for (claims.audience) |a| {
            if (std.mem.eql(u8, a, self.urls.issuer) or common.uriEql(a, self.urls.token_endpoint)) audience_ok = true;
        }
        if (!audience_ok) return error.WrongAudience;
        const exp = claims.expires_at orelse return error.Malformed;
        if (exp -| t > self.options.max_assertion_lifetime_seconds +| self.options.clock_skew_seconds) return error.LifetimeTooLong;
        const jti = claims.jwt_id orelse return error.MissingJti;
        if (jti.len == 0 or jti.len > 256) return error.MissingJti;
        const fresh = self.store.recordJti(client.client_id, jti, exp +| self.options.clock_skew_seconds, t) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Replayed,
        };
        if (!fresh) return error.Replayed;
        return client;
    }

    /// The asymmetric verification keys of a client.
    fn clientKeys(self: *AuthorizationServer, arena: Allocator, client: *const Client, t: i64) AssertionError![]const jwt.Key {
        const text: []const u8 = if (client.jwks) |j| j else if (client.jwks_uri) |uri|
            self.fetcher.get(arena, uri, self.fetcher.options.max_jwks_bytes, t) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.KeysUnavailable,
            }
        else
            return error.KeysUnavailable;
        const all = jwt.parseJwks(arena, text) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed => error.KeysUnavailable,
        };
        var keys: std.ArrayList(jwt.Key) = .empty;
        for (all) |k| if (k.alg.isAsymmetric()) try keys.append(arena, k);
        return keys.items;
    }

    const GrantContext = struct {
        arena: Allocator,
        params: Params,
        caller: Caller,
        proof: ?dpop.Proof,
        now: i64,
    };

    /// What a grant gives: the claims of the access token and the refresh token to issue.
    const Issue = struct {
        subject: []const u8,
        client_id: []const u8,
        resource: []const u8,
        scopes: []const []const u8,
        auth_time: ?i64 = null,
        refresh: ?RefreshPlan = null,
    };

    const RefreshPlan = struct {
        family: store_mod.FamilyId,
        /// The scopes of the grant family.
        scope: []const u8,
        dpop_jkt: ?[]const u8,
        expires_at: i64,
    };

    const GrantOutcome = union(enum) { issue: Issue, fail: Response };

    fn failGrant(arena: Allocator, code: Code, description: []const u8) Allocator.Error!GrantOutcome {
        return .{ .fail = try oauthError(arena, .bad_request, code, description, &.{}) };
    }

    fn authorizationCodeGrant(self: *AuthorizationServer, ctx: GrantContext) Allocator.Error!GrantOutcome {
        const arena = ctx.arena;
        if (!self.options.grants.authorization_code or self.options.authorizer == null) return failGrant(arena, .unsupported_grant_type, "The server does not offer this grant type");
        const client = ctx.caller.client orelse return failGrant(arena, .invalid_request, "The client_id parameter is missing");
        if (!client.grant_types.authorization_code) return failGrant(arena, .unauthorized_client, "The client cannot use the authorization code grant");
        const code = ctx.params.get("code") orelse return failGrant(arena, .invalid_request, "The code parameter is missing");
        const verifier = ctx.params.get("code_verifier") orelse return failGrant(arena, .invalid_request, "The code_verifier parameter is missing");
        if (!validVerifier(verifier)) return failGrant(arena, .invalid_request, "The code_verifier parameter is malformed");
        const hash = store_mod.hashSecret(code);
        const taken = (self.store.takeCode(arena, &hash, ctx.now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return failGrant(arena, .temporarily_unavailable, "The store is not available"),
        }) orelse return failGrant(arena, .invalid_grant, "The authorization code is not valid");
        const rec = taken.record;
        if (taken.state != .active) {
            // OAuth 2.1 section 4.1.3: a code that comes twice revokes the tokens of its grant.
            // The access tokens are JWTs and stay valid until they expire.
            log.warn("an authorization code came a second time: the server revokes the refresh tokens of its grant", .{});
            self.store.revokeFamily(&rec.family, ctx.now) catch {};
            return failGrant(arena, .invalid_grant, "The authorization code was used before");
        }
        if (!std.mem.eql(u8, rec.client_id, client.client_id)) return failGrant(arena, .invalid_grant, "The authorization code belongs to another client");
        if (ctx.params.get("redirect_uri")) |given| {
            if (!std.mem.eql(u8, given, rec.redirect_uri)) return failGrant(arena, .invalid_grant, "The redirect_uri is not the one of the authorization request");
        } else if (rec.redirect_uri_given) return failGrant(arena, .invalid_grant, "The redirect_uri parameter is missing");
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(verifier, &digest, .{});
        var expected: [43]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&expected, &digest);
        if (rec.code_challenge.len != 43 or !std.crypto.timing_safe.eql([43]u8, expected, rec.code_challenge[0..43].*)) {
            return failGrant(arena, .invalid_grant, "The code_verifier does not match the code_challenge");
        }
        if (ctx.params.get("resource")) |res| if (!common.uriEql(res, rec.resource)) return failGrant(arena, .invalid_target, "The resource is not the one of the authorization request");
        if (rec.dpop_jkt) |jkt| {
            const p = ctx.proof orelse return failGrant(arena, .invalid_grant, "The authorization code is bound to a DPoP key");
            if (!std.mem.eql(u8, p.jkt, jkt)) return failGrant(arena, .invalid_grant, "The DPoP key is not the key of the authorization code");
        }
        return .{ .issue = .{
            .subject = rec.subject,
            .client_id = client.client_id,
            .resource = rec.resource,
            .scopes = try client_metadata.splitScope(arena, rec.scope),
            .auth_time = rec.auth_time,
            .refresh = if (self.refreshAllowed(&client)) .{
                .family = rec.family,
                .scope = rec.scope,
                .dpop_jkt = self.refreshBinding(&client, ctx.proof),
                .expires_at = ctx.now + self.options.refresh_token_lifetime_seconds,
            } else null,
        } };
    }

    fn refreshAllowed(self: *const AuthorizationServer, client: *const Client) bool {
        return self.options.issue_refresh_tokens and self.options.grants.refresh_token and client.grant_types.refresh_token;
    }

    /// RFC 9449 section 5: the refresh token of a public client binds to its DPoP key.
    fn refreshBinding(self: *const AuthorizationServer, client: *const Client, proof: ?dpop.Proof) ?[]const u8 {
        _ = self;
        if (client.auth_method != .none) return null;
        const p = proof orelse return null;
        return p.jkt;
    }

    fn refreshTokenGrant(self: *AuthorizationServer, ctx: GrantContext) Allocator.Error!GrantOutcome {
        const arena = ctx.arena;
        if (!self.options.grants.refresh_token) return failGrant(arena, .unsupported_grant_type, "The server does not offer this grant type");
        const client = ctx.caller.client orelse return failGrant(arena, .invalid_request, "The client_id parameter is missing");
        if (!client.grant_types.refresh_token) return failGrant(arena, .unauthorized_client, "The client cannot use the refresh token grant");
        const token = ctx.params.get("refresh_token") orelse return failGrant(arena, .invalid_request, "The refresh_token parameter is missing");
        const hash = store_mod.hashSecret(token);
        const taken = (self.store.takeRefreshToken(arena, &hash, ctx.now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return failGrant(arena, .temporarily_unavailable, "The store is not available"),
        }) orelse return failGrant(arena, .invalid_grant, "The refresh token is not valid");
        const rec = taken.record;
        if (taken.state != .active) {
            // A rotated token that comes again: somebody has a copy. Revoke the family.
            if (taken.state == .used) log.warn("a rotated refresh token came a second time: the server revokes its grant", .{});
            self.store.revokeFamily(&rec.family, ctx.now) catch {};
            return failGrant(arena, .invalid_grant, "The refresh token is not valid");
        }
        if (!std.mem.eql(u8, rec.client_id, client.client_id)) return failGrant(arena, .invalid_grant, "The refresh token belongs to another client");
        if (rec.dpop_jkt) |jkt| {
            const p = ctx.proof orelse return failGrant(arena, .invalid_grant, "The refresh token is bound to a DPoP key");
            if (!std.mem.eql(u8, p.jkt, jkt)) return failGrant(arena, .invalid_grant, "The DPoP key is not the key of the refresh token");
        }
        // A wrong resource or scope is a mistake of the client: the token stays valid.
        if (ctx.params.get("resource")) |res| if (!common.uriEql(res, rec.resource)) {
            self.store.putRefreshToken(&hash, &rec, ctx.now) catch {};
            return failGrant(arena, .invalid_target, "The resource is not the one of the grant");
        };
        const held = try client_metadata.splitScope(arena, rec.scope);
        var scopes = held;
        if (ctx.params.get("scope")) |text| {
            // RFC 6749 section 6: a refresh request can ask for fewer scopes, not for more.
            // A malformed scope is not part of the grant either.
            const malformed: [1][]const u8 = .{text};
            const asked: []const []const u8 = parseScope(arena, text, self.options.limits.max_scopes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => &malformed,
            };
            for (asked) |s| if (!common.listContains(held, s)) {
                self.store.putRefreshToken(&hash, &rec, ctx.now) catch {};
                return failGrant(arena, .invalid_scope, "The scope is not part of the grant");
            };
            scopes = asked;
        }
        return .{ .issue = .{
            .subject = rec.subject,
            .client_id = client.client_id,
            .resource = rec.resource,
            .scopes = scopes,
            .auth_time = rec.auth_time,
            .refresh = .{ .family = rec.family, .scope = rec.scope, .dpop_jkt = rec.dpop_jkt, .expires_at = rec.expires_at },
        } };
    }

    fn clientCredentialsGrant(self: *AuthorizationServer, ctx: GrantContext) Allocator.Error!GrantOutcome {
        const arena = ctx.arena;
        if (!self.options.grants.client_credentials) return failGrant(arena, .unsupported_grant_type, "The server does not offer this grant type");
        const client = ctx.caller.client orelse return .{ .fail = try invalidClient(arena, false, "The grant needs client authentication") };
        // Only a confidential client can use this grant (RFC 6749 section 4.4).
        if (client.auth_method == .none) return failGrant(arena, .unauthorized_client, "A public client cannot use the client credentials grant");
        if (!client.grant_types.client_credentials) return failGrant(arena, .unauthorized_client, "The client cannot use the client credentials grant");
        const resource = self.resolveResource(ctx.params) catch return failGrant(arena, .invalid_target, "The server does not issue tokens for this resource");
        const scopes = self.requestedScopes(arena, ctx.params.get("scope"), &client, resource) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return failGrant(arena, .invalid_scope, "The scope is not valid for the client or the resource"),
        };
        return .{ .issue = .{ .subject = client.client_id, .client_id = client.client_id, .resource = resource.uri, .scopes = scopes } };
    }

    fn jwtBearerGrant(self: *AuthorizationServer, ctx: GrantContext) Allocator.Error!GrantOutcome {
        const arena = ctx.arena;
        const grants = self.options.grants;
        if (grants.id_jag == null and grants.workload == null) return failGrant(arena, .unsupported_grant_type, "The server does not offer this grant type");
        const assertion = ctx.params.get("assertion") orelse return failGrant(arena, .invalid_request, "The assertion parameter is missing");
        if (ctx.caller.client) |c| if (!c.grant_types.jwt_bearer) return failGrant(arena, .unauthorized_client, "The client cannot use the JWT bearer grant");
        const is_id_jag = hasType(arena, assertion, enterprise.jwt_type);
        if (grants.id_jag != null and (is_id_jag or grants.workload == null)) return self.idJagGrant(ctx, assertion);
        return self.workloadGrant(ctx, assertion);
    }

    fn idJagGrant(self: *AuthorizationServer, ctx: GrantContext, assertion: []const u8) Allocator.Error!GrantOutcome {
        const arena = ctx.arena;
        const client = ctx.caller.client orelse return .{ .fail = try invalidClient(arena, false, "The ID-JAG grant needs a client") };
        var validator = self.options.grants.id_jag.?.*;
        if (validator.replay == null) validator.replay = .{ .userdata = self, .seen = seenGrantJti };
        const grant = validator.validate(arena, assertion, client.client_id, ctx.now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .fail = try jsonResponse(arena, .bad_request, try enterprise.errorResponse(arena, e), &.{}) },
        };
        // The token is for a resource that the ID-JAG names, when it names one.
        const resource: Resource = blk: {
            if (ctx.params.get("resource") != null or grant.resources.len == 0) {
                const r = self.resolveResource(ctx.params) catch return failGrant(arena, .invalid_target, "The server does not issue tokens for this resource");
                if (grant.resources.len > 0 and !containsUri(grant.resources, r.uri)) return failGrant(arena, .invalid_target, "The ID-JAG does not name this resource");
                break :blk r;
            }
            for (grant.resources) |uri| if (self.findResource(uri)) |r| break :blk r;
            return failGrant(arena, .invalid_target, "The server does not issue tokens for the resource of the ID-JAG");
        };
        var scopes = try self.grantedScopes(arena, grant.scopes, &client, resource);
        if (ctx.params.get("scope")) |text| {
            const asked = parseScope(arena, text, self.options.limits.max_scopes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return failGrant(arena, .invalid_scope, "The scope is malformed"),
            };
            for (asked) |s| if (!common.listContains(scopes, s)) return failGrant(arena, .invalid_scope, "The scope is larger than the ID-JAG");
            scopes = asked;
        }
        return .{ .issue = .{ .subject = grant.subject, .client_id = client.client_id, .resource = resource.uri, .scopes = scopes } };
    }

    fn workloadGrant(self: *AuthorizationServer, ctx: GrantContext, assertion: []const u8) Allocator.Error!GrantOutcome {
        const arena = ctx.arena;
        var validator = self.options.grants.workload.?.*;
        if (validator.replay == null) validator.replay = .{ .userdata = self, .seen = seenGrantJti };
        const grant = validator.validate(arena, assertion, ctx.now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .fail = try jsonResponse(arena, .bad_request, try workload_identity.errorResponse(arena, e), &.{}) },
        };
        const resource = self.resolveResource(ctx.params) catch return failGrant(arena, .invalid_target, "The server does not issue tokens for this resource");
        const no_client: Client = .{ .client_id = grant.subject };
        const client = ctx.caller.client orelse no_client;
        const scopes = self.requestedScopes(arena, ctx.params.get("scope"), &client, resource) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return failGrant(arena, .invalid_scope, "The scope is not valid for the workload or the resource"),
        };
        return .{ .issue = .{ .subject = grant.subject, .client_id = client.client_id, .resource = resource.uri, .scopes = scopes } };
    }

    /// The replay check of the validators: the store records each `jti`.
    fn seenGrantJti(userdata: ?*anyopaque, iss: []const u8, jti: []const u8, expires_at: i64) bool {
        const self: *AuthorizationServer = @ptrCast(@alignCast(userdata.?));
        const fresh = self.store.recordJti(iss, jti, expires_at +| self.options.clock_skew_seconds, self.now()) catch return true;
        return !fresh;
    }

    /// Issue the access token and the refresh token of a grant.
    fn issueTokens(self: *AuthorizationServer, ctx: GrantContext, issue: Issue) Allocator.Error!Response {
        const arena = ctx.arena;
        const jkt: ?[]const u8 = if (ctx.proof) |p| p.jkt else null;
        const scope_text = try std.mem.join(arena, " ", issue.scopes);
        const access = self.signAccessToken(arena, issue, scope_text, jkt, ctx.now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return oauthError(arena, .internal_server_error, .server_error, "The server cannot sign the token", &.{}),
        };
        var refresh_token: ?[]const u8 = null;
        if (issue.refresh) |plan| {
            var raw: [32]u8 = undefined;
            self.io.randomSecure(&raw) catch return oauthError(arena, .internal_server_error, .server_error, "The server has no random data", &.{});
            const token = try common.base64Url(arena, &raw);
            const hash = store_mod.hashSecret(token);
            const record: store_mod.RefreshRecord = .{
                .client_id = issue.client_id,
                .subject = issue.subject,
                .scope = plan.scope,
                .resource = issue.resource,
                .dpop_jkt = plan.dpop_jkt,
                .family = plan.family,
                .auth_time = issue.auth_time orelse ctx.now,
                .expires_at = plan.expires_at,
            };
            self.store.putRefreshToken(&hash, &record, ctx.now) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.FamilyRevoked => return oauthError(arena, .bad_request, .invalid_grant, "The grant is revoked", &.{}),
                else => return oauthError(arena, .service_unavailable, .temporarily_unavailable, "The server cannot store the refresh token", &.{}),
            };
            refresh_token = token;
        }
        var aw: Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        w.print("{{\"access_token\":\"{s}\",\"token_type\":\"{s}\",\"expires_in\":{d}", .{ access, if (jkt != null) dpop.token_type else "Bearer", self.options.access_token_lifetime_seconds }) catch return error.OutOfMemory;
        if (scope_text.len > 0) w.print(",\"scope\":{f}", .{std.json.fmt(scope_text, .{})}) catch return error.OutOfMemory;
        if (refresh_token) |rt| w.print(",\"refresh_token\":\"{s}\"", .{rt}) catch return error.OutOfMemory;
        w.writeByte('}') catch return error.OutOfMemory;
        // A new nonce for the next request of the client (RFC 9449 section 8.2).
        if (self.options.dpop.nonce) |issuer_of_nonces| if (ctx.proof != null) {
            const buf = try arena.create([dpop.NonceIssuer.encoded_len]u8);
            if (issuer_of_nonces.issue(self.io, buf, ctx.now)) |nonce| {
                return jsonResponse(arena, .ok, aw.written(), &.{.{ .name = dpop.nonce_header_name, .value = nonce }});
            } else |_| {}
        };
        return jsonResponse(arena, .ok, aw.written(), &.{});
    }

    /// Sign a JWT access token (RFC 9068).
    fn signAccessToken(self: *AuthorizationServer, arena: Allocator, issue: Issue, scope: []const u8, jkt: ?[]const u8, t: i64) (jwt.SignError || error{EntropyUnavailable})![]u8 {
        var jti: [16]u8 = undefined;
        self.io.randomSecure(&jti) catch return error.EntropyUnavailable;
        var aw: Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        w.print("{{\"iss\":{f},\"sub\":{f},\"aud\":{f},\"client_id\":{f},\"scope\":{f},\"iat\":{d},\"exp\":{d},\"jti\":\"{s}\"", .{
            std.json.fmt(self.urls.issuer, .{}),
            std.json.fmt(issue.subject, .{}),
            std.json.fmt(issue.resource, .{}),
            std.json.fmt(issue.client_id, .{}),
            std.json.fmt(scope, .{}),
            t,
            t + self.options.access_token_lifetime_seconds,
            try common.base64Url(arena, &jti),
        }) catch return error.OutOfMemory;
        if (issue.auth_time) |at| w.print(",\"auth_time\":{d}", .{at}) catch return error.OutOfMemory;
        if (jkt) |k| w.print(",\"cnf\":{{\"jkt\":{f}}}", .{std.json.fmt(k, .{})}) catch return error.OutOfMemory;
        w.writeByte('}') catch return error.OutOfMemory;
        const key = self.options.signing_keys[0];
        return jwt.sign(arena, key.key, aw.written(), .{ .kid = key.kid, .typ = access_token_type });
    }

    // -- Registration endpoint --------------------------------------------------------------

    fn registrationEndpoint(self: *AuthorizationServer, arena: Allocator, request: *const Request) Allocator.Error!Response {
        const dcr = self.options.dynamic_registration.?;
        if (request.method != .POST) return methodNotAllowed(arena, "POST");
        if (dcr.initial_access_token) |want| {
            const h = request.header("authorization") orelse "";
            const ok = startsWithScheme(h, "Bearer") and constantTimeEql(std.mem.trim(u8, h[7..], " \t"), want);
            if (!ok) return oauthError(arena, .unauthorized, .invalid_token, "The registration needs a valid initial access token", &.{.{ .name = "www-authenticate", .value = "Bearer error=\"invalid_token\"" }});
        }
        const ct = request.header("content-type") orelse "";
        if (!std.ascii.startsWithIgnoreCase(ct, "application/json")) return oauthError(arena, .bad_request, .invalid_client_metadata, "The request body must be JSON", &.{});
        if (request.body.len > self.options.limits.max_body_bytes) return oauthError(arena, .payload_too_large, .invalid_client_metadata, "The request body is too large", &.{});
        const tree = json.parseTree(arena, request.body) catch return oauthError(arena, .bad_request, .invalid_client_metadata, "The request body is not valid JSON", &.{});
        if (tree != .object) return oauthError(arena, .bad_request, .invalid_client_metadata, "The request body is not a JSON object", &.{});

        const redirect_uris = client_metadata.redirectUris(arena, tree) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return oauthError(arena, .bad_request, .invalid_redirect_uri, "Each redirect URI must use https, or http with a loopback host", &.{}),
        };
        const method_text = json.getString(tree, "token_endpoint_auth_method") orelse "client_secret_basic";
        const method = std.meta.stringToEnum(AuthMethod, method_text) orelse return oauthError(arena, .bad_request, .invalid_client_metadata, "The server does not offer this token_endpoint_auth_method", &.{});
        var grant_types = client_metadata.grantTypes(tree, .{ .authorization_code = true }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return oauthError(arena, .bad_request, .invalid_client_metadata, "The server does not offer a grant type of the client", &.{}),
        };
        client_metadata.checkResponseTypes(tree) catch return oauthError(arena, .bad_request, .invalid_client_metadata, "The server offers the response type code only", &.{});
        if (grant_types.jwt_bearer) return oauthError(arena, .bad_request, .invalid_client_metadata, "The server does not offer this grant type for registered clients", &.{});
        if (grant_types.client_credentials and (!dcr.allow_client_credentials or method == .none)) return oauthError(arena, .bad_request, .invalid_client_metadata, "The client cannot register the client credentials grant", &.{});
        if (grant_types.authorization_code and redirect_uris.len == 0) return oauthError(arena, .bad_request, .invalid_redirect_uri, "The authorization code grant needs redirect_uris", &.{});
        if (!grant_types.authorization_code) grant_types.refresh_token = false;
        var client: Client = .{
            .client_id = undefined,
            .auth_method = method,
            .redirect_uris = redirect_uris,
            .grant_types = grant_types,
            .issued_at = self.now(),
        };
        if (json.getString(tree, "client_name")) |name| {
            if (name.len > 256) return oauthError(arena, .bad_request, .invalid_client_metadata, "The client_name is too long", &.{});
            client.client_name = name;
        }
        if (json.getString(tree, "scope")) |s| {
            const scopes = parseScope(arena, s, self.options.limits.max_scopes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return oauthError(arena, .bad_request, .invalid_client_metadata, "The scope is malformed", &.{}),
            };
            for (scopes) |one| if (!common.listContains(self.options.scopes_supported, one)) return oauthError(arena, .bad_request, .invalid_client_metadata, "The server does not offer a scope of the client", &.{});
            client.scopes = scopes;
        }
        if (common.boolField(tree, "dpop_bound_access_tokens")) |b| client.dpop_bound_access_tokens = b;
        client_metadata.readKeys(arena, tree, &client) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return oauthError(arena, .bad_request, .invalid_client_metadata, "The keys of the client are not valid", &.{}),
        };
        var id_bytes: [16]u8 = undefined;
        var secret_bytes: [32]u8 = undefined;
        self.io.randomSecure(&id_bytes) catch return oauthError(arena, .internal_server_error, .server_error, "The server has no random data", &.{});
        self.io.randomSecure(&secret_bytes) catch return oauthError(arena, .internal_server_error, .server_error, "The server has no random data", &.{});
        client.client_id = try common.base64Url(arena, &id_bytes);
        var secret: ?[]const u8 = null;
        if (method.hasSecret()) {
            secret = try common.base64Url(arena, &secret_bytes);
            client.secret_hash = store_mod.hashSecret(secret.?);
        }
        self.store.putClient(&client) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return oauthError(arena, .service_unavailable, .temporarily_unavailable, "The server cannot store the client", &.{}),
        };

        var aw: Io.Writer.Allocating = .init(arena);
        const w = &aw.writer;
        w.print("{{\"client_id\":\"{s}\",\"client_id_issued_at\":{d}", .{ client.client_id, client.issued_at }) catch return error.OutOfMemory;
        if (secret) |s| w.print(",\"client_secret\":\"{s}\",\"client_secret_expires_at\":0", .{s}) catch return error.OutOfMemory;
        w.print(",\"token_endpoint_auth_method\":\"{t}\",\"redirect_uris\":", .{method}) catch return error.OutOfMemory;
        writeStringArray(w, redirect_uris) catch return error.OutOfMemory;
        w.writeAll(",\"grant_types\":[") catch return error.OutOfMemory;
        writeGrantTypes(w, grant_types) catch return error.OutOfMemory;
        w.writeAll("],\"response_types\":") catch return error.OutOfMemory;
        w.writeAll(if (grant_types.authorization_code) "[\"code\"]" else "[]") catch return error.OutOfMemory;
        if (client.client_name) |n| w.print(",\"client_name\":{f}", .{std.json.fmt(n, .{})}) catch return error.OutOfMemory;
        if (client.scopes.len > 0) w.print(",\"scope\":{f}", .{std.json.fmt(try std.mem.join(arena, " ", client.scopes), .{})}) catch return error.OutOfMemory;
        if (client.dpop_bound_access_tokens) w.writeAll(",\"dpop_bound_access_tokens\":true") catch return error.OutOfMemory;
        w.writeByte('}') catch return error.OutOfMemory;
        return jsonResponse(arena, .created, aw.written(), &.{});
    }

    // -- Clients, resources and scopes ------------------------------------------------------

    /// The client with `client_id`: from the store, else from its metadata document.
    fn findClient(self: *AuthorizationServer, arena: Allocator, client_id: []const u8) Allocator.Error!?Client {
        if (client_id.len == 0 or client_id.len > 2048) return null;
        if (self.store.getClient(arena, client_id) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        }) |c| return c;
        if (self.options.client_metadata == null) return null;
        if (!common.validClientIdUrl(client_id)) return null;
        const body = self.fetcher.get(arena, client_id, self.fetcher.options.max_document_bytes, self.now()) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.info("the client metadata document is not available: {t}", .{e});
                return null;
            },
        };
        return client_metadata.parseDocument(arena, client_id, body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.info("the client metadata document is not valid: {s}", .{client_metadata.describe(e)});
                return null;
            },
        };
    }

    fn findResource(self: *const AuthorizationServer, uri: []const u8) ?Resource {
        for (self.options.resources) |r| if (common.uriEql(r.uri, uri)) return r;
        return null;
    }

    /// The resource of a request: its one `resource` parameter, else the first resource.
    fn resolveResource(self: *const AuthorizationServer, params: Params) error{InvalidTarget}!Resource {
        const n = params.count("resource");
        if (n > 1) return error.InvalidTarget;
        const uri = params.get("resource") orelse return self.options.resources[0];
        return self.findResource(uri) orelse error.InvalidTarget;
    }

    fn scopeAllowed(self: *const AuthorizationServer, scope: []const u8, client: *const Client, resource: Resource) bool {
        if (!common.listContains(self.options.scopes_supported, scope)) return false;
        if (client.scopes.len > 0 and !common.listContains(client.scopes, scope)) return false;
        if (resource.scopes.len > 0 and !common.listContains(resource.scopes, scope)) return false;
        return true;
    }

    /// The scopes of a request. Without `scope`, the default scopes that the client and the
    /// resource permit.
    fn requestedScopes(self: *const AuthorizationServer, arena: Allocator, text: ?[]const u8, client: *const Client, resource: Resource) (Allocator.Error || error{InvalidScope})![]const []const u8 {
        const t = text orelse return self.grantedScopes(arena, self.options.default_scopes, client, resource);
        const asked = try parseScope(arena, t, self.options.limits.max_scopes);
        for (asked) |s| if (!self.scopeAllowed(s, client, resource)) return error.InvalidScope;
        return asked;
    }

    /// The scopes of `list` that the server, the client and the resource permit.
    fn grantedScopes(self: *const AuthorizationServer, arena: Allocator, list: []const []const u8, client: *const Client, resource: Resource) Allocator.Error![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        for (list) |s| if (self.scopeAllowed(s, client, resource)) try common.appendUnique(arena, &out, s);
        return out.items;
    }

    // -- Consent tokens ---------------------------------------------------------------------

    /// The length of a consent token.
    pub const consent_token_len = 43;

    /// A token that binds a consent form to the browser of the user and to one authorization
    /// request. Put it into the form. When the form returns, check it with
    /// `checkConsentToken`. Thus another site cannot send the form for the user. `binding` is
    /// a secret value that the application keeps for the browser of the user, for example the
    /// value of a sign-in cookie.
    pub fn consentToken(self: *const AuthorizationServer, buf: *[consent_token_len]u8, binding: []const u8, request: *const AuthorizationRequest) []const u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        var h = HmacSha256.init(&self.consent_key);
        for ([_][]const u8{ binding, request.client_id, request.redirect_uri, request.resource, request.code_challenge, request.state orelse "" }) |part| {
            var len: [8]u8 = undefined;
            std.mem.writeInt(u64, &len, part.len, .big);
            h.update(&len);
            h.update(part);
        }
        for (request.scopes) |s| {
            h.update(s);
            h.update(" ");
        }
        h.final(&mac);
        return std.base64.url_safe_no_pad.Encoder.encode(buf, &mac);
    }

    /// True when `token` is the consent token of `binding` and `request`. The comparison
    /// takes constant time.
    pub fn checkConsentToken(self: *const AuthorizationServer, binding: []const u8, request: *const AuthorizationRequest, token: []const u8) bool {
        var buf: [consent_token_len]u8 = undefined;
        const want = self.consentToken(&buf, binding, request);
        return token.len == want.len and std.crypto.timing_safe.eql([consent_token_len]u8, want[0..consent_token_len].*, token[0..consent_token_len].*);
    }

    // -- HTTP -------------------------------------------------------------------------------

    /// Answer one request of a `std.http.Server`. Returns false when the path is not an
    /// endpoint of the server: then the function read and sent nothing, and the caller answers
    /// the request. `context` goes to the authorizer in `Request.context`.
    pub fn handleHttp(self: *AuthorizationServer, request: *http.Server.Request, context: ?*anyopaque) !bool {
        if (!self.isEndpoint(request.head.target)) return false;
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const resp = try self.readAndHandle(arena, request, context);
        try respondHttp(request, resp, request.head.keep_alive);
        return true;
    }

    fn readAndHandle(self: *AuthorizationServer, arena: Allocator, request: *http.Server.Request, context: ?*anyopaque) !Response {
        // Copy the head: the body can use its buffer.
        const target = try arena.dupe(u8, request.head.target);
        var headers: std.ArrayList(http.Header) = .empty;
        var it = request.iterateHeaders();
        while (it.next()) |h| {
            if (headers.items.len >= 100) break;
            try headers.append(arena, .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) });
        }
        const limit = self.options.limits.max_body_bytes;
        // The server does not read the body of these requests, so the connection ends.
        if (request.head.expect != null) {
            request.head.keep_alive = false;
            return errorPage(arena, .expectation_failed, .invalid_request, "The server does not send 100 Continue");
        }
        if (request.head.content_length) |len| if (len > limit) {
            request.head.keep_alive = false;
            return errorPage(arena, .payload_too_large, .invalid_request, "The request body is too large");
        };
        if (request.head.transfer_encoding == .none and request.head.content_length == null) request.head.content_length = 0;
        var body_buf: [4096]u8 = undefined;
        const body = request.readerExpectNone(&body_buf).allocRemaining(arena, .limited(limit)) catch |e| switch (e) {
            error.StreamTooLong => {
                request.head.keep_alive = false;
                return errorPage(arena, .payload_too_large, .invalid_request, "The request body is too large");
            },
            error.OutOfMemory => return error.OutOfMemory,
            error.ReadFailed => return error.ReadFailed,
        };
        const req: Request = .{ .method = request.head.method, .target = target, .headers = headers.items, .body = body, .context = context };
        return (try self.handle(arena, &req)) orelse errorPage(arena, .not_found, .invalid_request, "Not found");
    }

    /// Bind the listen socket. After this call `bound_port` has the port.
    pub fn listen(self: *AuthorizationServer, options: ListenOptions) !void {
        self.listen_options = options;
        self.permits = .{ .permits = options.max_connections };
        self.listen_options.listener = null;
        if (options.listener) |l| {
            self.listener = l;
        } else {
            var address = try Io.net.IpAddress.parse(options.address, options.port);
            self.listener = try address.listen(self.io, .{ .reuse_address = true });
        }
        self.bound_port = self.listener.?.socket.address.getPort();
    }

    /// Accept connections until a call to `shutdown`. Call `listen` first.
    pub fn serve(self: *AuthorizationServer) !void {
        if (self.listener == null) return error.NotListening;
        var accept_future = try self.io.concurrent(acceptLoop, .{self});
        self.stop_event.wait(self.io) catch {};
        wake.cancelAcceptLoop(self.io, &accept_future, self.listener.?.socket.address, &self.closing);
        self.group.await(self.io) catch {};
    }

    /// Accept no more connections and end the open ones. Safe to call from another task.
    pub fn shutdown(self: *AuthorizationServer) void {
        self.closing.store(true, .release);
        self.stop_event.set(self.io);
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items) |c| c.stream.shutdown(self.io, .both) catch {};
    }

    fn acceptLoop(self: *AuthorizationServer) void {
        while (!self.closing.load(.acquire)) {
            const stream = self.listener.?.accept(self.io) catch |e| switch (e) {
                error.SocketNotListening, error.Canceled => return,
                else => {
                    log.warn("accept failed: {t}", .{e});
                    continue;
                },
            };
            // The connection of `wake`, or a peer that came during the shutdown.
            if (self.closing.load(.acquire)) {
                stream.close(self.io);
                return;
            }
            self.permits.waitUncancelable(self.io);
            const conn = self.gpa.create(Connection) catch {
                self.permits.post(self.io);
                stream.close(self.io);
                continue;
            };
            conn.* = .{ .owner = self, .stream = stream };
            self.track(conn);
            self.group.concurrent(self.io, Connection.run, .{conn}) catch {
                self.untrack(conn);
                self.permits.post(self.io);
                stream.close(self.io);
                self.gpa.destroy(conn);
            };
        }
    }

    fn track(self: *AuthorizationServer, conn: *Connection) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        self.connections.append(self.gpa, conn) catch {};
    }

    fn untrack(self: *AuthorizationServer, conn: *Connection) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items, 0..) |c, i| if (c == conn) {
            _ = self.connections.swapRemove(i);
            return;
        };
    }
};

/// One connection of the listener.
const Connection = struct {
    owner: *AuthorizationServer,
    stream: Io.net.Stream,

    fn run(conn: *Connection) Io.Cancelable!void {
        const self = conn.owner;
        defer {
            self.untrack(conn);
            conn.stream.close(self.io);
            self.permits.post(self.io);
            self.gpa.destroy(conn);
        }
        const options = self.listen_options;
        const read_buf = self.gpa.alloc(u8, @max(options.max_head_bytes + 4096, tls.Connection.min_input_buffer_len)) catch return;
        defer self.gpa.free(read_buf);
        const write_buf = self.gpa.alloc(u8, tls.Connection.min_output_buffer_len) catch return;
        defer self.gpa.free(write_buf);
        var reader = conn.stream.reader(self.io, read_buf);
        var writer = conn.stream.writer(self.io, write_buf);

        var tls_conn: tls.Connection = undefined;
        var tls_active = false;
        var tls_read_buf: []u8 = &.{};
        var tls_write_buf: []u8 = &.{};
        defer {
            if (tls_active) {
                tls_conn.end() catch {};
                tls_conn.deinit();
            }
            self.gpa.free(tls_read_buf);
            self.gpa.free(tls_write_buf);
        }
        if (options.tls) |tls_server| {
            tls_read_buf = self.gpa.alloc(u8, tls.Connection.min_read_buffer_len) catch return;
            tls_write_buf = self.gpa.alloc(u8, 16 * 1024) catch return;
            tls_conn = tls_server.accept(&reader.interface, &writer.interface, .{
                .io = self.io,
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .allow_truncation_attacks = true,
            }) catch return;
            tls_active = true;
        }
        const in: *Io.Reader = if (tls_active) &tls_conn.reader else &reader.interface;
        const out: *Io.Writer = if (tls_active) &tls_conn.writer else &writer.interface;
        var http_server: http.Server = .init(in, out);
        var served: usize = 0;
        while (!self.closing.load(.acquire) and served < options.max_requests_per_connection) : (served += 1) {
            var request = http_server.receiveHead() catch |e| switch (e) {
                error.HttpHeadersOversize => {
                    out.writeAll("HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                    out.flush() catch {};
                    return;
                },
                else => return,
            };
            var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena_state.deinit();
            const resp = self.readAndHandle(arena_state.allocator(), &request, null) catch return;
            const keep_alive = request.head.keep_alive and served + 1 < options.max_requests_per_connection;
            respondHttp(&request, resp, keep_alive) catch return;
            if (!keep_alive) return;
        }
    }
};

/// Send `resp` on a request of a `std.http.Server`.
pub fn respondHttp(request: *http.Server.Request, resp: Response, keep_alive: bool) !void {
    try request.respond(resp.body, .{ .status = resp.status, .keep_alive = keep_alive, .extra_headers = resp.headers });
}

// -- Documents ---------------------------------------------------------------------------------

fn checkOptions(options: Options) InitError!void {
    const parts = common.splitUri(options.issuer) orelse return error.InvalidIssuer;
    if (parts.host().len == 0 or parts.userinfo.len > 0) return error.InvalidIssuer;
    if (std.mem.indexOfAny(u8, parts.rest, "?#") != null) return error.InvalidIssuer;
    if (parts.rest.len > 0 and parts.rest[parts.rest.len - 1] == '/') return error.InvalidIssuer;
    try checkSecure(options.allow_http, options.issuer);
    if (options.signing_keys.len == 0) return error.NoSigningKey;
    for (options.signing_keys, 0..) |k, i| {
        if (!k.key.algorithm().isAsymmetric()) return error.SymmetricKey;
        if (k.kid.len == 0) return error.InvalidKeyId;
        for (options.signing_keys[0..i]) |other| if (std.mem.eql(u8, other.kid, k.kid)) return error.InvalidKeyId;
    }
    if (options.resources.len == 0) return error.NoResource;
    for (options.resources) |r| {
        const rp = common.splitUri(r.uri) orelse return error.InvalidResource;
        if (rp.host().len == 0 or std.mem.indexOfScalar(u8, rp.rest, '#') != null) return error.InvalidResource;
        checkSecure(options.allow_http, r.uri) catch return error.InsecureUrl;
        for (r.scopes) |s| if (!common.listContains(options.scopes_supported, s)) return error.InvalidScope;
    }
    for (options.scopes_supported) |s| if (!validScopeToken(s)) return error.InvalidScope;
    for (options.default_scopes) |s| if (!common.listContains(options.scopes_supported, s)) return error.InvalidScope;
}

/// Return an error unless the URL uses https, or `http` with a loopback host and `allow_http`.
fn checkSecure(allow_http: bool, url: []const u8) InitError!void {
    const parts = common.splitUri(url) orelse return error.InvalidIssuer;
    if (std.ascii.eqlIgnoreCase(parts.scheme, "https")) return;
    if (!std.ascii.eqlIgnoreCase(parts.scheme, "http") or !allow_http) return error.InsecureUrl;
    if (!common.validRedirectUri(url)) return error.InsecureUrl;
}

fn makeUrls(arena: Allocator, issuer: []const u8) Allocator.Error!AuthorizationServer.Urls {
    const parts = common.splitUri(issuer).?;
    const origin = issuer[0 .. issuer.len - parts.rest.len];
    const p = parts.rest;
    return .{
        .issuer = try arena.dupe(u8, issuer),
        .authorization_endpoint = try std.mem.concat(arena, u8, &.{ origin, p, "/authorize" }),
        .token_endpoint = try std.mem.concat(arena, u8, &.{ origin, p, "/token" }),
        .jwks_uri = try std.mem.concat(arena, u8, &.{ origin, p, "/jwks" }),
        .registration_endpoint = try std.mem.concat(arena, u8, &.{ origin, p, "/register" }),
        .authorization_path = try std.mem.concat(arena, u8, &.{ p, "/authorize" }),
        .token_path = try std.mem.concat(arena, u8, &.{ p, "/token" }),
        .jwks_path = try std.mem.concat(arena, u8, &.{ p, "/jwks" }),
        .registration_path = try std.mem.concat(arena, u8, &.{ p, "/register" }),
        .metadata_path = try std.mem.concat(arena, u8, &.{ "/.well-known/oauth-authorization-server", p }),
        .openid_path = try std.mem.concat(arena, u8, &.{ "/.well-known/openid-configuration", p }),
        .openid_path_suffix = try std.mem.concat(arena, u8, &.{ p, "/.well-known/openid-configuration" }),
    };
}

/// The JWK set of the signing keys, with `kid`, `use` and `alg`.
fn jwksDocument(arena: Allocator, keys: []const SigningKey) Allocator.Error![]const u8 {
    var aw: Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    w.writeAll("{\"keys\":[") catch return error.OutOfMemory;
    for (keys, 0..) |k, i| {
        const jwk = jwt.publicJwk(arena, k.key) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.SymmetricKey => unreachable,
        };
        if (i > 0) w.writeByte(',') catch return error.OutOfMemory;
        w.print("{{\"kid\":{f},\"use\":\"sig\",\"alg\":\"{t}\",{s}", .{ std.json.fmt(k.kid, .{}), k.key.algorithm(), jwk[1..] }) catch return error.OutOfMemory;
    }
    w.writeAll("]}") catch return error.OutOfMemory;
    return aw.written();
}

/// The authorization server metadata (RFC 8414 section 2).
fn metadataDocument(arena: Allocator, self: *const AuthorizationServer) Allocator.Error![]const u8 {
    const o = self.options;
    const u = self.urls;
    var aw: Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    const code_flow = o.authorizer != null and o.grants.authorization_code;
    w.print("{{\"issuer\":{f}", .{std.json.fmt(u.issuer, .{})}) catch return error.OutOfMemory;
    if (o.authorizer != null) w.print(",\"authorization_endpoint\":{f}", .{std.json.fmt(u.authorization_endpoint, .{})}) catch return error.OutOfMemory;
    w.print(",\"token_endpoint\":{f},\"jwks_uri\":{f}", .{ std.json.fmt(u.token_endpoint, .{}), std.json.fmt(u.jwks_uri, .{}) }) catch return error.OutOfMemory;
    if (o.dynamic_registration != null) w.print(",\"registration_endpoint\":{f}", .{std.json.fmt(u.registration_endpoint, .{})}) catch return error.OutOfMemory;
    w.writeAll(",\"response_types_supported\":[") catch return error.OutOfMemory;
    if (code_flow) w.writeAll("\"code\"") catch return error.OutOfMemory;
    w.writeAll("],\"response_modes_supported\":[\"query\"],\"grant_types_supported\":[") catch return error.OutOfMemory;
    writeGrantTypes(w, .{
        .authorization_code = code_flow,
        .refresh_token = code_flow and o.grants.refresh_token and o.issue_refresh_tokens,
        .client_credentials = o.grants.client_credentials,
        .jwt_bearer = o.grants.id_jag != null or o.grants.workload != null,
    }) catch return error.OutOfMemory;
    w.writeAll("],\"code_challenge_methods_supported\":[\"S256\"]") catch return error.OutOfMemory;
    w.writeAll(",\"token_endpoint_auth_methods_supported\":[\"none\",\"client_secret_basic\",\"client_secret_post\",\"private_key_jwt\"]") catch return error.OutOfMemory;
    w.writeAll(",\"token_endpoint_auth_signing_alg_values_supported\":[\"ES256\",\"ES384\",\"EdDSA\",\"RS256\",\"PS256\"]") catch return error.OutOfMemory;
    w.writeAll(",\"scopes_supported\":") catch return error.OutOfMemory;
    writeStringArray(w, o.scopes_supported) catch return error.OutOfMemory;
    w.writeAll(",\"authorization_response_iss_parameter_supported\":true") catch return error.OutOfMemory;
    w.print(",\"client_id_metadata_document_supported\":{s}", .{if (o.client_metadata != null) "true" else "false"}) catch return error.OutOfMemory;
    if (o.dpop.enabled) {
        w.writeAll(",\"dpop_signing_alg_values_supported\":[") catch return error.OutOfMemory;
        var first = true;
        for (o.dpop.algorithms) |a| {
            if (!a.isAsymmetric()) continue;
            w.print("{s}\"{t}\"", .{ if (first) "" else ",", a }) catch return error.OutOfMemory;
            first = false;
        }
        w.writeByte(']') catch return error.OutOfMemory;
    }
    if (o.grants.id_jag != null) w.print(",\"authorization_grant_profiles_supported\":[\"{s}\"]", .{enterprise.grant_profile}) catch return error.OutOfMemory;
    w.writeByte('}') catch return error.OutOfMemory;
    return aw.written();
}

fn writeStringArray(w: *Io.Writer, list: []const []const u8) Io.Writer.Error!void {
    try w.writeByte('[');
    for (list, 0..) |s, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{f}", .{std.json.fmt(s, .{})});
    }
    try w.writeByte(']');
}

fn writeGrantTypes(w: *Io.Writer, g: GrantTypes) Io.Writer.Error!void {
    var first = true;
    const names = [_]struct { on: bool, name: []const u8 }{
        .{ .on = g.authorization_code, .name = "authorization_code" },
        .{ .on = g.refresh_token, .name = "refresh_token" },
        .{ .on = g.client_credentials, .name = "client_credentials" },
        .{ .on = g.jwt_bearer, .name = grant_type_jwt_bearer },
    };
    for (names) |n| {
        if (!n.on) continue;
        try w.print("{s}\"{s}\"", .{ if (first) "" else ",", n.name });
        first = false;
    }
}

// -- Responses ---------------------------------------------------------------------------------

/// A GET of a document: the metadata or the JWK set.
fn documentResponse(arena: Allocator, request: *const Request, body: []const u8) Allocator.Error!Response {
    if (request.method != .GET and request.method != .HEAD) return methodNotAllowed(arena, "GET");
    const headers = try arena.alloc(http.Header, 3);
    headers[0] = .{ .name = "content-type", .value = "application/json" };
    headers[1] = .{ .name = "cache-control", .value = "max-age=300" };
    headers[2] = .{ .name = "access-control-allow-origin", .value = "*" };
    return .{ .status = .ok, .headers = headers, .body = body };
}

fn jsonResponse(arena: Allocator, status: http.Status, body: []const u8, extra: []const http.Header) Allocator.Error!Response {
    const headers = try arena.alloc(http.Header, 3 + extra.len);
    headers[0] = .{ .name = "content-type", .value = "application/json" };
    headers[1] = .{ .name = "cache-control", .value = "no-store" };
    headers[2] = .{ .name = "pragma", .value = "no-cache" };
    @memcpy(headers[3..], extra);
    return .{ .status = status, .headers = headers, .body = body };
}

/// A token or registration error (RFC 6749 section 5.2).
fn oauthError(arena: Allocator, status: http.Status, code: Code, description: []const u8, extra: []const http.Header) Allocator.Error!Response {
    const body = try std.fmt.allocPrint(arena, "{{\"error\":\"{t}\",\"error_description\":{f}}}", .{ code, std.json.fmt(description, .{}) });
    return jsonResponse(arena, status, body, extra);
}

fn invalidClient(arena: Allocator, basic: bool, description: []const u8) Allocator.Error!Response {
    const extra: []const http.Header = if (basic) &.{.{ .name = "www-authenticate", .value = "Basic realm=\"token\"" }} else &.{};
    return oauthError(arena, .unauthorized, .invalid_client, description, extra);
}

/// An error page of the authorization endpoint for a request that the server cannot send back
/// to the client. The text has no input of the request.
fn errorPage(arena: Allocator, status: http.Status, code: Code, description: []const u8) Allocator.Error!Response {
    const headers = try arena.alloc(http.Header, 3);
    headers[0] = .{ .name = "content-type", .value = "text/plain; charset=utf-8" };
    headers[1] = .{ .name = "cache-control", .value = "no-store" };
    headers[2] = .{ .name = "x-content-type-options", .value = "nosniff" };
    return .{ .status = status, .headers = headers, .body = try std.fmt.allocPrint(arena, "{t}: {s}\n", .{ code, description }) };
}

fn methodNotAllowed(arena: Allocator, allow: []const u8) Allocator.Error!Response {
    const headers = try arena.alloc(http.Header, 2);
    headers[0] = .{ .name = "allow", .value = allow };
    headers[1] = .{ .name = "cache-control", .value = "no-store" };
    return .{ .status = .method_not_allowed, .headers = headers };
}

// -- Parameters --------------------------------------------------------------------------------

const ParamError = error{ OutOfMemory, Malformed, TooLarge };

const Params = struct {
    items: []const Param,

    fn get(self: Params, name: []const u8) ?[]const u8 {
        for (self.items) |p| if (std.mem.eql(u8, p.name, name)) return p.value;
        return null;
    }

    fn count(self: Params, name: []const u8) usize {
        var n: usize = 0;
        for (self.items) |p| {
            if (std.mem.eql(u8, p.name, name)) n += 1;
        }
        return n;
    }

    /// The name of a parameter that occurs more than once, without the names of `except`.
    fn duplicateName(self: Params, except: []const []const u8) ?[]const u8 {
        for (self.items, 0..) |p, i| {
            if (common.listContains(except, p.name)) continue;
            for (self.items[0..i]) |q| if (std.mem.eql(u8, p.name, q.name)) return p.name;
        }
        return null;
    }
};

/// Parse an `application/x-www-form-urlencoded` text. A malformed percent escape is an error.
fn parseParams(arena: Allocator, text: []const u8, limits: Limits) ParamError!Params {
    var list: std.ArrayList(Param) = .empty;
    var it = std.mem.splitScalar(u8, text, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        if (list.items.len >= limits.max_parameters) return error.TooLarge;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const name = try formDecode(arena, pair[0..eq]);
        const value = try formDecode(arena, if (eq < pair.len) pair[eq + 1 ..] else "");
        if (name.len == 0) continue;
        if (value.len > limits.max_parameter_bytes) return error.TooLarge;
        try list.append(arena, .{ .name = name, .value = value });
    }
    return .{ .items = list.items };
}

fn formDecode(arena: Allocator, text: []const u8) ParamError![]const u8 {
    const out = try arena.alloc(u8, text.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '+') {
            out[n] = ' ';
        } else if (c == '%') {
            if (i + 2 >= text.len) return error.Malformed;
            const hi = std.fmt.charToDigit(text[i + 1], 16) catch return error.Malformed;
            const lo = std.fmt.charToDigit(text[i + 2], 16) catch return error.Malformed;
            out[n] = hi * 16 + lo;
            i += 2;
        } else {
            out[n] = c;
        }
        n += 1;
    }
    return out[0..n];
}

/// Parse a scope text. Each scope must have the characters of RFC 6749 section 3.3.
fn parseScope(arena: Allocator, text: []const u8, max: usize) (Allocator.Error || error{InvalidScope})![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, ' ');
    while (it.next()) |s| {
        if (!validScopeToken(s)) return error.InvalidScope;
        try common.appendUnique(arena, &out, s);
        if (out.items.len > max) return error.InvalidScope;
    }
    return out.items;
}

/// A scope token: `%x21 / %x23-5B / %x5D-7E`, 128 bytes or less.
fn validScopeToken(s: []const u8) bool {
    if (s.len == 0 or s.len > 128) return false;
    for (s) |c| if (c < 0x21 or c > 0x7e or c == '"' or c == '\\') return false;
    return true;
}

/// A PKCE code verifier: 43 to 128 unreserved characters (RFC 7636 section 4.1).
fn validVerifier(v: []const u8) bool {
    if (v.len < 43 or v.len > 128) return false;
    for (v) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~')) return false;
    return true;
}

/// True for a base64url text without padding of the length `len`.
fn isBase64Url(text: []const u8, len: usize) bool {
    if (text.len != len) return false;
    for (text) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_')) return false;
    return true;
}

/// True when `given` is the registered redirect URI. A loopback URI with `http` can have
/// another port (RFC 8252 section 7.3). All other parts must be equal.
pub fn redirectMatches(registered: []const u8, given: []const u8) bool {
    if (std.mem.eql(u8, registered, given)) return true;
    const r = common.splitUri(registered) orelse return false;
    const g = common.splitUri(given) orelse return false;
    if (!std.mem.eql(u8, r.scheme, "http") or !std.mem.eql(u8, g.scheme, "http")) return false;
    if (!isLoopbackHost(r.host()) or !std.mem.eql(u8, r.host(), g.host())) return false;
    if (r.userinfo.len > 0 or g.userinfo.len > 0) return false;
    if (!validPort(r.host_port) or !validPort(g.host_port)) return false;
    return std.mem.eql(u8, r.rest, g.rest);
}

fn isLoopbackHost(host: []const u8) bool {
    if (std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1")) return true;
    const ip = Io.net.Ip4Address.parse(host, 0) catch return false;
    return ip.bytes[0] == 127;
}

/// True when the port of `host_port` is empty or a number.
fn validPort(host_port: []const u8) bool {
    const colon = std.mem.lastIndexOfScalar(u8, host_port, ':') orelse return true;
    if (std.mem.indexOfScalar(u8, host_port[colon..], ']') != null) return true;
    const port = host_port[colon + 1 ..];
    _ = std.fmt.parseInt(u16, port, 10) catch return port.len == 0;
    return true;
}

fn isFormContent(request: *const Request) bool {
    const ct = request.header("content-type") orelse return false;
    return std.ascii.startsWithIgnoreCase(ct, "application/x-www-form-urlencoded");
}

fn startsWithScheme(header: []const u8, scheme: []const u8) bool {
    return header.len > scheme.len and std.ascii.eqlIgnoreCase(header[0..scheme.len], scheme) and header[scheme.len] == ' ';
}

const BasicPair = struct { id: []const u8, secret: []const u8, raw_id: []const u8, raw_secret: []const u8 };

/// Decode `client_secret_basic` credentials: base64, then the form encoding of each part
/// (RFC 6749 section 2.3.1).
fn decodeBasic(arena: Allocator, encoded: []const u8) !BasicPair {
    const dec = std.base64.standard.Decoder;
    const len = try dec.calcSizeForSlice(encoded);
    if (len > 4096) return error.TooLarge;
    const raw = try arena.alloc(u8, len);
    try dec.decode(raw, encoded);
    const colon = std.mem.indexOfScalar(u8, raw, ':') orelse return error.Malformed;
    return .{
        .id = try formDecode(arena, raw[0..colon]),
        .secret = try formDecode(arena, raw[colon + 1 ..]),
        .raw_id = raw[0..colon],
        .raw_secret = raw[colon + 1 ..],
    };
}

/// True when the secret matches the hash of the client. Some clients send the secret without
/// the form encoding, so the raw text counts too.
fn secretOk(client: Client, secret: []const u8, raw: []const u8) bool {
    const hash = client.secret_hash orelse return false;
    const decoded_ok = store_mod.secretMatches(hash, secret);
    const raw_ok = store_mod.secretMatches(hash, raw);
    return decoded_ok or raw_ok;
}

fn constantTimeEql(a: []const u8, b: []const u8) bool {
    const ha = store_mod.hashSecret(a);
    return store_mod.secretMatches(ha, b);
}

fn containsUri(list: []const []const u8, uri: []const u8) bool {
    for (list) |u| if (common.uriEql(u, uri)) return true;
    return false;
}

/// True when the JOSE `typ` header of `token` is `want`. The comparison ignores case and an
/// `application/` prefix.
fn hasType(arena: Allocator, token: []const u8, want: []const u8) bool {
    const end = std.mem.indexOfScalar(u8, token, '.') orelse return false;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const len = dec.calcSizeForSlice(token[0..end]) catch return false;
    if (len > 4096) return false;
    const buf = arena.alloc(u8, len) catch return false;
    dec.decode(buf, token[0..end]) catch return false;
    const header = json.parseTree(arena, buf) catch return false;
    var typ = json.getString(header, "typ") orelse return false;
    if (std.ascii.startsWithIgnoreCase(typ, "application/")) typ = typ["application/".len..];
    return std.ascii.eqlIgnoreCase(typ, want);
}

test {
    _ = store_mod;
    _ = client_metadata;
}

test "parameters, scopes, verifiers and redirect URIs" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const p = try parseParams(arena, "a=1&b=x+y%20z&&c=&a=2", .{});
    try std.testing.expectEqualStrings("1", p.get("a").?);
    try std.testing.expectEqualStrings("x y z", p.get("b").?);
    try std.testing.expectEqualStrings("", p.get("c").?);
    try std.testing.expectEqualStrings("a", p.duplicateName(&.{}).?);
    try std.testing.expect(p.duplicateName(&.{"a"}) == null);
    try std.testing.expectError(error.Malformed, parseParams(arena, "a=%zz", .{}));
    try std.testing.expectError(error.Malformed, parseParams(arena, "a=%4", .{}));
    try std.testing.expectError(error.TooLarge, parseParams(arena, "a=1&b=2&c=3", .{ .max_parameters = 2 }));

    try std.testing.expectEqual(2, (try parseScope(arena, "mcp:read  mcp:write mcp:read", 8)).len);
    try std.testing.expectError(error.InvalidScope, parseScope(arena, "bad\"scope", 8));
    try std.testing.expect(validVerifier("a" ** 43));
    try std.testing.expect(!validVerifier("a" ** 42));
    try std.testing.expect(!validVerifier(("a" ** 42) ++ "+"));

    try std.testing.expect(redirectMatches("http://127.0.0.1/callback", "http://127.0.0.1:53111/callback"));
    try std.testing.expect(redirectMatches("http://[::1]:80/cb", "http://[::1]:9/cb"));
    try std.testing.expect(redirectMatches("http://localhost:3000/cb", "http://localhost:4000/cb"));
    try std.testing.expect(!redirectMatches("http://127.0.0.1/callback", "http://127.0.0.1:1/callback/x"));
    try std.testing.expect(!redirectMatches("http://127.0.0.1/callback", "http://127.0.0.2/callback"));
    try std.testing.expect(!redirectMatches("https://app.example.com/cb", "https://app.example.com:444/cb"));
    try std.testing.expect(!redirectMatches("https://app.example.com/cb", "https://app.example.com/cb?x=1"));
    try std.testing.expect(!redirectMatches("http://127.0.0.1/cb", "http://127.0.0.1@evil.example/cb"));
    try std.testing.expect(redirectMatches("https://app.example.com/cb", "https://app.example.com/cb"));

    const basic = try decodeBasic(arena, "YSUzQWI6cyUyMDE=");
    try std.testing.expectEqualStrings("a:b", basic.id);
    try std.testing.expectEqualStrings("s 1", basic.secret);
    try std.testing.expect(isBase64Url("abc-_", 5));
    try std.testing.expect(!isBase64Url("abc+_", 5));

    var aw: Io.Writer.Allocating = .init(arena);
    try htmlEscape(&aw.writer, "<a href=\"x\">'&'</a>");
    try std.testing.expectEqualStrings("&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;", aw.written());
}
