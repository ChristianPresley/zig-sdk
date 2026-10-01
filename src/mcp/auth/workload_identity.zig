//! Workload identity federation for MCP (SEP-1933). A client that runs as a workload, for
//! example in Kubernetes or on a cloud platform, uses the JWT that its platform issued to it.
//! The client gives the JWT to the authorization server of the MCP server as a JWT
//! authorization grant (RFC 7523 section 2.1). The client has no client ID, no secret and no
//! registration.
//!
//! The client side: `WorkloadIdentity` is a provider of the HTTP client transport. It finds the
//! authorization server, sends the workload JWT, and keeps the access token.
//!
//! The authorization server side: `WorkloadJwtValidator` checks a workload JWT at the token
//! endpoint, for an application that runs its own authorization server. `KeyDiscovery` gets the
//! keys of a trusted issuer with OpenID Connect Discovery.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const json = @import("../json.zig");
const common = @import("common.zig");
const jwt = @import("jwt.zig");
const dpop = @import("dpop.zig");

/// The identifier of the extension in the `extensions` capability. The draft of the extension
/// names no identifier. This value is the one that the MCP conformance suite uses.
pub const extension_id = "io.modelcontextprotocol/auth/wif";
/// The grant type of a JWT authorization grant (RFC 7523 section 2.1).
pub const grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The audiences that a workload JWT can name: the issuer identifier and the token endpoint of
/// the authorization server. The extension requires the token endpoint.
pub const Audience = struct {
    issuer: []const u8,
    token_endpoint: []const u8,
};

pub const WorkloadIdentity = struct {
    io: Io,
    gpa: Allocator,
    fetcher: common.Fetcher,
    options: Options,
    lock: Io.Mutex = .init,
    /// What the last flow found. A renewal uses it without discovery.
    issuer: ?[]u8 = null,
    token_endpoint: ?[]u8 = null,
    auth_methods: std.ArrayList([]u8) = .empty,
    signing_algs: std.ArrayList([]u8) = .empty,
    resource: ?[]u8 = null,
    scope: ?[]u8 = null,
    token: ?[]u8 = null,
    /// The token is DPoP-bound: requests carry it with the DPoP scheme and a proof.
    token_dpop: bool = false,
    /// Unix seconds. Null when the server gave no `expires_in`.
    expires_at: ?i64 = null,
    /// The `error` code of the last failed token request, if the server sent one.
    last_error: ?[]u8 = null,
    /// The SHA-256 hash of the last workload JWT that the server refused. The client does not
    /// send the same JWT again.
    refused: ?[32]u8 = null,

    /// Where the workload JWT comes from.
    pub const Source = union(enum) {
        /// A JWT that the application got. The client does not own it.
        static: []const u8,
        /// A file that the platform writes and rotates, for example a projected service account
        /// token of Kubernetes. The client reads the file for each token request.
        file: []const u8,
        /// A function that returns a JWT for the audience in `arena`. The application can ask
        /// its platform for a JWT with this audience here.
        callback: struct {
            userdata: ?*anyopaque = null,
            obtain: *const fn (userdata: ?*anyopaque, arena: Allocator, audience: Audience) anyerror![]const u8,
        },
    };

    pub const Options = struct {
        assertion: Source,
        /// The client authentication at the token endpoint. The extension needs none. Null
        /// sends no client authentication and no client ID.
        client: ?common.ClientAuth = null,
        /// The scopes to request. Null takes the challenge scope, else the `scopes_supported`
        /// of the protected resource metadata, else no scope.
        scope: ?[]const u8 = null,
        /// Get a new token when the current one expires within this number of seconds.
        refresh_margin_seconds: i64 = 60,
        max_step_up_attempts: u8 = 3,
        /// Accept `http` metadata and token endpoints. Tests only, production needs https.
        allow_http: bool = false,
        max_document_bytes: usize = 1 << 20,
        /// The largest workload JWT that the client reads from a file.
        max_assertion_bytes: usize = 64 << 10,
        /// The clock for token lifetimes. Null uses the real clock.
        clock: common.Clock = null,
        /// Request DPoP-bound tokens with this key (RFC 9449). Null requests bearer tokens.
        dpop: ?*dpop.Prover = null,
    };

    pub const Error = error{
        OutOfMemory,
        /// More challenges than `max_step_up_attempts` for one request.
        TooManyAttempts,
        NoResourceMetadata,
        /// The metadata `resource` is not the server URL.
        ResourceMismatch,
        NoAuthorizationServer,
        NoAuthorizationServerMetadata,
        /// The metadata `issuer` is not the issuer that the resource metadata names.
        IssuerMismatch,
        InsecureEndpoint,
        /// The server lists grant types without the JWT bearer grant.
        GrantTypeUnsupported,
        /// The source gave no workload JWT.
        AssertionUnavailable,
        /// The server refused this workload JWT before. The client waits for a new one.
        AssertionRefused,
        AuthMethodUnsupported,
        SigningAlgorithmUnsupported,
        SigningFailed,
        EntropyUnavailable,
        /// The token endpoint refused the request. `last_error` has the error code.
        TokenRequestFailed,
        /// The authorization server lists DPoP algorithms without the algorithm of the key.
        DpopAlgorithmUnsupported,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) WorkloadIdentity {
        return .{ .io = io, .gpa = gpa, .fetcher = .init(io, gpa, options.max_document_bytes, options.allow_http), .options = options };
    }

    pub fn deinit(self: *WorkloadIdentity) void {
        self.fetcher.deinit();
        self.forget();
        common.replaceOwned(self.gpa, &self.last_error, null) catch unreachable;
        self.auth_methods.deinit(self.gpa);
        self.signing_algs.deinit(self.gpa);
    }

    /// Discard the token and everything that discovery found.
    fn forget(self: *WorkloadIdentity) void {
        inline for (.{ "issuer", "token_endpoint", "resource", "scope", "token" }) |name| {
            common.replaceOwned(self.gpa, &@field(self, name), null) catch unreachable;
        }
        for (self.auth_methods.items) |s| self.gpa.free(s);
        self.auth_methods.clearRetainingCapacity();
        for (self.signing_algs.items) |s| self.gpa.free(s);
        self.signing_algs.clearRetainingCapacity();
        self.expires_at = null;
        self.token_dpop = false;
    }

    /// The interface for the `auth_provider` option of the HTTP client transport.
    pub fn provider(self: *WorkloadIdentity) common.Provider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: common.Provider.VTable = .{
        .token = providerToken,
        .handle_challenge = providerChallenge,
        .credentials = providerCredentials,
        .dpop_nonce = providerNonce,
    };

    fn providerToken(ptr: *anyopaque, arena: Allocator) ?[]const u8 {
        const self: *WorkloadIdentity = @ptrCast(@alignCast(ptr));
        return self.currentToken(arena);
    }

    fn providerChallenge(ptr: *anyopaque, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void {
        const self: *WorkloadIdentity = @ptrCast(@alignCast(ptr));
        return self.handleChallenge(arena, server_url, status, www_authenticate, attempt);
    }

    fn providerCredentials(ptr: *anyopaque, arena: Allocator, method: []const u8, url: []const u8) ?common.Credentials {
        const self: *WorkloadIdentity = @ptrCast(@alignCast(ptr));
        const t = self.currentToken(arena) orelse return null;
        self.lock.lockUncancelable(self.io);
        const bound = self.token_dpop;
        self.lock.unlock(self.io);
        return common.credentialsFor(arena, self.options.dpop, bound, t, method, url);
    }

    fn providerNonce(ptr: *anyopaque, url: []const u8, nonce: []const u8) void {
        const self: *WorkloadIdentity = @ptrCast(@alignCast(ptr));
        const p = self.options.dpop orelse return;
        p.rememberNonce(url, nonce) catch {};
    }

    /// The token for the next request, copied into `arena`. When the token expires within the
    /// refresh margin, the client requests a new one first with the current workload JWT. When
    /// that fails, the client keeps the old token until it expires.
    pub fn currentToken(self: *WorkloadIdentity, arena: Allocator) ?[]const u8 {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const time = common.now(self.io, self.options.clock);
        if (self.token != null and self.token_endpoint != null) if (self.expires_at) |exp| {
            if (time + self.options.refresh_margin_seconds >= exp) {
                self.requestToken(arena) catch {
                    if (time >= exp) common.replaceOwned(self.gpa, &self.token, null) catch {};
                };
            }
        };
        const t = self.token orelse return null;
        return arena.dupe(u8, t) catch null;
    }

    /// Get a token for `server_url` after a `401` or `403` challenge. A refused workload JWT
    /// stops the flow: the client does not send it again and does not change the grant type.
    pub fn handleChallenge(self: *WorkloadIdentity, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) Error!void {
        if (attempt > self.options.max_step_up_attempts) return error.TooManyAttempts;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const challenge: common.Challenge = if (www_authenticate) |h| try common.parseChallenge(arena, h) else .{};
        const step_up = challenge.isStepUp(status);

        const prm = try self.fetcher.resourceMetadata(arena, server_url, challenge.resource_metadata);
        if (!common.resourceCoversServer(prm.resource, server_url)) return error.ResourceMismatch;
        if (prm.authorization_servers.len == 0) return error.NoAuthorizationServer;
        const issuer = prm.authorization_servers[0];
        const meta = try self.fetcher.authorizationServer(arena, issuer);
        if (!std.mem.eql(u8, meta.issuer, issuer)) return error.IssuerMismatch;
        try common.requireHttps(self.options.allow_http, meta.token_endpoint);
        if (meta.grant_types_supported.len > 0 and !common.listContains(meta.grant_types_supported, grant_type)) return error.GrantTypeUnsupported;
        try meta.checkDpop(self.options.dpop);

        var held: std.ArrayList([]const u8) = .empty;
        if (self.scope) |s| {
            var it = std.mem.tokenizeScalar(u8, s, ' ');
            while (it.next()) |one| try held.append(arena, one);
        }
        const scope = try common.selectScope(arena, self.options.scope, challenge, prm.scopes_supported, held.items, step_up);

        // A new authorization server discards everything of the old one.
        const same_issuer = self.issuer != null and std.mem.eql(u8, self.issuer.?, issuer);
        if (!same_issuer) self.forget();
        try common.replaceOwned(self.gpa, &self.issuer, issuer);
        try common.replaceOwned(self.gpa, &self.token_endpoint, meta.token_endpoint);
        try common.replaceOwned(self.gpa, &self.resource, prm.resource);
        try common.replaceOwned(self.gpa, &self.scope, scope);
        try replaceList(self.gpa, &self.auth_methods, meta.token_endpoint_auth_methods_supported);
        try replaceList(self.gpa, &self.signing_algs, meta.token_endpoint_auth_signing_alg_values_supported);
        try self.requestToken(arena);
    }

    /// Get the workload JWT from the source, in `arena`.
    fn obtainAssertion(self: *WorkloadIdentity, arena: Allocator) Error![]const u8 {
        const text: []const u8 = switch (self.options.assertion) {
            .static => |t| t,
            .file => |path| Io.Dir.cwd().readFileAlloc(self.io, path, arena, .limited(self.options.max_assertion_bytes)) catch return error.AssertionUnavailable,
            .callback => |cb| cb.obtain(cb.userdata, arena, .{ .issuer = self.issuer.?, .token_endpoint = self.token_endpoint.? }) catch return error.AssertionUnavailable,
        };
        // A file often ends with a line break.
        const jwt_text = std.mem.trim(u8, text, " \t\r\n");
        if (jwt_text.len == 0) return error.AssertionUnavailable;
        return jwt_text;
    }

    /// The JWT bearer grant of RFC 7523 section 2.1 with the stored endpoint, resource and scope.
    fn requestToken(self: *WorkloadIdentity, arena: Allocator) Error!void {
        const time = common.now(self.io, self.options.clock);
        const assertion = try self.obtainAssertion(arena);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(assertion, &hash, .{});
        if (self.refused) |r| if (std.crypto.timing_safe.eql([32]u8, r, hash)) return error.AssertionRefused;

        var form: Io.Writer.Allocating = .init(arena);
        const w = &form.writer;
        var headers: std.ArrayList(http.Header) = .empty;
        try common.formField(w, "grant_type", grant_type, true);
        try common.formField(w, "assertion", assertion, false);
        try common.formField(w, "resource", self.resource.?, false);
        if (self.scope) |s| try common.formField(w, "scope", s, false);
        if (self.options.client) |client| try client.apply(self.io, arena, time, .{
            .issuer = self.issuer.?,
            .auth_methods_supported = self.auth_methods.items,
            .signing_algs_supported = self.signing_algs.items,
        }, w, &headers);
        switch (try self.fetcher.tokenRequest(arena, self.token_endpoint.?, form.written(), headers.items, self.options.dpop)) {
            .failed => |f| {
                try common.replaceOwned(self.gpa, &self.last_error, f.code);
                // An answer of the server about the grant: do not send this JWT again.
                if (f.status >= 400 and f.status < 500) self.refused = hash;
                return error.TokenRequestFailed;
            },
            .ok => |reply| {
                self.refused = null;
                try common.replaceOwned(self.gpa, &self.last_error, null);
                try common.replaceOwned(self.gpa, &self.token, reply.access_token);
                self.token_dpop = self.options.dpop != null and common.isDpopTokenType(reply.token_type);
                self.expires_at = if (reply.expires_in) |s| time +| s else null;
                if (reply.scope) |granted| try common.replaceOwned(self.gpa, &self.scope, granted);
            },
        }
    }
};

fn replaceList(gpa: Allocator, list: *std.ArrayList([]u8), items: []const []const u8) Allocator.Error!void {
    for (list.items) |s| gpa.free(s);
    list.clearRetainingCapacity();
    for (items) |s| {
        const copy = try gpa.dupe(u8, s);
        errdefer gpa.free(copy);
        try list.append(gpa, copy);
    }
}

// -- Authorization server side --------------------------------------------------------------------

/// An issuer of workload JWTs that the authorization server trusts.
pub const TrustedIssuer = struct {
    /// The `iss` of the JWTs, a URL.
    issuer: []const u8,
    /// The signature keys of the issuer. Empty gets the keys from `KeyDiscovery`.
    keys: []const jwt.Key = &.{},
};

/// What a valid workload JWT tells. The slices point into the arena of `validate`.
pub const Grant = struct {
    issuer: []const u8,
    /// The workload, for example a SPIFFE ID or a service account name. It is not a client ID
    /// and not a resource owner.
    subject: []const u8,
    jwt_id: []const u8,
    expires_at: i64,
    issued_at: i64,
    /// All claims, for the policy of the application.
    claims: Value,
};

pub const ValidateError = error{
    OutOfMemory,
    /// The JWT is not a compact JWS, or a required claim is missing or has the wrong type.
    Malformed,
    /// The `iss` is not a trusted issuer.
    UntrustedIssuer,
    /// The discovery of the keys of the issuer failed.
    KeysUnavailable,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
    Expired,
    NotYetValid,
    /// The lifetime is longer than `max_lifetime_seconds`.
    LifetimeTooLong,
    /// The `aud` names no accepted audience.
    AudienceMismatch,
    /// The replay check saw the `jti` before.
    Replayed,
    /// The policy of the application refused the workload.
    WorkloadNotAuthorized,
};

/// Checks a workload JWT at the token endpoint of an authorization server (RFC 7523 section 3
/// and the extension). Each rejection maps to the OAuth error `invalid_grant`.
pub const WorkloadJwtValidator = struct {
    /// The values that `aud` must name one of. The extension requires the URL of the token
    /// endpoint. Add the issuer identifier to accept that value too.
    audiences: []const []const u8,
    trusted_issuers: []const TrustedIssuer,
    /// Gets the keys of a trusted issuer without static keys. Null refuses such an issuer.
    discovery: ?*KeyDiscovery = null,
    /// The algorithms that the validator accepts. Only asymmetric algorithms have an effect.
    algorithms: []const jwt.Algorithm = &dpop.default_algorithms,
    clock_skew_seconds: i64 = 60,
    /// The longest accepted `exp` minus `iat`. Null skips the check. The extension recommends
    /// short lifetimes.
    max_lifetime_seconds: ?i64 = 3600,
    /// Records `jti` values to refuse a replay. Null skips the check.
    replay: ?ReplayCheck = null,
    /// The workload trust: decides if the workload gets a token. Null accepts every workload of
    /// a trusted issuer. We recommend a policy with an allow list of subjects.
    policy: ?Policy = null,

    pub const ReplayCheck = struct {
        userdata: ?*anyopaque = null,
        /// Return true when the store already has the pair of `issuer` and `jti`. Otherwise
        /// record the pair until `expires_at`.
        seen: *const fn (userdata: ?*anyopaque, issuer: []const u8, jti: []const u8, expires_at: i64) bool,
    };

    pub const Policy = struct {
        userdata: ?*anyopaque = null,
        /// Return true when the workload of `grant` can get a token.
        allow: *const fn (userdata: ?*anyopaque, grant: *const Grant) bool,
    };

    /// Validate `assertion` at `now` in Unix seconds.
    pub fn validate(self: *const WorkloadJwtValidator, arena: Allocator, assertion: []const u8, now: i64) ValidateError!Grant {
        // Find the issuer from the unverified `iss`, then verify with its keys only.
        const unverified = jwt.decodePayloadUnverified(arena, assertion) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed => error.Malformed,
        };
        const iss = json.getString(unverified, "iss") orelse return error.Malformed;
        const trusted = for (self.trusted_issuers) |t| {
            if (std.mem.eql(u8, t.issuer, iss)) break t;
        } else return error.UntrustedIssuer;
        const all_keys: []const jwt.Key = if (trusted.keys.len > 0) trusted.keys else blk: {
            const d = self.discovery orelse return error.KeysUnavailable;
            break :blk d.keys(arena, trusted.issuer, assertion) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.KeysUnavailable,
            };
        };
        var keys: std.ArrayList(jwt.Key) = .empty;
        for (all_keys) |k| {
            if (!k.alg.isAsymmetric()) continue;
            for (self.algorithms) |a| if (a == k.alg) {
                try keys.append(arena, k);
                break;
            };
        }
        const claims = jwt.verify(arena, assertion, .{
            .keys = keys.items,
            .issuer = trusted.issuer,
            .clock_skew_seconds = self.clock_skew_seconds,
        }, now) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed, error.TypeMismatch => error.Malformed,
            error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
            error.UnknownKey => error.UnknownKey,
            error.BadSignature => error.BadSignature,
            error.Expired => error.Expired,
            error.NotYetValid => error.NotYetValid,
            error.IssuerMismatch => error.UntrustedIssuer,
            error.AudienceMismatch => error.AudienceMismatch,
        };

        // The claims that the extension requires.
        const subject = claims.subject orelse return error.Malformed;
        const jti = claims.jwt_id orelse return error.Malformed;
        const exp = claims.expires_at orelse return error.Malformed;
        const iat = claims.issued_at orelse return error.Malformed;
        if (self.max_lifetime_seconds) |max| if (exp -| iat > max) return error.LifetimeTooLong;
        var audience_ok = false;
        for (claims.audience) |a| {
            for (self.audiences) |want| if (common.uriEql(a, want)) {
                audience_ok = true;
            };
        }
        if (!audience_ok) return error.AudienceMismatch;

        const grant: Grant = .{
            .issuer = trusted.issuer,
            .subject = subject,
            .jwt_id = jti,
            .expires_at = exp,
            .issued_at = iat,
            .claims = claims.payload,
        };
        if (self.policy) |p| if (!p.allow(p.userdata, &grant)) return error.WorkloadNotAuthorized;
        if (self.replay) |r| if (r.seen(r.userdata, trusted.issuer, jti, exp)) return error.Replayed;
        return grant;
    }
};

/// The body of the token error response for a rejected workload JWT (RFC 6749 section 5.2).
/// The error code is always `invalid_grant`. Answer it with status 400.
pub fn errorResponse(arena: Allocator, err: ValidateError) Allocator.Error![]u8 {
    const description: []const u8 = switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => "The workload JWT is malformed or lacks a required claim",
        error.UntrustedIssuer => "The workload JWT issuer is not trusted",
        error.KeysUnavailable => "The keys of the workload JWT issuer are not available",
        error.UnsupportedAlgorithm, error.UnknownKey, error.BadSignature => "The workload JWT signature is not valid",
        error.Expired => "The workload JWT expired",
        error.NotYetValid => "The workload JWT is not valid yet",
        error.LifetimeTooLong => "The workload JWT lifetime is too long",
        error.AudienceMismatch => "The workload JWT audience is not this authorization server",
        error.Replayed => "The workload JWT was used before",
        error.WorkloadNotAuthorized => "The workload is not authorized to get an access token",
    };
    return std.fmt.allocPrint(arena, "{{\"error\":\"invalid_grant\",\"error_description\":{f}}}", .{std.json.fmt(description, .{})});
}

/// Gets the keys of a trusted issuer with OpenID Connect Discovery 1.0: the configuration at
/// `{issuer}/.well-known/openid-configuration`, then the JWK set at its `jwks_uri`. Both URLs
/// must use https. The keys of each issuer stay in a cache for `cache_seconds`. A JWT with a
/// `kid` that the cache does not have starts a new fetch, at most once in `min_refresh_seconds`.
pub const KeyDiscovery = struct {
    io: Io,
    gpa: Allocator,
    fetcher: common.Fetcher,
    lock: Io.Mutex = .init,
    entries: std.ArrayList(Entry) = .empty,
    cache_seconds: i64 = 3600,
    min_refresh_seconds: i64 = 60,
    clock: common.Clock = null,

    const Entry = struct {
        issuer: []u8,
        /// The JWK set document. The keys come from it on each use.
        jwks: []u8,
        fetched_at: i64,
    };

    pub const Options = struct {
        /// Accept `http` URLs. Tests only.
        allow_http: bool = false,
        max_document_bytes: usize = 1 << 20,
        cache_seconds: i64 = 3600,
        min_refresh_seconds: i64 = 60,
        clock: common.Clock = null,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) KeyDiscovery {
        return .{
            .io = io,
            .gpa = gpa,
            .fetcher = .init(io, gpa, options.max_document_bytes, options.allow_http),
            .cache_seconds = options.cache_seconds,
            .min_refresh_seconds = options.min_refresh_seconds,
            .clock = options.clock,
        };
    }

    pub fn deinit(self: *KeyDiscovery) void {
        for (self.entries.items) |e| {
            self.gpa.free(e.issuer);
            self.gpa.free(e.jwks);
        }
        self.entries.deinit(self.gpa);
        self.fetcher.deinit();
    }

    pub const KeysError = error{ OutOfMemory, DiscoveryFailed, InsecureEndpoint };

    /// The keys of `issuer` in `arena`. `token` is the JWT that needs them: its `kid` decides
    /// if the cache is enough.
    pub fn keys(self: *KeyDiscovery, arena: Allocator, issuer: []const u8, token: []const u8) KeysError![]const jwt.Key {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const time = common.now(self.io, self.clock);
        const kid = tokenKid(arena, token);
        if (self.find(issuer)) |entry| {
            const cached = jwt.parseJwks(arena, entry.jwks) catch return error.DiscoveryFailed;
            const fresh = time - entry.fetched_at < self.cache_seconds;
            const has_kid = kid == null or for (cached) |k| {
                if (k.kid != null and std.mem.eql(u8, k.kid.?, kid.?)) break true;
            } else false;
            if (fresh and (has_kid or time - entry.fetched_at < self.min_refresh_seconds)) return cached;
        }
        const document = try self.fetchJwks(arena, issuer);
        const parsed = jwt.parseJwks(arena, document) catch return error.DiscoveryFailed;
        const copy = try self.gpa.dupe(u8, document);
        errdefer self.gpa.free(copy);
        if (self.find(issuer)) |entry| {
            self.gpa.free(entry.jwks);
            entry.jwks = copy;
            entry.fetched_at = time;
        } else {
            const issuer_copy = try self.gpa.dupe(u8, issuer);
            errdefer self.gpa.free(issuer_copy);
            try self.entries.append(self.gpa, .{ .issuer = issuer_copy, .jwks = copy, .fetched_at = time });
        }
        return parsed;
    }

    fn find(self: *KeyDiscovery, issuer: []const u8) ?*Entry {
        for (self.entries.items) |*e| if (std.mem.eql(u8, e.issuer, issuer)) return e;
        return null;
    }

    fn fetchJwks(self: *KeyDiscovery, arena: Allocator, issuer: []const u8) KeysError![]u8 {
        try common.requireHttps(self.fetcher.allow_http, issuer);
        // OpenID Connect Discovery 1.0 section 4: append the well-known path to the issuer.
        const config_url = try std.mem.concat(arena, u8, &.{ std.mem.trimEnd(u8, issuer, "/"), "/.well-known/openid-configuration" });
        const config = self.fetcher.fetch(arena, .GET, config_url, null, null, &.{}) catch |e| return mapFetch(e);
        if (config.status != 200) return error.DiscoveryFailed;
        const tree = json.parseTree(arena, config.body) catch return error.DiscoveryFailed;
        // Section 4.3: the `issuer` of the document must be the issuer of the query.
        const doc_issuer = json.getString(tree, "issuer") orelse return error.DiscoveryFailed;
        if (!std.mem.eql(u8, doc_issuer, issuer)) return error.DiscoveryFailed;
        const jwks_uri = json.getString(tree, "jwks_uri") orelse return error.DiscoveryFailed;
        try common.requireHttps(self.fetcher.allow_http, jwks_uri);
        const reply = self.fetcher.fetch(arena, .GET, jwks_uri, null, null, &.{}) catch |e| return mapFetch(e);
        if (reply.status != 200) return error.DiscoveryFailed;
        return reply.body;
    }

    fn mapFetch(err: anyerror) KeysError {
        return if (err == error.OutOfMemory) error.OutOfMemory else error.DiscoveryFailed;
    }
};

/// The `kid` of the JOSE header of `token`, or null.
fn tokenKid(arena: Allocator, token: []const u8) ?[]const u8 {
    const end = std.mem.indexOfScalar(u8, token, '.') orelse return null;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const len = dec.calcSizeForSlice(token[0..end]) catch return null;
    const buf = arena.alloc(u8, len) catch return null;
    dec.decode(buf, token[0..end]) catch return null;
    const header = json.parseTree(arena, buf) catch return null;
    return json.getString(header, "kid");
}

test "workload JWT validation rules" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const key: jwt.SigningKey = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{21} ** 32) };
    var buf: [97]u8 = undefined;
    const trusted = [_]TrustedIssuer{.{ .issuer = "https://issuer.example.org", .keys = &.{key.verificationKey(&buf, "k1")} }};
    const Allow = struct {
        fn allow(userdata: ?*anyopaque, grant: *const Grant) bool {
            _ = userdata;
            return std.mem.startsWith(u8, grant.subject, "spiffe://example.org/");
        }
    };
    const Replay = struct {
        last: ?[]const u8 = null,
        fn seen(userdata: ?*anyopaque, issuer: []const u8, jti: []const u8, expires_at: i64) bool {
            _ = issuer;
            _ = expires_at;
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.last) |l| if (std.mem.eql(u8, l, jti)) return true;
            self.last = jti;
            return false;
        }
    };
    var replay: Replay = .{};
    const v: WorkloadJwtValidator = .{
        .audiences = &.{"https://auth.example.com/token"},
        .trusted_issuers = &trusted,
        .policy = .{ .allow = Allow.allow },
        .replay = .{ .userdata = &replay, .seen = Replay.seen },
    };
    const good = "{\"iss\":\"https://issuer.example.org\",\"sub\":\"spiffe://example.org/ns/default/sa/router\",\"aud\":\"https://auth.example.com/token\",\"jti\":\"g1\",\"exp\":1300,\"iat\":1000}";
    const token = try jwt.sign(arena, &key, good, .{ .kid = "k1" });
    const grant = try v.validate(arena, token, 1100);
    try std.testing.expectEqualStrings("spiffe://example.org/ns/default/sa/router", grant.subject);
    try std.testing.expectEqualStrings("g1", grant.jwt_id);
    try std.testing.expectError(error.Replayed, v.validate(arena, token, 1100));

    const Case = struct { payload: []const u8, now: i64 = 1100, err: ValidateError };
    const cases = [_]Case{
        .{ .payload = good, .now = 1400, .err = error.Expired },
        .{ .payload = "{\"iss\":\"https://evil.example\",\"sub\":\"spiffe://example.org/a\",\"aud\":\"https://auth.example.com/token\",\"jti\":\"2\",\"exp\":1300,\"iat\":1000}", .err = error.UntrustedIssuer },
        .{ .payload = "{\"iss\":\"https://issuer.example.org\",\"sub\":\"spiffe://example.org/a\",\"aud\":\"https://auth.example.com\",\"jti\":\"3\",\"exp\":1300,\"iat\":1000}", .err = error.AudienceMismatch },
        .{ .payload = "{\"iss\":\"https://issuer.example.org\",\"sub\":\"spiffe://example.org/a\",\"aud\":\"https://auth.example.com/token\",\"exp\":1300,\"iat\":1000}", .err = error.Malformed },
        .{ .payload = "{\"iss\":\"https://issuer.example.org\",\"aud\":\"https://auth.example.com/token\",\"jti\":\"4\",\"exp\":1300,\"iat\":1000}", .err = error.Malformed },
        .{ .payload = "{\"iss\":\"https://issuer.example.org\",\"sub\":\"spiffe://example.org/a\",\"aud\":\"https://auth.example.com/token\",\"jti\":\"5\",\"exp\":9000,\"iat\":1000}", .err = error.LifetimeTooLong },
        .{ .payload = "{\"iss\":\"https://issuer.example.org\",\"sub\":\"spiffe://other.org/a\",\"aud\":\"https://auth.example.com/token\",\"jti\":\"6\",\"exp\":1300,\"iat\":1000}", .err = error.WorkloadNotAuthorized },
        .{ .payload = "{\"iss\":\"https://issuer.example.org\",\"sub\":\"spiffe://example.org/a\",\"aud\":\"https://auth.example.com/token\",\"jti\":\"7\",\"exp\":9223372036854775807,\"iat\":-9223372036854775807}", .err = error.LifetimeTooLong },
    };
    for (cases) |case| {
        const t = try jwt.sign(arena, &key, case.payload, .{ .kid = "k1" });
        try std.testing.expectError(case.err, v.validate(arena, t, case.now));
        const body = try errorResponse(arena, case.err);
        try std.testing.expectEqualStrings("invalid_grant", json.getString(try json.parseTree(arena, body), "error").?);
    }
    // An HS256 JWT never counts, also with a key of the issuer.
    const hs: jwt.SigningKey = .{ .hs256 = "a-shared-secret-of-thirty-two-b!" };
    var hs_buf: [97]u8 = undefined;
    const hs_trusted = [_]TrustedIssuer{.{ .issuer = "https://issuer.example.org", .keys = &.{hs.verificationKey(&hs_buf, null)} }};
    const hs_v: WorkloadJwtValidator = .{ .audiences = &.{"https://auth.example.com/token"}, .trusted_issuers = &hs_trusted };
    try std.testing.expectError(error.UnknownKey, hs_v.validate(arena, try jwt.sign(arena, &hs, good, .{}), 1100));
    // Without static keys and without discovery, the keys are not available.
    const no_keys = [_]TrustedIssuer{.{ .issuer = "https://issuer.example.org" }};
    const nd: WorkloadJwtValidator = .{ .audiences = &.{"https://auth.example.com/token"}, .trusted_issuers = &no_keys };
    try std.testing.expectError(error.KeysUnavailable, nd.validate(arena, token, 1100));
    try std.testing.expectError(error.Malformed, v.validate(arena, "x.y", 1100));
}
