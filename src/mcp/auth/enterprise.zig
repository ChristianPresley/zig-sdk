//! The Enterprise-Managed Authorization extension
//! (`io.modelcontextprotocol/enterprise-managed-authorization`), an application of the Identity
//! Assertion JWT Authorization Grant (ID-JAG).
//!
//! The client side: the application signs the user in to the enterprise identity provider
//! (IdP) and gives the identity assertion (an ID token) to `EnterpriseClient`. On a challenge,
//! the client exchanges the assertion at the IdP for an ID-JAG (RFC 8693). Then it gives the
//! ID-JAG to the MCP authorization server as a JWT authorization grant (RFC 7523). The client
//! never sends the user to the authorization endpoint of the MCP authorization server.
//!
//! The authorization server side: `IdJagValidator` checks an ID-JAG that a token request
//! carries, for an application that runs its own authorization server.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const json = @import("../json.zig");
const common = @import("common.zig");
const jwt = @import("jwt.zig");

/// The identifier of the extension in the `extensions` capability.
pub const extension_id = "io.modelcontextprotocol/enterprise-managed-authorization";
/// The grant profile in `authorization_grant_profiles_supported` of the authorization server.
pub const grant_profile = "urn:ietf:params:oauth:grant-profile:id-jag";
/// The token type of an ID-JAG in a token exchange.
pub const token_type_id_jag = "urn:ietf:params:oauth:token-type:id-jag";
/// The JOSE `typ` header of an ID-JAG.
pub const jwt_type = "oauth-id-jag+jwt";
pub const grant_type_token_exchange = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const grant_type_jwt_bearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The kind of the identity assertion that goes into `subject_token`.
pub const SubjectTokenType = enum {
    id_token,
    saml2,
    refresh_token,

    pub fn uri(self: SubjectTokenType) []const u8 {
        return switch (self) {
            .id_token => "urn:ietf:params:oauth:token-type:id_token",
            .saml2 => "urn:ietf:params:oauth:token-type:saml2",
            .refresh_token => "urn:ietf:params:oauth:token-type:refresh_token",
        };
    }
};

pub const IdentityAssertion = struct {
    token: []const u8,
    type: SubjectTokenType = .id_token,
};

pub const EnterpriseClient = struct {
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
    /// The ID-JAG and its expiry in Unix seconds.
    grant: ?[]u8 = null,
    grant_expires_at: ?i64 = null,
    /// The access token of the MCP authorization server and its expiry.
    token: ?[]u8 = null,
    expires_at: ?i64 = null,
    /// The `error` code of the last failed token request, if the server sent one.
    last_error: ?[]u8 = null,

    pub const Idp = struct {
        /// The token endpoint of the IdP. Null discovers it from `issuer`.
        token_endpoint: ?[]const u8 = null,
        /// The issuer identifier of the IdP, for discovery of the token endpoint.
        issuer: ?[]const u8 = null,
        /// How the client authenticates at the IdP. The spec requires the same authentication
        /// that the client uses for single sign-on at the IdP.
        client: common.ClientAuth,
    };

    /// Gives the identity assertion. The application calls its IdP here, for example with a
    /// refresh token, when the last assertion expired.
    pub const AssertionSource = union(enum) {
        /// An assertion that the application got at sign-in. The client does not own it.
        static: IdentityAssertion,
        callback: struct {
            userdata: ?*anyopaque = null,
            /// Return the assertion in `arena`.
            obtain: *const fn (userdata: ?*anyopaque, arena: Allocator) anyerror!IdentityAssertion,
        },
    };

    pub const Options = struct {
        idp: Idp,
        assertion: AssertionSource,
        /// How the client authenticates at the MCP authorization server. The `client_id` must
        /// be the `client_id` claim of the ID-JAG.
        client: common.ClientAuth,
        /// The scopes to request. Null takes the challenge scope, else the `scopes_supported`
        /// of the protected resource metadata, else no scope.
        scope: ?[]const u8 = null,
        /// Send `resource` in the token exchange. The spec makes it optional.
        send_resource: bool = true,
        /// Refuse an authorization server that does not list the ID-JAG grant profile.
        require_grant_profile: bool = false,
        /// Get a new token when the current one expires within this number of seconds.
        refresh_margin_seconds: i64 = 60,
        max_step_up_attempts: u8 = 3,
        /// Accept `http` metadata and token endpoints. Tests only, production needs https.
        allow_http: bool = false,
        max_document_bytes: usize = 1 << 20,
        /// The clock for token lifetimes and assertions. Null uses the real clock.
        clock: common.Clock = null,
    };

    pub const Error = error{
        OutOfMemory,
        TooManyAttempts,
        NoResourceMetadata,
        ResourceMismatch,
        NoAuthorizationServer,
        NoAuthorizationServerMetadata,
        IssuerMismatch,
        InsecureEndpoint,
        /// The authorization server does not list the ID-JAG grant profile or the grant type.
        GrantProfileUnsupported,
        /// The IdP has no token endpoint in the options or in its metadata.
        NoIdpTokenEndpoint,
        /// The assertion callback failed.
        AssertionUnavailable,
        AuthMethodUnsupported,
        SigningAlgorithmUnsupported,
        SigningFailed,
        EntropyUnavailable,
        /// The IdP refused the token exchange or returned no ID-JAG. See `last_error`.
        TokenExchangeFailed,
        /// The authorization server refused the ID-JAG. See `last_error`.
        TokenRequestFailed,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) EnterpriseClient {
        return .{ .io = io, .gpa = gpa, .fetcher = .init(io, gpa, options.max_document_bytes, options.allow_http), .options = options };
    }

    pub fn deinit(self: *EnterpriseClient) void {
        self.fetcher.deinit();
        self.forget();
        common.replaceOwned(self.gpa, &self.last_error, null) catch unreachable;
        self.auth_methods.deinit(self.gpa);
        self.signing_algs.deinit(self.gpa);
    }

    fn forget(self: *EnterpriseClient) void {
        inline for (.{ "issuer", "token_endpoint", "resource", "scope", "grant", "token" }) |name| {
            common.replaceOwned(self.gpa, &@field(self, name), null) catch unreachable;
        }
        for (self.auth_methods.items) |s| self.gpa.free(s);
        self.auth_methods.clearRetainingCapacity();
        for (self.signing_algs.items) |s| self.gpa.free(s);
        self.signing_algs.clearRetainingCapacity();
        self.grant_expires_at = null;
        self.expires_at = null;
    }

    /// The interface for the `auth_provider` option of the HTTP client transport.
    pub fn provider(self: *EnterpriseClient) common.Provider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: common.Provider.VTable = .{ .token = providerToken, .handle_challenge = providerChallenge };

    fn providerToken(ptr: *anyopaque, arena: Allocator) ?[]const u8 {
        const self: *EnterpriseClient = @ptrCast(@alignCast(ptr));
        return self.currentToken(arena);
    }

    fn providerChallenge(ptr: *anyopaque, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void {
        const self: *EnterpriseClient = @ptrCast(@alignCast(ptr));
        return self.handleChallenge(arena, server_url, status, www_authenticate, attempt);
    }

    /// The token for the next request, copied into `arena`. When the token expires within the
    /// refresh margin, the client gets a new one first. It uses the ID-JAG while the ID-JAG is
    /// valid, else it does a new token exchange.
    pub fn currentToken(self: *EnterpriseClient, arena: Allocator) ?[]const u8 {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const time = common.now(self.io, self.options.clock);
        if (self.token != null and self.token_endpoint != null) if (self.expires_at) |exp| {
            if (time + self.options.refresh_margin_seconds >= exp) {
                self.renew(arena) catch {
                    if (time >= exp) common.replaceOwned(self.gpa, &self.token, null) catch {};
                };
            }
        };
        const t = self.token orelse return null;
        return arena.dupe(u8, t) catch null;
    }

    /// Get a token for `server_url` after a `401` or `403` challenge.
    pub fn handleChallenge(self: *EnterpriseClient, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) Error!void {
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
        if (!self.options.allow_http and !std.mem.startsWith(u8, meta.token_endpoint, "https://")) return error.InsecureEndpoint;
        if (meta.grant_types_supported.len > 0 and !common.listContains(meta.grant_types_supported, grant_type_jwt_bearer)) return error.GrantProfileUnsupported;
        if (self.options.require_grant_profile and !common.listContains(meta.authorization_grant_profiles_supported, grant_profile)) return error.GrantProfileUnsupported;

        var held: std.ArrayList([]const u8) = .empty;
        if (self.scope) |s| {
            var it = std.mem.tokenizeScalar(u8, s, ' ');
            while (it.next()) |one| try held.append(arena, one);
        }
        const scope = try common.selectScope(arena, self.options.scope, challenge, prm.scopes_supported, held.items, step_up);

        // A challenge means that the token did not work: get a new ID-JAG as well, because
        // the audience, the resource or the scope can be different now.
        self.forget();
        try common.replaceOwned(self.gpa, &self.issuer, issuer);
        try common.replaceOwned(self.gpa, &self.token_endpoint, meta.token_endpoint);
        try common.replaceOwned(self.gpa, &self.resource, prm.resource);
        try common.replaceOwned(self.gpa, &self.scope, scope);
        try replaceList(self.gpa, &self.auth_methods, meta.token_endpoint_auth_methods_supported);
        try replaceList(self.gpa, &self.signing_algs, meta.token_endpoint_auth_signing_alg_values_supported);
        try self.renew(arena);
    }

    /// Get an access token: with the stored ID-JAG while it is valid, else with a new one.
    fn renew(self: *EnterpriseClient, arena: Allocator) Error!void {
        const time = common.now(self.io, self.options.clock);
        const grant_valid = self.grant != null and (self.grant_expires_at == null or time + self.options.refresh_margin_seconds < self.grant_expires_at.?);
        if (!grant_valid) try self.exchange(arena);
        self.requestToken(arena) catch |e| {
            if (!grant_valid or e != error.TokenRequestFailed) return e;
            // The server refused a grant that we thought valid: try once with a new one.
            try self.exchange(arena);
            try self.requestToken(arena);
        };
    }

    /// The token exchange at the IdP (spec section 4).
    fn exchange(self: *EnterpriseClient, arena: Allocator) Error!void {
        const time = common.now(self.io, self.options.clock);
        var idp_meta: ?common.ServerMetadata = null;
        const idp_endpoint: []const u8 = self.options.idp.token_endpoint orelse blk: {
            const idp_issuer = self.options.idp.issuer orelse return error.NoIdpTokenEndpoint;
            const m = self.fetcher.authorizationServer(arena, idp_issuer) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InsecureEndpoint => return error.InsecureEndpoint,
                else => return error.NoIdpTokenEndpoint,
            };
            if (!std.mem.eql(u8, m.issuer, idp_issuer)) return error.IssuerMismatch;
            idp_meta = m;
            break :blk m.token_endpoint;
        };
        if (!self.options.allow_http and !std.mem.startsWith(u8, idp_endpoint, "https://")) return error.InsecureEndpoint;
        const assertion: IdentityAssertion = switch (self.options.assertion) {
            .static => |a| a,
            .callback => |cb| cb.obtain(cb.userdata, arena) catch return error.AssertionUnavailable,
        };

        var form: Io.Writer.Allocating = .init(arena);
        const w = &form.writer;
        var headers: std.ArrayList(http.Header) = .empty;
        try common.formField(w, "grant_type", grant_type_token_exchange, true);
        try common.formField(w, "requested_token_type", token_type_id_jag, false);
        // The audience is the issuer identifier of the MCP authorization server.
        try common.formField(w, "audience", self.issuer.?, false);
        if (self.options.send_resource) try common.formField(w, "resource", self.resource.?, false);
        if (self.scope) |s| try common.formField(w, "scope", s, false);
        try common.formField(w, "subject_token", assertion.token, false);
        try common.formField(w, "subject_token_type", assertion.type.uri(), false);
        try self.options.idp.client.apply(self.io, arena, time, .{
            .issuer = if (idp_meta) |m| m.issuer else self.options.idp.issuer orelse idp_endpoint,
            .auth_methods_supported = if (idp_meta) |m| m.token_endpoint_auth_methods_supported else &.{},
            .signing_algs_supported = if (idp_meta) |m| m.token_endpoint_auth_signing_alg_values_supported else &.{},
        }, w, &headers);
        switch (try self.fetcher.tokenRequest(arena, idp_endpoint, form.written(), headers.items)) {
            .failed => |f| {
                try common.replaceOwned(self.gpa, &self.last_error, f.code);
                return error.TokenExchangeFailed;
            },
            .ok => |reply| {
                const issued = reply.issued_token_type orelse "";
                if (!std.mem.eql(u8, issued, token_type_id_jag)) {
                    try common.replaceOwned(self.gpa, &self.last_error, "unexpected_issued_token_type");
                    return error.TokenExchangeFailed;
                }
                try common.replaceOwned(self.gpa, &self.grant, reply.access_token);
                // The lifetime: `expires_in`, else the `exp` claim of the grant.
                self.grant_expires_at = if (reply.expires_in) |s| time + s else if (jwt.decodePayloadUnverified(arena, reply.access_token)) |p| jwt.integerClaim(p, "exp") else |_| null;
            },
        }
    }

    /// The JWT bearer grant at the MCP authorization server (spec section 5).
    fn requestToken(self: *EnterpriseClient, arena: Allocator) Error!void {
        const time = common.now(self.io, self.options.clock);
        var form: Io.Writer.Allocating = .init(arena);
        const w = &form.writer;
        var headers: std.ArrayList(http.Header) = .empty;
        try common.formField(w, "grant_type", grant_type_jwt_bearer, true);
        try common.formField(w, "assertion", self.grant.?, false);
        try self.options.client.apply(self.io, arena, time, .{
            .issuer = self.issuer.?,
            .auth_methods_supported = self.auth_methods.items,
            .signing_algs_supported = self.signing_algs.items,
        }, w, &headers);
        switch (try self.fetcher.tokenRequest(arena, self.token_endpoint.?, form.written(), headers.items)) {
            .failed => |f| {
                try common.replaceOwned(self.gpa, &self.last_error, f.code);
                return error.TokenRequestFailed;
            },
            .ok => |reply| {
                try common.replaceOwned(self.gpa, &self.last_error, null);
                try common.replaceOwned(self.gpa, &self.token, reply.access_token);
                self.expires_at = if (reply.expires_in) |s| time + s else null;
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

/// An IdP that the authorization server trusts, with its signature keys.
pub const TrustedIssuer = struct {
    issuer: []const u8,
    /// The keys of the IdP, for example from `jwt.parseJwks` of its `jwks_uri` document.
    keys: []const jwt.Key,
};

/// What a valid ID-JAG grants. The slices point into the arena of `validate`.
pub const Grant = struct {
    issuer: []const u8,
    subject: []const u8,
    client_id: []const u8,
    jwt_id: []const u8,
    expires_at: i64,
    issued_at: i64,
    /// The `resource` claim, or empty when the grant has none.
    resources: []const []const u8 = &.{},
    scopes: []const []const u8 = &.{},
    email: ?[]const u8 = null,
    /// All claims, for the policy of the application.
    claims: Value,
};

pub const ValidateError = error{
    OutOfMemory,
    /// The token is not a compact JWS, or a required claim is missing or has the wrong type.
    Malformed,
    /// The `typ` header is not `oauth-id-jag+jwt`.
    TypeMismatch,
    /// The `iss` is not a trusted IdP.
    UntrustedIssuer,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
    Expired,
    NotYetValid,
    /// The lifetime is longer than `max_lifetime_seconds`.
    LifetimeTooLong,
    /// The `aud` is not exactly the issuer identifier of this authorization server.
    AudienceMismatch,
    /// The `client_id` claim is not the client that authenticated the request.
    ClientMismatch,
    /// The `resource` claim names no resource of this authorization server.
    ResourceMismatch,
    /// The replay check saw the `jti` before.
    Replayed,
};

/// Checks an ID-JAG at the token endpoint of an authorization server (draft section 4.4.1 and
/// RFC 7521 section 5.2). Every rejection maps to the OAuth error `invalid_grant`.
pub const IdJagValidator = struct {
    /// The issuer identifier of this authorization server.
    issuer: []const u8,
    trusted_issuers: []const TrustedIssuer,
    /// The resource identifiers that this authorization server issues tokens for. Empty skips
    /// the check. Else a `resource` claim must name at least one of them, and `Grant.resources`
    /// keeps only those.
    resources: []const []const u8 = &.{},
    clock_skew_seconds: i64 = 60,
    /// The longest accepted `exp` minus `iat`. Null skips the check.
    max_lifetime_seconds: ?i64 = 600,
    /// Records `jti` values to refuse a replay. Null skips the check.
    replay: ?ReplayCheck = null,

    pub const ReplayCheck = struct {
        userdata: ?*anyopaque = null,
        /// Return true when the store already has the pair of `issuer` and `jti`. Otherwise
        /// record the pair until `expires_at`.
        seen: *const fn (userdata: ?*anyopaque, issuer: []const u8, jti: []const u8, expires_at: i64) bool,
    };

    /// Validate `assertion` for a request that `client_id` authenticated, at `now` in Unix
    /// seconds.
    pub fn validate(self: *const IdJagValidator, arena: Allocator, assertion: []const u8, client_id: []const u8, now: i64) ValidateError!Grant {
        // Find the IdP from the unverified `iss`, then verify with its keys only.
        const unverified = jwt.decodePayloadUnverified(arena, assertion) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed => error.Malformed,
        };
        const iss = json.getString(unverified, "iss") orelse return error.Malformed;
        const trusted = for (self.trusted_issuers) |t| {
            if (std.mem.eql(u8, t.issuer, iss)) break t;
        } else return error.UntrustedIssuer;
        const claims = jwt.verify(arena, assertion, .{
            .keys = trusted.keys,
            .issuer = trusted.issuer,
            .token_type = jwt_type,
            .clock_skew_seconds = self.clock_skew_seconds,
        }, now) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Malformed => error.Malformed,
            error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
            error.UnknownKey => error.UnknownKey,
            error.BadSignature => error.BadSignature,
            error.Expired => error.Expired,
            error.NotYetValid => error.NotYetValid,
            error.IssuerMismatch => error.UntrustedIssuer,
            error.AudienceMismatch => error.AudienceMismatch,
            error.TypeMismatch => error.TypeMismatch,
        };
        const payload = claims.payload;

        // Required claims (draft section 3.1).
        const subject = claims.subject orelse return error.Malformed;
        const jti = claims.jwt_id orelse return error.Malformed;
        const exp = claims.expires_at orelse return error.Malformed;
        const iat = claims.issued_at orelse return error.Malformed;
        const grant_client = claims.client_id orelse return error.Malformed;
        if (self.max_lifetime_seconds) |max| if (exp - iat > max) return error.LifetimeTooLong;

        // `aud`: one string, or an array with exactly one element, equal to our issuer.
        const aud = payload.object.get("aud") orelse return error.Malformed;
        const aud_value: []const u8 = switch (aud) {
            .string => |s| s,
            .array => |a| if (a.items.len == 1 and a.items[0] == .string) a.items[0].string else return error.AudienceMismatch,
            else => return error.Malformed,
        };
        if (!std.mem.eql(u8, aud_value, self.issuer)) return error.AudienceMismatch;

        // Client continuity.
        if (!std.mem.eql(u8, grant_client, client_id)) return error.ClientMismatch;

        // Resources.
        var resources: std.ArrayList([]const u8) = .empty;
        if (payload.object.get("resource")) |r| switch (r) {
            .string => |s| try resources.append(arena, s),
            .array => |a| for (a.items) |item| {
                if (item != .string) return error.Malformed;
                try resources.append(arena, item.string);
            },
            else => return error.Malformed,
        };
        if (self.resources.len > 0 and resources.items.len > 0) {
            var kept: std.ArrayList([]const u8) = .empty;
            for (resources.items) |r| if (common.listContains(self.resources, r)) try kept.append(arena, r);
            if (kept.items.len == 0) return error.ResourceMismatch;
            resources = kept;
        }

        if (self.replay) |r| if (r.seen(r.userdata, trusted.issuer, jti, exp)) return error.Replayed;

        return .{
            .issuer = trusted.issuer,
            .subject = subject,
            .client_id = grant_client,
            .jwt_id = jti,
            .expires_at = exp,
            .issued_at = iat,
            .resources = resources.items,
            .scopes = claims.scopes,
            .email = json.getString(payload, "email"),
            .claims = payload,
        };
    }
};

/// The body of the token error response for a rejected ID-JAG (RFC 6749 section 5.2). The
/// error code is always `invalid_grant`. Answer it with status 400.
pub fn errorResponse(arena: Allocator, err: ValidateError) Allocator.Error![]u8 {
    const description: []const u8 = switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => "The ID-JAG is malformed or lacks a required claim",
        error.TypeMismatch => "The ID-JAG typ header is not oauth-id-jag+jwt",
        error.UntrustedIssuer => "The ID-JAG issuer is not trusted",
        error.UnsupportedAlgorithm, error.UnknownKey, error.BadSignature => "The ID-JAG signature is not valid",
        error.Expired => "The ID-JAG expired",
        error.NotYetValid => "The ID-JAG is not valid yet",
        error.LifetimeTooLong => "The ID-JAG lifetime is too long",
        error.AudienceMismatch => "The ID-JAG audience is not this authorization server",
        error.ClientMismatch => "The ID-JAG client_id does not match the authenticated client",
        error.ResourceMismatch => "The ID-JAG resource is not served by this authorization server",
        error.Replayed => "The ID-JAG was used before",
    };
    return std.fmt.allocPrint(arena, "{{\"error\":\"invalid_grant\",\"error_description\":{f}}}", .{std.json.fmt(description, .{})});
}
