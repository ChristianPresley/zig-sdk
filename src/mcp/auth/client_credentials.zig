//! The OAuth Client Credentials extension (`io.modelcontextprotocol/oauth-client-credentials`):
//! machine-to-machine authorization without a user. The client finds the authorization server
//! in the protected resource metadata. It authenticates with a client secret or with a signed
//! JWT assertion (RFC 7523 section 2.2). It requests a token with the grant type
//! `client_credentials`, keeps the token, and gets a new one before it expires.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const common = @import("common.zig");
const jwt = @import("jwt.zig");

/// The identifier of the extension in the `extensions` capability.
pub const extension_id = "io.modelcontextprotocol/oauth-client-credentials";

pub const ClientCredentials = struct {
    io: Io,
    gpa: Allocator,
    fetcher: common.Fetcher,
    options: Options,
    lock: Io.Mutex = .init,
    /// What the last successful flow found. A proactive renewal uses it without discovery.
    issuer: ?[]u8 = null,
    token_endpoint: ?[]u8 = null,
    auth_methods: std.ArrayList([]u8) = .empty,
    signing_algs: std.ArrayList([]u8) = .empty,
    resource: ?[]u8 = null,
    scope: ?[]u8 = null,
    token: ?[]u8 = null,
    /// Unix seconds. Null when the server gave no `expires_in`.
    expires_at: ?i64 = null,
    /// The `error` code of the last failed token request, if the server sent one.
    last_error: ?[]u8 = null,

    pub const Options = struct {
        /// The pre-registered client and how it authenticates. The spec recommends
        /// `private_key_jwt`. This grant does not permit the `none` method.
        client: common.ClientAuth,
        /// The scopes to request. Null takes the challenge scope, else the `scopes_supported`
        /// of the protected resource metadata, else no scope.
        scope: ?[]const u8 = null,
        /// Get a new token when the current one expires within this number of seconds.
        refresh_margin_seconds: i64 = 60,
        max_step_up_attempts: u8 = 3,
        /// Accept an `http` token endpoint. Tests only, production needs https.
        allow_http: bool = false,
        max_document_bytes: usize = 1 << 20,
        /// The clock for token lifetimes and assertions. Null uses the real clock.
        clock: common.Clock = null,
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
        /// The server lists grant types, and `client_credentials` is not one of them.
        GrantTypeUnsupported,
        /// The client uses the `none` method, which this grant does not allow.
        ClientAuthenticationRequired,
        AuthMethodUnsupported,
        SigningAlgorithmUnsupported,
        SigningFailed,
        EntropyUnavailable,
        /// The token endpoint refused the request. `last_error` has the error code.
        TokenRequestFailed,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) ClientCredentials {
        return .{ .io = io, .gpa = gpa, .fetcher = .init(io, gpa, options.max_document_bytes), .options = options };
    }

    pub fn deinit(self: *ClientCredentials) void {
        self.fetcher.deinit();
        self.forget();
        common.replaceOwned(self.gpa, &self.last_error, null) catch unreachable;
        self.auth_methods.deinit(self.gpa);
        self.signing_algs.deinit(self.gpa);
    }

    /// Discard the token and everything that discovery found.
    fn forget(self: *ClientCredentials) void {
        inline for (.{ "issuer", "token_endpoint", "resource", "scope", "token" }) |name| {
            common.replaceOwned(self.gpa, &@field(self, name), null) catch unreachable;
        }
        for (self.auth_methods.items) |s| self.gpa.free(s);
        self.auth_methods.clearRetainingCapacity();
        for (self.signing_algs.items) |s| self.gpa.free(s);
        self.signing_algs.clearRetainingCapacity();
        self.expires_at = null;
    }

    /// The interface for the `auth_provider` option of the HTTP client transport.
    pub fn provider(self: *ClientCredentials) common.Provider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: common.Provider.VTable = .{ .token = providerToken, .handle_challenge = providerChallenge };

    fn providerToken(ptr: *anyopaque, arena: Allocator) ?[]const u8 {
        const self: *ClientCredentials = @ptrCast(@alignCast(ptr));
        return self.currentToken(arena);
    }

    fn providerChallenge(ptr: *anyopaque, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void {
        const self: *ClientCredentials = @ptrCast(@alignCast(ptr));
        return self.handleChallenge(arena, server_url, status, www_authenticate, attempt);
    }

    /// The token for the next request, copied into `arena`. When the token expires within the
    /// refresh margin, the client requests a new one first. When that fails, the client keeps
    /// the old token until it expires.
    pub fn currentToken(self: *ClientCredentials, arena: Allocator) ?[]const u8 {
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

    /// Get a token for `server_url` after a `401` or `403` challenge.
    pub fn handleChallenge(self: *ClientCredentials, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) Error!void {
        if (attempt > self.options.max_step_up_attempts) return error.TooManyAttempts;
        if (self.options.client == .none) return error.ClientAuthenticationRequired;
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
        if (meta.grant_types_supported.len > 0 and !common.listContains(meta.grant_types_supported, "client_credentials")) return error.GrantTypeUnsupported;

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

    /// The token request of RFC 6749 section 4.4 with the stored endpoint, resource and scope.
    fn requestToken(self: *ClientCredentials, arena: Allocator) Error!void {
        const time = common.now(self.io, self.options.clock);
        var form: Io.Writer.Allocating = .init(arena);
        const w = &form.writer;
        var headers: std.ArrayList(http.Header) = .empty;
        try common.formField(w, "grant_type", "client_credentials", true);
        try self.options.client.apply(self.io, arena, time, .{
            .issuer = self.issuer.?,
            .auth_methods_supported = self.auth_methods.items,
            .signing_algs_supported = self.signing_algs.items,
        }, w, &headers);
        try common.formField(w, "resource", self.resource.?, false);
        if (self.scope) |s| try common.formField(w, "scope", s, false);
        switch (try self.fetcher.tokenRequest(arena, self.token_endpoint.?, form.written(), headers.items)) {
            .failed => |f| {
                try common.replaceOwned(self.gpa, &self.last_error, f.code);
                return error.TokenRequestFailed;
            },
            .ok => |reply| {
                try common.replaceOwned(self.gpa, &self.last_error, null);
                try common.replaceOwned(self.gpa, &self.token, reply.access_token);
                self.expires_at = if (reply.expires_in) |s| time + s else null;
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
