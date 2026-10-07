//! The OAuth 2.1 client side of MCP authorization. It discovers the protected resource and
//! authorization server metadata, registers the client, runs the authorization code flow with
//! PKCE and requests tokens. The HTTP client transport calls it for 401 and 403 challenges.
//!
//! The client keeps credentials per issuer and never uses them for another authorization server.
//! When the server issues a refresh token, the client gets new access tokens with it and does
//! not send the user to the browser again.
//!
//! With the `storage` option, the client keeps the registration and the tokens in a
//! `TokenStorage`. A new process then uses them and needs no new authorization.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const json = @import("../json.zig");
const common = @import("common.zig");
const dpop = @import("dpop.zig");
const token_storage = @import("token_storage.zig");

const log = std.log.scoped(.mcp_auth);

const formField = common.formField;
const listContains = common.listContains;
const appendUnique = common.appendUnique;
const base64Url = common.base64Url;

pub const Client = struct {
    io: Io,
    gpa: Allocator,
    fetcher: common.Fetcher,
    options: Options,
    /// State for the current server: the issuer it delegates to and what we hold for it.
    issuer: ?[]u8 = null,
    /// The resource indicator of the tokens: the `resource` of the protected resource metadata.
    resource: ?[]u8 = null,
    /// The token endpoint of the issuer. A refresh before a request uses it without discovery.
    token_endpoint: ?[]u8 = null,
    registration: ?Registered = null,
    token: ?[]u8 = null,
    /// The token is DPoP-bound: requests carry it with the DPoP scheme and a proof.
    token_dpop: bool = false,
    /// Unix seconds. Null when the server gave no `expires_in`.
    expires_at: ?i64 = null,
    /// The refresh token of the current grant. Null when the server issued none.
    refresh_token: ?[]u8 = null,
    /// Scopes granted with the current token (space separated list kept as a slice list).
    granted_scopes: std.ArrayList([]u8) = .empty,
    /// The issuer of the first authorization server that used pre-registered credentials
    /// without an issuer.
    bound_issuer: ?[]u8 = null,
    /// The last error that an authorization server sent.
    failure: ?Failure = null,
    /// The client read the storage for the current issuer and resource.
    storage_loaded: bool = false,
    lock: Io.Mutex = .init,

    pub const Registration = union(enum) {
        /// Credentials issued out of band. The client uses the entry for the issuer of the
        /// authorization server. It never sends the entry to another authorization server.
        pre_registered: []const Credentials,
        /// A client ID metadata document URL (used when the server supports it, else DCR).
        /// The URL must use https and have a path.
        client_metadata_url: []const u8,
        /// Dynamic client registration only.
        dynamic,
    };

    /// Client credentials that an authorization server issued out of band.
    pub const Credentials = struct {
        /// The `issuer` identifier of the authorization server that issued the credentials.
        /// Null binds the credentials to the first authorization server that the client uses.
        /// We recommend that you set it.
        issuer: ?[]const u8 = null,
        client_id: []const u8,
        client_secret: ?[]const u8 = null,
    };

    /// The `application_type` of dynamic client registration (OpenID Connect Dynamic Client
    /// Registration 1.0).
    pub const ApplicationType = enum {
        /// Desktop and mobile applications, command line tools, and web applications on a
        /// local host.
        native,
        /// Browser-based applications that a remote host serves.
        web,
    };

    /// How the client gets the authorization code.
    pub const Authorize = union(enum) {
        /// Request the authorization URL, do not follow the redirect, and read the code from
        /// the `Location` header. For automated tests only.
        headless_redirect,
        /// Give the URL to the application, which returns the redirect URL it received.
        callback: struct {
            userdata: ?*anyopaque = null,
            open: *const fn (userdata: ?*anyopaque, arena: Allocator, url: []const u8) anyerror![]const u8,
        },
    };

    pub const Options = struct {
        registration: Registration = .dynamic,
        client_name: []const u8 = "zig-sdk",
        /// The redirect URI must use https or `http` with a loopback host.
        redirect_uri: []const u8 = "http://127.0.0.1:41893/callback",
        /// Set `.web` for a browser-based application that a remote host serves.
        application_type: ApplicationType = .native,
        authorize: Authorize = .headless_redirect,
        /// Ask for `offline_access` when the authorization server lists it.
        want_refresh_token: bool = true,
        /// Refresh the access token when it expires within this number of seconds.
        refresh_margin_seconds: i64 = 60,
        /// The clock for token lifetimes. Null uses the real clock.
        clock: common.Clock = null,
        max_step_up_attempts: u8 = 3,
        /// Accept `http` metadata, registration, authorization and token endpoints. Tests
        /// only, production needs https.
        allow_http: bool = false,
        /// Trust only the CA certificates of this bundle for the https requests of the client.
        /// These are the metadata, registration and token requests, and the authorization
        /// request of `headless_redirect`. Null uses the CA store of the system. Use it for a
        /// private CA or the CA of a test server. The bundle must stay valid and unchanged
        /// until `deinit`. The HTTP client transport can use the same bundle in its `tls`
        /// option: `.{ .trust = .{ .bundle = &bundle } }`.
        ca_bundle: ?*const std.crypto.Certificate.Bundle = null,
        max_document_bytes: usize = 1 << 20,
        /// Request DPoP-bound tokens with this key (RFC 9449). The token request and each
        /// request to the MCP server carry a proof. Null requests bearer tokens.
        dpop: ?*dpop.Prover = null,
        /// Send `dpop_bound_access_tokens` in dynamic client registration: the authorization
        /// server must then refuse token requests without a proof. It needs `dpop`.
        dpop_bound_access_tokens: bool = false,
        /// Keep the registration and the tokens in this storage. The client loads the record
        /// at the first challenge for an issuer and saves it after each change. The storage
        /// does not get the secret of pre-registered credentials.
        storage: ?token_storage.TokenStorage = null,
        /// The client part of the storage key. Null takes a value from `registration`: the client
        /// ID, the metadata document URL, or the client name and the redirect URI. Set it to
        /// keep the records of two accounts apart.
        storage_identity: ?[]const u8 = null,
    };

    const Registered = struct {
        client_id: []u8,
        client_secret: ?[]u8,
        auth_method: AuthMethod,
    };

    pub const AuthMethod = token_storage.AuthMethod;

    /// An error that an authorization server sent for a registration or a token request.
    pub const Failure = struct {
        step: Step,
        /// The HTTP status, or 0 when the request did not complete.
        status: u16,
        /// The `error` code of the response, for example `invalid_redirect_uri`.
        code: ?[]const u8 = null,
        /// The `error_description` of the response. It is text from the server.
        description: ?[]const u8 = null,

        /// `refresh` is a token request with a refresh token.
        pub const Step = enum { registration, token, refresh };
    };

    pub const Error = error{
        OutOfMemory,
        /// More challenges than `max_step_up_attempts` for one request.
        TooManyAttempts,
        /// The client found no protected resource metadata.
        NoResourceMetadata,
        /// The metadata `resource` is not the server URL.
        ResourceMismatch,
        NoAuthorizationServer,
        NoAuthorizationServerMetadata,
        /// The metadata `issuer` is not the URL of the query.
        IssuerMismatch,
        InsecureEndpoint,
        /// `Options.redirect_uri` does not use https or a loopback host.
        InvalidRedirectUri,
        /// The client ID metadata document URL does not use https or has no path.
        InvalidClientMetadataUrl,
        /// No pre-registered credentials are for the issuer of the authorization server. The
        /// authorization server changed, or the configuration has no entry for it.
        IssuerNotRegistered,
        /// The authorization server does not offer PKCE with S256.
        PkceUnsupported,
        /// No way to obtain a client id.
        RegistrationUnavailable,
        /// The authorization server rejected the registration. `lastFailure` has the details.
        RegistrationFailed,
        AuthorizationFailed,
        StateMismatch,
        IssMissing,
        IssMismatch,
        /// The token request failed. `lastFailure` has the details.
        TokenRequestFailed,
        HttpFailed,
        InvalidChallenge,
        /// The authorization server lists DPoP algorithms without the algorithm of the key.
        DpopAlgorithmUnsupported,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) Client {
        var fetcher: common.Fetcher = .init(io, gpa, options.max_document_bytes, options.allow_http);
        fetcher.ca_bundle = options.ca_bundle;
        return .{ .io = io, .gpa = gpa, .fetcher = fetcher, .options = options };
    }

    pub fn deinit(self: *Client) void {
        self.fetcher.deinit();
        self.clearCredentials();
        inline for (.{ "issuer", "resource", "token_endpoint", "bound_issuer" }) |name| {
            common.replaceOwned(self.gpa, &@field(self, name), null) catch unreachable;
        }
        self.clearFailure();
        self.granted_scopes.deinit(self.gpa);
    }

    /// Discard the registration and the tokens.
    fn clearCredentials(self: *Client) void {
        if (self.registration) |r| {
            self.gpa.free(r.client_id);
            if (r.client_secret) |s| {
                std.crypto.secureZero(u8, s);
                self.gpa.free(s);
            }
            self.registration = null;
        }
        self.clearTokens();
    }

    /// Discard the access token, the refresh token and the granted scopes.
    fn clearTokens(self: *Client) void {
        common.replaceOwned(self.gpa, &self.token, null) catch unreachable;
        common.replaceOwned(self.gpa, &self.refresh_token, null) catch unreachable;
        self.token_dpop = false;
        self.expires_at = null;
        for (self.granted_scopes.items) |s| self.gpa.free(s);
        self.granted_scopes.clearRetainingCapacity();
    }

    fn clearFailure(self: *Client) void {
        const f = self.failure orelse return;
        if (f.code) |c| self.gpa.free(c);
        if (f.description) |d| self.gpa.free(d);
        self.failure = null;
    }

    fn recordFailure(self: *Client, step: Failure.Step, status: u16, code: ?[]const u8, description: ?[]const u8) Allocator.Error!void {
        self.clearFailure();
        const owned_code: ?[]u8 = if (code) |c| try self.gpa.dupe(u8, c) else null;
        errdefer if (owned_code) |c| self.gpa.free(c);
        self.failure = .{
            .step = step,
            .status = status,
            .code = owned_code,
            .description = if (description) |d| try self.gpa.dupe(u8, d) else null,
        };
        log.warn("the {t} request failed with status {d}: {f} {f}", .{ step, status, std.json.fmt(code, .{}), std.json.fmt(description, .{}) });
    }

    /// The last error that an authorization server sent for a registration or a token
    /// request, copied into `arena`. Null when the last challenge had no such error.
    pub fn lastFailure(self: *Client, arena: Allocator) Allocator.Error!?Failure {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const f = self.failure orelse return null;
        return .{
            .step = f.step,
            .status = f.status,
            .code = if (f.code) |c| try arena.dupe(u8, c) else null,
            .description = if (f.description) |d| try arena.dupe(u8, d) else null,
        };
    }

    /// The bearer token to send, if any. The slice is valid until the next challenge.
    pub fn currentToken(self: *Client) ?[]const u8 {
        return self.token;
    }

    /// The interface for the `auth_provider` option of the HTTP client transport.
    pub fn provider(self: *Client) common.Provider {
        return .{ .ptr = self, .vtable = &provider_vtable };
    }

    const provider_vtable: common.Provider.VTable = .{
        .token = providerToken,
        .handle_challenge = providerChallenge,
        .credentials = providerCredentials,
        .dpop_nonce = providerNonce,
    };

    fn providerCredentials(ptr: *anyopaque, arena: Allocator, method: []const u8, url: []const u8) ?common.Credentials {
        const self: *Client = @ptrCast(@alignCast(ptr));
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.renewIfDue(arena);
        const t = self.token orelse return null;
        return common.credentialsFor(arena, self.options.dpop, self.token_dpop, t, method, url);
    }

    fn providerNonce(ptr: *anyopaque, url: []const u8, nonce: []const u8) void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        const p = self.options.dpop orelse return;
        p.rememberNonce(url, nonce) catch {};
    }

    fn providerToken(ptr: *anyopaque, arena: Allocator) ?[]const u8 {
        const self: *Client = @ptrCast(@alignCast(ptr));
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.renewIfDue(arena);
        const t = self.token orelse return null;
        return arena.dupe(u8, t) catch null;
    }

    /// Refresh the access token when it expires within the margin. When the refresh fails, the
    /// client keeps the old token until it expires. The caller holds the lock.
    fn renewIfDue(self: *Client, arena: Allocator) void {
        const exp = self.expires_at orelse return;
        if (self.token == null or self.refresh_token == null or self.registration == null) return;
        if (self.resource == null or self.token_endpoint == null) return;
        const time = common.now(self.io, self.options.clock);
        if (time +| self.options.refresh_margin_seconds < exp) return;
        self.clearFailure();
        _ = self.refresh(arena) catch |e| {
            log.warn("the refresh of the access token failed: {t}", .{e});
            if (time >= exp) common.replaceOwned(self.gpa, &self.token, null) catch unreachable;
        };
    }

    fn providerChallenge(ptr: *anyopaque, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        _ = try self.handleChallenge(arena, server_url, status, www_authenticate, attempt);
    }

    // -- Challenge handling -------------------------------------------------------------------

    pub const Challenge = common.Challenge;

    /// Parse a `WWW-Authenticate` value. The parser reads the `Bearer` and `DPoP` schemes and
    /// ignores other schemes.
    pub const parseChallenge = common.parseChallenge;

    /// Obtain a token for `server_url` after a challenge. `attempt` starts at 1 for the first
    /// challenge of a request. Returns the bearer token, owned by the client.
    ///
    /// When the client has a refresh token and the challenge is not a step-up, the client
    /// refreshes the access token first. When the server refuses the refresh token, the client
    /// runs the authorization code flow.
    pub fn handleChallenge(self: *Client, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) Error![]const u8 {
        if (attempt > self.options.max_step_up_attempts) return error.TooManyAttempts;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.clearFailure();
        if (!common.validRedirectUri(self.options.redirect_uri)) return error.InvalidRedirectUri;
        const challenge: Challenge = if (www_authenticate) |h| try parseChallenge(arena, h) else .{};
        const step_up = challenge.isStepUp(status);

        // Discovery.
        const prm = try self.fetcher.resourceMetadata(arena, server_url, challenge.resource_metadata);
        if (!common.resourceCoversServer(prm.resource, server_url)) return error.ResourceMismatch;
        // RFC 8707: the resource indicator is the canonical identifier from the metadata. The
        // discovery tries the path-inserted location first, so the value is the most specific
        // identifier that the server declares for itself.
        const resource = prm.resource;
        if (prm.authorization_servers.len == 0) return error.NoAuthorizationServer;
        const issuer = prm.authorization_servers[0];
        try self.selectServer(issuer, resource);
        const meta = try self.fetcher.authorizationServer(arena, issuer);
        if (!std.mem.eql(u8, meta.issuer, issuer)) return error.IssuerMismatch;
        const authorization_endpoint = meta.authorization_endpoint orelse return error.NoAuthorizationServerMetadata;
        try common.requireHttps(self.options.allow_http, authorization_endpoint);
        try common.requireHttps(self.options.allow_http, meta.token_endpoint);
        if (!listContains(meta.code_challenge_methods_supported, "S256")) return error.PkceUnsupported;
        try meta.checkDpop(self.options.dpop);
        try common.replaceOwned(self.gpa, &self.token_endpoint, meta.token_endpoint);

        // The storage can have a registration and tokens from an earlier process.
        var stored_token = false;
        if (!self.storage_loaded) {
            self.storage_loaded = true;
            stored_token = try self.loadStored(issuer, resource);
        }

        // Registration.
        try self.ensureRegistered(arena, meta);

        // A token from the storage was not in the request of this challenge, so try it first.
        if (stored_token and !step_up and !self.expiresSoon()) return self.token.?;
        // A refresh gets a new access token without the user. A step-up needs a new grant with
        // more scopes, and a refresh never widens the scope.
        if (!step_up and self.refresh_token != null) switch (try self.refresh(arena)) {
            .refreshed => return self.token.?,
            .grant_refused => {},
            .client_refused => try self.ensureRegistered(arena, meta),
        };
        const reg = self.registration.?;

        // Scopes: the challenge, else the resource metadata, else none. A step-up keeps what
        // was granted before. `offline_access` is added when the server lists it.
        var scopes: std.ArrayList([]const u8) = .empty;
        if (step_up) for (self.granted_scopes.items) |s| try appendUnique(arena, &scopes, s);
        if (challenge.scope) |list| {
            var it = std.mem.tokenizeScalar(u8, list, ' ');
            while (it.next()) |s| try appendUnique(arena, &scopes, s);
        } else if (!step_up) {
            for (prm.scopes_supported) |s| try appendUnique(arena, &scopes, s);
        }
        if (self.options.want_refresh_token and listContains(meta.scopes_supported, "offline_access")) try appendUnique(arena, &scopes, "offline_access");
        const scope_text: ?[]const u8 = if (scopes.items.len == 0) null else try std.mem.join(arena, " ", scopes.items);

        // Authorization code with PKCE.
        var verifier_bytes: [32]u8 = undefined;
        var state_bytes: [32]u8 = undefined;
        self.io.randomSecure(&verifier_bytes) catch return error.AuthorizationFailed;
        self.io.randomSecure(&state_bytes) catch return error.AuthorizationFailed;
        const verifier = try base64Url(arena, &verifier_bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
        const code_challenge = try base64Url(arena, &digest);
        const state = try base64Url(arena, &state_bytes);

        var url: Io.Writer.Allocating = .init(arena);
        const w = &url.writer;
        w.writeAll(authorization_endpoint) catch return error.OutOfMemory;
        w.writeAll(if (std.mem.indexOfScalar(u8, authorization_endpoint, '?') == null) "?" else "&") catch return error.OutOfMemory;
        try formField(w, "response_type", "code", true);
        try formField(w, "client_id", reg.client_id, false);
        try formField(w, "redirect_uri", self.options.redirect_uri, false);
        try formField(w, "state", state, false);
        try formField(w, "code_challenge", code_challenge, false);
        try formField(w, "code_challenge_method", "S256", false);
        try formField(w, "resource", resource, false);
        if (scope_text) |s| try formField(w, "scope", s, false);
        // RFC 9449 section 10: bind the authorization code to the DPoP key.
        if (self.options.dpop) |p| try formField(w, "dpop_jkt", p.jkt, false);
        const redirect = try self.obtainRedirect(arena, url.written());
        const params = try common.parseQuery(arena, redirect);
        const code = params.get("code") orelse return error.AuthorizationFailed;
        const got_state = params.get("state") orelse return error.StateMismatch;
        if (!std.mem.eql(u8, got_state, state)) return error.StateMismatch;
        // RFC 9207: compare `iss` by simple string comparison against the recorded issuer.
        if (params.get("iss")) |iss| {
            if (!std.mem.eql(u8, iss, issuer)) return error.IssMismatch;
        } else if (meta.authorization_response_iss_parameter_supported == true) {
            return error.IssMissing;
        }

        // Token request.
        var body: Io.Writer.Allocating = .init(arena);
        const bw = &body.writer;
        try formField(bw, "grant_type", "authorization_code", true);
        try formField(bw, "code", code, false);
        try formField(bw, "redirect_uri", self.options.redirect_uri, false);
        try formField(bw, "code_verifier", verifier, false);
        try formField(bw, "resource", resource, false);
        var extra: std.ArrayList(http.Header) = .empty;
        try clientAuthentication(arena, reg, bw, &extra);
        const reply = switch (try self.fetcher.tokenRequest(arena, meta.token_endpoint, body.written(), extra.items, self.options.dpop)) {
            .ok => |r| r,
            .failed => |f| {
                try self.recordFailure(.token, f.status, f.code, f.description);
                if (f.code) |c| if (std.mem.eql(u8, c, "invalid_client")) {
                    // The server does not know the client. The next challenge registers again.
                    self.deleteStored();
                    self.clearCredentials();
                };
                return error.TokenRequestFailed;
            },
        };
        // A new grant replaces the refresh token of the old grant, also with none.
        try self.keepTokens(reply, scope_text orelse "", false);
        self.saveStored();
        return self.token.?;
    }

    fn ensureRegistered(self: *Client, arena: Allocator, meta: common.ServerMetadata) Error!void {
        if (self.registration != null) return;
        try self.register(arena, meta);
        // The configuration holds pre-registered credentials, so only another registration
        // changes the record.
        if (self.options.registration != .pre_registered) self.saveStored();
    }

    /// True when the access token expires within the refresh margin.
    fn expiresSoon(self: *Client) bool {
        const exp = self.expires_at orelse return false;
        return common.now(self.io, self.options.clock) +| self.options.refresh_margin_seconds >= exp;
    }

    // -- Storage ---------------------------------------------------------------------------------

    /// The client ID of the pre-registered credentials for `issuer`, without a binding.
    fn configuredClientId(list: []const Credentials, issuer: []const u8) ?[]const u8 {
        for (list) |c| if (c.issuer) |i| if (std.mem.eql(u8, i, issuer)) return c.client_id;
        for (list) |c| if (c.issuer == null) return c.client_id;
        return null;
    }

    /// The client part of the storage key, owned by the caller. Null when the client has no
    /// identity for `issuer`.
    fn storageIdentity(self: *Client, issuer: []const u8) Allocator.Error!?[]u8 {
        if (self.options.storage_identity) |id| return try self.gpa.dupe(u8, id);
        return switch (self.options.registration) {
            .pre_registered => |list| if (configuredClientId(list, issuer)) |id| try self.gpa.dupe(u8, id) else null,
            .client_metadata_url => |url| try self.gpa.dupe(u8, url),
            .dynamic => try std.fmt.allocPrint(self.gpa, "dynamic {s} {s}", .{ self.options.client_name, self.options.redirect_uri }),
        };
    }

    /// Read the record of `issuer` and `resource`. Returns true when the record gave an access
    /// token. A DPoP-bound token works only with the DPoP key of its request. The same applies
    /// to the refresh token of a public client. Thus the client skips the tokens of another key.
    fn loadStored(self: *Client, issuer: []const u8, resource: []const u8) Allocator.Error!bool {
        const storage = self.options.storage orelse return false;
        const identity = (try self.storageIdentity(issuer)) orelse return false;
        defer self.gpa.free(identity);
        const key: token_storage.Key = .{ .issuer = issuer, .resource = resource, .client = identity };
        var record = (storage.load(self.gpa, key) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            log.warn("could not load the token record: {t}", .{e});
            if (e == error.InvalidRecord) storage.delete(key) catch {};
            return false;
        }) orelse return false;
        defer record.deinit(self.gpa);
        if (record.registration) |r| switch (self.options.registration) {
            // The configuration has the pre-registered credentials. A record of another client
            // ID is stale.
            .pre_registered => |list| if (!std.mem.eql(u8, configuredClientId(list, issuer) orelse "", r.client_id)) return false,
            else => if (self.registration == null) {
                const id = try self.gpa.dupe(u8, r.client_id);
                errdefer self.gpa.free(id);
                const secret: ?[]u8 = if (r.client_secret) |s| try self.gpa.dupe(u8, s) else null;
                self.registration = .{ .client_id = id, .client_secret = secret, .auth_method = r.auth_method };
            },
        };
        const jkt: ?[]const u8 = if (self.options.dpop) |p| p.jkt else null;
        const same_key = if (record.dpop_jkt) |a| (jkt != null and std.mem.eql(u8, a, jkt.?)) else jkt == null;
        if (!same_key) {
            log.info("the stored tokens are for another DPoP key", .{});
            return false;
        }
        try common.replaceOwned(self.gpa, &self.token, record.access_token);
        try common.replaceOwned(self.gpa, &self.refresh_token, record.refresh_token);
        self.token_dpop = record.dpop_bound and self.options.dpop != null;
        self.expires_at = record.expires_at;
        for (self.granted_scopes.items) |s| self.gpa.free(s);
        self.granted_scopes.clearRetainingCapacity();
        for (record.scopes) |s| {
            const copy = try self.gpa.dupe(u8, s);
            errdefer self.gpa.free(copy);
            try self.granted_scopes.append(self.gpa, copy);
        }
        return self.token != null;
    }

    /// Save the registration and the tokens for the current issuer and resource. A failure of
    /// the storage does not stop the flow. The log has it.
    fn saveStored(self: *Client) void {
        const storage = self.options.storage orelse return;
        const issuer = self.issuer orelse return;
        const resource = self.resource orelse return;
        const identity = (self.storageIdentity(issuer) catch return) orelse return;
        defer self.gpa.free(identity);
        const registration: ?token_storage.Record.Registration = if (self.registration) |r| .{
            .client_id = r.client_id,
            .client_secret = if (self.options.registration == .pre_registered) null else r.client_secret,
            .auth_method = r.auth_method,
        } else null;
        const record: token_storage.Record = .{
            .registration = registration,
            .access_token = self.token,
            .expires_at = self.expires_at,
            .refresh_token = self.refresh_token,
            .scopes = self.granted_scopes.items,
            .dpop_bound = self.token_dpop,
            .dpop_jkt = if (self.options.dpop) |p| p.jkt else null,
        };
        storage.save(self.gpa, .{ .issuer = issuer, .resource = resource, .client = identity }, record) catch |e|
            log.warn("could not save the token record: {t}", .{e});
    }

    /// Delete the record of the current issuer and resource.
    fn deleteStored(self: *Client) void {
        const storage = self.options.storage orelse return;
        const issuer = self.issuer orelse return;
        const resource = self.resource orelse return;
        const identity = (self.storageIdentity(issuer) catch return) orelse return;
        defer self.gpa.free(identity);
        storage.delete(.{ .issuer = issuer, .resource = resource, .client = identity }) catch |e|
            log.warn("could not delete the token record: {t}", .{e});
    }

    /// Add the client authentication of the registration to a token request.
    fn clientAuthentication(arena: Allocator, reg: Registered, form: *Io.Writer, headers: *std.ArrayList(http.Header)) Allocator.Error!void {
        if (reg.auth_method != .client_secret_basic) try formField(form, "client_id", reg.client_id, false);
        if (reg.auth_method == .client_secret_post) try formField(form, "client_secret", reg.client_secret orelse "", false);
        if (reg.auth_method == .client_secret_basic) {
            const pair = try std.mem.concat(arena, u8, &.{ reg.client_id, ":", reg.client_secret orelse "" });
            const enc = std.base64.standard.Encoder;
            const out = try arena.alloc(u8, enc.calcSize(pair.len));
            _ = enc.encode(out, pair);
            try headers.append(arena, .{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Basic ", out }) });
        }
    }

    /// Keep the tokens of a token response. `requested_scope` is the scope of the request, or
    /// null for a refresh. Without a new refresh token, a refresh keeps the old one.
    fn keepTokens(self: *Client, reply: common.TokenResponse, requested_scope: ?[]const u8, refreshing: bool) Allocator.Error!void {
        const time = common.now(self.io, self.options.clock);
        try common.replaceOwned(self.gpa, &self.token, reply.access_token);
        // RFC 9449 section 5: an authorization server without DPoP gives a bearer token.
        self.token_dpop = self.options.dpop != null and common.isDpopTokenType(reply.token_type);
        self.expires_at = if (reply.expires_in) |s| time +| s else null;
        // OAuth 2.1 section 4.3.1: a new refresh token replaces the old one.
        if (reply.refresh_token != null or !refreshing) try common.replaceOwned(self.gpa, &self.refresh_token, reply.refresh_token);
        // RFC 6749 section 5.1: without `scope`, the granted scope is the requested scope. A
        // refresh without `scope` keeps the scope of the grant.
        const granted = reply.scope orelse requested_scope orelse return;
        for (self.granted_scopes.items) |s| self.gpa.free(s);
        self.granted_scopes.clearRetainingCapacity();
        var it = std.mem.tokenizeScalar(u8, granted, ' ');
        while (it.next()) |s| {
            const copy = try self.gpa.dupe(u8, s);
            errdefer self.gpa.free(copy);
            try self.granted_scopes.append(self.gpa, copy);
        }
    }

    /// Use the issuer and the resource of a challenge. A new authorization server discards
    /// everything of the old one. When the same resource names a new authorization server, the
    /// client also deletes the stored record of the old one. A new resource discards the tokens,
    /// because a token is for one resource (RFC 8707).
    fn selectServer(self: *Client, issuer: []const u8, resource: []const u8) Allocator.Error!void {
        if (self.issuer == null or !std.mem.eql(u8, self.issuer.?, issuer)) {
            if (self.resource) |r| if (std.mem.eql(u8, r, resource)) self.deleteStored();
            self.clearCredentials();
            try common.replaceOwned(self.gpa, &self.issuer, issuer);
            self.storage_loaded = false;
        }
        if (self.resource == null or !std.mem.eql(u8, self.resource.?, resource)) {
            self.clearTokens();
            try common.replaceOwned(self.gpa, &self.resource, resource);
            self.storage_loaded = false;
        }
    }

    // -- Refresh ---------------------------------------------------------------------------------

    const RefreshOutcome = enum {
        refreshed,
        /// The server refused the refresh token. The client discarded the tokens.
        grant_refused,
        /// The server refused the client. The client discarded the registration and the tokens.
        client_refused,
    };

    /// Get a new access token with the refresh token (RFC 6749 section 6). The request has the
    /// `resource` and the granted scope, never a wider scope. It has the client authentication
    /// of the code exchange and a DPoP proof when `dpop` is set. The caller holds the lock.
    fn refresh(self: *Client, arena: Allocator) Error!RefreshOutcome {
        const reg = self.registration orelse return error.TokenRequestFailed;
        const refresh_token = self.refresh_token orelse return error.TokenRequestFailed;
        const resource = self.resource orelse return error.TokenRequestFailed;
        const endpoint = self.token_endpoint orelse return error.TokenRequestFailed;
        var body: Io.Writer.Allocating = .init(arena);
        const bw = &body.writer;
        try formField(bw, "grant_type", "refresh_token", true);
        try formField(bw, "refresh_token", refresh_token, false);
        try formField(bw, "resource", resource, false);
        if (self.granted_scopes.items.len > 0) try formField(bw, "scope", try std.mem.join(arena, " ", self.granted_scopes.items), false);
        var extra: std.ArrayList(http.Header) = .empty;
        try clientAuthentication(arena, reg, bw, &extra);
        const result = try self.fetcher.tokenRequest(arena, endpoint, body.written(), extra.items, self.options.dpop);
        std.crypto.secureZero(u8, body.written());
        switch (result) {
            .ok => |reply| {
                try self.keepTokens(reply, null, true);
                self.saveStored();
                return .refreshed;
            },
            .failed => |f| {
                try self.recordFailure(.refresh, f.status, f.code, f.description);
                const code = f.code orelse return error.TokenRequestFailed;
                if (std.mem.eql(u8, code, "invalid_client")) {
                    self.deleteStored();
                    self.clearCredentials();
                    return .client_refused;
                }
                const refused = [_][]const u8{ "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope" };
                if (listContains(&refused, code)) {
                    // The record keeps the registration without the refused tokens.
                    self.clearTokens();
                    self.saveStored();
                    return .grant_refused;
                }
                return error.TokenRequestFailed;
            },
        }
    }

    // -- Registration --------------------------------------------------------------------------

    fn chooseAuthMethod(supported: []const []const u8, has_secret: bool) AuthMethod {
        const list: []const []const u8 = if (supported.len == 0) &.{"client_secret_basic"} else supported;
        if (has_secret and listContains(list, "client_secret_basic")) return .client_secret_basic;
        if (has_secret and listContains(list, "client_secret_post")) return .client_secret_post;
        if (listContains(list, "none")) return .none;
        if (has_secret) return .client_secret_basic;
        return .none;
    }

    /// The pre-registered credentials for `issuer`. An entry with the issuer wins. Else the
    /// first entry without an issuer, which the client binds to the first issuer it sees.
    fn credentialsFor(self: *Client, list: []const Credentials, issuer: []const u8) Error!Credentials {
        for (list) |c| if (c.issuer) |i| if (std.mem.eql(u8, i, issuer)) return c;
        for (list) |c| if (c.issuer == null) {
            if (self.bound_issuer) |bound| {
                if (std.mem.eql(u8, bound, issuer)) return c;
                break;
            }
            self.bound_issuer = try self.gpa.dupe(u8, issuer);
            return c;
        };
        log.warn("no pre-registered credentials for the authorization server {f}", .{std.json.fmt(issuer, .{})});
        return error.IssuerNotRegistered;
    }

    fn register(self: *Client, arena: Allocator, meta: common.ServerMetadata) Error!void {
        switch (self.options.registration) {
            .pre_registered => |list| {
                const p = try self.credentialsFor(list, meta.issuer);
                const client_id = try self.gpa.dupe(u8, p.client_id);
                errdefer self.gpa.free(client_id);
                self.registration = .{
                    .client_id = client_id,
                    .client_secret = if (p.client_secret) |s| try self.gpa.dupe(u8, s) else null,
                    .auth_method = chooseAuthMethod(meta.token_endpoint_auth_methods_supported, p.client_secret != null),
                };
                return;
            },
            .client_metadata_url => |url| {
                if (!common.validClientIdUrl(url)) return error.InvalidClientMetadataUrl;
                if (meta.client_id_metadata_document_supported) {
                    self.registration = .{ .client_id = try self.gpa.dupe(u8, url), .client_secret = null, .auth_method = .none };
                    return;
                }
            },
            .dynamic => {},
        }
        const endpoint = meta.registration_endpoint orelse return error.RegistrationUnavailable;
        try common.requireHttps(self.options.allow_http, endpoint);
        // Ask for a public client unless only secret methods are offered.
        const wanted = chooseAuthMethod(meta.token_endpoint_auth_methods_supported, !listContains(meta.token_endpoint_auth_methods_supported, "none"));
        var body: Io.Writer.Allocating = .init(arena);
        const dpop_bound = self.options.dpop != null and self.options.dpop_bound_access_tokens;
        body.writer.print(
            "{{\"client_name\":{f},\"redirect_uris\":[{f}],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"token_endpoint_auth_method\":\"{s}\",\"application_type\":\"{s}\"{s}}}",
            .{ std.json.fmt(self.options.client_name, .{}), std.json.fmt(self.options.redirect_uri, .{}), @tagName(wanted), @tagName(self.options.application_type), if (dpop_bound) ",\"dpop_bound_access_tokens\":true" else "" },
        ) catch return error.OutOfMemory;
        const reply = self.fetcher.fetch(arena, .POST, endpoint, body.written(), "application/json", &.{}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try self.recordFailure(.registration, 0, null, null);
                return error.RegistrationFailed;
            },
        };
        const tree: ?std.json.Value = json.parseTree(arena, reply.body) catch null;
        if (reply.status != 201 and reply.status != 200) {
            // RFC 7591 section 3.2.2: the error response has `error` and `error_description`.
            const doc = tree orelse .null;
            try self.recordFailure(.registration, reply.status, json.getString(doc, "error"), json.getString(doc, "error_description"));
            return error.RegistrationFailed;
        }
        const client_id = json.getString(tree orelse .null, "client_id") orelse {
            try self.recordFailure(.registration, reply.status, null, "The registration response has no client_id");
            return error.RegistrationFailed;
        };
        const secret = json.getString(tree.?, "client_secret");
        var method = wanted;
        if (json.getString(tree.?, "token_endpoint_auth_method")) |m| {
            if (std.mem.eql(u8, m, "client_secret_basic")) method = .client_secret_basic;
            if (std.mem.eql(u8, m, "client_secret_post")) method = .client_secret_post;
            if (std.mem.eql(u8, m, "none")) method = .none;
        }
        if (secret == null) method = .none;
        const owned_id = try self.gpa.dupe(u8, client_id);
        errdefer self.gpa.free(owned_id);
        self.registration = .{
            .client_id = owned_id,
            .client_secret = if (secret) |s| try self.gpa.dupe(u8, s) else null,
            .auth_method = method,
        };
    }

    // -- Authorization ---------------------------------------------------------------------------

    /// Returns the redirect URL that carries the authorization response.
    fn obtainRedirect(self: *Client, arena: Allocator, authorization_url: []const u8) Error![]const u8 {
        switch (self.options.authorize) {
            .headless_redirect => {
                const reply = self.fetcher.fetch(arena, .GET, authorization_url, null, null, &.{}) catch return error.AuthorizationFailed;
                if (reply.status < 300 or reply.status >= 400) return error.AuthorizationFailed;
                return reply.location orelse error.AuthorizationFailed;
            },
            .callback => |cb| return cb.open(cb.userdata, arena, authorization_url) catch return error.AuthorizationFailed,
        }
    }
};

test "auth method choice" {
    try std.testing.expectEqual(Client.AuthMethod.client_secret_basic, Client.chooseAuthMethod(&.{"client_secret_basic"}, true));
    try std.testing.expectEqual(Client.AuthMethod.none, Client.chooseAuthMethod(&.{"none"}, false));
    try std.testing.expectEqual(Client.AuthMethod.client_secret_post, Client.chooseAuthMethod(&.{ "none", "client_secret_post" }, true));
}

test "pre-registered credentials are keyed by issuer" {
    var client: Client = .init(std.testing.io, std.testing.allocator, .{});
    defer client.deinit();
    const list = [_]Client.Credentials{
        .{ .issuer = "https://as1.example", .client_id = "one" },
        .{ .issuer = "https://as2.example", .client_id = "two" },
    };
    try std.testing.expectEqualStrings("one", (try client.credentialsFor(&list, "https://as1.example")).client_id);
    try std.testing.expectEqualStrings("two", (try client.credentialsFor(&list, "https://as2.example")).client_id);
    try std.testing.expectError(error.IssuerNotRegistered, client.credentialsFor(&list, "https://as3.example"));
    // The comparison is a simple string comparison.
    try std.testing.expectError(error.IssuerNotRegistered, client.credentialsFor(&list, "https://AS1.example"));

    // An entry without an issuer binds to the first issuer and refuses all others.
    const unbound = [_]Client.Credentials{.{ .client_id = "any" }};
    try std.testing.expectEqualStrings("any", (try client.credentialsFor(&unbound, "https://as1.example")).client_id);
    try std.testing.expectEqualStrings("any", (try client.credentialsFor(&unbound, "https://as1.example")).client_id);
    try std.testing.expectError(error.IssuerNotRegistered, client.credentialsFor(&unbound, "https://as2.example"));
}

test "registration refuses an insecure endpoint and an invalid metadata document URL" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const meta: common.ServerMetadata = .{ .issuer = "https://as.example", .token_endpoint = "https://as.example/token", .registration_endpoint = "http://as.example/register" };
    var client: Client = .init(std.testing.io, std.testing.allocator, .{});
    defer client.deinit();
    try std.testing.expectError(error.InsecureEndpoint, client.register(arena, meta));
    try std.testing.expect(client.registration == null);

    for ([_][]const u8{ "http://client.example/meta.json", "https://client.example", "https://client.example/" }) |url| {
        var cimd: Client = .init(std.testing.io, std.testing.allocator, .{ .registration = .{ .client_metadata_url = url } });
        defer cimd.deinit();
        var supported = meta;
        supported.client_id_metadata_document_supported = true;
        try std.testing.expectError(error.InvalidClientMetadataUrl, cimd.register(arena, supported));
    }
}
