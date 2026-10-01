//! The OAuth 2.1 client side of MCP authorization. It discovers the protected resource and
//! authorization server metadata, registers the client, runs the authorization code flow with
//! PKCE and requests tokens. The HTTP client transport calls it for 401 and 403 challenges.
//!
//! The client keeps credentials per issuer and never uses them for another authorization server.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const json = @import("../json.zig");
const common = @import("common.zig");
const dpop = @import("dpop.zig");

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
    registration: ?Registered = null,
    token: ?[]u8 = null,
    /// The token is DPoP-bound: requests carry it with the DPoP scheme and a proof.
    token_dpop: bool = false,
    /// Scopes granted with the current token (space separated list kept as a slice list).
    granted_scopes: std.ArrayList([]u8) = .empty,
    /// The issuer of the first authorization server that used pre-registered credentials
    /// without an issuer.
    bound_issuer: ?[]u8 = null,
    /// The last error that an authorization server sent.
    failure: ?Failure = null,
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
        max_step_up_attempts: u8 = 3,
        /// Accept `http` metadata, registration, authorization and token endpoints. Tests
        /// only, production needs https.
        allow_http: bool = false,
        max_document_bytes: usize = 1 << 20,
        /// Request DPoP-bound tokens with this key (RFC 9449). The token request and each
        /// request to the MCP server carry a proof. Null requests bearer tokens.
        dpop: ?*dpop.Prover = null,
        /// Send `dpop_bound_access_tokens` in dynamic client registration: the authorization
        /// server must then refuse token requests without a proof. It needs `dpop`.
        dpop_bound_access_tokens: bool = false,
    };

    const Registered = struct {
        client_id: []u8,
        client_secret: ?[]u8,
        auth_method: AuthMethod,
    };

    pub const AuthMethod = enum { client_secret_basic, client_secret_post, none };

    /// An error that an authorization server sent for a registration or a token request.
    pub const Failure = struct {
        step: Step,
        /// The HTTP status, or 0 when the request did not complete.
        status: u16,
        /// The `error` code of the response, for example `invalid_redirect_uri`.
        code: ?[]const u8 = null,
        /// The `error_description` of the response. It is text from the server.
        description: ?[]const u8 = null,

        pub const Step = enum { registration, token };
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
        return .{ .io = io, .gpa = gpa, .fetcher = .init(io, gpa, options.max_document_bytes, options.allow_http), .options = options };
    }

    pub fn deinit(self: *Client) void {
        self.fetcher.deinit();
        self.clearCredentials();
        if (self.issuer) |i| self.gpa.free(i);
        if (self.bound_issuer) |i| self.gpa.free(i);
        self.clearFailure();
        self.granted_scopes.deinit(self.gpa);
    }

    fn clearCredentials(self: *Client) void {
        if (self.registration) |r| {
            self.gpa.free(r.client_id);
            if (r.client_secret) |s| {
                std.crypto.secureZero(u8, s);
                self.gpa.free(s);
            }
            self.registration = null;
        }
        if (self.token) |t| {
            std.crypto.secureZero(u8, t);
            self.gpa.free(t);
            self.token = null;
        }
        self.token_dpop = false;
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
        const t = self.token orelse return null;
        return arena.dupe(u8, t) catch null;
    }

    fn providerChallenge(ptr: *anyopaque, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        _ = try self.handleChallenge(arena, server_url, status, www_authenticate, attempt);
    }

    // -- Challenge handling -------------------------------------------------------------------

    pub const Challenge = common.Challenge;

    /// Parse a `WWW-Authenticate` value. The parser knows only the `Bearer` scheme.
    pub const parseChallenge = common.parseChallenge;

    /// Obtain a token for `server_url` after a challenge. `attempt` starts at 1 for the first
    /// challenge of a request. Returns the bearer token, owned by the client.
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
        if (self.issuer == null or !std.mem.eql(u8, self.issuer.?, issuer)) {
            // A new authorization server: nothing from the old one may be reused.
            self.clearCredentials();
            if (self.issuer) |i| self.gpa.free(i);
            self.issuer = null;
            self.issuer = try self.gpa.dupe(u8, issuer);
        }
        const meta = try self.fetcher.authorizationServer(arena, issuer);
        if (!std.mem.eql(u8, meta.issuer, issuer)) return error.IssuerMismatch;
        const authorization_endpoint = meta.authorization_endpoint orelse return error.NoAuthorizationServerMetadata;
        try common.requireHttps(self.options.allow_http, authorization_endpoint);
        try common.requireHttps(self.options.allow_http, meta.token_endpoint);
        if (!listContains(meta.code_challenge_methods_supported, "S256")) return error.PkceUnsupported;
        try meta.checkDpop(self.options.dpop);

        // Registration.
        if (self.registration == null) try self.register(arena, meta);
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
        if (reg.auth_method != .client_secret_basic) try formField(bw, "client_id", reg.client_id, false);
        if (reg.auth_method == .client_secret_post) try formField(bw, "client_secret", reg.client_secret orelse "", false);
        var extra: std.ArrayList(http.Header) = .empty;
        if (reg.auth_method == .client_secret_basic) {
            const pair = try std.mem.concat(arena, u8, &.{ reg.client_id, ":", reg.client_secret orelse "" });
            const enc = std.base64.standard.Encoder;
            const out = try arena.alloc(u8, enc.calcSize(pair.len));
            _ = enc.encode(out, pair);
            try extra.append(arena, .{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Basic ", out }) });
        }
        const reply = switch (try self.fetcher.tokenRequest(arena, meta.token_endpoint, body.written(), extra.items, self.options.dpop)) {
            .ok => |r| r,
            .failed => |f| {
                try self.recordFailure(.token, f.status, f.code, f.description);
                return error.TokenRequestFailed;
            },
        };

        // Store.
        if (self.token) |t| {
            std.crypto.secureZero(u8, t);
            self.gpa.free(t);
        }
        self.token = null;
        self.token = try self.gpa.dupe(u8, reply.access_token);
        // RFC 9449 section 5: an authorization server without DPoP gives a bearer token.
        self.token_dpop = self.options.dpop != null and common.isDpopTokenType(reply.token_type);
        for (self.granted_scopes.items) |s| self.gpa.free(s);
        self.granted_scopes.clearRetainingCapacity();
        const granted = reply.scope orelse scope_text orelse "";
        var it = std.mem.tokenizeScalar(u8, granted, ' ');
        while (it.next()) |s| try self.granted_scopes.append(self.gpa, try self.gpa.dupe(u8, s));
        return self.token.?;
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
