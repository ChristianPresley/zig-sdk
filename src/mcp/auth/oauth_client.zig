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
    /// Scopes granted with the current token (space separated list kept as a slice list).
    granted_scopes: std.ArrayList([]u8) = .empty,
    lock: Io.Mutex = .init,

    pub const Registration = union(enum) {
        /// Credentials issued out of band.
        pre_registered: struct { client_id: []const u8, client_secret: ?[]const u8 = null },
        /// A client ID metadata document URL (used when the server supports it, else DCR).
        client_metadata_url: []const u8,
        /// Dynamic client registration only.
        dynamic,
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
        redirect_uri: []const u8 = "http://127.0.0.1:41893/callback",
        authorize: Authorize = .headless_redirect,
        /// Ask for `offline_access` when the authorization server lists it.
        want_refresh_token: bool = true,
        max_step_up_attempts: u8 = 3,
        /// Accept `http` authorization server endpoints. Tests only, production needs https.
        allow_http: bool = false,
        max_document_bytes: usize = 1 << 20,
    };

    const Registered = struct {
        client_id: []u8,
        client_secret: ?[]u8,
        auth_method: AuthMethod,
    };

    pub const AuthMethod = enum { client_secret_basic, client_secret_post, none };

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
        /// The authorization server does not offer PKCE with S256.
        PkceUnsupported,
        /// No way to obtain a client id.
        RegistrationUnavailable,
        RegistrationFailed,
        AuthorizationFailed,
        StateMismatch,
        IssMissing,
        IssMismatch,
        TokenRequestFailed,
        HttpFailed,
        InvalidChallenge,
    };

    pub fn init(io: Io, gpa: Allocator, options: Options) Client {
        return .{ .io = io, .gpa = gpa, .fetcher = .init(io, gpa, options.max_document_bytes), .options = options };
    }

    pub fn deinit(self: *Client) void {
        self.fetcher.deinit();
        self.clearCredentials();
        if (self.issuer) |i| self.gpa.free(i);
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
        for (self.granted_scopes.items) |s| self.gpa.free(s);
        self.granted_scopes.clearRetainingCapacity();
    }

    /// The bearer token to send, if any. The slice is valid until the next challenge.
    pub fn currentToken(self: *Client) ?[]const u8 {
        return self.token;
    }

    /// The interface for the `auth_provider` option of the HTTP client transport.
    pub fn provider(self: *Client) common.Provider {
        return .{ .ptr = self, .vtable = &provider_vtable };
    }

    const provider_vtable: common.Provider.VTable = .{ .token = providerToken, .handle_challenge = providerChallenge };

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

    /// Parse a `WWW-Authenticate` value. Only the `Bearer` scheme is understood.
    pub const parseChallenge = common.parseChallenge;

    /// Obtain a token for `server_url` after a challenge. `attempt` starts at 1 for the first
    /// challenge of a request. Returns the bearer token, owned by the client.
    pub fn handleChallenge(self: *Client, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) Error![]const u8 {
        if (attempt > self.options.max_step_up_attempts) return error.TooManyAttempts;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const challenge: Challenge = if (www_authenticate) |h| try parseChallenge(arena, h) else .{};
        const step_up = challenge.isStepUp(status);

        // Discovery.
        const prm = try self.fetcher.resourceMetadata(arena, server_url, challenge.resource_metadata);
        if (!common.resourceCoversServer(prm.resource, server_url)) return error.ResourceMismatch;
        // RFC 8707: the resource indicator is the canonical identifier from the metadata.
        const resource = prm.resource;
        if (prm.authorization_servers.len == 0) return error.NoAuthorizationServer;
        const issuer = prm.authorization_servers[0];
        if (self.issuer == null or !std.mem.eql(u8, self.issuer.?, issuer)) {
            // A new authorization server: nothing from the old one may be reused.
            self.clearCredentials();
            if (self.issuer) |i| self.gpa.free(i);
            self.issuer = try self.gpa.dupe(u8, issuer);
        }
        const meta = try self.fetcher.authorizationServer(arena, issuer);
        if (!std.mem.eql(u8, meta.issuer, issuer)) return error.IssuerMismatch;
        const authorization_endpoint = meta.authorization_endpoint orelse return error.NoAuthorizationServerMetadata;
        if (!self.options.allow_http) {
            if (!std.mem.startsWith(u8, authorization_endpoint, "https://") or !std.mem.startsWith(u8, meta.token_endpoint, "https://")) return error.InsecureEndpoint;
        }
        if (!listContains(meta.code_challenge_methods_supported, "S256")) return error.PkceUnsupported;

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
        const reply = switch (try self.fetcher.tokenRequest(arena, meta.token_endpoint, body.written(), extra.items)) {
            .ok => |r| r,
            .failed => return error.TokenRequestFailed,
        };

        // Store.
        if (self.token) |t| {
            std.crypto.secureZero(u8, t);
            self.gpa.free(t);
        }
        self.token = try self.gpa.dupe(u8, reply.access_token);
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

    fn register(self: *Client, arena: Allocator, meta: common.ServerMetadata) Error!void {
        switch (self.options.registration) {
            .pre_registered => |p| {
                self.registration = .{
                    .client_id = try self.gpa.dupe(u8, p.client_id),
                    .client_secret = if (p.client_secret) |s| try self.gpa.dupe(u8, s) else null,
                    .auth_method = chooseAuthMethod(meta.token_endpoint_auth_methods_supported, p.client_secret != null),
                };
                return;
            },
            .client_metadata_url => |url| if (meta.client_id_metadata_document_supported) {
                self.registration = .{ .client_id = try self.gpa.dupe(u8, url), .client_secret = null, .auth_method = .none };
                return;
            },
            .dynamic => {},
        }
        const endpoint = meta.registration_endpoint orelse return error.RegistrationUnavailable;
        // Ask for a public client unless only secret methods are offered.
        const wanted = chooseAuthMethod(meta.token_endpoint_auth_methods_supported, !listContains(meta.token_endpoint_auth_methods_supported, "none"));
        var body: Io.Writer.Allocating = .init(arena);
        body.writer.print(
            "{{\"client_name\":{f},\"redirect_uris\":[{f}],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"token_endpoint_auth_method\":\"{s}\",\"application_type\":\"native\"}}",
            .{ std.json.fmt(self.options.client_name, .{}), std.json.fmt(self.options.redirect_uri, .{}), @tagName(wanted) },
        ) catch return error.OutOfMemory;
        const reply = self.fetcher.fetch(arena, .POST, endpoint, body.written(), "application/json", &.{}) catch return error.RegistrationFailed;
        if (reply.status != 201 and reply.status != 200) return error.RegistrationFailed;
        const tree = json.parseTree(arena, reply.body) catch return error.RegistrationFailed;
        const client_id = json.getString(tree, "client_id") orelse return error.RegistrationFailed;
        const secret = json.getString(tree, "client_secret");
        var method = wanted;
        if (json.getString(tree, "token_endpoint_auth_method")) |m| {
            if (std.mem.eql(u8, m, "client_secret_basic")) method = .client_secret_basic;
            if (std.mem.eql(u8, m, "client_secret_post")) method = .client_secret_post;
            if (std.mem.eql(u8, m, "none")) method = .none;
        }
        if (secret == null) method = .none;
        self.registration = .{
            .client_id = try self.gpa.dupe(u8, client_id),
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
