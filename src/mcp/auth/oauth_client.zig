//! The OAuth 2.1 client side of MCP authorization. It discovers the protected resource and
//! authorization server metadata, registers the client, runs the authorization code flow with
//! PKCE and requests tokens. The HTTP client transport calls it for 401 and 403 challenges.
//!
//! Credentials are kept per issuer and never reused for another authorization server.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const json = @import("../json.zig");

pub const Client = struct {
    io: Io,
    gpa: Allocator,
    http_client: http.Client,
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

    /// How the authorization code is obtained.
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
        /// No protected resource metadata was found.
        NoResourceMetadata,
        /// The metadata `resource` is not the server URL.
        ResourceMismatch,
        NoAuthorizationServer,
        NoAuthorizationServerMetadata,
        /// The metadata `issuer` is not the URL that was queried.
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
        return .{ .io = io, .gpa = gpa, .http_client = .{ .allocator = gpa, .io = io }, .options = options };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
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

    // -- Challenge handling -------------------------------------------------------------------

    pub const Challenge = struct {
        scheme_is_bearer: bool = false,
        resource_metadata: ?[]const u8 = null,
        scope: ?[]const u8 = null,
        err: ?[]const u8 = null,
    };

    /// Parse a `WWW-Authenticate` value. Only the `Bearer` scheme is understood.
    pub fn parseChallenge(arena: Allocator, header: []const u8) Allocator.Error!Challenge {
        var c: Challenge = .{};
        var rest = std.mem.trim(u8, header, " \t");
        if (rest.len < 6 or !std.ascii.eqlIgnoreCase(rest[0..6], "Bearer")) return c;
        c.scheme_is_bearer = true;
        rest = rest[6..];
        while (true) {
            rest = std.mem.trimStart(u8, rest, " \t,");
            if (rest.len == 0) break;
            const eq = std.mem.indexOfScalar(u8, rest, '=') orelse break;
            const key = std.mem.trim(u8, rest[0..eq], " \t");
            rest = rest[eq + 1 ..];
            var value: []const u8 = undefined;
            if (rest.len > 0 and rest[0] == '"') {
                const end = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse rest.len;
                value = rest[1..end];
                rest = if (end < rest.len) rest[end + 1 ..] else "";
            } else {
                const end = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
                value = std.mem.trim(u8, rest[0..end], " \t");
                rest = rest[end..];
            }
            const owned = try arena.dupe(u8, value);
            if (std.ascii.eqlIgnoreCase(key, "resource_metadata")) c.resource_metadata = owned;
            if (std.ascii.eqlIgnoreCase(key, "scope")) c.scope = owned;
            if (std.ascii.eqlIgnoreCase(key, "error")) c.err = owned;
        }
        return c;
    }

    /// Obtain a token for `server_url` after a challenge. `attempt` starts at 1 for the first
    /// challenge of a request. Returns the bearer token, owned by the client.
    pub fn handleChallenge(self: *Client, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) Error![]const u8 {
        if (attempt > self.options.max_step_up_attempts) return error.TooManyAttempts;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const challenge: Challenge = if (www_authenticate) |h| try parseChallenge(arena, h) else .{};
        const step_up = status == 403 or (challenge.err != null and std.mem.eql(u8, challenge.err.?, "insufficient_scope"));

        // Discovery.
        const prm = try self.discoverResourceMetadata(arena, server_url, challenge.resource_metadata);
        if (!resourceCoversServer(prm.resource, server_url)) return error.ResourceMismatch;
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
        const meta = try self.discoverAuthorizationServer(arena, issuer);
        if (!std.mem.eql(u8, meta.issuer, issuer)) return error.IssuerMismatch;
        if (!self.options.allow_http) {
            if (!std.mem.startsWith(u8, meta.authorization_endpoint, "https://") or !std.mem.startsWith(u8, meta.token_endpoint, "https://")) return error.InsecureEndpoint;
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
        w.writeAll(meta.authorization_endpoint) catch return error.OutOfMemory;
        w.writeAll(if (std.mem.indexOfScalar(u8, meta.authorization_endpoint, '?') == null) "?" else "&") catch return error.OutOfMemory;
        try formField(w, "response_type", "code", true);
        try formField(w, "client_id", reg.client_id, false);
        try formField(w, "redirect_uri", self.options.redirect_uri, false);
        try formField(w, "state", state, false);
        try formField(w, "code_challenge", code_challenge, false);
        try formField(w, "code_challenge_method", "S256", false);
        try formField(w, "resource", resource, false);
        if (scope_text) |s| try formField(w, "scope", s, false);
        const redirect = try self.obtainRedirect(arena, url.written());
        const params = try parseQuery(arena, redirect);
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
        const reply = self.fetch(arena, .POST, meta.token_endpoint, body.written(), "application/x-www-form-urlencoded", extra.items) catch return error.TokenRequestFailed;
        if (reply.status != 200) return error.TokenRequestFailed;
        const tree = json.parseTree(arena, reply.body) catch return error.TokenRequestFailed;
        const access_token = json.getString(tree, "access_token") orelse return error.TokenRequestFailed;

        // Store.
        if (self.token) |t| {
            std.crypto.secureZero(u8, t);
            self.gpa.free(t);
        }
        self.token = try self.gpa.dupe(u8, access_token);
        for (self.granted_scopes.items) |s| self.gpa.free(s);
        self.granted_scopes.clearRetainingCapacity();
        const granted = json.getString(tree, "scope") orelse scope_text orelse "";
        var it = std.mem.tokenizeScalar(u8, granted, ' ');
        while (it.next()) |s| try self.granted_scopes.append(self.gpa, try self.gpa.dupe(u8, s));
        return self.token.?;
    }

    // -- Discovery -----------------------------------------------------------------------------

    const ResourceMetadata = struct {
        resource: []const u8,
        authorization_servers: []const []const u8,
        scopes_supported: []const []const u8 = &.{},
    };

    fn discoverResourceMetadata(self: *Client, arena: Allocator, server_url: []const u8, hinted: ?[]const u8) Error!ResourceMetadata {
        var candidates: std.ArrayList([]const u8) = .empty;
        if (hinted) |h| try candidates.append(arena, h);
        const parts = try splitUrl(arena, server_url);
        if (parts.path.len > 0) try candidates.append(arena, try std.mem.concat(arena, u8, &.{ parts.origin, "/.well-known/oauth-protected-resource", parts.path }));
        try candidates.append(arena, try std.mem.concat(arena, u8, &.{ parts.origin, "/.well-known/oauth-protected-resource" }));
        for (candidates.items) |url| {
            const reply = self.fetch(arena, .GET, url, null, null, &.{}) catch continue;
            if (reply.status != 200) continue;
            const tree = json.parseTree(arena, reply.body) catch continue;
            const resource = json.getString(tree, "resource") orelse continue;
            return .{
                .resource = resource,
                .authorization_servers = try stringList(arena, tree, "authorization_servers"),
                .scopes_supported = try stringList(arena, tree, "scopes_supported"),
            };
        }
        return error.NoResourceMetadata;
    }

    const ServerMetadata = struct {
        issuer: []const u8,
        authorization_endpoint: []const u8,
        token_endpoint: []const u8,
        registration_endpoint: ?[]const u8 = null,
        scopes_supported: []const []const u8 = &.{},
        code_challenge_methods_supported: []const []const u8 = &.{},
        token_endpoint_auth_methods_supported: []const []const u8 = &.{},
        authorization_response_iss_parameter_supported: ?bool = null,
        client_id_metadata_document_supported: bool = false,
    };

    /// RFC 8414 with the MCP discovery order for issuers with and without a path.
    fn discoverAuthorizationServer(self: *Client, arena: Allocator, issuer: []const u8) Error!ServerMetadata {
        const parts = try splitUrl(arena, issuer);
        var candidates: std.ArrayList([]const u8) = .empty;
        if (parts.path.len > 0) {
            try candidates.append(arena, try std.mem.concat(arena, u8, &.{ parts.origin, "/.well-known/oauth-authorization-server", parts.path }));
            try candidates.append(arena, try std.mem.concat(arena, u8, &.{ parts.origin, "/.well-known/openid-configuration", parts.path }));
            try candidates.append(arena, try std.mem.concat(arena, u8, &.{ parts.origin, parts.path, "/.well-known/openid-configuration" }));
        } else {
            try candidates.append(arena, try std.mem.concat(arena, u8, &.{ parts.origin, "/.well-known/oauth-authorization-server" }));
            try candidates.append(arena, try std.mem.concat(arena, u8, &.{ parts.origin, "/.well-known/openid-configuration" }));
        }
        for (candidates.items) |url| {
            const reply = self.fetch(arena, .GET, url, null, null, &.{}) catch continue;
            if (reply.status != 200) continue;
            const tree = json.parseTree(arena, reply.body) catch continue;
            return .{
                .issuer = json.getString(tree, "issuer") orelse continue,
                .authorization_endpoint = json.getString(tree, "authorization_endpoint") orelse continue,
                .token_endpoint = json.getString(tree, "token_endpoint") orelse continue,
                .registration_endpoint = json.getString(tree, "registration_endpoint"),
                .scopes_supported = try stringList(arena, tree, "scopes_supported"),
                .code_challenge_methods_supported = try stringList(arena, tree, "code_challenge_methods_supported"),
                .token_endpoint_auth_methods_supported = try stringList(arena, tree, "token_endpoint_auth_methods_supported"),
                .authorization_response_iss_parameter_supported = boolField(tree, "authorization_response_iss_parameter_supported"),
                .client_id_metadata_document_supported = boolField(tree, "client_id_metadata_document_supported") orelse false,
            };
        }
        return error.NoAuthorizationServerMetadata;
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

    fn register(self: *Client, arena: Allocator, meta: ServerMetadata) Error!void {
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
        const reply = self.fetch(arena, .POST, endpoint, body.written(), "application/json", &.{}) catch return error.RegistrationFailed;
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
                const reply = self.fetch(arena, .GET, authorization_url, null, null, &.{}) catch return error.AuthorizationFailed;
                if (reply.status < 300 or reply.status >= 400) return error.AuthorizationFailed;
                return reply.location orelse error.AuthorizationFailed;
            },
            .callback => |cb| return cb.open(cb.userdata, arena, authorization_url) catch return error.AuthorizationFailed,
        }
    }

    // -- HTTP ------------------------------------------------------------------------------------

    const Reply = struct { status: u16, body: []u8, location: ?[]const u8 };

    fn fetch(self: *Client, arena: Allocator, method: http.Method, url: []const u8, body: ?[]const u8, content_type: ?[]const u8, extra: []const http.Header) !Reply {
        const uri = try std.Uri.parse(url);
        var req = try self.http_client.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .extra_headers = extra,
            .headers = .{
                .content_type = if (content_type) |ct| .{ .override = ct } else .default,
                .accept_encoding = .{ .override = "identity" },
            },
        });
        defer req.deinit();
        if (body) |b| {
            try req.sendBodyComplete(try arena.dupe(u8, b));
        } else {
            try req.sendBodiless();
        }
        var redirect_buf: [2048]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);
        const status: u16 = @intFromEnum(response.head.status);
        const location: ?[]const u8 = if (response.head.location) |l| try arena.dupe(u8, l) else null;
        var transfer: [4096]u8 = undefined;
        const reader = response.reader(&transfer);
        const text = try reader.allocRemaining(arena, .limited(self.options.max_document_bytes));
        return .{ .status = status, .body = text, .location = location };
    }
};

// -- Helpers -----------------------------------------------------------------------------------

/// True when the metadata `resource` is the server URL or a parent of it. Metadata at the
/// root well-known location names the origin (RFC 9728 section 3).
fn resourceCoversServer(resource: []const u8, server_url: []const u8) bool {
    if (std.mem.eql(u8, resource, server_url)) return true;
    const base = std.mem.trimEnd(u8, resource, "/");
    if (base.len == 0 or !std.mem.startsWith(u8, server_url, base)) return false;
    const rest = server_url[base.len..];
    return rest.len == 0 or rest[0] == '/' or rest[0] == '?';
}

const UrlParts = struct { origin: []const u8, path: []const u8 };

/// Split a URL into `scheme://host[:port]` and its path without query or trailing slash.
fn splitUrl(arena: Allocator, url: []const u8) error{OutOfMemory}!UrlParts {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return .{ .origin = url, .path = "" };
    const after = scheme_end + 3;
    const path_start = std.mem.indexOfScalarPos(u8, url, after, '/') orelse url.len;
    const origin = url[0..path_start];
    var path = url[path_start..];
    if (std.mem.indexOfAny(u8, path, "?#")) |q| path = path[0..q];
    path = std.mem.trimEnd(u8, path, "/");
    return .{ .origin = try arena.dupe(u8, origin), .path = try arena.dupe(u8, path) };
}

fn stringList(arena: Allocator, tree: Value, key: []const u8) Allocator.Error![]const []const u8 {
    if (tree != .object) return &.{};
    const v = tree.object.get(key) orelse return &.{};
    if (v != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (v.array.items) |item| if (item == .string) try out.append(arena, item.string);
    return out.items;
}

fn boolField(tree: Value, key: []const u8) ?bool {
    if (tree != .object) return null;
    const v = tree.object.get(key) orelse return null;
    return if (v == .bool) v.bool else null;
}

fn listContains(list: []const []const u8, item: []const u8) bool {
    for (list) |s| if (std.mem.eql(u8, s, item)) return true;
    return false;
}

fn appendUnique(arena: Allocator, list: *std.ArrayList([]const u8), item: []const u8) Allocator.Error!void {
    if (listContains(list.items, item)) return;
    try list.append(arena, item);
}

fn base64Url(arena: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(bytes.len));
    _ = enc.encode(out, bytes);
    return out;
}

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

/// Write `key=value` with form encoding, preceded by `&` unless it is the first field.
fn formField(w: *Io.Writer, key: []const u8, value: []const u8, first: bool) error{OutOfMemory}!void {
    if (!first) w.writeByte('&') catch return error.OutOfMemory;
    w.writeAll(key) catch return error.OutOfMemory;
    w.writeByte('=') catch return error.OutOfMemory;
    for (value) |c| {
        if (isUnreserved(c)) {
            w.writeByte(c) catch return error.OutOfMemory;
        } else {
            w.print("%{X:0>2}", .{c}) catch return error.OutOfMemory;
        }
    }
}

/// Parse the query string of a URL into a map of decoded keys and values.
fn parseQuery(arena: Allocator, url: []const u8) Allocator.Error!std.StringHashMapUnmanaged([]const u8) {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    const q = std.mem.indexOfScalar(u8, url, '?') orelse return map;
    var query = url[q + 1 ..];
    if (std.mem.indexOfScalar(u8, query, '#')) |h| query = query[0..h];
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const key = try decodeComponent(arena, pair[0..eq]);
        const value = try decodeComponent(arena, if (eq < pair.len) pair[eq + 1 ..] else "");
        try map.put(arena, key, value);
    }
    return map;
}

fn decodeComponent(arena: Allocator, text: []const u8) Allocator.Error![]const u8 {
    const buf = try arena.dupe(u8, text);
    for (buf) |*c| if (c.* == '+') {
        c.* = ' ';
    };
    return std.Uri.percentDecodeInPlace(buf);
}

test "challenge parsing" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const c = try Client.parseChallenge(arena, "Bearer error=\"insufficient_scope\", scope=\"mcp:write mcp:read\", resource_metadata=\"https://s.example/.well-known/oauth-protected-resource/mcp\"");
    try std.testing.expect(c.scheme_is_bearer);
    try std.testing.expectEqualStrings("insufficient_scope", c.err.?);
    try std.testing.expectEqualStrings("mcp:write mcp:read", c.scope.?);
    try std.testing.expectEqualStrings("https://s.example/.well-known/oauth-protected-resource/mcp", c.resource_metadata.?);
    const basic = try Client.parseChallenge(arena, "Basic realm=x");
    try std.testing.expect(!basic.scheme_is_bearer);
}

test "resource coverage" {
    try std.testing.expect(resourceCoversServer("http://h:1/mcp", "http://h:1/mcp"));
    try std.testing.expect(resourceCoversServer("http://h:1", "http://h:1/mcp"));
    try std.testing.expect(resourceCoversServer("http://h:1/", "http://h:1/mcp"));
    try std.testing.expect(!resourceCoversServer("http://h:1/mc", "http://h:1/mcp"));
    try std.testing.expect(!resourceCoversServer("https://evil.example.com/mcp", "http://h:1/mcp"));
    try std.testing.expect(!resourceCoversServer("http://h:1/mcp/x", "http://h:1/mcp"));
}

test "url helpers" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const p = try splitUrl(arena, "https://host.example:8443/tenant/mcp?x=1");
    try std.testing.expectEqualStrings("https://host.example:8443", p.origin);
    try std.testing.expectEqualStrings("/tenant/mcp", p.path);
    const root = try splitUrl(arena, "http://localhost:3000");
    try std.testing.expectEqualStrings("", root.path);
    var q = try parseQuery(arena, "http://127.0.0.1/cb?code=abc%20d&state=s1&iss=http%3A%2F%2Fas");
    try std.testing.expectEqualStrings("abc d", q.get("code").?);
    try std.testing.expectEqualStrings("http://as", q.get("iss").?);
    var aw: Io.Writer.Allocating = .init(arena);
    try formField(&aw.writer, "scope", "mcp:read mcp:write", true);
    try formField(&aw.writer, "resource", "http://x/mcp", false);
    try std.testing.expectEqualStrings("scope=mcp%3Aread%20mcp%3Awrite&resource=http%3A%2F%2Fx%2Fmcp", aw.written());
    try std.testing.expectEqual(Client.AuthMethod.client_secret_basic, Client.chooseAuthMethod(&.{"client_secret_basic"}, true));
    try std.testing.expectEqual(Client.AuthMethod.none, Client.chooseAuthMethod(&.{"none"}, false));
    try std.testing.expectEqual(Client.AuthMethod.client_secret_post, Client.chooseAuthMethod(&.{ "none", "client_secret_post" }, true));
}
