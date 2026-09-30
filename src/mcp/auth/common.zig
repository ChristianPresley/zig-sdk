//! The parts that all OAuth client flows of the SDK share. This file has the provider interface
//! of the HTTP client transport and the HTTP requests. It also has the discovery of metadata,
//! the client authentication at a token endpoint, and the token responses.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const json = @import("../json.zig");
const jwt = @import("jwt.zig");

// -- Provider ------------------------------------------------------------------------------------

/// Gives bearer tokens to the HTTP client transport and answers `401` and `403` challenges.
/// `OAuthClient`, `ClientCredentials` and `EnterpriseClient` each supply one.
pub const Provider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The token for the next request, copied into `arena`, or null. A provider can get
        /// a new token here when the current one expires soon.
        token: *const fn (ptr: *anyopaque, arena: Allocator) ?[]const u8,
        /// Get a token after a challenge. `attempt` starts at 1 for the first challenge of a
        /// request.
        handle_challenge: *const fn (ptr: *anyopaque, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void,
    };

    pub fn token(self: Provider, arena: Allocator) ?[]const u8 {
        return self.vtable.token(self.ptr, arena);
    }

    pub fn handleChallenge(self: Provider, arena: Allocator, server_url: []const u8, status: u16, www_authenticate: ?[]const u8, attempt: u8) anyerror!void {
        return self.vtable.handle_challenge(self.ptr, arena, server_url, status, www_authenticate, attempt);
    }
};

/// A source of Unix seconds. Null uses the real clock of the `Io`.
pub const Clock = ?*const fn () i64;

pub fn now(io: Io, clock: Clock) i64 {
    if (clock) |f| return f();
    return Io.Clock.Timestamp.now(io, .real).raw.toSeconds();
}

// -- Challenges ----------------------------------------------------------------------------------

pub const Challenge = struct {
    scheme_is_bearer: bool = false,
    resource_metadata: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    err: ?[]const u8 = null,

    /// True for a `403` or an `insufficient_scope` error: the client needs more scopes.
    pub fn isStepUp(self: Challenge, status: u16) bool {
        return status == 403 or (self.err != null and std.mem.eql(u8, self.err.?, "insufficient_scope"));
    }
};

/// Parse a `WWW-Authenticate` value. The parser knows only the `Bearer` scheme.
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

/// The scope of a token request, or null for none. `configured` wins. Else the challenge
/// scope, else the `scopes_supported` of the resource. A step-up keeps the scopes in `held`.
pub fn selectScope(arena: Allocator, configured: ?[]const u8, challenge: Challenge, resource_scopes: []const []const u8, held: []const []const u8, step_up: bool) Allocator.Error!?[]const u8 {
    var scopes: std.ArrayList([]const u8) = .empty;
    if (configured) |list| {
        var it = std.mem.tokenizeScalar(u8, list, ' ');
        while (it.next()) |s| try appendUnique(arena, &scopes, s);
    }
    if (step_up) for (held) |s| try appendUnique(arena, &scopes, s);
    if (challenge.scope) |list| {
        var it = std.mem.tokenizeScalar(u8, list, ' ');
        while (it.next()) |s| try appendUnique(arena, &scopes, s);
    } else if (!step_up and configured == null) {
        for (resource_scopes) |s| try appendUnique(arena, &scopes, s);
    }
    if (scopes.items.len == 0) return null;
    return try std.mem.join(arena, " ", scopes.items);
}

// -- HTTP and discovery --------------------------------------------------------------------------

pub const DiscoveryError = error{
    OutOfMemory,
    /// The client found no protected resource metadata.
    NoResourceMetadata,
    NoAuthorizationServerMetadata,
    /// A metadata URL does not use https, and the fetcher does not accept `http`.
    InsecureEndpoint,
};

pub const ResourceMetadata = struct {
    resource: []const u8,
    authorization_servers: []const []const u8,
    scopes_supported: []const []const u8 = &.{},
};

/// Authorization server metadata (RFC 8414). A document without `issuer` or `token_endpoint`
/// does not count.
pub const ServerMetadata = struct {
    issuer: []const u8,
    authorization_endpoint: ?[]const u8 = null,
    token_endpoint: []const u8,
    registration_endpoint: ?[]const u8 = null,
    scopes_supported: []const []const u8 = &.{},
    code_challenge_methods_supported: []const []const u8 = &.{},
    token_endpoint_auth_methods_supported: []const []const u8 = &.{},
    token_endpoint_auth_signing_alg_values_supported: []const []const u8 = &.{},
    grant_types_supported: []const []const u8 = &.{},
    /// The grant profiles of draft-ietf-oauth-identity-assertion-authz-grant section 7.2.
    authorization_grant_profiles_supported: []const []const u8 = &.{},
    authorization_response_iss_parameter_supported: ?bool = null,
    client_id_metadata_document_supported: bool = false,
};

/// A token response (RFC 6749 section 5.1, RFC 8693 section 2.2).
pub const TokenResponse = struct {
    access_token: []const u8,
    token_type: ?[]const u8 = null,
    expires_in: ?i64 = null,
    scope: ?[]const u8 = null,
    refresh_token: ?[]const u8 = null,
    issued_token_type: ?[]const u8 = null,
    /// The whole response object.
    raw: Value,
};

/// A token error response (RFC 6749 section 5.2) or another failure of the request.
pub const TokenFailure = struct {
    /// The HTTP status, or 0 when the request did not complete.
    status: u16,
    /// The `error` code of the response, for example `invalid_grant`.
    code: ?[]const u8 = null,
    description: ?[]const u8 = null,
};

pub const TokenResult = union(enum) {
    ok: TokenResponse,
    failed: TokenFailure,
};

pub const Fetcher = struct {
    http_client: http.Client,
    max_document_bytes: usize,
    /// Accept `http` metadata URLs. Tests only, production needs https.
    allow_http: bool,

    pub fn init(io: Io, gpa: Allocator, max_document_bytes: usize, allow_http: bool) Fetcher {
        return .{ .http_client = .{ .allocator = gpa, .io = io }, .max_document_bytes = max_document_bytes, .allow_http = allow_http };
    }

    pub fn deinit(self: *Fetcher) void {
        self.http_client.deinit();
    }

    pub const Reply = struct { status: u16, body: []u8, location: ?[]const u8 };

    pub fn fetch(self: *Fetcher, arena: Allocator, method: http.Method, url: []const u8, body: ?[]const u8, content_type: ?[]const u8, extra: []const http.Header) !Reply {
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
        const text = try reader.allocRemaining(arena, .limited(self.max_document_bytes));
        return .{ .status = status, .body = text, .location = location };
    }

    /// Protected resource metadata (RFC 9728): the URL of the challenge, else the
    /// path-inserted well-known location, else the root. Without `allow_http`, each URL must
    /// use https.
    pub fn resourceMetadata(self: *Fetcher, arena: Allocator, server_url: []const u8, hinted: ?[]const u8) DiscoveryError!ResourceMetadata {
        try requireHttps(self.allow_http, server_url);
        if (hinted) |h| try requireHttps(self.allow_http, h);
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

    /// RFC 8414 with the MCP discovery order for issuers with and without a path. Without
    /// `allow_http`, the issuer must use https.
    pub fn authorizationServer(self: *Fetcher, arena: Allocator, issuer: []const u8) DiscoveryError!ServerMetadata {
        try requireHttps(self.allow_http, issuer);
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
                .authorization_endpoint = json.getString(tree, "authorization_endpoint"),
                .token_endpoint = json.getString(tree, "token_endpoint") orelse continue,
                .registration_endpoint = json.getString(tree, "registration_endpoint"),
                .scopes_supported = try stringList(arena, tree, "scopes_supported"),
                .code_challenge_methods_supported = try stringList(arena, tree, "code_challenge_methods_supported"),
                .token_endpoint_auth_methods_supported = try stringList(arena, tree, "token_endpoint_auth_methods_supported"),
                .token_endpoint_auth_signing_alg_values_supported = try stringList(arena, tree, "token_endpoint_auth_signing_alg_values_supported"),
                .grant_types_supported = try stringList(arena, tree, "grant_types_supported"),
                .authorization_grant_profiles_supported = try stringList(arena, tree, "authorization_grant_profiles_supported"),
                .authorization_response_iss_parameter_supported = boolField(tree, "authorization_response_iss_parameter_supported"),
                .client_id_metadata_document_supported = boolField(tree, "client_id_metadata_document_supported") orelse false,
            };
        }
        return error.NoAuthorizationServerMetadata;
    }

    /// POST a form to a token endpoint and parse the answer.
    pub fn tokenRequest(self: *Fetcher, arena: Allocator, token_endpoint: []const u8, form: []const u8, extra: []const http.Header) Allocator.Error!TokenResult {
        const reply = self.fetch(arena, .POST, token_endpoint, form, "application/x-www-form-urlencoded", extra) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .failed = .{ .status = 0 } },
        };
        const tree = json.parseTree(arena, reply.body) catch return .{ .failed = .{ .status = reply.status } };
        if (tree != .object) return .{ .failed = .{ .status = reply.status } };
        if (reply.status != 200) return .{ .failed = .{
            .status = reply.status,
            .code = json.getString(tree, "error"),
            .description = json.getString(tree, "error_description"),
        } };
        const access_token = json.getString(tree, "access_token") orelse return .{ .failed = .{ .status = reply.status } };
        return .{ .ok = .{
            .access_token = access_token,
            .token_type = json.getString(tree, "token_type"),
            .expires_in = if (tree.object.get("expires_in")) |v| switch (v) {
                .integer => |i| i,
                .float => |f| @intFromFloat(f),
                else => null,
            } else null,
            .scope = json.getString(tree, "scope"),
            .refresh_token = json.getString(tree, "refresh_token"),
            .issued_token_type = json.getString(tree, "issued_token_type"),
            .raw = tree,
        } };
    }
};

// -- Client authentication -----------------------------------------------------------------------

pub const SecretMethod = enum { client_secret_basic, client_secret_post };

/// How a client authenticates at a token endpoint.
pub const ClientAuth = union(enum) {
    /// A public client. The `client_id` goes into the request body.
    none: struct { client_id: []const u8 },
    /// A client secret (OAuth 2.1 section 2.4.1). A null `method` takes `client_secret_basic`
    /// when the server lists it or lists no methods, else `client_secret_post`.
    client_secret: struct {
        client_id: []const u8,
        client_secret: []const u8,
        method: ?SecretMethod = null,
    },
    /// A signed JWT assertion, `private_key_jwt` (RFC 7523 section 2.2). The `iss` and `sub`
    /// claims are the client id. The `aud` claim is `audience`, else the issuer identifier of the
    /// authorization server.
    private_key_jwt: struct {
        client_id: []const u8,
        key: *const jwt.SigningKey,
        kid: ?[]const u8 = null,
        audience: ?[]const u8 = null,
        lifetime_seconds: i64 = 300,
    },

    pub fn clientId(self: ClientAuth) []const u8 {
        return switch (self) {
            inline else => |v| v.client_id,
        };
    }

    pub const ApplyError = error{
        OutOfMemory,
        /// The server lists token endpoint authentication methods, and the method of the client
        /// is not one of them.
        AuthMethodUnsupported,
        /// The server lists signing algorithms, and the algorithm of the key is not one of them.
        SigningAlgorithmUnsupported,
        SigningFailed,
        EntropyUnavailable,
    };

    /// What the token endpoint offers. Empty lists mean that the server did not say.
    pub const Endpoint = struct {
        issuer: []const u8,
        auth_methods_supported: []const []const u8 = &.{},
        signing_algs_supported: []const []const u8 = &.{},
    };

    /// Add the client authentication to a token request: fields to `form`, headers to `headers`.
    pub fn apply(self: ClientAuth, io: Io, arena: Allocator, time: i64, endpoint: Endpoint, form: *Io.Writer, headers: *std.ArrayList(http.Header)) ApplyError!void {
        const methods = endpoint.auth_methods_supported;
        switch (self) {
            .none => |c| try formField(form, "client_id", c.client_id, false),
            .client_secret => |c| {
                const method: SecretMethod = c.method orelse if (methods.len == 0 or listContains(methods, "client_secret_basic"))
                    .client_secret_basic
                else if (listContains(methods, "client_secret_post"))
                    .client_secret_post
                else
                    return error.AuthMethodUnsupported;
                if (methods.len > 0 and !listContains(methods, @tagName(method))) return error.AuthMethodUnsupported;
                switch (method) {
                    .client_secret_post => {
                        try formField(form, "client_id", c.client_id, false);
                        try formField(form, "client_secret", c.client_secret, false);
                    },
                    .client_secret_basic => try headers.append(arena, .{ .name = "authorization", .value = try basicCredentials(arena, c.client_id, c.client_secret) }),
                }
            },
            .private_key_jwt => |c| {
                if (methods.len > 0 and !listContains(methods, "private_key_jwt")) return error.AuthMethodUnsupported;
                const alg = @tagName(c.key.algorithm());
                if (endpoint.signing_algs_supported.len > 0 and !listContains(endpoint.signing_algs_supported, alg)) return error.SigningAlgorithmUnsupported;
                const assertion = try clientAssertion(io, arena, c.key, c.kid, c.client_id, c.audience orelse endpoint.issuer, time, c.lifetime_seconds);
                try formField(form, "client_assertion_type", client_assertion_type_jwt, false);
                try formField(form, "client_assertion", assertion, false);
            },
        }
    }
};

/// The `client_assertion_type` of a JWT client assertion (RFC 7523 section 2.2).
pub const client_assertion_type_jwt = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Make a client assertion: `iss` and `sub` are the client id, and `jti` is random.
pub fn clientAssertion(io: Io, arena: Allocator, key: *const jwt.SigningKey, kid: ?[]const u8, client_id: []const u8, audience: []const u8, time: i64, lifetime_seconds: i64) ClientAuth.ApplyError![]u8 {
    var jti_bytes: [16]u8 = undefined;
    io.randomSecure(&jti_bytes) catch return error.EntropyUnavailable;
    const jti = try base64Url(arena, &jti_bytes);
    const payload = std.fmt.allocPrint(arena, "{{\"iss\":{f},\"sub\":{f},\"aud\":{f},\"iat\":{d},\"exp\":{d},\"jti\":\"{s}\"}}", .{
        std.json.fmt(client_id, .{}),
        std.json.fmt(client_id, .{}),
        std.json.fmt(audience, .{}),
        time,
        time + lifetime_seconds,
        jti,
    }) catch return error.OutOfMemory;
    return jwt.sign(arena, key, payload, .{ .kid = kid }) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.SigningFailed => error.SigningFailed,
    };
}

/// The `Authorization` value of `client_secret_basic`: both parts form-encoded (RFC 6749
/// section 2.3.1), joined with a colon, in base64.
pub fn basicCredentials(arena: Allocator, client_id: []const u8, client_secret: []const u8) Allocator.Error![]const u8 {
    var pair: Io.Writer.Allocating = .init(arena);
    formEncode(&pair.writer, client_id) catch return error.OutOfMemory;
    pair.writer.writeByte(':') catch return error.OutOfMemory;
    formEncode(&pair.writer, client_secret) catch return error.OutOfMemory;
    const enc = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(pair.written().len));
    _ = enc.encode(out, pair.written());
    return std.mem.concat(arena, u8, &.{ "Basic ", out });
}

// -- Helpers -------------------------------------------------------------------------------------

/// True when the metadata `resource` is the server URL or a parent of it. Metadata at the
/// root well-known location names the origin (RFC 9728 section 3). The comparison ignores the
/// case of the scheme and the host.
pub fn resourceCoversServer(resource: []const u8, server_url: []const u8) bool {
    const r = splitUri(resource) orelse return std.mem.eql(u8, resource, server_url);
    const s = splitUri(server_url) orelse return false;
    if (!r.sameOrigin(s)) return false;
    if (std.mem.eql(u8, r.rest, s.rest)) return true;
    const base = std.mem.trimEnd(u8, r.rest, "/");
    if (!std.mem.startsWith(u8, s.rest, base)) return false;
    const rest = s.rest[base.len..];
    return rest.len == 0 or rest[0] == '/' or rest[0] == '?';
}

/// The parts of an absolute URI with an authority. The parts are slices of the URI.
pub const UriSplit = struct {
    scheme: []const u8,
    /// The user information with its `@`, or empty.
    userinfo: []const u8,
    /// The host and the port.
    host_port: []const u8,
    /// The path, the query and the fragment.
    rest: []const u8,

    /// True when the scheme and the host are equal without regard to case, and the user
    /// information and the port are equal.
    pub fn sameOrigin(a: UriSplit, b: UriSplit) bool {
        return std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and std.mem.eql(u8, a.userinfo, b.userinfo) and std.ascii.eqlIgnoreCase(a.host_port, b.host_port);
    }

    /// The host without the port and without the brackets of an IPv6 address.
    pub fn host(self: UriSplit) []const u8 {
        const hp = self.host_port;
        if (hp.len > 0 and hp[0] == '[') {
            const close = std.mem.indexOfScalar(u8, hp, ']') orelse return hp;
            return hp[1..close];
        }
        const colon = std.mem.lastIndexOfScalar(u8, hp, ':') orelse return hp;
        return hp[0..colon];
    }
};

/// Split `scheme://authority/rest`. Returns null for a text without `://`.
pub fn splitUri(uri: []const u8) ?UriSplit {
    const sep = std.mem.indexOf(u8, uri, "://") orelse return null;
    if (sep == 0) return null;
    const after = sep + 3;
    const end = std.mem.indexOfAnyPos(u8, uri, after, "/?#") orelse uri.len;
    const authority = uri[after..end];
    const at = std.mem.lastIndexOfScalar(u8, authority, '@');
    return .{
        .scheme = uri[0..sep],
        .userinfo = if (at) |i| authority[0 .. i + 1] else "",
        .host_port = if (at) |i| authority[i + 1 ..] else authority,
        .rest = uri[end..],
    };
}

/// Compare two URIs with the rules for the canonical server URI of MCP. The scheme and the
/// host can have a different case (RFC 3986 section 6.2.2.1). All other parts must be equal.
/// A text without `://` must be equal byte for byte.
pub fn uriEql(a: []const u8, b: []const u8) bool {
    const x = splitUri(a) orelse return std.mem.eql(u8, a, b);
    const y = splitUri(b) orelse return std.mem.eql(u8, a, b);
    return x.sameOrigin(y) and std.mem.eql(u8, x.rest, y.rest);
}

/// Return `error.InsecureEndpoint` for a URL without https, unless `allow_http` is set.
pub fn requireHttps(allow_http: bool, url: []const u8) error{InsecureEndpoint}!void {
    if (allow_http) return;
    const parts = splitUri(url) orelse return error.InsecureEndpoint;
    if (!std.ascii.eqlIgnoreCase(parts.scheme, "https")) return error.InsecureEndpoint;
}

/// True for a redirect URI with https, or with `http` and a loopback host. A loopback host is
/// `localhost`, an address in `127.0.0.0/8` or `[::1]`.
pub fn validRedirectUri(uri: []const u8) bool {
    const parts = splitUri(uri) orelse return false;
    if (parts.userinfo.len > 0 or parts.host().len == 0) return false;
    if (std.mem.indexOfScalar(u8, parts.rest, '#') != null) return false;
    if (std.ascii.eqlIgnoreCase(parts.scheme, "https")) return true;
    if (!std.ascii.eqlIgnoreCase(parts.scheme, "http")) return false;
    const h = parts.host();
    if (std.ascii.eqlIgnoreCase(h, "localhost") or std.mem.eql(u8, h, "::1")) return true;
    const ip = Io.net.Ip4Address.parse(h, 0) catch return false;
    return ip.bytes[0] == 127;
}

/// True for a URL that can be a client ID metadata document URL. The URL must have https, a
/// host and a path other than `/`. It must not have a `.` or `..` segment, user information or
/// a fragment.
pub fn validClientIdUrl(url: []const u8) bool {
    const parts = splitUri(url) orelse return false;
    if (!std.ascii.eqlIgnoreCase(parts.scheme, "https")) return false;
    if (parts.userinfo.len > 0 or parts.host().len == 0) return false;
    if (std.mem.indexOfScalar(u8, parts.rest, '#') != null) return false;
    const path = parts.rest[0 .. std.mem.indexOfScalar(u8, parts.rest, '?') orelse parts.rest.len];
    if (path.len <= 1) return false;
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |segment| {
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    }
    return true;
}

pub const UrlParts = struct { origin: []const u8, path: []const u8 };

/// Split a URL into `scheme://host[:port]` and its path without query or trailing slash.
pub fn splitUrl(arena: Allocator, url: []const u8) error{OutOfMemory}!UrlParts {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return .{ .origin = url, .path = "" };
    const after = scheme_end + 3;
    const path_start = std.mem.indexOfScalarPos(u8, url, after, '/') orelse url.len;
    const origin = url[0..path_start];
    var path = url[path_start..];
    if (std.mem.indexOfAny(u8, path, "?#")) |q| path = path[0..q];
    path = std.mem.trimEnd(u8, path, "/");
    return .{ .origin = try arena.dupe(u8, origin), .path = try arena.dupe(u8, path) };
}

pub fn stringList(arena: Allocator, tree: Value, key: []const u8) Allocator.Error![]const []const u8 {
    if (tree != .object) return &.{};
    const v = tree.object.get(key) orelse return &.{};
    if (v != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (v.array.items) |item| if (item == .string) try out.append(arena, item.string);
    return out.items;
}

pub fn boolField(tree: Value, key: []const u8) ?bool {
    if (tree != .object) return null;
    const v = tree.object.get(key) orelse return null;
    return if (v == .bool) v.bool else null;
}

pub fn listContains(list: []const []const u8, item: []const u8) bool {
    for (list) |s| if (std.mem.eql(u8, s, item)) return true;
    return false;
}

pub fn appendUnique(arena: Allocator, list: *std.ArrayList([]const u8), item: []const u8) Allocator.Error!void {
    if (listContains(list.items, item)) return;
    try list.append(arena, item);
}

pub fn base64Url(arena: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(bytes.len));
    _ = enc.encode(out, bytes);
    return out;
}

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

fn formEncode(w: *Io.Writer, value: []const u8) Io.Writer.Error!void {
    for (value) |c| {
        if (isUnreserved(c)) {
            try w.writeByte(c);
        } else {
            try w.print("%{X:0>2}", .{c});
        }
    }
}

/// Write `key=value` with form encoding, preceded by `&` unless it is the first field.
pub fn formField(w: *Io.Writer, key: []const u8, value: []const u8, first: bool) error{OutOfMemory}!void {
    if (!first) w.writeByte('&') catch return error.OutOfMemory;
    w.writeAll(key) catch return error.OutOfMemory;
    w.writeByte('=') catch return error.OutOfMemory;
    formEncode(w, value) catch return error.OutOfMemory;
}

/// Parse the query string of a URL into a map of decoded keys and values.
pub fn parseQuery(arena: Allocator, url: []const u8) Allocator.Error!std.StringHashMapUnmanaged([]const u8) {
    const q = std.mem.indexOfScalar(u8, url, '?') orelse return .empty;
    return parseForm(arena, url[q + 1 ..]);
}

/// Parse an `application/x-www-form-urlencoded` text into a map of decoded keys and values.
pub fn parseForm(arena: Allocator, text: []const u8) Allocator.Error!std.StringHashMapUnmanaged([]const u8) {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    var query = text;
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

/// Replace an owned string: erase and free the old value, then store a copy of the new one.
pub fn replaceOwned(gpa: Allocator, slot: *?[]u8, value: ?[]const u8) Allocator.Error!void {
    const copy: ?[]u8 = if (value) |v| try gpa.dupe(u8, v) else null;
    if (slot.*) |old| {
        std.crypto.secureZero(u8, old);
        gpa.free(old);
    }
    slot.* = copy;
}

test "challenge parsing" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const c = try parseChallenge(arena, "Bearer error=\"insufficient_scope\", scope=\"mcp:write mcp:read\", resource_metadata=\"https://s.example/.well-known/oauth-protected-resource/mcp\"");
    try std.testing.expect(c.scheme_is_bearer);
    try std.testing.expect(c.isStepUp(401));
    try std.testing.expectEqualStrings("insufficient_scope", c.err.?);
    try std.testing.expectEqualStrings("mcp:write mcp:read", c.scope.?);
    try std.testing.expectEqualStrings("https://s.example/.well-known/oauth-protected-resource/mcp", c.resource_metadata.?);
    const basic = try parseChallenge(arena, "Basic realm=x");
    try std.testing.expect(!basic.scheme_is_bearer);
}

test "resource coverage" {
    try std.testing.expect(resourceCoversServer("http://h:1/mcp", "http://h:1/mcp"));
    try std.testing.expect(resourceCoversServer("http://h:1", "http://h:1/mcp"));
    try std.testing.expect(resourceCoversServer("http://h:1/", "http://h:1/mcp"));
    try std.testing.expect(!resourceCoversServer("http://h:1/mc", "http://h:1/mcp"));
    try std.testing.expect(!resourceCoversServer("https://evil.example.com/mcp", "http://h:1/mcp"));
    try std.testing.expect(!resourceCoversServer("http://h:1/mcp/x", "http://h:1/mcp"));
    // Uppercase scheme and host are accepted. The path keeps its case.
    try std.testing.expect(resourceCoversServer("HTTPS://MCP.Example.com/mcp", "https://mcp.example.com/mcp"));
    try std.testing.expect(resourceCoversServer("https://MCP.example.com", "HTTPS://mcp.EXAMPLE.com/mcp"));
    try std.testing.expect(!resourceCoversServer("https://mcp.example.com/MCP", "https://mcp.example.com/mcp"));
    try std.testing.expect(!resourceCoversServer("https://u@mcp.example.com/mcp", "https://mcp.example.com/mcp"));
}

test "canonical URI comparison" {
    try std.testing.expect(uriEql("https://mcp.example.com/mcp", "HTTPS://MCP.EXAMPLE.COM/mcp"));
    try std.testing.expect(uriEql("https://mcp.example.com:8443", "https://Mcp.Example.Com:8443"));
    try std.testing.expect(!uriEql("https://mcp.example.com/mcp", "https://mcp.example.com/MCP"));
    try std.testing.expect(!uriEql("https://mcp.example.com/mcp", "https://mcp.example.com/mcp/"));
    try std.testing.expect(!uriEql("https://mcp.example.com:8443", "https://mcp.example.com:8444"));
    try std.testing.expect(uriEql("urn:example:api", "urn:example:api"));
    try std.testing.expect(!uriEql("urn:example:api", "URN:example:api"));
}

test "redirect URI, client ID URL and https checks" {
    try std.testing.expect(validRedirectUri("http://127.0.0.1:41893/callback"));
    try std.testing.expect(validRedirectUri("http://localhost:3000/callback"));
    try std.testing.expect(validRedirectUri("http://LOCALHOST/cb"));
    try std.testing.expect(validRedirectUri("http://[::1]:8080/cb"));
    try std.testing.expect(validRedirectUri("http://127.8.9.10/cb"));
    try std.testing.expect(validRedirectUri("https://app.example.com/callback"));
    try std.testing.expect(!validRedirectUri("http://app.example.com/callback"));
    try std.testing.expect(!validRedirectUri("http://localhost.example.com/cb"));
    try std.testing.expect(!validRedirectUri("http://128.0.0.1/cb"));
    try std.testing.expect(!validRedirectUri("com.example.app:/callback"));
    try std.testing.expect(!validRedirectUri("https://app.example.com/cb#x"));
    try std.testing.expect(!validRedirectUri("https:///cb"));

    try std.testing.expect(validClientIdUrl("https://example.com/client.json"));
    try std.testing.expect(validClientIdUrl("HTTPS://example.com/a/b?v=1"));
    try std.testing.expect(!validClientIdUrl("http://example.com/client.json"));
    try std.testing.expect(!validClientIdUrl("https://example.com"));
    try std.testing.expect(!validClientIdUrl("https://example.com/"));
    try std.testing.expect(!validClientIdUrl("https://example.com/a/../client.json"));
    try std.testing.expect(!validClientIdUrl("https://example.com/./client.json"));
    try std.testing.expect(!validClientIdUrl("https://user@example.com/client.json"));
    try std.testing.expect(!validClientIdUrl("https://example.com/client.json#top"));
    try std.testing.expect(!validClientIdUrl("client.json"));

    try requireHttps(false, "https://as.example.com");
    try requireHttps(false, "HTTPS://as.example.com");
    try requireHttps(true, "http://127.0.0.1:9");
    try std.testing.expectError(error.InsecureEndpoint, requireHttps(false, "http://as.example.com"));
    try std.testing.expectError(error.InsecureEndpoint, requireHttps(false, "as.example.com"));
}

test "url and form helpers" {
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
    try std.testing.expectEqualStrings("Basic YSUzQWI6cyUyMDE=", try basicCredentials(arena, "a:b", "s 1"));
}

test "scope selection" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const none: Challenge = .{};
    try std.testing.expectEqualStrings("a b", (try selectScope(arena, null, none, &.{ "a", "b" }, &.{}, false)).?);
    try std.testing.expectEqualStrings("x", (try selectScope(arena, "x", none, &.{ "a", "b" }, &.{}, false)).?);
    try std.testing.expect((try selectScope(arena, null, none, &.{}, &.{}, false)) == null);
    const up: Challenge = .{ .scope = "w" };
    try std.testing.expectEqualStrings("r w", (try selectScope(arena, null, up, &.{"a"}, &.{"r"}, true)).?);
}

test "client authentication" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var form: Io.Writer.Allocating = .init(arena);
    var headers: std.ArrayList(http.Header) = .empty;
    const secret: ClientAuth = .{ .client_secret = .{ .client_id = "c", .client_secret = "s" } };
    try secret.apply(io, arena, 1000, .{ .issuer = "https://as", .auth_methods_supported = &.{ "client_secret_post", "private_key_jwt" } }, &form.writer, &headers);
    try std.testing.expectEqualStrings("&client_id=c&client_secret=s", form.written());
    try std.testing.expectEqual(0, headers.items.len);
    try secret.apply(io, arena, 1000, .{ .issuer = "https://as" }, &form.writer, &headers);
    try std.testing.expectEqualStrings("authorization", headers.items[0].name);
    try std.testing.expectError(error.AuthMethodUnsupported, secret.apply(io, arena, 1000, .{ .issuer = "https://as", .auth_methods_supported = &.{"private_key_jwt"} }, &form.writer, &headers));

    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const key: jwt.SigningKey = .{ .es256 = try Ecdsa.KeyPair.generateDeterministic([_]u8{3} ** 32) };
    const signed: ClientAuth = .{ .private_key_jwt = .{ .client_id = "c", .key = &key, .kid = "k" } };
    try std.testing.expectError(error.SigningAlgorithmUnsupported, signed.apply(io, arena, 1000, .{ .issuer = "https://as", .signing_algs_supported = &.{"RS256"} }, &form.writer, &headers));
    var jwt_form: Io.Writer.Allocating = .init(arena);
    try signed.apply(io, arena, 1000, .{ .issuer = "https://as", .auth_methods_supported = &.{"private_key_jwt"}, .signing_algs_supported = &.{"ES256"} }, &jwt_form.writer, &headers);
    const fields = try parseForm(arena, jwt_form.written());
    try std.testing.expectEqualStrings(client_assertion_type_jwt, fields.get("client_assertion_type").?);
    var buf: [97]u8 = undefined;
    const keys = [_]jwt.Key{key.verificationKey(&buf, "k")};
    const claims = try jwt.verify(arena, fields.get("client_assertion").?, .{ .keys = &keys, .issuer = "c", .audience = "https://as" }, 1000);
    try std.testing.expectEqualStrings("c", claims.subject.?);
    try std.testing.expectEqual(1300, claims.expires_at.?);
    try std.testing.expect(claims.jwt_id != null);
    try std.testing.expect(fields.get("client_id") == null);
}
