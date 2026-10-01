//! An authorization server next to an MCP server in one process. The MCP server accepts the
//! JWT access tokens of the authorization server, as bearer tokens and as DPoP-bound tokens. A
//! consent page asks the user to allow each client.
//!
//! The example serves plain HTTP on the loopback address and has no sign-in: each user is
//! `demo-user`. A real deployment uses HTTPS, signs the user in, and keeps the signing key.
//!
//! Usage: authorization_server [as-port] [mcp-port]
const std = @import("std");
const mcp = @import("mcp");
const as = mcp.auth.authorization_server;
const types = mcp.types;

/// The name of the cookie that binds the consent form to the browser.
const cookie_name = "demo_browser";

/// The consent page of the example.
const Consent = struct {
    io: std.Io,
    server: *mcp.auth.AuthorizationServer = undefined,

    fn authorizer(self: *Consent) as.Authorizer {
        return .{ .userdata = self, .decide = decide };
    }

    fn decide(userdata: ?*anyopaque, arena: std.mem.Allocator, request: *const as.AuthorizationRequest) anyerror!as.Decision {
        const self: *Consent = @ptrCast(@alignCast(userdata.?));
        if (request.http.method == .POST) {
            // The answer of the form: the consent token must be the token of this browser.
            const binding = cookieValue(request.http.header("cookie") orelse "", cookie_name) orelse return .deny;
            const token = request.param("consent_token") orelse return .deny;
            if (!self.server.checkConsentToken(binding, request, token)) return .deny;
            if (!std.mem.eql(u8, request.param("decision") orelse "", "allow")) return .deny;
            return .{ .approve = .{ .subject = "demo-user" } };
        }
        // A new random value in a cookie binds the form to this browser.
        var raw: [16]u8 = undefined;
        try self.io.randomSecure(&raw);
        const binding = try mcp.auth.common.base64Url(arena, &raw);
        var buf: [mcp.auth.AuthorizationServer.consent_token_len]u8 = undefined;
        const token = self.server.consentToken(&buf, binding, request);

        var page: std.Io.Writer.Allocating = .init(arena);
        const w = &page.writer;
        try w.writeAll("<!doctype html><title>Allow access</title><h1>Allow access?</h1><p>The client <b>");
        try as.htmlEscape(w, request.client_name orelse request.client_id);
        try w.writeAll("</b> wants access to <code>");
        try as.htmlEscape(w, request.resource);
        try w.writeAll("</code> with the scopes <code>");
        for (request.scopes) |s| {
            try as.htmlEscape(w, s);
            try w.writeByte(' ');
        }
        try w.writeAll("</code>. After your answer, the browser goes to <b>");
        try as.htmlEscape(w, request.redirect_host);
        try w.writeAll("</b>.</p><form method=\"post\">");
        try w.writeAll(try request.hiddenFields(arena));
        try w.print("<input type=\"hidden\" name=\"consent_token\" value=\"{s}\">", .{token});
        try w.writeAll("<button name=\"decision\" value=\"allow\">Allow</button> <button name=\"decision\" value=\"deny\">Deny</button></form>");
        const headers = try arena.alloc(std.http.Header, 4);
        headers[0] = .{ .name = "content-type", .value = "text/html; charset=utf-8" };
        headers[1] = .{ .name = "cache-control", .value = "no-store" };
        headers[2] = .{ .name = "set-cookie", .value = try std.fmt.allocPrint(arena, "{s}={s}; Path=/; HttpOnly; SameSite=Lax", .{ cookie_name, binding }) };
        // Another site cannot show the page in a frame.
        headers[3] = .{ .name = "content-security-policy", .value = "frame-ancestors 'none'" };
        return .{ .respond = .{ .status = .ok, .headers = headers, .body = page.written() } };
    }
};

/// The value of the cookie `name` in a `Cookie` header.
fn cookieValue(header: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeAny(u8, header, "; ");
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }
    return null;
}

/// Answers with the user of the access token.
fn whoami(ctx: *mcp.RequestContext, args: std.json.Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const p = ctx.principal() orelse return error.NoPrincipal;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "You are {s}.", .{p.subject orelse "unknown"}) };
}

fn serveAuthorizationServer(server: *mcp.auth.AuthorizationServer) void {
    server.serve() catch |e| std.log.err("the authorization server stopped: {t}", .{e});
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const as_port: u16 = if (args.len > 1) try std.fmt.parseInt(u16, args[1], 10) else 9000;
    const mcp_port: u16 = if (args.len > 2) try std.fmt.parseInt(u16, args[2], 10) else 3000;
    const issuer = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{as_port});
    const mcp_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/mcp", .{mcp_port});

    // The authorization server. The key is new at each start, so old tokens stop to work.
    var key = try as.generateSigningKey(io);
    defer key.deinit();
    const signing_keys = [_]as.SigningKey{.{ .key = &key, .kid = "example-1" }};
    const resources = [_]as.Resource{.{ .uri = mcp_url }};
    // A public client for local tools. Each loopback port matches its redirect URI.
    const clients = [_]as.ClientRegistration{.{
        .client_id = "example-client",
        .client_name = "Example client",
        .redirect_uris = &.{"http://127.0.0.1/callback"},
    }};
    var consent: Consent = .{ .io = io };
    var auth_server = try mcp.auth.AuthorizationServer.init(io, gpa, .{
        .issuer = issuer,
        .signing_keys = &signing_keys,
        .resources = &resources,
        .scopes_supported = &.{ "mcp:read", "mcp:write" },
        .default_scopes = &.{"mcp:read"},
        .authorizer = consent.authorizer(),
        .clients = &clients,
        // MCP deprecates dynamic registration. Local tools often still need it.
        .dynamic_registration = .{},
        // Plain HTTP with a loopback host, for this example only.
        .allow_http = true,
    });
    defer auth_server.deinit();
    consent.server = &auth_server;
    try auth_server.listen(.{ .port = as_port });
    var as_future = try io.concurrent(serveAuthorizationServer, .{&auth_server});
    defer {
        auth_server.shutdown();
        as_future.await(io);
    }

    // The MCP server verifies the tokens with the keys of the authorization server.
    var verifier: mcp.auth.JwtVerifier = .{
        .options = .{
            .keys = try auth_server.verificationKeys(arena),
            .issuer = issuer,
            .audience = mcp_url,
            .token_type = as.access_token_type,
        },
        .clock = .{ .io = io },
    };
    const authorization_servers = [_][]const u8{issuer};
    const dpop_policy: mcp.auth.DpopPolicy = .{ .io = io };
    const rs: mcp.auth.ResourceServer = .{
        .resource = mcp_url,
        .resource_metadata_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/.well-known/oauth-protected-resource/mcp", .{mcp_port}),
        .authorization_servers = &authorization_servers,
        .scopes_supported = &.{"mcp:read"},
        .required_scopes = &.{"mcp:read"},
        .verifier = verifier.verifier(),
        .dpop = &dpop_policy,
    };
    var server = try mcp.Server.init(gpa, io, .{
        .info = .{ .name = "authorization-example", .version = "0.1.0" },
        .authorization_extensions = .{ .dpop = true },
    });
    defer server.deinit();
    try server.addToolJson(.{ .name = "whoami", .description = "Tell the user of the access token." }, whoami);
    var transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = mcp_port, .auth = &rs });
    defer transport.deinit();
    try transport.bind();
    std.log.info("authorization server on {s}, MCP server on {s}", .{ issuer, mcp_url });
    try transport.serve();
}
