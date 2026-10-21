//! The fixture authorization server for the authorization server scenarios of the official
//! conformance suite. It approves each authorization request for one test user without
//! consent, so use it for tests only. It serves plain HTTP on the loopback address.
//!
//! `--dcr` adds dynamic client registration (RFC 7591) at `/register`. Without `--dcr`, the
//! server has no registration endpoint. `--dcr-token T` requires the bearer token `T` on each
//! registration request. The option is valid only with `--dcr`. This is a test fixture: do
//! not use it in production.
//!
//! Usage: mcp-conformance-authorization-server [--port N] [--client-id ID] [--resource URL]
//!        [--dcr [--dcr-token T]]
const std = @import("std");
const builtin = @import("builtin");
const mcp = @import("mcp");
const as = mcp.auth.authorization_server;

const usage = "usage: mcp-conformance-authorization-server [--port N] [--client-id ID] [--resource URL] [--dcr [--dcr-token T]]";

/// The settings from the command line.
const Config = struct {
    port: u16 = 3100,
    client_id: []const u8 = "conformance-client",
    resource: []const u8 = "http://127.0.0.1:3000/mcp",
    /// `--dcr`: offer dynamic client registration. The default offers none.
    dcr: bool = false,
    /// `--dcr-token T`: the initial access token of each registration request.
    dcr_token: ?[]const u8 = null,

    /// The dynamic registration of the server options, or null without `--dcr`. The library
    /// checks the metadata of each registration, also the redirect URIs.
    fn dynamicRegistration(self: Config) ?as.DynamicRegistration {
        if (!self.dcr) return null;
        return .{ .initial_access_token = self.dcr_token };
    }
};

/// Parse the command line. An unknown argument is an error.
fn parseArgs(args: []const []const u8) !Config {
    var config: Config = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const has_value = i + 1 < args.len;
        if (std.mem.eql(u8, args[i], "--port") and has_value) {
            i += 1;
            config.port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, args[i], "--client-id") and has_value) {
            i += 1;
            config.client_id = args[i];
        } else if (std.mem.eql(u8, args[i], "--resource") and has_value) {
            i += 1;
            config.resource = args[i];
        } else if (std.mem.eql(u8, args[i], "--dcr")) {
            config.dcr = true;
        } else if (std.mem.eql(u8, args[i], "--dcr-token") and has_value) {
            i += 1;
            if (args[i].len == 0) return error.InvalidArguments;
            config.dcr_token = args[i];
        } else {
            return error.InvalidArguments;
        }
    }
    if (config.dcr_token != null and !config.dcr) return error.DcrTokenNeedsDcr;
    return config;
}

/// The authorization server of the fixture and the data that its options point to.
const Fixture = struct {
    key: mcp.auth.jwt.SigningKey,
    signing_keys: [1]as.SigningKey,
    resources: [1]as.Resource,
    clients: [1]as.ClientRegistration,
    auto: as.AutoApprove,
    server: mcp.auth.AuthorizationServer,

    /// Make the server. The fixture must not move after this call.
    fn init(self: *Fixture, io: std.Io, gpa: std.mem.Allocator, config: Config, issuer: []const u8) !void {
        self.key = try as.generateSigningKey(io);
        errdefer self.key.deinit();
        self.signing_keys = .{.{ .key = &self.key, .kid = "conformance-1" }};
        self.resources = .{.{ .uri = config.resource }};
        // The suite sends the redirect URI http://127.0.0.1:<port>/callback. A loopback
        // redirect URI matches with each port.
        self.clients = .{.{
            .client_id = config.client_id,
            .client_name = "MCP conformance suite",
            .redirect_uris = &.{"http://127.0.0.1/callback"},
        }};
        self.auto = .{ .subject = "conformance-user" };
        self.server = try mcp.auth.AuthorizationServer.init(io, gpa, .{
            .issuer = issuer,
            .signing_keys = &self.signing_keys,
            .resources = &self.resources,
            .scopes_supported = &.{ "mcp:read", "mcp:write" },
            .authorizer = self.auto.authorizer(),
            .clients = &self.clients,
            .dynamic_registration = config.dynamicRegistration(),
            .allow_http = true,
        });
    }

    fn deinit(self: *Fixture) void {
        self.server.deinit();
        self.key.deinit();
    }
};

pub fn main(init: std.process.Init) !void {
    // In a release build without libc, `init.gpa` is the debug allocator of std, with one lock for
    // every allocation of every thread. The allocator of std for many threads has no such lock.
    const gpa = if (builtin.mode == .Debug) init.gpa else std.heap.smp_allocator;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const config = parseArgs(args) catch |e| {
        if (e == error.DcrTokenNeedsDcr) std.log.err("--dcr-token needs --dcr", .{});
        std.log.err(usage, .{});
        return e;
    };

    const issuer = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{config.port});
    var fixture: Fixture = undefined;
    try fixture.init(io, gpa, config, issuer);
    defer fixture.deinit();
    try fixture.server.listen(.{ .port = config.port });
    std.log.info("authorization server listening on {s}{s}", .{ issuer, if (config.dcr) " with dynamic client registration" else "" });
    try fixture.server.serve();
}

// -- Tests ------------------------------------------------------------------------------------

const testing = std.testing;
const test_issuer = "http://127.0.0.1:3100";
const public_client = "{\"client_name\":\"Tool\",\"redirect_uris\":[\"http://127.0.0.1/callback\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"token_endpoint_auth_method\":\"none\"}";

fn metadata(f: *Fixture, arena: std.mem.Allocator) !std.json.Value {
    const req: as.Request = .{ .method = .GET, .target = "/.well-known/oauth-authorization-server" };
    const res = (try f.server.handle(arena, &req)).?;
    try testing.expectEqual(std.http.Status.ok, res.status);
    return mcp.json.parseTree(arena, res.body);
}

fn register(f: *Fixture, arena: std.mem.Allocator, body: []const u8, token: ?[]const u8) !?as.Response {
    var headers: std.ArrayList(std.http.Header) = .empty;
    try headers.append(arena, .{ .name = "content-type", .value = "application/json" });
    if (token) |t| try headers.append(arena, .{ .name = "authorization", .value = try std.fmt.allocPrint(arena, "Bearer {s}", .{t}) });
    const req: as.Request = .{ .method = .POST, .target = "/register", .headers = headers.items, .body = body };
    return f.server.handle(arena, &req);
}

test "parseArgs: the defaults, --dcr, --dcr-token and the errors" {
    const defaults = try parseArgs(&.{"server"});
    try testing.expect(!defaults.dcr);
    try testing.expect(defaults.dynamicRegistration() == null);
    const dcr = try parseArgs(&.{ "server", "--dcr" });
    try testing.expect(dcr.dynamicRegistration().?.initial_access_token == null);
    const with_token = try parseArgs(&.{ "server", "--dcr-token", "secret", "--dcr" });
    try testing.expectEqualStrings("secret", with_token.dynamicRegistration().?.initial_access_token.?);
    try testing.expectError(error.DcrTokenNeedsDcr, parseArgs(&.{ "server", "--dcr-token", "secret" }));
    try testing.expectError(error.InvalidArguments, parseArgs(&.{ "server", "--dcr", "--dcr-token", "" }));
    try testing.expectError(error.InvalidArguments, parseArgs(&.{ "server", "--dcr-token" }));
    try testing.expectError(error.InvalidArguments, parseArgs(&.{ "server", "--unknown" }));
}

test "without --dcr: no registration_endpoint and no /register" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Fixture = undefined;
    try f.init(testing.io, testing.allocator, try parseArgs(&.{"server"}), test_issuer);
    defer f.deinit();
    try testing.expect((try metadata(&f, arena)).object.get("registration_endpoint") == null);
    try testing.expect((try register(&f, arena, public_client, null)) == null);
}

test "--dcr: the metadata names /register and a registration succeeds" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Fixture = undefined;
    try f.init(testing.io, testing.allocator, try parseArgs(&.{ "server", "--dcr" }), test_issuer);
    defer f.deinit();
    try testing.expectEqualStrings(test_issuer ++ "/register", (try metadata(&f, arena)).object.get("registration_endpoint").?.string);
    const created = (try register(&f, arena, public_client, null)).?;
    try testing.expectEqual(std.http.Status.created, created.status);
    const body = try mcp.json.parseTree(arena, created.body);
    try testing.expect(body.object.get("client_id").?.string.len > 0);
    // The library checks the redirect URIs: http needs a loopback host.
    const insecure = (try register(&f, arena, "{\"redirect_uris\":[\"http://app.example.com/cb\"],\"token_endpoint_auth_method\":\"none\"}", null)).?;
    try testing.expectEqual(std.http.Status.bad_request, insecure.status);
    try testing.expectEqualStrings("invalid_redirect_uri", (try mcp.json.parseTree(arena, insecure.body)).object.get("error").?.string);
}

test "--dcr-token: a registration without the token or with a wrong token gets 401" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: Fixture = undefined;
    try f.init(testing.io, testing.allocator, try parseArgs(&.{ "server", "--dcr", "--dcr-token", "initial-token" }), test_issuer);
    defer f.deinit();
    try testing.expectEqual(std.http.Status.unauthorized, (try register(&f, arena, public_client, null)).?.status);
    try testing.expectEqual(std.http.Status.unauthorized, (try register(&f, arena, public_client, "wrong")).?.status);
    try testing.expectEqual(std.http.Status.created, (try register(&f, arena, public_client, "initial-token")).?.status);
}
