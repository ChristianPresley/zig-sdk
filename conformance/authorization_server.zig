//! The fixture authorization server for the authorization server scenarios of the official
//! conformance suite. It approves each authorization request for one test user without
//! consent, so use it for tests only. It serves plain HTTP on the loopback address.
//!
//! Usage: mcp-conformance-authorization-server [--port N] [--client-id ID] [--resource URL]
const std = @import("std");
const mcp = @import("mcp");
const as = mcp.auth.authorization_server;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var port: u16 = 3100;
    var client_id: []const u8 = "conformance-client";
    var resource: []const u8 = "http://127.0.0.1:3000/mcp";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const has_value = i + 1 < args.len;
        if (std.mem.eql(u8, args[i], "--port") and has_value) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, args[i], "--client-id") and has_value) {
            i += 1;
            client_id = args[i];
        } else if (std.mem.eql(u8, args[i], "--resource") and has_value) {
            i += 1;
            resource = args[i];
        } else {
            std.log.err("usage: mcp-conformance-authorization-server [--port N] [--client-id ID] [--resource URL]", .{});
            return error.InvalidArguments;
        }
    }

    var key = try as.generateSigningKey(io);
    defer key.deinit();
    const signing_keys = [_]as.SigningKey{.{ .key = &key, .kid = "conformance-1" }};
    const resources = [_]as.Resource{.{ .uri = resource }};
    // The suite sends the redirect URI http://127.0.0.1:<port>/callback. A loopback redirect
    // URI matches with each port.
    const clients = [_]as.ClientRegistration{.{
        .client_id = client_id,
        .client_name = "MCP conformance suite",
        .redirect_uris = &.{"http://127.0.0.1/callback"},
    }};
    const auto: as.AutoApprove = .{ .subject = "conformance-user" };
    const issuer = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{port});
    var server = try mcp.auth.AuthorizationServer.init(io, gpa, .{
        .issuer = issuer,
        .signing_keys = &signing_keys,
        .resources = &resources,
        .scopes_supported = &.{ "mcp:read", "mcp:write" },
        .authorizer = auto.authorizer(),
        .clients = &clients,
        .allow_http = true,
    });
    defer server.deinit();
    try server.listen(.{ .port = port });
    std.log.info("authorization server listening on {s}", .{issuer});
    try server.serve();
}
