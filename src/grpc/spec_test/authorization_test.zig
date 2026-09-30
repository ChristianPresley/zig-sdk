//! Tests for the authorization rules that apply to the gRPC transport.
//! The gRPC server uses the same bearer token checks as the HTTP server.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("mcp");
const types = mcp.types;
const jwt = mcp.auth.jwt;
const grpc = @import("../../mcp_grpc.zig");

const secret = "g3a-grpc-auth-secret-with-32-bytes!!";

fn fixedNow() i64 {
    return 1000;
}

// RequestContext.principal returns null for gRPC requests, so the handler does not read it.
fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "ok", .{}) };
}

fn serveIgnoringErrors(t: *grpc.Server) void {
    t.serve() catch {};
}

/// Calls `whoami` over a new channel with the given metadata.
fn callWhoami(port: u16, metadata: []const grpc.http2.Connection.Header) !?[]u8 {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const channel = try grpc.Channel.init(io, gpa, .{ .host = "127.0.0.1", .port = port, .extra_metadata = metadata });
    defer channel.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(channel.transport());
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const result = client.callTool(arena_state.allocator(), "whoami", null, .{}) catch |e| switch (e) {
        error.InvalidResponse => return null,
        else => return e,
    };
    return try gpa.dupe(u8, result.content[0].text.text);
}

test "grpc server requires a valid bearer token for the audience when auth is set" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "grpc-auth", .version = "1" } });
    defer server.deinit();
    try server.addToolJson(.{ .name = "whoami" }, whoami);
    const keys = [_]jwt.Key{.{ .alg = .HS256, .material = .{ .secret = secret } }};
    var jv: mcp.auth.JwtVerifier = .{ .options = .{ .keys = &keys, .audience = "grpc://127.0.0.1/mcp" }, .clock = .{ .fixed = fixedNow } };
    const rs: mcp.auth.ResourceServer = .{
        .resource = "grpc://127.0.0.1/mcp",
        .resource_metadata_url = "https://127.0.0.1/.well-known/oauth-protected-resource/mcp",
        .authorization_servers = &.{"https://as.example"},
        .verifier = jv.verifier(),
    };
    var transport: grpc.Server = .init(io, gpa, &server, .{ .port = 0, .auth = &rs });
    try transport.bind();
    var future = try io.concurrent(serveIgnoringErrors, .{&transport});
    defer {
        transport.shutdown();
        future.await(io);
        transport.deinit();
    }
    const port = transport.bound_port;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No token and a token for another audience: the call fails.
    try std.testing.expect((try callWhoami(port, &.{})) == null);
    const foreign = try jwt.signHs256(arena, "{\"sub\":\"eve\",\"aud\":\"https://other.example/mcp\",\"exp\":2000}", secret, null);
    try std.testing.expect((try callWhoami(port, &.{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", foreign }) }})) == null);

    // A valid token: the call reaches the handler.
    const good = try jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"grpc://127.0.0.1/mcp\",\"exp\":2000}", secret, null);
    const who = (try callWhoami(port, &.{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", good }) }})).?;
    defer gpa.free(who);
    try std.testing.expectEqualStrings("ok", who);
}
