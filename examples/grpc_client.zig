//! An MCP client over the gRPC binding: it discovers the server, lists the tools and calls
//! `add`.
//!
//! Usage: grpc_client [host] [port] [ca.pem]
//! With a CA file the client connects with TLS and ALPN `h2` and verifies the chain.
const std = @import("std");
const mcp = @import("mcp");
const mcp_grpc = @import("mcp_grpc");

fn onProgress(userdata: ?*anyopaque, params: mcp.types.ProgressNotificationParams) void {
    _ = userdata;
    std.log.info("progress {d} of {?d}", .{ params.progress, params.total });
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const host: []const u8 = if (args.len > 1) args[1] else "127.0.0.1";
    const port: u16 = if (args.len > 2) try std.fmt.parseInt(u16, args[2], 10) else 50051;

    var anchors: ?mcp.tls.CaSet = null;
    defer if (anchors) |*a| a.deinit();
    var setup: ?mcp.transport.http1.TlsSetup = null;
    if (args.len > 3) {
        anchors = .init(gpa);
        try anchors.?.addFile(io, args[3]);
        setup = .{ .trust = .{ .ca_set = &anchors.? } };
    }

    const channel = try mcp_grpc.Channel.init(io, gpa, .{ .host = host, .port = port, .tls = setup });
    defer channel.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "grpc-example-client", .version = "0.1.0" } });
    defer client.deinit();
    client.connect(channel.transport());

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const disc = try client.discover(arena, .{ .timeout = .fromSeconds(10) });
    if (disc._meta) |m| if (m.@"io.modelcontextprotocol/serverInfo") |info| std.log.info("server: {s} {s}", .{ info.name, info.version });
    std.log.info("protocol: {s}", .{disc.supportedVersions[0]});
    const tools = try client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    for (tools.tools) |t| std.log.info("tool: {s}", .{t.name});
    const sum = try client.callTool(arena, "add", .{ .a = 40, .b = 2 }, .{ .timeout = .fromSeconds(10), .on_progress = onProgress });
    std.log.info("add(40, 2) = {s}", .{sum.content[0].text.text});
}
