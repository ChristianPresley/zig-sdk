//! An MCP server over HTTPS with the in-tree TLS 1.3 server.
//!
//! Usage: https_server <cert.pem> <key.pem> [port]
const std = @import("std");
const mcp = @import("mcp");
const types = mcp.types;

const AddArgs = struct {
    a: i64,
    b: i64,
    pub const json_schema = .{ .description = "Add two integers." };
};

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) {
        std.log.err("usage: https_server <cert.pem> <key.pem> [port]", .{});
        return error.InvalidArguments;
    }
    const port: u16 = if (args.len > 3) try std.fmt.parseInt(u16, args[3], 10) else 8443;

    var chain = try mcp.tls.CertChain.loadFiles(gpa, io, args[1], args[2]);
    defer chain.deinit();
    const chains = [_]*const mcp.tls.CertChain{&chain};
    const tls_server = try mcp.tls.Server.init(.{ .chains = &chains, .alpn = &.{"http/1.1"} });

    var server = try mcp.Server.init(gpa, io, .{
        .info = .{ .name = "https-example", .version = "0.1.0" },
        .instructions = "Use the add tool.",
    });
    defer server.deinit();
    try server.addTool(.{ .name = "add" }, add);

    var transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = port, .tls = &tls_server });
    defer transport.deinit();
    try transport.bind();
    std.log.info("https server listening on https://127.0.0.1:{d}/mcp", .{transport.bound_port});
    try transport.serve();
}
