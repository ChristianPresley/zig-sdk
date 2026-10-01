//! A minimal MCP server on WebSocket connections with one tool.
//!
//! Run it with `zig build run-websocket_server`. It listens on `ws://127.0.0.1:3001/mcp`.
//! Connect with `client_cli ws ws://127.0.0.1:3001/mcp -- list`. Each WebSocket text message
//! is one JSON-RPC message. The upgrade request must offer the subprotocol `mcp`.
//!
//! Usage: websocket_server [port] [cert.pem key.pem]
//!
//! With a certificate and a key, the server serves `wss` with the in-tree TLS 1.3 server.
const std = @import("std");
const mcp = @import("mcp");

const AddArgs = struct {
    a: i64,
    b: i64,
    pub const json_schema = .{
        .description = "Add two integers.",
        .fields = .{ .a = .{ .description = "Left operand" }, .b = .{ .description = "Right operand" } },
    };
};

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(mcp.CallToolResult) {
    try ctx.checkCancel();
    return .{ .complete = try mcp.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const port: u16 = if (args.len > 1) try std.fmt.parseInt(u16, args[1], 10) else 3001;

    var chain: ?mcp.tls.CertChain = null;
    defer if (chain) |*c| c.deinit();
    var chains: [1]*const mcp.tls.CertChain = undefined;
    var tls_server: ?mcp.tls.Server = null;
    if (args.len > 3) {
        chain = try mcp.tls.CertChain.loadFiles(gpa, io, args[2], args[3]);
        chains = .{&chain.?};
        tls_server = try mcp.tls.Server.init(.{ .chains = &chains, .alpn = &.{"http/1.1"} });
    }

    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "zig-sdk-websocket-example", .version = "0.0.1" } });
    defer server.deinit();
    try server.addTool(.{ .name = "add", .description = "Add two integers", .annotations = .{ .readOnlyHint = true } }, add);
    var transport: mcp.transport.websocket.Server = .init(io, gpa, &server, .{
        .port = port,
        .tls = if (tls_server) |*t| t else null,
    });
    defer transport.deinit();
    try transport.bind();
    std.log.info("listening on {s}://127.0.0.1:{d}/mcp", .{ if (tls_server != null) "wss" else "ws", transport.bound_port });
    try transport.serve();
}
