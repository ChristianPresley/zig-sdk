//! A minimal MCP server on a Unix domain socket with one tool.
//!
//! Run it with `zig build run-unix_server -- /tmp/mcp.sock`. Connect with
//! `client_cli unix /tmp/mcp.sock -- list`. Each line on the socket is one JSON-RPC message,
//! as on stdio. The server removes a stale socket file at start.
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
    const path = if (args.len > 1) args[1] else "mcp.sock";
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "zig-sdk-unix-example", .version = "0.0.1" } });
    defer server.deinit();
    try server.addTool(.{ .name = "add", .description = "Add two integers", .annotations = .{ .readOnlyHint = true } }, add);
    var transport: mcp.transport.unix.Server = .init(io, gpa, &server, .{ .path = path });
    defer transport.deinit();
    try transport.bind();
    std.log.info("listening on {s}", .{path});
    try transport.serve();
}
