//! A small MCP client for the command line. It connects over stdio to a server process
//! or over Streamable HTTP to a URL, then lists the tools or calls one.
//!
//! Usage:
//!   client_cli stdio <command> [args...] -- list
//!   client_cli stdio <command> [args...] -- call <tool> [json-arguments]
//!   client_cli http <url> -- list
//!   client_cli http <url> -- call <tool> [json-arguments]
const std = @import("std");
const mcp = @import("mcp");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const separator = for (args, 0..) |a, i| {
        if (std.mem.eql(u8, a, "--")) break i;
    } else return usage();
    if (separator < 3 or args.len < separator + 2) return usage();
    const mode = args[1];
    const action = args[separator + 1 ..];

    var stdio_client: ?*mcp.transport.stdio.Client = null;
    defer if (stdio_client) |c| c.deinit();
    var http_client: ?*mcp.transport.HttpClient = null;
    defer if (http_client) |c| c.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "client_cli", .version = "0.1.0" } });
    defer client.deinit();
    if (std.mem.eql(u8, mode, "stdio")) {
        stdio_client = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = args[2..separator] });
        client.connect(stdio_client.?.transport());
    } else if (std.mem.eql(u8, mode, "http")) {
        http_client = try mcp.transport.HttpClient.init(io, gpa, .{ .url = args[2] });
        client.connect(http_client.?.transport());
    } else return usage();

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    const w = &stdout.interface;
    defer w.flush() catch {};

    if (std.mem.eql(u8, action[0], "list")) {
        const tools = try client.listTools(arena, null, .{ .timeout = .fromSeconds(30) });
        for (tools.tools) |t| try w.print("{s}: {s}\n", .{ t.name, t.description orelse "" });
        return;
    }
    if (std.mem.eql(u8, action[0], "call") and action.len >= 2) {
        const arguments: std.json.Value = if (action.len > 2) try mcp.json.parseTree(arena, action[2]) else .{ .object = .empty };
        var diag: mcp.Client.Diagnostics = .{};
        const result = client.callTool(arena, action[1], arguments, .{ .timeout = .fromSeconds(60), .diagnostics = &diag }) catch |e| switch (e) {
            error.Rpc => {
                try w.print("error {d}: {s}\n", .{ diag.rpc_error.?.code, diag.rpc_error.?.message });
                return;
            },
            else => return e,
        };
        for (result.content) |block| switch (block) {
            .text => |t| try w.print("{s}\n", .{t.text}),
            else => try w.print("[{t} content]\n", .{block}),
        };
        if (result.isError orelse false) try w.print("(tool error)\n", .{});
        return;
    }
    return usage();
}

fn usage() error{InvalidArguments} {
    std.log.err("usage: client_cli (stdio <command> [args...] | http <url>) -- (list | call <tool> [json-arguments])", .{});
    return error.InvalidArguments;
}
