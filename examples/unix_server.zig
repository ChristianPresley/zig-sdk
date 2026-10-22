//! A minimal MCP server on a Unix domain socket with one tool.
//!
//! Run it with `zig build run-unix_server`. It creates the private directory `mcp-run` and
//! listens on `mcp-run/mcp.sock`. Connect with `client_cli unix mcp-run/mcp.sock -- list`.
//! Another path must be in a directory that only you can write to, for example one that
//! `mcp.transport.unix.createPrivateDirectory` made. Each line on the socket is one JSON-RPC
//! message, as on stdio. The server removes a stale socket file at start.
const std = @import("std");
const builtin = @import("builtin");
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
    // In a release build without libc, `init.gpa` is the debug allocator of std, with one lock for
    // every allocation of every thread. The allocator of std for many threads has no such lock.
    const gpa = if (builtin.mode == .Debug) init.gpa else std.heap.smp_allocator;
    // Each task that waits is a thread. On Windows, `stack_size` is only the committed part of its
    // stack, and the reserve stays the 16 MiB of the executable. Thus 64 KiB keeps the full stack.
    var threaded: std.Io.Threaded = .init(gpa, .{
        .stack_size = if (builtin.os.tag == .windows) 64 * 1024 else std.Thread.SpawnConfig.default_stack_size,
        .environ = init.minimal.environ,
        .argv0 = .init(init.minimal.args),
    });
    defer threaded.deinit();
    const io = threaded.io();
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const path = if (args.len > 1) args[1] else path: {
        try mcp.transport.unix.createPrivateDirectory(io, "mcp-run");
        break :path "mcp-run/mcp.sock";
    };
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "zig-sdk-unix-example", .version = "0.0.1" } });
    defer server.deinit();
    try server.addTool(.{ .name = "add", .description = "Add two integers", .annotations = .{ .readOnlyHint = true } }, add);
    var transport: mcp.transport.unix.Server = .init(io, gpa, &server, .{ .path = path });
    defer transport.deinit();
    try transport.bind();
    std.log.info("listening on {s}", .{path});
    try transport.serve();
}
