//! A minimal MCP server over stdio with one tool, one resource and one prompt.
//!
//! Run it with `zig build run-stdio_server` and send newline-delimited JSON-RPC on stdin.
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

fn readme(ctx: *mcp.RequestContext, uri: []const u8) anyerror!mcp.Outcome(mcp.ReadResourceResult) {
    const contents = try ctx.arena.alloc(mcp.types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "This server adds integers." } };
    return .{ .complete = .{ .contents = contents } };
}

fn greet(ctx: *mcp.RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(mcp.GetPromptResult) {
    const who = if (args) |a| a.map.get("name") orelse "world" else "world";
    const messages = try ctx.arena.alloc(mcp.types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = try std.fmt.allocPrint(ctx.arena, "Say hello to {s}.", .{who}) } } };
    return .{ .complete = .{ .messages = messages } };
}

pub fn main(init: std.process.Init) !void {
    // In a release build without libc, `init.gpa` is the debug allocator of std, with one lock for
    // every allocation of every thread. The allocator of std for many threads has no such lock.
    const gpa = if (builtin.mode == .debug) init.gpa else std.heap.smp_allocator;
    // Each task that waits is a thread. On Windows, `stack_size` is only the committed part of its
    // stack, and the reserve stays the 16 MiB of the executable. Thus 64 KiB keeps the full stack.
    var threaded: std.Io.Threaded = .init(gpa, .{
        .stack_size = if (builtin.os.tag == .windows) 64 * 1024 else std.Thread.SpawnConfig.default_stack_size,
        .environ = init.minimal.environ,
        .argv0 = .init(init.minimal.args),
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mcp.Server.init(gpa, io, .{
        .info = .{ .name = "zig-sdk-example", .version = "0.0.1" },
        .instructions = "Use the add tool to add two integers.",
    });
    defer server.deinit();
    try server.addTool(.{ .name = "add", .description = "Add two integers", .annotations = .{ .readOnlyHint = true } }, add);
    try server.addResource(.{ .uri = "example://readme", .name = "readme", .mime_type = "text/plain" }, readme);
    try server.addPrompt(.{ .name = "greet", .arguments = &.{.{ .name = "name", .required = false }} }, greet);
    try mcp.transport.stdio.serve(io, gpa, &server);
}
