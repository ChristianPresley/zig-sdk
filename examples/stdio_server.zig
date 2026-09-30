//! A minimal MCP server over stdio with one tool, one resource and one prompt.
//!
//! Run it with `zig build run-stdio_server` and send newline-delimited JSON-RPC on stdin.
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
    const gpa = init.gpa;
    const io = init.io;
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
