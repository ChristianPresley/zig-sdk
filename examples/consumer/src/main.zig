//! A consumer of the SDK through `b.dependency("mcp", ...)`. It builds a server and a
//! client in one process over the in-memory link. `--check` runs one call and exits.
const std = @import("std");
const mcp = @import("mcp");

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(mcp.CallToolResult) {
    return .{ .complete = try mcp.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "consumer", .version = "0.0.1" } });
    defer server.deinit();
    try server.addTool(.{ .name = "add" }, add);

    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "consumer-client", .version = "0.0.1" } });
    defer client.deinit();
    client.connect(link.transport());

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const result = try client.callTool(arena_state.allocator(), "add", .{ .a = 40, .b = 2 }, .{});
    const text = result.content[0].text.text;
    if (!std.mem.eql(u8, text, "42")) return 1;
    std.log.info("the consumer called add through the SDK dependency: {s}", .{text});
    return 0;
}
