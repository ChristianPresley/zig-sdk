//! An MCP server over the gRPC binding, with cleartext HTTP/2 or TLS with ALPN `h2`.
//!
//! Usage: grpc_server [port] [cert.pem key.pem]
const std = @import("std");
const builtin = @import("builtin");
const mcp = @import("mcp");
const mcp_grpc = @import("mcp_grpc");
const types = mcp.types;

const AddArgs = struct {
    a: i64,
    b: i64,
    pub const json_schema = .{ .description = "Add two integers." };
};

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    try ctx.progress(1, 2, "adding");
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
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
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const port: u16 = if (args.len > 1) try std.fmt.parseInt(u16, args[1], 10) else 50051;

    var chain: ?mcp.tls.CertChain = null;
    defer if (chain) |*c| c.deinit();
    var chains: [1]*const mcp.tls.CertChain = undefined;
    var tls_server: ?mcp.tls.Server = null;
    if (args.len > 3) {
        chain = try mcp.tls.CertChain.loadFiles(gpa, io, args[2], args[3]);
        chains = .{&chain.?};
        tls_server = try mcp.tls.Server.init(.{ .chains = &chains, .alpn = &.{"h2"} });
    }

    var server = try mcp.Server.init(gpa, io, .{
        .info = .{ .name = "grpc-example", .version = "0.1.0" },
        .instructions = "Use the add tool.",
    });
    defer server.deinit();
    try server.addTool(.{ .name = "add" }, add);

    var transport: mcp_grpc.Server = .init(io, gpa, &server, .{ .port = port, .tls = if (tls_server) |*t| t else null });
    defer transport.deinit();
    try transport.bind();
    std.log.info("gRPC server listening on 127.0.0.1:{d} ({s})", .{ transport.bound_port, if (tls_server != null) "TLS, ALPN h2" else "cleartext HTTP/2" });
    try transport.serve();
}
