//! An MCP client over the gRPC binding: it discovers the server, lists the tools and calls
//! one tool.
//!
//! Usage: grpc_client [host] [port] [ca.pem] [--metadata key=value]... [--tool name] [--args json]
//! With a CA file the client connects with TLS and ALPN `h2` and verifies the chain.
//!
//! Each `--metadata` adds one metadata entry to every call. The key goes to lowercase. `--tool`
//! names the tool to call. The default is `test_simple_text` of the conformance server.
//! `--args` gives the arguments of the tool as a JSON object. The default is `{}`.
const std = @import("std");
const builtin = @import("builtin");
const mcp = @import("mcp");
const mcp_grpc = @import("mcp_grpc");

const Header = mcp_grpc.http2.Connection.Header;

fn onProgress(userdata: ?*anyopaque, params: mcp.types.ProgressNotificationParams) void {
    _ = userdata;
    std.log.info("progress {d} of {?d}", .{ params.progress, params.total });
}

/// The settings from the command line.
const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 50051,
    ca_file: ?[]const u8 = null,
    metadata: []const Header = &.{},
    tool: []const u8 = "test_simple_text",
    /// The arguments of the tool as JSON text.
    args: []const u8 = "{}",
};

/// Parse the command line. The positional arguments are the host, the port and the CA file.
fn parseArgs(arena: std.mem.Allocator, args: []const []const u8) !Config {
    var config: Config = .{};
    var metadata: std.ArrayList(Header) = .empty;
    var position: usize = 0;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const has_value = i + 1 < args.len;
        if (std.mem.eql(u8, arg, "--metadata") and has_value) {
            i += 1;
            const eq = std.mem.indexOfScalar(u8, args[i], '=') orelse return error.InvalidMetadata;
            if (eq == 0) return error.InvalidMetadata;
            try metadata.append(arena, .{ .name = try std.ascii.allocLowerString(arena, args[i][0..eq]), .value = args[i][eq + 1 ..] });
        } else if (std.mem.eql(u8, arg, "--tool") and has_value) {
            i += 1;
            config.tool = args[i];
        } else if (std.mem.eql(u8, arg, "--args") and has_value) {
            i += 1;
            config.args = args[i];
        } else if (std.mem.startsWith(u8, arg, "--")) {
            return error.InvalidArguments;
        } else {
            switch (position) {
                0 => config.host = arg,
                1 => config.port = try std.fmt.parseInt(u16, arg, 10),
                2 => config.ca_file = arg,
                else => return error.InvalidArguments,
            }
            position += 1;
        }
    }
    config.metadata = try metadata.toOwnedSlice(arena);
    return config;
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
    const config = parseArgs(init.arena.allocator(), args) catch |e| {
        std.log.err("usage: grpc_client [host] [port] [ca.pem] [--metadata key=value]... [--tool name] [--args json]", .{});
        return e;
    };

    var anchors: ?mcp.tls.CaSet = null;
    defer if (anchors) |*a| a.deinit();
    var setup: ?mcp.transport.http1.TlsSetup = null;
    if (config.ca_file) |ca_file| {
        anchors = .init(gpa);
        try anchors.?.addFile(io, ca_file);
        setup = .{ .trust = .{ .ca_set = &anchors.? } };
    }

    const channel = try mcp_grpc.Channel.init(io, gpa, .{ .host = config.host, .port = config.port, .tls = setup, .extra_metadata = config.metadata });
    defer channel.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "grpc-example-client", .version = "0.1.0" } });
    defer client.deinit();
    client.connect(channel.transport());

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const tool_args = try mcp.json.parseTree(arena, config.args);
    if (tool_args != .object) {
        std.log.err("--args must be a JSON object", .{});
        return error.InvalidArguments;
    }
    const disc = try client.discover(arena, .{ .timeout = .fromSeconds(10) });
    if (disc._meta) |m| if (m.@"io.modelcontextprotocol/serverInfo") |info| std.log.info("server: {s} {s}", .{ info.name, info.version });
    std.log.info("protocol: {s}", .{disc.supportedVersions[0]});
    const tools = try client.listTools(arena, null, .{ .timeout = .fromSeconds(10) });
    for (tools.tools) |t| std.log.info("tool: {s}", .{t.name});
    const result = try client.callTool(arena, config.tool, tool_args, .{ .timeout = .fromSeconds(10), .on_progress = onProgress });
    if (result.isError orelse false) std.log.warn("{s} gave a tool error", .{config.tool});
    for (result.content) |block| switch (block) {
        .text => |t| std.log.info("{s}: {s}", .{ config.tool, t.text }),
        else => std.log.info("{s}: a {t} block", .{ config.tool, block }),
    };
}

test "parseArgs: positional arguments, repeated metadata, the tool and its arguments" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const defaults = try parseArgs(arena, &.{"grpc_client"});
    try std.testing.expectEqualStrings("127.0.0.1", defaults.host);
    try std.testing.expectEqual(@as(u16, 50051), defaults.port);
    try std.testing.expectEqualStrings("test_simple_text", defaults.tool);
    try std.testing.expectEqualStrings("{}", defaults.args);
    try std.testing.expectEqual(0, defaults.metadata.len);

    const config = try parseArgs(arena, &.{ "grpc_client", "localhost", "43001", "ca.pem", "--metadata", "Authorization=Bearer x=y", "--tool", "add", "--metadata", "x-trace=1", "--args", "{\"a\":1}" });
    try std.testing.expectEqualStrings("localhost", config.host);
    try std.testing.expectEqual(@as(u16, 43001), config.port);
    try std.testing.expectEqualStrings("ca.pem", config.ca_file.?);
    try std.testing.expectEqualStrings("add", config.tool);
    try std.testing.expectEqualStrings("{\"a\":1}", config.args);
    try std.testing.expectEqual(2, config.metadata.len);
    try std.testing.expectEqualStrings("authorization", config.metadata[0].name);
    try std.testing.expectEqualStrings("Bearer x=y", config.metadata[0].value);
    try std.testing.expectEqualStrings("x-trace", config.metadata[1].name);

    try std.testing.expectError(error.InvalidMetadata, parseArgs(arena, &.{ "grpc_client", "--metadata", "novalue" }));
    try std.testing.expectError(error.InvalidArguments, parseArgs(arena, &.{ "grpc_client", "--unknown" }));
}
