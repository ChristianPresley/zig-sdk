//! A small MCP client for the command line. It connects to a server, and then it lists the
//! tools or calls one. The modes are `stdio` (a server process), `http` (Streamable HTTP),
//! `unix` (a Unix domain socket) and `ws` (WebSocket with a `ws` or `wss` URL).
//!
//! With `--oauth`, the HTTP client answers authorization challenges with `OAuthClient`. The
//! client keeps its registration and its tokens in the keychain of the host. Thus the next run
//! needs no new sign-in. A host without a keychain uses encrypted files in the home directory
//! when the environment variable `MCP_TOKEN_KEY` has a key of 64 hexadecimal digits. Else the
//! tokens stay in memory.
//!
//! Usage:
//!   client_cli stdio <command> [args...] -- list
//!   client_cli stdio <command> [args...] -- call <tool> [json-arguments]
//!   client_cli http <url> [--oauth] -- list
//!   client_cli http <url> [--oauth] -- call <tool> [json-arguments]
//!   client_cli unix <path> -- list
//!   client_cli unix <path> -- call <tool> [json-arguments]
//!   client_cli ws <url> -- list
//!   client_cli ws <url> -- call <tool> [json-arguments]
const std = @import("std");
const builtin = @import("builtin");
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
    var unix_client: ?*mcp.transport.unix.Client = null;
    defer if (unix_client) |c| c.deinit();
    var ws_client: ?*mcp.transport.websocket.Client = null;
    defer if (ws_client) |c| c.deinit();
    var tokens: TokenStore = .none;
    defer tokens.deinit();
    var oauth: ?mcp.auth.OAuthClient = null;
    defer if (oauth) |*o| o.deinit();
    var client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "client_cli", .version = "0.1.0" } });
    defer client.deinit();
    if (std.mem.eql(u8, mode, "stdio")) {
        stdio_client = try mcp.transport.stdio.Client.spawn(io, gpa, .{ .argv = args[2..separator] });
        client.connect(stdio_client.?.transport());
    } else if (std.mem.eql(u8, mode, "http")) {
        if (separator > 3 and std.mem.eql(u8, args[3], "--oauth")) {
            tokens = .open(io, gpa, init.environ_map);
            oauth = .init(io, gpa, .{
                .client_name = "client_cli",
                .authorize = .{ .callback = .{ .userdata = @constCast(&io), .open = askForRedirect } },
                .storage = tokens.storage(),
            });
        }
        http_client = try mcp.transport.HttpClient.init(io, gpa, .{ .url = args[2], .auth = if (oauth) |*o| o else null });
        client.connect(http_client.?.transport());
    } else if (std.mem.eql(u8, mode, "unix")) {
        unix_client = try mcp.transport.unix.Client.connect(io, gpa, .{ .path = args[2] });
        client.connect(unix_client.?.transport());
    } else if (std.mem.eql(u8, mode, "ws")) {
        ws_client = try mcp.transport.websocket.Client.init(io, gpa, .{ .url = args[2] });
        client.connect(ws_client.?.transport());
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

/// The token storage of the example: the keychain of the host, else encrypted files, else none.
const TokenStore = union(enum) {
    keychain: mcp.auth.KeychainTokenStorage,
    files: mcp.auth.FileTokenStorage,
    none,

    fn open(io: std.Io, gpa: std.mem.Allocator, env: *const std.process.Environ.Map) TokenStore {
        if (mcp.auth.KeychainTokenStorage.init(io, gpa, .{ .service = "zig-sdk client_cli", .environ_map = env })) |keychain| {
            return .{ .keychain = keychain };
        } else |e| std.log.info("no keychain ({t}), the tokens go to files or stay in memory", .{e});
        // `FileTokenStorage` needs a key of the application. A real application keeps it in a
        // safe location. This example reads it from the environment.
        const hex = env.get("MCP_TOKEN_KEY") orelse return .none;
        var key: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &key);
        if (hex.len != 64) return .none;
        _ = std.fmt.hexToBytes(&key, hex) catch return .none;
        const home = env.get(if (builtin.os.tag == .windows) "LOCALAPPDATA" else "HOME") orelse return .none;
        const dir = std.fs.path.join(gpa, &.{ home, ".mcp-client-cli-tokens" }) catch return .none;
        defer gpa.free(dir);
        const files = mcp.auth.FileTokenStorage.init(io, gpa, .{ .dir = dir, .key = key }) catch |e| {
            std.log.warn("no token files in {s}: {t}", .{ dir, e });
            return .none;
        };
        return .{ .files = files };
    }

    fn storage(self: *TokenStore) ?mcp.auth.TokenStorage {
        return switch (self.*) {
            .keychain => |*k| k.storage(),
            .files => |*f| f.storage(),
            .none => null,
        };
    }

    fn deinit(self: *TokenStore) void {
        switch (self.*) {
            .keychain => |*k| k.deinit(),
            .files => |*f| f.deinit(),
            .none => {},
        }
    }
};

/// Show the authorization URL and read the redirect URL that the user pastes. The SDK never
/// opens a browser.
fn askForRedirect(userdata: ?*anyopaque, arena: std.mem.Allocator, url: []const u8) anyerror![]const u8 {
    const io: *const std.Io = @ptrCast(@alignCast(userdata.?));
    std.debug.print("Open this URL in a browser and sign in:\n{s}\nThen paste the address of the last page here:\n", .{url});
    var buf: [8192]u8 = undefined;
    var stdin = std.Io.File.stdin().reader(io.*, &buf);
    const line = try stdin.interface.takeDelimiterExclusive('\n');
    return arena.dupe(u8, std.mem.trim(u8, line, " \t\r"));
}

fn usage() error{InvalidArguments} {
    std.log.err("usage: client_cli (stdio <command> [args...] | http <url> [--oauth] | unix <path> | ws <url>) -- (list | call <tool> [json-arguments])", .{});
    return error.InvalidArguments;
}
