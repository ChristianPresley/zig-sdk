//! Tests for the caching, completion, logging and pagination utilities of the specification.
//! Each test checks one rule of these pages.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("../../mcp.zig");
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const types = mcp.types;
const json = mcp.json;
const Harness = mcp.transport.memory.Harness;
const Transport = mcp.transport.Transport;

const meta_none =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;

fn metaWithLevel(arena: std.mem.Allocator, level: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{{}},\"io.modelcontextprotocol/logLevel\":\"{s}\"}}", .{level});
}

fn request(arena: std.mem.Allocator, id: i64, method: []const u8, meta: []const u8, extra: []const u8) ![]u8 {
    const sep: []const u8 = if (extra.len > 0) "," else "";
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta, sep, extra });
}

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

fn result(v: Value) Value {
    return v.object.get("result").?;
}

// -- Server fixtures ----------------------------------------------------------------------------

fn noop(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "ok", .{}) };
}

fn chatty(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    try ctx.logText(.debug, "spec", "debug line", .{});
    try ctx.logText(.info, "spec", "info line", .{});
    try ctx.logText(.@"error", "spec", "error line", .{});
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "done", .{}) };
}

fn readNegative(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "negative" } };
    return .{ .complete = .{ .contents = contents, .ttlMs = -7 } };
}

/// Counts handler calls through the registration `userdata`.
fn readCounted(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const counter: *u32 = @ptrCast(@alignCast(ctx.userdata.?));
    counter.* += 1;
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "counted" } };
    return .{ .complete = .{ .contents = contents } };
}

/// Asks for one elicitation before it completes. Counts every round.
fn readAfterConfirm(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const counter: *u32 = @ptrCast(@alignCast(ctx.userdata.?));
    counter.* += 1;
    if (try ctx.elicitResponse("confirm")) |_| {
        const contents = try ctx.arena.alloc(types.ResourceContents, 1);
        contents[0] = .{ .text = .{ .uri = uri, .text = "confirmed" } };
        return .{ .complete = .{ .contents = contents } };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("confirm", "Confirm?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn promptHi(ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    _ = args;
    const messages = try ctx.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = "hi" } } };
    return .{ .complete = .{ .messages = messages } };
}

fn readTemplated(ctx: *RequestContext, uri: []const u8, vars: []const mcp.UriTemplate.Variable) anyerror!mcp.Outcome(types.ReadResourceResult) {
    _ = vars;
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "templated" } };
    return .{ .complete = .{ .contents = contents } };
}

var completion_calls: u32 = 0;

fn completeCounted(ctx: *RequestContext, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion {
    completion_calls += 1;
    return completeTwo(ctx, params);
}

fn completeTwo(ctx: *RequestContext, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion {
    _ = params;
    const values = try ctx.arena.alloc([]const u8, 2);
    values[0] = "alpha";
    values[1] = "beta";
    return .{ .values = values };
}

fn completeFails(ctx: *RequestContext, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion {
    _ = ctx;
    _ = params;
    return error.Boom;
}

const ServerFixture = struct {
    server: Server,
    harness: Harness,
    arena_state: std.heap.ArenaAllocator,

    fn init(self: *ServerFixture, options: Server.Options) !void {
        const gpa = std.testing.allocator;
        self.arena_state = .init(gpa);
        self.server = try Server.init(gpa, std.testing.io, options);
        self.harness = .init(std.testing.io, gpa, &self.server);
    }

    fn deinit(self: *ServerFixture) void {
        self.harness.deinit();
        self.server.deinit();
        self.arena_state.deinit();
    }

    fn arena(self: *ServerFixture) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// Send a request and return the parsed last frame.
    fn call(self: *ServerFixture, id: i64, method: []const u8, meta: []const u8, extra: []const u8) !Value {
        self.harness.clear();
        try self.harness.send(try request(self.arena(), id, method, meta, extra));
        try std.testing.expect(self.harness.finished);
        return json.parseTree(self.arena(), self.harness.last().?);
    }

    /// The number of output notifications with the given method.
    fn notificationCount(self: *ServerFixture, method: []const u8) !usize {
        var n: usize = 0;
        for (self.harness.out.items) |frame| {
            const v = try json.parseTree(self.arena(), frame);
            const m = v.object.get("method") orelse continue;
            if (std.mem.eql(u8, m.string, method)) n += 1;
        }
        return n;
    }
};

// -- Scripted client transport ------------------------------------------------------------------

/// A client transport that answers each request with the next scripted result. It records
/// the request frames and sends the scripted notifications before each response. A result
/// that starts with `error:` is the error object of an error response.
const Scripted = struct {
    gpa: std.mem.Allocator,
    results: []const []const u8,
    notes: []const []const u8 = &.{},
    calls: usize = 0,
    sent: std.ArrayList([]u8) = .empty,
    /// The credential of the transport, for example a bearer token.
    token: ?[]const u8 = null,
    /// A new credential that the transport takes during the next request, as after a challenge.
    rotate_to: ?[]const u8 = null,

    fn deinit(self: *Scripted) void {
        for (self.sent.items) |s| self.gpa.free(s);
        self.sent.deinit(self.gpa);
    }

    fn transport(self: *Scripted) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{ .kind = .memory, .exchange = exchange, .notify = notify, .credential = credential };

    fn credential(ptr: *anyopaque, arena: std.mem.Allocator) std.mem.Allocator.Error!?[]const u8 {
        const self: *Scripted = @ptrCast(@alignCast(ptr));
        const t = self.token orelse return null;
        return try arena.dupe(u8, t);
    }

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Scripted = @ptrCast(@alignCast(ptr));
        const copy = try self.gpa.dupe(u8, ex.frame);
        self.sent.append(self.gpa, copy) catch |e| {
            self.gpa.free(copy);
            return e;
        };
        const body = self.results[@min(self.calls, self.results.len - 1)];
        self.calls += 1;
        if (self.rotate_to) |t| {
            self.token = t;
            self.rotate_to = null;
        }
        for (self.notes) |note| ex.sink.deliver(io, note) catch return error.InvalidFrame;
        const is_error = std.mem.startsWith(u8, body, "error:");
        const member: []const u8 = if (is_error) "error" else "result";
        const payload = if (is_error) body["error:".len..] else body;
        const frame = try std.fmt.allocPrint(self.gpa, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"{s}\":{s}}}", .{ ex.id.integer, member, payload });
        defer self.gpa.free(frame);
        ex.sink.deliver(io, frame) catch return error.InvalidFrame;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = ptr;
        _ = io;
        _ = frame;
    }

    /// The `params` object of the request frame number `index`.
    fn sentParams(self: *Scripted, arena: std.mem.Allocator, index: usize) !Value {
        const v = try json.parseTree(arena, self.sent.items[index]);
        return v.object.get("params").?;
    }
};

const client_info: types.Implementation = .{ .name = "spec-client", .version = "1" };

// -- Caching: server ----------------------------------------------------------------------------

test "server sends negative ttl hints as zero" {
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" }, .cache = .{
        .discover = .{ .ttl_ms = -5 },
        .lists = .{ .ttl_ms = -1 },
        .reads = .{ .ttl_ms = 1000 },
    } });
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "noop" }, noop);
    try f.server.addResource(.{ .uri = "test://negative", .name = "negative" }, readNegative);

    const disc = result(try f.call(1, "server/discover", meta_none, ""));
    try std.testing.expectEqual(@as(i64, 0), disc.object.get("ttlMs").?.integer);
    const list = result(try f.call(2, "tools/list", meta_none, ""));
    try std.testing.expectEqual(@as(i64, 0), list.object.get("ttlMs").?.integer);
    // A handler that sets a negative value also gets zero on the wire.
    const read = result(try f.call(3, "resources/read", meta_none, "\"uri\":\"test://negative\""));
    try std.testing.expectEqual(@as(i64, 0), read.object.get("ttlMs").?.integer);
}

test "server applies the same cache scope and ttl to every page of a list" {
    var f: ServerFixture = undefined;
    var options: Server.Options = .{ .info = .{ .name = "t", .version = "1" }, .cache = .{ .lists = .{ .ttl_ms = 5000, .scope = .public } } };
    options.limits.page_size = 1;
    try f.init(options);
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "a" }, noop);
    try f.server.addToolJson(.{ .name = "b" }, noop);
    try f.server.addToolJson(.{ .name = "c" }, noop);

    var pages: usize = 0;
    var cursor: ?[]const u8 = null;
    while (true) : (pages += 1) {
        const extra = if (cursor) |c| try std.fmt.allocPrint(f.arena(), "\"cursor\":\"{s}\"", .{c}) else "";
        const page = result(try f.call(@intCast(pages + 1), "tools/list", meta_none, extra));
        try std.testing.expectEqualStrings("public", page.object.get("cacheScope").?.string);
        try std.testing.expectEqual(@as(i64, 5000), page.object.get("ttlMs").?.integer);
        const next = page.object.get("nextCursor") orelse break;
        cursor = next.string;
    }
    try std.testing.expectEqual(2, pages);
}

test "server sends ttl hints with and without listChanged" {
    // Explicit capabilities without listChanged.
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" }, .capabilities = .{ .tools = .{ .listChanged = false } }, .cache = .{ .lists = .{ .ttl_ms = 30_000 } } });
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "noop" }, noop);
    const disc = result(try f.call(1, "server/discover", meta_none, ""));
    try std.testing.expect(!disc.object.get("capabilities").?.object.get("tools").?.object.get("listChanged").?.bool);
    const list = result(try f.call(2, "tools/list", meta_none, ""));
    try std.testing.expectEqual(@as(i64, 30_000), list.object.get("ttlMs").?.integer);

    // The default capabilities advertise listChanged, and the hint is still sent.
    var g: ServerFixture = undefined;
    try g.init(.{ .info = .{ .name = "t", .version = "1" }, .cache = .{ .lists = .{ .ttl_ms = 30_000 } } });
    defer g.deinit();
    try g.server.addToolJson(.{ .name = "noop" }, noop);
    const disc2 = result(try g.call(1, "server/discover", meta_none, ""));
    try std.testing.expect(disc2.object.get("capabilities").?.object.get("tools").?.object.get("listChanged").?.bool);
    const list2 = result(try g.call(2, "tools/list", meta_none, ""));
    try std.testing.expectEqual(@as(i64, 30_000), list2.object.get("ttlMs").?.integer);
}

// -- Caching: client ----------------------------------------------------------------------------

test "client cache hits only for the same method and parameters" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{ .gpa = gpa, .results = &.{
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"private\",\"contents\":[{\"uri\":\"test://a\",\"text\":\"a\"}]}",
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"private\",\"contents\":[{\"uri\":\"test://b\",\"text\":\"b\"}]}",
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"tools\":[],\"nextCursor\":\"c1\"}",
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"tools\":[]}",
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"prompts\":[]}",
    } };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer client.deinit();
    client.connect(script.transport());

    // Same uri: served from the cache. Other uri: sent to the server.
    const a1 = try client.readResource(arena, "test://a", .{});
    const a2 = try client.readResource(arena, "test://a", .{});
    try std.testing.expectEqualStrings("a", a2.contents[0].text.text);
    try std.testing.expectEqualStrings(a1.contents[0].text.uri, a2.contents[0].text.uri);
    try std.testing.expectEqual(1, script.calls);
    const b = try client.readResource(arena, "test://b", .{});
    try std.testing.expectEqualStrings("b", b.contents[0].text.text);
    try std.testing.expectEqual(2, script.calls);

    // A different cursor is a different key.
    _ = try client.listTools(arena, null, .{});
    try std.testing.expectEqual(3, script.calls);
    _ = try client.listTools(arena, "c1", .{});
    try std.testing.expectEqual(4, script.calls);
    _ = try client.listTools(arena, "c1", .{});
    _ = try client.listTools(arena, null, .{});
    try std.testing.expectEqual(4, script.calls);

    // A different method with the same (empty) parameters is a different key.
    const prompts = try client.listPrompts(arena, null, .{});
    try std.testing.expectEqual(0, prompts.prompts.len);
    try std.testing.expectEqual(5, script.calls);
}

test "client does not cache results of multi round-trip retries" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, io, .{ .info = .{ .name = "t", .version = "1" }, .cache = .{ .reads = .{ .ttl_ms = 60_000 } } });
    defer server.deinit();
    var rounds: u32 = 0;
    try server.addResource(.{ .uri = "test://confirm", .name = "confirm", .userdata = &rounds }, readAfterConfirm);
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    const Hook = struct {
        fn answer(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
            _ = params;
            return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"x\"}") };
        }
    };
    var client: Client = .init(gpa, io, .{
        .info = client_info,
        .capabilities = .{ .elicitation = .{} },
        .hooks = .{ .elicit_form = Hook.answer },
        .cache = .{ .enabled = true },
    });
    defer client.deinit();
    client.connect(link.transport());

    const first = try client.readResource(arena, "test://confirm", .{});
    try std.testing.expectEqualStrings("confirmed", first.contents[0].text.text);
    try std.testing.expectEqual(2, rounds);
    // The final result carries a positive ttlMs, but it came from a retry with inputResponses.
    try std.testing.expectEqual(0, client.cache.count());
    _ = try client.readResource(arena, "test://confirm", .{});
    try std.testing.expectEqual(4, rounds);
}

test "client treats a zero, absent or negative ttl as immediately stale" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{ .gpa = gpa, .results = &.{
        "{\"resultType\":\"complete\",\"ttlMs\":0,\"contents\":[{\"uri\":\"test://zero\",\"text\":\"z\"}]}",
        "{\"resultType\":\"complete\",\"ttlMs\":0,\"contents\":[{\"uri\":\"test://zero\",\"text\":\"z\"}]}",
        "{\"resultType\":\"complete\",\"contents\":[{\"uri\":\"test://absent\",\"text\":\"a\"}]}",
        "{\"resultType\":\"complete\",\"contents\":[{\"uri\":\"test://absent\",\"text\":\"a\"}]}",
        "{\"resultType\":\"complete\",\"ttlMs\":-5,\"contents\":[{\"uri\":\"test://negative\",\"text\":\"n\"}]}",
        "{\"resultType\":\"complete\",\"ttlMs\":-5,\"contents\":[{\"uri\":\"test://negative\",\"text\":\"n\"}]}",
    } };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer client.deinit();
    client.connect(script.transport());

    const uris = [_][]const u8{ "test://zero", "test://absent", "test://negative" };
    for (uris, 0..) |uri, i| {
        _ = try client.readResource(arena, uri, .{});
        _ = try client.readResource(arena, uri, .{});
        try std.testing.expectEqual(2 * (i + 1), script.calls);
        try std.testing.expectEqual(0, client.cache.count());
    }
}

test "client fetches an expired page again with its cursor" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{ .gpa = gpa, .results = &.{
        "{\"resultType\":\"complete\",\"ttlMs\":60,\"tools\":[]}",
    } };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer client.deinit();
    client.connect(script.transport());

    _ = try client.listTools(arena, "page-2", .{});
    _ = try client.listTools(arena, "page-2", .{});
    try std.testing.expectEqual(1, script.calls);
    try std.testing.io.sleep(.fromMilliseconds(90), .awake);
    _ = try client.listTools(arena, "page-2", .{});
    try std.testing.expectEqual(2, script.calls);
    const params = try script.sentParams(arena, 1);
    try std.testing.expectEqualStrings("page-2", params.object.get("cursor").?.string);
}

test "client caches are not shared between client instances" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server = try Server.init(gpa, io, .{ .info = .{ .name = "t", .version = "1" }, .cache = .{ .reads = .{ .ttl_ms = 60_000, .scope = .private } } });
    defer server.deinit();
    var reads: u32 = 0;
    try server.addResource(.{ .uri = "test://mine", .name = "mine", .userdata = &reads }, readCounted);
    var link_a: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var link_b: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var a: Client = .init(gpa, io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer a.deinit();
    a.connect(link_a.transport());
    var b: Client = .init(gpa, io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer b.deinit();
    b.connect(link_b.transport());

    const first = try a.readResource(arena, "test://mine", .{});
    try std.testing.expectEqual(types.CacheScope.private, first.cacheScope.?);
    _ = try a.readResource(arena, "test://mine", .{});
    try std.testing.expectEqual(1, reads);
    // The private result of client A is not visible to client B.
    _ = try b.readResource(arena, "test://mine", .{});
    try std.testing.expectEqual(2, reads);
}

test "client does not cache a caller request that carries requestState" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{ .gpa = gpa, .results = &.{
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"public\",\"contents\":[{\"uri\":\"test://a\",\"text\":\"a\"}]}",
    } };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer client.deinit();
    client.connect(script.transport());

    // The caller drives the multi round-trip retry and sends only requestState.
    const params = try json.parseTree(arena, "{\"uri\":\"test://a\",\"requestState\":\"opaque-state\"}");
    _ = try client.request(arena, .@"resources/read", params, .{});
    _ = try client.request(arena, .@"resources/read", params, .{});
    try std.testing.expectEqual(2, script.calls);
    try std.testing.expectEqual(0, client.cache.count());
    try std.testing.expectEqualStrings("opaque-state", (try script.sentParams(arena, 1)).object.get("requestState").?.string);
    // The same request without requestState is cacheable.
    _ = try client.readResource(arena, "test://a", .{});
    _ = try client.readResource(arena, "test://a", .{});
    try std.testing.expectEqual(3, script.calls);
    try std.testing.expectEqual(1, client.cache.count());
}

test "client keeps private cache entries apart by authorization context" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const private_a = "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"private\",\"contents\":[{\"uri\":\"test://a\",\"text\":\"a\"}]}";
    const unscoped_b = "{\"resultType\":\"complete\",\"ttlMs\":60000,\"contents\":[{\"uri\":\"test://b\",\"text\":\"b\"}]}";
    var script: Scripted = .{ .gpa = gpa, .token = "token-alice", .results = &.{
        private_a,
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"public\",\"tools\":[]}",
        private_a,
        private_a,
        unscoped_b,
        unscoped_b,
    } };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer client.deinit();
    client.connect(script.transport());

    // Alice: the private read and the public list are cached.
    _ = try client.readResource(arena, "test://a", .{});
    _ = try client.readResource(arena, "test://a", .{});
    _ = try client.listTools(arena, null, .{});
    try std.testing.expectEqual(2, script.calls);
    // Bob: the private read of Alice is not shared. The public list is shared.
    script.token = "token-bob";
    _ = try client.readResource(arena, "test://a", .{});
    try std.testing.expectEqual(3, script.calls);
    _ = try client.listTools(arena, null, .{});
    try std.testing.expectEqual(3, script.calls);
    // Alice again: the token change dropped her private entry.
    script.token = "token-alice";
    _ = try client.readResource(arena, "test://a", .{});
    try std.testing.expectEqual(4, script.calls);
    // A result without cacheScope counts as private.
    _ = try client.readResource(arena, "test://b", .{});
    script.token = null;
    _ = try client.readResource(arena, "test://b", .{});
    try std.testing.expectEqual(6, script.calls);
    // A token change during the request: the private result is not stored.
    script.rotate_to = "token-carol";
    _ = try client.readResource(arena, "test://c", .{});
    _ = try client.readResource(arena, "test://c", .{});
    try std.testing.expectEqual(8, script.calls);
    try std.testing.expect(client.cache.count() > 0);
    // A new connection drops every cached result.
    client.connect(script.transport());
    try std.testing.expectEqual(0, client.cache.count());

    // The HTTP transport gives the authorization header as the credential.
    const http = try mcp.transport.HttpClient.init(std.testing.io, gpa, .{
        .url = "http://127.0.0.1:9/mcp",
        .extra_headers = &.{.{ .name = "Authorization", .value = "Bearer t1" }},
    });
    defer http.deinit();
    try std.testing.expectEqualStrings("Bearer t1", (try http.transport().credential(arena)).?);
}

test "client drops the cached pages of a list after an invalid cursor error" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{ .gpa = gpa, .results = &.{
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"public\",\"tools\":[],\"nextCursor\":\"c1\"}",
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"public\",\"tools\":[]}",
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"public\",\"prompts\":[]}",
        "error:{\"code\":-32602,\"message\":\"Invalid cursor\"}",
        "{\"resultType\":\"complete\",\"ttlMs\":60000,\"cacheScope\":\"public\",\"tools\":[]}",
    } };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info, .cache = .{ .enabled = true } });
    defer client.deinit();
    client.connect(script.transport());

    _ = try client.listTools(arena, null, .{});
    _ = try client.listTools(arena, "c1", .{});
    _ = try client.listPrompts(arena, null, .{});
    try std.testing.expectEqual(3, client.cache.count());
    // The server now rejects the cursor.
    var diag: Client.Diagnostics = .{};
    try std.testing.expectError(error.Rpc, client.listTools(arena, "c1", .{ .cache_mode = .refresh, .diagnostics = &diag }));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
    // Both pages of tools/list are gone. The prompts page stays.
    try std.testing.expectEqual(1, client.cache.count());
    _ = try client.listTools(arena, null, .{});
    try std.testing.expectEqual(5, script.calls);
}

// -- Completion ---------------------------------------------------------------------------------

test "completion needs the completions capability" {
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" } });
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "noop" }, noop);
    try f.server.addPrompt(.{ .name = "p" }, promptHi);
    const params = "\"ref\":{\"type\":\"ref/prompt\",\"name\":\"p\"},\"argument\":{\"name\":\"a\",\"value\":\"x\"}";

    // Without a completion handler the capability is absent and the method is not found.
    const disc = result(try f.call(1, "server/discover", meta_none, ""));
    try std.testing.expect(disc.object.get("capabilities").?.object.get("completions") == null);
    try std.testing.expectEqual(@as(i64, -32601), errorCode(try f.call(2, "completion/complete", meta_none, params)).?);

    // A completion handler declares the capability.
    f.server.setCompletionHandler(completeTwo);
    const disc2 = result(try f.call(3, "server/discover", meta_none, ""));
    try std.testing.expect(disc2.object.get("capabilities").?.object.get("completions") != null);
    const comp = result(try f.call(4, "completion/complete", meta_none, params));
    try std.testing.expectEqual(2, comp.object.get("completion").?.object.get("values").?.array.items.len);
}

test "completion rejects malformed parameters with invalid params" {
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" } });
    defer f.deinit();
    f.server.setCompletionHandler(completeTwo);

    // The required `argument` is missing.
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(1, "completion/complete", meta_none, "\"ref\":{\"type\":\"ref/prompt\",\"name\":\"p\"}")).?);
    // The required `ref` is missing.
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(2, "completion/complete", meta_none, "\"argument\":{\"name\":\"a\",\"value\":\"x\"}")).?);
    // The reference type is unknown.
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(3, "completion/complete", meta_none, "\"ref\":{\"type\":\"ref/tool\",\"name\":\"p\"},\"argument\":{\"name\":\"a\",\"value\":\"x\"}")).?);
    // The argument value is not a string.
    try std.testing.expectEqual(@as(i64, -32602), errorCode(try f.call(4, "completion/complete", meta_none, "\"ref\":{\"type\":\"ref/prompt\",\"name\":\"p\"},\"argument\":{\"name\":\"a\",\"value\":7}")).?);
}

test "completion handler failure is an internal error" {
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" } });
    defer f.deinit();
    try f.server.addPrompt(.{ .name = "p" }, promptHi);
    f.server.setCompletionHandler(completeFails);
    const v = try f.call(1, "completion/complete", meta_none, "\"ref\":{\"type\":\"ref/prompt\",\"name\":\"p\"},\"argument\":{\"name\":\"a\",\"value\":\"x\"}");
    try std.testing.expectEqual(@as(i64, -32603), errorCode(v).?);
}

test "completion rejects an unknown prompt or resource template with invalid params" {
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" } });
    defer f.deinit();
    try f.server.addPrompt(.{ .name = "p" }, promptHi);
    try f.server.addPrompt(.{ .name = "off" }, promptHi);
    _ = f.server.setPromptEnabled(std.testing.io, "off", false);
    try f.server.addResourceTemplate(.{ .uri_template = "test://items/{id}", .name = "items" }, readTemplated);
    try f.server.addResource(.{ .uri = "test://static", .name = "static" }, readNegative);
    f.server.setCompletionHandler(completeCounted);
    completion_calls = 0;

    const Case = struct { ref: []const u8, code: ?i64 };
    const cases = [_]Case{
        .{ .ref = "{\"type\":\"ref/prompt\",\"name\":\"p\"}", .code = null },
        .{ .ref = "{\"type\":\"ref/prompt\",\"name\":\"missing\"}", .code = -32602 },
        // A disabled prompt is unknown to the client.
        .{ .ref = "{\"type\":\"ref/prompt\",\"name\":\"off\"}", .code = -32602 },
        .{ .ref = "{\"type\":\"ref/resource\",\"uri\":\"test://items/{id}\"}", .code = null },
        .{ .ref = "{\"type\":\"ref/resource\",\"uri\":\"test://items/7\"}", .code = null },
        .{ .ref = "{\"type\":\"ref/resource\",\"uri\":\"test://static\"}", .code = null },
        .{ .ref = "{\"type\":\"ref/resource\",\"uri\":\"test://other/{x}\"}", .code = -32602 },
    };
    var expected_calls: u32 = 0;
    for (cases, 0..) |c, i| {
        const extra = try std.fmt.allocPrint(f.arena(), "\"ref\":{s},\"argument\":{{\"name\":\"a\",\"value\":\"x\"}}", .{c.ref});
        const v = try f.call(@intCast(i + 1), "completion/complete", meta_none, extra);
        if (c.code) |code| {
            try std.testing.expectEqual(code, errorCode(v).?);
        } else {
            try std.testing.expect(errorCode(v) == null);
            expected_calls += 1;
        }
    }
    // The server rejects an unknown target before it calls the handler.
    try std.testing.expectEqual(expected_calls, completion_calls);
}

// -- Logging ------------------------------------------------------------------------------------

test "log messages need the logging capability and a log level in the request" {
    // Without the logging capability nothing is sent, even with a log level.
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" } });
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "chatty" }, chatty);
    _ = result(try f.call(1, "tools/call", try metaWithLevel(f.arena(), "debug"), "\"name\":\"chatty\""));
    try std.testing.expectEqual(0, try f.notificationCount("notifications/message"));

    var g: ServerFixture = undefined;
    try g.init(.{ .info = .{ .name = "t", .version = "1" }, .capabilities = .{ .logging = .{ .object = .empty } } });
    defer g.deinit();
    try g.server.addToolJson(.{ .name = "chatty" }, chatty);
    // A request without a log level gets no log messages.
    _ = result(try g.call(2, "tools/call", meta_none, "\"name\":\"chatty\""));
    try std.testing.expectEqual(0, try g.notificationCount("notifications/message"));
    // With `warning`, only the `error` message is sent, before the response.
    _ = result(try g.call(3, "tools/call", try metaWithLevel(g.arena(), "warning"), "\"name\":\"chatty\""));
    try std.testing.expectEqual(1, try g.notificationCount("notifications/message"));
    try std.testing.expectEqual(2, g.harness.out.items.len);
    const note = try json.parseTree(g.arena(), g.harness.out.items[0]);
    try std.testing.expectEqualStrings("notifications/message", note.object.get("method").?.string);
    try std.testing.expectEqualStrings("error", note.object.get("params").?.object.get("level").?.string);
    // With `debug`, all three messages are sent.
    _ = result(try g.call(4, "tools/call", try metaWithLevel(g.arena(), "debug"), "\"name\":\"chatty\""));
    try std.testing.expectEqual(3, try g.notificationCount("notifications/message"));
}

test "an unknown log level in the request is invalid params" {
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" }, .capabilities = .{ .logging = .{ .object = .empty } } });
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "chatty" }, chatty);
    const v = try f.call(1, "tools/call", try metaWithLevel(f.arena(), "verbose"), "\"name\":\"chatty\"");
    try std.testing.expectEqual(@as(i64, -32602), errorCode(v).?);
    try std.testing.expectEqual(0, try f.notificationCount("notifications/message"));
}

test "log messages go only to the stream of the request that set the level" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: ServerFixture = undefined;
    try f.init(.{ .info = .{ .name = "t", .version = "1" }, .capabilities = .{ .logging = .{ .object = .empty } } });
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "chatty" }, chatty);

    // A listen stream on its own harness.
    var listen: Harness = .init(io, gpa, &f.server);
    defer listen.deinit();
    var token: Transport.CancelToken = .{};
    const frame = try request(f.arena(), 50, "subscriptions/listen", try metaWithLevel(f.arena(), "debug"), "\"notifications\":{\"toolsListChanged\":true}");
    var future = try io.concurrent(Harness.sendWithToken, .{ &listen, frame, &token });
    var spins: usize = 0;
    while (listen.out.items.len == 0 and spins < 200) : (spins += 1) try io.sleep(.fromMilliseconds(5), .awake);
    try std.testing.expectEqual(1, listen.out.items.len);

    // A tool call with a log level gets its messages on its own stream.
    _ = result(try f.call(51, "tools/call", try metaWithLevel(f.arena(), "debug"), "\"name\":\"chatty\""));
    try std.testing.expectEqual(3, try f.notificationCount("notifications/message"));

    f.server.shutdownSubscriptions(io);
    try future.await(io);
    for (listen.out.items) |out| {
        const v = try json.parseTree(f.arena(), out);
        if (v.object.get("method")) |m| try std.testing.expect(!std.mem.eql(u8, m.string, "notifications/message"));
    }
    try std.testing.expectEqual(2, listen.out.items.len);
}

test "client drops a log notification with an invalid level" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{
        .gpa = gpa,
        .results = &.{"{\"resultType\":\"complete\",\"content\":[]}"},
        .notes = &.{
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"loud\",\"data\":\"bad\"}}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"good\"}}",
        },
    };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info, .log_level = .debug });
    defer client.deinit();
    client.connect(script.transport());

    const Sink = struct {
        count: u32 = 0,
        level: ?types.LoggingLevel = null,
        fn onLog(userdata: ?*anyopaque, params: types.LoggingMessageNotificationParams) void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.count += 1;
            self.level = params.level;
        }
    };
    var sink: Sink = .{};
    _ = try client.callTool(arena, "any", null, .{ .on_log = Sink.onLog, .userdata = &sink });
    try std.testing.expectEqual(1, sink.count);
    try std.testing.expectEqual(types.LoggingLevel.info, sink.level.?);
    // The request carried the log level in `_meta`.
    const params = try script.sentParams(arena, 0);
    try std.testing.expectEqualStrings("debug", params.object.get("_meta").?.object.get("io.modelcontextprotocol/logLevel").?.string);
}

// -- Pagination ---------------------------------------------------------------------------------

test "server cursors are stable" {
    var f: ServerFixture = undefined;
    var options: Server.Options = .{ .info = .{ .name = "t", .version = "1" } };
    options.limits.page_size = 2;
    try f.init(options);
    defer f.deinit();
    try f.server.addToolJson(.{ .name = "a" }, noop);
    try f.server.addToolJson(.{ .name = "b" }, noop);
    try f.server.addToolJson(.{ .name = "c" }, noop);

    const first = result(try f.call(1, "tools/list", meta_none, ""));
    const cursor = try f.arena().dupe(u8, first.object.get("nextCursor").?.string);
    const extra = try std.fmt.allocPrint(f.arena(), "\"cursor\":\"{s}\"", .{cursor});
    const again = result(try f.call(2, "tools/list", meta_none, extra));
    const once_more = result(try f.call(3, "tools/list", meta_none, extra));
    try std.testing.expectEqualStrings("c", again.object.get("tools").?.array.items[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("c", once_more.object.get("tools").?.array.items[0].object.get("name").?.string);
    // A second listing from the start hands out the same cursor.
    const restart = result(try f.call(4, "tools/list", meta_none, ""));
    try std.testing.expectEqualStrings(cursor, restart.object.get("nextCursor").?.string);
}

test "client pages through a server page size it does not know" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var options: Server.Options = .{ .info = .{ .name = "t", .version = "1" } };
    options.limits.page_size = 2;
    var server = try Server.init(gpa, io, options);
    defer server.deinit();
    const names = [_][]const u8{ "t1", "t2", "t3", "t4", "t5" };
    for (names) |n| try server.addToolJson(.{ .name = n }, noop);
    var link: mcp.transport.memory.ClientLink = .init(io, gpa, &server);
    var client: Client = .init(gpa, io, .{ .info = client_info });
    defer client.deinit();
    client.connect(link.transport());

    var seen: usize = 0;
    var pages: usize = 0;
    var cursor: ?[]const u8 = null;
    while (true) {
        const page = try client.listTools(arena, cursor, .{});
        pages += 1;
        seen += page.tools.len;
        cursor = page.nextCursor orelse break;
    }
    try std.testing.expectEqual(names.len, seen);
    try std.testing.expectEqual(3, pages);
}

test "client passes cursors back unchanged, also an empty cursor" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var script: Scripted = .{ .gpa = gpa, .results = &.{
        "{\"resultType\":\"complete\",\"tools\":[],\"nextCursor\":\"\"}",
        "{\"resultType\":\"complete\",\"tools\":[],\"nextCursor\":\"a+b/=?x y%20\"}",
        "{\"resultType\":\"complete\",\"tools\":[]}",
    } };
    defer script.deinit();
    var client: Client = .init(gpa, std.testing.io, .{ .info = client_info });
    defer client.deinit();
    client.connect(script.transport());

    const first = try client.listTools(arena, null, .{});
    try std.testing.expect(first.nextCursor != null);
    try std.testing.expectEqual(0, first.nextCursor.?.len);
    const second = try client.listTools(arena, first.nextCursor, .{});
    try std.testing.expectEqualStrings("", (try script.sentParams(arena, 1)).object.get("cursor").?.string);
    const third = try client.listTools(arena, second.nextCursor, .{});
    try std.testing.expectEqualStrings("a+b/=?x y%20", (try script.sentParams(arena, 2)).object.get("cursor").?.string);
    try std.testing.expect(third.nextCursor == null);
    try std.testing.expect((try script.sentParams(arena, 0)).object.get("cursor") == null);
}
