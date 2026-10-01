//! The MCP client over the typed channel against the SDK server, on a loopback socket. Raw
//! HTTP/2 calls check the status codes and the metadata that the SDK client never sends.
const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const mcp = @import("mcp");
const types = mcp.types;
const json = mcp.json;
const Client = mcp.Client;
const jwt = mcp.auth.jwt;
const grpc_server = @import("transport/grpc_server.zig");
const typed_client = @import("transport/typed_client.zig");
const Connection = @import("http2/Connection.zig");
const lpm = @import("grpc/lpm.zig");
const codec = @import("protobuf/codec.zig");
const pb = @import("protobuf/mcp_messages.zig");
const service = @import("typed/service.zig");

const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const sum_schema =
    \\{"type":"object","properties":{"sum":{"type":"integer"}},"required":["sum"]}
;

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    // The typed binding drops the progress notification.
    try ctx.progress(50, 100, null);
    var structured: std.json.ObjectMap = .empty;
    try structured.put(ctx.arena, "sum", .{ .integer = args.a + args.b });
    var result = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b});
    result.structuredContent = .{ .object = structured };
    return .{ .complete = result };
}

fn media(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const blocks = try ctx.arena.alloc(types.ContentBlock, 4);
    const audience = try ctx.arena.alloc(types.Role, 1);
    audience[0] = .user;
    blocks[0] = .{ .image = .{ .data = png, .mimeType = "image/png", .annotations = .{ .audience = audience, .priority = 0.5 } } };
    blocks[1] = .{ .audio = .{ .data = "UklGRg==", .mimeType = "audio/wav" } };
    blocks[2] = .{ .resource = .{ .resource = .{ .blob = .{ .uri = "test://bin", .mimeType = "application/octet-stream", .blob = "AAEC" } } } };
    blocks[3] = .{ .resource_link = .{ .name = "doc", .uri = "test://doc", .mimeType = "text/plain", .size = 12 } };
    return .{ .complete = .{ .content = blocks } };
}

fn arrayResult(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var result = try types.CallToolResult.text(ctx.arena, "[]", .{});
    result.structuredContent = .{ .array = .init(ctx.arena) };
    return .{ .complete = result };
}

fn askName(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    if (try ctx.elicitResponse("user_name")) |resp| {
        const name = json.getString(resp.content.?, "name") orelse "?";
        return .{ .complete = try types.CallToolResult.text(ctx.arena, "hello {s}", .{name}) };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "Name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", "Your name", true));
    try ir.setStateFmt("{{\"round\":1}}", .{});
    return .{ .input_required = ir };
}

fn slow(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    var waited: u32 = 0;
    while (waited < 5000) : (waited += 20) {
        try ctx.checkCancel();
        try ctx.io.sleep(.fromMilliseconds(20), .awake);
    }
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "late", .{}) };
}

fn whoami(ctx: *mcp.RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    const subject = if (ctx.principal()) |p| p.subject orelse "?" else "nobody";
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{s}", .{subject}) };
}

fn readText(ctx: *mcp.RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "hello" } };
    return .{ .complete = .{ .contents = contents } };
}

fn readBinary(ctx: *mcp.RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .blob = .{ .uri = uri, .mimeType = "image/png", .blob = png } };
    return .{ .complete = .{ .contents = contents } };
}

fn readItem(ctx: *mcp.RequestContext, uri: []const u8, vars: []const mcp.UriTemplate.Variable) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = try std.fmt.allocPrint(ctx.arena, "item {s}", .{vars[0].value}) } };
    return .{ .complete = .{ .contents = contents } };
}

fn greet(ctx: *mcp.RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    const name = if (args) |a| a.map.get("name") orelse "?" else "?";
    const messages = try ctx.arena.alloc(types.PromptMessage, 2);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = try std.fmt.allocPrint(ctx.arena, "Hello {s}", .{name}) } } };
    messages[1] = .{ .role = .assistant, .content = .{ .resource = .{ .resource = .{ .text = .{ .uri = "test://text", .text = "context" } } } } };
    return .{ .complete = .{ .description = "A greeting", .messages = messages } };
}

fn completeValues(ctx: *mcp.RequestContext, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion {
    const values = try ctx.arena.alloc([]const u8, 2);
    values[0] = try std.fmt.allocPrint(ctx.arena, "{s}1", .{params.argument.value});
    values[1] = try std.fmt.allocPrint(ctx.arena, "{s}2", .{params.argument.value});
    return .{ .values = values, .total = 5, .hasMore = true };
}

fn answerForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"name\":\"Bob\"}") };
}

const Recorder = struct {
    progress: u32 = 0,

    fn onProgress(userdata: ?*anyopaque, params: types.ProgressNotificationParams) void {
        const self: *Recorder = @ptrCast(@alignCast(userdata.?));
        _ = params;
        self.progress += 1;
    }
};

/// The count of tools of the fixture. The page size is 2, so `tools/list` has 4 pages.
const tool_count = 7;

const FixtureOptions = struct {
    fallback: typed_client.Fallback = .none,
    auth: ?*const mcp.auth.ResourceServer = null,
    metadata: []const Connection.Header = &.{},
};

const Fixture = struct {
    server: mcp.Server,
    transport: grpc_server.Server,
    future: Io.Future(void),
    channel: *typed_client.TypedChannel,
    client: Client,

    fn start(self: *Fixture, options: FixtureOptions) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        var limits: mcp.Limits = .{};
        limits.page_size = 2;
        self.server = try mcp.Server.init(gpa, io, .{
            .info = .{ .name = "typed-test", .version = "1" },
            .capabilities = .{ .tools = .{}, .completions = .{ .object = .empty } },
            .mrtr = .{ .elicitation = true },
            .limits = limits,
            .invalid_args_policy = .rpc_error,
        });
        errdefer self.server.deinit();
        try self.server.addTool(.{ .name = "add", .title = "Add", .description = "Adds two numbers", .output_schema = sum_schema, .annotations = .{ .readOnlyHint = true } }, add);
        try self.server.addToolJson(.{ .name = "media", .description = "Returns media" }, media);
        try self.server.addToolJson(.{ .name = "array_result" }, arrayResult);
        try self.server.addToolJson(.{ .name = "ask_name" }, askName);
        try self.server.addToolJson(.{ .name = "slow" }, slow);
        try self.server.addToolJson(.{ .name = "whoami" }, whoami);
        try self.server.addToolJson(.{ .name = "seventh", .meta = try json.parseTree(self.server.registry_arena.allocator(), "{\"k\":\"v\"}") }, whoami);
        try self.server.addResource(.{ .uri = "test://text", .name = "Text", .mime_type = "text/plain" }, readText);
        try self.server.addResource(.{ .uri = "test://binary", .name = "Binary", .mime_type = "image/png", .size = 70 }, readBinary);
        try self.server.addResourceTemplate(.{ .uri_template = "test://items/{id}", .name = "Item", .description = "An item" }, readItem);
        try self.server.addPrompt(.{ .name = "greet", .title = "Greet", .arguments = &.{.{ .name = "name", .description = "Who", .required = true }} }, greet);
        self.server.setCompletionHandler(completeValues);
        self.transport = .init(io, gpa, &self.server, .{ .port = 0, .auth = options.auth, .bindings = .{ .tunnel = true, .typed = true } });
        try self.transport.bind();
        self.future = try io.concurrent(serveIgnoringErrors, .{&self.transport});
        self.channel = try typed_client.TypedChannel.init(io, gpa, .{
            .channel = .{ .host = "127.0.0.1", .port = self.transport.bound_port, .extra_metadata = options.metadata },
            .fallback = options.fallback,
        });
        self.client = .init(gpa, io, .{
            .info = .{ .name = "cli", .version = "1" },
            .capabilities = .{ .elicitation = .{} },
            .hooks = .{ .elicit_form = answerForm },
        });
        self.client.connect(self.channel.transport());
    }

    fn serveIgnoringErrors(t: *grpc_server.Server) void {
        t.serve() catch {};
    }

    fn stop(self: *Fixture) void {
        const io = std.testing.io;
        self.client.deinit();
        self.channel.deinit();
        self.transport.shutdown();
        self.future.await(io);
        self.transport.deinit();
        self.server.deinit();
    }
};

const timeout: Client.RequestOptions = .{ .timeout = .fromSeconds(10) };

test "typed: every method of the typed service from the MCP client" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The server merges the pages of the list into one response.
    const tools = try f.client.listTools(arena, null, timeout);
    try std.testing.expectEqual(tool_count, tools.tools.len);
    try std.testing.expect(tools.nextCursor == null);
    try std.testing.expectEqualStrings("add", tools.tools[0].name);
    try std.testing.expectEqualStrings("Add", tools.tools[0].title.?);
    try std.testing.expect(tools.tools[0].outputSchema != null);
    try std.testing.expect(tools.tools[0].annotations.?.readOnlyHint.?);
    try std.testing.expectEqualStrings("v", json.getString(tools.tools[6]._meta.?, "k").?);
    try std.testing.expectEqualStrings("typed-test", tools._meta.?.@"io.modelcontextprotocol/serverInfo".?.name);

    // A tool with structured content. The progress notification does not arrive.
    var rec: Recorder = .{};
    var diag: Client.Diagnostics = .{};
    var options = timeout;
    options.on_progress = Recorder.onProgress;
    options.userdata = &rec;
    options.diagnostics = &diag;
    const sum = try f.client.callTool(arena, "add", .{ .a = 40, .b = 2 }, options);
    try std.testing.expectEqualStrings("42", sum.content[0].text.text);
    try std.testing.expectEqual(@as(i64, 42), sum.structuredContent.?.object.get("sum").?.integer);
    try std.testing.expect(!diag.structured_content_invalid);
    try std.testing.expectEqual(0, rec.progress);

    // Images, audio and resources as bytes, with annotations.
    const m = try f.client.callTool(arena, "media", null, timeout);
    try std.testing.expectEqual(4, m.content.len);
    try std.testing.expectEqualStrings(png, m.content[0].image.data);
    try std.testing.expectEqual(@as(f64, 0.5), m.content[0].image.annotations.?.priority.?);
    try std.testing.expectEqual(types.Role.user, m.content[0].image.annotations.?.audience.?[0]);
    try std.testing.expectEqualStrings("audio/wav", m.content[1].audio.mimeType);
    try std.testing.expectEqualStrings("AAEC", m.content[2].resource.resource.blob.blob);
    try std.testing.expectEqual(@as(i64, 12), m.content[3].resource_link.size.?);

    // A multi round-trip tool call: the hook answers, and the client sends the call again.
    const greeted = try f.client.callTool(arena, "ask_name", null, timeout);
    try std.testing.expectEqualStrings("hello Bob", greeted.content[0].text.text);

    // Resources: text, binary, templates.
    const resources = try f.client.listResources(arena, null, timeout);
    try std.testing.expectEqual(2, resources.resources.len);
    try std.testing.expectEqual(@as(i64, 70), resources.resources[1].size.?);
    const text = try f.client.readResource(arena, "test://text", timeout);
    try std.testing.expectEqualStrings("hello", text.contents[0].text.text);
    try std.testing.expect(text.ttlMs != null);
    const binary = try f.client.readResource(arena, "test://binary", timeout);
    try std.testing.expectEqualStrings(png, binary.contents[0].blob.blob);
    const templates = try f.client.listResourceTemplates(arena, null, timeout);
    try std.testing.expectEqualStrings("test://items/{id}", templates.resourceTemplates[0].uriTemplate);
    const item = try f.client.readResource(arena, "test://items/7", timeout);
    try std.testing.expectEqualStrings("item 7", item.contents[0].text.text);

    // Prompts with arguments.
    const prompts = try f.client.listPrompts(arena, null, timeout);
    try std.testing.expectEqualStrings("greet", prompts.prompts[0].name);
    try std.testing.expect(prompts.prompts[0].arguments.?[0].required.?);
    const prompt = try f.client.getPrompt(arena, "greet", .{ .name = "Ada" }, timeout);
    try std.testing.expectEqualStrings("A greeting", prompt.description.?);
    try std.testing.expectEqualStrings("Hello Ada", prompt.messages[0].content.text.text);
    try std.testing.expectEqualStrings("context", prompt.messages[1].content.resource.resource.text.text);

    // Completion for a prompt argument and for a template variable.
    const prompt_params = try json.parseTree(arena, "{\"ref\":{\"type\":\"ref/prompt\",\"name\":\"greet\"},\"argument\":{\"name\":\"name\",\"value\":\"A\"}}");
    const completion = (try f.client.requestAs(arena, types.CompleteResult, "completion/complete", prompt_params, timeout)).result;
    try std.testing.expectEqualStrings("A1", completion.completion.values[0]);
    try std.testing.expectEqual(@as(i64, 5), completion.completion.total.?);
    try std.testing.expect(completion.completion.hasMore.?);
    const template_params = try json.parseTree(arena, "{\"ref\":{\"type\":\"ref/resource\",\"uri\":\"test://items/{id}\"},\"argument\":{\"name\":\"id\",\"value\":\"9\"},\"context\":{\"arguments\":{\"x\":\"y\"}}}");
    const by_template = (try f.client.requestAs(arena, types.CompleteResult, "completion/complete", template_params, timeout)).result;
    try std.testing.expectEqualStrings("92", by_template.completion.values[1]);
}

test "typed: JSON-RPC errors map to status codes and back" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diag: Client.Diagnostics = .{};
    var options = timeout;
    options.diagnostics = &diag;

    // An unknown tool and invalid arguments: -32602 in the trailers, the same error.Rpc as
    // on the other transports.
    try std.testing.expectError(error.Rpc, f.client.callTool(arena, "nope", null, options));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
    try std.testing.expectError(error.Rpc, f.client.callTool(arena, "add", .{ .a = "x" }, options));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
    try std.testing.expectError(error.Rpc, f.client.getPrompt(arena, "nope", null, options));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
    try std.testing.expectError(error.Rpc, f.client.readResource(arena, "test://none", options));
    try std.testing.expectEqualStrings("test://none", json.getString(diag.rpc_error.?.data.?, "uri").?);
    // A long error: no mcp-error-bin, thus the code from mcp-error-code and a shorter message.
    const long_uri = "test://" ++ "x" ** 5000;
    try std.testing.expectError(error.Rpc, f.client.readResource(arena, long_uri, options));
    try std.testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);
    try std.testing.expectEqual(service.max_error_message_bytes, diag.rpc_error.?.message.len);
    try std.testing.expect(diag.rpc_error.?.data == null);

    // A result that the messages cannot carry: -32603 with the reason.
    try std.testing.expectError(error.Rpc, f.client.callTool(arena, "array_result", null, options));
    try std.testing.expectEqual(@as(i64, -32603), diag.rpc_error.?.code);
    try std.testing.expectEqualStrings("The typed gRPC binding cannot express structuredContent that is not a JSON object", diag.rpc_error.?.message);

    // A method without an RPC, and a cursor, fail before a byte goes out.
    try std.testing.expectError(error.InvalidRequest, f.client.discover(arena, timeout));
    try std.testing.expectError(error.InvalidRequest, f.client.listTools(arena, "abc", timeout));

    const io = std.testing.io;
    const port = f.transport.bound_port;
    const unknown = try rawCall(gpa, io, port, service.Rpc.call_tool.path(), &.{}, try encodeCall(arena, "nope", null, null));
    defer unknown.deinit(gpa);
    try std.testing.expectEqualStrings("3", unknown.grpc_status.?);
    try std.testing.expectEqualStrings("-32602", unknown.error_code.?);

    // Malformed protobuf: INVALID_ARGUMENT with -32700.
    const malformed = try rawCall(gpa, io, port, service.Rpc.list_tools.path(), &.{}, &.{ 0x0a, 0x05 });
    defer malformed.deinit(gpa);
    try std.testing.expectEqualStrings("3", malformed.grpc_status.?);
    try std.testing.expectEqualStrings("-32700", malformed.error_code.?);

    // An RPC that the service does not have.
    const missing = try rawCall(gpa, io, port, "/model_context_protocol.Mcp/Initialize", &.{}, "");
    defer missing.deinit(gpa);
    try std.testing.expectEqualStrings("12", missing.grpc_status.?);

    // A routing header that does not match the message: -32020.
    const mismatch = try rawCall(gpa, io, port, service.Rpc.call_tool.path(), &.{.{ .name = "mcp_tool", .value = "other" }}, try encodeCall(arena, "add", "{\"a\":1,\"b\":2}", null));
    defer mismatch.deinit(gpa);
    try std.testing.expectEqualStrings("3", mismatch.grpc_status.?);
    try std.testing.expectEqualStrings("-32020", mismatch.error_code.?);

    // A foreign client without _meta and with the matching routing header: the server adds
    // the protocol version and empty capabilities.
    const plain = try rawCall(gpa, io, port, service.Rpc.call_tool.path(), &.{.{ .name = "mcp_tool", .value = "add" }}, try encodeCall(arena, "add", "{\"a\":1,\"b\":2}", null));
    defer plain.deinit(gpa);
    try std.testing.expectEqualStrings("0", plain.grpc_status.?);
    const response = try codec.decode(pb.CallToolResponse, arena, plain.message.?, .{});
    try std.testing.expectEqualStrings("3", response.content[0].text.?.text);
    try std.testing.expectEqual(@as(i64, 3), response.structured_content.?.object.get("sum").?.integer);

    // Another protocol version in the metadata: the server answers -32022.
    const old = try rawCall(gpa, io, port, service.Rpc.list_tools.path(), &.{.{ .name = "mcp-protocol-version", .value = "2025-06-18" }}, "");
    defer old.deinit(gpa);
    try std.testing.expectEqualStrings("3", old.grpc_status.?);
    try std.testing.expectEqualStrings("-32022", old.error_code.?);
    // The metadata and _meta disagree: -32020.
    const disagree = try rawCall(gpa, io, port, service.Rpc.list_tools.path(), &.{.{ .name = "mcp-protocol-version", .value = "2025-06-18" }}, try encodeList(arena, "{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}"));
    defer disagree.deinit(gpa);
    try std.testing.expectEqualStrings("-32020", disagree.error_code.?);

    // A server without the typed binding, and one without the tunnel.
    var tunnel_only: grpc_server.Server = .init(io, gpa, &f.server, .{ .port = 0 });
    try tunnel_only.bind();
    var tunnel_future = try io.concurrent(Fixture.serveIgnoringErrors, .{&tunnel_only});
    defer {
        tunnel_only.shutdown();
        tunnel_future.await(io);
        tunnel_only.deinit();
    }
    const off = try rawCall(gpa, io, tunnel_only.bound_port, service.Rpc.list_tools.path(), &.{}, "");
    defer off.deinit(gpa);
    try std.testing.expectEqualStrings("12", off.grpc_status.?);
    var typed_only: grpc_server.Server = .init(io, gpa, &f.server, .{ .port = 0, .bindings = .{ .tunnel = false, .typed = true } });
    try typed_only.bind();
    var typed_future = try io.concurrent(Fixture.serveIgnoringErrors, .{&typed_only});
    defer {
        typed_only.shutdown();
        typed_future.await(io);
        typed_only.deinit();
    }
    const no_tunnel = try rawCall(gpa, io, typed_only.bound_port, grpc_server.call_path, &.{}, "");
    defer no_tunnel.deinit(gpa);
    try std.testing.expectEqualStrings("12", no_tunnel.grpc_status.?);
    const typed_ok = try rawCall(gpa, io, typed_only.bound_port, service.Rpc.list_prompts.path(), &.{}, "");
    defer typed_ok.deinit(gpa);
    try std.testing.expectEqualStrings("0", typed_ok.grpc_status.?);
}

test "typed: deadlines and cancellation" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f: Fixture = undefined;
    try f.start(.{});
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The client deadline resets the stream, and the server handler stops.
    try std.testing.expectError(error.Timeout, f.client.callTool(arena, "slow", null, .{ .timeout = .fromMilliseconds(300) }));
    const again = try f.client.callTool(arena, "add", .{ .a = 1, .b = 1 }, timeout);
    try std.testing.expectEqualStrings("2", again.content[0].text.text);

    // The server deadline from grpc-timeout ends the call with DEADLINE_EXCEEDED.
    const late = try rawCall(gpa, io, f.transport.bound_port, service.Rpc.call_tool.path(), &.{.{ .name = "grpc-timeout", .value = "200m" }}, try encodeCall(arena, "slow", null, null));
    defer late.deinit(gpa);
    try std.testing.expectEqualStrings("4", late.grpc_status.?);

    // A cancel token stops the call.
    var token: mcp.transport.CancelToken = .{};
    token.cancel(io, "early");
    try std.testing.expectError(error.Canceled, f.client.callTool(arena, "slow", null, .{ .cancel = &token }));
}

test "typed: the tunnel fallback carries the methods without an RPC" {
    const gpa = std.testing.allocator;
    var f: Fixture = undefined;
    try f.start(.{ .fallback = .tunnel });
    defer f.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const disc = try f.client.discover(arena, timeout);
    try std.testing.expectEqualStrings("2026-07-28", disc.supportedVersions[0]);
    const tools = try f.client.listTools(arena, null, timeout);
    try std.testing.expectEqual(tool_count, tools.tools.len);
}

const secret = "typed-grpc-auth-secret-with-32-bytes";

fn fixedNow() i64 {
    return 1000;
}

test "typed: a bearer token is required when auth is set" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const keys = [_]jwt.Key{.{ .alg = .HS256, .material = .{ .secret = secret } }};
    var jv: mcp.auth.JwtVerifier = .{ .options = .{ .keys = &keys, .audience = "grpc://127.0.0.1/mcp" }, .clock = .{ .fixed = fixedNow } };
    const rs: mcp.auth.ResourceServer = .{
        .resource = "grpc://127.0.0.1/mcp",
        .resource_metadata_url = "https://127.0.0.1/.well-known/oauth-protected-resource/mcp",
        .authorization_servers = &.{"https://as.example"},
        .verifier = jv.verifier(),
    };
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Without a token: UNAUTHENTICATED with a challenge, and the client sees HTTP 401.
    var f: Fixture = undefined;
    try f.start(.{ .auth = &rs });
    defer f.stop();
    const denied = try rawCall(gpa, io, f.transport.bound_port, service.Rpc.list_tools.path(), &.{}, "");
    defer denied.deinit(gpa);
    try std.testing.expectEqualStrings("16", denied.grpc_status.?);
    try std.testing.expect(denied.challenge);
    try std.testing.expectError(error.InvalidResponse, f.client.callTool(arena, "whoami", null, timeout));

    // With a valid token: the handler sees the principal.
    const good = try jwt.signHs256(arena, "{\"sub\":\"alice\",\"aud\":\"grpc://127.0.0.1/mcp\",\"exp\":2000}", secret, null);
    const metadata = [_]Connection.Header{.{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", good }) }};
    const channel = try typed_client.TypedChannel.init(io, gpa, .{ .channel = .{ .host = "127.0.0.1", .port = f.transport.bound_port, .extra_metadata = &metadata } });
    defer channel.deinit();
    var client: Client = .init(gpa, io, .{ .info = .{ .name = "cli", .version = "1" } });
    defer client.deinit();
    client.connect(channel.transport());
    const who = try client.callTool(arena, "whoami", null, timeout);
    try std.testing.expectEqualStrings("alice", who.content[0].text.text);
}

// -- Raw calls ----------------------------------------------------------------------------------

fn encodeCall(arena: std.mem.Allocator, name: []const u8, arguments: ?[]const u8, meta: ?[]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const msg: pb.CallToolRequest = .{
        .common = if (meta) |m| .{ .metadata = try json.parseTree(arena, m) } else null,
        .request = .{ .name = name, .arguments = if (arguments) |a| try json.parseTree(arena, a) else null },
    };
    try codec.encode(pb.CallToolRequest, arena, &out, msg, .{});
    return out.items;
}

fn encodeList(arena: std.mem.Allocator, meta: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try codec.encode(pb.ListToolsRequest, arena, &out, .{ .common = .{ .metadata = try json.parseTree(arena, meta) } }, .{});
    return out.items;
}

const RawCall = struct {
    status: []const u8,
    grpc_status: ?[]const u8 = null,
    error_code: ?[]const u8 = null,
    challenge: bool = false,
    message: ?[]const u8 = null,

    fn deinit(self: RawCall, gpa: std.mem.Allocator) void {
        gpa.free(self.status);
        if (self.grpc_status) |v| gpa.free(v);
        if (self.error_code) |v| gpa.free(v);
        if (self.message) |v| gpa.free(v);
    }
};

/// One unary call with a raw protobuf body.
fn rawCall(gpa: std.mem.Allocator, io: Io, port: u16, path: []const u8, metadata: []const Connection.Header, body: []const u8) !RawCall {
    const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const in_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(in_buf);
    const out_buf = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(out_buf);
    var reader = stream.reader(io, in_buf);
    var writer = stream.writer(io, out_buf);
    const conn = try Connection.init(gpa, io, &reader.interface, &writer.interface, .{ .role = .client });
    defer conn.deinit();
    try conn.handshake();
    var run_future = try io.concurrent(Connection.run, .{conn});
    defer {
        conn.shutdown();
        stream.shutdown(io, .send) catch {};
        run_future.await(io);
    }
    const h2 = try conn.openStream();
    defer h2.close();
    var headers: std.ArrayList(Connection.Header) = .empty;
    defer headers.deinit(gpa);
    try headers.appendSlice(gpa, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    });
    try headers.appendSlice(gpa, metadata);
    try h2.sendHeaders(headers.items, false);
    try lpm.write(h2, gpa, body, true);
    const response = try h2.waitHeaders();
    var result: RawCall = .{ .status = try gpa.dupe(u8, Connection.findHeader(response, ":status") orelse "") };
    var source = response;
    if (Connection.findHeader(response, "grpc-status") == null) {
        while (try lpm.read(h2, gpa, 1 << 20)) |payload| {
            if (result.message) |old| gpa.free(old);
            result.message = payload;
        }
        source = try h2.waitEnd();
    }
    if (Connection.findHeader(source, "grpc-status")) |v| result.grpc_status = try gpa.dupe(u8, v);
    if (Connection.findHeader(source, service.header_error_code)) |v| result.error_code = try gpa.dupe(u8, v);
    result.challenge = Connection.findHeader(source, "www-authenticate") != null;
    return result;
}
