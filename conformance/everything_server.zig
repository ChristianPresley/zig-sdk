//! The conformance "everything server": every tool, resource and prompt that the official
//! conformance suite for MCP 2026-07-28 expects. Serves Streamable HTTP by default and
//! stdio with `--stdio`. `--grpc-port` adds the gRPC tunnel, `--grpc-typed` also serves the
//! typed service `model_context_protocol.Mcp` on that port, and `--ws-port` adds the
//! WebSocket binding on `ws://127.0.0.1:N/mcp`. `--no-tunnel` with `--grpc-typed` removes the
//! tunnel from the gRPC port.
//!
//! Usage: mcp-conformance-server [--port N] [--grpc-port N] [--grpc-typed] [--no-tunnel] [--ws-port N] [--stdio]
const std = @import("std");
const builtin = @import("builtin");
const mcp = @import("mcp");
const mcp_grpc = @import("mcp_grpc");
const types = mcp.types;
const Ctx = mcp.RequestContext;
const Result = mcp.Outcome(types.CallToolResult);

const png_1x1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const wav_empty = "UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA=";

const NoArgs = struct {};

fn textResult(ctx: *Ctx, comptime fmt: []const u8, args: anytype) anyerror!Result {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, fmt, args) };
}

fn simpleText(ctx: *Ctx, _: NoArgs) anyerror!Result {
    return textResult(ctx, "This is a simple text response", .{});
}

fn imageContent(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const blocks = try ctx.arena.alloc(types.ContentBlock, 1);
    blocks[0] = .{ .image = .{ .data = png_1x1, .mimeType = "image/png" } };
    return .{ .complete = .{ .content = blocks } };
}

fn audioContent(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const blocks = try ctx.arena.alloc(types.ContentBlock, 1);
    blocks[0] = .{ .audio = .{ .data = wav_empty, .mimeType = "audio/wav" } };
    return .{ .complete = .{ .content = blocks } };
}

fn embeddedResource(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const blocks = try ctx.arena.alloc(types.ContentBlock, 1);
    blocks[0] = .{ .resource = .{ .resource = .{ .text = .{ .uri = "test://embedded-resource", .mimeType = "text/plain", .text = "This is an embedded resource" } } } };
    return .{ .complete = .{ .content = blocks } };
}

fn multipleContentTypes(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const blocks = try ctx.arena.alloc(types.ContentBlock, 3);
    blocks[0] = .{ .text = .{ .text = "Text content" } };
    blocks[1] = .{ .image = .{ .data = png_1x1, .mimeType = "image/png" } };
    blocks[2] = .{ .resource = .{ .resource = .{ .text = .{ .uri = "test://mixed-content-resource", .mimeType = "text/plain", .text = "Mixed content resource" } } } };
    return .{ .complete = .{ .content = blocks } };
}

fn errorHandling(ctx: *Ctx, _: NoArgs) anyerror!Result {
    return .{ .complete = try types.CallToolResult.err(ctx.arena, "Tool execution failed as requested", .{}) };
}

fn withProgress(ctx: *Ctx, _: NoArgs) anyerror!Result {
    try ctx.progress(0, 100, "Starting");
    try ctx.progress(50, 100, "Halfway");
    try ctx.progress(100, 100, "Done");
    return textResult(ctx, "Progress complete", .{});
}

fn withLogging(ctx: *Ctx, _: NoArgs) anyerror!Result {
    try ctx.logText(.info, "everything-server", "Tool started", .{});
    try ctx.logText(.debug, "everything-server", "Detail", .{});
    try ctx.logText(.info, "everything-server", "Tool finished", .{});
    return textResult(ctx, "Logging complete", .{});
}

fn missingCapability(ctx: *Ctx, _: NoArgs) anyerror!Result {
    // Never reached without the sampling capability: the registration requires it.
    return textResult(ctx, "capability present", .{});
}

fn streamingElicitation(ctx: *Ctx, _: NoArgs) anyerror!Result {
    return textResult(ctx, "Streaming elicitation acknowledged", .{});
}

fn sampling(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.sampleResponse("sample")) |r| {
        return textResult(ctx, "Sampled with model {s}", .{r.model});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.sample("sample", try samplingParams(ctx, "Say hello"));
    return .{ .input_required = ir };
}

fn samplingParams(ctx: *Ctx, prompt: []const u8) !types.CreateMessageRequestParams {
    const messages = try ctx.arena.alloc(types.SamplingMessage, 1);
    messages[0] = .{ .role = .user, .content = .{ .single = .{ .text = .{ .text = prompt } } } };
    return .{ .messages = messages, .maxTokens = 100 };
}

fn elicitation(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.elicitResponse("input")) |r| {
        return textResult(ctx, "Elicitation {t}", .{r.action});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("input", "Please provide input", try mcp.InputRequired.stringSchema(ctx.arena, "value", "A value", true));
    return .{ .input_required = ir };
}

fn elicitationEnums(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.elicitResponse("choice")) |r| {
        return textResult(ctx, "Choice {t}", .{r.action});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    var schema: types.ElicitRequestFormParams.RequestedSchema = .{ .properties = .{} };
    const values = try ctx.arena.alloc([]const u8, 2);
    values[0] = "red";
    values[1] = "blue";
    try schema.properties.map.put(ctx.arena, "color", .{ .@"enum" = .{ .single_select = .{ .untitled = .{ .@"enum" = values } } } });
    try ir.elicitForm("choice", "Pick a color", schema);
    return .{ .input_required = ir };
}

fn elicitationDefaults(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.elicitResponse("defaults")) |r| {
        return textResult(ctx, "Defaults {t}", .{r.action});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    var schema: types.ElicitRequestFormParams.RequestedSchema = .{ .properties = .{} };
    try schema.properties.map.put(ctx.arena, "name", .{ .string = .{ .default = "anonymous" } });
    try schema.properties.map.put(ctx.arena, "count", .{ .number = .{ .type = .integer, .default = 1 } });
    try ir.elicitForm("defaults", "Confirm the defaults", schema);
    return .{ .input_required = ir };
}

fn triggerToolChange(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const enabled = state.hidden_tool_enabled.load(.acquire);
    _ = ctx.server.setToolEnabled(ctx.io, "test_hidden_tool", !enabled);
    state.hidden_tool_enabled.store(!enabled, .release);
    return textResult(ctx, "Tool list changed", .{});
}

fn triggerPromptChange(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const enabled = state.hidden_prompt_enabled.load(.acquire);
    _ = ctx.server.setPromptEnabled(ctx.io, "test_hidden_prompt", !enabled);
    state.hidden_prompt_enabled.store(!enabled, .release);
    return textResult(ctx, "Prompt list changed", .{});
}

/// The URI of the resource that `test_trigger_resource_update` announces.
const watched_uri = "test://watched-resource";

/// Announce a change of the watched resource and of the resource list. A listen stream with
/// `resourceSubscriptions` and `resourcesListChanged` then gets both notifications.
fn triggerResourceUpdate(ctx: *Ctx, _: NoArgs) anyerror!Result {
    ctx.server.notifyResourceUpdated(ctx.io, watched_uri);
    ctx.server.notifyResourcesListChanged(ctx.io);
    return textResult(ctx, "Resource updated", .{});
}

fn hiddenTool(ctx: *Ctx, _: NoArgs) anyerror!Result {
    return textResult(ctx, "hidden", .{});
}

// -- Tasks extension tools -------------------------------------------------------------------

const GreetArgs = struct { name: []const u8 = "world" };

fn greet(ctx: *Ctx, args: GreetArgs) anyerror!Result {
    return textResult(ctx, "Hello, {s}!", .{args.name});
}

/// Sleep in short steps so a cancellation stops the task quickly.
fn sleepSeconds(ctx: *Ctx, seconds: i64) anyerror!void {
    var remaining_ms: i64 = seconds * 1000;
    while (remaining_ms > 0) : (remaining_ms -= 100) {
        try ctx.checkCancel();
        try ctx.io.sleep(.fromMilliseconds(@min(remaining_ms, 100)), .awake);
    }
}

const SlowArgs = struct { seconds: i64 = 0, label: ?[]const u8 = null };

fn slowCompute(ctx: *Ctx, args: SlowArgs) anyerror!Result {
    if (!ctx.inTask()) return .start_task;
    try sleepSeconds(ctx, @max(args.seconds, 0));
    return textResult(ctx, "computed {s} after {d} s", .{ args.label orelse "job", args.seconds });
}

fn failingJob(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (!ctx.inTask()) return .start_task;
    try sleepSeconds(ctx, 1);
    return .{ .complete = try types.CallToolResult.err(ctx.arena, "The job failed as designed", .{}) };
}

fn protocolErrorJob(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (!ctx.inTask()) return .start_task;
    return ctx.setError(mcp.protocol.errors.internalError("The job hit an internal error as designed"));
}

const ConfirmDeleteArgs = struct { filename: []const u8 = "file.txt" };

fn confirmDelete(ctx: *Ctx, args: ConfirmDeleteArgs) anyerror!Result {
    if (!ctx.inTask()) return .start_task;
    if (try ctx.elicitResponse("confirm")) |r| {
        if (r.action != .accept) return textResult(ctx, "Kept {s}", .{args.filename});
        return textResult(ctx, "Deleted {s}", .{args.filename});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    const message = try std.fmt.allocPrint(ctx.arena, "Delete {s}?", .{args.filename});
    try ir.elicitForm("confirm", message, try mcp.InputRequired.stringSchema(ctx.arena, "confirm", "Type yes", false));
    return .{ .input_required = ir };
}

fn multiInput(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (!ctx.inTask()) return .start_task;
    if (ctx.hasAllResponses(&.{ "first", "second" })) {
        const first = nameFrom((try ctx.elicitResponse("first")).?);
        const second = nameFrom((try ctx.elicitResponse("second")).?);
        return textResult(ctx, "{s} and {s}", .{ first, second });
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    if ((try ctx.elicitResponse("first")) == null) try ir.elicitForm("first", "First name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    if ((try ctx.elicitResponse("second")) == null) try ir.elicitForm("second", "Second name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    return .{ .input_required = ir };
}

fn toolWithTask(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const answer = try ctx.elicitResponse("user_name");
    if (answer == null) {
        var ir: mcp.InputRequired = .init(ctx.arena);
        try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", "Your name", true));
        return .{ .input_required = ir };
    }
    if (!ctx.inTask()) return .start_task;
    return textResult(ctx, "Hello, {s}! The task is done.", .{nameFrom(answer.?)});
}

// -- Multi round-trip request tools ----------------------------------------------------------

fn nameFrom(r: types.ElicitResult) []const u8 {
    const content = r.content orelse return "unknown";
    return mcp.json.getString(content, "name") orelse "unknown";
}

fn irElicitation(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.elicitResponse("user_name")) |r| {
        if (r.action != .accept) return textResult(ctx, "The user declined", .{});
        return textResult(ctx, "Hello, {s}!", .{nameFrom(r)});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", "Your name", true));
    return .{ .input_required = ir };
}

fn irSampling(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.sampleResponse("capital_question")) |r| {
        const answer = switch (r.content) {
            .single => |c| if (c == .text) c.text.text else "(non-text)",
            .list => "(list)",
        };
        return textResult(ctx, "The model ({s}) said: {s}", .{ r.model, answer });
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.sample("capital_question", try samplingParams(ctx, "What is the capital of France?"));
    return .{ .input_required = ir };
}

fn irListRoots(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.rootsResponse("client_roots")) |r| {
        return textResult(ctx, "The client has {d} root(s)", .{r.roots.len});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.listRoots("client_roots");
    return .{ .input_required = ir };
}

fn irRequestState(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.elicitResponse("confirm")) |_| {
        const s = (try ctx.state(struct { nonce: []const u8 })) orelse return textResult(ctx, "state-missing", .{});
        return textResult(ctx, "state-ok {s}", .{s.nonce});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("confirm", "Confirm?", try mcp.InputRequired.stringSchema(ctx.arena, "ok", null, false));
    try ir.setStateFmt("{{\"nonce\":\"request-state-nonce\"}}", .{});
    return .{ .input_required = ir };
}

fn irMultipleInputs(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const have_all = ctx.hasAllResponses(&.{ "user_name", "greeting", "client_roots" });
    if (have_all) {
        const name = nameFrom((try ctx.elicitResponse("user_name")).?);
        const greeting = (try ctx.sampleResponse("greeting")).?;
        const roots = (try ctx.rootsResponse("client_roots")).?;
        return textResult(ctx, "{s}: model {s}, {d} roots", .{ name, greeting.model, roots.roots.len });
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
    try ir.sample("greeting", try samplingParams(ctx, "Say hello"));
    try ir.listRoots("client_roots");
    try ir.setStateFmt("{{\"phase\":\"collect\"}}", .{});
    return .{ .input_required = ir };
}

const MultiRoundState = struct { round: u32, name: ?[]const u8 = null };

fn irMultiRound(ctx: *Ctx, _: NoArgs) anyerror!Result {
    const saved = (try ctx.state(MultiRoundState)) orelse MultiRoundState{ .round = 0 };
    if (saved.round == 0) {
        var ir: mcp.InputRequired = .init(ctx.arena);
        try ir.elicitForm("step1", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
        try ir.setStateFmt("{{\"round\":1}}", .{});
        return .{ .input_required = ir };
    }
    if (saved.round == 1) {
        const r = (try ctx.elicitResponse("step1")) orelse {
            var ir: mcp.InputRequired = .init(ctx.arena);
            try ir.elicitForm("step1", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
            try ir.setStateFmt("{{\"round\":1}}", .{});
            return .{ .input_required = ir };
        };
        var ir: mcp.InputRequired = .init(ctx.arena);
        try ir.elicitForm("step2", "What is your favorite color?", try mcp.InputRequired.stringSchema(ctx.arena, "color", null, true));
        try ir.setStateFmt("{{\"round\":2,\"name\":{f}}}", .{std.json.fmt(nameFrom(r), .{})});
        return .{ .input_required = ir };
    }
    const r = (try ctx.elicitResponse("step2")) orelse return textResult(ctx, "missing step2", .{});
    const color = if (r.content) |c| mcp.json.getString(c, "color") orelse "?" else "?";
    return textResult(ctx, "{s} likes {s}", .{ saved.name orelse "someone", color });
}

fn irTamperedState(ctx: *Ctx, _: NoArgs) anyerror!Result {
    if (try ctx.elicitResponse("confirm")) |_| {
        return textResult(ctx, "state accepted", .{});
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("confirm", "Confirm?", try mcp.InputRequired.stringSchema(ctx.arena, "ok", null, false));
    try ir.setStateFmt("{{\"secret\":\"do-not-tamper\"}}", .{});
    return .{ .input_required = ir };
}

fn irCapabilities(ctx: *Ctx, _: NoArgs) anyerror!Result {
    var ir: mcp.InputRequired = .init(ctx.arena);
    var pending: usize = 0;
    if (ctx.hasClientCapability(.elicitation_form) and (try ctx.elicitResponse("user_name")) == null) {
        try ir.elicitForm("user_name", "What is your name?", try mcp.InputRequired.stringSchema(ctx.arena, "name", null, true));
        pending += 1;
    }
    if (ctx.hasClientCapability(.sampling) and (try ctx.sampleResponse("greeting")) == null) {
        try ir.sample("greeting", try samplingParams(ctx, "Say hello"));
        pending += 1;
    }
    if (ctx.hasClientCapability(.roots) and (try ctx.rootsResponse("client_roots")) == null) {
        try ir.listRoots("client_roots");
        pending += 1;
    }
    if (pending > 0) return .{ .input_required = ir };
    return textResult(ctx, "All declared capabilities were used", .{});
}

fn jsonSchema2020(ctx: *Ctx, args: std.json.Value) anyerror!Result {
    return textResult(ctx, "{s}", .{try mcp.json.writeAlloc(ctx.arena, args)});
}

const HeaderArgs = struct {
    region: []const u8,
    priority: ?i64 = null,
    verbose: ?bool = null,
    pub const json_schema = .{ .fields = .{
        .region = .{ .header = "Region" },
        .priority = .{ .header = "Priority" },
        .verbose = .{ .header = "Verbose" },
    } };
};

fn xMcpHeader(ctx: *Ctx, args: HeaderArgs) anyerror!Result {
    return textResult(ctx, "region={s} priority={?d} verbose={?}", .{ args.region, args.priority, args.verbose });
}

// -- Resources --------------------------------------------------------------------------------

fn readStaticText(ctx: *Ctx, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "This is a static text resource" } };
    return .{ .complete = .{ .contents = contents } };
}

fn readStaticBinary(ctx: *Ctx, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .blob = .{ .uri = uri, .mimeType = "image/png", .blob = png_1x1 } };
    return .{ .complete = .{ .contents = contents } };
}

fn readWatched(ctx: *Ctx, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "watched" } };
    return .{ .complete = .{ .contents = contents } };
}

fn readTemplate(ctx: *Ctx, uri: []const u8, vars: []const mcp.UriTemplate.Variable) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{
        .uri = uri,
        .mimeType = "application/json",
        .text = try std.fmt.allocPrint(ctx.arena, "{{\"id\":\"{s}\",\"templateTest\":true,\"data\":\"Template data for {s}\"}}", .{ vars[0].value, vars[0].value }),
    } };
    return .{ .complete = .{ .contents = contents } };
}

// -- Prompts ----------------------------------------------------------------------------------

fn oneMessage(ctx: *Ctx, content: types.ContentBlock) ![]types.PromptMessage {
    const messages = try ctx.arena.alloc(types.PromptMessage, 1);
    messages[0] = .{ .role = .user, .content = content };
    return messages;
}

fn simplePrompt(ctx: *Ctx, _: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    return .{ .complete = .{ .description = "A simple prompt", .messages = try oneMessage(ctx, .{ .text = .{ .text = "This is a simple prompt" } }) } };
}

fn promptWithArguments(ctx: *Ctx, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    const a1 = if (args) |a| a.map.get("arg1") orelse "" else "";
    const a2 = if (args) |a| a.map.get("arg2") orelse "" else "";
    const text = try std.fmt.allocPrint(ctx.arena, "Prompt with arg1={s} and arg2={s}", .{ a1, a2 });
    return .{ .complete = .{ .messages = try oneMessage(ctx, .{ .text = .{ .text = text } }) } };
}

fn promptWithEmbeddedResource(ctx: *Ctx, args: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    const uri = if (args) |a| a.map.get("resourceUri") orelse "test://example-resource" else "test://example-resource";
    const messages = try ctx.arena.alloc(types.PromptMessage, 2);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = "Here is a resource" } } };
    messages[1] = .{ .role = .user, .content = .{ .resource = .{ .resource = .{ .text = .{ .uri = uri, .mimeType = "text/plain", .text = "Embedded resource content" } } } } };
    return .{ .complete = .{ .messages = messages } };
}

fn promptWithImage(ctx: *Ctx, _: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    const messages = try ctx.arena.alloc(types.PromptMessage, 2);
    messages[0] = .{ .role = .user, .content = .{ .text = .{ .text = "Describe this image" } } };
    messages[1] = .{ .role = .user, .content = .{ .image = .{ .data = png_1x1, .mimeType = "image/png" } } };
    return .{ .complete = .{ .messages = messages } };
}

fn irPrompt(ctx: *Ctx, _: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    if (try ctx.elicitResponse("user_context")) |r| {
        const context = if (r.content) |c| mcp.json.getString(c, "context") orelse "" else "";
        const text = try std.fmt.allocPrint(ctx.arena, "Context: {s}", .{context});
        return .{ .complete = .{ .messages = try oneMessage(ctx, .{ .text = .{ .text = text } }) } };
    }
    var ir: mcp.InputRequired = .init(ctx.arena);
    try ir.elicitForm("user_context", "What context should the prompt use?", try mcp.InputRequired.stringSchema(ctx.arena, "context", null, true));
    return .{ .input_required = ir };
}

fn hiddenPrompt(ctx: *Ctx, _: ?std.json.ArrayHashMap([]const u8)) anyerror!mcp.Outcome(types.GetPromptResult) {
    return .{ .complete = .{ .messages = try oneMessage(ctx, .{ .text = .{ .text = "hidden" } }) } };
}

fn complete(ctx: *Ctx, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion {
    _ = ctx;
    _ = params;
    return .{ .values = &.{}, .total = 0, .hasMore = false };
}

const State = struct {
    hidden_tool_enabled: std.atomic.Value(bool) = .init(false),
    hidden_prompt_enabled: std.atomic.Value(bool) = .init(false),
};
var state: State = .{};

const json_schema_2020_12 =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","$defs":{"address":{"$anchor":"addressDef","type":"object","properties":{"street":{"type":"string"},"city":{"type":"string"}}}},"properties":{"name":{"type":"string"},"address":{"$ref":"#/$defs/address"},"contactMethod":{"type":"string","enum":["phone","email"]},"phone":{"type":"string"},"email":{"type":"string"}},"allOf":[{"anyOf":[{"required":["phone"]},{"required":["email"]}]}],"if":{"properties":{"contactMethod":{"const":"phone"}},"required":["contactMethod"]},"then":{"required":["phone"]},"else":{"required":["email"]},"additionalProperties":false}
;

/// The options of the server engine.
fn serverOptions() mcp.Server.Options {
    return .{
        .info = .{ .name = "mcp-conformance-test-server", .version = "0.1.0" },
        .instructions = "Everything server for conformance tests.",
        .capabilities = .{
            .tools = .{ .listChanged = true },
            .prompts = .{ .listChanged = true },
            .resources = .{ .listChanged = true, .subscribe = true },
            .completions = .{ .object = .empty },
            .logging = .{ .object = .empty },
        },
        .mrtr = .{ .elicitation = true, .sampling = true, .sampling_tools = true, .roots = true },
        .tasks = .{},
    };
}

/// Register each tool, resource and prompt of the fixture.
fn register(server: *mcp.Server, io: std.Io) !void {
    try server.addTool(.{ .name = "test_simple_text", .description = "Returns simple text" }, simpleText);
    try server.addTool(.{ .name = "test_image_content", .description = "Returns image content" }, imageContent);
    try server.addTool(.{ .name = "test_audio_content", .description = "Returns audio content" }, audioContent);
    try server.addTool(.{ .name = "test_embedded_resource", .description = "Returns an embedded resource" }, embeddedResource);
    try server.addTool(.{ .name = "test_multiple_content_types", .description = "Returns mixed content" }, multipleContentTypes);
    try server.addTool(.{ .name = "test_error_handling", .description = "Returns an error result" }, errorHandling);
    try server.addTool(.{ .name = "test_tool_with_progress", .description = "Sends progress notifications" }, withProgress);
    try server.addTool(.{ .name = "test_tool_with_logging", .description = "Sends log messages" }, withLogging);
    try server.addTool(.{ .name = "test_logging_tool", .description = "Sends log messages" }, withLogging);
    try server.addTool(.{ .name = "test_missing_capability", .description = "Needs the sampling capability", .requires_client = .{ .sampling = .{} } }, missingCapability);
    try server.addTool(.{ .name = "test_streaming_elicitation", .description = "Elicitation over a stream" }, streamingElicitation);
    try server.addTool(.{ .name = "test_sampling", .description = "Requests sampling" }, sampling);
    try server.addTool(.{ .name = "test_elicitation", .description = "Requests elicitation" }, elicitation);
    try server.addTool(.{ .name = "test_elicitation_sep1330_enums", .description = "Elicitation with enums" }, elicitationEnums);
    try server.addTool(.{ .name = "test_elicitation_sep1034_defaults", .description = "Elicitation with defaults" }, elicitationDefaults);
    try server.addTool(.{ .name = "test_trigger_tool_change", .description = "Changes the tool list" }, triggerToolChange);
    try server.addTool(.{ .name = "test_trigger_prompt_change", .description = "Changes the prompt list" }, triggerPromptChange);
    try server.addTool(.{ .name = "test_trigger_resource_update", .description = "Announces a change of test://watched-resource and of the resource list" }, triggerResourceUpdate);
    try server.addTool(.{ .name = "test_hidden_tool", .description = "Appears after a change" }, hiddenTool);
    try server.addTool(.{ .name = "test_input_required_result_elicitation", .description = "MRTR elicitation" }, irElicitation);
    try server.addTool(.{ .name = "test_input_required_result_sampling", .description = "MRTR sampling" }, irSampling);
    try server.addTool(.{ .name = "test_input_required_result_list_roots", .description = "MRTR roots" }, irListRoots);
    try server.addTool(.{ .name = "test_input_required_result_request_state", .description = "MRTR with state" }, irRequestState);
    try server.addTool(.{ .name = "test_input_required_result_multiple_inputs", .description = "MRTR with several inputs" }, irMultipleInputs);
    try server.addTool(.{ .name = "test_input_required_result_multi_round", .description = "MRTR with three rounds" }, irMultiRound);
    try server.addTool(.{ .name = "test_input_required_result_tampered_state", .description = "MRTR state integrity" }, irTamperedState);
    try server.addTool(.{ .name = "test_input_required_result_capabilities", .description = "MRTR per declared capability" }, irCapabilities);
    try server.addToolJson(.{ .name = "json_schema_2020_12_tool", .description = "Tool with a 2020-12 schema", .input_schema = json_schema_2020_12 }, jsonSchema2020);
    try server.addTool(.{ .name = "test_x_mcp_header", .description = "Tool with header annotations" }, xMcpHeader);
    try server.addTool(.{ .name = "greet", .description = "Greets by name" }, greet);
    try server.addTool(.{ .name = "slow_compute", .description = "Sleeps for some seconds inside a task", .task_support = .optional }, slowCompute);
    try server.addTool(.{ .name = "failing_job", .description = "A task that ends in a tool error", .task_support = .required }, failingJob);
    try server.addTool(.{ .name = "protocol_error_job", .description = "A task that ends in a protocol error", .task_support = .optional }, protocolErrorJob);
    try server.addTool(.{ .name = "confirm_delete", .description = "A task that asks for confirmation", .task_support = .optional }, confirmDelete);
    try server.addTool(.{ .name = "multi_input", .description = "A task that asks two questions at once", .task_support = .optional }, multiInput);
    try server.addTool(.{ .name = "test_tool_with_task", .description = "MRTR round then a task", .task_support = .required }, toolWithTask);
    _ = server.setToolEnabled(io, "test_hidden_tool", false);

    try server.addResource(.{ .uri = "test://static-text", .name = "Static Text Resource", .mime_type = "text/plain", .description = "A static text resource" }, readStaticText);
    try server.addResource(.{ .uri = "test://static-binary", .name = "Static Binary Resource", .mime_type = "image/png", .description = "A static binary resource" }, readStaticBinary);
    try server.addResource(.{ .uri = watched_uri, .name = "Watched Resource", .mime_type = "text/plain" }, readWatched);
    try server.addResourceTemplate(.{ .uri_template = "test://template/{id}/data", .name = "Template Resource", .mime_type = "application/json", .description = "A resource template" }, readTemplate);

    try server.addPrompt(.{ .name = "test_simple_prompt", .description = "A simple prompt" }, simplePrompt);
    try server.addPrompt(.{ .name = "test_prompt_with_arguments", .description = "A prompt with arguments", .arguments = &.{ .{ .name = "arg1", .description = "First argument", .required = true }, .{ .name = "arg2", .description = "Second argument", .required = true } } }, promptWithArguments);
    try server.addPrompt(.{ .name = "test_prompt_with_embedded_resource", .description = "A prompt with an embedded resource", .arguments = &.{.{ .name = "resourceUri", .description = "Resource URI", .required = true }} }, promptWithEmbeddedResource);
    try server.addPrompt(.{ .name = "test_prompt_with_image", .description = "A prompt with an image" }, promptWithImage);
    try server.addPrompt(.{ .name = "test_input_required_result_prompt", .description = "A prompt that needs input" }, irPrompt);
    try server.addPrompt(.{ .name = "test_hidden_prompt", .description = "Appears after a change" }, hiddenPrompt);
    _ = server.setPromptEnabled(io, "test_hidden_prompt", false);
    server.setCompletionHandler(complete);
}

/// The settings from the command line.
const Config = struct {
    port: u16 = 3000,
    stdio: bool = false,
    grpc_port: ?u16 = null,
    grpc_typed: bool = false,
    /// False with `--no-tunnel`: the gRPC port serves the typed service only. A call of the
    /// tunnel then gets `UNIMPLEMENTED`, as a call of an unknown service.
    grpc_tunnel: bool = true,
    ws_port: ?u16 = null,

    fn grpcBindings(self: Config) mcp_grpc.server.Bindings {
        return .{ .tunnel = self.grpc_tunnel, .typed = self.grpc_typed };
    }
};

/// Parse the command line. The function ignores an unknown argument.
fn parseArgs(args: []const []const u8) !Config {
    var config: Config = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            i += 1;
            config.port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--grpc-port") and i + 1 < args.len) {
            i += 1;
            config.grpc_port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, args[i], "--grpc-typed")) {
            config.grpc_typed = true;
        } else if (std.mem.eql(u8, args[i], "--no-tunnel")) {
            config.grpc_tunnel = false;
        } else if (std.mem.eql(u8, args[i], "--ws-port") and i + 1 < args.len) {
            i += 1;
            config.ws_port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, args[i], "--stdio")) {
            config.stdio = true;
        }
    }
    // Without the tunnel and without the typed service, the gRPC port has no service.
    if (!config.grpc_tunnel and !config.grpc_typed) return error.NoGrpcService;
    return config;
}

pub fn main(init: std.process.Init) !void {
    // In a release build without libc, `init.gpa` is the debug allocator of std, with one lock for
    // every allocation of every thread. The allocator of std for many threads has no such lock.
    const gpa = if (builtin.mode == .Debug) init.gpa else std.heap.smp_allocator;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var config = parseArgs(args) catch |e| {
        if (e == error.NoGrpcService) std.log.err("--no-tunnel needs --grpc-typed", .{});
        return e;
    };
    if (init.environ_map.get("PORT")) |p| config.port = std.fmt.parseInt(u16, p, 10) catch config.port;
    const port = config.port;
    const use_stdio = config.stdio;
    const grpc_port = config.grpc_port;
    const grpc_typed = config.grpc_typed;
    const ws_port = config.ws_port;

    var server = try mcp.Server.init(gpa, io, serverOptions());
    defer server.deinit();
    try register(&server, io);

    if (use_stdio) {
        try mcp.transport.stdio.serve(io, gpa, &server);
        return;
    }
    var transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = port });
    defer transport.deinit();
    try transport.bind();
    std.log.info("everything server listening on http://127.0.0.1:{d}/mcp", .{transport.bound_port});

    var grpc_transport: mcp_grpc.Server = .init(io, gpa, &server, .{ .port = grpc_port orelse 0, .bindings = config.grpcBindings() });
    defer grpc_transport.deinit();
    var grpc_future: ?std.Io.Future(void) = null;
    defer if (grpc_future) |*f| {
        grpc_transport.shutdown();
        f.await(io);
    };
    if (grpc_port != null) {
        try grpc_transport.bind();
        const services: []const u8 = if (!config.grpc_tunnel) " with the typed service only" else if (grpc_typed) " with the typed service" else "";
        std.log.info("everything server listening for gRPC on 127.0.0.1:{d}{s}", .{ grpc_transport.bound_port, services });
        grpc_future = try io.concurrent(serveGrpc, .{&grpc_transport});
    }

    var ws_transport: mcp.transport.websocket.Server = .init(io, gpa, &server, .{ .port = ws_port orelse 0 });
    defer ws_transport.deinit();
    var ws_future: ?std.Io.Future(void) = null;
    defer if (ws_future) |*f| {
        ws_transport.shutdown();
        f.await(io);
    };
    if (ws_port != null) {
        try ws_transport.bind();
        std.log.info("everything server listening for WebSocket on ws://127.0.0.1:{d}/mcp", .{ws_transport.bound_port});
        ws_future = try io.concurrent(serveWebSocket, .{&ws_transport});
    }
    try transport.serve();
}

fn serveGrpc(transport: *mcp_grpc.Server) void {
    transport.serve() catch |e| std.log.err("gRPC server failed: {t}", .{e});
}

fn serveWebSocket(transport: *mcp.transport.websocket.Server) void {
    transport.serve() catch |e| std.log.err("WebSocket server failed: {t}", .{e});
}

// -- Tests ------------------------------------------------------------------------------------

const testing = std.testing;
const Harness = mcp.transport.memory.Harness;

const test_meta =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;

/// The fixture server on the in-memory harness.
const TestServer = struct {
    server: mcp.Server,
    arena_state: std.heap.ArenaAllocator,

    fn init(self: *TestServer, options: mcp.Server.Options) !void {
        self.arena_state = .init(testing.allocator);
        self.server = try mcp.Server.init(testing.allocator, testing.io, options);
        try register(&self.server, testing.io);
    }

    fn deinit(self: *TestServer) void {
        self.server.deinit();
        self.arena_state.deinit();
    }

    fn arena(self: *TestServer) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// Send one request on a new harness and return the parsed last frame.
    fn call(self: *TestServer, method: []const u8, params: []const u8) !std.json.Value {
        var harness: Harness = .init(testing.io, testing.allocator, &self.server);
        defer harness.deinit();
        const sep: []const u8 = if (params.len > 0) "," else "";
        try harness.send(try std.fmt.allocPrint(self.arena(), "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ method, test_meta, sep, params }));
        try testing.expect(harness.finished);
        return mcp.json.parseTree(self.arena(), harness.last().?);
    }
};

/// Wait until the harness has `count` frames, for 2 seconds at most.
fn waitForFrames(harness: *Harness, count: usize) !void {
    var spins: usize = 0;
    while (spins < 400) : (spins += 1) {
        harness.out_lock.lockUncancelable(testing.io);
        const n = harness.out.items.len;
        harness.out_lock.unlock(testing.io);
        if (n >= count) return;
        try testing.io.sleep(.fromMilliseconds(5), .awake);
    }
    return error.Timeout;
}

test "test_trigger_resource_update sends resources/updated and resources/list_changed to a listen stream" {
    var t: TestServer = undefined;
    try t.init(serverOptions());
    defer t.deinit();
    const io = testing.io;

    var listen: Harness = .init(io, testing.allocator, &t.server);
    defer listen.deinit();
    var token: mcp.transport.Transport.CancelToken = .{};
    const frame = try std.fmt.allocPrint(t.arena(), "{{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"subscriptions/listen\",\"params\":{{{s},\"notifications\":{{\"resourcesListChanged\":true,\"resourceSubscriptions\":[\"{s}\"]}}}}}}", .{ test_meta, watched_uri });
    var future = try io.concurrent(Harness.sendWithToken, .{ &listen, frame, &token });
    try waitForFrames(&listen, 1);

    const reply = try t.call("tools/call", "\"name\":\"test_trigger_resource_update\",\"arguments\":{}");
    try testing.expectEqualStrings("Resource updated", reply.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
    try waitForFrames(&listen, 3);
    const updated = try mcp.json.parseTree(t.arena(), listen.out.items[1]);
    try testing.expectEqualStrings("notifications/resources/updated", updated.object.get("method").?.string);
    try testing.expectEqualStrings(watched_uri, updated.object.get("params").?.object.get("uri").?.string);
    const changed = try mcp.json.parseTree(t.arena(), listen.out.items[2]);
    try testing.expectEqualStrings("notifications/resources/list_changed", changed.object.get("method").?.string);

    t.server.shutdownSubscriptions(io);
    try future.await(io);
}

test "parseArgs: --no-tunnel with --grpc-typed serves the typed service only" {
    const config = try parseArgs(&.{ "server", "--grpc-port", "0", "--grpc-typed", "--no-tunnel" });
    try testing.expectEqual(mcp_grpc.server.Bindings{ .tunnel = false, .typed = true }, config.grpcBindings());
    // The default keeps the tunnel.
    try testing.expectEqual(mcp_grpc.server.Bindings{ .tunnel = true, .typed = false }, (try parseArgs(&.{"server"})).grpcBindings());
    try testing.expectError(error.NoGrpcService, parseArgs(&.{ "server", "--no-tunnel" }));
}

fn serveGrpcIgnoringErrors(transport: *mcp_grpc.Server) void {
    transport.serve() catch {};
}

test "--no-tunnel: a tunnel call gets UNIMPLEMENTED and the typed service answers" {
    var t: TestServer = undefined;
    try t.init(serverOptions());
    defer t.deinit();
    const io = testing.io;
    const gpa = testing.allocator;
    const config = try parseArgs(&.{ "server", "--grpc-typed", "--no-tunnel" });
    var grpc_transport: mcp_grpc.Server = .init(io, gpa, &t.server, .{ .port = 0, .bindings = config.grpcBindings() });
    defer grpc_transport.deinit();
    try grpc_transport.bind();
    var future = try io.concurrent(serveGrpcIgnoringErrors, .{&grpc_transport});
    defer {
        grpc_transport.shutdown();
        future.await(io);
    }

    // The tunnel answers as an unknown service.
    const tunnel = try mcp_grpc.Channel.init(io, gpa, .{ .host = "127.0.0.1", .port = grpc_transport.bound_port });
    defer tunnel.deinit();
    var tunnel_client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "test", .version = "1" } });
    defer tunnel_client.deinit();
    tunnel_client.connect(tunnel.transport());
    // The call ends with a gRPC status and no JSON-RPC answer. The test of the typed binding
    // in src/grpc/typed_test.zig reads the status UNIMPLEMENTED from the same bindings.
    var diag: mcp.Client.Diagnostics = .{};
    try testing.expectError(error.TransportFailed, tunnel_client.listTools(t.arena(), null, .{ .timeout = .fromSeconds(10), .diagnostics = &diag }));
    try testing.expect(diag.rpc_error == null);

    // The typed service answers.
    const typed = try mcp_grpc.TypedChannel.init(io, gpa, .{ .channel = .{ .host = "127.0.0.1", .port = grpc_transport.bound_port } });
    defer typed.deinit();
    var typed_client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "test", .version = "1" } });
    defer typed_client.deinit();
    typed_client.connect(typed.transport());
    const tools = try typed_client.listTools(t.arena(), null, .{ .timeout = .fromSeconds(10) });
    try testing.expect(tools.tools.len > 0);
}
