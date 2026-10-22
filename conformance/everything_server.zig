//! The conformance "everything server": every tool, resource and prompt that the official
//! conformance suite for MCP 2026-07-28 expects. Serves Streamable HTTP by default and
//! stdio with `--stdio`. `--grpc-port` adds the gRPC tunnel, `--grpc-typed` also serves the
//! typed service `model_context_protocol.Mcp` on that port, and `--ws-port` adds the
//! WebSocket binding on `ws://127.0.0.1:N/mcp`. `--no-tunnel` with `--grpc-typed` removes the
//! tunnel from the gRPC port.
//!
//! `--tls-cert` and `--tls-key` give PEM files for TLS on the HTTP
//! listener and on the gRPC listener. `--log-requests` logs one JSON line for each handler call.
//! `--apps` adds a fixture of the MCP Apps extension: a `ui://` view and a tool that names it.
//! `--reuse-address` lets a new server bind a port at once after the old one stops.
//!
//! Usage: mcp-conformance-server [--port N] [--grpc-port N] [--grpc-typed] [--no-tunnel] [--ws-port N]
//!        [--tls-cert cert.pem --tls-key key.pem] [--log-requests] [--apps] [--reuse-address]
//!        [--max-connections N] [--max-in-flight N] [--idle-timeout S] [--stdio]
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

// -- MCP Apps fixture (--apps) ----------------------------------------------------------------

/// The `ui://` resource of the fixture of the MCP Apps extension.
const app_view_uri = "ui://conformance/view";
const app_view_html =
    \\<!doctype html>
    \\<html><head><meta charset="utf-8"><title>Conformance view</title></head>
    \\<body><p>The view of test_app_tool.</p></body></html>
;

fn appTool(ctx: *Ctx, _: NoArgs) anyerror!Result {
    return textResult(ctx, "A result for the view", .{});
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
    /// True with `--log-requests`.
    log_requests: std.atomic.Value(bool) = .init(false),
};
var state: State = .{};

// -- Request log ------------------------------------------------------------------------------

const request_log = std.log.scoped(.request_log);

/// The function that gets each line of the request log. A test can replace it.
var request_log_sink: *const fn (line: []const u8) void = logRequestLine;

fn logRequestLine(line: []const u8) void {
    request_log.info("{s}", .{line});
}

/// Write one line of the request log as a JSON object. The line has the transport, the
/// method, the request ID and the target: the tool name, prompt name or resource URI. It also
/// has the outcome, the JSON-RPC error code and the duration. It has no arguments, no content
/// and no headers.
fn writeRequestLine(w: *std.Io.Writer, kind: mcp.transport.Transport.Kind, method: []const u8, id: mcp.jsonrpc.RequestId, target: []const u8, outcome: []const u8, code: ?i64, duration_us: i64) std.Io.Writer.Error!void {
    try w.print("{{\"transport\":\"{t}\",\"method\":{f},\"id\":", .{ kind, std.json.fmt(method, .{}) });
    switch (id) {
        .string => |text| try w.print("{f}", .{std.json.fmt(text, .{})}),
        .integer => |n| try w.print("{d}", .{n}),
        .big => |digits| try w.writeAll(digits),
    }
    try w.print(",\"target\":{f},\"outcome\":\"{s}\",\"code\":", .{ std.json.fmt(target, .{}), outcome });
    if (code) |c| try w.print("{d}", .{c}) else try w.writeAll("null");
    try w.print(",\"duration_us\":{d}}}", .{duration_us});
}

/// The outcome of a handler for the request log: a name and a JSON-RPC error code or null.
fn outcomeOf(ctx: *const Ctx, result: anytype) struct { []const u8, ?i64 } {
    const value = result catch |e| {
        if (e == error.Rpc) if (ctx.rpc_error) |r| return .{ "error", r.code };
        return .{ "error", mcp.protocol.errors.Code.internal_error.int() };
    };
    const T = @TypeOf(value);
    if (@typeInfo(T) != .@"union") return .{ "complete", null };
    return switch (value) {
        .complete => |c| if (@TypeOf(c) == types.CallToolResult and (c.isError orelse false)) .{ "tool_error", null } else .{ "complete", null },
        .input_required => .{ "input_required", null },
        .start_task => .{ "task", null },
    };
}

/// Log one line for a handler call when `--log-requests` is on.
fn logCall(ctx: *const Ctx, start: std.Io.Clock.Timestamp, result: anytype) void {
    const outcome, const code = outcomeOf(ctx, result);
    const duration_us: i64 = @intCast(start.durationTo(std.Io.Clock.Timestamp.now(ctx.io, .awake)).raw.toMicroseconds());
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    writeRequestLine(&w, ctx.kind, ctx.method, ctx.id, ctx.target, outcome, code, duration_us) catch return;
    request_log_sink(w.buffered());
}

/// The handler with a line of the request log for each call. Without `--log-requests`, the
/// wrapper only calls the handler.
fn logged(comptime handler: anytype) @TypeOf(handler) {
    const info = @typeInfo(@TypeOf(handler)).@"fn";
    const R = info.return_type.?;
    return switch (info.params.len) {
        2 => struct {
            fn call(ctx: *Ctx, a: info.params[1].type.?) R {
                if (!state.log_requests.load(.monotonic)) return handler(ctx, a);
                const start = std.Io.Clock.Timestamp.now(ctx.io, .awake);
                const result = handler(ctx, a);
                logCall(ctx, start, result);
                return result;
            }
        }.call,
        3 => struct {
            fn call(ctx: *Ctx, a: info.params[1].type.?, b: info.params[2].type.?) R {
                if (!state.log_requests.load(.monotonic)) return handler(ctx, a, b);
                const start = std.Io.Clock.Timestamp.now(ctx.io, .awake);
                const result = handler(ctx, a, b);
                logCall(ctx, start, result);
                return result;
            }
        }.call,
        else => @compileError("unexpected handler"),
    };
}

const json_schema_2020_12 =
    \\{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","$defs":{"address":{"$anchor":"addressDef","type":"object","properties":{"street":{"type":"string"},"city":{"type":"string"}}}},"properties":{"name":{"type":"string"},"address":{"$ref":"#/$defs/address"},"contactMethod":{"type":"string","enum":["phone","email"]},"phone":{"type":"string"},"email":{"type":"string"}},"allOf":[{"anyOf":[{"required":["phone"]},{"required":["email"]}]}],"if":{"properties":{"contactMethod":{"const":"phone"}},"required":["contactMethod"]},"then":{"required":["phone"]},"else":{"required":["email"]},"additionalProperties":false}
;

/// The options of the server engine. `apps` declares the MCP Apps extension for `--apps`.
fn serverOptions(apps: bool) mcp.Server.Options {
    return .{
        .apps = if (apps) .{} else null,
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
    try server.addTool(.{ .name = "test_simple_text", .description = "Returns simple text" }, logged(simpleText));
    try server.addTool(.{ .name = "test_image_content", .description = "Returns image content" }, logged(imageContent));
    try server.addTool(.{ .name = "test_audio_content", .description = "Returns audio content" }, logged(audioContent));
    try server.addTool(.{ .name = "test_embedded_resource", .description = "Returns an embedded resource" }, logged(embeddedResource));
    try server.addTool(.{ .name = "test_multiple_content_types", .description = "Returns mixed content" }, logged(multipleContentTypes));
    try server.addTool(.{ .name = "test_error_handling", .description = "Returns an error result" }, logged(errorHandling));
    try server.addTool(.{ .name = "test_tool_with_progress", .description = "Sends progress notifications" }, logged(withProgress));
    try server.addTool(.{ .name = "test_tool_with_logging", .description = "Sends log messages" }, logged(withLogging));
    try server.addTool(.{ .name = "test_logging_tool", .description = "Sends log messages" }, logged(withLogging));
    try server.addTool(.{ .name = "test_missing_capability", .description = "Needs the sampling capability", .requires_client = .{ .sampling = .{} } }, logged(missingCapability));
    try server.addTool(.{ .name = "test_streaming_elicitation", .description = "Elicitation over a stream" }, logged(streamingElicitation));
    try server.addTool(.{ .name = "test_sampling", .description = "Requests sampling" }, logged(sampling));
    try server.addTool(.{ .name = "test_elicitation", .description = "Requests elicitation" }, logged(elicitation));
    try server.addTool(.{ .name = "test_elicitation_sep1330_enums", .description = "Elicitation with enums" }, logged(elicitationEnums));
    try server.addTool(.{ .name = "test_elicitation_sep1034_defaults", .description = "Elicitation with defaults" }, logged(elicitationDefaults));
    try server.addTool(.{ .name = "test_trigger_tool_change", .description = "Changes the tool list" }, logged(triggerToolChange));
    try server.addTool(.{ .name = "test_trigger_prompt_change", .description = "Changes the prompt list" }, logged(triggerPromptChange));
    try server.addTool(.{ .name = "test_trigger_resource_update", .description = "Announces a change of test://watched-resource and of the resource list" }, logged(triggerResourceUpdate));
    try server.addTool(.{ .name = "test_hidden_tool", .description = "Appears after a change" }, logged(hiddenTool));
    try server.addTool(.{ .name = "test_input_required_result_elicitation", .description = "MRTR elicitation" }, logged(irElicitation));
    try server.addTool(.{ .name = "test_input_required_result_sampling", .description = "MRTR sampling" }, logged(irSampling));
    try server.addTool(.{ .name = "test_input_required_result_list_roots", .description = "MRTR roots" }, logged(irListRoots));
    try server.addTool(.{ .name = "test_input_required_result_request_state", .description = "MRTR with state" }, logged(irRequestState));
    try server.addTool(.{ .name = "test_input_required_result_multiple_inputs", .description = "MRTR with several inputs" }, logged(irMultipleInputs));
    try server.addTool(.{ .name = "test_input_required_result_multi_round", .description = "MRTR with three rounds" }, logged(irMultiRound));
    try server.addTool(.{ .name = "test_input_required_result_tampered_state", .description = "MRTR state integrity" }, logged(irTamperedState));
    try server.addTool(.{ .name = "test_input_required_result_capabilities", .description = "MRTR per declared capability" }, logged(irCapabilities));
    try server.addToolJson(.{ .name = "json_schema_2020_12_tool", .description = "Tool with a 2020-12 schema", .input_schema = json_schema_2020_12 }, logged(jsonSchema2020));
    try server.addTool(.{ .name = "test_x_mcp_header", .description = "Tool with header annotations" }, logged(xMcpHeader));
    try server.addTool(.{ .name = "greet", .description = "Greets by name" }, logged(greet));
    try server.addTool(.{ .name = "slow_compute", .description = "Sleeps for some seconds inside a task", .task_support = .optional }, logged(slowCompute));
    try server.addTool(.{ .name = "failing_job", .description = "A task that ends in a tool error", .task_support = .required }, logged(failingJob));
    try server.addTool(.{ .name = "protocol_error_job", .description = "A task that ends in a protocol error", .task_support = .optional }, logged(protocolErrorJob));
    try server.addTool(.{ .name = "confirm_delete", .description = "A task that asks for confirmation", .task_support = .optional }, logged(confirmDelete));
    try server.addTool(.{ .name = "multi_input", .description = "A task that asks two questions at once", .task_support = .optional }, logged(multiInput));
    try server.addTool(.{ .name = "test_tool_with_task", .description = "MRTR round then a task", .task_support = .required }, logged(toolWithTask));
    _ = server.setToolEnabled(io, "test_hidden_tool", false);

    try server.addResource(.{ .uri = "test://static-text", .name = "Static Text Resource", .mime_type = "text/plain", .description = "A static text resource" }, logged(readStaticText));
    try server.addResource(.{ .uri = "test://static-binary", .name = "Static Binary Resource", .mime_type = "image/png", .description = "A static binary resource" }, logged(readStaticBinary));
    try server.addResource(.{ .uri = watched_uri, .name = "Watched Resource", .mime_type = "text/plain" }, logged(readWatched));
    try server.addResourceTemplate(.{ .uri_template = "test://template/{id}/data", .name = "Template Resource", .mime_type = "application/json", .description = "A resource template" }, logged(readTemplate));

    try server.addPrompt(.{ .name = "test_simple_prompt", .description = "A simple prompt" }, logged(simplePrompt));
    try server.addPrompt(.{ .name = "test_prompt_with_arguments", .description = "A prompt with arguments", .arguments = &.{ .{ .name = "arg1", .description = "First argument", .required = true }, .{ .name = "arg2", .description = "Second argument", .required = true } } }, logged(promptWithArguments));
    try server.addPrompt(.{ .name = "test_prompt_with_embedded_resource", .description = "A prompt with an embedded resource", .arguments = &.{.{ .name = "resourceUri", .description = "Resource URI", .required = true }} }, logged(promptWithEmbeddedResource));
    try server.addPrompt(.{ .name = "test_prompt_with_image", .description = "A prompt with an image" }, logged(promptWithImage));
    try server.addPrompt(.{ .name = "test_input_required_result_prompt", .description = "A prompt that needs input" }, logged(irPrompt));
    try server.addPrompt(.{ .name = "test_hidden_prompt", .description = "Appears after a change" }, logged(hiddenPrompt));
    _ = server.setPromptEnabled(io, "test_hidden_prompt", false);
    server.setCompletionHandler(logged(complete));

    // The fixture of the MCP Apps extension: a view and a tool that names it in `_meta.ui`.
    if (server.options.apps != null) {
        try server.addUiResource(.{ .uri = app_view_uri, .name = "Conformance View", .description = "The view of test_app_tool" }, app_view_html);
        try server.addTool(.{ .name = "test_app_tool", .description = "A tool with a view", .ui = .{ .resourceUri = app_view_uri } }, logged(appTool));
    }
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
    /// The PEM files of `--tls-cert` and `--tls-key`. With both, the HTTP listener serves
    /// HTTPS and the gRPC listener serves TLS with ALPN `h2`.
    tls_cert: ?[]const u8 = null,
    tls_key: ?[]const u8 = null,
    /// `--log-requests`: log one line for each call of a tool, resource, prompt or completion
    /// handler, at the level info in the scope `request_log`.
    log_requests: bool = false,
    /// `--apps`: declare the MCP Apps extension and serve its fixture.
    apps: bool = false,
    /// `--reuse-address`: set `reuse_address` on the HTTP, WebSocket and gRPC listeners. Then
    /// a new server can bind a port at once while old connections are in `TIME_WAIT`. On Linux
    /// and the BSDs a second server of the same user can then bind the same port and share the
    /// connections. The test runner must stop the old process first. The server ignores the
    /// option on Windows.
    reuse_address: bool = false,
    /// `--max-connections N`: `Limits.http.max_connections` of the HTTP listener, for load
    /// tests with many idle connections. Null keeps the default of the library.
    max_connections: ?u32 = null,
    /// `--max-in-flight N`: `Limits.http.max_in_flight`, the worker tasks of the HTTP
    /// listener. Null keeps the default of the library.
    max_in_flight: ?u32 = null,
    /// `--idle-timeout S`: `Limits.http.idle_timeout` in seconds, zero for no limit. Null
    /// keeps the default of the library.
    idle_timeout_s: ?u32 = null,

    /// True when the listeners set `reuse_address`: with `--reuse-address` and not on Windows.
    fn reuseAddress(self: Config) bool {
        return self.reuse_address and builtin.os.tag != .windows;
    }

    fn grpcBindings(self: Config) mcp_grpc.server.Bindings {
        return .{ .tunnel = self.grpc_tunnel, .typed = self.grpc_typed };
    }
};

/// The certificate chain and the TLS servers of the listeners.
const TlsListeners = struct {
    chain: mcp.tls.CertChain,
    chains: [1]*const mcp.tls.CertChain,
    /// ALPN `http/1.1`, for the Streamable HTTP listener.
    http: mcp.tls.Server,
    /// ALPN `h2`, for the gRPC listener.
    grpc: mcp.tls.Server,

    /// Load the chain and the key from PEM files, as the example `https_server` does.
    fn load(self: *TlsListeners, gpa: std.mem.Allocator, io: std.Io, cert: []const u8, key: []const u8) !void {
        self.chain = try mcp.tls.CertChain.loadFiles(gpa, io, cert, key);
        errdefer self.chain.deinit();
        self.chains = .{&self.chain};
        self.http = try mcp.tls.Server.init(.{ .chains = &self.chains, .alpn = &.{"http/1.1"} });
        self.grpc = try mcp.tls.Server.init(.{ .chains = &self.chains, .alpn = &.{"h2"} });
    }

    fn deinit(self: *TlsListeners) void {
        self.chain.deinit();
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
        } else if (std.mem.eql(u8, args[i], "--reuse-address")) {
            config.reuse_address = true;
        } else if (std.mem.eql(u8, args[i], "--max-connections") and i + 1 < args.len) {
            i += 1;
            config.max_connections = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidMaxConnections;
            if (config.max_connections == 0) return error.InvalidMaxConnections;
        } else if (std.mem.eql(u8, args[i], "--max-in-flight") and i + 1 < args.len) {
            i += 1;
            config.max_in_flight = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidMaxInFlight;
        } else if (std.mem.eql(u8, args[i], "--idle-timeout") and i + 1 < args.len) {
            i += 1;
            config.idle_timeout_s = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidIdleTimeout;
        } else if (std.mem.eql(u8, args[i], "--apps")) {
            config.apps = true;
        } else if (std.mem.eql(u8, args[i], "--log-requests")) {
            config.log_requests = true;
        } else if (std.mem.eql(u8, args[i], "--tls-cert") and i + 1 < args.len) {
            i += 1;
            config.tls_cert = args[i];
        } else if (std.mem.eql(u8, args[i], "--tls-key") and i + 1 < args.len) {
            i += 1;
            config.tls_key = args[i];
        }
    }
    if ((config.tls_cert == null) != (config.tls_key == null)) return error.TlsNeedsCertAndKey;
    // Without the tunnel and without the typed service, the gRPC port has no service.
    if (!config.grpc_tunnel and !config.grpc_typed) return error.NoGrpcService;
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
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var config = parseArgs(args) catch |e| {
        switch (e) {
            error.NoGrpcService => std.log.err("--no-tunnel needs --grpc-typed", .{}),
            error.TlsNeedsCertAndKey => std.log.err("--tls-cert and --tls-key go together", .{}),
            else => {},
        }
        return e;
    };
    if (init.environ_map.get("PORT")) |p| config.port = std.fmt.parseInt(u16, p, 10) catch config.port;
    const port = config.port;
    const use_stdio = config.stdio;
    const grpc_port = config.grpc_port;
    const grpc_typed = config.grpc_typed;
    const ws_port = config.ws_port;

    state.log_requests.store(config.log_requests, .monotonic);
    var options = serverOptions(config.apps);
    options.limits.http.reuse_address = config.reuseAddress();
    if (config.reuse_address and !config.reuseAddress()) std.log.info("--reuse-address has no effect on Windows", .{});
    if (config.max_connections) |n| options.limits.http.max_connections = n;
    if (config.max_in_flight) |n| options.limits.http.max_in_flight = n;
    if (config.idle_timeout_s) |s| options.limits.http.idle_timeout = .fromSeconds(s);
    var server = try mcp.Server.init(gpa, io, options);
    defer server.deinit();
    try register(&server, io);

    if (use_stdio) {
        try mcp.transport.stdio.serve(io, gpa, &server);
        return;
    }
    var tls_listeners: TlsListeners = undefined;
    const use_tls = config.tls_cert != null;
    if (use_tls) try tls_listeners.load(gpa, io, config.tls_cert.?, config.tls_key.?);
    defer if (use_tls) tls_listeners.deinit();

    var transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = port, .tls = if (use_tls) &tls_listeners.http else null });
    defer transport.deinit();
    try transport.bind();
    std.log.info("everything server listening on {s}://127.0.0.1:{d}/mcp", .{ if (use_tls) "https" else "http", transport.bound_port });

    var grpc_transport: mcp_grpc.Server = .init(io, gpa, &server, .{ .port = grpc_port orelse 0, .bindings = config.grpcBindings(), .tls = if (use_tls) &tls_listeners.grpc else null, .reuse_address = config.reuseAddress() });
    defer grpc_transport.deinit();
    var grpc_future: ?std.Io.Future(void) = null;
    defer if (grpc_future) |*f| {
        grpc_transport.shutdown();
        f.await(io);
    };
    if (grpc_port != null) {
        try grpc_transport.bind();
        const services: []const u8 = if (!config.grpc_tunnel) " with the typed service only" else if (grpc_typed) " with the typed service" else "";
        std.log.info("everything server listening for gRPC{s} on 127.0.0.1:{d}{s}", .{ if (use_tls) " with TLS" else "", grpc_transport.bound_port, services });
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
        return self.callWithMeta(method, test_meta, params);
    }

    fn callWithMeta(self: *TestServer, method: []const u8, meta: []const u8, params: []const u8) !std.json.Value {
        var harness: Harness = .init(testing.io, testing.allocator, &self.server);
        defer harness.deinit();
        const sep: []const u8 = if (params.len > 0) "," else "";
        try harness.send(try std.fmt.allocPrint(self.arena(), "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ method, meta, sep, params }));
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
    try t.init(serverOptions(false));
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
    try t.init(serverOptions(false));
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

test "--tls-cert and --tls-key: HTTPS and gRPC with TLS from the fixture certificate" {
    var t: TestServer = undefined;
    try t.init(serverOptions(false));
    defer t.deinit();
    const io = testing.io;
    const gpa = testing.allocator;
    const config = try parseArgs(&.{ "server", "--tls-cert", "test/fixtures/tls/pem/p256.crt", "--tls-key", "test/fixtures/tls/pem/p256.key" });
    try testing.expectError(error.TlsNeedsCertAndKey, parseArgs(&.{ "server", "--tls-cert", "cert.pem" }));
    var listeners: TlsListeners = undefined;
    try listeners.load(gpa, io, config.tls_cert.?, config.tls_key.?);
    defer listeners.deinit();

    var http_transport: mcp.transport.http.Server = .init(io, gpa, &t.server, .{ .port = 0, .tls = &listeners.http });
    defer http_transport.deinit();
    try http_transport.bind();
    var http_future = try io.concurrent(serveHttpIgnoringErrors, .{&http_transport});
    defer {
        http_transport.shutdown();
        http_future.await(io);
    }
    var grpc_transport: mcp_grpc.Server = .init(io, gpa, &t.server, .{ .port = 0, .tls = &listeners.grpc });
    defer grpc_transport.deinit();
    try grpc_transport.bind();
    var grpc_future = try io.concurrent(serveGrpcIgnoringErrors, .{&grpc_transport});
    defer {
        grpc_transport.shutdown();
        grpc_future.await(io);
    }

    // The fixture certificate signs itself.
    const url = try std.fmt.allocPrint(t.arena(), "https://127.0.0.1:{d}/mcp", .{http_transport.bound_port});
    const http_link = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url, .tls = .{ .trust = .self_signed } });
    defer http_link.deinit();
    var http_client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "test", .version = "1" } });
    defer http_client.deinit();
    http_client.connect(http_link.transport());
    const no_args: std.json.Value = .{ .object = .empty };
    const over_https = try http_client.callTool(t.arena(), "test_simple_text", no_args, .{ .timeout = .fromSeconds(10) });
    try testing.expectEqualStrings("This is a simple text response", over_https.content[0].text.text);

    const channel = try mcp_grpc.Channel.init(io, gpa, .{ .host = "127.0.0.1", .port = grpc_transport.bound_port, .tls = .{ .trust = .self_signed } });
    defer channel.deinit();
    var grpc_client: mcp.Client = .init(gpa, io, .{ .info = .{ .name = "test", .version = "1" } });
    defer grpc_client.deinit();
    grpc_client.connect(channel.transport());
    const over_grpc = try grpc_client.callTool(t.arena(), "test_simple_text", no_args, .{ .timeout = .fromSeconds(10) });
    try testing.expectEqualStrings("This is a simple text response", over_grpc.content[0].text.text);
}

fn serveHttpIgnoringErrors(transport: *mcp.transport.http.Server) void {
    transport.serve() catch {};
}

test "writeRequestLine: one JSON object with the transport, the method, the ID, the target, the outcome and the duration" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequestLine(&w, .grpc, "tools/call", .{ .string = "a\"b" }, "test_simple_text", "error", -32602, 42);
    try testing.expectEqualStrings("{\"transport\":\"grpc\",\"method\":\"tools/call\",\"id\":\"a\\\"b\",\"target\":\"test_simple_text\",\"outcome\":\"error\",\"code\":-32602,\"duration_us\":42}", w.buffered());
}

var captured_lines: std.ArrayList([]u8) = .empty;

fn captureLine(line: []const u8) void {
    const copy = testing.allocator.dupe(u8, line) catch return;
    captured_lines.append(testing.allocator, copy) catch testing.allocator.free(copy);
}

test "--log-requests: one line for each call, without the arguments" {
    var t: TestServer = undefined;
    try t.init(serverOptions(false));
    defer t.deinit();
    const config = try parseArgs(&.{ "server", "--log-requests" });
    try testing.expect(config.log_requests);
    state.log_requests.store(true, .monotonic);
    request_log_sink = captureLine;
    defer {
        state.log_requests.store(false, .monotonic);
        request_log_sink = logRequestLine;
        for (captured_lines.items) |line| testing.allocator.free(line);
        captured_lines.clearAndFree(testing.allocator);
    }

    const ok = try t.call("tools/call", "\"name\":\"greet\",\"arguments\":{\"name\":\"secret-value\"}");
    try testing.expectEqualStrings("Hello, secret-value!", ok.object.get("result").?.object.get("content").?.array.items[0].object.get("text").?.string);
    _ = try t.call("tools/call", "\"name\":\"test_error_handling\",\"arguments\":{}");
    _ = try t.call("resources/read", "\"uri\":\"test://static-text\"");
    try testing.expectEqual(3, captured_lines.items.len);
    const first = try mcp.json.parseTree(t.arena(), captured_lines.items[0]);
    try testing.expectEqualStrings("memory", first.object.get("transport").?.string);
    try testing.expectEqualStrings("tools/call", first.object.get("method").?.string);
    try testing.expectEqual(@as(i64, 1), first.object.get("id").?.integer);
    try testing.expectEqualStrings("greet", first.object.get("target").?.string);
    try testing.expectEqualStrings("complete", first.object.get("outcome").?.string);
    try testing.expect(first.object.get("duration_us").?.integer >= 0);
    try testing.expect(std.mem.indexOf(u8, captured_lines.items[0], "secret-value") == null);
    const second = try mcp.json.parseTree(t.arena(), captured_lines.items[1]);
    try testing.expectEqualStrings("tool_error", second.object.get("outcome").?.string);
    const third = try mcp.json.parseTree(t.arena(), captured_lines.items[2]);
    try testing.expectEqualStrings("resources/read", third.object.get("method").?.string);
    try testing.expectEqualStrings("test://static-text", third.object.get("target").?.string);
}

const test_meta_ui =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/ui":{"mimeTypes":["text/html;profile=mcp-app"]}}}}
;

fn findTool(list: std.json.Value, name: []const u8) ?std.json.Value {
    for (list.object.get("result").?.object.get("tools").?.array.items) |tool| {
        if (std.mem.eql(u8, tool.object.get("name").?.string, name)) return tool;
    }
    return null;
}

test "--apps: a ui:// view with the MIME type of the extension and a tool with _meta.ui.resourceUri" {
    try testing.expect((try parseArgs(&.{ "server", "--apps" })).apps);
    var t: TestServer = undefined;
    try t.init(serverOptions(true));
    defer t.deinit();

    const discover = try t.callWithMeta("server/discover", test_meta_ui, "");
    try testing.expect(discover.object.get("result").?.object.get("capabilities").?.object.get("extensions").?.object.get("io.modelcontextprotocol/ui") != null);
    const tools = try t.callWithMeta("tools/list", test_meta_ui, "");
    const tool = findTool(tools, "test_app_tool") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(app_view_uri, tool.object.get("_meta").?.object.get("ui").?.object.get("resourceUri").?.string);
    const read = try t.callWithMeta("resources/read", test_meta_ui, "\"uri\":\"" ++ app_view_uri ++ "\"");
    const content = read.object.get("result").?.object.get("contents").?.array.items[0].object;
    try testing.expectEqualStrings("text/html;profile=mcp-app", content.get("mimeType").?.string);
    try testing.expect(std.mem.startsWith(u8, content.get("text").?.string, "<!doctype html>"));
}

test "without --apps: no view and no tool of the fixture" {
    var t: TestServer = undefined;
    try t.init(serverOptions(false));
    defer t.deinit();
    try testing.expect(findTool(try t.callWithMeta("tools/list", test_meta_ui, ""), "test_app_tool") == null);
}

test "--max-connections: the HTTP limit, with the default of the library without the option" {
    try testing.expectEqual(null, (try parseArgs(&.{"server"})).max_connections);
    try testing.expectEqual(10000, (try parseArgs(&.{ "server", "--max-connections", "10000" })).max_connections);
    try testing.expectError(error.InvalidMaxConnections, parseArgs(&.{ "server", "--max-connections", "0" }));
    try testing.expectError(error.InvalidMaxConnections, parseArgs(&.{ "server", "--max-connections", "many" }));
}

test "--max-in-flight: the worker tasks of the HTTP listener, zero for the connection limit" {
    try testing.expectEqual(null, (try parseArgs(&.{"server"})).max_in_flight);
    try testing.expectEqual(64, (try parseArgs(&.{ "server", "--max-in-flight", "64" })).max_in_flight);
    try testing.expectEqual(0, (try parseArgs(&.{ "server", "--max-in-flight", "0" })).max_in_flight);
    try testing.expectError(error.InvalidMaxInFlight, parseArgs(&.{ "server", "--max-in-flight", "all" }));
}

test "--idle-timeout: the idle limit of the HTTP listener in seconds, zero for no limit" {
    try testing.expectEqual(null, (try parseArgs(&.{"server"})).idle_timeout_s);
    try testing.expectEqual(0, (try parseArgs(&.{ "server", "--idle-timeout", "0" })).idle_timeout_s);
    try testing.expectEqual(600, (try parseArgs(&.{ "server", "--idle-timeout", "600" })).idle_timeout_s);
    try testing.expectError(error.InvalidIdleTimeout, parseArgs(&.{ "server", "--idle-timeout", "soon" }));
}

test "--reuse-address: on for the listeners except on Windows, off by default" {
    try testing.expect(!(try parseArgs(&.{"server"})).reuseAddress());
    const config = try parseArgs(&.{ "server", "--reuse-address" });
    try testing.expect(config.reuse_address);
    try testing.expectEqual(builtin.os.tag != .windows, config.reuseAddress());
    try testing.expect(!serverOptions(false).limits.http.reuse_address);
}
