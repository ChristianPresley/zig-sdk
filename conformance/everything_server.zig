//! The conformance "everything server": every tool, resource and prompt that the official
//! conformance suite for MCP 2026-07-28 expects. Serves Streamable HTTP by default and
//! stdio with `--stdio`.
//!
//! Usage: mcp-conformance-server [--port N] [--grpc-port N] [--stdio]
const std = @import("std");
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

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var port: u16 = 3000;
    var use_stdio = false;
    var grpc_port: ?u16 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            i += 1;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--grpc-port") and i + 1 < args.len) {
            i += 1;
            grpc_port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, args[i], "--stdio")) {
            use_stdio = true;
        }
    }
    if (init.environ_map.get("PORT")) |p| port = std.fmt.parseInt(u16, p, 10) catch port;

    var server = try mcp.Server.init(gpa, io, .{
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
    });
    defer server.deinit();

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
    try server.addResource(.{ .uri = "test://watched-resource", .name = "Watched Resource", .mime_type = "text/plain" }, readWatched);
    try server.addResourceTemplate(.{ .uri_template = "test://template/{id}/data", .name = "Template Resource", .mime_type = "application/json", .description = "A resource template" }, readTemplate);

    try server.addPrompt(.{ .name = "test_simple_prompt", .description = "A simple prompt" }, simplePrompt);
    try server.addPrompt(.{ .name = "test_prompt_with_arguments", .description = "A prompt with arguments", .arguments = &.{ .{ .name = "arg1", .description = "First argument", .required = true }, .{ .name = "arg2", .description = "Second argument", .required = true } } }, promptWithArguments);
    try server.addPrompt(.{ .name = "test_prompt_with_embedded_resource", .description = "A prompt with an embedded resource", .arguments = &.{.{ .name = "resourceUri", .description = "Resource URI", .required = true }} }, promptWithEmbeddedResource);
    try server.addPrompt(.{ .name = "test_prompt_with_image", .description = "A prompt with an image" }, promptWithImage);
    try server.addPrompt(.{ .name = "test_input_required_result_prompt", .description = "A prompt that needs input" }, irPrompt);
    try server.addPrompt(.{ .name = "test_hidden_prompt", .description = "Appears after a change" }, hiddenPrompt);
    _ = server.setPromptEnabled(io, "test_hidden_prompt", false);
    server.setCompletionHandler(complete);

    if (use_stdio) {
        try mcp.transport.stdio.serve(io, gpa, &server);
        return;
    }
    var transport: mcp.transport.http.Server = .init(io, gpa, &server, .{ .port = port });
    defer transport.deinit();
    try transport.bind();
    std.log.info("everything server listening on http://127.0.0.1:{d}/mcp", .{transport.bound_port});
    if (grpc_port) |gp| {
        var grpc_transport: mcp_grpc.Server = .init(io, gpa, &server, .{ .port = gp });
        defer grpc_transport.deinit();
        try grpc_transport.bind();
        std.log.info("everything server listening for gRPC on 127.0.0.1:{d}", .{grpc_transport.bound_port});
        var grpc_future = try io.concurrent(serveGrpc, .{&grpc_transport});
        defer {
            grpc_transport.shutdown();
            grpc_future.await(io);
        }
        try transport.serve();
        return;
    }
    try transport.serve();
}

fn serveGrpc(transport: *mcp_grpc.Server) void {
    transport.serve() catch |e| std.log.err("gRPC server failed: {t}", .{e});
}
