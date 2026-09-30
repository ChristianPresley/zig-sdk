//! The conformance "everything client": runs the client scenario named by the environment
//! variable `MCP_CONFORMANCE_SCENARIO` against the server URL given as the last argument.
//!
//! The suite passes `MCP_CONFORMANCE_CONTEXT` (JSON) with scenario data and expects a silent
//! exit code 0 when the scenario ran.
const std = @import("std");
const mcp = @import("mcp");
const types = mcp.types;
const json = mcp.json;
const Client = mcp.Client;
const Value = std.json.Value;

const request_timeout: std.Io.Duration = .fromSeconds(20);

fn acceptForm(ctx: *Client.HookContext, params: types.ElicitRequestFormParams) anyerror!types.ElicitResult {
    _ = params;
    return .{ .action = .accept, .content = try json.parseTree(ctx.arena, "{\"confirmed\":true,\"name\":\"Alice\"}") };
}

fn declineUrl(ctx: *Client.HookContext, params: types.ElicitRequestURLParams) anyerror!types.ElicitResult {
    _ = ctx;
    _ = params;
    return .{ .action = .decline };
}

fn sample(ctx: *Client.HookContext, params: types.CreateMessageRequestParams) anyerror!types.CreateMessageResult {
    _ = ctx;
    _ = params;
    return .{ .role = .assistant, .content = .{ .single = .{ .text = .{ .text = "Hello from the conformance client" } } }, .model = "conformance-model", .stopReason = "endTurn" };
}

fn listRoots(ctx: *Client.HookContext) anyerror![]const types.Root {
    const roots = try ctx.arena.alloc(types.Root, 1);
    roots[0] = .{ .uri = "file:///workspace", .name = "workspace" };
    return roots;
}

const Runner = struct {
    arena: std.mem.Allocator,
    client: *Client,
    context: ?Value,

    fn opts(self: *Runner) Client.RequestOptions {
        _ = self;
        return .{ .timeout = request_timeout };
    }

    fn toolsCall(self: *Runner) !void {
        _ = try self.client.listTools(self.arena, null, self.opts());
        _ = try self.client.callTool(self.arena, "add_numbers", .{ .a = 5, .b = 3 }, self.opts());
    }

    fn requestMetadata(self: *Runner) !void {
        _ = try self.client.discover(self.arena, self.opts());
        _ = try self.client.listTools(self.arena, null, self.opts());
    }

    fn requestState(self: *Runner) !void {
        _ = try self.client.listTools(self.arena, null, self.opts());
        _ = try self.client.callTool(self.arena, "test_mrtr_echo_state", null, self.opts());
        _ = try self.client.callTool(self.arena, "test_mrtr_no_state", null, self.opts());
        _ = try self.client.callTool(self.arena, "test_mrtr_unrelated", null, self.opts());
        _ = try self.client.callTool(self.arena, "test_mrtr_no_result_type", null, self.opts());
    }

    fn standardHeaders(self: *Runner) !void {
        const tools = try self.client.listTools(self.arena, null, self.opts());
        for (tools.tools) |t| _ = try self.client.callTool(self.arena, t.name, null, self.opts());
        const resources = try self.client.listResources(self.arena, null, self.opts());
        for (resources.resources) |r| _ = try self.client.readResource(self.arena, r.uri, self.opts());
        const prompts = try self.client.listPrompts(self.arena, null, self.opts());
        for (prompts.prompts) |p| _ = try self.client.getPrompt(self.arena, p.name, null, self.opts());
    }

    /// Replay the tool calls from the scenario context with their arguments verbatim.
    fn customHeaders(self: *Runner) !void {
        _ = try self.client.listTools(self.arena, null, self.opts());
        const context = self.context orelse return error.MissingContext;
        const calls = context.object.get("toolCalls") orelse return error.MissingContext;
        for (calls.array.items) |call| {
            const name = json.getString(call, "name") orelse continue;
            const arguments = call.object.get("arguments") orelse Value{ .object = .empty };
            _ = try self.client.callTool(self.arena, name, arguments, self.opts());
        }
    }

    /// Call every tool the transport kept. Tools with invalid header annotations are gone.
    fn invalidToolHeaders(self: *Runner) !void {
        const tools = try self.client.listTools(self.arena, null, self.opts());
        for (tools.tools) |t| {
            var args: std.json.ObjectMap = .empty;
            if (t.inputSchema == .object) if (t.inputSchema.object.get("required")) |req| if (req == .array) {
                for (req.array.items) |name| if (name == .string) try args.put(self.arena, name.string, .{ .string = "us-west1" });
            };
            _ = try self.client.callTool(self.arena, t.name, Value{ .object = args }, self.opts());
        }
    }

    fn schemaPreservation(self: *Runner) !void {
        const tools = try self.client.listTools(self.arena, null, self.opts());
        for (tools.tools) |t| {
            if (!std.mem.eql(u8, t.name, "json_schema_2020_12_tool")) continue;
            var args: std.json.ObjectMap = .empty;
            try args.put(self.arena, "schema", t.inputSchema);
            _ = try self.client.callTool(self.arena, "json_schema_echo", Value{ .object = args }, self.opts());
            return;
        }
        return error.ToolNotFound;
    }

    fn refNoDeref(self: *Runner) !void {
        // Listing is enough: the SDK never fetches a `$ref` URI.
        _ = try self.client.listTools(self.arena, null, self.opts());
    }
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.log.err("usage: mcp-conformance-client <server url>", .{});
        return 2;
    }
    const url = args[args.len - 1];
    const scenario = init.environ_map.get("MCP_CONFORMANCE_SCENARIO") orelse "tools_call";
    const context: ?Value = if (init.environ_map.get("MCP_CONFORMANCE_CONTEXT")) |text| json.parseTree(arena, text) catch null else null;

    const http = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url });
    defer http.deinit();
    var client: Client = .init(gpa, io, .{
        .info = .{ .name = "zig-sdk-conformance-client", .version = "0.1.0" },
        .capabilities = .{ .roots = .{}, .sampling = .{}, .elicitation = .{ .form = .{ .object = .empty }, .url = .{ .object = .empty } } },
        .hooks = .{ .elicit_form = acceptForm, .elicit_url = declineUrl, .sample = sample, .list_roots = listRoots },
    });
    defer client.deinit();
    client.connect(http.transport());

    var runner: Runner = .{ .arena = arena, .client = &client, .context = context };
    const result = if (std.mem.eql(u8, scenario, "tools_call"))
        runner.toolsCall()
    else if (std.mem.eql(u8, scenario, "request-metadata"))
        runner.requestMetadata()
    else if (std.mem.eql(u8, scenario, "sep-2322-client-request-state"))
        runner.requestState()
    else if (std.mem.eql(u8, scenario, "http-standard-headers"))
        runner.standardHeaders()
    else if (std.mem.eql(u8, scenario, "http-custom-headers"))
        runner.customHeaders()
    else if (std.mem.eql(u8, scenario, "http-invalid-tool-headers"))
        runner.invalidToolHeaders()
    else if (std.mem.eql(u8, scenario, "json-schema-2020-12-preservation"))
        runner.schemaPreservation()
    else if (std.mem.eql(u8, scenario, "json-schema-ref-no-deref"))
        runner.refNoDeref()
    else {
        std.log.err("scenario {s} is not implemented", .{scenario});
        return 1;
    };
    result catch |e| {
        std.log.err("scenario {s} failed: {t}", .{ scenario, e });
        return 1;
    };
    return 0;
}
