//! The conformance "everything client": runs the client scenario named by the environment
//! variable `MCP_CONFORMANCE_SCENARIO` against the server URL given as the last argument.
//!
//! The suite passes `MCP_CONFORMANCE_CONTEXT` (JSON) with scenario data and expects a silent
//! exit code 0 when the scenario ran.
//!
//! The scenarios `auth/client-credentials-*` use `ClientCredentials`, and the scenario
//! `auth/enterprise-managed-authorization` uses `EnterpriseClient`. All other `auth/*`
//! scenarios use `OAuthClient`.
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

    /// The authorization scenarios list the tools and call the test tool. The transport
    /// answers the challenges on the way.
    fn authorized(self: *Runner) !void {
        _ = try self.client.listTools(self.arena, null, self.opts());
        _ = try self.client.callTool(self.arena, "test-tool", null, self.opts());
    }

    fn refNoDeref(self: *Runner) !void {
        // Listing is enough: the SDK never fetches a `$ref` URI.
        _ = try self.client.listTools(self.arena, null, self.opts());
    }
};

fn missingContext(scenario: []const u8) u8 {
    std.log.err("scenario {s} needs MCP_CONFORMANCE_CONTEXT with its credentials", .{scenario});
    return 1;
}

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

    // Authorization: pre-registered credentials from the context when given, else a client
    // ID metadata document where supported, else dynamic registration. The context does not
    // name the issuer, so the credentials bind to the first authorization server.
    var registration: mcp.auth.OAuthClient.Registration = .{ .client_metadata_url = "https://conformance-test.local/client-metadata.json" };
    var pre_registered: [1]mcp.auth.OAuthClient.Credentials = undefined;
    if (context) |ctx| if (json.getString(ctx, "client_id")) |client_id| {
        pre_registered[0] = .{ .client_id = client_id, .client_secret = json.getString(ctx, "client_secret") };
        registration = .{ .pre_registered = &pre_registered };
    };
    var oauth: mcp.auth.OAuthClient = .init(io, gpa, .{ .registration = registration, .allow_http = true, .authorize = .headless_redirect });
    defer oauth.deinit();
    var capabilities: types.ClientCapabilities = .{ .roots = .{}, .sampling = .{}, .elicitation = .{ .form = .{ .object = .empty }, .url = .{ .object = .empty } } };

    // The authorization extensions replace the interactive flow.
    var provider: mcp.auth.Provider = oauth.provider();
    var signing_key: ?mcp.auth.jwt.SigningKey = null;
    defer if (signing_key) |*k| k.deinit();
    var client_credentials: ?mcp.auth.ClientCredentials = null;
    defer if (client_credentials) |*c| c.deinit();
    var enterprise: ?mcp.auth.EnterpriseClient = null;
    defer if (enterprise) |*e| e.deinit();
    if (std.mem.startsWith(u8, scenario, "auth/client-credentials-")) {
        const ctx = context orelse return missingContext(scenario);
        const client_id = json.getString(ctx, "client_id") orelse return missingContext(scenario);
        var auth: mcp.auth.ClientAuth = undefined;
        if (json.getString(ctx, "private_key_pem")) |pem_text| {
            signing_key = try mcp.auth.jwt.SigningKey.fromPem(gpa, pem_text);
            auth = .{ .private_key_jwt = .{ .client_id = client_id, .key = &signing_key.? } };
        } else {
            const secret = json.getString(ctx, "client_secret") orelse return missingContext(scenario);
            auth = .{ .client_secret = .{ .client_id = client_id, .client_secret = secret } };
        }
        client_credentials = .init(io, gpa, .{ .client = auth, .allow_http = true });
        provider = client_credentials.?.provider();
        capabilities = try mcp.auth.withExtension(arena, capabilities, mcp.auth.client_credentials.extension_id);
    } else if (std.mem.eql(u8, scenario, "auth/enterprise-managed-authorization")) {
        const ctx = context orelse return missingContext(scenario);
        const get = struct {
            fn field(c: Value, key: []const u8) ![]const u8 {
                return json.getString(c, key) orelse error.MissingContext;
            }
        }.field;
        enterprise = .init(io, gpa, .{
            .idp = .{
                .token_endpoint = try get(ctx, "idp_token_endpoint"),
                .issuer = json.getString(ctx, "idp_issuer"),
                .client = .{ .none = .{ .client_id = try get(ctx, "idp_client_id") } },
            },
            .assertion = .{ .static = .{ .token = try get(ctx, "idp_id_token") } },
            .client = .{ .client_secret = .{ .client_id = try get(ctx, "client_id"), .client_secret = try get(ctx, "client_secret") } },
            .allow_http = true,
        });
        provider = enterprise.?.provider();
        capabilities = try mcp.auth.withExtension(arena, capabilities, mcp.auth.enterprise.extension_id);
    }

    const http = try mcp.transport.HttpClient.init(io, gpa, .{ .url = url, .auth_provider = provider });
    defer http.deinit();
    var client: Client = .init(gpa, io, .{
        .info = .{ .name = "zig-sdk-conformance-client", .version = "0.1.0" },
        .capabilities = capabilities,
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
    else if (std.mem.startsWith(u8, scenario, "auth/"))
        runner.authorized()
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
