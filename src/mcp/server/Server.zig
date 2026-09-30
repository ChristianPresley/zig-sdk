//! The MCP server engine: registries, the dispatch ladder, multi round-trip requests,
//! subscriptions and the result metadata. Transports feed it `Inbound` messages.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;

const types = @import("../protocol/types.zig");
const version = @import("../protocol/version.zig");
const errors = @import("../protocol/errors.zig");
const meta_mod = @import("../protocol/meta.zig");
const methods = @import("../protocol/methods.zig");
const json = @import("../json.zig");
const message = @import("../jsonrpc/message.zig");
const RequestId = @import("../jsonrpc/id.zig").RequestId;
const Transport = @import("../transport/Transport.zig");
const Limits = @import("../Limits.zig");
const derive = @import("../schema/derive.zig");
const validator = @import("../schema/validator.zig");
const envelope = @import("../transport/envelope.zig");
const UriTemplate = @import("../uri_template/UriTemplate.zig");
const request_state = @import("request_state.zig");
const mrtr = @import("mrtr.zig");
const tasks = @import("tasks.zig");
const client_credentials = @import("../auth/client_credentials.zig");
const enterprise = @import("../auth/enterprise.zig");
const skills = @import("skills.zig");
const skills_proto = @import("../protocol/skills.zig");
const apps = @import("apps.zig");
const apps_proto = @import("../protocol/apps.zig");
pub const RequestContext = @import("RequestContext.zig");
pub const Outcome = mrtr.Outcome;
pub const InputRequired = mrtr.InputRequired;

const Server = @This();

pub const CacheHint = struct {
    ttl_ms: i64 = 0,
    scope: types.CacheScope = .private,
};

pub const Options = struct {
    info: types.Implementation,
    instructions: ?[]const u8 = null,
    /// Exact mirror of the advertised `ServerCapabilities`. The registration of a tool,
    /// resource or prompt declares the matching capability when it is absent.
    capabilities: types.ServerCapabilities = .{},
    /// Which kinds of input requests handlers can issue.
    mrtr: struct {
        elicitation: bool = true,
        sampling: bool = false,
        sampling_tools: bool = false,
        roots: bool = false,
    } = .{},
    limits: Limits = .{},
    /// How the server protects `requestState`. `unprotected` is only acceptable when tampering
    /// can cause nothing worse than request failure.
    request_state: enum { sealed_ephemeral, unprotected } = .sealed_ephemeral,
    /// What happens when tool arguments violate the input schema.
    invalid_args_policy: enum { tool_error, rpc_error } = .tool_error,
    /// Mirror `structuredContent` into a text block when the handler gave none.
    structured_text_mirror: bool = true,
    /// Ignore JSON Schema keywords that the validator does not support. Without this option,
    /// the registration of the tool fails.
    allow_unsupported_schema_keywords: bool = false,
    /// Enable the Tasks extension. The server then advertises it under `extensions`.
    tasks: ?tasks.Options = null,
    /// The authorization extensions that the authorization server of this MCP server
    /// provides. The server advertises each enabled one under `extensions`.
    authorization_extensions: struct {
        /// `io.modelcontextprotocol/oauth-client-credentials`.
        client_credentials: bool = false,
        /// `io.modelcontextprotocol/enterprise-managed-authorization`.
        enterprise_managed: bool = false,
    } = .{},
    /// Enable the Skills extension. The server then advertises it under `extensions` and
    /// declares the `resources` capability. Register skills with `addSkill`.
    skills: ?skills.Options = null,
    /// Enable the MCP Apps extension. The server then advertises it under `extensions`.
    /// Register views with `addUiResource` and link tools to them with `ToolDef.ui`.
    apps: ?apps.Options = null,
    cache: struct {
        discover: CacheHint = .{},
        lists: CacheHint = .{},
        reads: CacheHint = .{},
    } = .{},
};

pub const ToolHandler = *const fn (ctx: *RequestContext, args: Value) anyerror!Outcome(types.CallToolResult);
pub const ResourceHandler = *const fn (ctx: *RequestContext, uri: []const u8) anyerror!Outcome(types.ReadResourceResult);
pub const TemplateHandler = *const fn (ctx: *RequestContext, uri: []const u8, vars: []const UriTemplate.Variable) anyerror!Outcome(types.ReadResourceResult);
pub const TemplateLister = *const fn (ctx: *RequestContext) anyerror![]const types.Resource;
pub const PromptHandler = *const fn (ctx: *RequestContext, args: ?std.json.ArrayHashMap([]const u8)) anyerror!Outcome(types.GetPromptResult);
pub const CompletionHandler = *const fn (ctx: *RequestContext, params: types.CompleteRequestParams) anyerror!types.CompleteResult.Completion;

pub const ToolDef = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    annotations: ?types.ToolAnnotations = null,
    icons: ?[]const types.Icon = null,
    /// Only for `addToolJson`: the input schema as JSON text.
    input_schema: ?[]const u8 = null,
    /// JSON text of the output schema.
    output_schema: ?[]const u8 = null,
    /// Client capabilities the tool needs. Checked before the handler runs (`-32021`).
    requires_client: ?types.ClientCapabilities = null,
    /// How the tool relates to the Tasks extension.
    task_support: tasks.TaskSupport = .none,
    /// The `_meta` object of the tool. The server copies it.
    meta: ?Value = null,
    /// The MCP Apps metadata. The server puts it under `_meta.ui`. `resourceUri` must be a
    /// `ui://` URI. `checkUiLinks` checks that the resource exists.
    ui: ?apps_proto.ToolMeta = null,
    userdata: ?*anyopaque = null,
};

pub const ResourceDef = struct {
    uri: []const u8,
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    mime_type: ?[]const u8 = null,
    annotations: ?types.Annotations = null,
    size: ?i64 = null,
    /// The `_meta` object of the resource. The server copies it.
    meta: ?Value = null,
    userdata: ?*anyopaque = null,
};

pub const ResourceTemplateDef = struct {
    uri_template: []const u8,
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    mime_type: ?[]const u8 = null,
    annotations: ?types.Annotations = null,
    list: ?TemplateLister = null,
    userdata: ?*anyopaque = null,
};

pub const PromptDef = struct {
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    arguments: ?[]const types.PromptArgument = null,
    userdata: ?*anyopaque = null,
};

const ToolEntry = struct {
    def: types.Tool,
    input: validator.Schema,
    output: ?validator.Schema,
    handler: ToolHandler,
    requires_client: ?types.ClientCapabilities,
    task_support: tasks.TaskSupport,
    /// The MCP Apps metadata, also present under `def._meta.ui`.
    ui: ?apps_proto.ToolMeta = null,
    userdata: ?*anyopaque,
    enabled: bool = true,
};

const ResourceEntry = struct {
    def: types.Resource,
    handler: ResourceHandler,
    userdata: ?*anyopaque,
    enabled: bool = true,
};

const TemplateEntry = struct {
    def: types.ResourceTemplate,
    template: UriTemplate,
    handler: TemplateHandler,
    list: ?TemplateLister,
    userdata: ?*anyopaque,
    enabled: bool = true,
};

const PromptEntry = struct {
    def: types.Prompt,
    handler: PromptHandler,
    userdata: ?*anyopaque,
    enabled: bool = true,
};

const Subscription = struct {
    id: RequestId,
    filter: types.SubscriptionFilter,
    responder: Transport.Responder,
    cancel: *Transport.CancelToken,
    kind: Transport.Kind,
    mutex: Io.Mutex = .init,
    broken: bool = false,
    arena: std.heap.ArenaAllocator,
};

gpa: Allocator,
options: Options,
/// Owns every registered definition. Never reset.
registry_arena: std.heap.ArenaAllocator,
registry_lock: Io.RwLock = .init,
tools: std.ArrayList(ToolEntry) = .empty,
resources: std.ArrayList(ResourceEntry) = .empty,
templates: std.ArrayList(TemplateEntry) = .empty,
prompts: std.ArrayList(PromptEntry) = .empty,
completion_handler: ?CompletionHandler = null,
subscriptions: std.ArrayList(*Subscription) = .empty,
subscriptions_lock: Io.Mutex = .init,
state_codec: ?request_state.Codec = null,
task_store: ?tasks.Store = null,
skill_registry: ?skills.Registry = null,
/// Counts of protocol violations by peers, for diagnostics.
violations: std.atomic.Value(u64) = .init(0),
/// Set once `shutdownSubscriptions` ran. Later listen requests end immediately.
shutting_down: std.atomic.Value(bool) = .init(false),

pub const InitError = error{ OutOfMemory, EntropyUnavailable };

pub fn init(gpa: Allocator, io: Io, options: Options) InitError!Server {
    var server: Server = .{
        .gpa = gpa,
        .options = options,
        .registry_arena = .init(gpa),
    };
    if (options.request_state == .sealed_ephemeral) {
        server.state_codec = try request_state.Codec.initRandom(io, options.limits.request_state_ttl);
    }
    errdefer {
        if (server.state_codec) |*c| c.deinit();
        server.registry_arena.deinit();
    }
    if (options.tasks) |task_options| {
        server.task_store = tasks.Store.init(gpa, io, task_options);
        try server.advertiseExtension(tasks.extension_id, .{ .object = .empty });
    }
    if (options.skills) |skill_options| {
        server.skill_registry = skills.Registry.init(skill_options);
        try server.advertiseExtension(skills.extension_id, try server.skill_registry.?.settings(server.registry_arena.allocator()));
        // Skill files are resources. The extension needs the `resources` capability.
        if (server.options.capabilities.resources == null) server.options.capabilities.resources = .{ .listChanged = true, .subscribe = true };
    }
    if (options.apps != null) try server.advertiseExtension(apps.extension_id, .{ .object = .empty });
    if (options.authorization_extensions.client_credentials) try server.advertiseExtension(client_credentials.extension_id, .{ .object = .empty });
    if (options.authorization_extensions.enterprise_managed) try server.advertiseExtension(enterprise.extension_id, .{ .object = .empty });
    return server;
}

/// Add an extension to `capabilities.extensions`. The function keeps the other extensions
/// that the caller declared.
fn advertiseExtension(self: *Server, id: []const u8, settings: Value) Allocator.Error!void {
    const arena = self.registry_arena.allocator();
    var ext: std.json.ObjectMap = .empty;
    if (self.options.capabilities.extensions) |existing| if (existing == .object) {
        var it = existing.object.iterator();
        while (it.next()) |kv| try ext.put(arena, kv.key_ptr.*, kv.value_ptr.*);
    };
    try ext.put(arena, id, settings);
    self.options.capabilities.extensions = .{ .object = ext };
}

pub fn deinit(self: *Server) void {
    if (self.task_store) |*store| store.deinit();
    if (self.skill_registry) |*r| r.deinit(self.gpa);
    if (self.state_codec) |*c| c.deinit();
    self.tools.deinit(self.gpa);
    self.resources.deinit(self.gpa);
    self.templates.deinit(self.gpa);
    self.prompts.deinit(self.gpa);
    for (self.subscriptions.items) |s| {
        s.arena.deinit();
        self.gpa.destroy(s);
    }
    self.subscriptions.deinit(self.gpa);
    self.registry_arena.deinit();
    self.* = undefined;
}

// ---------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------

pub const RegisterError = error{
    OutOfMemory,
    InvalidToolName,
    InvalidSchema,
    SchemaNotObject,
    /// An `x-mcp-header` annotation is malformed, duplicated or on a non-scalar property.
    InvalidHeaderAnnotation,
    /// The schema uses a keyword or a regular expression feature that the validator does
    /// not support (see `Options`).
    UnsupportedKeyword,
    /// The schema references a document other than itself.
    RemoteRef,
    /// The schema names a dialect other than JSON Schema 2020-12.
    UnsupportedDialect,
    DuplicateName,
    InvalidUriTemplate,
    /// `ToolDef.meta` or `ResourceDef.meta` is not an object, or `ToolDef.meta` has a `ui`
    /// key and `ToolDef.ui` is also set.
    InvalidMeta,
    /// A UI resource URI is not a `ui://` URI, or the visibility list is empty or repeats a
    /// value.
    InvalidUiMeta,
    /// The server has no option for the extension.
    ExtensionNotEnabled,
};

/// The errors of `addSkill` and `addDynamicSkill`.
pub const SkillRegisterError = RegisterError || skills.DefinitionError;

/// Copy a JSON value into the registry arena.
fn copyValue(self: *Server, value: Value) Allocator.Error!Value {
    const arena = self.registry_arena.allocator();
    const text = try json.writeAlloc(arena, value);
    return json.parseTree(arena, text) catch return error.OutOfMemory;
}

/// Build the `_meta` object of a tool from `def.meta` and `def.ui`.
fn toolMetaValue(self: *Server, def: ToolDef) RegisterError!?Value {
    const arena = self.registry_arena.allocator();
    var meta: ?Value = null;
    if (def.meta) |m| {
        if (m != .object) return error.InvalidMeta;
        meta = try self.copyValue(m);
    }
    const ui = def.ui orelse return meta;
    if (ui.resourceUri) |uri| if (!apps_proto.isUiUri(uri)) return error.InvalidUiMeta;
    if (ui.visibility) |list| {
        if (list.len == 0) return error.InvalidUiMeta;
        for (list, 0..) |v, i| for (list[0..i]) |w| if (v == w) return error.InvalidUiMeta;
    }
    if (meta == null) meta = .{ .object = .empty };
    if (meta.?.object.get("ui") != null) return error.InvalidMeta;
    const ui_value = (try apps_proto.metaValue(arena, ui)).object.get("ui").?;
    try meta.?.object.put(arena, "ui", ui_value);
    return meta;
}

fn compileSchema(self: *Server, root: Value) RegisterError!validator.Schema {
    return validator.compile(self.registry_arena.allocator(), root, .{
        .allow_unsupported_keywords = self.options.allow_unsupported_schema_keywords,
        .limits = self.options.limits.schema,
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedKeyword, error.UnsupportedRegex => return error.UnsupportedKeyword,
        error.RemoteRef => return error.RemoteRef,
        error.UnsupportedDialect => return error.UnsupportedDialect,
        error.InvalidSchema, error.SchemaTooDeep, error.TooManySubschemas, error.DuplicateAnchor => return error.InvalidSchema,
        error.InvalidRegex, error.RegexTooLarge => return error.InvalidSchema,
    };
}

fn validateToolName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128) return false;
    for (name) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.')) return false;
    }
    return true;
}

fn parseSchemaObject(self: *Server, text: []const u8, require_object_type: bool) RegisterError!Value {
    const arena = self.registry_arena.allocator();
    const tree = json.parseTree(arena, text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSchema,
    };
    if (tree != .object) return error.SchemaNotObject;
    if (require_object_type) {
        const t = json.getString(tree, "type") orelse return error.SchemaNotObject;
        if (!std.mem.eql(u8, t, "object")) return error.SchemaNotObject;
    }
    return tree;
}

/// Register a tool. The server parses the arguments into the type of the second parameter of
/// the handler. The SDK derives the input schema from that type at compile time.
pub fn addTool(self: *Server, def: ToolDef, comptime handler: anytype) RegisterError!void {
    const Fn = @TypeOf(handler);
    const params = @typeInfo(Fn).@"fn".params;
    if (params.len != 2) @compileError("tool handler must be fn (*RequestContext, Args) anyerror!Outcome(CallToolResult)");
    const Args = params[1].type.?;
    if (Args == Value) return self.addToolJson(def, handler);
    const Wrapper = struct {
        fn call(ctx: *RequestContext, args: Value) anyerror!Outcome(types.CallToolResult) {
            const parsed = json.parseValue(Args, ctx.arena, args) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidArguments,
            };
            return handler(ctx, parsed);
        }
    };
    var d = def;
    d.input_schema = derive.schemaText(Args);
    return self.addToolJson(d, Wrapper.call);
}

/// Register a tool with an explicit JSON Schema (as text) and a raw-value handler.
pub fn addToolJson(self: *Server, def: ToolDef, handler: ToolHandler) RegisterError!void {
    if (!validateToolName(def.name)) return error.InvalidToolName;
    const arena = self.registry_arena.allocator();
    const input_schema = try self.parseSchemaObject(def.input_schema orelse "{\"type\":\"object\"}", true);
    const output_schema: ?Value = if (def.output_schema) |t| try self.parseSchemaObject(t, false) else null;
    if (!envelope.schemaHeadersValid(input_schema)) return error.InvalidHeaderAnnotation;
    const input = try self.compileSchema(input_schema);
    const output: ?validator.Schema = if (output_schema) |o| try self.compileSchema(o) else null;
    const meta = try self.toolMetaValue(def);
    const entry: ToolEntry = .{
        .def = .{
            .name = try arena.dupe(u8, def.name),
            .title = if (def.title) |t| try arena.dupe(u8, t) else null,
            .description = if (def.description) |t| try arena.dupe(u8, t) else null,
            .icons = def.icons,
            .inputSchema = input_schema,
            .outputSchema = output_schema,
            .annotations = def.annotations,
            ._meta = meta,
        },
        .input = input,
        .output = output,
        .handler = handler,
        .requires_client = def.requires_client,
        .task_support = def.task_support,
        .ui = if (def.ui) |ui| .{
            .resourceUri = if (ui.resourceUri) |u| try arena.dupe(u8, u) else null,
            .visibility = if (ui.visibility) |v| try arena.dupe(apps_proto.Visibility, v) else null,
        } else null,
        .userdata = def.userdata,
    };
    self.registry_lock.lockSharedUncancelable(std.Io.Threaded.global_single_threaded.io());
    defer self.registry_lock.unlockShared(std.Io.Threaded.global_single_threaded.io());
    for (self.tools.items) |t| if (std.mem.eql(u8, t.def.name, def.name)) return error.DuplicateName;
    try self.tools.append(self.gpa, entry);
    if (self.options.capabilities.tools == null) self.options.capabilities.tools = .{ .listChanged = true };
}

pub fn addResource(self: *Server, def: ResourceDef, handler: ResourceHandler) RegisterError!void {
    const arena = self.registry_arena.allocator();
    for (self.resources.items) |r| if (std.mem.eql(u8, r.def.uri, def.uri)) return error.DuplicateName;
    if (def.meta) |m| if (m != .object) return error.InvalidMeta;
    const meta: ?Value = if (def.meta) |m| try self.copyValue(m) else null;
    try self.resources.append(self.gpa, .{
        .def = .{
            .uri = try arena.dupe(u8, def.uri),
            .name = try arena.dupe(u8, def.name),
            .title = if (def.title) |t| try arena.dupe(u8, t) else null,
            .description = if (def.description) |t| try arena.dupe(u8, t) else null,
            .mimeType = if (def.mime_type) |t| try arena.dupe(u8, t) else null,
            .annotations = def.annotations,
            .size = def.size,
            ._meta = meta,
        },
        .handler = handler,
        .userdata = def.userdata,
    });
    if (self.options.capabilities.resources == null) self.options.capabilities.resources = .{ .listChanged = true, .subscribe = true };
}

/// Register a skill of the Skills extension from files in memory. The function parses the
/// frontmatter of `SKILL.md`. It checks the rules of the extension and of the Agent Skills
/// specification. Then it computes the digests and registers every file as a resource. The
/// server copies all bytes.
pub fn addSkill(self: *Server, def: skills.SkillDef) SkillRegisterError!void {
    const registry = if (self.skill_registry) |*r| r else return error.ExtensionNotEnabled;
    const arena = self.registry_arena.allocator();
    const limits = self.options.limits.skills;
    const prepared = try registry.prepare(arena, def, limits.max_files, limits.max_bytes);
    for (prepared.new_files) |file| {
        try self.addResource(.{
            .uri = file.uri,
            .name = file.name,
            .description = file.description,
            .mime_type = file.mime_type,
            .size = @intCast(file.content.len),
            .userdata = file,
        }, skills.readFile);
    }
    try registry.commit(self.gpa, prepared);
}

/// Register a skill whose content the application generates. The entry has
/// `"resources": "dynamic"`. The application serves the files with its own resources or
/// resource templates. `def.skill_md` gives the frontmatter of the entry.
pub fn addDynamicSkill(self: *Server, def: skills.DynamicSkillDef) SkillRegisterError!void {
    const registry = if (self.skill_registry) |*r| r else return error.ExtensionNotEnabled;
    const prepared = try registry.prepareDynamic(self.registry_arena.allocator(), def);
    try registry.commit(self.gpa, prepared);
}

/// Register a view of the MCP Apps extension with static HTML. The server copies the HTML.
pub fn addUiResource(self: *Server, def: apps.UiResourceDef, html: []const u8) RegisterError!void {
    return self.addUiEntry(def, try self.registry_arena.allocator().dupe(u8, html), null);
}

/// Register a view of the MCP Apps extension whose content `handler` gives. The server sets
/// the MIME type and the UI metadata of each content item.
pub fn addUiResourceHandler(self: *Server, def: apps.UiResourceDef, handler: apps.ResourceHandler) RegisterError!void {
    return self.addUiEntry(def, null, handler);
}

fn addUiEntry(self: *Server, def: apps.UiResourceDef, html: ?[]const u8, handler: ?apps.ResourceHandler) RegisterError!void {
    if (!apps_proto.isUiUri(def.uri)) return error.InvalidUiMeta;
    const arena = self.registry_arena.allocator();
    const meta: ?Value = if (def.meta) |m| try apps_proto.metaValue(arena, m) else null;
    const entry = try arena.create(apps.UiEntry);
    entry.* = .{ .html = html, .meta = meta, .handler = handler, .userdata = def.userdata };
    try self.addResource(.{
        .uri = def.uri,
        .name = def.name,
        .title = def.title,
        .description = def.description,
        .mime_type = apps_proto.mime_type,
        .size = if (html) |h| @intCast(h.len) else null,
        .meta = if (def.meta_in_listing) meta else null,
        .userdata = entry,
    }, apps.readUi);
}

pub const UiLinkError = error{
    /// A tool names a `resourceUri` that no resource or resource template of the server
    /// serves. `checkUiLinks` stores the tool name in `broken_tool`.
    UnknownUiResource,
};

/// Check that the `_meta.ui.resourceUri` of every tool names a resource of this server.
/// The extension requires that the resource exists. Call it after the registration.
pub fn checkUiLinks(self: *Server, broken_tool: ?*[]const u8) UiLinkError!void {
    var scratch: std.heap.ArenaAllocator = .init(self.gpa);
    defer scratch.deinit();
    var vars: std.ArrayList(UriTemplate.Variable) = .empty;
    for (self.tools.items) |t| {
        const ui = t.ui orelse continue;
        const uri = ui.resourceUri orelse continue;
        const found = blk: {
            for (self.resources.items) |r| if (std.mem.eql(u8, r.def.uri, uri)) break :blk true;
            for (self.templates.items) |tpl| {
                vars.clearRetainingCapacity();
                if (tpl.template.match(uri, &vars, scratch.allocator()) catch false) break :blk true;
            }
            break :blk false;
        };
        if (!found) {
            if (broken_tool) |out| out.* = t.def.name;
            return error.UnknownUiResource;
        }
    }
}

/// True when the tool must stay hidden from the client of `ctx`. This occurs when the Apps
/// fallback applies to the client and only a view can call the tool.
fn hiddenFromClient(self: *const Server, ctx: *const RequestContext, entry: *const ToolEntry) bool {
    const ui = entry.ui orelse return false;
    if (!self.plainToolsFor(ctx)) return false;
    return !ui.visibleToModel();
}

/// True when the client of `ctx` gets tools without UI metadata.
fn plainToolsFor(self: *const Server, ctx: *const RequestContext) bool {
    const options = self.options.apps orelse return false;
    if (!options.fallback_for_other_clients) return false;
    return !apps_proto.clientSupports(ctx.meta.client_capabilities);
}

/// A copy of a tool definition without the UI keys in `_meta`.
fn withoutUiMeta(arena: Allocator, def: types.Tool) Allocator.Error!types.Tool {
    const meta = def._meta orelse return def;
    if (meta != .object) return def;
    var copy: std.json.ObjectMap = .empty;
    var it = meta.object.iterator();
    while (it.next()) |kv| {
        if (std.mem.eql(u8, kv.key_ptr.*, "ui") or std.mem.eql(u8, kv.key_ptr.*, apps_proto.legacy_resource_uri_key)) continue;
        try copy.put(arena, kv.key_ptr.*, kv.value_ptr.*);
    }
    var out = def;
    out._meta = if (copy.count() == 0) null else .{ .object = copy };
    return out;
}

pub fn addResourceTemplate(self: *Server, def: ResourceTemplateDef, handler: TemplateHandler) RegisterError!void {
    const arena = self.registry_arena.allocator();
    const source = try arena.dupe(u8, def.uri_template);
    const template = UriTemplate.parse(arena, source, self.options.limits.uri_template.max_expressions) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidUriTemplate,
    };
    try self.templates.append(self.gpa, .{
        .def = .{
            .uriTemplate = source,
            .name = try arena.dupe(u8, def.name),
            .title = if (def.title) |t| try arena.dupe(u8, t) else null,
            .description = if (def.description) |t| try arena.dupe(u8, t) else null,
            .mimeType = if (def.mime_type) |t| try arena.dupe(u8, t) else null,
            .annotations = def.annotations,
        },
        .template = template,
        .handler = handler,
        .list = def.list,
        .userdata = def.userdata,
    });
    if (self.options.capabilities.resources == null) self.options.capabilities.resources = .{ .listChanged = true, .subscribe = true };
}

pub fn addPrompt(self: *Server, def: PromptDef, handler: PromptHandler) RegisterError!void {
    if (!validateToolName(def.name)) return error.InvalidToolName;
    const arena = self.registry_arena.allocator();
    for (self.prompts.items) |p| if (std.mem.eql(u8, p.def.name, def.name)) return error.DuplicateName;
    try self.prompts.append(self.gpa, .{
        .def = .{
            .name = try arena.dupe(u8, def.name),
            .title = if (def.title) |t| try arena.dupe(u8, t) else null,
            .description = if (def.description) |t| try arena.dupe(u8, t) else null,
            .arguments = def.arguments,
        },
        .handler = handler,
        .userdata = def.userdata,
    });
    if (self.options.capabilities.prompts == null) self.options.capabilities.prompts = .{ .listChanged = true };
}

pub fn setCompletionHandler(self: *Server, handler: CompletionHandler) void {
    self.completion_handler = handler;
    if (self.options.capabilities.completions == null) self.options.capabilities.completions = .{ .object = .empty };
}

/// Enable or disable a registered tool. Publishes `notifications/tools/list_changed`.
pub fn setToolEnabled(self: *Server, io: Io, name: []const u8, enabled: bool) bool {
    var changed = false;
    for (self.tools.items) |*t| {
        if (std.mem.eql(u8, t.def.name, name)) {
            changed = t.enabled != enabled;
            t.enabled = enabled;
        }
    }
    if (changed) self.publish(io, .tools_list_changed, null);
    return changed;
}

pub fn setPromptEnabled(self: *Server, io: Io, name: []const u8, enabled: bool) bool {
    var changed = false;
    for (self.prompts.items) |*p| {
        if (std.mem.eql(u8, p.def.name, name)) {
            changed = p.enabled != enabled;
            p.enabled = enabled;
        }
    }
    if (changed) self.publish(io, .prompts_list_changed, null);
    return changed;
}

/// Announce that a resource changed. Delivered to listeners subscribed to `uri`.
pub fn notifyResourceUpdated(self: *Server, io: Io, uri: []const u8) void {
    self.publish(io, .resource_updated, uri);
}

pub fn notifyToolsListChanged(self: *Server, io: Io) void {
    self.publish(io, .tools_list_changed, null);
}

pub fn notifyPromptsListChanged(self: *Server, io: Io) void {
    self.publish(io, .prompts_list_changed, null);
}

pub fn notifyResourcesListChanged(self: *Server, io: Io) void {
    self.publish(io, .resources_list_changed, null);
}

// ---------------------------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------------------------

/// Handle one inbound message. Requests always end in exactly one `finish` or `abort` on the
/// responder. This function ignores notifications and responses. Transports process
/// `notifications/cancelled` themselves.
pub fn handle(self: *Server, io: Io, inbound: Transport.Inbound) void {
    switch (inbound.message) {
        .request => |req| self.handleRequest(io, inbound, req),
        .notification => {},
        .response, .error_response => _ = self.violations.fetchAdd(1, .monotonic),
    }
}

fn handleRequest(self: *Server, io: Io, inbound: Transport.Inbound, req: message.Message.Request) void {
    var ctx: RequestContext = .{
        .io = io,
        .gpa = self.gpa,
        .arena = inbound.arena,
        .server = self,
        .id = req.id,
        .method = req.method,
        .meta = undefined,
        .params = req.params,
        .cancel = inbound.cancel,
        .transport_context = inbound.context,
        .responder = inbound.responder,
        .kind = inbound.kind,
    };
    self.dispatch(&ctx) catch |e| switch (e) {
        error.Rpc => {
            const err = ctx.rpc_error orelse errors.internalError("Internal error");
            self.sendError(&ctx, err);
        },
        error.Canceled => inbound.responder.abort(io),
        error.OutOfMemory => self.sendError(&ctx, errors.internalError("Out of memory")),
    };
}

fn sendError(self: *Server, ctx: *RequestContext, err: errors.RpcError) void {
    _ = self;
    std.debug.assert(errors.Code.isEmittable(err.code));
    var aw: Io.Writer.Allocating = .init(ctx.arena);
    message.writeErrorResponse(&aw.writer, ctx.id, err.toWire()) catch {
        ctx.responder.abort(ctx.io);
        return;
    };
    ctx.responder.finish(ctx.io, aw.written()) catch {};
}

fn finishResult(self: *Server, ctx: *RequestContext, result: anytype) RequestContext.Error!void {
    var stamped = result;
    const T = @TypeOf(stamped);
    if (@hasField(T, "_meta")) {
        const MetaT = @TypeOf(stamped._meta);
        if (MetaT == ?types.ResultMetaObject) {
            if (stamped._meta == null) stamped._meta = .{};
            if (stamped._meta.?.@"io.modelcontextprotocol/serverInfo" == null) {
                stamped._meta.?.@"io.modelcontextprotocol/serverInfo" = self.options.info;
            }
        } else if (MetaT == types.SubscriptionsListenResultMetaObject) {
            if (stamped._meta.@"io.modelcontextprotocol/serverInfo" == null) {
                stamped._meta.@"io.modelcontextprotocol/serverInfo" = self.options.info;
            }
        }
    }
    if (@hasField(T, "ttlMs") and @hasField(T, "cacheScope")) {
        // `skills/get` carries the same cache fields as `resources/read`.
        const hint = if (T == types.DiscoverResult) self.options.cache.discover else if (T == types.ReadResourceResult or T == skills_proto.GetSkillResult) self.options.cache.reads else self.options.cache.lists;
        if (stamped.ttlMs == null) stamped.ttlMs = @max(hint.ttl_ms, 0);
        if (stamped.cacheScope == null) stamped.cacheScope = hint.scope;
        if (stamped.ttlMs.? < 0) stamped.ttlMs = 0;
    }
    var aw: Io.Writer.Allocating = .init(ctx.arena);
    message.writeResponse(&aw.writer, ctx.id, stamped) catch return error.OutOfMemory;
    ctx.responder.finish(ctx.io, aw.written()) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Canceled,
    };
}

fn dispatch(self: *Server, ctx: *RequestContext) RequestContext.Error!void {
    // Legacy handshake from a pre-2026 client: name the supported versions.
    if (std.mem.eql(u8, ctx.method, "initialize")) {
        var map: std.json.ObjectMap = .empty;
        var versions: std.json.Array = .init(ctx.arena);
        try versions.append(.{ .string = version.version });
        try map.put(ctx.arena, "supportedVersions", .{ .array = versions });
        return ctx.setError(.{
            .code = errors.Code.method_not_found.int(),
            .message = "Method not found: initialize. This server supports MCP 2026-07-28 only. Use server/discover.",
            .data = .{ .object = map },
        });
    }

    // Required per-request envelope.
    ctx.meta = meta_mod.lift(ctx.arena, ctx.params) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MissingMeta => return ctx.setError(errors.invalidParams("params._meta is required")),
        error.MissingProtocolVersion => return ctx.setError(errors.invalidParams("params._meta[\"io.modelcontextprotocol/protocolVersion\"] is required")),
        error.MissingClientCapabilities => return ctx.setError(errors.invalidParams("params._meta[\"io.modelcontextprotocol/clientCapabilities\"] is required")),
        error.InvalidMeta => return ctx.setError(errors.invalidParams("params._meta is malformed")),
    };

    // Version.
    if (!std.mem.eql(u8, ctx.meta.protocol_version, version.version)) {
        const err = try errors.unsupportedProtocolVersion(ctx.arena, &version.supported_versions, ctx.meta.protocol_version);
        return ctx.setError(err);
    }

    // The Tasks extension has its own methods.
    if (std.mem.startsWith(u8, ctx.method, "tasks/")) return self.dispatchTask(ctx);
    // So has the Skills extension.
    if (std.mem.startsWith(u8, ctx.method, "skills/") or std.mem.eql(u8, ctx.method, skills_proto.method_directory_read)) return self.dispatchSkills(ctx);

    // Method table and capability gate.
    const method = methods.Method.fromName(ctx.method) orelse {
        const msg = try std.fmt.allocPrint(ctx.arena, "Method not found: {s}", .{ctx.method});
        return ctx.setError(errors.methodNotFound(msg));
    };
    if (!self.isMethodAvailable(method)) {
        const msg = try std.fmt.allocPrint(ctx.arena, "Method not found: {s} (capability not declared)", .{ctx.method});
        return ctx.setError(errors.methodNotFound(msg));
    }

    switch (method) {
        inline else => |m| try self.dispatchTyped(ctx, m),
    }
}

fn isMethodAvailable(self: *const Server, method: methods.Method) bool {
    const caps = self.options.capabilities;
    return switch (method.gate()) {
        .none => true,
        .tools => caps.tools != null,
        .resources => caps.resources != null,
        .prompts => caps.prompts != null,
        .completions => caps.completions != null,
        .subscriptions => self.supportsSubscriptions(),
    };
}

fn supportsSubscriptions(self: *const Server) bool {
    const caps = self.options.capabilities;
    if (caps.tools) |t| if (t.listChanged orelse false) return true;
    if (caps.prompts) |p| if (p.listChanged orelse false) return true;
    if (caps.resources) |r| {
        if (r.listChanged orelse false) return true;
        if (r.subscribe orelse false) return true;
    }
    return false;
}

fn parseParams(ctx: *RequestContext, comptime T: type) RequestContext.Error!T {
    const p = ctx.params orelse return ctx.setError(errors.invalidParams("params is required"));
    return json.parseValue(T, ctx.arena, p) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MissingField => return ctx.setError(errors.invalidParams("params is missing a required field")),
        else => return ctx.setError(errors.invalidParams("params has an unexpected shape")),
    };
}

fn dispatchTyped(self: *Server, ctx: *RequestContext, comptime method: methods.Method) RequestContext.Error!void {
    const params = try parseParams(ctx, method.Params());
    switch (method) {
        .@"server/discover" => {
            const result: types.DiscoverResult = .{
                .supportedVersions = &version.supported_versions,
                .capabilities = self.options.capabilities,
                .instructions = self.options.instructions,
            };
            try self.finishResult(ctx, result);
        },
        .@"tools/list" => {
            var items: std.ArrayList(types.Tool) = .empty;
            const plain = self.plainToolsFor(ctx);
            for (self.tools.items) |*t| {
                if (!t.enabled or self.hiddenFromClient(ctx, t)) continue;
                try items.append(ctx.arena, if (plain and t.ui != null) try withoutUiMeta(ctx.arena, t.def) else t.def);
            }
            const page = try self.paginate(ctx, types.Tool, items.items, params.cursor);
            try self.finishResult(ctx, types.ListToolsResult{ .tools = page.items, .nextCursor = page.next_cursor });
        },
        .@"tools/call" => try self.callTool(ctx, params),
        .@"resources/list" => {
            var items: std.ArrayList(types.Resource) = .empty;
            for (self.resources.items) |r| if (r.enabled) try items.append(ctx.arena, r.def);
            for (self.templates.items) |t| {
                if (!t.enabled) continue;
                const lister = t.list orelse continue;
                ctx.userdata = t.userdata;
                const listed = lister(ctx) catch |e| return mapHandlerError(ctx, e);
                try items.appendSlice(ctx.arena, listed);
            }
            const page = try self.paginate(ctx, types.Resource, items.items, params.cursor);
            try self.finishResult(ctx, types.ListResourcesResult{ .resources = page.items, .nextCursor = page.next_cursor });
        },
        .@"resources/templates/list" => {
            var items: std.ArrayList(types.ResourceTemplate) = .empty;
            for (self.templates.items) |t| if (t.enabled) try items.append(ctx.arena, t.def);
            const page = try self.paginate(ctx, types.ResourceTemplate, items.items, params.cursor);
            try self.finishResult(ctx, types.ListResourceTemplatesResult{ .resourceTemplates = page.items, .nextCursor = page.next_cursor });
        },
        .@"resources/read" => try self.readResource(ctx, params),
        .@"prompts/list" => {
            var items: std.ArrayList(types.Prompt) = .empty;
            for (self.prompts.items) |p| if (p.enabled) try items.append(ctx.arena, p.def);
            const page = try self.paginate(ctx, types.Prompt, items.items, params.cursor);
            try self.finishResult(ctx, types.ListPromptsResult{ .prompts = page.items, .nextCursor = page.next_cursor });
        },
        .@"prompts/get" => try self.getPrompt(ctx, params),
        .@"completion/complete" => {
            var completion: types.CompleteResult.Completion = .{ .values = &.{} };
            if (self.completion_handler) |h| {
                completion = h(ctx, params) catch |e| return mapHandlerError(ctx, e);
            }
            const max = self.options.limits.completion_max_values;
            if (completion.values.len > max) {
                completion.values = completion.values[0..max];
                completion.hasMore = true;
            }
            try self.finishResult(ctx, types.CompleteResult{ .completion = completion });
        },
        .@"subscriptions/listen" => try self.listen(ctx, params),
    }
}

fn mapHandlerError(ctx: *RequestContext, e: anyerror) RequestContext.Error {
    return switch (e) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        error.Rpc => error.Rpc,
        else => {
            const msg = std.fmt.allocPrint(ctx.arena, "Internal error: {t}", .{e}) catch return error.OutOfMemory;
            return ctx.setError(errors.internalError(msg));
        },
    };
}

// ---------------------------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------------------------

fn Page(comptime T: type) type {
    return struct { items: []const T, next_cursor: ?[]const u8 };
}

fn paginate(self: *Server, ctx: *RequestContext, comptime T: type, items: []const T, cursor: ?[]const u8) RequestContext.Error!Page(T) {
    const page_size: usize = self.options.limits.page_size;
    var offset: usize = 0;
    if (cursor) |c| {
        if (c.len > 0) {
            offset = decodeCursor(c) orelse return ctx.setError(errors.invalidParams("Invalid cursor"));
            if (offset > items.len) return ctx.setError(errors.invalidParams("Invalid cursor"));
        }
    }
    const end = @min(items.len, offset + page_size);
    var next: ?[]const u8 = null;
    if (end < items.len) next = try encodeCursor(ctx.arena, end);
    return .{ .items = items[offset..end], .next_cursor = next };
}

fn encodeCursor(arena: Allocator, offset: usize) Allocator.Error![]const u8 {
    const raw = try std.fmt.allocPrint(arena, "v1:{d}", .{offset});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const out = try arena.alloc(u8, encoder.calcSize(raw.len));
    return encoder.encode(out, raw);
}

fn decodeCursor(cursor: []const u8) ?usize {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    var buf: [64]u8 = undefined;
    const len = decoder.calcSizeForSlice(cursor) catch return null;
    if (len > buf.len) return null;
    decoder.decode(buf[0..len], cursor) catch return null;
    const raw = buf[0..len];
    if (!std.mem.startsWith(u8, raw, "v1:")) return null;
    return std.fmt.parseInt(usize, raw[3..], 10) catch null;
}

// ---------------------------------------------------------------------------------------------
// Tools, resources, prompts
// ---------------------------------------------------------------------------------------------

fn prepareInputRound(self: *Server, ctx: *RequestContext, method_name: []const u8, target: []const u8, responses: ?types.InputResponses, sealed: ?[]const u8) RequestContext.Error!void {
    ctx.target = target;
    ctx.input_responses = responses;
    if (sealed) |s| {
        if (self.state_codec) |codec| {
            const ad = try request_state.aad(ctx.arena, method_name, target, "");
            const now = Io.Clock.real.now(ctx.io).toSeconds();
            ctx.request_state = codec.unseal(ctx.arena, ad, s, now) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Invalid, error.Expired => {
                    var map: std.json.ObjectMap = .empty;
                    try map.put(ctx.arena, "reason", .{ .string = "invalid_request_state" });
                    return ctx.setError(.{ .code = errors.Code.invalid_params.int(), .message = "Invalid or expired requestState", .data = .{ .object = map } });
                },
            };
        } else {
            ctx.request_state = s;
        }
    }
}

fn finishInputRequired(self: *Server, ctx: *RequestContext, method: methods.Method, ir: InputRequired) RequestContext.Error!void {
    if (!method.allowsInputRequired()) return ctx.setError(errors.internalError("Handler returned input_required for a method that does not allow it"));
    if (ir.count() == 0 and ir.state == null) return ctx.setError(errors.internalError("InputRequiredResult needs inputRequests or requestState"));
    // Every input request kind must be enabled and declared by the client.
    var it = ir.requests.map.iterator();
    while (it.next()) |kv| {
        switch (kv.value_ptr.*) {
            .@"elicitation/create" => |e| {
                if (!self.options.mrtr.elicitation) return ctx.setError(errors.internalError("Elicitation is disabled on this server"));
                try ctx.requireClientCapability(if (e.params.mode() == .url) .elicitation_url else .elicitation_form);
            },
            .@"sampling/createMessage" => |s| {
                if (!self.options.mrtr.sampling) return ctx.setError(errors.internalError("Sampling is disabled on this server"));
                try ctx.requireClientCapability(.sampling);
                if (s.params.tools != null or s.params.toolChoice != null) {
                    if (!self.options.mrtr.sampling_tools) return ctx.setError(errors.internalError("Sampling with tools is disabled on this server"));
                    try ctx.requireClientCapability(.sampling_tools);
                }
            },
            .@"roots/list" => {
                if (!self.options.mrtr.roots) return ctx.setError(errors.internalError("Roots are disabled on this server"));
                try ctx.requireClientCapability(.roots);
            },
        }
    }
    var result: types.InputRequiredResult = .{};
    if (ir.count() > 0) result.inputRequests = ir.requests;
    if (ir.state) |s| {
        if (self.state_codec) |codec| {
            const ad = try request_state.aad(ctx.arena, method.name(), ctx.target, "");
            const now = Io.Clock.real.now(ctx.io).toSeconds();
            result.requestState = codec.seal(ctx.arena, ctx.io, ad, s, now) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.EntropyUnavailable => return ctx.setError(errors.internalError("Entropy unavailable")),
            };
        } else {
            result.requestState = s;
        }
    }
    try self.finishResult(ctx, result);
}

fn callTool(self: *Server, ctx: *RequestContext, params: types.CallToolRequestParams) RequestContext.Error!void {
    const found = self.findTool(params.name);
    const entry = if (found != null and !self.hiddenFromClient(ctx, found.?)) found.? else {
        const msg = try std.fmt.allocPrint(ctx.arena, "Unknown tool: {s}", .{params.name});
        return ctx.setError(errors.invalidParams(msg));
    };
    if (params.arguments) |a| if (a != .object) return ctx.setError(errors.invalidParams("arguments must be an object"));
    if (entry.requires_client) |required| try self.requireCapabilities(ctx, required);
    const client_has_tasks = self.task_store != null and ctx.meta.client_capabilities.hasExtension(tasks.extension_id);
    if (entry.task_support == .required and !client_has_tasks) return ctx.setError(try tasks.missingExtensionError(ctx.arena));
    const args: Value = params.arguments orelse .{ .object = .empty };
    if (try checkArguments(ctx, entry, args)) |detail| return self.rejectArguments(ctx, params.name, detail);
    try self.prepareInputRound(ctx, "tools/call", params.name, params.inputResponses, params.requestState);
    ctx.userdata = entry.userdata;
    var outcome = entry.handler(ctx, args) catch |e| switch (e) {
        error.InvalidArguments => return self.rejectArguments(ctx, params.name, "the arguments do not parse"),
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
        error.Rpc => return error.Rpc,
        else => {
            const result = try types.CallToolResult.err(ctx.arena, "Tool failed: {t}", .{e});
            return self.finishResult(ctx, result);
        },
    };
    if (outcome == .start_task) {
        if (client_has_tasks and entry.task_support != .none) return self.startTask(ctx, entry, params);
        // Without the extension the task body runs at once, inside a synthetic task.
        var synthetic: tasks.Task = .{
            .arena_state = .init(self.gpa),
            .id = "sync",
            .tool = params.name,
            .params = ctx.params orelse .null,
            .kind = ctx.kind,
            .created_ms = 0,
            .updated_ms = 0,
            .ttl_ms = 0,
        };
        defer synthetic.arena_state.deinit();
        ctx.task = &synthetic;
        defer ctx.task = null;
        outcome = entry.handler(ctx, args) catch |e| switch (e) {
            error.InvalidArguments => return self.rejectArguments(ctx, params.name, "the arguments do not parse"),
            error.Canceled => return error.Canceled,
            error.OutOfMemory => return error.OutOfMemory,
            error.Rpc => return error.Rpc,
            else => {
                const result = try types.CallToolResult.err(ctx.arena, "Tool failed: {t}", .{e});
                return self.finishResult(ctx, result);
            },
        };
        if (outcome == .start_task) return ctx.setError(errors.internalError("The tool returned start_task inside a task"));
    }
    switch (outcome) {
        .start_task => unreachable,
        .complete => |r| {
            var result = r;
            if (entry.output) |*out| if (result.isError != true) {
                const sc = result.structuredContent orelse return ctx.setError(errors.internalError("Tool declares an outputSchema but returned no structuredContent"));
                const report = validator.validate(ctx.arena, out, sc) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return ctx.setError(errors.internalError("structuredContent could not be validated")),
                };
                if (!report.valid) {
                    const f = report.first().?;
                    const msg = try std.fmt.allocPrint(ctx.arena, "structuredContent does not match outputSchema at \"{s}\": {s}", .{ f.instance_path, f.message });
                    return ctx.setError(errors.internalError(msg));
                }
            };
            if (self.options.structured_text_mirror and result.structuredContent != null and !hasText(result.content)) {
                const blocks = try ctx.arena.alloc(types.ContentBlock, result.content.len + 1);
                @memcpy(blocks[0..result.content.len], result.content);
                blocks[result.content.len] = .{ .text = .{ .text = try json.writeAlloc(ctx.arena, result.structuredContent.?) } };
                result.content = blocks;
            }
            try self.finishResult(ctx, result);
        },
        .input_required => |ir| try self.finishInputRequired(ctx, .@"tools/call", ir),
    }
}

/// Validate tool arguments against the input schema. Returns a detail string on failure.
fn checkArguments(ctx: *RequestContext, entry: *const ToolEntry, args: Value) RequestContext.Error!?[]const u8 {
    const report = validator.validate(ctx.arena, &entry.input, args) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.EvalBudgetExceeded, error.TooManyRefHops, error.InstanceTooDeep => return "the arguments are too complex to validate",
    };
    if (report.valid) return null;
    const f = report.first().?;
    if (f.instance_path.len == 0) return f.message;
    return try std.fmt.allocPrint(ctx.arena, "at \"{s}\": {s}", .{ f.instance_path, f.message });
}

fn rejectArguments(self: *Server, ctx: *RequestContext, name: []const u8, detail: []const u8) RequestContext.Error!void {
    const msg = try std.fmt.allocPrint(ctx.arena, "Invalid arguments for tool {s}: {s}", .{ name, detail });
    switch (self.options.invalid_args_policy) {
        .tool_error => {
            const result = try types.CallToolResult.err(ctx.arena, "{s}", .{msg});
            return self.finishResult(ctx, result);
        },
        .rpc_error => return ctx.setError(errors.invalidParams(msg)),
    }
}

fn hasText(blocks: []const types.ContentBlock) bool {
    for (blocks) |b| if (b == .text) return true;
    return false;
}

fn requireCapabilities(self: *Server, ctx: *RequestContext, required: types.ClientCapabilities) RequestContext.Error!void {
    _ = self;
    const have = ctx.meta.client_capabilities;
    var missing = false;
    if (required.roots != null and have.roots == null) missing = true;
    if (required.sampling) |s| {
        if (have.sampling == null) missing = true else if (s.tools != null and have.sampling.?.tools == null) missing = true;
    }
    if (required.elicitation) |e| {
        if (e.form != null and !have.hasElicitation(.form)) missing = true;
        if (e.url != null and !have.hasElicitation(.url)) missing = true;
        if (e.form == null and e.url == null and have.elicitation == null) missing = true;
    }
    if (!missing) return;
    const err = try errors.missingRequiredClientCapability(ctx.arena, required, "The tool needs a client capability that the client did not declare");
    return ctx.setError(err);
}

fn findTool(self: *Server, name: []const u8) ?*ToolEntry {
    for (self.tools.items) |*t| if (t.enabled and std.mem.eql(u8, t.def.name, name)) return t;
    return null;
}

fn readResource(self: *Server, ctx: *RequestContext, params: types.ReadResourceRequestParams) RequestContext.Error!void {
    try self.prepareInputRound(ctx, "resources/read", params.uri, params.inputResponses, params.requestState);
    for (self.resources.items) |r| {
        if (!r.enabled or !std.mem.eql(u8, r.def.uri, params.uri)) continue;
        ctx.userdata = r.userdata;
        const outcome = r.handler(ctx, params.uri) catch |e| return mapHandlerError(ctx, e);
        return self.finishRead(ctx, outcome, params.uri);
    }
    var vars: std.ArrayList(UriTemplate.Variable) = .empty;
    for (self.templates.items) |t| {
        if (!t.enabled) continue;
        vars.clearRetainingCapacity();
        if (!try t.template.match(params.uri, &vars, ctx.arena)) continue;
        ctx.userdata = t.userdata;
        const outcome = t.handler(ctx, params.uri, vars.items) catch |e| return mapHandlerError(ctx, e);
        return self.finishRead(ctx, outcome, params.uri);
    }
    return ctx.setError(try errors.resourceNotFound(ctx.arena, params.uri));
}

fn finishRead(self: *Server, ctx: *RequestContext, outcome: Outcome(types.ReadResourceResult), uri: []const u8) RequestContext.Error!void {
    switch (outcome) {
        .complete => |r| {
            if (r.contents.len == 0) return ctx.setError(try errors.resourceNotFound(ctx.arena, uri));
            try self.finishResult(ctx, r);
        },
        .input_required => |ir| try self.finishInputRequired(ctx, .@"resources/read", ir),
        .start_task => return ctx.setError(errors.internalError("Only tools can start a task")),
    }
}

fn getPrompt(self: *Server, ctx: *RequestContext, params: types.GetPromptRequestParams) RequestContext.Error!void {
    for (self.prompts.items) |p| {
        if (!p.enabled or !std.mem.eql(u8, p.def.name, params.name)) continue;
        if (p.def.arguments) |defs| {
            for (defs) |d| {
                if (d.required orelse false) {
                    const present = if (params.arguments) |a| a.map.get(d.name) != null else false;
                    if (!present) {
                        const msg = try std.fmt.allocPrint(ctx.arena, "Missing required argument: {s}", .{d.name});
                        return ctx.setError(errors.invalidParams(msg));
                    }
                }
            }
        }
        try self.prepareInputRound(ctx, "prompts/get", params.name, params.inputResponses, params.requestState);
        ctx.userdata = p.userdata;
        const outcome = p.handler(ctx, params.arguments) catch |e| return mapHandlerError(ctx, e);
        switch (outcome) {
            .complete => |r| try self.finishResult(ctx, r),
            .input_required => |ir| try self.finishInputRequired(ctx, .@"prompts/get", ir),
            .start_task => return ctx.setError(errors.internalError("Only tools can start a task")),
        }
        return;
    }
    const msg = try std.fmt.allocPrint(ctx.arena, "Unknown prompt: {s}", .{params.name});
    return ctx.setError(errors.invalidParams(msg));
}

// ---------------------------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------------------------

pub const Event = enum { tools_list_changed, prompts_list_changed, resources_list_changed, resource_updated };

fn listen(self: *Server, ctx: *RequestContext, params: types.SubscriptionsListenRequestParams) RequestContext.Error!void {
    const caps = self.options.capabilities;
    const filter = params.notifications;
    if (filter.resourceSubscriptions) |uris| {
        if (uris.len > self.options.limits.max_resource_subscription_uris) return ctx.setError(errors.internalError("Too many resource subscriptions"));
    }
    // Honour only what the server declared.
    var honoured: types.SubscriptionFilter = .{};
    if (filter.toolsListChanged orelse false) {
        if (caps.tools) |t| if (t.listChanged orelse false) {
            honoured.toolsListChanged = true;
        };
    }
    if (filter.promptsListChanged orelse false) {
        if (caps.prompts) |p| if (p.listChanged orelse false) {
            honoured.promptsListChanged = true;
        };
    }
    if (filter.resourcesListChanged orelse false) {
        if (caps.resources) |r| if (r.listChanged orelse false) {
            honoured.resourcesListChanged = true;
        };
    }
    if (filter.resourceSubscriptions) |uris| {
        if (caps.resources) |r| if (r.subscribe orelse false) {
            honoured.resourceSubscriptions = uris;
        };
    }

    const sub = try self.gpa.create(Subscription);
    var owned = true;
    errdefer if (owned) self.gpa.destroy(sub);
    sub.* = .{
        .id = undefined,
        .filter = undefined,
        .responder = ctx.responder,
        .cancel = ctx.cancel,
        .kind = ctx.kind,
        .arena = .init(self.gpa),
    };
    errdefer if (owned) sub.arena.deinit();
    const sub_arena = sub.arena.allocator();
    sub.id = try ctx.id.dupe(sub_arena);
    sub.filter = honoured;
    if (honoured.resourceSubscriptions) |uris| {
        const copy = try sub_arena.alloc([]const u8, uris.len);
        for (uris, 0..) |u, i| copy[i] = try sub_arena.dupe(u8, u);
        sub.filter.resourceSubscriptions = copy;
    }

    {
        self.subscriptions_lock.lockUncancelable(ctx.io);
        defer self.subscriptions_lock.unlock(ctx.io);
        if (self.subscriptions.items.len >= self.options.limits.max_listen_subscriptions) {
            sub.arena.deinit();
            self.gpa.destroy(sub);
            return ctx.setError(errors.internalError("Too many subscriptions"));
        }
        try self.subscriptions.append(self.gpa, sub);
        owned = false;
    }
    ctx.long_lived = true;
    if (self.shutting_down.load(.acquire)) ctx.cancel.cancel(ctx.io, shutdown_reason);

    // The acknowledgement is always the first message on the stream.
    const ack: types.SubscriptionsAcknowledgedNotificationParams = .{
        ._meta = .{ .@"io.modelcontextprotocol/subscriptionId" = ctx.id },
        .notifications = honoured,
    };
    ctx.sendNotification("notifications/subscriptions/acknowledged", ack) catch |e| {
        _ = self.removeSubscription(ctx.io, sub);
        return e;
    };

    // Park until the client cancels, the transport closes, or the server shuts down.
    ctx.cancel.wait(ctx.io) catch {};
    const by_server = self.removeSubscription(ctx.io, sub);
    if (!by_server) return error.Canceled;
    // Graceful teardown: a completion result, then (on stdio) a cancellation notification.
    const result: types.SubscriptionsListenResult = .{ ._meta = .{ .@"io.modelcontextprotocol/subscriptionId" = ctx.id } };
    try self.finishResult(ctx, result);
}

/// Remove the subscription. Returns true when the server (not the client) ended it.
fn removeSubscription(self: *Server, io: Io, sub: *Subscription) bool {
    self.subscriptions_lock.lockUncancelable(io);
    defer self.subscriptions_lock.unlock(io);
    for (self.subscriptions.items, 0..) |s, i| {
        if (s == sub) {
            _ = self.subscriptions.swapRemove(i);
            break;
        }
    }
    const by_server = sub.cancel.reason != null and std.mem.eql(u8, sub.cancel.reason.?, shutdown_reason);
    sub.arena.deinit();
    self.gpa.destroy(sub);
    return by_server;
}

pub const shutdown_reason = "server shutdown";

/// End every subscription gracefully. Call before the transport closes.
pub fn shutdownSubscriptions(self: *Server, io: Io) void {
    self.shutting_down.store(true, .release);
    self.subscriptions_lock.lockUncancelable(io);
    const subs = self.subscriptions.items;
    // Copy the tokens: `listen` removes entries as the tasks wake.
    var tokens: [64]*Transport.CancelToken = undefined;
    var count: usize = 0;
    for (subs) |s| {
        if (count == tokens.len) break;
        tokens[count] = s.cancel;
        count += 1;
    }
    self.subscriptions_lock.unlock(io);
    for (tokens[0..count]) |t| t.cancel(io, shutdown_reason);
}

fn publish(self: *Server, io: Io, event: Event, uri: ?[]const u8) void {
    self.subscriptions_lock.lockUncancelable(io);
    defer self.subscriptions_lock.unlock(io);
    for (self.subscriptions.items) |sub| {
        if (sub.broken) continue;
        const wanted = switch (event) {
            .tools_list_changed => sub.filter.toolsListChanged orelse false,
            .prompts_list_changed => sub.filter.promptsListChanged orelse false,
            .resources_list_changed => sub.filter.resourcesListChanged orelse false,
            .resource_updated => blk: {
                const uris = sub.filter.resourceSubscriptions orelse break :blk false;
                for (uris) |u| if (std.mem.eql(u8, u, uri.?)) break :blk true;
                break :blk false;
            },
        };
        if (!wanted) continue;
        self.deliver(io, sub, event, uri) catch {
            sub.broken = true;
            sub.cancel.cancel(io, "stream closed");
        };
    }
}

fn deliver(self: *Server, io: Io, sub: *Subscription, event: Event, uri: ?[]const u8) !void {
    _ = self;
    var buf: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var aw: Io.Writer.Allocating = .init(fba.allocator());
    const meta: types.NotificationMetaObject = .{ .@"io.modelcontextprotocol/subscriptionId" = sub.id };
    switch (event) {
        .tools_list_changed => try message.writeNotification(&aw.writer, "notifications/tools/list_changed", types.NotificationParams{ ._meta = meta }),
        .prompts_list_changed => try message.writeNotification(&aw.writer, "notifications/prompts/list_changed", types.NotificationParams{ ._meta = meta }),
        .resources_list_changed => try message.writeNotification(&aw.writer, "notifications/resources/list_changed", types.NotificationParams{ ._meta = meta }),
        .resource_updated => try message.writeNotification(&aw.writer, "notifications/resources/updated", types.ResourceUpdatedNotificationParams{ ._meta = meta, .uri = uri.? }),
    }
    sub.mutex.lockUncancelable(io);
    defer sub.mutex.unlock(io);
    try sub.responder.notify(io, aw.written());
}

test {
    std.testing.refAllDecls(@This());
}

// ---------------------------------------------------------------------------------------------
// Tasks extension
// ---------------------------------------------------------------------------------------------

/// Create the task, start its runner, and answer with `CreateTaskResult`.
fn startTask(self: *Server, ctx: *RequestContext, entry: *ToolEntry, params: types.CallToolRequestParams) RequestContext.Error!void {
    const store = &self.task_store.?;
    const task = store.create(params.name, ctx.params orelse .null, ctx.kind) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TooManyTasks => return ctx.setError(errors.internalError("Too many tasks")),
        error.EntropyUnavailable => return ctx.setError(errors.internalError("No entropy for the task id")),
    };
    _ = entry;
    // The task is in the store: a `tasks/get` resolves from now on.
    task.future = ctx.io.concurrent(runTask, .{ self, ctx.io, task }) catch null;
    if (task.future == null) runTask(self, ctx.io, task);
    task.lock.lockUncancelable(ctx.io);
    defer task.lock.unlock(ctx.io);
    const result: tasks.CreateTaskResult = .{
        .taskId = task.id,
        .status = @tagName(task.status),
        .createdAt = try tasks.formatTimestamp(ctx.arena, task.created_ms),
        .lastUpdatedAt = try tasks.formatTimestamp(ctx.arena, task.updated_ms),
        .ttlMs = task.ttl_ms,
        .pollIntervalMs = store.options.poll_interval_ms,
    };
    try self.finishResult(ctx, result);
}

const noop_responder_vtable: Transport.Responder.VTable = .{
    .notify = noopNotify,
    .finish = noopFinish,
    .abort = noopAbort,
};

fn noopNotify(_: *anyopaque, _: Io, _: []const u8) Transport.SendError!void {}
fn noopFinish(_: *anyopaque, _: Io, _: []const u8) Transport.SendError!void {}
fn noopAbort(_: *anyopaque, _: Io) void {}

/// The body of a task: run the tool handler once with the answers collected so far.
fn runTask(self: *Server, io: Io, task: *tasks.Task) void {
    const arena = task.arena();
    var dummy: u8 = 0;
    var ctx: RequestContext = .{
        .io = io,
        .gpa = self.gpa,
        .arena = arena,
        .server = self,
        .id = .{ .integer = 0 },
        .method = "tools/call",
        .meta = undefined,
        .params = task.params,
        .cancel = &task.cancel,
        .responder = .{ .ptr = &dummy, .vtable = &noop_responder_vtable },
        .kind = task.kind,
        .task = task,
    };
    const outcome = self.runTaskBody(&ctx, task) catch |e| switch (e) {
        error.Canceled => {
            self.settleTask(io, task, .cancelled, null, null);
            return;
        },
        error.OutOfMemory => {
            self.settleTask(io, task, .failed, null, errors.internalError("Out of memory").toWire());
            return;
        },
        error.Rpc => {
            const err = ctx.rpc_error orelse errors.internalError("Internal error");
            self.settleTask(io, task, .failed, null, err.toWire());
            return;
        },
    };
    switch (outcome) {
        .complete => |result| {
            const text = json.writeAlloc(arena, result) catch {
                self.settleTask(io, task, .failed, null, errors.internalError("Out of memory").toWire());
                return;
            };
            const tree = json.parseTree(arena, text) catch {
                self.settleTask(io, task, .failed, null, errors.internalError("Out of memory").toWire());
                return;
            };
            self.settleTask(io, task, .completed, tree, null);
        },
        .input_required => |ir| {
            const text = json.writeAlloc(arena, ir.requests) catch {
                self.settleTask(io, task, .failed, null, errors.internalError("Out of memory").toWire());
                return;
            };
            const tree = json.parseTree(arena, text) catch {
                self.settleTask(io, task, .failed, null, errors.internalError("Out of memory").toWire());
                return;
            };
            task.lock.lockUncancelable(io);
            defer task.lock.unlock(io);
            if (task.status == .cancelled) return;
            task.status = .input_required;
            task.input_requests = tree;
            task.updated_ms = tasks.nowMs(io);
        },
        .start_task => self.settleTask(io, task, .failed, null, errors.internalError("The tool returned start_task inside a task").toWire()),
    }
}

fn runTaskBody(self: *Server, ctx: *RequestContext, task: *tasks.Task) RequestContext.Error!Outcome(types.CallToolResult) {
    ctx.meta = meta_mod.lift(ctx.arena, ctx.params) catch return ctx.setError(errors.internalError("The task params lost their _meta"));
    const entry = self.findTool(task.tool) orelse return ctx.setError(errors.internalError("The tool of the task is gone"));
    ctx.userdata = entry.userdata;
    const params = json.parseValue(types.CallToolRequestParams, ctx.arena, task.params) catch return ctx.setError(errors.internalError("The task params do not parse"));
    // Answers: the ones the creating request carried, then the ones from `tasks/update`.
    var responses: std.json.ObjectMap = .empty;
    if (params.inputResponses) |given| {
        var it = given.map.iterator();
        while (it.next()) |kv| try responses.put(ctx.arena, kv.key_ptr.*, kv.value_ptr.*);
    }
    {
        task.lock.lockUncancelable(ctx.io);
        defer task.lock.unlock(ctx.io);
        var it = task.input_responses.iterator();
        while (it.next()) |kv| try responses.put(ctx.arena, kv.key_ptr.*, kv.value_ptr.*);
    }
    try self.prepareInputRound(ctx, "tools/call", task.tool, .{ .map = responses }, params.requestState);
    const args: Value = params.arguments orelse .{ .object = .empty };
    return entry.handler(ctx, args) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
        error.Rpc => return error.Rpc,
        error.InvalidArguments => return .{ .complete = try types.CallToolResult.err(ctx.arena, "Invalid arguments for tool {s}", .{task.tool}) },
        else => return .{ .complete = try types.CallToolResult.err(ctx.arena, "Tool failed: {t}", .{e}) },
    };
}

fn settleTask(self: *Server, io: Io, task: *tasks.Task, status: tasks.Status, result: ?Value, err: ?types.Error) void {
    _ = self;
    task.lock.lockUncancelable(io);
    defer task.lock.unlock(io);
    if (task.isTerminal()) return;
    task.status = status;
    task.result = result;
    task.err = err;
    task.input_requests = null;
    task.updated_ms = tasks.nowMs(io);
}

fn dispatchTask(self: *Server, ctx: *RequestContext) RequestContext.Error!void {
    const store: *tasks.Store = if (self.task_store) |*s| s else {
        const msg = try std.fmt.allocPrint(ctx.arena, "Method not found: {s}", .{ctx.method});
        return ctx.setError(errors.methodNotFound(msg));
    };
    const is_get = std.mem.eql(u8, ctx.method, "tasks/get");
    const is_update = std.mem.eql(u8, ctx.method, "tasks/update");
    const is_cancel = std.mem.eql(u8, ctx.method, "tasks/cancel");
    if (!is_get and !is_update and !is_cancel) {
        const msg = try std.fmt.allocPrint(ctx.arena, "Method not found: {s}", .{ctx.method});
        return ctx.setError(errors.methodNotFound(msg));
    }
    if (!ctx.meta.client_capabilities.hasExtension(tasks.extension_id)) return ctx.setError(try tasks.missingExtensionError(ctx.arena));
    if (is_get) {
        const params = try parseParams(ctx, tasks.GetParams);
        const task = store.get(params.taskId) orelse return ctx.setError(errors.invalidParams("Unknown taskId"));
        task.lock.lockUncancelable(ctx.io);
        defer task.lock.unlock(ctx.io);
        const detailed: tasks.DetailedTask = .{
            .taskId = task.id,
            .status = @tagName(task.status),
            .createdAt = try tasks.formatTimestamp(ctx.arena, task.created_ms),
            .lastUpdatedAt = try tasks.formatTimestamp(ctx.arena, task.updated_ms),
            .ttlMs = task.ttl_ms,
            .pollIntervalMs = store.options.poll_interval_ms,
            .inputRequests = if (task.status == .input_required) task.input_requests else null,
            .result = if (task.status == .completed) task.result else null,
            .@"error" = if (task.status == .failed) task.err else null,
        };
        return self.finishResult(ctx, detailed);
    }
    if (is_update) {
        const params = try parseParams(ctx, tasks.UpdateParams);
        const task = store.get(params.taskId) orelse return ctx.setError(errors.invalidParams("Unknown taskId"));
        var resume_now = false;
        {
            task.lock.lockUncancelable(ctx.io);
            defer task.lock.unlock(ctx.io);
            if (task.status == .input_required) {
                if (params.inputResponses) |given| {
                    var it = given.map.iterator();
                    while (it.next()) |kv| {
                        // Copy the answer into the task arena; the request arena dies soon.
                        const text = try json.writeAlloc(task.arena(), kv.value_ptr.*);
                        const copy = json.parseTree(task.arena(), text) catch return error.OutOfMemory;
                        try task.input_responses.put(task.arena(), try task.arena().dupe(u8, kv.key_ptr.*), copy);
                        if (task.input_requests) |*pending| if (pending.* == .object) {
                            _ = pending.object.orderedRemove(kv.key_ptr.*);
                        };
                    }
                }
                const pending_count: usize = if (task.input_requests) |p| (if (p == .object) p.object.count() else 0) else 0;
                if (pending_count == 0) {
                    task.status = .working;
                    task.input_requests = null;
                    resume_now = true;
                }
                task.updated_ms = tasks.nowMs(ctx.io);
            }
        }
        if (resume_now) {
            if (task.future) |*f| {
                f.await(ctx.io);
                task.future = null;
            }
            task.future = ctx.io.concurrent(runTask, .{ self, ctx.io, task }) catch null;
            if (task.future == null) runTask(self, ctx.io, task);
        }
        return self.finishResult(ctx, types.EmptyResult{});
    }
    // tasks/cancel
    const params = try parseParams(ctx, tasks.CancelParams);
    const task = store.get(params.taskId) orelse return ctx.setError(errors.invalidParams("Unknown taskId"));
    var running = false;
    {
        task.lock.lockUncancelable(ctx.io);
        defer task.lock.unlock(ctx.io);
        if (!task.isTerminal()) {
            running = true;
            task.cancel.cancel(ctx.io, "cancelled by the client");
        }
    }
    if (running) {
        if (task.future) |*f| {
            _ = f.cancel(ctx.io);
            task.future = null;
        }
        self.settleTask(ctx.io, task, .cancelled, null, null);
    }
    return self.finishResult(ctx, types.EmptyResult{});
}

// ---------------------------------------------------------------------------------------------
// Skills extension
// ---------------------------------------------------------------------------------------------

fn dispatchSkills(self: *Server, ctx: *RequestContext) RequestContext.Error!void {
    const registry: *skills.Registry = if (self.skill_registry) |*r| r else {
        const msg = try std.fmt.allocPrint(ctx.arena, "Method not found: {s}", .{ctx.method});
        return ctx.setError(errors.methodNotFound(msg));
    };
    if (std.mem.eql(u8, ctx.method, skills_proto.method_list)) {
        const params = try parseParams(ctx, types.PaginatedRequestParams);
        const page = try self.paginate(ctx, skills_proto.Skill, registry.entries.items, params.cursor);
        return self.finishResult(ctx, skills_proto.ListSkillsResult{ .skills = page.items, .nextCursor = page.next_cursor });
    }
    if (std.mem.eql(u8, ctx.method, skills_proto.method_get)) {
        const params = try parseParams(ctx, skills_proto.GetSkillParams);
        const skill = registry.findSkill(params.uri) orelse {
            const msg = try std.fmt.allocPrint(ctx.arena, "No skill is served at {s}", .{params.uri});
            return ctx.setError(errors.invalidParams(msg));
        };
        return self.finishResult(ctx, skills_proto.GetSkillResult{ .skill = skill });
    }
    // Without `directoryRead` the method is unknown, as the extension says.
    if (std.mem.eql(u8, ctx.method, skills_proto.method_directory_read) and registry.options.directory_read) {
        const params = try parseParams(ctx, skills_proto.ReadDirectoryParams);
        const children = try registry.directoryChildren(ctx.arena, params.uri) orelse {
            const msg = try std.fmt.allocPrint(ctx.arena, "{s} is not a directory resource", .{params.uri});
            return ctx.setError(errors.invalidParams(msg));
        };
        const page = try self.paginate(ctx, types.Resource, children, params.cursor);
        return self.finishResult(ctx, skills_proto.ReadDirectoryResult{ .resources = page.items, .nextCursor = page.next_cursor });
    }
    const msg = try std.fmt.allocPrint(ctx.arena, "Method not found: {s}", .{ctx.method});
    return ctx.setError(errors.methodNotFound(msg));
}
