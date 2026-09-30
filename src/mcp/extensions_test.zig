//! The Skills and MCP Apps extensions over the in-memory harness and the in-memory link.
const std = @import("std");
const Value = std.json.Value;
const mcp = @import("../mcp.zig");
const Server = mcp.Server;
const Client = mcp.Client;
const RequestContext = mcp.RequestContext;
const types = mcp.types;
const json = mcp.json;
const skills = mcp.protocol.skills;
const apps = mcp.protocol.apps;
const Harness = mcp.transport.memory.Harness;

const testing = std.testing;

const meta_plain =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
;
const meta_ui =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/ui":{"mimeTypes":["text/html;profile=mcp-app"]}}}}
;

fn request(arena: std.mem.Allocator, id: i64, method: []const u8, meta: []const u8, extra: []const u8) ![]u8 {
    const sep: []const u8 = if (extra.len > 0) "," else "";
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{{{s}{s}{s}}}}}", .{ id, method, meta, sep, extra });
}

// The example skill of the extension specification. The sizes and digests are those of the
// specification.
const pdf_skill_md = "---\nname: pdf-processing\ndescription: Extract, fill, and assemble PDF documents\n---\n\n# PDF processing\n\nChoose the matching template from `templates/`.\n";
const invoice_md = "# Invoice\n\nCustomer:\nAmount:\n";
const purchase_order_md = "# Purchase order\n\nSupplier:\nItems:\n";
const logo_png = [_]u8{ 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00 };

const refunds_md =
    \\---
    \\name: refunds
    \\description: Process customer refund requests per company policy
    \\license: Apache-2.0
    \\metadata:
    \\  author: acme
    \\---
    \\
    \\Use `examples/email.md`.
    \\
;

const daily_md = "---\nname: daily\ndescription: Assemble the report of today from live data\n---\n\nRead the live numbers.\n";

fn readDaily(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/markdown", .text = daily_md } };
    return .{ .complete = .{ .contents = contents } };
}

fn addExampleSkills(server: *Server) !void {
    try server.addSkill(.{
        .name = "pdf-processing",
        .skill_md = pdf_skill_md,
        .files = &.{
            .{ .path = "templates/invoice.md", .content = invoice_md },
            .{ .path = "templates/purchase-order.md", .content = purchase_order_md },
            .{ .path = "templates/regional/eu.md", .content = "# EU\n" },
            .{ .path = "assets/logo.png", .content = &logo_png },
        },
    });
    try server.addSkill(.{
        .prefix = "acme/billing",
        .name = "refunds",
        .skill_md = refunds_md,
        .files = &.{.{ .path = "examples/email.md", .content = "Dear customer,\n" }},
    });
    try server.addDynamicSkill(.{ .prefix = "reports", .name = "daily", .skill_md = daily_md });
    try server.addResource(.{ .uri = "skill://reports/daily/SKILL.md", .name = "daily", .mime_type = "text/markdown" }, readDaily);
}

const SkillFixture = struct {
    server: Server,
    harness: Harness,
    arena_state: std.heap.ArenaAllocator,

    fn init(self: *SkillFixture, options: Server.Options) !void {
        self.arena_state = .init(testing.allocator);
        self.server = try Server.init(testing.allocator, testing.io, options);
        try addExampleSkills(&self.server);
        self.harness = .init(testing.io, testing.allocator, &self.server);
    }

    fn deinit(self: *SkillFixture) void {
        self.harness.deinit();
        self.server.deinit();
        self.arena_state.deinit();
    }

    fn call(self: *SkillFixture, id: i64, method: []const u8, extra: []const u8) !Value {
        const arena = self.arena_state.allocator();
        self.harness.clear();
        try self.harness.send(try request(arena, id, method, meta_plain, extra));
        try testing.expect(self.harness.finished);
        return json.parseTree(arena, self.harness.last().?);
    }
};

fn errorCode(v: Value) ?i64 {
    const e = v.object.get("error") orelse return null;
    return e.object.get("code").?.integer;
}

fn resultOf(v: Value) Value {
    return v.object.get("result").?;
}

test "skills: discovery, list, get and pagination" {
    var f: SkillFixture = undefined;
    try f.init(.{ .info = .{ .name = "s", .version = "1" }, .skills = .{}, .limits = .{ .page_size = 2 }, .cache = .{ .lists = .{ .ttl_ms = 300_000, .scope = .public } } });
    defer f.deinit();

    const disc = resultOf(try f.call(1, "server/discover", ""));
    const caps = disc.object.get("capabilities").?;
    try testing.expect(caps.object.get("resources") != null);
    const settings = caps.object.get("extensions").?.object.get(skills.extension_id).?;
    try testing.expect(settings.object.get("directoryRead").?.bool);

    // Page one holds two entries. Each entry is complete.
    const page1 = resultOf(try f.call(2, "skills/list", ""));
    try testing.expectEqualStrings("complete", page1.object.get("resultType").?.string);
    try testing.expectEqual(@as(i64, 300_000), page1.object.get("ttlMs").?.integer);
    try testing.expectEqualStrings("public", page1.object.get("cacheScope").?.string);
    const entries = page1.object.get("skills").?.array.items;
    try testing.expectEqual(2, entries.len);
    try testing.expectEqualStrings("skill://pdf-processing/SKILL.md", entries[0].object.get("uri").?.string);
    const files = entries[0].object.get("resources").?.array.items;
    try testing.expectEqual(5, files.len);
    try testing.expectEqualStrings("sha256:99b737495721155ece826d57521e2d66141ebdc1344a400487481ea2642ab19e", files[0].object.get("digest").?.string);
    try testing.expectEqual(@as(i64, 151), files[0].object.get("size").?.integer);
    try testing.expectEqualStrings("sha256:61f4ea6d2c75fde1b4977219e7e3107d491c3c26aefb6686e84d6281c088d9ee", files[1].object.get("digest").?.string);
    try testing.expectEqualStrings("sha256:f2ff774b1737ff3dec81c47946f9976f18a1a9f69dda0a81f22eabd95173c158", files[2].object.get("digest").?.string);
    const refunds = entries[1].object.get("frontmatter").?;
    try testing.expectEqualStrings("Apache-2.0", refunds.object.get("license").?.string);
    try testing.expectEqualStrings("acme", refunds.object.get("metadata").?.object.get("author").?.string);

    const cursor = page1.object.get("nextCursor").?.string;
    const extra = try std.fmt.allocPrint(f.arena_state.allocator(), "\"cursor\":\"{s}\"", .{cursor});
    const page2 = resultOf(try f.call(3, "skills/list", extra));
    const rest = page2.object.get("skills").?.array.items;
    try testing.expectEqual(1, rest.len);
    try testing.expectEqualStrings("dynamic", rest[0].object.get("resources").?.string);
    try testing.expect(page2.object.get("nextCursor") == null);

    const got = resultOf(try f.call(4, "skills/get", "\"uri\":\"skill://acme/billing/refunds/SKILL.md\""));
    try testing.expectEqualStrings("refunds", got.object.get("skill").?.object.get("frontmatter").?.object.get("name").?.string);
    try testing.expect(got.object.get("ttlMs") != null);
    try testing.expectEqual(@as(?i64, -32602), errorCode(try f.call(5, "skills/get", "\"uri\":\"skill://acme/billing/chargebacks/SKILL.md\"")));
    try testing.expectEqual(@as(?i64, -32601), errorCode(try f.call(6, "skills/other", "")));

    // Skill files are ordinary resources. Bytes that are not UTF-8 go out as a blob.
    const md = resultOf(try f.call(7, "resources/read", "\"uri\":\"skill://pdf-processing/SKILL.md\""));
    const item = md.object.get("contents").?.array.items[0];
    try testing.expectEqualStrings("text/markdown", item.object.get("mimeType").?.string);
    try testing.expectEqualStrings(pdf_skill_md, item.object.get("text").?.string);
    const logo = resultOf(try f.call(8, "resources/read", "\"uri\":\"skill://pdf-processing/assets/logo.png\""));
    try testing.expectEqualStrings("image/png", logo.object.get("contents").?.array.items[0].object.get("mimeType").?.string);
    try testing.expect(logo.object.get("contents").?.array.items[0].object.get("blob") != null);
}

test "skills: directory reads" {
    var f: SkillFixture = undefined;
    try f.init(.{ .info = .{ .name = "s", .version = "1" }, .skills = .{} });
    defer f.deinit();

    const root = resultOf(try f.call(1, "resources/directory/read", "\"uri\":\"skill://pdf-processing\""));
    const children = root.object.get("resources").?.array.items;
    try testing.expectEqual(3, children.len);
    try testing.expectEqualStrings("skill://pdf-processing/SKILL.md", children[0].object.get("uri").?.string);
    try testing.expectEqualStrings("skill://pdf-processing/assets", children[1].object.get("uri").?.string);
    try testing.expectEqualStrings("inode/directory", children[1].object.get("mimeType").?.string);
    try testing.expect(root.object.get("ttlMs") == null);

    const templates = resultOf(try f.call(2, "resources/directory/read", "\"uri\":\"skill://pdf-processing/templates\""));
    const t = templates.object.get("resources").?.array.items;
    try testing.expectEqual(3, t.len);
    try testing.expectEqualStrings("invoice.md", t[0].object.get("name").?.string);
    try testing.expectEqualStrings("text/markdown", t[0].object.get("mimeType").?.string);
    try testing.expectEqualStrings("regional", t[2].object.get("name").?.string);
    try testing.expectEqualStrings("inode/directory", t[2].object.get("mimeType").?.string);

    // The prefix of a skill path is also a directory.
    const prefix = resultOf(try f.call(3, "resources/directory/read", "\"uri\":\"skill://acme\""));
    try testing.expectEqualStrings("skill://acme/billing", prefix.object.get("resources").?.array.items[0].object.get("uri").?.string);

    try testing.expectEqual(@as(?i64, -32602), errorCode(try f.call(4, "resources/directory/read", "\"uri\":\"skill://pdf-processing/SKILL.md\"")));
    try testing.expectEqual(@as(?i64, -32602), errorCode(try f.call(5, "resources/directory/read", "\"uri\":\"skill://pdf-processing/\"")));
    try testing.expectEqual(@as(?i64, -32602), errorCode(try f.call(6, "resources/directory/read", "\"uri\":\"skill://nothing\"")));
}

test "skills: directoryRead off and the extension off" {
    var f: SkillFixture = undefined;
    try f.init(.{ .info = .{ .name = "s", .version = "1" }, .skills = .{ .directory_read = false } });
    defer f.deinit();
    const disc = resultOf(try f.call(1, "server/discover", ""));
    const settings = disc.object.get("capabilities").?.object.get("extensions").?.object.get(skills.extension_id).?;
    try testing.expectEqual(0, settings.object.count());
    try testing.expectEqual(@as(?i64, -32601), errorCode(try f.call(2, "resources/directory/read", "\"uri\":\"skill://pdf-processing\"")));

    var plain = try Server.init(testing.allocator, testing.io, .{ .info = .{ .name = "p", .version = "1" } });
    defer plain.deinit();
    try testing.expectError(error.ExtensionNotEnabled, plain.addSkill(.{ .name = "x", .skill_md = "---\nname: x\ndescription: y\n---\n" }));
    var h: Harness = .init(testing.io, testing.allocator, &plain);
    defer h.deinit();
    try h.send(try request(f.arena_state.allocator(), 3, "skills/list", meta_plain, ""));
    const v = try json.parseTree(f.arena_state.allocator(), h.last().?);
    try testing.expectEqual(@as(?i64, -32601), errorCode(v));
}

test "skills: registration rules" {
    var server = try Server.init(testing.allocator, testing.io, .{ .info = .{ .name = "s", .version = "1" }, .skills = .{}, .limits = .{ .skills = .{ .max_files = 3, .max_bytes = 200 } } });
    defer server.deinit();
    const md = "---\nname: tool\ndescription: A tool skill\n---\nBody\n";
    try testing.expectError(error.NameMismatch, server.addSkill(.{ .name = "other", .skill_md = md }));
    try testing.expectError(error.InvalidSkillName, server.addSkill(.{ .name = "Tool", .skill_md = md }));
    try testing.expectError(error.MissingFrontmatter, server.addSkill(.{ .name = "tool", .skill_md = "# no frontmatter\n" }));
    try testing.expectError(error.UnsupportedFrontmatter, server.addSkill(.{ .name = "tool", .skill_md = "---\nname: tool\ndescription: &a x\n---\n" }));
    try testing.expectError(error.InvalidFrontmatter, server.addSkill(.{ .name = "tool", .skill_md = "---\nname: tool\n---\n" }));
    try testing.expectError(error.InvalidFilePath, server.addSkill(.{ .name = "tool", .skill_md = md, .files = &.{.{ .path = "../x", .content = "" }} }));
    try testing.expectError(error.InvalidFilePath, server.addSkill(.{ .name = "tool", .skill_md = md, .files = &.{ .{ .path = "a", .content = "" }, .{ .path = "a", .content = "" } } }));
    try testing.expectError(error.InvalidSkillPath, server.addSkill(.{ .prefix = "a b", .name = "tool", .skill_md = md }));
    try testing.expectError(error.TooManySkillFiles, server.addSkill(.{ .name = "tool", .skill_md = md, .files = &.{ .{ .path = "a", .content = "" }, .{ .path = "b", .content = "" }, .{ .path = "c", .content = "" } } }));
    try testing.expectError(error.SkillTooLarge, server.addSkill(.{ .name = "tool", .skill_md = md, .files = &.{.{ .path = "big", .content = "x" ** 200 }} }));
    try server.addSkill(.{ .name = "tool", .skill_md = md, .files = &.{.{ .path = "inner/SKILL.md", .content = "---\nname: inner\ndescription: Nested\n---\n" }} });
    try testing.expectError(error.DuplicateSkill, server.addSkill(.{ .name = "tool", .skill_md = md }));

    // A nested skill shares its files with the enclosing skill.
    try server.addSkill(.{ .prefix = "tool", .name = "inner", .skill_md = "---\nname: inner\ndescription: Nested\n---\n" });
    try testing.expectEqual(2, server.resources.items.len);
    // A nested skill with a file that the enclosing skill does not list is rejected.
    try testing.expectError(error.IncompleteSkill, server.addSkill(.{ .prefix = "tool", .name = "extra", .skill_md = "---\nname: extra\ndescription: Nested\n---\n" }));
    // An enclosing skill must list the files of the nested skills inside it.
    try server.addSkill(.{ .prefix = "outer", .name = "deep", .skill_md = "---\nname: deep\ndescription: Deep\n---\n" });
    try testing.expectError(error.IncompleteSkill, server.addSkill(.{ .name = "outer", .skill_md = "---\nname: outer\ndescription: Outer\n---\n" }));
    try testing.expectError(error.ConflictingSkillFile, server.addSkill(.{ .name = "outer", .skill_md = "---\nname: outer\ndescription: Outer\n---\n", .files = &.{.{ .path = "deep/SKILL.md", .content = "changed" }} }));
}

// ---------------------------------------------------------------------------------------------
// Skills through the client
// ---------------------------------------------------------------------------------------------

const ClientFixture = struct {
    server: Server,
    link: mcp.transport.memory.ClientLink,
    client: Client,

    fn init(self: *ClientFixture, server_options: Server.Options, client_options: Client.Options) !void {
        self.server = try Server.init(testing.allocator, testing.io, server_options);
        self.link = .init(testing.io, testing.allocator, &self.server);
        self.client = .init(testing.allocator, testing.io, client_options);
        self.client.connect(self.link.transport());
    }

    fn deinit(self: *ClientFixture) void {
        self.client.deinit();
        self.server.deinit();
    }
};

test "skills: the client lists, gets, reads and verifies" {
    var f: ClientFixture = undefined;
    try f.init(.{ .info = .{ .name = "s", .version = "1" }, .skills = .{} }, .{ .info = .{ .name = "c", .version = "1" } });
    defer f.deinit();
    try addExampleSkills(&f.server);
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const disc = try f.client.discover(arena, .{});
    try testing.expect(skills.serverSupports(disc.capabilities));
    try testing.expect(skills.serverSupportsDirectoryRead(disc.capabilities));

    const list = try f.client.listSkills(arena, null, .{});
    try testing.expectEqual(3, list.skills.len);
    for (list.skills) |s| try skills.validateEntry(s, skills.max_files_per_skill, skills.max_bytes_per_skill);
    const pdf = list.skills[0];

    // Every listed file reads and verifies, the binary file too.
    for (pdf.resources.?.files) |file| {
        const bytes = try f.client.readSkillFile(arena, pdf, file.uri, .{});
        try testing.expectEqual(@as(usize, @intCast(file.size)), bytes.len);
    }
    // A file that the held entry does not list is refused before any request.
    try testing.expectError(error.UnlistedFile, f.client.readSkillFile(arena, pdf, "skill://pdf-processing/templates/credit-note.md", .{}));
    // A stale entry fails the verification.
    var stale = pdf;
    const files = try arena.dupe(skills.SkillResource, pdf.resources.?.files);
    files[1].digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    stale.resources = .{ .files = files };
    try testing.expectError(error.DigestMismatch, f.client.readSkillFile(arena, stale, files[1].uri, .{}));
    files[1].size += 1;
    try testing.expectError(error.SizeMismatch, f.client.readSkillFile(arena, stale, files[1].uri, .{}));
    // An entry whose frontmatter differs from the file is not loaded.
    var changed = pdf;
    changed.frontmatter = try skills.parseYamlMapping(arena, "name: pdf-processing\ndescription: Something else\n");
    try testing.expectError(error.FrontmatterMismatch, f.client.readSkillFile(arena, changed, pdf.uri, .{}));

    // A dynamic skill has no digests, but the frontmatter check still applies.
    const daily = (try f.client.getSkill(arena, "skill://reports/daily/SKILL.md", .{})).skill;
    try testing.expect(daily.resources.? == .dynamic);
    _ = try f.client.readSkillFile(arena, daily, daily.uri, .{});
    try testing.expectError(error.OutsideSkill, f.client.readSkillFile(arena, daily, "skill://other/SKILL.md", .{}));

    var diag: Client.Diagnostics = .{};
    try testing.expectError(error.Rpc, f.client.getSkill(arena, "skill://none/SKILL.md", .{ .diagnostics = &diag }));
    try testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);

    const dir = try f.client.readDirectory(arena, "skill://pdf-processing/templates", null, .{});
    try testing.expectEqual(3, dir.resources.len);
    try testing.expectEqualStrings(skills.directory_mime_type, dir.resources[2].mimeType.?);
}

// ---------------------------------------------------------------------------------------------
// MCP Apps
// ---------------------------------------------------------------------------------------------

const dashboard_html = "<!DOCTYPE html><html><body>Weather</body></html>";

fn weather(ctx: *RequestContext, args: Value) anyerror!mcp.Outcome(types.CallToolResult) {
    _ = args;
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "Sunny, 22 degrees", .{}) };
}

fn dynamicView(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .text = "<!DOCTYPE html><html></html>" } };
    return .{ .complete = .{ .contents = contents } };
}

fn wrongView(ctx: *RequestContext, uri: []const u8) anyerror!mcp.Outcome(types.ReadResourceResult) {
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    contents[0] = .{ .text = .{ .uri = uri, .mimeType = "text/html", .text = "<html></html>" } };
    return .{ .complete = .{ .contents = contents } };
}

fn addWeather(server: *Server) !void {
    try server.addUiResource(.{
        .uri = "ui://weather/dashboard",
        .name = "weather_dashboard",
        .description = "Interactive weather dashboard view",
        .meta = .{ .csp = .{ .connectDomains = &.{"https://api.example.com"} }, .prefersBorder = true },
    }, dashboard_html);
    try server.addUiResourceHandler(.{ .uri = "ui://weather/dynamic", .name = "dynamic" }, dynamicView);
    try server.addUiResourceHandler(.{ .uri = "ui://weather/wrong", .name = "wrong", .meta_in_listing = false }, wrongView);
    try server.addToolJson(.{ .name = "get_weather", .description = "Current weather", .ui = .{ .resourceUri = "ui://weather/dashboard" }, .meta = .{ .object = .empty } }, weather);
    try server.addToolJson(.{ .name = "refresh_dashboard", .ui = .{ .resourceUri = "ui://weather/dashboard", .visibility = &.{.app} } }, weather);
    try server.addToolJson(.{ .name = "plain" }, weather);
}

test "apps: views, tool metadata and the client declaration" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: ClientFixture = undefined;
    try f.init(.{ .info = .{ .name = "s", .version = "1" }, .apps = .{} }, .{ .info = .{ .name = "c", .version = "1" }, .capabilities = try apps.declare(arena, .{}) });
    defer f.deinit();
    try addWeather(&f.server);
    try f.server.checkUiLinks(null);

    const disc = try f.client.discover(arena, .{});
    try testing.expect(disc.capabilities.extensions.?.object.get(apps.extension_id) != null);

    const tools = (try f.client.listTools(arena, null, .{})).tools;
    try testing.expectEqual(3, tools.len);
    const ui = (try f.client.toolUi(arena, tools[0])).?;
    try testing.expectEqualStrings("ui://weather/dashboard", ui.resourceUri.?);
    try testing.expect(ui.visibleToModel());
    const app_only = (try f.client.toolUi(arena, tools[1])).?;
    try testing.expect(!app_only.visibleToModel() and app_only.callableByApp());
    try testing.expectEqual(2, (try apps.modelTools(arena, tools)).len);
    try testing.expect(try f.client.toolUi(arena, tools[2]) == null);
    // A view calls an app-only tool through the host.
    const r = try f.client.callTool(arena, "refresh_dashboard", null, .{});
    try testing.expectEqualStrings("Sunny, 22 degrees", r.content[0].text.text);

    // The listed resource carries the UI metadata for a review before the read.
    const listed = (try f.client.listResources(arena, null, .{})).resources;
    try testing.expectEqualStrings(apps.mime_type, listed[0].mimeType.?);
    try testing.expect(listed[0]._meta.?.object.get("ui") != null);
    try testing.expect(listed[2]._meta == null);

    const view = try f.client.readUiResource(arena, "ui://weather/dashboard", listed[0]._meta, .{});
    try testing.expectEqualStrings(dashboard_html, view.html);
    try testing.expect(view.meta.?.prefersBorder.?);
    try testing.expectEqualStrings("https://api.example.com", view.meta.?.csp.?.connectDomains.?[0]);
    const dynamic = try f.client.readUiResource(arena, "ui://weather/dynamic", null, .{});
    try testing.expect(dynamic.meta == null);
    var diag: Client.Diagnostics = .{};
    try testing.expectError(error.Rpc, f.client.readUiResource(arena, "ui://weather/wrong", null, .{ .diagnostics = &diag }));
    try testing.expectEqual(@as(i64, -32603), diag.rpc_error.?.code);
    try testing.expectError(error.NotUiUri, f.client.readUiResource(arena, "https://example.com", null, .{}));
}

test "apps: a client without the extension gets plain tools" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var f: ClientFixture = undefined;
    try f.init(.{ .info = .{ .name = "s", .version = "1" }, .apps = .{} }, .{ .info = .{ .name = "c", .version = "1" } });
    defer f.deinit();
    try addWeather(&f.server);

    const tools = (try f.client.listTools(arena, null, .{})).tools;
    try testing.expectEqual(2, tools.len);
    try testing.expectEqualStrings("get_weather", tools[0].name);
    try testing.expect(tools[0]._meta == null);
    try testing.expect(try apps.toolMeta(arena, tools[0]) == null);
    // The tool still gives meaningful content without a view.
    const r = try f.client.callTool(arena, "get_weather", null, .{});
    try testing.expectEqualStrings("Sunny, 22 degrees", r.content[0].text.text);
    var diag: Client.Diagnostics = .{};
    try testing.expectError(error.Rpc, f.client.callTool(arena, "refresh_dashboard", null, .{ .diagnostics = &diag }));
    try testing.expectEqual(@as(i64, -32602), diag.rpc_error.?.code);

    // With the fallback off, every client gets the metadata.
    var h_server = try Server.init(testing.allocator, testing.io, .{ .info = .{ .name = "s", .version = "1" }, .apps = .{ .fallback_for_other_clients = false } });
    defer h_server.deinit();
    try addWeather(&h_server);
    var h: Harness = .init(testing.io, testing.allocator, &h_server);
    defer h.deinit();
    try h.send(try request(arena, 1, "tools/list", meta_plain, ""));
    const v = try json.parseTree(arena, h.last().?);
    try testing.expectEqual(3, resultOf(v).object.get("tools").?.array.items.len);
    h.clear();
    try h.send(try request(arena, 2, "tools/list", meta_ui, ""));
    const w = try json.parseTree(arena, h.last().?);
    try testing.expect(resultOf(w).object.get("tools").?.array.items[0].object.get("_meta").?.object.get("ui") != null);
}

test "apps: registration checks" {
    var server = try Server.init(testing.allocator, testing.io, .{ .info = .{ .name = "s", .version = "1" }, .apps = .{} });
    defer server.deinit();
    try testing.expectError(error.InvalidUiMeta, server.addUiResource(.{ .uri = "https://x/view", .name = "v" }, "<html></html>"));
    try testing.expectError(error.InvalidUiMeta, server.addToolJson(.{ .name = "a", .ui = .{ .resourceUri = "https://x" } }, weather));
    try testing.expectError(error.InvalidUiMeta, server.addToolJson(.{ .name = "b", .ui = .{ .visibility = &.{} } }, weather));
    try testing.expectError(error.InvalidUiMeta, server.addToolJson(.{ .name = "c", .ui = .{ .visibility = &.{ .app, .app } } }, weather));
    var meta_arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer meta_arena.deinit();
    try testing.expectError(error.InvalidMeta, server.addToolJson(.{ .name = "d", .meta = try json.parseTree(meta_arena.allocator(), "{\"ui\":{}}"), .ui = .{} }, weather));
    try server.addToolJson(.{ .name = "orphan", .ui = .{ .resourceUri = "ui://missing/view" } }, weather);
    var broken: []const u8 = "";
    try testing.expectError(error.UnknownUiResource, server.checkUiLinks(&broken));
    try testing.expectEqualStrings("orphan", broken);
    try server.addResourceTemplate(.{ .uri_template = "ui://missing/{name}", .name = "views" }, templateView);
    try server.checkUiLinks(null);
}

fn templateView(ctx: *RequestContext, uri: []const u8, vars: []const mcp.UriTemplate.Variable) anyerror!mcp.Outcome(types.ReadResourceResult) {
    _ = vars;
    return dynamicView(ctx, uri);
}
