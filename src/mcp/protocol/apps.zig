//! Wire types and shared rules of the MCP Apps extension (`io.modelcontextprotocol/ui`,
//! SEP-1865). A server declares HTML views as `ui://` resources and links tools to them with
//! `_meta.ui`. A host that declares the extension renders the view of a tool in a sandboxed
//! frame.
//!
//! The SDK provides the parts of the extension between a client and a server. These are the
//! resource and tool metadata, the client declaration and the fallback for other clients.
//! Other parts are host behavior in a browser. These are the `ui/` messages between a host
//! and a view, the sandbox proxy, the content security policy and the display modes. These
//! parts are out of the scope of this SDK.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("types.zig");
const json = @import("../json.zig");

pub const extension_id = "io.modelcontextprotocol/ui";
/// The MIME type of an HTML view. The content of a UI resource must have this type.
pub const mime_type = "text/html;profile=mcp-app";
/// The URI scheme of UI resources.
pub const scheme_prefix = "ui://";
/// The flat `_meta` key of earlier drafts. The extension deprecates it. The SDK reads it as
/// a fallback and never writes it.
pub const legacy_resource_uri_key = "ui/resourceUri";

/// The origins that a view needs. A host builds the content security policy from them.
pub const Csp = struct {
    /// Origins for network requests (`connect-src`).
    connectDomains: ?[]const []const u8 = null,
    /// Origins for scripts, images, styles, fonts and media.
    resourceDomains: ?[]const []const u8 = null,
    /// Origins for nested frames (`frame-src`).
    frameDomains: ?[]const []const u8 = null,
    /// Allowed base URIs of the document (`base-uri`).
    baseUriDomains: ?[]const []const u8 = null,
};

/// The browser permissions that a view asks for. A host can grant them or not.
pub const Permissions = struct {
    camera: ?types.Empty = null,
    microphone: ?types.Empty = null,
    geolocation: ?types.Empty = null,
    clipboardWrite: ?types.Empty = null,
};

/// The `_meta.ui` object of a UI resource: on the listed resource, on the read content item,
/// or on both. The value on the content item has priority.
pub const ResourceMeta = struct {
    csp: ?Csp = null,
    permissions: ?Permissions = null,
    /// A dedicated origin for the view. The format depends on the host.
    domain: ?[]const u8 = null,
    /// True asks for a visible border and background. Null lets the host decide.
    prefersBorder: ?bool = null,
};

/// Who can see and call a tool.
pub const Visibility = enum {
    /// The model sees the tool and can call it.
    model,
    /// A view of the same server can call the tool.
    app,
};

/// The `_meta.ui` object of a tool.
pub const ToolMeta = struct {
    /// The `ui://` resource that renders the results of the tool.
    resourceUri: ?[]const u8 = null,
    /// Null means `["model", "app"]`.
    visibility: ?[]const Visibility = null,

    pub fn visibleToModel(self: ToolMeta) bool {
        return self.has(.model);
    }

    pub fn callableByApp(self: ToolMeta) bool {
        return self.has(.app);
    }

    fn has(self: ToolMeta, v: Visibility) bool {
        const list = self.visibility orelse return true;
        for (list) |item| if (item == v) return true;
        return false;
    }
};

/// The settings of the extension in the client capabilities.
pub const ClientSettings = struct {
    /// The content types that the host can render. Required.
    mimeTypes: []const []const u8,
};

/// True when `uri` is a `ui://` URI with a path.
pub fn isUiUri(uri: []const u8) bool {
    return uri.len > scheme_prefix.len and std.mem.startsWith(u8, uri, scheme_prefix);
}

/// True when the client declared the extension with the MIME type of HTML views. A server
/// gives UI metadata only to such a client. Other clients get plain tools.
pub fn clientSupports(caps: types.ClientCapabilities) bool {
    const ext = caps.extensions orelse return false;
    if (ext != .object) return false;
    const settings = ext.object.get(extension_id) orelse return false;
    if (settings != .object) return false;
    const list = settings.object.get("mimeTypes") orelse return false;
    if (list != .array) return false;
    for (list.array.items) |m| if (m == .string and std.mem.eql(u8, m.string, mime_type)) return true;
    return false;
}

/// The client capabilities with the extension declared for HTML views. Other extensions are
/// kept.
pub fn declare(arena: Allocator, caps: types.ClientCapabilities) Allocator.Error!types.ClientCapabilities {
    var list: std.json.Array = .init(arena);
    try list.append(.{ .string = mime_type });
    var settings: std.json.ObjectMap = .empty;
    try settings.put(arena, "mimeTypes", .{ .array = list });
    return caps.withExtension(arena, extension_id, .{ .object = settings });
}

pub const MetaError = error{
    OutOfMemory,
    /// `_meta.ui` has an unexpected shape or an unknown visibility value.
    InvalidUiMeta,
};

/// The UI metadata of a tool, or null when the tool has none. The function reads
/// `_meta.ui` and falls back to the deprecated flat key.
pub fn toolMeta(arena: Allocator, tool: types.Tool) MetaError!?ToolMeta {
    const meta = tool._meta orelse return null;
    if (meta != .object) return null;
    if (meta.object.get("ui")) |ui| {
        return json.parseValue(ToolMeta, arena, ui) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidUiMeta,
        };
    }
    if (meta.object.get(legacy_resource_uri_key)) |uri| {
        if (uri != .string) return error.InvalidUiMeta;
        return .{ .resourceUri = uri.string };
    }
    return null;
}

/// The tools that a host can give to the model. A host must not give a tool to the model
/// when its visibility does not include `model`.
pub fn modelTools(arena: Allocator, tools: []const types.Tool) MetaError![]const types.Tool {
    var out: std.ArrayList(types.Tool) = .empty;
    for (tools) |t| {
        const m = try toolMeta(arena, t);
        if (m) |ui| if (!ui.visibleToModel()) continue;
        try out.append(arena, t);
    }
    return out.items;
}

/// The UI metadata of a view. The value on the read content item has priority over the
/// value on the listed resource.
pub fn resourceMeta(arena: Allocator, content_meta: ?Value, listing_meta: ?Value) MetaError!?ResourceMeta {
    if (try uiObject(arena, content_meta)) |m| return m;
    return uiObject(arena, listing_meta);
}

fn uiObject(arena: Allocator, meta: ?Value) MetaError!?ResourceMeta {
    const m = meta orelse return null;
    if (m != .object) return null;
    const ui = m.object.get("ui") orelse return null;
    return json.parseValue(ResourceMeta, arena, ui) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidUiMeta,
    };
}

/// The `_meta` object `{"ui": meta}`.
pub fn metaValue(arena: Allocator, meta: anytype) Allocator.Error!Value {
    const text = try json.writeAlloc(arena, meta);
    const ui = json.parseTree(arena, text) catch return error.OutOfMemory;
    var obj: std.json.ObjectMap = .empty;
    try obj.put(arena, "ui", ui);
    return .{ .object = obj };
}

/// A view that a client read.
pub const UiResource = struct {
    uri: []const u8,
    /// The HTML document.
    html: []const u8,
    /// The UI metadata after the priority rule of `resourceMeta`.
    meta: ?ResourceMeta = null,
};

pub const ReadError = MetaError || error{
    /// The URI is not a `ui://` URI.
    NotUiUri,
    /// The result has no content item for the URI.
    MissingContent,
    /// The content item has a MIME type other than `text/html;profile=mcp-app`.
    WrongMimeType,
    /// The blob is not valid base64.
    InvalidBlob,
};

/// Extract the view from a `resources/read` result. `listing_meta` is the `_meta` of the
/// listed resource, when the client has it.
pub fn uiResourceFromRead(arena: Allocator, uri: []const u8, result: types.ReadResourceResult, listing_meta: ?Value) ReadError!UiResource {
    if (!isUiUri(uri)) return error.NotUiUri;
    for (result.contents) |c| {
        if (!std.mem.eql(u8, c.uri(), uri)) continue;
        const item_mime: ?[]const u8, const item_meta: ?Value, const html: []const u8 = switch (c) {
            .text => |t| .{ t.mimeType, t._meta, t.text },
            .blob => |b| blk: {
                const decoder = std.base64.standard.Decoder;
                const len = decoder.calcSizeForSlice(b.blob) catch return error.InvalidBlob;
                const out = try arena.alloc(u8, len);
                decoder.decode(out, b.blob) catch return error.InvalidBlob;
                break :blk .{ b.mimeType, b._meta, out };
            },
        };
        const m = item_mime orelse return error.WrongMimeType;
        if (!std.mem.eql(u8, m, mime_type)) return error.WrongMimeType;
        return .{ .uri = uri, .html = html, .meta = try resourceMeta(arena, item_meta, listing_meta) };
    }
    return error.MissingContent;
}

test "tool metadata and visibility" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const schema = try json.parseTree(arena, "{\"type\":\"object\"}");
    const tools = [_]types.Tool{
        .{ .name = "plain", .inputSchema = schema },
        .{ .name = "both", .inputSchema = schema, ._meta = try json.parseTree(arena, "{\"ui\":{\"resourceUri\":\"ui://w/d\"}}") },
        .{ .name = "app_only", .inputSchema = schema, ._meta = try json.parseTree(arena, "{\"ui\":{\"resourceUri\":\"ui://w/d\",\"visibility\":[\"app\"]}}") },
        .{ .name = "legacy", .inputSchema = schema, ._meta = try json.parseTree(arena, "{\"ui/resourceUri\":\"ui://w/old\"}") },
    };
    try std.testing.expect(try toolMeta(arena, tools[0]) == null);
    const both = (try toolMeta(arena, tools[1])).?;
    try std.testing.expect(both.visibleToModel() and both.callableByApp());
    const app_only = (try toolMeta(arena, tools[2])).?;
    try std.testing.expect(!app_only.visibleToModel() and app_only.callableByApp());
    try std.testing.expectEqualStrings("ui://w/old", (try toolMeta(arena, tools[3])).?.resourceUri.?);
    const visible = try modelTools(arena, &tools);
    try std.testing.expectEqual(3, visible.len);
    const bad: types.Tool = .{ .name = "bad", .inputSchema = schema, ._meta = try json.parseTree(arena, "{\"ui\":{\"visibility\":[\"robot\"]}}") };
    try std.testing.expectError(error.InvalidUiMeta, toolMeta(arena, bad));
}

test "client declaration and resource metadata priority" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expect(!clientSupports(.{}));
    const caps = try declare(arena, .{ .extensions = try json.parseTree(arena, "{\"x/other\":{}}") });
    try std.testing.expect(clientSupports(caps));
    try std.testing.expect(caps.hasExtension("x/other"));
    try std.testing.expectEqualStrings(
        \\{"extensions":{"x/other":{},"io.modelcontextprotocol/ui":{"mimeTypes":["text/html;profile=mcp-app"]}}}
    , try json.writeAlloc(arena, caps));

    const listing = try metaValue(arena, ResourceMeta{ .prefersBorder = false, .domain = "a.example" });
    const item = try metaValue(arena, ResourceMeta{ .prefersBorder = true, .csp = .{ .connectDomains = &.{"https://api.example"} } });
    const chosen = (try resourceMeta(arena, item, listing)).?;
    try std.testing.expect(chosen.prefersBorder.?);
    try std.testing.expect(chosen.domain == null);
    const fallback = (try resourceMeta(arena, null, listing)).?;
    try std.testing.expectEqualStrings("a.example", fallback.domain.?);

    const contents = [_]types.ResourceContents{.{ .text = .{ .uri = "ui://w/d", .mimeType = mime_type, .text = "<!DOCTYPE html><html></html>", ._meta = item } }};
    const view = try uiResourceFromRead(arena, "ui://w/d", .{ .contents = &contents }, listing);
    try std.testing.expectEqualStrings("https://api.example", view.meta.?.csp.?.connectDomains.?[0]);
    const wrong = [_]types.ResourceContents{.{ .text = .{ .uri = "ui://w/d", .mimeType = "text/html", .text = "x" } }};
    try std.testing.expectError(error.WrongMimeType, uiResourceFromRead(arena, "ui://w/d", .{ .contents = &wrong }, null));
    try std.testing.expectError(error.NotUiUri, uiResourceFromRead(arena, "https://x", .{ .contents = &wrong }, null));
}
