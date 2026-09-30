//! The server part of the MCP Apps extension (`io.modelcontextprotocol/ui`). The server
//! registers HTML views as `ui://` resources and links tools to them with `_meta.ui`. See
//! `protocol/apps.zig` for the parts of the extension that are out of scope.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("../protocol/types.zig");
const errors = @import("../protocol/errors.zig");
const proto = @import("../protocol/apps.zig");
const mrtr = @import("mrtr.zig");
const RequestContext = @import("RequestContext.zig");

pub const extension_id = proto.extension_id;

pub const Options = struct {
    /// Serve plain tools to a client that did not declare the extension with the MIME type
    /// of HTML views. Such a client gets no `_meta.ui` in `tools/list` and does not see tools
    /// that only a view can call. A call to such a tool gets error `-32602`.
    fallback_for_other_clients: bool = true,
};

pub const ResourceHandler = *const fn (ctx: *RequestContext, uri: []const u8) anyerror!mrtr.Outcome(types.ReadResourceResult);

/// A view: a `ui://` resource with the MIME type `text/html;profile=mcp-app`.
pub const UiResourceDef = struct {
    /// Must start with `ui://`.
    uri: []const u8,
    name: []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    /// The UI metadata. The server puts it on every content item that it reads.
    meta: ?proto.ResourceMeta = null,
    /// Also put `meta` on the entry in `resources/list`. A host can then examine the
    /// security configuration before it reads the view.
    meta_in_listing: bool = true,
    userdata: ?*anyopaque = null,
};

/// A registered view. The registry arena of the server owns it.
pub const UiEntry = struct {
    /// Static HTML, or null when `handler` gives the content.
    html: ?[]const u8,
    /// `{"ui": meta}`, or null.
    meta: ?Value,
    handler: ?ResourceHandler,
    userdata: ?*anyopaque,
};

/// The resource handler of every view. It gives static HTML or calls the application
/// handler. Then it sets the MIME type and the UI metadata of each content item. A content
/// item with another MIME type is an internal error.
pub fn readUi(ctx: *RequestContext, uri: []const u8) anyerror!mrtr.Outcome(types.ReadResourceResult) {
    const entry: *const UiEntry = @ptrCast(@alignCast(ctx.userdata.?));
    if (entry.html) |html| {
        const contents = try ctx.arena.alloc(types.ResourceContents, 1);
        if (std.unicode.utf8ValidateSlice(html)) {
            contents[0] = .{ .text = .{ .uri = uri, .mimeType = proto.mime_type, ._meta = entry.meta, .text = html } };
        } else {
            const encoder = std.base64.standard.Encoder;
            const out = try ctx.arena.alloc(u8, encoder.calcSize(html.len));
            contents[0] = .{ .blob = .{ .uri = uri, .mimeType = proto.mime_type, ._meta = entry.meta, .blob = encoder.encode(out, html) } };
        }
        return .{ .complete = .{ .contents = contents } };
    }
    ctx.userdata = entry.userdata;
    const outcome = try entry.handler.?(ctx, uri);
    switch (outcome) {
        .complete => |r| {
            const contents = try ctx.arena.dupe(types.ResourceContents, r.contents);
            for (contents) |*c| switch (c.*) {
                inline else => |*item| {
                    if (item.mimeType) |m| {
                        if (!std.mem.eql(u8, m, proto.mime_type)) return ctx.setError(errors.internalError("A UI resource must have the MIME type text/html;profile=mcp-app"));
                    } else item.mimeType = proto.mime_type;
                    if (item._meta == null) item._meta = entry.meta;
                },
            };
            var result = r;
            result.contents = contents;
            return .{ .complete = result };
        },
        else => return outcome,
    }
}
