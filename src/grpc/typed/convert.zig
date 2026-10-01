//! The mapping between MCP JSON and the messages of the typed binding, in both directions.
//!
//! The server decodes a request message into JSON-RPC params and encodes a JSON-RPC result
//! into a response message. The client does the reverse. The mapping follows the reference
//! transport `mcp-grpc-transport-py`:
//!
//! - `_meta` of the params and of the result travels in `common.metadata`.
//! - JSON values (tool arguments, schemas, `structuredContent`, `_meta`) travel as
//!   `google.protobuf.Struct`.
//! - The `bytes` fields (`data` of an image or an audio block, `blob` of a resource) carry
//!   the base64 text of MCP, not the decoded octets.
//!
//! The conversion of JSON to a message is strict. A field that the messages cannot carry
//! gives `error.Unexpressible`, and the context then has the reason. The conversion does not
//! drop such a field.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const ObjectMap = std.json.ObjectMap;
const pb = @import("../protobuf/mcp_messages.zig");
const codec = @import("../protobuf/codec.zig");
const well_known = @import("../protobuf/well_known.zig");
const service = @import("service.zig");
const Rpc = service.Rpc;

pub const Error = error{
    OutOfMemory,
    /// The MCP value is valid, but the typed messages have no field for a part of it.
    Unexpressible,
    /// The value does not have the shape of its MCP type or of its message.
    Invalid,
};

pub const DecodeError = Error || codec.DecodeError;

/// The state of one conversion.
pub const Context = struct {
    arena: Allocator,
    /// The reason of the last failure, in `arena`.
    reason: []const u8 = "",
    limits: codec.Limits = .{},

    fn fail(cx: *Context, comptime err: Error, comptime fmt: []const u8, args: anytype) Error {
        cx.reason = std.fmt.allocPrint(cx.arena, fmt, args) catch return error.OutOfMemory;
        return err;
    }
};

// -- Entry points -----------------------------------------------------------------------------

/// Decode the request message of `rpc` into the JSON-RPC params. The strings of the params
/// point into `bytes`.
pub fn decodeRequest(cx: *Context, rpc: Rpc, bytes: []const u8) DecodeError!Value {
    switch (rpc) {
        inline else => |r| {
            const msg = try codec.decode(r.Request(), cx.arena, bytes, cx.limits);
            return requestToJson(cx, r, msg);
        },
    }
}

/// Encode the JSON-RPC params of `rpc` as its request message and append the bytes to `out`.
pub fn encodeRequest(cx: *Context, gpa: Allocator, out: *std.ArrayList(u8), rpc: Rpc, params: Value) Error!void {
    switch (rpc) {
        inline else => |r| try encodeMessage(cx, r.Request(), gpa, out, try paramsToPb(cx, r, params)),
    }
}

/// Decode the response message of `rpc` into the JSON-RPC result. The strings of the result
/// point into `bytes`.
pub fn decodeResponse(cx: *Context, rpc: Rpc, bytes: []const u8) DecodeError!Value {
    switch (rpc) {
        inline else => |r| {
            const msg = try codec.decode(r.Response(), cx.arena, bytes, cx.limits);
            return responseToJson(cx, r, msg);
        },
    }
}

/// Encode the JSON-RPC result of `rpc` as its response message and append the bytes to `out`.
pub fn encodeResult(cx: *Context, gpa: Allocator, out: *std.ArrayList(u8), rpc: Rpc, result: Value) Error!void {
    switch (rpc) {
        inline else => |r| try encodeMessage(cx, r.Response(), gpa, out, try resultToPb(cx, r, result)),
    }
}

/// The routing metadata of a request and the value that it must have.
pub const Route = struct {
    header: []const u8,
    value: []const u8,
};

/// The routing metadata of the JSON-RPC params of `rpc`, or null.
pub fn route(rpc: Rpc, params: Value) ?Route {
    const header = rpc.routeHeader() orelse return null;
    const value: ?[]const u8 = switch (rpc) {
        .call_tool, .get_prompt => getString(params, "name"),
        .read_resource => getString(params, "uri"),
        .complete => blk: {
            if (params != .object) break :blk null;
            const ref = params.object.get("ref") orelse break :blk null;
            const t = getString(ref, "type") orelse break :blk null;
            if (std.mem.eql(u8, t, "ref/resource")) break :blk getString(ref, "uri");
            if (std.mem.eql(u8, t, "ref/prompt")) break :blk getString(ref, "name");
            break :blk null;
        },
        else => null,
    };
    return .{ .header = header, .value = value orelse return null };
}

fn encodeMessage(cx: *Context, comptime T: type, gpa: Allocator, out: *std.ArrayList(u8), msg: T) Error!void {
    codec.encode(T, gpa, out, msg, cx.limits) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsafeInteger => return cx.fail(error.Unexpressible, "an integer outside the range from -(2^53) to 2^53 in a JSON value", .{}),
        error.InvalidValue => return cx.fail(error.Invalid, "a JSON value that is not an object in an object field", .{}),
        error.TooDeep => return cx.fail(error.Unexpressible, "a JSON value with more than {d} levels", .{cx.limits.max_depth}),
        error.MessageTooLarge => return cx.fail(error.Unexpressible, "a message larger than 4 GiB", .{}),
    };
}

// -- JSON helpers -----------------------------------------------------------------------------

fn getString(v: Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const s = v.object.get(key) orelse return null;
    return if (s == .string) s.string else null;
}

/// The value of `key`. A JSON null counts as an absent field.
fn field(o: ObjectMap, key: []const u8) ?Value {
    const v = o.get(key) orelse return null;
    return if (v == .null) null else v;
}

fn contains(comptime list: []const []const u8, key: []const u8) bool {
    inline for (list) |item| if (std.mem.eql(u8, item, key)) return true;
    return false;
}

/// Refuse a key that the message of `what` has no field for.
fn checkKeys(cx: *Context, o: ObjectMap, comptime allowed: []const []const u8, comptime what: []const u8) Error!void {
    var it = o.iterator();
    while (it.next()) |kv| {
        if (!contains(allowed, kv.key_ptr.*)) return cx.fail(error.Unexpressible, "the field {s} of " ++ what, .{kv.key_ptr.*});
    }
}

fn asObject(cx: *Context, v: Value, comptime what: []const u8) Error!ObjectMap {
    if (v != .object) return cx.fail(error.Invalid, what ++ " is not an object", .{});
    return v.object;
}

fn asArray(cx: *Context, v: Value, comptime what: []const u8) Error![]const Value {
    if (v != .array) return cx.fail(error.Invalid, what ++ " is not an array", .{});
    return v.array.items;
}

fn asString(cx: *Context, v: Value, comptime what: []const u8) Error![]const u8 {
    if (v != .string) return cx.fail(error.Invalid, what ++ " is not a string", .{});
    return v.string;
}

fn asBool(cx: *Context, v: Value, comptime what: []const u8) Error!bool {
    if (v != .bool) return cx.fail(error.Invalid, what ++ " is not a boolean", .{});
    return v.bool;
}

fn asInt(cx: *Context, v: Value, comptime what: []const u8) Error!i64 {
    switch (v) {
        .integer => |i| return i,
        .float => |f| {
            const limit: f64 = @floatFromInt(std.math.maxInt(i64));
            if (@trunc(f) == f and @abs(f) < limit) return @intFromFloat(f);
            return cx.fail(error.Unexpressible, what ++ " is not an integer", .{});
        },
        .number_string => return cx.fail(error.Unexpressible, what ++ " is outside the range of a 64-bit integer", .{}),
        else => return cx.fail(error.Invalid, what ++ " is not a number", .{}),
    }
}

fn asNumber(cx: *Context, v: Value, comptime what: []const u8) Error!f64 {
    switch (v) {
        .integer => |i| return @floatFromInt(i),
        .float => |f| return f,
        .number_string => return cx.fail(error.Unexpressible, what ++ " is outside the range of a double", .{}),
        else => return cx.fail(error.Invalid, what ++ " is not a number", .{}),
    }
}

fn reqString(cx: *Context, o: ObjectMap, comptime key: []const u8, comptime what: []const u8) Error![]const u8 {
    const v = field(o, key) orelse return cx.fail(error.Invalid, what ++ " has no " ++ key, .{});
    return asString(cx, v, what ++ "." ++ key);
}

fn optString(cx: *Context, o: ObjectMap, comptime key: []const u8, comptime what: []const u8) Error![]const u8 {
    const v = field(o, key) orelse return "";
    return asString(cx, v, what ++ "." ++ key);
}

fn stringList(cx: *Context, v: Value, comptime what: []const u8) Error![]const []const u8 {
    const items = try asArray(cx, v, what);
    const out = try cx.arena.alloc([]const u8, items.len);
    for (items, out) |item, *s| s.* = try asString(cx, item, "an item of " ++ what);
    return out;
}

fn f32From(cx: *Context, v: Value, comptime what: []const u8) Error!f32 {
    const n: f32 = @floatCast(try asNumber(cx, v, what));
    if (!std.math.isFinite(n)) return cx.fail(error.Unexpressible, what ++ " is outside the range of a float", .{});
    return n;
}

fn u32From(cx: *Context, v: Value, comptime what: []const u8) Error!u32 {
    const i = try asInt(cx, v, what);
    return std.math.cast(u32, i) orelse return cx.fail(error.Unexpressible, what ++ " is outside the range from 0 to 2^32", .{});
}

fn u64From(cx: *Context, v: Value, comptime what: []const u8) Error!u64 {
    const i = try asInt(cx, v, what);
    return std.math.cast(u64, i) orelse return cx.fail(error.Invalid, what ++ " is negative", .{});
}

/// `_meta` and other JSON objects that travel as a `Struct`.
fn objectValue(cx: *Context, v: Value, comptime what: []const u8) Error!Value {
    if (v != .object) return cx.fail(error.Invalid, what ++ " is not an object", .{});
    return v;
}

fn metaOf(cx: *Context, o: ObjectMap) Error!?Value {
    const m = field(o, "_meta") orelse return null;
    return try objectValue(cx, m, "_meta");
}

/// A JSON object under construction. Keys keep their insertion order.
const Obj = struct {
    cx: *Context,
    map: ObjectMap = .empty,

    fn put(self: *Obj, key: []const u8, v: Value) Error!void {
        try self.map.put(self.cx.arena, key, v);
    }

    fn putString(self: *Obj, key: []const u8, s: []const u8) Error!void {
        try self.put(key, .{ .string = s });
    }

    /// Put a string that is not empty. Proto3 does not tell an empty string from an absent one.
    fn putText(self: *Obj, key: []const u8, s: []const u8) Error!void {
        if (s.len > 0) try self.putString(key, s);
    }

    fn putMeta(self: *Obj, metadata: ?Value) Error!void {
        if (metadata) |m| try self.put("_meta", m);
    }

    fn value(self: Obj) Value {
        return .{ .object = self.map };
    }
};

fn stringArray(cx: *Context, list: []const []const u8) Error!Value {
    var array: std.json.Array = .init(cx.arena);
    try array.ensureTotalCapacity(list.len);
    for (list) |s| array.appendAssumeCapacity(.{ .string = s });
    return .{ .array = array };
}

/// The JSON number of a 32-bit float. The shortest decimal text of the float keeps 0.3 as
/// 0.3 and not as 0.30000001192092896.
fn f32Json(cx: *Context, x: f32) Error!Value {
    if (!std.math.isFinite(x)) return cx.fail(error.Invalid, "a float that is not finite", .{});
    var buf: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}", .{x}) catch unreachable;
    return .{ .float = std.fmt.parseFloat(f64, text) catch unreachable };
}

fn f64Json(cx: *Context, x: f64) Error!Value {
    return well_known.numberValue(x) catch return cx.fail(error.Invalid, "a double that is not finite", .{});
}

/// The bytes of a `bytes` field as a JSON string. They must be base64 text.
fn base64Json(cx: *Context, bytes: []const u8, comptime what: []const u8) Error!Value {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(bytes) catch return cx.fail(error.Invalid, what ++ " is not base64 text", .{});
    const scratch = try cx.arena.alloc(u8, size);
    decoder.decode(scratch, bytes) catch return cx.fail(error.Invalid, what ++ " is not base64 text", .{});
    return .{ .string = bytes };
}

// -- Simple types -----------------------------------------------------------------------------

fn roleToPb(cx: *Context, v: Value) Error!pb.Role {
    const s = try asString(cx, v, "a role");
    if (std.mem.eql(u8, s, "user")) return .user;
    if (std.mem.eql(u8, s, "assistant")) return .assistant;
    return cx.fail(error.Invalid, "the role {s}", .{s});
}

fn roleJson(cx: *Context, r: pb.Role) Error!Value {
    switch (r) {
        .user => return .{ .string = "user" },
        .assistant => return .{ .string = "assistant" },
        else => return cx.fail(error.Invalid, "the role {d}", .{@intFromEnum(r)}),
    }
}

fn annotationsToPb(cx: *Context, v: Value) Error!pb.Annotations {
    const o = try asObject(cx, v, "annotations");
    try checkKeys(cx, o, &.{ "audience", "priority", "lastModified" }, "annotations");
    var out: pb.Annotations = .{};
    if (field(o, "audience")) |a| {
        const items = try asArray(cx, a, "annotations.audience");
        const roles = try cx.arena.alloc(pb.Role, items.len);
        for (items, roles) |item, *r| r.* = try roleToPb(cx, item);
        out.audience = roles;
    }
    if (field(o, "priority")) |p| out.priority = try f32From(cx, p, "annotations.priority");
    if (field(o, "lastModified")) |lm| out.last_modified = try asString(cx, lm, "annotations.lastModified");
    return out;
}

fn annotationsJson(cx: *Context, a: pb.Annotations) Error!Value {
    var obj: Obj = .{ .cx = cx };
    if (a.audience.len > 0) {
        var array: std.json.Array = .init(cx.arena);
        for (a.audience) |r| try array.append(try roleJson(cx, r));
        try obj.put("audience", .{ .array = array });
    }
    if (a.priority) |p| try obj.put("priority", try f32Json(cx, p));
    if (a.last_modified) |lm| try obj.putString("lastModified", lm);
    return obj.value();
}

fn iconsToPb(cx: *Context, v: Value) Error![]const pb.Icon {
    const items = try asArray(cx, v, "icons");
    const out = try cx.arena.alloc(pb.Icon, items.len);
    for (items, out) |item, *icon| {
        const o = try asObject(cx, item, "an icon");
        try checkKeys(cx, o, &.{ "src", "mimeType", "sizes", "theme" }, "an icon");
        icon.* = .{ .src = try reqString(cx, o, "src", "an icon"), .mime_type = try optString(cx, o, "mimeType", "an icon") };
        if (field(o, "sizes")) |s| icon.sizes = try stringList(cx, s, "icon sizes");
        if (field(o, "theme")) |t| {
            const theme = try asString(cx, t, "an icon theme");
            icon.theme = if (std.mem.eql(u8, theme, "light")) .light else if (std.mem.eql(u8, theme, "dark")) .dark else return cx.fail(error.Invalid, "the icon theme {s}", .{theme});
        }
    }
    return out;
}

fn iconsJson(cx: *Context, icons: []const pb.Icon) Error!Value {
    var array: std.json.Array = .init(cx.arena);
    for (icons) |icon| {
        var obj: Obj = .{ .cx = cx };
        try obj.putString("src", icon.src);
        try obj.putText("mimeType", icon.mime_type);
        if (icon.sizes.len > 0) try obj.put("sizes", try stringArray(cx, icon.sizes));
        switch (icon.theme) {
            .unspecified => {},
            .light => try obj.putString("theme", "light"),
            .dark => try obj.putString("theme", "dark"),
            _ => return cx.fail(error.Invalid, "the icon theme {d}", .{@intFromEnum(icon.theme)}),
        }
        try array.append(obj.value());
    }
    return .{ .array = array };
}

fn ttlToPb(cx: *Context, o: ObjectMap) Error!?well_known.Duration {
    const v = field(o, "ttlMs") orelse return null;
    const ms = @max(try asInt(cx, v, "ttlMs"), 0);
    return .{ .seconds = @divTrunc(ms, 1000), .nanos = @intCast(@rem(ms, 1000) * 1_000_000) };
}

fn cacheScopeToPb(cx: *Context, o: ObjectMap) Error!pb.CacheScope {
    const v = field(o, "cacheScope") orelse return .unspecified;
    const s = try asString(cx, v, "cacheScope");
    if (std.mem.eql(u8, s, "public")) return .public;
    if (std.mem.eql(u8, s, "private")) return .private;
    return cx.fail(error.Invalid, "the cache scope {s}", .{s});
}

fn putCache(obj: *Obj, ttl: ?well_known.Duration, scope: pb.CacheScope) Error!void {
    if (ttl) |d| {
        if (d.seconds < 0 or d.nanos < 0 or d.nanos >= 1_000_000_000) return obj.cx.fail(error.Invalid, "a negative or malformed ttl", .{});
        const ms = (d.seconds *| 1000) +| @divTrunc(d.nanos, 1_000_000);
        try obj.put("ttlMs", .{ .integer = ms });
    }
    switch (scope) {
        .unspecified => {},
        .public => try obj.putString("cacheScope", "public"),
        .private => try obj.putString("cacheScope", "private"),
        _ => return obj.cx.fail(error.Invalid, "the cache scope {d}", .{@intFromEnum(scope)}),
    }
}

// -- Content ----------------------------------------------------------------------------------

const Content = pb.CallToolResponse.Content;

fn contentToPb(cx: *Context, v: Value) Error!Content {
    const o = try asObject(cx, v, "a content block");
    const t = try reqString(cx, o, "type", "a content block");
    if (std.mem.eql(u8, t, "text")) {
        try checkKeys(cx, o, &.{ "type", "text", "annotations", "_meta" }, "a text content block");
        return .{ .text = .{
            .text = try reqString(cx, o, "text", "a text content block"),
            .annotations = if (field(o, "annotations")) |a| try annotationsToPb(cx, a) else null,
            .metadata = try metaOf(cx, o),
        } };
    }
    if (std.mem.eql(u8, t, "image")) return .{ .image = try mediaToPb(cx, o) };
    if (std.mem.eql(u8, t, "audio")) return .{ .audio = try mediaToPb(cx, o) };
    if (std.mem.eql(u8, t, "resource")) {
        try checkKeys(cx, o, &.{ "type", "resource", "annotations", "_meta" }, "an embedded resource");
        return .{ .embedded_resource = .{
            .contents = try resourceContentsToPb(cx, field(o, "resource") orelse return cx.fail(error.Invalid, "an embedded resource has no resource", .{})),
            .annotations = if (field(o, "annotations")) |a| try annotationsToPb(cx, a) else null,
            .metadata = try metaOf(cx, o),
        } };
    }
    if (std.mem.eql(u8, t, "resource_link")) return .{ .resource_link = try resourceToPb(cx, o, true) };
    return cx.fail(error.Unexpressible, "a content block of the type {s}", .{t});
}

fn mediaToPb(cx: *Context, o: ObjectMap) Error!pb.ImageContent {
    try checkKeys(cx, o, &.{ "type", "data", "mimeType", "annotations", "_meta" }, "an image or audio content block");
    return .{
        .data = try reqString(cx, o, "data", "an image or audio content block"),
        .mime_type = try reqString(cx, o, "mimeType", "an image or audio content block"),
        .annotations = if (field(o, "annotations")) |a| try annotationsToPb(cx, a) else null,
        .metadata = try metaOf(cx, o),
    };
}

fn contentJson(cx: *Context, c: Content) Error!Value {
    const kinds = @intFromBool(c.text != null) + @intFromBool(c.image != null) + @intFromBool(c.audio != null) +
        @intFromBool(c.embedded_resource != null) + @intFromBool(c.resource_link != null);
    if (kinds != 1) return cx.fail(error.Invalid, "a content block with {d} kinds", .{kinds});
    var obj: Obj = .{ .cx = cx };
    if (c.text) |t| {
        try obj.putString("type", "text");
        try obj.putString("text", t.text);
        if (t.annotations) |a| try obj.put("annotations", try annotationsJson(cx, a));
        try obj.putMeta(t.metadata);
    } else if (c.image orelse c.audio) |m| {
        try obj.putString("type", if (c.image != null) "image" else "audio");
        try obj.put("data", try base64Json(cx, m.data, "the data of an image or audio block"));
        try obj.putString("mimeType", m.mime_type);
        if (m.annotations) |a| try obj.put("annotations", try annotationsJson(cx, a));
        try obj.putMeta(m.metadata);
    } else if (c.embedded_resource) |e| {
        try obj.putString("type", "resource");
        try obj.put("resource", try resourceContentsJson(cx, e.contents orelse return cx.fail(error.Invalid, "an embedded resource has no contents", .{})));
        if (e.annotations) |a| try obj.put("annotations", try annotationsJson(cx, a));
        try obj.putMeta(e.metadata);
    } else if (c.resource_link) |r| {
        return resourceJson(cx, r, true);
    }
    return obj.value();
}

fn resourceContentsToPb(cx: *Context, v: Value) Error!pb.ResourceContents {
    const o = try asObject(cx, v, "resource contents");
    try checkKeys(cx, o, &.{ "uri", "mimeType", "_meta", "text", "blob" }, "resource contents");
    const text = field(o, "text");
    const blob = field(o, "blob");
    if ((text == null) == (blob == null)) return cx.fail(error.Invalid, "resource contents need exactly one of text and blob", .{});
    return .{
        .uri = try reqString(cx, o, "uri", "resource contents"),
        .mime_type = try optString(cx, o, "mimeType", "resource contents"),
        .text = if (text) |t| try asString(cx, t, "the text of a resource") else "",
        .blob = if (blob) |b| try asString(cx, b, "the blob of a resource") else "",
        .metadata = try metaOf(cx, o),
    };
}

fn resourceContentsJson(cx: *Context, c: pb.ResourceContents) Error!Value {
    if (c.text.len > 0 and c.blob.len > 0) return cx.fail(error.Invalid, "resource contents with text and blob", .{});
    var obj: Obj = .{ .cx = cx };
    try obj.putString("uri", c.uri);
    try obj.putText("mimeType", c.mime_type);
    try obj.putMeta(c.metadata);
    // As in the reference transport: a blob that is not empty, else the text.
    if (c.blob.len > 0) {
        try obj.put("blob", try base64Json(cx, c.blob, "the blob of a resource"));
    } else {
        try obj.putString("text", c.text);
    }
    return obj.value();
}

fn resourceToPb(cx: *Context, o: ObjectMap, comptime link: bool) Error!pb.Resource {
    const what = if (link) "a resource link" else "a resource";
    const keys = [_][]const u8{ "name", "title", "icons", "uri", "description", "mimeType", "annotations", "size", "_meta" };
    try checkKeys(cx, o, if (link) &(keys ++ [_][]const u8{"type"}) else &keys, what);
    return .{
        .uri = try reqString(cx, o, "uri", what),
        .name = try reqString(cx, o, "name", what),
        .title = try optString(cx, o, "title", what),
        .description = try optString(cx, o, "description", what),
        .mime_type = try optString(cx, o, "mimeType", what),
        .annotations = if (field(o, "annotations")) |a| try annotationsToPb(cx, a) else null,
        .size = if (field(o, "size")) |s| try u64From(cx, s, what ++ ".size") else 0,
        .icons = if (field(o, "icons")) |i| try iconsToPb(cx, i) else &.{},
        .metadata = try metaOf(cx, o),
    };
}

fn resourceJson(cx: *Context, r: pb.Resource, link: bool) Error!Value {
    var obj: Obj = .{ .cx = cx };
    if (link) try obj.putString("type", "resource_link");
    try obj.putString("name", r.name);
    try obj.putText("title", r.title);
    if (r.icons.len > 0) try obj.put("icons", try iconsJson(cx, r.icons));
    try obj.putString("uri", r.uri);
    try obj.putText("description", r.description);
    try obj.putText("mimeType", r.mime_type);
    if (r.annotations) |a| try obj.put("annotations", try annotationsJson(cx, a));
    if (r.size > 0) try obj.put("size", .{ .integer = std.math.cast(i64, r.size) orelse return cx.fail(error.Invalid, "a resource size above 2^63", .{}) });
    try obj.putMeta(r.metadata);
    return obj.value();
}

// -- Tools, prompts and templates -------------------------------------------------------------

fn toolToPb(cx: *Context, v: Value) Error!pb.Tool {
    const o = try asObject(cx, v, "a tool");
    try checkKeys(cx, o, &.{ "name", "title", "icons", "description", "inputSchema", "outputSchema", "annotations", "_meta" }, "a tool");
    var out: pb.Tool = .{
        .name = try reqString(cx, o, "name", "a tool"),
        .title = try optString(cx, o, "title", "a tool"),
        .description = try optString(cx, o, "description", "a tool"),
        .input_schema = try objectValue(cx, field(o, "inputSchema") orelse return cx.fail(error.Invalid, "a tool has no inputSchema", .{}), "inputSchema"),
        .icons = if (field(o, "icons")) |i| try iconsToPb(cx, i) else &.{},
        .metadata = try metaOf(cx, o),
    };
    if (field(o, "outputSchema")) |s| out.output_schema = try objectValue(cx, s, "outputSchema");
    if (field(o, "annotations")) |a| {
        const ao = try asObject(cx, a, "tool annotations");
        try checkKeys(cx, ao, &.{ "title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint" }, "tool annotations");
        out.annotations = .{
            .title = try optString(cx, ao, "title", "tool annotations"),
            .read_only_hint = if (field(ao, "readOnlyHint")) |h| try asBool(cx, h, "readOnlyHint") else false,
            .destructive_hint = if (field(ao, "destructiveHint")) |h| try asBool(cx, h, "destructiveHint") else false,
            .idempotent_hint = if (field(ao, "idempotentHint")) |h| try asBool(cx, h, "idempotentHint") else false,
            .open_world_hint = if (field(ao, "openWorldHint")) |h| try asBool(cx, h, "openWorldHint") else false,
        };
    }
    return out;
}

fn toolJson(cx: *Context, t: pb.Tool) Error!Value {
    var obj: Obj = .{ .cx = cx };
    try obj.putString("name", t.name);
    try obj.putText("title", t.title);
    if (t.icons.len > 0) try obj.put("icons", try iconsJson(cx, t.icons));
    try obj.putText("description", t.description);
    if (t.input_schema) |s| {
        try obj.put("inputSchema", s);
    } else {
        var schema: Obj = .{ .cx = cx };
        try schema.putString("type", "object");
        try obj.put("inputSchema", schema.value());
    }
    if (t.output_schema) |s| try obj.put("outputSchema", s);
    if (t.annotations) |a| {
        // A false hint is the proto3 default, thus the same as an absent hint.
        var ao: Obj = .{ .cx = cx };
        try ao.putText("title", a.title);
        if (a.read_only_hint) try ao.put("readOnlyHint", .{ .bool = true });
        if (a.destructive_hint) try ao.put("destructiveHint", .{ .bool = true });
        if (a.idempotent_hint) try ao.put("idempotentHint", .{ .bool = true });
        if (a.open_world_hint) try ao.put("openWorldHint", .{ .bool = true });
        try obj.put("annotations", ao.value());
    }
    try obj.putMeta(t.metadata);
    return obj.value();
}

fn promptToPb(cx: *Context, v: Value) Error!pb.Prompt {
    const o = try asObject(cx, v, "a prompt");
    try checkKeys(cx, o, &.{ "name", "title", "icons", "description", "arguments", "_meta" }, "a prompt");
    var out: pb.Prompt = .{
        .name = try reqString(cx, o, "name", "a prompt"),
        .title = try optString(cx, o, "title", "a prompt"),
        .description = try optString(cx, o, "description", "a prompt"),
        .icons = if (field(o, "icons")) |i| try iconsToPb(cx, i) else &.{},
        .metadata = try metaOf(cx, o),
    };
    if (field(o, "arguments")) |a| {
        const items = try asArray(cx, a, "prompt arguments");
        const args = try cx.arena.alloc(pb.Prompt.Argument, items.len);
        for (items, args) |item, *arg| {
            const ao = try asObject(cx, item, "a prompt argument");
            try checkKeys(cx, ao, &.{ "name", "title", "description", "required" }, "a prompt argument");
            arg.* = .{
                .name = try reqString(cx, ao, "name", "a prompt argument"),
                .title = try optString(cx, ao, "title", "a prompt argument"),
                .description = try optString(cx, ao, "description", "a prompt argument"),
                .required = if (field(ao, "required")) |r| try asBool(cx, r, "required") else false,
            };
        }
        out.arguments = args;
    }
    return out;
}

fn promptJson(cx: *Context, p: pb.Prompt) Error!Value {
    var obj: Obj = .{ .cx = cx };
    try obj.putString("name", p.name);
    try obj.putText("title", p.title);
    if (p.icons.len > 0) try obj.put("icons", try iconsJson(cx, p.icons));
    try obj.putText("description", p.description);
    if (p.arguments.len > 0) {
        var array: std.json.Array = .init(cx.arena);
        for (p.arguments) |arg| {
            var ao: Obj = .{ .cx = cx };
            try ao.putString("name", arg.name);
            try ao.putText("title", arg.title);
            try ao.putText("description", arg.description);
            if (arg.required) try ao.put("required", .{ .bool = true });
            try array.append(ao.value());
        }
        try obj.put("arguments", .{ .array = array });
    }
    try obj.putMeta(p.metadata);
    return obj.value();
}

fn templateToPb(cx: *Context, v: Value) Error!pb.ResourceTemplate {
    const o = try asObject(cx, v, "a resource template");
    try checkKeys(cx, o, &.{ "name", "title", "icons", "uriTemplate", "description", "mimeType", "annotations", "_meta" }, "a resource template");
    return .{
        .uri_template = try reqString(cx, o, "uriTemplate", "a resource template"),
        .name = try reqString(cx, o, "name", "a resource template"),
        .title = try optString(cx, o, "title", "a resource template"),
        .description = try optString(cx, o, "description", "a resource template"),
        .mime_type = try optString(cx, o, "mimeType", "a resource template"),
        .annotations = if (field(o, "annotations")) |a| try annotationsToPb(cx, a) else null,
        .icons = if (field(o, "icons")) |i| try iconsToPb(cx, i) else &.{},
        .metadata = try metaOf(cx, o),
    };
}

fn templateJson(cx: *Context, t: pb.ResourceTemplate) Error!Value {
    var obj: Obj = .{ .cx = cx };
    try obj.putString("name", t.name);
    try obj.putText("title", t.title);
    if (t.icons.len > 0) try obj.put("icons", try iconsJson(cx, t.icons));
    try obj.putString("uriTemplate", t.uri_template);
    try obj.putText("description", t.description);
    try obj.putText("mimeType", t.mime_type);
    if (t.annotations) |a| try obj.put("annotations", try annotationsJson(cx, a));
    try obj.putMeta(t.metadata);
    return obj.value();
}

fn promptMessageToPb(cx: *Context, v: Value) Error!pb.PromptMessage {
    const o = try asObject(cx, v, "a prompt message");
    try checkKeys(cx, o, &.{ "role", "content" }, "a prompt message");
    const c = try contentToPb(cx, field(o, "content") orelse return cx.fail(error.Invalid, "a prompt message has no content", .{}));
    return .{
        .role = try roleToPb(cx, field(o, "role") orelse return cx.fail(error.Invalid, "a prompt message has no role", .{})),
        .text = c.text,
        .image = c.image,
        .audio = c.audio,
        .embedded_resource = c.embedded_resource,
        .resource_link = c.resource_link,
    };
}

fn promptMessageJson(cx: *Context, m: pb.PromptMessage) Error!Value {
    var obj: Obj = .{ .cx = cx };
    try obj.put("role", try roleJson(cx, m.role));
    try obj.put("content", try contentJson(cx, .{ .text = m.text, .image = m.image, .audio = m.audio, .embedded_resource = m.embedded_resource, .resource_link = m.resource_link }));
    return obj.value();
}

// -- Input requests and input responses ---------------------------------------------------------

fn inputRequestsToPb(cx: *Context, v: Value) Error![]const pb.InputRequestEntry {
    const o = try asObject(cx, v, "inputRequests");
    const out = try cx.arena.alloc(pb.InputRequestEntry, o.count());
    var it = o.iterator();
    var i: usize = 0;
    while (it.next()) |kv| : (i += 1) {
        out[i] = .{ .key = kv.key_ptr.*, .value = try inputRequestToPb(cx, kv.key_ptr.*, kv.value_ptr.*) };
    }
    return out;
}

fn inputRequestToPb(cx: *Context, key: []const u8, v: Value) Error!pb.InputRequest {
    const o = try asObject(cx, v, "an input request");
    try checkKeys(cx, o, &.{ "method", "params" }, "an input request");
    const method = try reqString(cx, o, "method", "an input request");
    const params = field(o, "params");
    if (std.mem.eql(u8, method, "elicitation/create")) {
        return .{ .elicit_request = try elicitToPb(cx, key, params orelse return cx.fail(error.Invalid, "an elicitation request has no params", .{})) };
    }
    if (std.mem.eql(u8, method, "sampling/createMessage")) {
        return .{ .sampling_create_message = try samplingRequestToPb(cx, params orelse return cx.fail(error.Invalid, "a sampling request has no params", .{})) };
    }
    if (std.mem.eql(u8, method, "roots/list")) {
        if (params) |p| if ((try asObject(cx, p, "the params of roots/list")).count() > 0) return cx.fail(error.Unexpressible, "the params of a roots/list input request", .{});
        return .{ .list_roots_request = .{} };
    }
    return cx.fail(error.Unexpressible, "an input request of the method {s}", .{method});
}

fn inputRequestsJson(cx: *Context, entries: []const pb.InputRequestEntry) Error!Value {
    var obj: Obj = .{ .cx = cx };
    for (entries) |e| try obj.put(e.key, try inputRequestJson(cx, e.value orelse return cx.fail(error.Invalid, "the input request {s} is empty", .{e.key})));
    return obj.value();
}

fn inputRequestJson(cx: *Context, r: pb.InputRequest) Error!Value {
    const kinds = @intFromBool(r.elicit_request != null) + @intFromBool(r.sampling_create_message != null) + @intFromBool(r.list_roots_request != null);
    if (kinds != 1) return cx.fail(error.Invalid, "an input request with {d} kinds", .{kinds});
    var obj: Obj = .{ .cx = cx };
    if (r.elicit_request) |e| {
        try obj.putString("method", "elicitation/create");
        try obj.put("params", try elicitJson(cx, e));
    } else if (r.sampling_create_message) |s| {
        try obj.putString("method", "sampling/createMessage");
        try obj.put("params", try samplingRequestJson(cx, s));
    } else {
        try obj.putString("method", "roots/list");
    }
    return obj.value();
}

fn inputResponsesToPb(cx: *Context, v: Value) Error![]const pb.InputResponseEntry {
    const o = try asObject(cx, v, "inputResponses");
    const out = try cx.arena.alloc(pb.InputResponseEntry, o.count());
    var it = o.iterator();
    var i: usize = 0;
    while (it.next()) |kv| : (i += 1) {
        out[i] = .{ .key = kv.key_ptr.*, .value = try inputResponseToPb(cx, kv.value_ptr.*) };
    }
    return out;
}

/// The keys of an input response tell its kind. `action` marks an elicitation result,
/// `model` a sampling result and `roots` a roots result.
fn inputResponseToPb(cx: *Context, v: Value) Error!pb.InputResponse {
    const o = try asObject(cx, v, "an input response");
    if (o.get("action") != null) {
        try checkKeys(cx, o, &.{ "action", "content" }, "an elicitation result");
        const action = try reqString(cx, o, "action", "an elicitation result");
        const t: pb.ElicitResult.Type = if (std.mem.eql(u8, action, "accept")) .accept else if (std.mem.eql(u8, action, "decline")) .decline else if (std.mem.eql(u8, action, "cancel")) .cancel else return cx.fail(error.Invalid, "the elicitation action {s}", .{action});
        return .{ .elicit_result = .{ .type = t, .content = if (field(o, "content")) |c| try objectValue(cx, c, "the content of an elicitation result") else null } };
    }
    if (o.get("model") != null) {
        try checkKeys(cx, o, &.{ "role", "content", "model", "stopReason" }, "a sampling result");
        return .{ .sampling_create_message_result = .{
            .message = try samplingMessageToPb(cx, o),
            .model = try reqString(cx, o, "model", "a sampling result"),
            .stop_reason = try optString(cx, o, "stopReason", "a sampling result"),
        } };
    }
    if (o.get("roots") != null) {
        try checkKeys(cx, o, &.{"roots"}, "a roots result");
        const items = try asArray(cx, o.get("roots").?, "roots");
        const roots = try cx.arena.alloc(pb.ListRootsResult.Root, items.len);
        for (items, roots) |item, *root| {
            const ro = try asObject(cx, item, "a root");
            try checkKeys(cx, ro, &.{ "uri", "name" }, "a root");
            root.* = .{ .uri = try reqString(cx, ro, "uri", "a root"), .name = try optString(cx, ro, "name", "a root") };
        }
        return .{ .root_list_result = .{ .roots = roots } };
    }
    return cx.fail(error.Unexpressible, "an input response that is not an elicitation, sampling or roots result", .{});
}

fn inputResponsesJson(cx: *Context, entries: []const pb.InputResponseEntry) Error!Value {
    var obj: Obj = .{ .cx = cx };
    for (entries) |e| try obj.put(e.key, try inputResponseJson(cx, e.value orelse return cx.fail(error.Invalid, "the input response {s} is empty", .{e.key})));
    return obj.value();
}

fn inputResponseJson(cx: *Context, r: pb.InputResponse) Error!Value {
    const kinds = @intFromBool(r.elicit_result != null) + @intFromBool(r.sampling_create_message_result != null) + @intFromBool(r.root_list_result != null);
    if (kinds != 1) return cx.fail(error.Invalid, "an input response with {d} kinds", .{kinds});
    var obj: Obj = .{ .cx = cx };
    if (r.elicit_result) |e| {
        try obj.putString("action", switch (e.type) {
            .accept => "accept",
            .decline => "decline",
            .cancel => "cancel",
            else => return cx.fail(error.Invalid, "the elicitation result type {d}", .{@intFromEnum(e.type)}),
        });
        if (e.content) |c| try obj.put("content", c);
    } else if (r.sampling_create_message_result) |s| {
        const m = s.message orelse return cx.fail(error.Invalid, "a sampling result has no message", .{});
        try obj.put("role", try roleJson(cx, m.role));
        try obj.put("content", try samplingContentJson(cx, m));
        try obj.putString("model", s.model);
        try obj.putText("stopReason", s.stop_reason);
    } else {
        const roots = r.root_list_result.?.roots;
        var array: std.json.Array = .init(cx.arena);
        for (roots) |root| {
            var ro: Obj = .{ .cx = cx };
            try ro.putString("uri", root.uri);
            try ro.putText("name", root.name);
            try array.append(ro.value());
        }
        try obj.put("roots", .{ .array = array });
    }
    return obj.value();
}

// -- Sampling ---------------------------------------------------------------------------------

/// A sampling message of MCP: `role` and `content`, one text, image or audio block. A list
/// with one block counts as that block.
fn samplingMessageToPb(cx: *Context, o: ObjectMap) Error!pb.SamplingMessage {
    var content = field(o, "content") orelse return cx.fail(error.Invalid, "a sampling message has no content", .{});
    if (content == .array) {
        if (content.array.items.len != 1) return cx.fail(error.Unexpressible, "a sampling message with {d} content blocks", .{content.array.items.len});
        content = content.array.items[0];
    }
    const c = try contentToPb(cx, content);
    if (c.embedded_resource != null or c.resource_link != null) return cx.fail(error.Invalid, "a sampling message with a resource block", .{});
    return .{
        .role = try roleToPb(cx, field(o, "role") orelse return cx.fail(error.Invalid, "a sampling message has no role", .{})),
        .text = c.text,
        .image = c.image,
        .audio = c.audio,
    };
}

fn samplingContentJson(cx: *Context, m: pb.SamplingMessage) Error!Value {
    return contentJson(cx, .{ .text = m.text, .image = m.image, .audio = m.audio });
}

fn samplingRequestToPb(cx: *Context, v: Value) Error!pb.SamplingCreateMessageRequest {
    const o = try asObject(cx, v, "sampling params");
    try checkKeys(cx, o, &.{ "messages", "modelPreferences", "systemPrompt", "includeContext", "temperature", "maxTokens", "stopSequences" }, "sampling params");
    var out: pb.SamplingCreateMessageRequest = .{ .system_prompt = try optString(cx, o, "systemPrompt", "sampling params") };
    const items = try asArray(cx, field(o, "messages") orelse return cx.fail(error.Invalid, "sampling params have no messages", .{}), "sampling messages");
    const messages = try cx.arena.alloc(pb.SamplingMessage, items.len);
    for (items, messages) |item, *m| {
        const mo = try asObject(cx, item, "a sampling message");
        try checkKeys(cx, mo, &.{ "role", "content" }, "a sampling message");
        m.* = try samplingMessageToPb(cx, mo);
    }
    out.messages = messages;
    if (field(o, "modelPreferences")) |p| {
        const po = try asObject(cx, p, "model preferences");
        try checkKeys(cx, po, &.{ "hints", "costPriority", "speedPriority", "intelligencePriority" }, "model preferences");
        var prefs: pb.SamplingCreateMessageRequest.ModelPreferences = .{};
        if (field(po, "hints")) |h| {
            const hint_items = try asArray(cx, h, "model hints");
            const hints = try cx.arena.alloc(pb.SamplingCreateMessageRequest.ModelHint, hint_items.len);
            for (hint_items, hints) |item, *hint| {
                const ho = try asObject(cx, item, "a model hint");
                try checkKeys(cx, ho, &.{"name"}, "a model hint");
                hint.* = .{ .name = try optString(cx, ho, "name", "a model hint") };
            }
            prefs.hints = hints;
        }
        if (field(po, "costPriority")) |n| prefs.cost_priority = try f32From(cx, n, "costPriority");
        if (field(po, "speedPriority")) |n| prefs.speed_priority = try f32From(cx, n, "speedPriority");
        if (field(po, "intelligencePriority")) |n| prefs.intelligence_priority = try f32From(cx, n, "intelligencePriority");
        out.model_preferences = prefs;
    }
    if (field(o, "includeContext")) |ic| {
        const s = try asString(cx, ic, "includeContext");
        out.include_context = if (std.mem.eql(u8, s, "none")) .none else if (std.mem.eql(u8, s, "thisServer")) .this_server else if (std.mem.eql(u8, s, "allServers")) .all_servers else return cx.fail(error.Invalid, "the includeContext value {s}", .{s});
    }
    if (field(o, "temperature")) |t| out.temperature = try f32From(cx, t, "temperature");
    const max_tokens = try asInt(cx, field(o, "maxTokens") orelse return cx.fail(error.Invalid, "sampling params have no maxTokens", .{}), "maxTokens");
    out.max_tokens = std.math.cast(i32, max_tokens) orelse return cx.fail(error.Unexpressible, "maxTokens {d} outside the range of a 32-bit integer", .{max_tokens});
    if (field(o, "stopSequences")) |s| out.stop_sequence = try stringList(cx, s, "stopSequences");
    return out;
}

fn samplingRequestJson(cx: *Context, s: pb.SamplingCreateMessageRequest) Error!Value {
    var obj: Obj = .{ .cx = cx };
    var messages: std.json.Array = .init(cx.arena);
    for (s.messages) |m| {
        var mo: Obj = .{ .cx = cx };
        try mo.put("role", try roleJson(cx, m.role));
        try mo.put("content", try samplingContentJson(cx, m));
        try messages.append(mo.value());
    }
    try obj.put("messages", .{ .array = messages });
    if (s.model_preferences) |p| {
        var po: Obj = .{ .cx = cx };
        if (p.hints.len > 0) {
            var hints: std.json.Array = .init(cx.arena);
            for (p.hints) |h| {
                var ho: Obj = .{ .cx = cx };
                try ho.putText("name", h.name);
                try hints.append(ho.value());
            }
            try po.put("hints", .{ .array = hints });
        }
        if (p.cost_priority) |n| try po.put("costPriority", try f32Json(cx, n));
        if (p.speed_priority) |n| try po.put("speedPriority", try f32Json(cx, n));
        if (p.intelligence_priority) |n| try po.put("intelligencePriority", try f32Json(cx, n));
        try obj.put("modelPreferences", po.value());
    }
    try obj.putText("systemPrompt", s.system_prompt);
    switch (s.include_context) {
        .none => {},
        .this_server => try obj.putString("includeContext", "thisServer"),
        .all_servers => try obj.putString("includeContext", "allServers"),
        _ => return cx.fail(error.Invalid, "the includeContext value {d}", .{@intFromEnum(s.include_context)}),
    }
    if (s.temperature) |t| try obj.put("temperature", try f32Json(cx, t));
    try obj.put("maxTokens", .{ .integer = s.max_tokens });
    if (s.stop_sequence.len > 0) try obj.put("stopSequences", try stringArray(cx, s.stop_sequence));
    return obj.value();
}

// -- Elicitation ------------------------------------------------------------------------------

/// The parameters of an elicitation. A URL elicitation puts the key of the input request in
/// `UrlMode.id`.
fn elicitToPb(cx: *Context, key: []const u8, v: Value) Error!pb.ElicitRequest {
    const o = try asObject(cx, v, "elicitation params");
    const mode = try optString(cx, o, "mode", "elicitation params");
    if (std.mem.eql(u8, mode, "url")) {
        try checkKeys(cx, o, &.{ "mode", "message", "url" }, "URL elicitation params");
        return .{
            .message = try reqString(cx, o, "message", "elicitation params"),
            .url_mode = .{ .id = key, .url = try reqString(cx, o, "url", "URL elicitation params") },
        };
    }
    if (mode.len > 0 and !std.mem.eql(u8, mode, "form")) return cx.fail(error.Invalid, "the elicitation mode {s}", .{mode});
    try checkKeys(cx, o, &.{ "mode", "message", "requestedSchema" }, "form elicitation params");
    const schema = try asObject(cx, field(o, "requestedSchema") orelse return cx.fail(error.Invalid, "form elicitation params have no requestedSchema", .{}), "requestedSchema");
    try checkKeys(cx, schema, &.{ "type", "properties", "required" }, "requestedSchema");
    if (field(schema, "type")) |t| if (!std.mem.eql(u8, try asString(cx, t, "requestedSchema.type"), "object")) return cx.fail(error.Invalid, "requestedSchema.type is not object", .{});
    var out: pb.ElicitRequest = .{ .message = try reqString(cx, o, "message", "elicitation params") };
    if (field(schema, "properties")) |p| {
        const props = try asObject(cx, p, "requestedSchema.properties");
        const entries = try cx.arena.alloc(pb.SchemaEntry, props.count());
        var it = props.iterator();
        var i: usize = 0;
        while (it.next()) |kv| : (i += 1) entries[i] = .{ .key = kv.key_ptr.*, .value = try primitiveToPb(cx, kv.value_ptr.*) };
        out.requested_schema = entries;
    }
    if (field(schema, "required")) |r| out.required_fields = try stringList(cx, r, "requestedSchema.required");
    return out;
}

fn elicitJson(cx: *Context, e: pb.ElicitRequest) Error!Value {
    var obj: Obj = .{ .cx = cx };
    if (e.url_mode) |u| {
        try obj.putString("mode", "url");
        try obj.putString("message", e.message);
        try obj.putString("url", u.url);
        return obj.value();
    }
    try obj.putString("message", e.message);
    var schema: Obj = .{ .cx = cx };
    try schema.putString("type", "object");
    var props: Obj = .{ .cx = cx };
    for (e.requested_schema) |entry| {
        try props.put(entry.key, try primitiveJson(cx, entry.value orelse return cx.fail(error.Invalid, "the schema of {s} is empty", .{entry.key})));
    }
    try schema.put("properties", props.value());
    if (e.required_fields.len > 0) try schema.put("required", try stringArray(cx, e.required_fields));
    try obj.put("requestedSchema", schema.value());
    return obj.value();
}

const Prim = pb.PrimitiveSchemaDefinition;

fn primitiveToPb(cx: *Context, v: Value) Error!Prim {
    const o = try asObject(cx, v, "a property schema");
    const t = try reqString(cx, o, "type", "a property schema");
    const title = try optString(cx, o, "title", "a property schema");
    const description = try optString(cx, o, "description", "a property schema");
    const default = field(o, "default");
    if (std.mem.eql(u8, t, "boolean")) {
        try checkKeys(cx, o, &.{ "type", "title", "description", "default" }, "a boolean schema");
        return .{ .boolean_schema = .{ .title = title, .description = description, .default = if (default) |d| try asBool(cx, d, "a boolean default") else false } };
    }
    if (std.mem.eql(u8, t, "number") or std.mem.eql(u8, t, "integer")) {
        try checkKeys(cx, o, &.{ "type", "title", "description", "minimum", "maximum", "default" }, "a number schema");
        var n: Prim.NumberSchema = .{ .title = title, .description = description };
        if (std.mem.eql(u8, t, "integer")) {
            // The range message is present, also without bounds: it marks the type integer.
            n.integer_range = .{
                .minimum = if (field(o, "minimum")) |m| try asInt(cx, m, "an integer minimum") else null,
                .maximum = if (field(o, "maximum")) |m| try asInt(cx, m, "an integer maximum") else null,
            };
            if (default) |d| n.default_integer = try asInt(cx, d, "an integer default");
        } else {
            n.double_range = .{
                .minimum = if (field(o, "minimum")) |m| try asNumber(cx, m, "a minimum") else null,
                .maximum = if (field(o, "maximum")) |m| try asNumber(cx, m, "a maximum") else null,
            };
            if (default) |d| n.default_number = try asNumber(cx, d, "a number default");
        }
        return .{ .number_schema = n };
    }
    if (std.mem.eql(u8, t, "array")) {
        try checkKeys(cx, o, &.{ "type", "title", "description", "minItems", "maxItems", "items", "default" }, "a multi-select enum schema");
        const items = try asObject(cx, field(o, "items") orelse return cx.fail(error.Invalid, "a multi-select enum schema has no items", .{}), "items");
        var e: Prim.EnumSchema = .{ .title = title, .description = description };
        if (items.get("anyOf")) |any_of| {
            try checkKeys(cx, items, &.{"anyOf"}, "the items of a titled multi-select enum");
            try titledOptions(cx, any_of, &e);
        } else {
            try checkKeys(cx, items, &.{ "type", "enum" }, "the items of a multi-select enum");
            if (field(items, "type")) |it| if (!std.mem.eql(u8, try asString(cx, it, "items.type"), "string")) return cx.fail(error.Unexpressible, "a multi-select enum of a type other than string", .{});
            e.enum_list = try stringList(cx, items.get("enum") orelse return cx.fail(error.Invalid, "a multi-select enum has no enum", .{}), "enum");
        }
        e.multi_select = .{
            .default_items = if (default) |d| try stringList(cx, d, "a multi-select default") else &.{},
            .min_items = if (field(o, "minItems")) |m| try u32From(cx, m, "minItems") else null,
            .max_items = if (field(o, "maxItems")) |m| try u32From(cx, m, "maxItems") else null,
        };
        return .{ .enum_schema = e };
    }
    if (!std.mem.eql(u8, t, "string")) return cx.fail(error.Unexpressible, "a property schema of the type {s}", .{t});
    if (o.get("oneOf") != null or o.get("enum") != null) {
        var e: Prim.EnumSchema = .{ .title = title, .description = description };
        if (o.get("oneOf")) |one_of| {
            try checkKeys(cx, o, &.{ "type", "title", "description", "oneOf", "default" }, "a titled enum schema");
            try titledOptions(cx, one_of, &e);
        } else {
            try checkKeys(cx, o, &.{ "type", "title", "description", "enum", "enumNames", "default" }, "an enum schema");
            e.enum_list = try stringList(cx, o.get("enum").?, "enum");
            if (field(o, "enumNames")) |names| {
                e.enum_names = try stringList(cx, names, "enumNames");
                if (e.enum_names.len != e.enum_list.len) return cx.fail(error.Invalid, "enumNames and enum have different lengths", .{});
            }
        }
        e.single_select = .{ .default_item = if (default) |d| try asString(cx, d, "an enum default") else null };
        return .{ .enum_schema = e };
    }
    try checkKeys(cx, o, &.{ "type", "title", "description", "minLength", "maxLength", "format", "default" }, "a string schema");
    var s: Prim.StringSchema = .{ .title = title, .description = description };
    if (field(o, "minLength")) |m| s.min_length = try u64From(cx, m, "minLength");
    if (field(o, "maxLength")) |m| s.max_length = try u64From(cx, m, "maxLength");
    if (field(o, "format")) |f| {
        const format = try asString(cx, f, "format");
        s.format = if (std.mem.eql(u8, format, "email")) .email else if (std.mem.eql(u8, format, "uri")) .uri else if (std.mem.eql(u8, format, "date")) .date else if (std.mem.eql(u8, format, "date-time")) .date_time else return cx.fail(error.Unexpressible, "the string format {s}", .{format});
    }
    if (default) |d| s.default_value = try asString(cx, d, "a string default");
    return .{ .string_schema = s };
}

/// `oneOf` or `anyOf` options with `const` and `title`.
fn titledOptions(cx: *Context, v: Value, e: *Prim.EnumSchema) Error!void {
    const options = try asArray(cx, v, "enum options");
    const values = try cx.arena.alloc([]const u8, options.len);
    const names = try cx.arena.alloc([]const u8, options.len);
    for (options, values, names) |option, *value, *name| {
        const oo = try asObject(cx, option, "an enum option");
        try checkKeys(cx, oo, &.{ "const", "title" }, "an enum option");
        value.* = try reqString(cx, oo, "const", "an enum option");
        name.* = try reqString(cx, oo, "title", "an enum option");
    }
    e.enum_list = values;
    e.enum_names = names;
}

fn primitiveJson(cx: *Context, p: Prim) Error!Value {
    const kinds = @intFromBool(p.string_schema != null) + @intFromBool(p.number_schema != null) + @intFromBool(p.boolean_schema != null) + @intFromBool(p.enum_schema != null);
    if (kinds != 1) return cx.fail(error.Invalid, "a property schema with {d} kinds", .{kinds});
    var obj: Obj = .{ .cx = cx };
    if (p.string_schema) |s| {
        try obj.putString("type", "string");
        try obj.putText("title", s.title);
        try obj.putText("description", s.description);
        if (s.min_length) |m| try obj.put("minLength", .{ .integer = std.math.cast(i64, m) orelse return cx.fail(error.Invalid, "minLength above 2^63", .{}) });
        if (s.max_length) |m| try obj.put("maxLength", .{ .integer = std.math.cast(i64, m) orelse return cx.fail(error.Invalid, "maxLength above 2^63", .{}) });
        switch (s.format) {
            .unknown => {},
            .email => try obj.putString("format", "email"),
            .uri => try obj.putString("format", "uri"),
            .date => try obj.putString("format", "date"),
            .date_time => try obj.putString("format", "date-time"),
            _ => return cx.fail(error.Invalid, "the string format {d}", .{@intFromEnum(s.format)}),
        }
        if (s.default_value) |d| try obj.putString("default", d);
    } else if (p.number_schema) |n| {
        const integer = n.integer_range != null;
        try obj.putString("type", if (integer) "integer" else "number");
        try obj.putText("title", n.title);
        try obj.putText("description", n.description);
        if (n.integer_range) |r| {
            if (r.minimum) |m| try obj.put("minimum", .{ .integer = m });
            if (r.maximum) |m| try obj.put("maximum", .{ .integer = m });
        } else if (n.double_range) |r| {
            if (r.minimum) |m| try obj.put("minimum", try f64Json(cx, m));
            if (r.maximum) |m| try obj.put("maximum", try f64Json(cx, m));
        }
        if (n.default_integer) |d| {
            try obj.put("default", .{ .integer = d });
        } else if (n.default_number) |d| {
            try obj.put("default", try f64Json(cx, d));
        }
    } else if (p.boolean_schema) |b| {
        try obj.putString("type", "boolean");
        try obj.putText("title", b.title);
        try obj.putText("description", b.description);
        if (b.default) try obj.put("default", .{ .bool = true });
    } else {
        const e = p.enum_schema.?;
        if (e.enum_names.len > 0 and e.enum_names.len != e.enum_list.len) return cx.fail(error.Invalid, "enum_names and enum_list have different lengths", .{});
        const titled = e.enum_names.len > 0;
        if (e.multi_select) |m| {
            try obj.putString("type", "array");
            try obj.putText("title", e.title);
            try obj.putText("description", e.description);
            if (m.min_items) |n| try obj.put("minItems", .{ .integer = n });
            if (m.max_items) |n| try obj.put("maxItems", .{ .integer = n });
            var items: Obj = .{ .cx = cx };
            if (titled) {
                try items.put("anyOf", try optionsJson(cx, e));
            } else {
                try items.putString("type", "string");
                try items.put("enum", try stringArray(cx, e.enum_list));
            }
            try obj.put("items", items.value());
            if (m.default_items.len > 0) try obj.put("default", try stringArray(cx, m.default_items));
        } else {
            try obj.putString("type", "string");
            try obj.putText("title", e.title);
            try obj.putText("description", e.description);
            if (titled) {
                try obj.put("oneOf", try optionsJson(cx, e));
            } else {
                try obj.put("enum", try stringArray(cx, e.enum_list));
            }
            if (e.single_select) |s| if (s.default_item) |d| try obj.putString("default", d);
        }
    }
    return obj.value();
}

fn optionsJson(cx: *Context, e: Prim.EnumSchema) Error!Value {
    var array: std.json.Array = .init(cx.arena);
    for (e.enum_list, e.enum_names) |value, name| {
        var oo: Obj = .{ .cx = cx };
        try oo.putString("const", value);
        try oo.putString("title", name);
        try array.append(oo.value());
    }
    return .{ .array = array };
}

// -- Requests ---------------------------------------------------------------------------------

fn requestFieldsToPb(cx: *Context, o: ObjectMap) Error!?pb.RequestFields {
    var c: pb.RequestFields = .{};
    var any = false;
    if (try metaOf(cx, o)) |m| {
        c.metadata = m;
        any = true;
    }
    if (field(o, "inputResponses")) |ir| {
        c.input_responses = try inputResponsesToPb(cx, ir);
        any = true;
    }
    if (field(o, "requestState")) |rs| {
        c.request_state = try asString(cx, rs, "requestState");
        any = true;
    }
    return if (any) c else null;
}

fn paramsToPb(cx: *Context, comptime rpc: Rpc, params: Value) Error!rpc.Request() {
    const o = try asObject(cx, params, "params");
    const common = try requestFieldsToPb(cx, o);
    switch (rpc) {
        .list_resources, .list_resource_templates, .list_prompts, .list_tools => {
            try checkKeys(cx, o, &.{ "_meta", "inputResponses", "requestState", "cursor" }, "the params of " ++ rpc.method());
            if (field(o, "cursor")) |c| if ((try asString(cx, c, "cursor")).len > 0) return cx.fail(error.Unexpressible, "a cursor: the typed binding has no pagination", .{});
            return .{ .common = common };
        },
        .read_resource => {
            try checkKeys(cx, o, &.{ "_meta", "inputResponses", "requestState", "uri" }, "the params of resources/read");
            return .{ .common = common, .uri = try reqString(cx, o, "uri", "the params of resources/read") };
        },
        .get_prompt => {
            try checkKeys(cx, o, &.{ "_meta", "inputResponses", "requestState", "name", "arguments" }, "the params of prompts/get");
            return .{
                .common = common,
                .name = try reqString(cx, o, "name", "the params of prompts/get"),
                .arguments = if (field(o, "arguments")) |a| try stringEntries(cx, a, "prompt arguments") else &.{},
            };
        },
        .call_tool => {
            try checkKeys(cx, o, &.{ "_meta", "inputResponses", "requestState", "name", "arguments" }, "the params of tools/call");
            return .{ .common = common, .request = .{
                .name = try reqString(cx, o, "name", "the params of tools/call"),
                .arguments = if (field(o, "arguments")) |a| try objectValue(cx, a, "tool arguments") else null,
            } };
        },
        .complete => {
            try checkKeys(cx, o, &.{ "_meta", "inputResponses", "requestState", "ref", "argument", "context" }, "the params of completion/complete");
            var out: pb.CompletionRequest = .{ .common = common };
            const ref = try asObject(cx, field(o, "ref") orelse return cx.fail(error.Invalid, "a completion request has no ref", .{}), "ref");
            const ref_type = try reqString(cx, ref, "type", "ref");
            if (std.mem.eql(u8, ref_type, "ref/prompt")) {
                try checkKeys(cx, ref, &.{ "type", "name", "title" }, "a prompt reference");
                out.prompt_reference = .{ .name = try reqString(cx, ref, "name", "a prompt reference"), .title = try optString(cx, ref, "title", "a prompt reference") };
            } else if (std.mem.eql(u8, ref_type, "ref/resource")) {
                try checkKeys(cx, ref, &.{ "type", "uri" }, "a resource reference");
                out.resource_reference = .{ .uri = try reqString(cx, ref, "uri", "a resource reference") };
            } else return cx.fail(error.Invalid, "the reference type {s}", .{ref_type});
            const arg = try asObject(cx, field(o, "argument") orelse return cx.fail(error.Invalid, "a completion request has no argument", .{}), "argument");
            try checkKeys(cx, arg, &.{ "name", "value" }, "a completion argument");
            out.argument = .{ .name = try reqString(cx, arg, "name", "a completion argument"), .value = try reqString(cx, arg, "value", "a completion argument") };
            if (field(o, "context")) |c| {
                const co = try asObject(cx, c, "context");
                try checkKeys(cx, co, &.{"arguments"}, "a completion context");
                out.context = .{ .arguments = if (field(co, "arguments")) |a| try stringEntries(cx, a, "context arguments") else &.{} };
            }
            return out;
        },
    }
}

fn stringEntries(cx: *Context, v: Value, comptime what: []const u8) Error![]const pb.StringEntry {
    const o = try asObject(cx, v, what);
    const out = try cx.arena.alloc(pb.StringEntry, o.count());
    var it = o.iterator();
    var i: usize = 0;
    while (it.next()) |kv| : (i += 1) out[i] = .{ .key = kv.key_ptr.*, .value = try asString(cx, kv.value_ptr.*, "a value of " ++ what) };
    return out;
}

fn stringEntriesJson(cx: *Context, entries: []const pb.StringEntry) Error!Value {
    var obj: Obj = .{ .cx = cx };
    for (entries) |e| try obj.putString(e.key, e.value);
    return obj.value();
}

fn requestToJson(cx: *Context, comptime rpc: Rpc, msg: rpc.Request()) Error!Value {
    var obj: Obj = .{ .cx = cx };
    if (msg.common) |c| {
        try obj.putMeta(c.metadata);
        if (c.input_responses.len > 0) try obj.put("inputResponses", try inputResponsesJson(cx, c.input_responses));
        if (c.request_state) |rs| try obj.putString("requestState", rs);
    }
    switch (rpc) {
        .list_resources, .list_resource_templates, .list_prompts, .list_tools => {},
        .read_resource => {
            if (msg.uri.len == 0) return cx.fail(error.Invalid, "Missing resource URI", .{});
            try obj.putString("uri", msg.uri);
        },
        .get_prompt => {
            if (msg.name.len == 0) return cx.fail(error.Invalid, "Missing prompt name", .{});
            try obj.putString("name", msg.name);
            if (msg.arguments.len > 0) try obj.put("arguments", try stringEntriesJson(cx, msg.arguments));
        },
        .call_tool => {
            const request = msg.request orelse return cx.fail(error.Invalid, "Missing tool name", .{});
            if (request.name.len == 0) return cx.fail(error.Invalid, "Missing tool name", .{});
            try obj.putString("name", request.name);
            if (request.arguments) |a| try obj.put("arguments", a);
        },
        .complete => {
            var ref: Obj = .{ .cx = cx };
            if (msg.resource_reference != null and msg.prompt_reference != null) return cx.fail(error.Invalid, "A completion request has two references", .{});
            if (msg.prompt_reference) |p| {
                try ref.putString("type", "ref/prompt");
                try ref.putString("name", p.name);
                try ref.putText("title", p.title);
            } else if (msg.resource_reference) |r| {
                try ref.putString("type", "ref/resource");
                try ref.putString("uri", r.uri);
            } else return cx.fail(error.Invalid, "A completion request has no reference", .{});
            try obj.put("ref", ref.value());
            const arg = msg.argument orelse return cx.fail(error.Invalid, "A completion request has no argument", .{});
            var ao: Obj = .{ .cx = cx };
            try ao.putString("name", arg.name);
            try ao.putString("value", arg.value);
            try obj.put("argument", ao.value());
            if (msg.context) |c| {
                var co: Obj = .{ .cx = cx };
                if (c.arguments.len > 0) try co.put("arguments", try stringEntriesJson(cx, c.arguments));
                try obj.put("context", co.value());
            }
        },
    }
    return obj.value();
}

// -- Results ----------------------------------------------------------------------------------

fn listOf(cx: *Context, o: ObjectMap, comptime key: []const u8, comptime T: type, comptime convert: fn (*Context, Value) Error!T) Error![]const T {
    const items = try asArray(cx, field(o, key) orelse return cx.fail(error.Invalid, "the result has no " ++ key, .{}), key);
    const out = try cx.arena.alloc(T, items.len);
    for (items, out) |item, *x| x.* = try convert(cx, item);
    return out;
}

fn resourceValueToPb(cx: *Context, v: Value) Error!pb.Resource {
    return resourceToPb(cx, try asObject(cx, v, "a resource"), false);
}

fn resultToPb(cx: *Context, comptime rpc: Rpc, result: Value) Error!rpc.Response() {
    const o = try asObject(cx, result, "the result");
    const result_type = if (field(o, "resultType")) |t| try asString(cx, t, "resultType") else "complete";
    var common: pb.ResponseFields = .{ .result_type = .complete, .metadata = try metaOf(cx, o) };
    if (std.mem.eql(u8, result_type, "input_required")) {
        try checkKeys(cx, o, &.{ "_meta", "resultType", "inputRequests", "requestState" }, "an input required result");
        common.result_type = .input_required;
        if (field(o, "inputRequests")) |ir| common.input_requests = try inputRequestsToPb(cx, ir);
        if (field(o, "requestState")) |rs| common.request_state = try asString(cx, rs, "requestState");
        return .{ .common = common };
    }
    if (!std.mem.eql(u8, result_type, "complete")) return cx.fail(error.Unexpressible, "a result of the type {s}", .{result_type});
    switch (rpc) {
        .list_tools => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "ttlMs", "cacheScope", "tools" }, "the tools/list result");
            return .{ .common = common, .tools = try listOf(cx, o, "tools", pb.Tool, toolToPb), .ttl = try ttlToPb(cx, o), .cache_scope = try cacheScopeToPb(cx, o) };
        },
        .list_resources => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "ttlMs", "cacheScope", "resources" }, "the resources/list result");
            return .{ .common = common, .resources = try listOf(cx, o, "resources", pb.Resource, resourceValueToPb), .ttl = try ttlToPb(cx, o), .cache_scope = try cacheScopeToPb(cx, o) };
        },
        .list_resource_templates => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "ttlMs", "cacheScope", "resourceTemplates" }, "the resources/templates/list result");
            return .{ .common = common, .resource_templates = try listOf(cx, o, "resourceTemplates", pb.ResourceTemplate, templateToPb), .ttl = try ttlToPb(cx, o), .cache_scope = try cacheScopeToPb(cx, o) };
        },
        .list_prompts => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "ttlMs", "cacheScope", "prompts" }, "the prompts/list result");
            return .{ .common = common, .prompts = try listOf(cx, o, "prompts", pb.Prompt, promptToPb), .ttl = try ttlToPb(cx, o), .cache_scope = try cacheScopeToPb(cx, o) };
        },
        .read_resource => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "ttlMs", "cacheScope", "contents" }, "the resources/read result");
            return .{ .common = common, .resource = try listOf(cx, o, "contents", pb.ResourceContents, resourceContentsToPb), .ttl = try ttlToPb(cx, o), .cache_scope = try cacheScopeToPb(cx, o) };
        },
        .get_prompt => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "description", "messages" }, "the prompts/get result");
            return .{ .common = common, .description = try optString(cx, o, "description", "the prompts/get result"), .messages = try listOf(cx, o, "messages", pb.PromptMessage, promptMessageToPb) };
        },
        .call_tool => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "content", "structuredContent", "isError" }, "the tools/call result");
            var out: pb.CallToolResponse = .{ .common = common, .content = try listOf(cx, o, "content", Content, contentToPb) };
            if (field(o, "structuredContent")) |s| {
                if (s != .object) return cx.fail(error.Unexpressible, "structuredContent that is not a JSON object", .{});
                out.structured_content = s;
            }
            if (field(o, "isError")) |e| out.is_error = try asBool(cx, e, "isError");
            return out;
        },
        .complete => {
            try checkKeys(cx, o, &.{ "_meta", "resultType", "completion" }, "the completion/complete result");
            const c = try asObject(cx, field(o, "completion") orelse return cx.fail(error.Invalid, "the result has no completion", .{}), "completion");
            try checkKeys(cx, c, &.{ "values", "total", "hasMore" }, "a completion");
            return .{
                .common = common,
                .values = try stringList(cx, field(c, "values") orelse return cx.fail(error.Invalid, "a completion has no values", .{}), "completion values"),
                .total_matches = if (field(c, "total")) |t| try asInt(cx, t, "completion total") else null,
                .has_more = if (field(c, "hasMore")) |h| try asBool(cx, h, "hasMore") else false,
            };
        },
    }
}

fn responseToJson(cx: *Context, comptime rpc: Rpc, msg: rpc.Response()) Error!Value {
    var obj: Obj = .{ .cx = cx };
    const common = msg.common orelse pb.ResponseFields{};
    switch (common.result_type) {
        // An unset result type counts as complete.
        .unspecified, .complete => {},
        .input_required => {
            try obj.putString("resultType", "input_required");
            try obj.putMeta(common.metadata);
            if (common.input_requests.len > 0) try obj.put("inputRequests", try inputRequestsJson(cx, common.input_requests));
            if (common.request_state) |rs| try obj.putString("requestState", rs);
            return obj.value();
        },
        _ => return cx.fail(error.Invalid, "the result type {d}", .{@intFromEnum(common.result_type)}),
    }
    try obj.putString("resultType", "complete");
    try obj.putMeta(common.metadata);
    switch (rpc) {
        .list_tools => {
            var array: std.json.Array = .init(cx.arena);
            for (msg.tools) |t| try array.append(try toolJson(cx, t));
            try obj.put("tools", .{ .array = array });
            try putCache(&obj, msg.ttl, msg.cache_scope);
        },
        .list_resources => {
            var array: std.json.Array = .init(cx.arena);
            for (msg.resources) |r| try array.append(try resourceJson(cx, r, false));
            try obj.put("resources", .{ .array = array });
            try putCache(&obj, msg.ttl, msg.cache_scope);
        },
        .list_resource_templates => {
            var array: std.json.Array = .init(cx.arena);
            for (msg.resource_templates) |t| try array.append(try templateJson(cx, t));
            try obj.put("resourceTemplates", .{ .array = array });
            try putCache(&obj, msg.ttl, msg.cache_scope);
        },
        .list_prompts => {
            var array: std.json.Array = .init(cx.arena);
            for (msg.prompts) |p| try array.append(try promptJson(cx, p));
            try obj.put("prompts", .{ .array = array });
            try putCache(&obj, msg.ttl, msg.cache_scope);
        },
        .read_resource => {
            var array: std.json.Array = .init(cx.arena);
            for (msg.resource) |c| try array.append(try resourceContentsJson(cx, c));
            try obj.put("contents", .{ .array = array });
            try putCache(&obj, msg.ttl, msg.cache_scope);
        },
        .get_prompt => {
            try obj.putText("description", msg.description);
            var array: std.json.Array = .init(cx.arena);
            for (msg.messages) |m| try array.append(try promptMessageJson(cx, m));
            try obj.put("messages", .{ .array = array });
        },
        .call_tool => {
            var array: std.json.Array = .init(cx.arena);
            for (msg.content) |c| try array.append(try contentJson(cx, c));
            try obj.put("content", .{ .array = array });
            if (msg.structured_content) |s| try obj.put("structuredContent", s);
            if (msg.is_error) try obj.put("isError", .{ .bool = true });
        },
        .complete => {
            var c: Obj = .{ .cx = cx };
            try c.put("values", try stringArray(cx, msg.values));
            if (msg.total_matches) |t| try c.put("total", .{ .integer = t });
            if (msg.has_more) try c.put("hasMore", .{ .bool = true });
            try obj.put("completion", c.value());
        },
    }
    return obj.value();
}

// -- Tests ------------------------------------------------------------------------------------

/// JSON equality: objects without regard to key order, numbers by value.
fn jsonEql(a: Value, b: Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |x| return b == .bool and b.bool == x,
        .integer, .float, .number_string => {
            const x = numberOf(a) orelse return false;
            const y = numberOf(b) orelse return false;
            return x == y;
        },
        .string => |s| return b == .string and std.mem.eql(u8, s, b.string),
        .array => |x| {
            if (b != .array or b.array.items.len != x.items.len) return false;
            for (x.items, b.array.items) |p, q| if (!jsonEql(p, q)) return false;
            return true;
        },
        .object => |x| {
            if (b != .object or b.object.count() != x.count()) return false;
            var it = x.iterator();
            while (it.next()) |kv| {
                const other = b.object.get(kv.key_ptr.*) orelse return false;
                if (!jsonEql(kv.value_ptr.*, other)) return false;
            }
            return true;
        },
    }
}

fn numberOf(v: Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn expectJson(expected: []const u8, actual: Value) !void {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const want = try std.json.parseFromSliceLeaky(Value, arena_state.allocator(), expected, .{});
    if (jsonEql(want, actual)) return;
    const got = try std.json.Stringify.valueAlloc(arena_state.allocator(), actual, .{});
    std.debug.print("\nexpected: {s}\nactual:   {s}\n", .{ expected, got });
    return error.TestExpectedEqual;
}

/// The server encodes a result, the client decodes it. Returns the decoded JSON.
fn resultRoundTrip(arena: Allocator, rpc: Rpc, text: []const u8) !Value {
    const gpa = std.testing.allocator;
    const result = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var server: Context = .{ .arena = arena };
    try encodeResult(&server, gpa, &out, rpc, result);
    var client: Context = .{ .arena = arena };
    return decodeResponse(&client, rpc, try arena.dupe(u8, out.items));
}

/// The client encodes params, the server decodes them. Returns the decoded JSON.
fn paramsRoundTrip(arena: Allocator, rpc: Rpc, text: []const u8) !Value {
    const gpa = std.testing.allocator;
    const params = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var client: Context = .{ .arena = arena };
    try encodeRequest(&client, gpa, &out, rpc, params);
    var server: Context = .{ .arena = arena };
    return decodeRequest(&server, rpc, try arena.dupe(u8, out.items));
}

fn expectResult(rpc: Rpc, text: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try expectJson(text, try resultRoundTrip(arena_state.allocator(), rpc, text));
}

fn expectParams(rpc: Rpc, text: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try expectJson(text, try paramsRoundTrip(arena_state.allocator(), rpc, text));
}

test "results of the list methods survive a round trip" {
    try expectResult(.list_tools,
        \\{"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"s","version":"1"}},"ttlMs":1500,"cacheScope":"public",
        \\"tools":[{"name":"add","title":"Add","description":"Adds","icons":[{"src":"https://x.example/i.png","mimeType":"image/png","sizes":["48x48","any"],"theme":"dark"}],
        \\"inputSchema":{"type":"object","properties":{"a":{"type":"integer","minimum":0},"b":{"type":"number","maximum":2.5}},"required":["a"],"additionalProperties":false},
        \\"outputSchema":{"type":"object","properties":{"sum":{"type":"integer"}}},"annotations":{"title":"T","readOnlyHint":true,"destructiveHint":true,"idempotentHint":true,"openWorldHint":true},"_meta":{"k":"v"}},
        \\{"name":"min","inputSchema":{"type":"object"}}]}
    );
    try expectResult(.list_resources,
        \\{"resultType":"complete","ttlMs":0,"cacheScope":"private","resources":[{"name":"r","title":"R","uri":"test://r","description":"d","mimeType":"text/plain",
        \\"annotations":{"audience":["assistant"],"priority":0.5,"lastModified":"2026-09-30T00:00:00Z"},"size":12,"icons":[{"src":"data:image/png;base64,AA=="}],"_meta":{"x":[1,2]}},{"name":"b","uri":"test://b"}]}
    );
    try expectResult(.list_resource_templates,
        \\{"resultType":"complete","resourceTemplates":[{"name":"t","title":"T","uriTemplate":"test://t/{id}","description":"d","mimeType":"application/json","annotations":{"priority":1},"_meta":{"y":true}}]}
    );
    try expectResult(.list_prompts,
        \\{"resultType":"complete","ttlMs":60000,"prompts":[{"name":"p","title":"P","description":"d","arguments":[{"name":"a","title":"A","description":"first","required":true},{"name":"b"}],"_meta":{"z":null}}]}
    );
}

test "tool results with every content block survive a round trip" {
    const text =
        \\{"resultType":"complete","_meta":{"trace":"t1"},"content":[
        \\{"type":"text","text":"hi","annotations":{"audience":["user","assistant"],"priority":0.3,"lastModified":"2026-01-01T00:00:00Z"},"_meta":{"x":1}},
        \\{"type":"image","data":"iVBORw0KGgo=","mimeType":"image/png","annotations":{"priority":0.75}},
        \\{"type":"audio","data":"UklGRg==","mimeType":"audio/wav","_meta":{"seconds":1.5}},
        \\{"type":"resource","resource":{"uri":"test://e","mimeType":"text/plain","text":"embedded","_meta":{"m":"n"}},"annotations":{"priority":1},"_meta":{"e":1}},
        \\{"type":"resource","resource":{"uri":"test://b","mimeType":"application/octet-stream","blob":"AAEC"}},
        \\{"type":"resource_link","name":"l","uri":"test://l","title":"Link","description":"d","mimeType":"text/html","size":42,"annotations":{"audience":["user"]},"icons":[{"src":"https://x.example/l.svg","theme":"light"}],"_meta":{"l":2}}],
        \\"structuredContent":{"sum":42,"items":[1.5,"x",null,true,{"deep":[[]]}]},"isError":true}
    ;
    try expectResult(.call_tool, text);

    // The bytes fields carry the base64 text, as in the reference transport.
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    var cx: Context = .{ .arena = arena };
    try encodeResult(&cx, std.testing.allocator, &out, .call_tool, try std.json.parseFromSliceLeaky(Value, arena, text, .{}));
    const msg = try codec.decode(pb.CallToolResponse, arena, out.items, .{});
    try std.testing.expectEqualStrings("iVBORw0KGgo=", msg.content[1].image.?.data);
    try std.testing.expectEqualStrings("UklGRg==", msg.content[2].audio.?.data);
    try std.testing.expectEqualStrings("AAEC", msg.content[4].embedded_resource.?.contents.?.blob);
    try std.testing.expectEqual(pb.ResultType.complete, msg.common.?.result_type);
    try std.testing.expect(msg.is_error);
}

test "read, prompt and completion results survive a round trip" {
    try expectResult(.read_resource,
        \\{"resultType":"complete","ttlMs":2001,"cacheScope":"public","contents":[{"uri":"test://t","mimeType":"text/plain","text":"hello"},{"uri":"test://b","mimeType":"image/png","blob":"iVBORw0KGgo=","_meta":{"k":1}},{"uri":"test://empty","text":""}]}
    );
    try expectResult(.get_prompt,
        \\{"resultType":"complete","description":"A prompt","messages":[{"role":"user","content":{"type":"text","text":"Describe"}},{"role":"assistant","content":{"type":"image","data":"AA==","mimeType":"image/png"}},
        \\{"role":"user","content":{"type":"resource","resource":{"uri":"test://r","text":"body"}}},{"role":"user","content":{"type":"resource_link","name":"n","uri":"test://n"}}]}
    );
    try expectResult(.complete,
        \\{"resultType":"complete","completion":{"values":["a","b"],"total":10,"hasMore":true}}
    );
    try expectResult(.complete,
        \\{"resultType":"complete","completion":{"values":[]}}
    );
}

test "input required results survive a round trip" {
    try expectResult(.call_tool,
        \\{"resultType":"input_required","_meta":{"m":1},"requestState":"opaque-state","inputRequests":{
        \\"form":{"method":"elicitation/create","params":{"message":"Who?","requestedSchema":{"type":"object","properties":{
        \\"name":{"type":"string","title":"Name","description":"Your name","minLength":1,"maxLength":40,"format":"email","default":"a@b.example"},
        \\"age":{"type":"integer","minimum":0,"maximum":150,"default":30},
        \\"ratio":{"type":"number","minimum":0.5,"default":1.5},
        \\"plain":{"type":"integer"},
        \\"ok":{"type":"boolean","title":"OK","default":true},
        \\"color":{"type":"string","enum":["red","blue"],"default":"red"},
        \\"size":{"type":"string","title":"Size","oneOf":[{"const":"s","title":"Small"},{"const":"l","title":"Large"}]},
        \\"tags":{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string","enum":["x","y"]},"default":["x"]},
        \\"titled":{"type":"array","items":{"anyOf":[{"const":"p","title":"P"}]}}},"required":["name"]}}},
        \\"link":{"method":"elicitation/create","params":{"mode":"url","message":"Sign in","url":"https://x.example/auth"}},
        \\"sample":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Hi"}},{"role":"assistant","content":{"type":"image","data":"AA==","mimeType":"image/png"}}],
        \\"modelPreferences":{"hints":[{"name":"claude"}],"costPriority":0.25,"speedPriority":0.5,"intelligencePriority":1},"systemPrompt":"Be brief","includeContext":"thisServer","temperature":0.7,"maxTokens":100,"stopSequences":["END"]}},
        \\"roots":{"method":"roots/list"}}}
    );
    try expectResult(.read_resource,
        \\{"resultType":"input_required","requestState":"only-state"}
    );
}

test "params of every method survive a round trip" {
    try expectParams(.list_tools,
        \\{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}},"io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},"progressToken":7}}
    );
    try expectParams(.list_resources, "{}");
    try expectParams(.list_resource_templates, "{\"_meta\":{\"a\":1}}");
    try expectParams(.list_prompts, "{\"_meta\":{}}");
    try expectParams(.read_resource, "{\"_meta\":{\"a\":1},\"uri\":\"test://r\"}");
    try expectParams(.get_prompt, "{\"name\":\"p\",\"arguments\":{\"arg1\":\"x\",\"arg2\":\"\"}}");
    try expectParams(.call_tool,
        \\{"_meta":{"progressToken":"p"},"name":"add","arguments":{"a":1,"b":{"c":[true,null,"s",2.5]}},"requestState":"st",
        \\"inputResponses":{"e":{"action":"accept","content":{"name":"Bob","n":3,"tags":["x"]}},"d":{"action":"decline"},
        \\"s":{"role":"assistant","content":{"type":"text","text":"Paris"},"model":"m1","stopReason":"endTurn"},
        \\"r":{"roots":[{"uri":"file:///a","name":"A"},{"uri":"file:///b"}]}}}
    );
    try expectParams(.call_tool, "{\"name\":\"no_arguments\"}");
    try expectParams(.call_tool, "{\"name\":\"empty_arguments\",\"arguments\":{}}");
    try expectParams(.complete,
        \\{"ref":{"type":"ref/prompt","name":"p","title":"P"},"argument":{"name":"a","value":"x"},"context":{"arguments":{"b":"y"}}}
    );
    try expectParams(.complete,
        \\{"ref":{"type":"ref/resource","uri":"test://t/{id}"},"argument":{"name":"id","value":"1"}}
    );
}

test "a part that the messages cannot carry gives Unexpressible with a reason" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Case = struct { rpc: Rpc, result: bool, text: []const u8, reason: []const u8 };
    const cases = [_]Case{
        .{ .rpc = .call_tool, .result = true, .text = "{\"content\":[],\"structuredContent\":[1,2]}", .reason = "structuredContent that is not a JSON object" },
        .{ .rpc = .call_tool, .result = true, .text = "{\"resultType\":\"task\",\"task\":{}}", .reason = "a result of the type task" },
        .{ .rpc = .list_tools, .result = true, .text = "{\"tools\":[],\"nextCursor\":\"abc\"}", .reason = "the field nextCursor of the tools/list result" },
        .{ .rpc = .list_tools, .result = true, .text = "{\"tools\":[{\"name\":\"t\",\"inputSchema\":{},\"execution\":{}}]}", .reason = "the field execution of a tool" },
        .{ .rpc = .call_tool, .result = true, .text = "{\"content\":[{\"type\":\"tool_use\",\"id\":\"1\",\"name\":\"t\",\"input\":{}}]}", .reason = "a content block of the type tool_use" },
        .{ .rpc = .call_tool, .result = true, .text = "{\"content\":[],\"structuredContent\":{\"n\":9007199254740993}}", .reason = "an integer outside the range from -(2^53) to 2^53 in a JSON value" },
        .{ .rpc = .call_tool, .result = true, .text = "{\"resultType\":\"input_required\",\"inputRequests\":{\"s\":{\"method\":\"sampling/createMessage\",\"params\":{\"messages\":[],\"maxTokens\":1,\"tools\":[]}}}}", .reason = "the field tools of sampling params" },
        .{ .rpc = .call_tool, .result = true, .text = "{\"resultType\":\"input_required\",\"inputRequests\":{\"f\":{\"method\":\"elicitation/create\",\"params\":{\"message\":\"m\",\"requestedSchema\":{\"$schema\":\"x\",\"type\":\"object\",\"properties\":{}}}}}}", .reason = "the field $schema of requestedSchema" },
        .{ .rpc = .list_prompts, .result = false, .text = "{\"cursor\":\"abc\"}", .reason = "a cursor: the typed binding has no pagination" },
        .{ .rpc = .call_tool, .result = false, .text = "{\"name\":\"t\",\"arguments\":{\"big\":-9007199254740993}}", .reason = "an integer outside the range from -(2^53) to 2^53 in a JSON value" },
        .{ .rpc = .call_tool, .result = false, .text = "{\"name\":\"t\",\"inputResponses\":{\"e\":{\"action\":\"accept\",\"_meta\":{}}}}", .reason = "the field _meta of an elicitation result" },
        .{ .rpc = .call_tool, .result = false, .text = "{\"name\":\"t\",\"inputResponses\":{\"s\":{\"role\":\"user\",\"content\":[],\"model\":\"m\"}}}", .reason = "a sampling message with 0 content blocks" },
    };
    for (cases) |c| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(std.testing.allocator);
        var cx: Context = .{ .arena = arena };
        const value = try std.json.parseFromSliceLeaky(Value, arena, c.text, .{});
        const outcome = if (c.result) encodeResult(&cx, std.testing.allocator, &out, c.rpc, value) else encodeRequest(&cx, std.testing.allocator, &out, c.rpc, value);
        try std.testing.expectError(error.Unexpressible, outcome);
        try std.testing.expectEqualStrings(c.reason, cx.reason);
    }
}

test "invalid messages give Invalid with a reason" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var cx: Context = .{ .arena = arena };
    // A tool call without a request, and with an empty name.
    try std.testing.expectError(error.Invalid, decodeRequest(&cx, .call_tool, &.{}));
    try std.testing.expectEqualStrings("Missing tool name", cx.reason);
    try std.testing.expectError(error.Invalid, decodeRequest(&cx, .call_tool, &.{ 0x12, 0x00 }));
    try std.testing.expectError(error.Invalid, decodeRequest(&cx, .read_resource, &.{}));
    try std.testing.expectEqualStrings("Missing resource URI", cx.reason);
    try std.testing.expectError(error.Invalid, decodeRequest(&cx, .get_prompt, &.{}));
    try std.testing.expectError(error.Invalid, decodeRequest(&cx, .complete, &.{ 0x22, 0x00 }));
    try std.testing.expectEqualStrings("A completion request has no reference", cx.reason);
    // A result type that MCP does not have: common = 1 { result_type = 9 7 }.
    try std.testing.expectError(error.Invalid, decodeResponse(&cx, .list_tools, &.{ 0x0a, 0x02, 0x48, 0x07 }));
    // Image data that is not base64 text: content = 2 { image = 2 { data = 1 "!!" } }.
    try std.testing.expectError(error.Invalid, decodeResponse(&cx, .call_tool, &.{ 0x12, 0x06, 0x12, 0x04, 0x0a, 0x02, '!', '!' }));
    try std.testing.expectEqualStrings("the data of an image or audio block is not base64 text", cx.reason);
    // Malformed protobuf is a decode error, not a conversion error.
    try std.testing.expectError(error.Truncated, decodeRequest(&cx, .list_tools, &.{ 0x0a, 0x05 }));
}

test "the lossy parts of the mapping" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // A false hint and the proto3 default are the same: the receiver sees an absent hint.
    try expectJson(
        \\{"resultType":"complete","tools":[{"name":"t","inputSchema":{"type":"object"},"annotations":{}}]}
    , try resultRoundTrip(arena, .list_tools,
        \\{"tools":[{"name":"t","inputSchema":{"type":"object"},"annotations":{"destructiveHint":false,"openWorldHint":false}}]}
    ));
    // An empty blob arrives as an empty text, and a boolean default false as no default.
    try expectJson(
        \\{"resultType":"complete","contents":[{"uri":"test://x","text":""}]}
    , try resultRoundTrip(arena, .read_resource, "{\"contents\":[{\"uri\":\"test://x\",\"blob\":\"\"}]}"));
    // A float priority keeps about seven digits, and the legacy enumNames form arrives as oneOf.
    try expectJson(
        \\{"resultType":"input_required","inputRequests":{"f":{"method":"elicitation/create","params":{"message":"m","requestedSchema":{"type":"object","properties":{
        \\"b":{"type":"boolean"},"e":{"type":"string","oneOf":[{"const":"a","title":"A"}]}}}}}}}
    , try resultRoundTrip(arena, .call_tool,
        \\{"resultType":"input_required","inputRequests":{"f":{"method":"elicitation/create","params":{"mode":"form","message":"m","requestedSchema":{"type":"object","properties":{
        \\"b":{"type":"boolean","default":false},"e":{"type":"string","enum":["a"],"enumNames":["A"]}}}}}}}
    ));
    const priority = try resultRoundTrip(arena, .list_resources, "{\"resources\":[{\"name\":\"n\",\"uri\":\"u\",\"annotations\":{\"priority\":0.123456789}}]}");
    try std.testing.expectEqual(@as(f64, 0.12345679), priority.object.get("resources").?.array.items[0].object.get("annotations").?.object.get("priority").?.float);
}

test "routing metadata of the params" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const tool = route(.call_tool, try std.json.parseFromSliceLeaky(Value, arena, "{\"name\":\"add\"}", .{})).?;
    try std.testing.expectEqualStrings("mcp_tool", tool.header);
    try std.testing.expectEqualStrings("add", tool.value);
    try std.testing.expectEqualStrings("test://r", route(.read_resource, try std.json.parseFromSliceLeaky(Value, arena, "{\"uri\":\"test://r\"}", .{})).?.value);
    try std.testing.expectEqualStrings("mcp_prompt", route(.get_prompt, try std.json.parseFromSliceLeaky(Value, arena, "{\"name\":\"p\"}", .{})).?.header);
    const prompt_ref = route(.complete, try std.json.parseFromSliceLeaky(Value, arena, "{\"ref\":{\"type\":\"ref/prompt\",\"name\":\"p\"}}", .{})).?;
    try std.testing.expectEqualStrings("mcp_resource", prompt_ref.header);
    try std.testing.expectEqualStrings("p", prompt_ref.value);
    try std.testing.expect(route(.list_tools, .{ .object = .empty }) == null);
}
