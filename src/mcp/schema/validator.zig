//! JSON Schema 2020-12 validator over `std.json.Value`.
//!
//! The validator evaluates each keyword of the 2020-12 vocabularies for the core, the
//! applicators, the unevaluated locations and the validation. The keywords of the vocabularies
//! for the format, the content and the meta-data are annotations. The validator keeps them and
//! does not evaluate them. This is the default behavior of 2020-12. Thus `format`,
//! `contentEncoding`, `contentMediaType` and `contentSchema` never make an instance invalid.
//!
//! A document can hold more than one schema resource. The root and each subschema with `$id`
//! start a resource. The compiler resolves `$id`, `$ref` and `$dynamicRef` against the base
//! URI of their resource with the rules of RFC 3986. The base URI of a root without `$id` is
//! `default_base_uri`. The compiler resolves each reference one time. A reference to a URI
//! outside the document fails with `error.RemoteRef`, because the validator never gets a
//! schema from the network.
//!
//! The keywords `unevaluatedProperties` and `unevaluatedItems` use the annotations of the
//! subschemas that the instance passes. The keyword `not` gives no annotations. The keyword
//! `$dynamicRef` uses the dynamic scope. The dynamic scope is the list of the resources that
//! the evaluation entered.
//!
//! The validator ignores unknown keywords. The keywords `$recursiveRef` and `$recursiveAnchor`
//! of 2019-09 are unknown keywords in 2020-12.
//!
//! The keywords `pattern` and `patternProperties` use the engine in `regex.zig`. The compiler
//! compiles each regular expression one time and keeps the program in the `Schema`. The engine
//! does not support all features of ECMA-262. Refer to `regex.zig` for the list.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Limits = @import("../Limits.zig");
const regex = @import("regex.zig");

pub const dialect_2020_12 = "https://json-schema.org/draft/2020-12/schema";

/// The base URI of a root schema without `$id`. The domain `.invalid` never resolves.
pub const default_base_uri = "https://schema.invalid/root.json";

pub const Options = struct {
    /// Ignore a regular expression that uses a feature that `regex.zig` does not support.
    /// Without this option, the compiler rejects the schema.
    allow_unsupported_keywords: bool = false,
    limits: Limits.Schema = .{},
};

pub const CompileError = error{
    OutOfMemory,
    /// `$schema` names a dialect other than 2020-12.
    UnsupportedDialect,
    /// `$schema` is in a subschema that is not the root of a schema resource.
    UnsupportedKeyword,
    /// A `$ref` or a `$dynamicRef` points to a URI outside the document.
    RemoteRef,
    /// A keyword has an operand of the wrong shape, a reference has no target, or two
    /// resources have the same `$id`.
    InvalidSchema,
    SchemaTooDeep,
    TooManySubschemas,
    DuplicateAnchor,
    /// A `pattern` value or a `patternProperties` key is not an ECMA-262 regular expression.
    InvalidRegex,
    /// A regular expression uses a feature that `regex.zig` rejects. With
    /// `Options.allow_unsupported_keywords` the validator ignores that expression.
    UnsupportedRegex,
    /// A regular expression is larger than `max_pattern_bytes` or `max_regex_states`.
    RegexTooLarge,
};

pub const ValidateError = error{
    OutOfMemory,
    EvalBudgetExceeded,
    TooManyRefHops,
    InstanceTooDeep,
};

/// A compiled schema. The root value must outlive the schema.
pub const Schema = struct {
    root: Value,
    options: Options,
    /// The schema resources of the document. Item 0 is the resource of the root.
    resources: []const Resource = &.{},
    /// The resource and the resolved references of each schema object, by the address of
    /// the key storage of the object.
    nodes: std.AutoHashMapUnmanaged(usize, Node) = .empty,
    /// The compiled `pattern` values and `patternProperties` keys, by source text.
    patterns: std.StringHashMapUnmanaged(regex.Regex) = .empty,
    /// The largest match buffer that one of `patterns` needs, in `u32` items.
    pattern_buffer_len: usize = 0,
};

/// A schema resource: the root schema or a subschema with `$id`.
pub const Resource = struct {
    /// The absolute URI of the resource, without a fragment.
    uri: []const u8,
    root: Value,
    /// The names of `$anchor` and `$dynamicAnchor` in the resource.
    anchors: std.StringHashMapUnmanaged(Value) = .empty,
    /// The names of `$dynamicAnchor` in the resource.
    dynamic_anchors: std.StringHashMapUnmanaged(Value) = .empty,
};

/// The compiled facts about one schema object.
pub const Node = struct {
    /// The index of the resource of the object in `Schema.resources`.
    resource: u32,
    /// The target of `$ref`.
    ref: ?Value = null,
    /// The target of `$dynamicRef` before the dynamic scope applies.
    dynamic_ref: ?Value = null,
    /// The anchor name of `$dynamicRef` when its target has this name in `$dynamicAnchor`.
    /// Without this name, `$dynamicRef` is equal to `$ref`.
    dynamic_name: ?[]const u8 = null,
};

pub const Failure = struct {
    /// JSON pointer to the instance location.
    instance_path: []const u8,
    keyword: []const u8,
    message: []const u8,
};

pub const Result = struct {
    valid: bool,
    failures: []const Failure,
    /// True when the validator found more failures than `limits.max_errors`.
    truncated: bool = false,

    pub fn first(self: Result) ?Failure {
        return if (self.failures.len > 0) self.failures[0] else null;
    }
};

const schema_map_keywords = [_][]const u8{ "properties", "$defs", "definitions", "dependentSchemas" };
const schema_list_keywords = [_][]const u8{ "prefixItems", "allOf", "anyOf", "oneOf" };
const schema_single_keywords = [_][]const u8{
    "items",                 "additionalProperties", "propertyNames", "contains", "not", "if", "then", "else",
    "unevaluatedProperties", "unevaluatedItems",     "contentSchema",
};
const annotation_string_keywords = [_][]const u8{ "contentEncoding", "contentMediaType" };
const type_names = [_][]const u8{ "null", "boolean", "object", "array", "number", "integer", "string" };

/// The identity of a schema object: the address of its key storage. An empty object has no
/// keywords and thus no identity.
fn nodeKey(value: Value) ?usize {
    if (value != .object or value.object.count() == 0) return null;
    return @intFromPtr(value.object.keys().ptr);
}

const PendingRef = struct {
    /// The identity of the schema object that holds the reference.
    owner: usize,
    ref: []const u8,
    resource: u32,
    dynamic: bool,
};

const Target = struct {
    value: Value,
    resource: u32,
    dynamic_name: ?[]const u8 = null,
};

const Compiler = struct {
    arena: Allocator,
    options: Options,
    count: u32 = 0,
    resources: std.ArrayList(Resource) = .empty,
    /// The index of each resource in `resources`, by URI.
    resource_ids: std.StringHashMapUnmanaged(u32) = .empty,
    nodes: std.AutoHashMapUnmanaged(usize, Node) = .empty,
    refs: std.ArrayList(PendingRef) = .empty,
    patterns: std.StringHashMapUnmanaged(regex.Regex) = .empty,
    pattern_buffer_len: usize = 0,
    /// True while the compiler reads a reference target that no known keyword holds. The
    /// identifiers in such a target do not replace the identifiers of the document.
    detached: bool = false,

    fn pattern(self: *Compiler, source: []const u8) CompileError!void {
        if (self.patterns.contains(source)) return;
        const re = regex.compile(self.arena, source, .{
            .max_pattern_bytes = self.options.limits.max_pattern_bytes,
            .max_states = self.options.limits.max_regex_states,
        }) catch |e| switch (e) {
            error.UnsupportedRegex => {
                if (self.options.allow_unsupported_keywords) return;
                return error.UnsupportedRegex;
            },
            else => |other| return other,
        };
        try self.patterns.put(self.arena, source, re);
        self.pattern_buffer_len = @max(self.pattern_buffer_len, re.bufferLen());
    }

    /// Add the resource of `root`, with `id` resolved against `base`.
    fn addResource(self: *Compiler, base: []const u8, id: []const u8, root: Value) CompileError!u32 {
        const uri = try resolveUri(self.arena, base, id);
        const hash = std.mem.indexOfScalar(u8, uri, '#') orelse uri.len;
        // An identifier can have an empty fragment, but no other fragment.
        if (hash + 1 < uri.len) return error.InvalidSchema;
        const plain = uri[0..hash];
        const index: u32 = @intCast(self.resources.items.len);
        try self.resources.append(self.arena, .{ .uri = plain, .root = root });
        const gop = try self.resource_ids.getOrPut(self.arena, plain);
        if (gop.found_existing) {
            if (!self.detached) return error.InvalidSchema;
        } else gop.value_ptr.* = index;
        return index;
    }

    fn anchor(self: *Compiler, resource: u32, name: []const u8, owner: Value, dynamic: bool) CompileError!void {
        const r = &self.resources.items[resource];
        const gop = try r.anchors.getOrPut(self.arena, name);
        if (gop.found_existing) {
            // `$anchor` and `$dynamicAnchor` can give one object the same name.
            if (nodeKey(gop.value_ptr.*) != nodeKey(owner)) {
                if (self.detached) return;
                return error.DuplicateAnchor;
            }
        } else gop.value_ptr.* = owner;
        if (dynamic) try r.dynamic_anchors.put(self.arena, name, owner);
    }

    fn node(self: *Compiler, value: Value, depth: u16, resource: u32, is_root: bool) CompileError!void {
        switch (value) {
            .bool => return,
            .object => |obj| {
                if (depth > self.options.limits.max_depth) return error.SchemaTooDeep;
                self.count += 1;
                if (self.count > self.options.limits.max_subschemas) return error.TooManySubschemas;
                var res = resource;
                var resource_root = is_root;
                if (!is_root) if (obj.get("$id")) |id| {
                    if (id != .string) return error.InvalidSchema;
                    res = try self.addResource(self.resources.items[resource].uri, id.string, value);
                    resource_root = true;
                };
                const key = nodeKey(value) orelse return;
                try self.nodes.put(self.arena, key, .{ .resource = res });
                var it = obj.iterator();
                while (it.next()) |kv| try self.keyword(kv.key_ptr.*, kv.value_ptr.*, depth, res, resource_root, value);
            },
            else => return error.InvalidSchema,
        }
    }

    fn keyword(self: *Compiler, key: []const u8, value: Value, depth: u16, resource: u32, resource_root: bool, owner: Value) CompileError!void {
        if (std.mem.eql(u8, key, "$schema")) {
            if (!resource_root) return error.UnsupportedKeyword;
            if (value != .string or !std.mem.eql(u8, value.string, dialect_2020_12)) return error.UnsupportedDialect;
            return;
        }
        if (std.mem.eql(u8, key, "$id")) {
            if (value != .string) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "$anchor") or std.mem.eql(u8, key, "$dynamicAnchor")) {
            if (value != .string or !isPlainName(value.string)) return error.InvalidSchema;
            try self.anchor(resource, value.string, owner, key[1] == 'd');
            return;
        }
        if (std.mem.eql(u8, key, "$ref") or std.mem.eql(u8, key, "$dynamicRef")) {
            if (value != .string) return error.InvalidSchema;
            try self.refs.append(self.arena, .{ .owner = nodeKey(owner).?, .ref = value.string, .resource = resource, .dynamic = key[1] == 'd' });
            return;
        }
        for (schema_map_keywords) |k| if (std.mem.eql(u8, key, k)) {
            if (value != .object) return error.InvalidSchema;
            var it = value.object.iterator();
            while (it.next()) |kv| try self.node(kv.value_ptr.*, depth + 1, resource, false);
            return;
        };
        for (schema_list_keywords) |k| if (std.mem.eql(u8, key, k)) {
            if (value != .array or value.array.items.len == 0) return error.InvalidSchema;
            for (value.array.items) |item| try self.node(item, depth + 1, resource, false);
            return;
        };
        for (schema_single_keywords) |k| if (std.mem.eql(u8, key, k)) {
            if (value == .array) return error.InvalidSchema;
            try self.node(value, depth + 1, resource, false);
            return;
        };
        for (annotation_string_keywords) |k| if (std.mem.eql(u8, key, k)) {
            if (value != .string) return error.InvalidSchema;
            return;
        };
        if (std.mem.eql(u8, key, "type")) {
            switch (value) {
                .string => |s| if (!isTypeName(s)) return error.InvalidSchema,
                .array => |a| for (a.items) |item| {
                    if (item != .string or !isTypeName(item.string)) return error.InvalidSchema;
                },
                else => return error.InvalidSchema,
            }
            return;
        }
        if (std.mem.eql(u8, key, "enum")) {
            if (value != .array) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "required")) {
            if (!isStringArray(value)) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "dependentRequired")) {
            if (value != .object) return error.InvalidSchema;
            var it = value.object.iterator();
            while (it.next()) |kv| if (!isStringArray(kv.value_ptr.*)) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "minimum") or std.mem.eql(u8, key, "maximum") or
            std.mem.eql(u8, key, "exclusiveMinimum") or std.mem.eql(u8, key, "exclusiveMaximum"))
        {
            if (toF64(value) == null) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "multipleOf")) {
            const m = toF64(value) orelse return error.InvalidSchema;
            if (!(m > 0)) return error.InvalidSchema;
            return;
        }
        if (isCountKeyword(key)) {
            if (countValue(value) == null) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "uniqueItems")) {
            if (value != .bool) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "pattern")) {
            if (value != .string) return error.InvalidSchema;
            try self.pattern(value.string);
            return;
        }
        if (std.mem.eql(u8, key, "patternProperties")) {
            if (value != .object) return error.InvalidSchema;
            var it = value.object.iterator();
            while (it.next()) |kv| {
                try self.pattern(kv.key_ptr.*);
                try self.node(kv.value_ptr.*, depth + 1, resource, false);
            }
            return;
        }
        // Everything else is an annotation or an unknown keyword and is ignored.
    }

    /// Resolve `ref` against the URI of `resource` and find its target in the document.
    fn resolve(self: *Compiler, resource: u32, ref: []const u8) CompileError!Target {
        const uri = try resolveUri(self.arena, self.resources.items[resource].uri, ref);
        const hash = std.mem.indexOfScalar(u8, uri, '#') orelse uri.len;
        const id = self.resource_ids.get(uri[0..hash]) orelse return error.RemoteRef;
        const r = self.resources.items[id];
        const fragment = if (hash < uri.len) uri[hash + 1 ..] else "";
        if (fragment.len == 0) return .{ .value = r.root, .resource = id };
        if (fragment[0] != '/') {
            const target = r.anchors.get(fragment) orelse return error.InvalidSchema;
            return .{ .value = target, .resource = id, .dynamic_name = if (r.dynamic_anchors.contains(fragment)) fragment else null };
        }
        // A JSON pointer. It can cross into an embedded resource, and then the target is in
        // that resource.
        var current = r.root;
        var res = id;
        var it = std.mem.splitScalar(u8, fragment[1..], '/');
        var buf: [256]u8 = undefined;
        while (it.next()) |raw| {
            const token = unescapeToken(&buf, raw) orelse return error.InvalidSchema;
            switch (current) {
                .object => |obj| current = obj.get(token) orelse return error.InvalidSchema,
                .array => |arr| {
                    const index = std.fmt.parseInt(usize, token, 10) catch return error.InvalidSchema;
                    if (index >= arr.items.len) return error.InvalidSchema;
                    current = arr.items[index];
                },
                else => return error.InvalidSchema,
            }
            if (nodeKey(current)) |k| if (self.nodes.get(k)) |n| {
                res = n.resource;
            };
        }
        return switch (current) {
            .object, .bool => .{ .value = current, .resource = res },
            else => error.InvalidSchema,
        };
    }
};

fn isCountKeyword(key: []const u8) bool {
    const names = [_][]const u8{ "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties", "minContains", "maxContains" };
    for (names) |n| if (std.mem.eql(u8, key, n)) return true;
    return false;
}

/// The value of a count keyword such as `maxLength`: a non-negative integer. A number with a
/// zero fraction, such as `2.0`, is an integer too. A count larger than `usize` gets the
/// maximum `usize`.
fn countValue(value: Value) ?usize {
    switch (value) {
        .integer => |i| return if (i < 0) null else std.math.cast(usize, i) orelse std.math.maxInt(usize),
        .float, .number_string => {
            if (!isInteger(value)) return null;
            const f = toF64(value).?;
            if (f < 0) return null;
            if (f >= @as(f64, @floatFromInt(std.math.maxInt(usize)))) return std.math.maxInt(usize);
            return @intFromFloat(f);
        },
        else => return null,
    }
}

/// The value of a count keyword that the compiler checked.
fn countOf(value: Value) usize {
    return countValue(value).?;
}

fn isTypeName(s: []const u8) bool {
    for (type_names) |n| if (std.mem.eql(u8, s, n)) return true;
    return false;
}

fn isStringArray(value: Value) bool {
    if (value != .array) return false;
    for (value.array.items) |item| if (item != .string) return false;
    return true;
}

fn isPlainName(s: []const u8) bool {
    if (s.len == 0) return false;
    if (!(std.ascii.isAlphabetic(s[0]) or s[0] == '_')) return false;
    for (s[1..]) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.')) return false;
    return true;
}

/// Compile a schema. The compiler checks the dialect and the keywords and compiles the
/// regular expressions. It finds the schema resources and their anchors, and resolves every
/// reference one time.
pub fn compile(arena: Allocator, root: Value, options: Options) CompileError!Schema {
    var c: Compiler = .{ .arena = arena, .options = options };
    var id: []const u8 = "";
    if (root == .object) if (root.object.get("$id")) |v| {
        if (v != .string) return error.InvalidSchema;
        id = v.string;
    };
    _ = try c.addResource(default_base_uri, id, root);
    try c.node(root, 0, 0, true);
    // A reference can point into a member that the walk above does not visit, such as an
    // unknown keyword. Compile each such target too, so that validation never meets an
    // unchecked operand. The list grows while the loop runs, because a target can hold
    // references.
    var i: usize = 0;
    while (i < c.refs.items.len) : (i += 1) {
        const pending = c.refs.items[i];
        const target = try c.resolve(pending.resource, pending.ref);
        if (nodeKey(target.value)) |k| if (!c.nodes.contains(k)) {
            c.detached = true;
            try c.node(target.value, 0, target.resource, false);
        };
        const owner = c.nodes.getPtr(pending.owner).?;
        if (pending.dynamic) {
            owner.dynamic_ref = target.value;
            owner.dynamic_name = target.dynamic_name;
        } else owner.ref = target.value;
    }
    return .{
        .root = root,
        .options = options,
        .resources = c.resources.items,
        .nodes = c.nodes,
        .patterns = c.patterns,
        .pattern_buffer_len = c.pattern_buffer_len,
    };
}

/// The five parts of a URI reference (RFC 3986, section 3). A null part is absent.
const UriParts = struct {
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    path: []const u8 = "",
    query: ?[]const u8 = null,
    fragment: ?[]const u8 = null,
};

fn splitUri(text: []const u8) UriParts {
    var parts: UriParts = .{};
    var rest = text;
    if (std.mem.indexOfScalar(u8, rest, '#')) |i| {
        parts.fragment = rest[i + 1 ..];
        rest = rest[0..i];
    }
    if (std.mem.indexOfScalar(u8, rest, '?')) |i| {
        parts.query = rest[i + 1 ..];
        rest = rest[0..i];
    }
    for (rest, 0..) |c, i| {
        if (c == ':') {
            if (i > 0 and std.ascii.isAlphabetic(rest[0])) {
                parts.scheme = rest[0..i];
                rest = rest[i + 1 ..];
            }
            break;
        }
        if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.')) break;
    }
    if (std.mem.startsWith(u8, rest, "//")) {
        const end = std.mem.indexOfScalarPos(u8, rest, 2, '/') orelse rest.len;
        parts.authority = rest[2..end];
        rest = rest[end..];
    }
    parts.path = rest;
    return parts;
}

/// Resolve a URI reference against a base URI (RFC 3986, section 5.2.2).
fn resolveUri(arena: Allocator, base_text: []const u8, ref_text: []const u8) Allocator.Error![]const u8 {
    const base = splitUri(base_text);
    const r = splitUri(ref_text);
    var t: UriParts = .{ .fragment = r.fragment };
    if (r.scheme != null) {
        t.scheme = r.scheme;
        t.authority = r.authority;
        t.path = try removeDotSegments(arena, r.path);
        t.query = r.query;
    } else {
        if (r.authority != null) {
            t.authority = r.authority;
            t.path = try removeDotSegments(arena, r.path);
            t.query = r.query;
        } else {
            if (r.path.len == 0) {
                t.path = base.path;
                t.query = r.query orelse base.query;
            } else {
                const merged = if (r.path[0] == '/') r.path else try mergePaths(arena, base, r.path);
                t.path = try removeDotSegments(arena, merged);
                t.query = r.query;
            }
            t.authority = base.authority;
        }
        t.scheme = base.scheme;
    }
    var out: std.ArrayList(u8) = .empty;
    if (t.scheme) |s| try out.print(arena, "{s}:", .{s});
    if (t.authority) |a| try out.print(arena, "//{s}", .{a});
    try out.appendSlice(arena, t.path);
    if (t.query) |q| try out.print(arena, "?{s}", .{q});
    if (t.fragment) |f| try out.print(arena, "#{s}", .{f});
    return out.items;
}

/// Merge a relative path with the path of the base URI (RFC 3986, section 5.2.3).
fn mergePaths(arena: Allocator, base: UriParts, path: []const u8) Allocator.Error![]const u8 {
    if (base.authority != null and base.path.len == 0) return std.mem.concat(arena, u8, &.{ "/", path });
    const cut = if (std.mem.lastIndexOfScalar(u8, base.path, '/')) |i| i + 1 else 0;
    return std.mem.concat(arena, u8, &.{ base.path[0..cut], path });
}

/// Remove the segments `.` and `..` from a path (RFC 3986, section 5.2.4).
fn removeDotSegments(arena: Allocator, path: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var in = path;
    while (in.len > 0) {
        if (std.mem.startsWith(u8, in, "../")) {
            in = in[3..];
        } else if (std.mem.startsWith(u8, in, "./") or std.mem.startsWith(u8, in, "/./")) {
            in = in[2..];
        } else if (std.mem.eql(u8, in, "/.")) {
            in = "/";
        } else if (std.mem.startsWith(u8, in, "/../") or std.mem.eql(u8, in, "/..")) {
            in = if (in.len == 3) "/" else in[3..];
            const cut = std.mem.lastIndexOfScalar(u8, out.items, '/') orelse 0;
            out.shrinkRetainingCapacity(cut);
        } else if (std.mem.eql(u8, in, ".") or std.mem.eql(u8, in, "..")) {
            in = "";
        } else {
            const start: usize = if (in[0] == '/') 1 else 0;
            const end = std.mem.indexOfScalarPos(u8, in, start, '/') orelse in.len;
            try out.appendSlice(arena, in[0..end]);
            in = in[end..];
        }
    }
    return out.items;
}

/// Decode a JSON pointer token: percent escapes first, then `~1` and `~0`.
fn unescapeToken(buf: []u8, raw: []const u8) ?[]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) {
        var c = raw[i];
        i += 1;
        if (c == '%') {
            if (i + 2 > raw.len) return null;
            c = std.fmt.parseInt(u8, raw[i .. i + 2], 16) catch return null;
            i += 2;
        }
        if (c == '~') {
            if (i >= raw.len) return null;
            const next = raw[i];
            i += 1;
            c = switch (next) {
                '0' => '~',
                '1' => '/',
                else => return null,
            };
        }
        if (n == buf.len) return null;
        buf[n] = c;
        n += 1;
    }
    return buf[0..n];
}

const Segment = union(enum) { key: []const u8, index: usize };

/// A set of evaluated locations of one instance: the member indexes of an object or the item
/// indexes of an array, one bit each.
const Marks = []u64;

fn isMarked(marks: Marks, i: usize) bool {
    return marks[i / 64] & (@as(u64, 1) << @intCast(i % 64)) != 0;
}

fn mark(marks: ?Marks, i: usize) void {
    const m = marks orelse return;
    m[i / 64] |= @as(u64, 1) << @intCast(i % 64);
}

const Evaluator = struct {
    arena: Allocator,
    schema: *const Schema,
    limits: Limits.Schema,
    budget: u32,
    ref_hops: u16 = 0,
    path: std.ArrayList(Segment) = .empty,
    failures: std.ArrayList(Failure) = .empty,
    truncated: bool = false,
    regex_buffer: []u32 = &.{},
    /// The dynamic scope: the indexes of the resources that the evaluation entered, the
    /// outermost first.
    scope: std.ArrayList(u32) = .empty,

    /// Match `s` against the compiled expression for `source`. Return null when the compiler
    /// ignored the expression.
    fn matchPattern(self: *Evaluator, source: []const u8, s: []const u8) ?bool {
        const re = self.schema.patterns.getPtr(source) orelse return null;
        return re.isMatchBuffer(self.regex_buffer, s);
    }

    fn fail(self: *Evaluator, collect: bool, keyword: []const u8, comptime fmt: []const u8, args: anytype) ValidateError!bool {
        if (!collect) return false;
        if (self.failures.items.len >= self.limits.max_errors) {
            self.truncated = true;
            return false;
        }
        try self.failures.append(self.arena, .{
            .instance_path = try self.renderPath(),
            .keyword = keyword,
            .message = try std.fmt.allocPrint(self.arena, fmt, args),
        });
        return false;
    }

    fn renderPath(self: *Evaluator) Allocator.Error![]const u8 {
        var out: std.Io.Writer.Allocating = .init(self.arena);
        for (self.path.items) |seg| {
            out.writer.writeByte('/') catch return error.OutOfMemory;
            switch (seg) {
                .index => |i| out.writer.print("{d}", .{i}) catch return error.OutOfMemory,
                .key => |k| for (k) |c| switch (c) {
                    '~' => out.writer.writeAll("~0") catch return error.OutOfMemory,
                    '/' => out.writer.writeAll("~1") catch return error.OutOfMemory,
                    else => out.writer.writeByte(c) catch return error.OutOfMemory,
                },
            }
        }
        return out.toOwnedSlice() catch return error.OutOfMemory;
    }

    /// Make an empty set of marks for `len` locations. Each word of the set costs one unit of
    /// the evaluation budget, so that the memory of the marks has a limit too.
    fn newMarks(self: *Evaluator, len: usize) ValidateError!Marks {
        const words = (len + 63) / 64;
        if (words > self.budget) return error.EvalBudgetExceeded;
        self.budget -= @intCast(words);
        const m = try self.arena.alloc(u64, words);
        @memset(m, 0);
        return m;
    }

    /// Evaluate `node` against a child location of the instance. The annotations of a child
    /// location do not go to the parent location.
    fn child(self: *Evaluator, node: Value, inst: Value, seg: Segment, depth: u16, collect: bool) ValidateError!bool {
        if (depth + 1 > self.limits.max_depth) return error.InstanceTooDeep;
        try self.path.append(self.arena, seg);
        defer _ = self.path.pop();
        return self.eval(node, inst, depth + 1, collect, null);
    }

    /// Follow a reference to `target` at the same instance location.
    fn follow(self: *Evaluator, target: Value, inst: Value, depth: u16, collect: bool, marks: ?Marks) ValidateError!bool {
        if (self.ref_hops >= self.limits.max_ref_hops) return error.TooManyRefHops;
        self.ref_hops += 1;
        defer self.ref_hops -= 1;
        return self.eval(target, inst, depth, collect, marks);
    }

    /// The target of a `$dynamicRef`: the outermost resource in the dynamic scope that has
    /// the anchor name in `$dynamicAnchor`, or else the static target.
    fn dynamicTarget(self: *Evaluator, n: Node, target: Value) Value {
        const name = n.dynamic_name orelse return target;
        for (self.scope.items) |id| {
            if (self.schema.resources[id].dynamic_anchors.get(name)) |v| return v;
        }
        return target;
    }

    /// Evaluate `node` against `inst`. When `marks` is not null and the instance is valid,
    /// add the locations that this schema evaluated to `marks`.
    fn eval(self: *Evaluator, node: Value, inst: Value, depth: u16, collect: bool, marks: ?Marks) ValidateError!bool {
        switch (node) {
            .bool => |b| {
                if (b) return true;
                return self.fail(collect, "false", "the schema rejects every value", .{});
            },
            .object => |obj| {
                if (self.budget == 0) return error.EvalBudgetExceeded;
                self.budget -= 1;
                const info: ?Node = if (nodeKey(node)) |k| self.schema.nodes.get(k) else null;
                // The evaluation enters a resource when the resource changes.
                const entered = if (info) |n| self.scope.items.len == 0 or self.scope.getLast() != n.resource else false;
                if (entered) try self.scope.append(self.arena, info.?.resource);
                defer if (entered) {
                    _ = self.scope.pop();
                };
                // The locations that this schema evaluated. The set exists only when this
                // schema or a parent at the same location has an unevaluated keyword.
                const local: ?Marks = switch (inst) {
                    .object => |o| if (marks != null or obj.contains("unevaluatedProperties")) try self.newMarks(o.count()) else null,
                    .array => |a| if (marks != null or obj.contains("unevaluatedItems")) try self.newMarks(a.items.len) else null,
                    else => null,
                };
                defer if (local) |m| self.arena.free(m);
                var ok = true;
                if (info) |n| {
                    if (n.ref) |target| if (!try self.follow(target, inst, depth, collect, local)) {
                        ok = false;
                    };
                    if (n.dynamic_ref) |target| if (!try self.follow(self.dynamicTarget(n, target), inst, depth, collect, local)) {
                        ok = false;
                    };
                }
                if (obj.get("type")) |t| if (!try self.checkType(t, inst, collect)) {
                    ok = false;
                };
                if (obj.get("enum")) |e| {
                    var found = false;
                    for (e.array.items) |item| if (eql(item, inst)) {
                        found = true;
                        break;
                    };
                    if (!found) ok = try self.fail(collect, "enum", "value is not one of the allowed values", .{}) and ok;
                }
                if (obj.get("const")) |c| if (!eql(c, inst)) {
                    ok = try self.fail(collect, "const", "value is not the required constant", .{}) and ok;
                };
                switch (inst) {
                    .integer, .float, .number_string => if (!try self.checkNumber(obj, inst, collect)) {
                        ok = false;
                    },
                    .string => |s| if (!try self.checkString(obj, s, collect)) {
                        ok = false;
                    },
                    .object => if (!try self.checkObject(obj, inst, depth, collect, local)) {
                        ok = false;
                    },
                    .array => if (!try self.checkArray(obj, inst, depth, collect, local)) {
                        ok = false;
                    },
                    else => {},
                }
                if (!try self.checkLogic(obj, inst, depth, collect, local)) ok = false;
                if (local) |m| {
                    // The unevaluated keywords come after all other keywords of the object.
                    if (!try self.checkUnevaluated(obj, inst, depth, collect, m)) ok = false;
                    if (ok) if (marks) |parent| for (parent, m) |*p, x| {
                        p.* |= x;
                    };
                }
                return ok;
            },
            else => return true,
        }
    }

    fn checkType(self: *Evaluator, t: Value, inst: Value, collect: bool) ValidateError!bool {
        const matches = switch (t) {
            .string => |s| typeMatches(s, inst),
            .array => |a| blk: {
                for (a.items) |item| if (typeMatches(item.string, inst)) break :blk true;
                break :blk false;
            },
            else => true,
        };
        if (matches) return true;
        const want = if (t == .string) t.string else "one of the listed types";
        return self.fail(collect, "type", "expected {s}, found {s}", .{ want, typeName(inst) });
    }

    fn checkNumber(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, collect: bool) ValidateError!bool {
        var ok = true;
        const x = toF64(inst) orelse return true;
        if (obj.get("minimum")) |m| if (x < toF64(m).?) {
            ok = try self.fail(collect, "minimum", "value is less than the minimum", .{}) and ok;
        };
        if (obj.get("maximum")) |m| if (x > toF64(m).?) {
            ok = try self.fail(collect, "maximum", "value is greater than the maximum", .{}) and ok;
        };
        if (obj.get("exclusiveMinimum")) |m| if (x <= toF64(m).?) {
            ok = try self.fail(collect, "exclusiveMinimum", "value is not greater than the exclusive minimum", .{}) and ok;
        };
        if (obj.get("exclusiveMaximum")) |m| if (x >= toF64(m).?) {
            ok = try self.fail(collect, "exclusiveMaximum", "value is not less than the exclusive maximum", .{}) and ok;
        };
        if (obj.get("multipleOf")) |m| if (!isMultipleOf(inst, m)) {
            ok = try self.fail(collect, "multipleOf", "value is not a multiple of the divisor", .{}) and ok;
        };
        return ok;
    }

    fn checkString(self: *Evaluator, obj: std.json.ObjectMap, s: []const u8, collect: bool) ValidateError!bool {
        var ok = true;
        if (obj.get("pattern")) |p| if (p == .string) if (self.matchPattern(p.string, s)) |matched| if (!matched) {
            ok = try self.fail(collect, "pattern", "string does not match the pattern \"{s}\"", .{p.string}) and ok;
        };
        const min = obj.get("minLength");
        const max = obj.get("maxLength");
        if (min == null and max == null) return ok;
        const len = std.unicode.utf8CountCodepoints(s) catch s.len;
        if (min) |m| if (len < countOf(m)) {
            ok = try self.fail(collect, "minLength", "string is shorter than {d} characters", .{countOf(m)}) and ok;
        };
        if (max) |m| if (len > countOf(m)) {
            ok = try self.fail(collect, "maxLength", "string is longer than {d} characters", .{countOf(m)}) and ok;
        };
        return ok;
    }

    fn checkObject(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, depth: u16, collect: bool, marks: ?Marks) ValidateError!bool {
        var ok = true;
        const members = inst.object;
        if (obj.get("required")) |req| for (req.array.items) |name| {
            if (!members.contains(name.string)) {
                ok = try self.fail(collect, "required", "missing required property \"{s}\"", .{name.string}) and ok;
            }
        };
        if (obj.get("minProperties")) |m| if (members.count() < countOf(m)) {
            ok = try self.fail(collect, "minProperties", "object has fewer than {d} properties", .{countOf(m)}) and ok;
        };
        if (obj.get("maxProperties")) |m| if (members.count() > countOf(m)) {
            ok = try self.fail(collect, "maxProperties", "object has more than {d} properties", .{countOf(m)}) and ok;
        };
        if (obj.get("dependentRequired")) |deps| {
            var it = deps.object.iterator();
            while (it.next()) |kv| {
                if (!members.contains(kv.key_ptr.*)) continue;
                for (kv.value_ptr.array.items) |name| if (!members.contains(name.string)) {
                    ok = try self.fail(collect, "dependentRequired", "property \"{s}\" needs property \"{s}\"", .{ kv.key_ptr.*, name.string }) and ok;
                };
            }
        }
        if (obj.get("dependentSchemas")) |deps| {
            var it = deps.object.iterator();
            while (it.next()) |kv| {
                if (!members.contains(kv.key_ptr.*)) continue;
                if (!try self.eval(kv.value_ptr.*, inst, depth, collect, marks)) ok = false;
            }
        }
        const props = obj.get("properties");
        const pattern_props = obj.get("patternProperties");
        const additional = obj.get("additionalProperties");
        const names_schema = obj.get("propertyNames");
        for (members.keys(), members.values(), 0..) |name, value, i| {
            var covered = false;
            if (props) |p| if (p.object.get(name)) |sub| {
                covered = true;
                if (!try self.child(sub, value, .{ .key = name }, depth, collect)) ok = false;
            };
            // A name that a `patternProperties` expression matches is not additional.
            if (pattern_props) |pp| if (pp == .object) {
                var pit = pp.object.iterator();
                while (pit.next()) |entry| {
                    const matched = self.matchPattern(entry.key_ptr.*, name) orelse continue;
                    if (!matched) continue;
                    covered = true;
                    if (!try self.child(entry.value_ptr.*, value, .{ .key = name }, depth, collect)) ok = false;
                }
            };
            if (!covered) if (additional) |a| {
                covered = true;
                if (!try self.child(a, value, .{ .key = name }, depth, collect)) ok = false;
            };
            if (covered) mark(marks, i);
            if (names_schema) |ns| {
                if (!try self.child(ns, .{ .string = name }, .{ .key = name }, depth, collect)) ok = false;
            }
        }
        return ok;
    }

    fn checkArray(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, depth: u16, collect: bool, marks: ?Marks) ValidateError!bool {
        var ok = true;
        const items = inst.array.items;
        if (obj.get("minItems")) |m| if (items.len < countOf(m)) {
            ok = try self.fail(collect, "minItems", "array has fewer than {d} items", .{countOf(m)}) and ok;
        };
        if (obj.get("maxItems")) |m| if (items.len > countOf(m)) {
            ok = try self.fail(collect, "maxItems", "array has more than {d} items", .{countOf(m)}) and ok;
        };
        if (obj.get("uniqueItems")) |u| if (u.bool) {
            outer: for (items, 0..) |a, i| {
                for (items[i + 1 ..]) |b| if (eql(a, b)) {
                    ok = try self.fail(collect, "uniqueItems", "array has duplicate items", .{}) and ok;
                    break :outer;
                };
            }
        };
        var prefix_len: usize = 0;
        if (obj.get("prefixItems")) |prefix| {
            prefix_len = prefix.array.items.len;
            for (prefix.array.items, 0..) |sub, i| {
                if (i >= items.len) break;
                if (!try self.child(sub, items[i], .{ .index = i }, depth, collect)) ok = false;
                mark(marks, i);
            }
        }
        if (obj.get("items")) |sub| {
            var i = prefix_len;
            while (i < items.len) : (i += 1) {
                if (!try self.child(sub, items[i], .{ .index = i }, depth, collect)) ok = false;
                mark(marks, i);
            }
        }
        if (obj.get("contains")) |sub| {
            var matched: usize = 0;
            for (items, 0..) |item, i| {
                if (try self.child(sub, item, .{ .index = i }, depth, false)) {
                    matched += 1;
                    mark(marks, i);
                }
            }
            const min: usize = if (obj.get("minContains")) |m| countOf(m) else 1;
            if (matched < min) {
                ok = try self.fail(collect, "contains", "array needs at least {d} matching items", .{min}) and ok;
            }
            if (obj.get("maxContains")) |m| if (matched > countOf(m)) {
                ok = try self.fail(collect, "maxContains", "array has more than {d} matching items", .{countOf(m)}) and ok;
            };
        }
        return ok;
    }

    fn checkLogic(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, depth: u16, collect: bool, marks: ?Marks) ValidateError!bool {
        var ok = true;
        if (obj.get("allOf")) |list| for (list.array.items) |sub| {
            if (!try self.eval(sub, inst, depth, collect, marks)) ok = false;
        };
        if (obj.get("anyOf")) |list| {
            // With marks, every alternative that passes gives annotations. Thus the loop
            // stops at the first match only without marks.
            var any = false;
            for (list.array.items) |sub| if (try self.eval(sub, inst, depth, false, marks)) {
                any = true;
                if (marks == null) break;
            };
            if (!any) ok = try self.fail(collect, "anyOf", "value matches none of the alternatives", .{}) and ok;
        }
        if (obj.get("oneOf")) |list| {
            var matches: usize = 0;
            for (list.array.items) |sub| if (try self.eval(sub, inst, depth, false, marks)) {
                matches += 1;
            };
            if (matches != 1) ok = try self.fail(collect, "oneOf", "value matches {d} alternatives, expected exactly one", .{matches}) and ok;
        }
        if (obj.get("not")) |sub| if (try self.eval(sub, inst, depth, false, null)) {
            ok = try self.fail(collect, "not", "value matches the forbidden schema", .{}) and ok;
        };
        if (obj.get("if")) |cond| {
            if (try self.eval(cond, inst, depth, false, marks)) {
                if (obj.get("then")) |sub| if (!try self.eval(sub, inst, depth, collect, marks)) {
                    ok = false;
                };
            } else {
                if (obj.get("else")) |sub| if (!try self.eval(sub, inst, depth, collect, marks)) {
                    ok = false;
                };
            }
        }
        return ok;
    }

    /// Apply `unevaluatedProperties` or `unevaluatedItems` to each location that is not in
    /// `marks`, and then add that location to `marks`.
    fn checkUnevaluated(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, depth: u16, collect: bool, marks: Marks) ValidateError!bool {
        var ok = true;
        switch (inst) {
            .object => |members| if (obj.get("unevaluatedProperties")) |sub| {
                for (members.keys(), members.values(), 0..) |name, value, i| {
                    if (isMarked(marks, i)) continue;
                    if (!try self.child(sub, value, .{ .key = name }, depth, collect)) ok = false;
                    mark(marks, i);
                }
            },
            .array => |arr| if (obj.get("unevaluatedItems")) |sub| {
                for (arr.items, 0..) |item, i| {
                    if (isMarked(marks, i)) continue;
                    if (!try self.child(sub, item, .{ .index = i }, depth, collect)) ok = false;
                    mark(marks, i);
                }
            },
            else => {},
        }
        return ok;
    }
};

/// Validate an instance against a compiled schema. Failure messages live in `arena`.
pub fn validate(arena: Allocator, schema: *const Schema, instance: Value) ValidateError!Result {
    var ev: Evaluator = .{
        .arena = arena,
        .schema = schema,
        .limits = schema.options.limits,
        .budget = schema.options.limits.eval_budget,
        .regex_buffer = try arena.alloc(u32, schema.pattern_buffer_len),
    };
    const valid = try ev.eval(schema.root, instance, 0, true, null);
    return .{ .valid = valid, .failures = ev.failures.items, .truncated = ev.truncated };
}

/// Parse schema text and compile it in one step.
pub fn compileText(arena: Allocator, text: []const u8, options: Options) (CompileError || error{Syntax})!Schema {
    const root = std.json.parseFromSliceLeaky(Value, arena, text, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Syntax,
    };
    return compile(arena, root, options);
}

fn typeName(v: Value) []const u8 {
    return switch (v) {
        .null => "null",
        .bool => "boolean",
        .integer, .float, .number_string => "number",
        .string => "string",
        .array => "array",
        .object => "object",
    };
}

fn typeMatches(name: []const u8, v: Value) bool {
    if (std.mem.eql(u8, name, "null")) return v == .null;
    if (std.mem.eql(u8, name, "boolean")) return v == .bool;
    if (std.mem.eql(u8, name, "string")) return v == .string;
    if (std.mem.eql(u8, name, "array")) return v == .array;
    if (std.mem.eql(u8, name, "object")) return v == .object;
    if (std.mem.eql(u8, name, "number")) return v == .integer or v == .float or v == .number_string;
    if (std.mem.eql(u8, name, "integer")) return isInteger(v);
    return false;
}

fn isInteger(v: Value) bool {
    return switch (v) {
        .integer => true,
        .float => |f| std.math.isFinite(f) and @trunc(f) == f,
        .number_string => |s| blk: {
            const f = std.fmt.parseFloat(f64, s) catch break :blk false;
            break :blk std.math.isFinite(f) and @trunc(f) == f;
        },
        else => false,
    };
}

fn toF64(v: Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn isMultipleOf(inst: Value, divisor: Value) bool {
    if (inst == .integer and divisor == .integer) return @rem(inst.integer, divisor.integer) == 0;
    const x = toF64(inst) orelse return true;
    const d = toF64(divisor) orelse return true;
    const q = x / d;
    if (!std.math.isFinite(q)) return false;
    const r = @round(q);
    return @abs(q - r) <= 1e-9 * @max(1.0, @abs(q));
}

/// Deep equality with numeric comparison across integer and float representations.
pub fn eql(a: Value, b: Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |x| return b == .bool and b.bool == x,
        .integer, .float, .number_string => {
            if (a == .integer and b == .integer) return a.integer == b.integer;
            const x = toF64(a) orelse return false;
            const y = toF64(b) orelse return false;
            return x == y;
        },
        .string => |s| return b == .string and std.mem.eql(u8, s, b.string),
        .array => |arr| {
            if (b != .array or b.array.items.len != arr.items.len) return false;
            for (arr.items, b.array.items) |x, y| if (!eql(x, y)) return false;
            return true;
        },
        .object => |obj| {
            if (b != .object or b.object.count() != obj.count()) return false;
            var it = obj.iterator();
            while (it.next()) |kv| {
                const other = b.object.get(kv.key_ptr.*) orelse return false;
                if (!eql(kv.value_ptr.*, other)) return false;
            }
            return true;
        },
    }
}

// -- Tests -----------------------------------------------------------------------------------

const Case = struct { schema: []const u8, instance: []const u8, valid: bool };

fn runCases(cases: []const Case) !void {
    for (cases) |case| {
        var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const schema = try compileText(arena, case.schema, .{});
        const inst = try std.json.parseFromSliceLeaky(Value, arena, case.instance, .{});
        const result = try validate(arena, &schema, inst);
        if (result.valid != case.valid) {
            std.debug.print("schema {s} instance {s}: expected valid={}\n", .{ case.schema, case.instance, case.valid });
            return error.TestUnexpectedResult;
        }
    }
}

test "type, enum and const" {
    try runCases(&.{
        .{ .schema = "{\"type\":\"integer\"}", .instance = "1", .valid = true },
        .{ .schema = "{\"type\":\"integer\"}", .instance = "1.0", .valid = true },
        .{ .schema = "{\"type\":\"integer\"}", .instance = "1.5", .valid = false },
        .{ .schema = "{\"type\":\"integer\"}", .instance = "\"1\"", .valid = false },
        .{ .schema = "{\"type\":\"number\"}", .instance = "1.5", .valid = true },
        .{ .schema = "{\"type\":[\"string\",\"null\"]}", .instance = "null", .valid = true },
        .{ .schema = "{\"type\":[\"string\",\"null\"]}", .instance = "true", .valid = false },
        .{ .schema = "{\"type\":\"object\"}", .instance = "[]", .valid = false },
        .{ .schema = "{\"enum\":[1,\"a\",null,[1]]}", .instance = "[1]", .valid = true },
        .{ .schema = "{\"enum\":[1,\"a\",null,[1]]}", .instance = "1.0", .valid = true },
        .{ .schema = "{\"enum\":[1,\"a\",null,[1]]}", .instance = "\"b\"", .valid = false },
        .{ .schema = "{\"const\":{\"a\":1,\"b\":[true]}}", .instance = "{\"b\":[true],\"a\":1}", .valid = true },
        .{ .schema = "{\"const\":{\"a\":1}}", .instance = "{\"a\":1,\"b\":2}", .valid = false },
        .{ .schema = "true", .instance = "\"anything\"", .valid = true },
        .{ .schema = "false", .instance = "1", .valid = false },
    });
}

test "numbers and strings" {
    try runCases(&.{
        .{ .schema = "{\"minimum\":2}", .instance = "2", .valid = true },
        .{ .schema = "{\"minimum\":2}", .instance = "1.9", .valid = false },
        .{ .schema = "{\"exclusiveMinimum\":2}", .instance = "2", .valid = false },
        .{ .schema = "{\"maximum\":2.5}", .instance = "3", .valid = false },
        .{ .schema = "{\"exclusiveMaximum\":3}", .instance = "2.99", .valid = true },
        .{ .schema = "{\"multipleOf\":2}", .instance = "10", .valid = true },
        .{ .schema = "{\"multipleOf\":2}", .instance = "7", .valid = false },
        .{ .schema = "{\"multipleOf\":0.0001}", .instance = "0.0075", .valid = true },
        .{ .schema = "{\"multipleOf\":1.5}", .instance = "4.5", .valid = true },
        .{ .schema = "{\"multipleOf\":0.123456789}", .instance = "1e308", .valid = false },
        .{ .schema = "{\"minimum\":2}", .instance = "\"x\"", .valid = true },
        .{ .schema = "{\"minLength\":2,\"maxLength\":3}", .instance = "\"ab\"", .valid = true },
        .{ .schema = "{\"minLength\":2,\"maxLength\":3}", .instance = "\"a\"", .valid = false },
        .{ .schema = "{\"maxLength\":2}", .instance = "\"\\u00e9\\u00e9\"", .valid = true },
        .{ .schema = "{\"maxLength\":2}", .instance = "\"abc\"", .valid = false },
    });
}

test "objects" {
    try runCases(&.{
        .{ .schema = "{\"properties\":{\"a\":{\"type\":\"integer\"}},\"required\":[\"a\"]}", .instance = "{\"a\":1}", .valid = true },
        .{ .schema = "{\"properties\":{\"a\":{\"type\":\"integer\"}},\"required\":[\"a\"]}", .instance = "{}", .valid = false },
        .{ .schema = "{\"properties\":{\"a\":{\"type\":\"integer\"}}}", .instance = "{\"a\":\"x\"}", .valid = false },
        .{ .schema = "{\"properties\":{\"a\":{}},\"additionalProperties\":false}", .instance = "{\"a\":1,\"b\":2}", .valid = false },
        .{ .schema = "{\"properties\":{\"a\":{}},\"additionalProperties\":{\"type\":\"string\"}}", .instance = "{\"a\":1,\"b\":\"x\"}", .valid = true },
        .{ .schema = "{\"additionalProperties\":{\"type\":\"string\"}}", .instance = "{\"b\":2}", .valid = false },
        .{ .schema = "{\"propertyNames\":{\"maxLength\":2}}", .instance = "{\"ab\":1}", .valid = true },
        .{ .schema = "{\"propertyNames\":{\"maxLength\":2}}", .instance = "{\"abc\":1}", .valid = false },
        .{ .schema = "{\"minProperties\":1,\"maxProperties\":2}", .instance = "{}", .valid = false },
        .{ .schema = "{\"minProperties\":1,\"maxProperties\":2}", .instance = "{\"a\":1,\"b\":2,\"c\":3}", .valid = false },
        .{ .schema = "{\"dependentRequired\":{\"a\":[\"b\"]}}", .instance = "{\"a\":1}", .valid = false },
        .{ .schema = "{\"dependentRequired\":{\"a\":[\"b\"]}}", .instance = "{\"a\":1,\"b\":1}", .valid = true },
        .{ .schema = "{\"dependentRequired\":{\"a\":[\"b\"]}}", .instance = "{\"b\":1}", .valid = true },
        .{ .schema = "{\"dependentSchemas\":{\"a\":{\"required\":[\"b\"]}}}", .instance = "{\"a\":1}", .valid = false },
        .{ .schema = "{\"dependentSchemas\":{\"a\":{\"required\":[\"b\"]}}}", .instance = "{\"a\":1,\"b\":2}", .valid = true },
        .{ .schema = "{\"required\":[\"a\"]}", .instance = "[]", .valid = true },
    });
}

test "arrays" {
    try runCases(&.{
        .{ .schema = "{\"items\":{\"type\":\"integer\"}}", .instance = "[1,2]", .valid = true },
        .{ .schema = "{\"items\":{\"type\":\"integer\"}}", .instance = "[1,\"a\"]", .valid = false },
        .{ .schema = "{\"prefixItems\":[{\"type\":\"integer\"},{\"type\":\"string\"}]}", .instance = "[1,\"a\",true]", .valid = true },
        .{ .schema = "{\"prefixItems\":[{\"type\":\"integer\"}],\"items\":false}", .instance = "[1,2]", .valid = false },
        .{ .schema = "{\"prefixItems\":[{\"type\":\"integer\"}],\"items\":false}", .instance = "[1]", .valid = true },
        .{ .schema = "{\"contains\":{\"type\":\"integer\"}}", .instance = "[\"a\",1]", .valid = true },
        .{ .schema = "{\"contains\":{\"type\":\"integer\"}}", .instance = "[\"a\"]", .valid = false },
        .{ .schema = "{\"contains\":{\"type\":\"integer\"},\"minContains\":2}", .instance = "[1]", .valid = false },
        .{ .schema = "{\"contains\":{\"type\":\"integer\"},\"minContains\":0}", .instance = "[]", .valid = true },
        .{ .schema = "{\"contains\":{\"type\":\"integer\"},\"maxContains\":1}", .instance = "[1,2]", .valid = false },
        .{ .schema = "{\"minItems\":1,\"maxItems\":2}", .instance = "[]", .valid = false },
        .{ .schema = "{\"minItems\":1,\"maxItems\":2}", .instance = "[1,2,3]", .valid = false },
        .{ .schema = "{\"uniqueItems\":true}", .instance = "[1,1.0]", .valid = false },
        .{ .schema = "{\"uniqueItems\":true}", .instance = "[{\"a\":1},{\"a\":2}]", .valid = true },
        .{ .schema = "{\"uniqueItems\":false}", .instance = "[1,1]", .valid = true },
    });
}

test "logic, conditionals and references" {
    try runCases(&.{
        .{ .schema = "{\"allOf\":[{\"type\":\"integer\"},{\"minimum\":2}]}", .instance = "2", .valid = true },
        .{ .schema = "{\"allOf\":[{\"type\":\"integer\"},{\"minimum\":2}]}", .instance = "1", .valid = false },
        .{ .schema = "{\"anyOf\":[{\"type\":\"integer\"},{\"type\":\"string\"}]}", .instance = "\"a\"", .valid = true },
        .{ .schema = "{\"anyOf\":[{\"type\":\"integer\"},{\"type\":\"string\"}]}", .instance = "null", .valid = false },
        .{ .schema = "{\"oneOf\":[{\"type\":\"integer\"},{\"minimum\":2}]}", .instance = "1", .valid = true },
        .{ .schema = "{\"oneOf\":[{\"type\":\"integer\"},{\"minimum\":2}]}", .instance = "3", .valid = false },
        .{ .schema = "{\"oneOf\":[{\"type\":\"integer\"},{\"minimum\":2}]}", .instance = "2.5", .valid = true },
        .{ .schema = "{\"not\":{\"type\":\"integer\"}}", .instance = "1", .valid = false },
        .{ .schema = "{\"not\":{\"type\":\"integer\"}}", .instance = "\"a\"", .valid = true },
        .{ .schema = "{\"if\":{\"type\":\"integer\"},\"then\":{\"minimum\":1},\"else\":{\"type\":\"string\"}}", .instance = "0", .valid = false },
        .{ .schema = "{\"if\":{\"type\":\"integer\"},\"then\":{\"minimum\":1},\"else\":{\"type\":\"string\"}}", .instance = "1", .valid = true },
        .{ .schema = "{\"if\":{\"type\":\"integer\"},\"then\":{\"minimum\":1},\"else\":{\"type\":\"string\"}}", .instance = "\"x\"", .valid = true },
        .{ .schema = "{\"if\":{\"type\":\"integer\"},\"then\":{\"minimum\":1},\"else\":{\"type\":\"string\"}}", .instance = "null", .valid = false },
        .{ .schema = "{\"if\":{\"type\":\"integer\"},\"then\":{\"minimum\":1}}", .instance = "null", .valid = true },
        .{ .schema = "{\"$defs\":{\"n\":{\"type\":\"integer\"}},\"$ref\":\"#/$defs/n\"}", .instance = "1", .valid = true },
        .{ .schema = "{\"$defs\":{\"n\":{\"type\":\"integer\"}},\"$ref\":\"#/$defs/n\"}", .instance = "\"a\"", .valid = false },
        .{ .schema = "{\"$defs\":{\"n\":{\"$anchor\":\"num\",\"type\":\"integer\"}},\"properties\":{\"a\":{\"$ref\":\"#num\"}}}", .instance = "{\"a\":\"x\"}", .valid = false },
        .{ .schema = "{\"$defs\":{\"a/b\":{\"type\":\"integer\"}},\"$ref\":\"#/$defs/a~1b\"}", .instance = "\"x\"", .valid = false },
        .{ .schema = "{\"$defs\":{\"a%b\":{\"type\":\"integer\"}},\"$ref\":\"#/$defs/a%25b\"}", .instance = "\"x\"", .valid = false },
        .{ .schema = "{\"prefixItems\":[{\"type\":\"integer\"}],\"$defs\":{\"x\":{\"$ref\":\"#/prefixItems/0\"}},\"items\":{\"$ref\":\"#/$defs/x\"}}", .instance = "[1,2]", .valid = true },
        .{ .schema = "{\"properties\":{\"next\":{\"$ref\":\"#\"},\"v\":{\"type\":\"integer\"}}}", .instance = "{\"v\":1,\"next\":{\"v\":\"x\"}}", .valid = false },
        .{ .schema = "{\"properties\":{\"next\":{\"$ref\":\"#\"},\"v\":{\"type\":\"integer\"}}}", .instance = "{\"v\":1,\"next\":{\"v\":2}}", .valid = true },
        .{ .schema = "{\"$ref\":\"#/$defs/a\",\"$defs\":{\"a\":{\"minimum\":1}},\"maximum\":2}", .instance = "3", .valid = false },
        .{ .schema = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"title\":\"t\",\"format\":\"email\",\"x-mcp-header\":\"X\",\"default\":1}", .instance = "\"not an email\"", .valid = true },
    });
}

test "unevaluatedProperties and unevaluatedItems" {
    try runCases(&.{
        // Adjacent keywords give annotations.
        .{ .schema = "{\"properties\":{\"a\":true},\"patternProperties\":{\"^x-\":true},\"unevaluatedProperties\":false}", .instance = "{\"a\":1,\"x-b\":2}", .valid = true },
        .{ .schema = "{\"properties\":{\"a\":true},\"unevaluatedProperties\":false}", .instance = "{\"a\":1,\"b\":2}", .valid = false },
        .{ .schema = "{\"properties\":{\"a\":true},\"unevaluatedProperties\":{\"type\":\"integer\"}}", .instance = "{\"a\":\"s\",\"b\":2}", .valid = true },
        .{ .schema = "{\"additionalProperties\":true,\"unevaluatedProperties\":false}", .instance = "{\"b\":2}", .valid = true },
        // Annotations come from in-place subschemas that pass.
        .{ .schema = "{\"allOf\":[{\"properties\":{\"a\":true}}],\"unevaluatedProperties\":false}", .instance = "{\"a\":1}", .valid = true },
        .{ .schema = "{\"anyOf\":[{\"properties\":{\"a\":{\"type\":\"integer\"}}},{\"properties\":{\"b\":true}}],\"unevaluatedProperties\":false}", .instance = "{\"a\":1,\"b\":2}", .valid = true },
        .{ .schema = "{\"anyOf\":[{\"properties\":{\"a\":{\"type\":\"integer\"}}},{\"properties\":{\"b\":true}}],\"unevaluatedProperties\":false}", .instance = "{\"a\":\"s\",\"b\":2}", .valid = false },
        .{ .schema = "{\"oneOf\":[{\"properties\":{\"a\":true},\"required\":[\"a\"]},{\"properties\":{\"b\":true},\"required\":[\"b\"]}],\"unevaluatedProperties\":false}", .instance = "{\"a\":1}", .valid = true },
        .{ .schema = "{\"if\":{\"properties\":{\"a\":{\"const\":1}}},\"then\":{\"properties\":{\"b\":true}},\"else\":{\"properties\":{\"c\":true}},\"unevaluatedProperties\":false}", .instance = "{\"a\":1,\"b\":2}", .valid = true },
        .{ .schema = "{\"if\":{\"properties\":{\"a\":{\"const\":1}}},\"then\":{\"properties\":{\"b\":true}},\"else\":{\"properties\":{\"c\":true}},\"unevaluatedProperties\":false}", .instance = "{\"a\":2,\"c\":2}", .valid = false },
        .{ .schema = "{\"dependentSchemas\":{\"a\":{\"properties\":{\"b\":true}}},\"properties\":{\"a\":true},\"unevaluatedProperties\":false}", .instance = "{\"a\":1,\"b\":2}", .valid = true },
        .{ .schema = "{\"$defs\":{\"d\":{\"properties\":{\"a\":true}}},\"$ref\":\"#/$defs/d\",\"unevaluatedProperties\":false}", .instance = "{\"a\":1}", .valid = true },
        // The keyword `not` gives no annotations.
        .{ .schema = "{\"not\":{\"not\":{\"properties\":{\"a\":true}}},\"unevaluatedProperties\":false}", .instance = "{\"a\":1}", .valid = false },
        // A sibling subschema cannot see the annotations of another sibling.
        .{ .schema = "{\"allOf\":[{\"properties\":{\"a\":true}},{\"unevaluatedProperties\":false}]}", .instance = "{\"a\":1}", .valid = false },
        // A nested unevaluated keyword evaluates all remaining names.
        .{ .schema = "{\"allOf\":[{\"unevaluatedProperties\":true}],\"unevaluatedProperties\":false}", .instance = "{\"a\":1}", .valid = true },
        // Annotations of a child location do not go to the parent location.
        .{ .schema = "{\"properties\":{\"o\":{\"properties\":{\"a\":true}}},\"unevaluatedProperties\":false}", .instance = "{\"o\":{\"a\":1}}", .valid = true },
        .{ .schema = "{\"properties\":{\"o\":{\"unevaluatedProperties\":false}}}", .instance = "{\"o\":{\"a\":1}}", .valid = false },
        // Items.
        .{ .schema = "{\"prefixItems\":[true],\"unevaluatedItems\":false}", .instance = "[1]", .valid = true },
        .{ .schema = "{\"prefixItems\":[true],\"unevaluatedItems\":false}", .instance = "[1,2]", .valid = false },
        .{ .schema = "{\"prefixItems\":[true],\"items\":true,\"unevaluatedItems\":false}", .instance = "[1,2]", .valid = true },
        .{ .schema = "{\"contains\":{\"type\":\"string\"},\"unevaluatedItems\":false}", .instance = "[\"a\",\"b\"]", .valid = true },
        .{ .schema = "{\"contains\":{\"type\":\"string\"},\"unevaluatedItems\":false}", .instance = "[\"a\",1]", .valid = false },
        .{ .schema = "{\"anyOf\":[{\"prefixItems\":[true,true]},{\"prefixItems\":[true]}],\"unevaluatedItems\":false}", .instance = "[1,2]", .valid = true },
        .{ .schema = "{\"allOf\":[{\"prefixItems\":[true]}],\"unevaluatedItems\":{\"type\":\"integer\"}}", .instance = "[\"a\",2]", .valid = true },
        .{ .schema = "{\"allOf\":[{\"prefixItems\":[true]}],\"unevaluatedItems\":{\"type\":\"integer\"}}", .instance = "[\"a\",\"b\"]", .valid = false },
        .{ .schema = "{\"unevaluatedItems\":false}", .instance = "{\"a\":1}", .valid = true },
        .{ .schema = "{\"unevaluatedProperties\":false}", .instance = "[1]", .valid = true },
    });
}

test "embedded resources and base URIs" {
    try runCases(&.{
        // A reference resolves against the base URI of its resource.
        .{ .schema = "{\"$id\":\"https://example.com/root.json\",\"$defs\":{\"a\":{\"$id\":\"a/schema.json\",\"$defs\":{\"n\":{\"type\":\"integer\"}},\"$ref\":\"#/$defs/n\"}},\"$ref\":\"a/schema.json\"}", .instance = "1", .valid = true },
        .{ .schema = "{\"$id\":\"https://example.com/root.json\",\"$defs\":{\"a\":{\"$id\":\"a/schema.json\",\"$defs\":{\"n\":{\"type\":\"integer\"}},\"$ref\":\"#/$defs/n\"}},\"$ref\":\"a/schema.json\"}", .instance = "\"x\"", .valid = false },
        .{ .schema = "{\"$id\":\"https://example.com/root.json\",\"$defs\":{\"a\":{\"$id\":\"a/schema.json\",\"$defs\":{\"n\":{\"type\":\"integer\"}}}},\"$ref\":\"https://example.com/a/schema.json#/$defs/n\"}", .instance = "\"x\"", .valid = false },
        // An `$id` resolves against the nearest parent resource.
        .{ .schema = "{\"$id\":\"https://example.com/x/root.json\",\"$defs\":{\"b\":{\"$id\":\"b/\",\"$defs\":{\"c\":{\"$id\":\"c.json\",\"type\":\"string\"}}}},\"$ref\":\"https://example.com/x/b/c.json\"}", .instance = "1", .valid = false },
        .{ .schema = "{\"$id\":\"https://example.com/x/root.json\",\"$defs\":{\"b\":{\"$id\":\"b/\",\"$defs\":{\"c\":{\"$id\":\"../c.json\",\"type\":\"string\"}}}},\"$ref\":\"c.json\"}", .instance = "\"s\"", .valid = true },
        // A reference to an anchor uses the anchors of the target resource.
        .{ .schema = "{\"$id\":\"https://example.com/root.json\",\"$defs\":{\"a\":{\"$anchor\":\"n\",\"type\":\"string\"},\"b\":{\"$id\":\"b.json\",\"$defs\":{\"n\":{\"$anchor\":\"n\",\"type\":\"integer\"}}}},\"$ref\":\"b.json#n\"}", .instance = "1", .valid = true },
        .{ .schema = "{\"$id\":\"https://example.com/root.json\",\"$defs\":{\"a\":{\"$anchor\":\"n\",\"type\":\"string\"},\"b\":{\"$id\":\"b.json\",\"$defs\":{\"n\":{\"$anchor\":\"n\",\"type\":\"integer\"}}}},\"$ref\":\"#n\"}", .instance = "1", .valid = false },
        // The fragment `#` in a subschema resource is the root of that resource.
        .{ .schema = "{\"$defs\":{\"list\":{\"$id\":\"urn:example:list\",\"type\":\"array\",\"items\":{\"$ref\":\"#\"}}},\"$ref\":\"urn:example:list\"}", .instance = "[[[]]]", .valid = true },
        .{ .schema = "{\"$defs\":{\"list\":{\"$id\":\"urn:example:list\",\"type\":\"array\",\"items\":{\"$ref\":\"#\"}}},\"$ref\":\"urn:example:list\"}", .instance = "[[1]]", .valid = false },
        // An `$id` in a value that is not a schema is not an identifier.
        .{ .schema = "{\"$defs\":{\"a\":{\"const\":{\"$id\":\"https://example.com/c.json\"}},\"b\":{\"$id\":\"https://example.com/c.json\",\"type\":\"string\"}},\"$ref\":\"https://example.com/c.json\"}", .instance = "\"s\"", .valid = true },
        // A reference into an unknown keyword uses the resource of that location.
        .{ .schema = "{\"$defs\":{\"r\":{\"$id\":\"https://example.com/r.json\",\"x-unknown\":{\"$ref\":\"#/$defs/n\"},\"$defs\":{\"n\":{\"type\":\"null\"}}}},\"$ref\":\"https://example.com/r.json#/x-unknown\"}", .instance = "null", .valid = true },
        .{ .schema = "{\"$defs\":{\"r\":{\"$id\":\"https://example.com/r.json\",\"x-unknown\":{\"$ref\":\"#/$defs/n\"},\"$defs\":{\"n\":{\"type\":\"null\"}}}},\"$ref\":\"https://example.com/r.json#/x-unknown\"}", .instance = "1", .valid = false },
    });
}

test "dynamic references and the dynamic scope" {
    try runCases(&.{
        // The outermost resource in the dynamic scope with the anchor name wins.
        .{ .schema = "{\"$id\":\"https://example.com/strict\",\"$dynamicAnchor\":\"node\",\"$ref\":\"tree\",\"unevaluatedProperties\":false,\"$defs\":{\"tree\":{\"$id\":\"tree\",\"$dynamicAnchor\":\"node\",\"type\":\"object\",\"properties\":{\"data\":true,\"children\":{\"type\":\"array\",\"items\":{\"$dynamicRef\":\"#node\"}}}}}}", .instance = "{\"children\":[{\"data\":1}]}", .valid = true },
        .{ .schema = "{\"$id\":\"https://example.com/strict\",\"$dynamicAnchor\":\"node\",\"$ref\":\"tree\",\"unevaluatedProperties\":false,\"$defs\":{\"tree\":{\"$id\":\"tree\",\"$dynamicAnchor\":\"node\",\"type\":\"object\",\"properties\":{\"data\":true,\"children\":{\"type\":\"array\",\"items\":{\"$dynamicRef\":\"#node\"}}}}}}", .instance = "{\"children\":[{\"daat\":1}]}", .valid = false },
        // Without the strict root, the tree schema allows other names.
        .{ .schema = "{\"$id\":\"https://example.com/root\",\"$ref\":\"tree\",\"$defs\":{\"tree\":{\"$id\":\"tree\",\"$dynamicAnchor\":\"node\",\"type\":\"object\",\"properties\":{\"data\":true,\"children\":{\"type\":\"array\",\"items\":{\"$dynamicRef\":\"#node\"}}}}}}", .instance = "{\"children\":[{\"daat\":1}]}", .valid = true },
        // A target without `$dynamicAnchor` makes `$dynamicRef` equal to `$ref`.
        .{ .schema = "{\"$id\":\"https://example.com/root\",\"$ref\":\"list\",\"$defs\":{\"foo\":{\"$dynamicAnchor\":\"items\",\"type\":\"string\"},\"list\":{\"$id\":\"list\",\"type\":\"array\",\"items\":{\"$dynamicRef\":\"#items\"},\"$defs\":{\"items\":{\"$anchor\":\"items\"}}}}}", .instance = "[1]", .valid = true },
        // A resource that the evaluation left is not in the dynamic scope.
        .{ .schema = "{\"$id\":\"https://example.com/main\",\"if\":{\"$id\":\"first\",\"$defs\":{\"t\":{\"$dynamicAnchor\":\"t\",\"type\":\"number\"}}},\"then\":{\"$id\":\"second\",\"$ref\":\"start\",\"$defs\":{\"t\":{\"$dynamicAnchor\":\"t\",\"type\":\"null\"}}},\"$defs\":{\"start\":{\"$id\":\"start\",\"$dynamicRef\":\"inner#t\"},\"inner\":{\"$id\":\"inner\",\"$dynamicAnchor\":\"t\",\"type\":\"string\"}}}", .instance = "null", .valid = true },
        .{ .schema = "{\"$id\":\"https://example.com/main\",\"if\":{\"$id\":\"first\",\"$defs\":{\"t\":{\"$dynamicAnchor\":\"t\",\"type\":\"number\"}}},\"then\":{\"$id\":\"second\",\"$ref\":\"start\",\"$defs\":{\"t\":{\"$dynamicAnchor\":\"t\",\"type\":\"null\"}}},\"$defs\":{\"start\":{\"$id\":\"start\",\"$dynamicRef\":\"inner#t\"},\"inner\":{\"$id\":\"inner\",\"$dynamicAnchor\":\"t\",\"type\":\"string\"}}}", .instance = "1", .valid = false },
        .{ .schema = "{\"$id\":\"https://example.com/main\",\"if\":{\"$id\":\"first\",\"$defs\":{\"t\":{\"$dynamicAnchor\":\"t\",\"type\":\"number\"}}},\"then\":{\"$id\":\"second\",\"$ref\":\"start\",\"$defs\":{\"t\":{\"$dynamicAnchor\":\"t\",\"type\":\"null\"}}},\"$defs\":{\"start\":{\"$id\":\"start\",\"$dynamicRef\":\"inner#t\"},\"inner\":{\"$id\":\"inner\",\"$dynamicAnchor\":\"t\",\"type\":\"string\"}}}", .instance = "\"s\"", .valid = false },
        // A `$dynamicRef` with a JSON pointer is equal to `$ref`.
        .{ .schema = "{\"$defs\":{\"a\":{\"$dynamicAnchor\":\"a\",\"type\":\"integer\"}},\"$dynamicRef\":\"#/$defs/a\"}", .instance = "\"x\"", .valid = false },
    });
}

test "content, format and unknown keywords are annotations" {
    try runCases(&.{
        // The content keywords are annotations. The validator does not decode or parse the string.
        .{ .schema = "{\"contentEncoding\":\"base64\"}", .instance = "\"not base64!\"", .valid = true },
        .{ .schema = "{\"contentMediaType\":\"application/json\"}", .instance = "\"{not json\"", .valid = true },
        .{ .schema = "{\"contentMediaType\":\"application/json\",\"contentSchema\":{\"type\":\"object\",\"required\":[\"a\"]}}", .instance = "\"[]\"", .valid = true },
        .{ .schema = "{\"contentEncoding\":\"base64\",\"contentMediaType\":\"application/json\",\"contentSchema\":false}", .instance = "\"e30=\"", .valid = true },
        .{ .schema = "{\"contentEncoding\":\"base64\",\"type\":\"string\"}", .instance = "1", .valid = false },
        // The keyword `format` is an annotation.
        .{ .schema = "{\"format\":\"date-time\"}", .instance = "\"yesterday\"", .valid = true },
        .{ .schema = "{\"format\":\"ipv4\"}", .instance = "\"999.1.1.1\"", .valid = true },
        // The keywords of 2019-09 are unknown keywords.
        .{ .schema = "{\"$recursiveAnchor\":true,\"$recursiveRef\":\"#\",\"type\":\"integer\"}", .instance = "1", .valid = true },
        .{ .schema = "{\"$recursiveAnchor\":true,\"$recursiveRef\":\"#\",\"type\":\"integer\"}", .instance = "\"x\"", .valid = false },
    });
}

test "URI reference resolution" {
    // RFC 3986, section 5.4.
    const base = "http://a/b/c/d;p?q";
    const cases = [_][2][]const u8{
        .{ "g:h", "g:h" },
        .{ "g", "http://a/b/c/g" },
        .{ "./g", "http://a/b/c/g" },
        .{ "g/", "http://a/b/c/g/" },
        .{ "/g", "http://a/g" },
        .{ "//g", "http://g" },
        .{ "?y", "http://a/b/c/d;p?y" },
        .{ "g?y", "http://a/b/c/g?y" },
        .{ "#s", "http://a/b/c/d;p?q#s" },
        .{ "g#s", "http://a/b/c/g#s" },
        .{ "g?y#s", "http://a/b/c/g?y#s" },
        .{ ";x", "http://a/b/c/;x" },
        .{ "g;x", "http://a/b/c/g;x" },
        .{ "g;x?y#s", "http://a/b/c/g;x?y#s" },
        .{ "", "http://a/b/c/d;p?q" },
        .{ ".", "http://a/b/c/" },
        .{ "./", "http://a/b/c/" },
        .{ "..", "http://a/b/" },
        .{ "../", "http://a/b/" },
        .{ "../g", "http://a/b/g" },
        .{ "../..", "http://a/" },
        .{ "../../", "http://a/" },
        .{ "../../g", "http://a/g" },
        .{ "../../../g", "http://a/g" },
        .{ "../../../../g", "http://a/g" },
        .{ "/./g", "http://a/g" },
        .{ "/../g", "http://a/g" },
        .{ "g.", "http://a/b/c/g." },
        .{ ".g", "http://a/b/c/.g" },
        .{ "g..", "http://a/b/c/g.." },
        .{ "..g", "http://a/b/c/..g" },
        .{ "./../g", "http://a/b/g" },
        .{ "./g/.", "http://a/b/c/g/" },
        .{ "g/./h", "http://a/b/c/g/h" },
        .{ "g/../h", "http://a/b/c/h" },
        .{ "g;x=1/./y", "http://a/b/c/g;x=1/y" },
        .{ "g;x=1/../y", "http://a/b/c/y" },
        .{ "g?y/./x", "http://a/b/c/g?y/./x" },
        .{ "g?y/../x", "http://a/b/c/g?y/../x" },
        .{ "g#s/./x", "http://a/b/c/g#s/./x" },
        .{ "g#s/../x", "http://a/b/c/g#s/../x" },
        .{ "http:g", "http:g" },
    };
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    for (cases) |case| {
        try std.testing.expectEqualStrings(case[1], try resolveUri(arena_state.allocator(), base, case[0]));
    }
}

test "compile rejects unsupported and remote schemas" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // `$schema` is valid only at the root of a resource.
    try std.testing.expectError(error.UnsupportedKeyword, compileText(arena, "{\"properties\":{\"a\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}}}", .{}));
    _ = try compileText(arena, "{\"properties\":{\"a\":{\"$id\":\"x\",\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}}}", .{});
    try std.testing.expectError(error.UnsupportedDialect, compileText(arena, "{\"properties\":{\"a\":{\"$id\":\"x\",\"$schema\":\"http://json-schema.org/draft-07/schema#\"}}}", .{}));
    try std.testing.expectError(error.RemoteRef, compileText(arena, "{\"$ref\":\"https://example.com/s.json\"}", .{}));
    try std.testing.expectError(error.RemoteRef, compileText(arena, "{\"$dynamicRef\":\"other.json#x\"}", .{}));
    // A reference to an `$id` in a subschema is local.
    _ = try compileText(arena, "{\"$ref\":\"https://example.com/s.json\",\"$defs\":{\"s\":{\"$id\":\"https://example.com/s.json\"}}}", .{});
    try std.testing.expectError(error.UnsupportedDialect, compileText(arena, "{\"$schema\":\"http://json-schema.org/draft-07/schema#\"}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$ref\":\"#/$defs/missing\"}", .{}));
    // A reference into an unknown member is compiled too.
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$ref\":\"#/x\",\"x\":{\"minimum\":\"a\"}}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$ref\":\"#/x\",\"x\":5}", .{}));
    // A reference to the root or to a known subschema does not compile it again.
    _ = try compileText(arena, "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:x\",\"properties\":{\"n\":{\"$ref\":\"#\"}}}", .{});
    _ = try compileText(arena, "{\"properties\":{\"a\":{\"type\":\"integer\"},\"b\":{\"type\":\"string\"}},\"$ref\":\"#/properties/a\"}", .{ .limits = .{ .max_subschemas = 3 } });
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"items\":[{}]}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"type\":\"int\"}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"multipleOf\":0}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"required\":[1]}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"allOf\":[]}", .{}));
    try std.testing.expectError(error.DuplicateAnchor, compileText(arena, "{\"$defs\":{\"a\":{\"$anchor\":\"x\"},\"b\":{\"$anchor\":\"x\"}}}", .{}));
    try std.testing.expectError(error.Syntax, compileText(arena, "{", .{}));
    // Identifiers: a fragment other than an empty one, two resources with one URI.
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$defs\":{\"a\":{\"$id\":\"a.json#x\"}}}", .{}));
    _ = try compileText(arena, "{\"$defs\":{\"a\":{\"$id\":\"a.json#\"}}}", .{});
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$defs\":{\"a\":{\"$id\":\"a.json\"},\"b\":{\"$id\":\"./a.json\"}}}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$id\":1}", .{}));
    // Anchors are local to their resource.
    _ = try compileText(arena, "{\"$defs\":{\"a\":{\"$anchor\":\"x\"},\"b\":{\"$id\":\"b.json\",\"$anchor\":\"x\"}}}", .{});
    try std.testing.expectError(error.DuplicateAnchor, compileText(arena, "{\"$defs\":{\"a\":{\"$anchor\":\"x\"},\"b\":{\"$dynamicAnchor\":\"x\"}}}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$dynamicAnchor\":\"1x\"}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"$ref\":\"#nothing\"}", .{}));
    // The new keywords check their operands.
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"unevaluatedProperties\":[]}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"unevaluatedItems\":1}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"contentEncoding\":1}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"contentSchema\":{\"type\":\"int\"}}", .{}));
    // A count can be a number with a zero fraction.
    _ = try compileText(arena, "{\"maxLength\":2.0}", .{});
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"maxLength\":2.5}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"minItems\":-1}", .{}));
    // Limits.
    try std.testing.expectError(error.TooManySubschemas, compileText(arena, "{\"properties\":{\"a\":{},\"b\":{}}}", .{ .limits = .{ .max_subschemas = 2 } }));
    try std.testing.expectError(error.SchemaTooDeep, compileText(arena, "{\"properties\":{\"a\":{\"properties\":{\"b\":{}}}}}", .{ .limits = .{ .max_depth = 1 } }));
}

test "pattern, patternProperties and propertyNames" {
    try runCases(&.{
        .{ .schema = "{\"pattern\":\"^[a-z]+$\"}", .instance = "\"abc\"", .valid = true },
        .{ .schema = "{\"pattern\":\"^[a-z]+$\"}", .instance = "\"abC\"", .valid = false },
        // The search is not anchored.
        .{ .schema = "{\"pattern\":\"b\"}", .instance = "\"abc\"", .valid = true },
        .{ .schema = "{\"pattern\":\"^b\"}", .instance = "\"abc\"", .valid = false },
        // Other types are ignored.
        .{ .schema = "{\"pattern\":\"^a\"}", .instance = "1", .valid = true },
        .{ .schema = "{\"pattern\":\"^.$\"}", .instance = "\"\\ud83d\\ude00\"", .valid = true },
        .{ .schema = "{\"pattern\":\"\\\\p{ASCII}\",\"minLength\":2}", .instance = "\"a\"", .valid = false },
        .{ .schema = "{\"patternProperties\":{\"^x-\":{\"type\":\"string\"}}}", .instance = "{\"x-a\":\"s\",\"b\":1}", .valid = true },
        .{ .schema = "{\"patternProperties\":{\"^x-\":{\"type\":\"string\"}}}", .instance = "{\"x-a\":1}", .valid = false },
        // Every matching expression applies.
        .{ .schema = "{\"patternProperties\":{\"a\":{\"minimum\":2},\"b\":{\"maximum\":3}}}", .instance = "{\"ab\":4}", .valid = false },
        .{ .schema = "{\"patternProperties\":{\"a\":{\"minimum\":2},\"b\":{\"maximum\":3}}}", .instance = "{\"ab\":3}", .valid = true },
        // Names that `patternProperties` matches are not additional.
        .{ .schema = "{\"properties\":{\"id\":{}},\"patternProperties\":{\"^x-\":{}},\"additionalProperties\":false}", .instance = "{\"id\":1,\"x-y\":2}", .valid = true },
        .{ .schema = "{\"properties\":{\"id\":{}},\"patternProperties\":{\"^x-\":{}},\"additionalProperties\":false}", .instance = "{\"id\":1,\"y\":2}", .valid = false },
        // `properties` and `patternProperties` both apply to one name.
        .{ .schema = "{\"properties\":{\"xa\":{\"type\":\"integer\"}},\"patternProperties\":{\"^x\":{\"minimum\":5}}}", .instance = "{\"xa\":3}", .valid = false },
        .{ .schema = "{\"patternProperties\":{\"^\\\\d+$\":false}}", .instance = "{\"12\":null}", .valid = false },
        .{ .schema = "{\"propertyNames\":{\"pattern\":\"^[a-z_]+$\"}}", .instance = "{\"ok_name\":1}", .valid = true },
        .{ .schema = "{\"propertyNames\":{\"pattern\":\"^[a-z_]+$\"}}", .instance = "{\"Bad\":1}", .valid = false },
    });
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // With the opt-in, an unsupported `pattern` is an annotation and an unsupported
    // `patternProperties` expression matches no name.
    const loose: Options = .{ .allow_unsupported_keywords = true };
    const ignored = try compileText(arena, "{\"pattern\":\"(?=a)\",\"patternProperties\":{\"(.)\\\\1\":true},\"additionalProperties\":{\"type\":\"string\"}}", loose);
    try std.testing.expect((try validate(arena, &ignored, .{ .string = "b" })).valid);
    const obj = try std.json.parseFromSliceLeaky(Value, arena, "{\"aa\":5}", .{});
    try std.testing.expect(!(try validate(arena, &ignored, obj)).valid);
    // The failure names the keyword and the pattern.
    const s = try compileText(arena, "{\"properties\":{\"a\":{\"pattern\":\"^\\\\d+$\"}}}", .{});
    const bad = try std.json.parseFromSliceLeaky(Value, arena, "{\"a\":\"12x\"}", .{});
    const result = try validate(arena, &s, bad);
    try std.testing.expect(!result.valid);
    try std.testing.expectEqualStrings("pattern", result.failures[0].keyword);
    try std.testing.expectEqualStrings("/a", result.failures[0].instance_path);
    try std.testing.expectEqualStrings("string does not match the pattern \"^\\d+$\"", result.failures[0].message);
    // One expression that occurs two times compiles one time.
    const twice = try compileText(arena, "{\"pattern\":\"a\",\"patternProperties\":{\"a\":{\"pattern\":\"a\"}}}", .{});
    try std.testing.expectEqual(1, twice.patterns.count());
}

test "regular expression compile errors and limits" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"pattern\":1}", .{}));
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"patternProperties\":[]}", .{}));
    try std.testing.expectError(error.InvalidRegex, compileText(arena, "{\"pattern\":\"(\"}", .{}));
    try std.testing.expectError(error.InvalidRegex, compileText(arena, "{\"patternProperties\":{\"[\":{}}}", .{}));
    try std.testing.expectError(error.InvalidRegex, compileText(arena, "{\"pattern\":\"(\"}", .{ .allow_unsupported_keywords = true }));
    try std.testing.expectError(error.UnsupportedRegex, compileText(arena, "{\"pattern\":\"(a)\\\\1\"}", .{}));
    try std.testing.expectError(error.UnsupportedRegex, compileText(arena, "{\"properties\":{\"a\":{\"pattern\":\"(?<=a)b\"}}}", .{}));
    try std.testing.expectError(error.UnsupportedRegex, compileText(arena, "{\"patternProperties\":{\"\\\\p{L}\":{}}}", .{}));
    // Subschemas of `patternProperties` are compiled.
    try std.testing.expectError(error.InvalidSchema, compileText(arena, "{\"patternProperties\":{\"a\":{\"type\":\"int\"}}}", .{}));
    // `max_pattern_bytes`.
    try std.testing.expectError(error.RegexTooLarge, compileText(arena, "{\"pattern\":\"abcde\"}", .{ .limits = .{ .max_pattern_bytes = 4 } }));
    _ = try compileText(arena, "{\"pattern\":\"abcd\"}", .{ .limits = .{ .max_pattern_bytes = 4 } });
    // `max_regex_states`.
    try std.testing.expectError(error.RegexTooLarge, compileText(arena, "{\"pattern\":\"^[a-z]{1,64}$\"}", .{ .limits = .{ .max_regex_states = 64 } }));
    _ = try compileText(arena, "{\"pattern\":\"^[a-z]{1,64}$\"}", .{});
    try std.testing.expectError(error.RegexTooLarge, compileText(arena, "{\"pattern\":\"(a{100}){100}\"}", .{}));
}

test "failure report and evaluation limits" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const schema = try compileText(arena, "{\"properties\":{\"a\":{\"items\":{\"type\":\"integer\"}},\"b~\":{\"type\":\"string\"}},\"required\":[\"c\"]}", .{ .limits = .{ .max_errors = 2 } });
    const inst = try std.json.parseFromSliceLeaky(Value, arena, "{\"a\":[1,\"x\"],\"b~\":1}", .{});
    const result = try validate(arena, &schema, inst);
    try std.testing.expect(!result.valid);
    try std.testing.expect(result.truncated);
    try std.testing.expectEqual(2, result.failures.len);
    try std.testing.expectEqualStrings("required", result.failures[0].keyword);
    try std.testing.expectEqualStrings("", result.failures[0].instance_path);
    try std.testing.expectEqualStrings("/a/1", result.failures[1].instance_path);
    try std.testing.expectEqualStrings("type", result.failures[1].keyword);

    const looping = try compileText(arena, "{\"$defs\":{\"a\":{\"$ref\":\"#/$defs/b\"},\"b\":{\"$ref\":\"#/$defs/a\"}},\"$ref\":\"#/$defs/a\"}", .{ .limits = .{ .max_ref_hops = 8 } });
    try std.testing.expectError(error.TooManyRefHops, validate(arena, &looping, .{ .integer = 1 }));

    const budget = try compileText(arena, "{\"items\":{\"type\":\"integer\"}}", .{ .limits = .{ .eval_budget = 3 } });
    const many = try std.json.parseFromSliceLeaky(Value, arena, "[1,2,3,4]", .{});
    try std.testing.expectError(error.EvalBudgetExceeded, validate(arena, &budget, many));

    // The set of evaluated items costs one unit of the budget per 64 items.
    const three = try std.json.parseFromSliceLeaky(Value, arena, "[1,2,3]", .{});
    const tight = try compileText(arena, "{\"unevaluatedItems\":{\"type\":\"integer\"}}", .{ .limits = .{ .eval_budget = 4 } });
    try std.testing.expectError(error.EvalBudgetExceeded, validate(arena, &tight, three));
    const enough = try compileText(arena, "{\"unevaluatedItems\":{\"type\":\"integer\"}}", .{ .limits = .{ .eval_budget = 5 } });
    try std.testing.expect((try validate(arena, &enough, three)).valid);

    const deep = try compileText(arena, "{\"properties\":{\"n\":{\"$ref\":\"#\"}}}", .{ .limits = .{ .max_depth = 2 } });
    const nested = try std.json.parseFromSliceLeaky(Value, arena, "{\"n\":{\"n\":{\"n\":{}}}}", .{});
    try std.testing.expectError(error.InstanceTooDeep, validate(arena, &deep, nested));
}
