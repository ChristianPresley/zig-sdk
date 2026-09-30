//! JSON Schema 2020-12 subset validator over `std.json.Value`.
//!
//! The validator has no dynamic scope and no annotation collection. The compiler rejects the
//! keywords that need them. With `Options.allow_unsupported_keywords`, the compiler ignores
//! them. The compiler always rejects remote references. The validator keeps annotation
//! keywords such as `title`, `description`, `default`, `format` and `x-*` keys, but does not
//! evaluate them.
//!
//! The keywords `pattern` and `patternProperties` use the engine in `regex.zig`. The compiler
//! compiles each regular expression one time and keeps the program in the `Schema`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Limits = @import("../Limits.zig");
const regex = @import("regex.zig");

pub const dialect_2020_12 = "https://json-schema.org/draft/2020-12/schema";

pub const Options = struct {
    /// Ignore unsupported keywords. Without this option, the compiler rejects the schema.
    allow_unsupported_keywords: bool = false,
    limits: Limits.Schema = .{},
};

pub const CompileError = error{
    OutOfMemory,
    /// `$schema` names a dialect other than 2020-12.
    UnsupportedDialect,
    /// A keyword from the unsupported list is present.
    UnsupportedKeyword,
    /// A `$ref` points outside the document.
    RemoteRef,
    /// A keyword has an operand of the wrong shape, or a `$ref` has no target.
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
    anchors: std.StringHashMapUnmanaged(Value),
    options: Options,
    /// The compiled `pattern` values and `patternProperties` keys, by source text.
    patterns: std.StringHashMapUnmanaged(regex.Regex) = .empty,
    /// The largest match buffer that one of `patterns` needs, in `u32` items.
    pattern_buffer_len: usize = 0,
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

const unsupported_keywords = std.StaticStringMap(void).initComptime(.{
    .{"unevaluatedProperties"},
    .{"unevaluatedItems"},
    .{"$dynamicRef"},
    .{"$dynamicAnchor"},
    .{"$recursiveRef"},
    .{"$recursiveAnchor"},
    .{"contentEncoding"},
    .{"contentMediaType"},
    .{"contentSchema"},
});

const schema_map_keywords = [_][]const u8{ "properties", "$defs", "definitions", "dependentSchemas" };
const schema_list_keywords = [_][]const u8{ "prefixItems", "allOf", "anyOf", "oneOf" };
const schema_single_keywords = [_][]const u8{ "items", "additionalProperties", "propertyNames", "contains", "not", "if", "then", "else" };
const type_names = [_][]const u8{ "null", "boolean", "object", "array", "number", "integer", "string" };

const Compiler = struct {
    arena: Allocator,
    options: Options,
    count: u32 = 0,
    anchors: std.StringHashMapUnmanaged(Value) = .empty,
    refs: std.ArrayList([]const u8) = .empty,
    patterns: std.StringHashMapUnmanaged(regex.Regex) = .empty,
    pattern_buffer_len: usize = 0,
    /// The schema objects that the walk compiled, by the address of their key storage.
    visited: std.AutoHashMapUnmanaged(usize, void) = .empty,

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

    fn node(self: *Compiler, value: Value, depth: u16, is_root: bool) CompileError!void {
        switch (value) {
            .bool => return,
            .object => |obj| {
                if (depth > self.options.limits.max_depth) return error.SchemaTooDeep;
                if (obj.count() > 0) try self.visited.put(self.arena, @intFromPtr(obj.keys().ptr), {});
                self.count += 1;
                if (self.count > self.options.limits.max_subschemas) return error.TooManySubschemas;
                var it = obj.iterator();
                while (it.next()) |kv| try self.keyword(kv.key_ptr.*, kv.value_ptr.*, depth, is_root);
            },
            else => return error.InvalidSchema,
        }
    }

    fn keyword(self: *Compiler, key: []const u8, value: Value, depth: u16, is_root: bool) CompileError!void {
        if (unsupported_keywords.has(key)) {
            if (self.options.allow_unsupported_keywords) return;
            return error.UnsupportedKeyword;
        }
        if (std.mem.eql(u8, key, "$schema")) {
            if (!is_root) return error.UnsupportedKeyword;
            if (value != .string or !std.mem.eql(u8, value.string, dialect_2020_12)) return error.UnsupportedDialect;
            return;
        }
        if (std.mem.eql(u8, key, "$id")) {
            if (value != .string) return error.InvalidSchema;
            if (!is_root) {
                if (self.options.allow_unsupported_keywords) return;
                return error.UnsupportedKeyword;
            }
            return;
        }
        if (std.mem.eql(u8, key, "$anchor")) {
            if (value != .string or !isPlainName(value.string)) return error.InvalidSchema;
            return;
        }
        if (std.mem.eql(u8, key, "$ref")) {
            if (value != .string) return error.InvalidSchema;
            if (!std.mem.startsWith(u8, value.string, "#")) return error.RemoteRef;
            try self.refs.append(self.arena, value.string);
            return;
        }
        for (schema_map_keywords) |k| if (std.mem.eql(u8, key, k)) {
            if (value != .object) return error.InvalidSchema;
            var it = value.object.iterator();
            while (it.next()) |kv| try self.node(kv.value_ptr.*, depth + 1, false);
            return;
        };
        for (schema_list_keywords) |k| if (std.mem.eql(u8, key, k)) {
            if (value != .array or value.array.items.len == 0) return error.InvalidSchema;
            for (value.array.items) |item| try self.node(item, depth + 1, false);
            return;
        };
        for (schema_single_keywords) |k| if (std.mem.eql(u8, key, k)) {
            if (value == .array) return error.InvalidSchema;
            try self.node(value, depth + 1, false);
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
            if (value != .integer or value.integer < 0) return error.InvalidSchema;
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
                try self.node(kv.value_ptr.*, depth + 1, false);
            }
            return;
        }
        // Everything else is an annotation or an unknown keyword and is ignored.
    }
};

fn isCountKeyword(key: []const u8) bool {
    const names = [_][]const u8{ "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties", "minContains", "maxContains" };
    for (names) |n| if (std.mem.eql(u8, key, n)) return true;
    return false;
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

/// Compile a schema: check the dialect, reject unsupported keywords and remote references,
/// compile the regular expressions, collect anchors and resolve every local reference once.
pub fn compile(arena: Allocator, root: Value, options: Options) CompileError!Schema {
    var c: Compiler = .{ .arena = arena, .options = options };
    try c.node(root, 0, true);
    try collectAnchors(arena, root, &c.anchors);
    var schema: Schema = .{
        .root = root,
        .anchors = c.anchors,
        .options = options,
        .patterns = c.patterns,
        .pattern_buffer_len = c.pattern_buffer_len,
    };
    // A reference can point into a member that the walk above does not visit, such as an
    // unknown keyword. Compile each target too, so that validation never meets an unchecked
    // operand. The list grows while the loop runs, because a target can hold references.
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var i: usize = 0;
    while (i < c.refs.items.len) : (i += 1) {
        const ref = c.refs.items[i];
        const target = resolveRef(&schema, ref) orelse return error.InvalidSchema;
        if ((try seen.getOrPut(arena, ref)).found_existing) continue;
        // The walk above already compiled the root and every schema under a known keyword.
        if (target == .object and target.object.count() > 0 and c.visited.contains(@intFromPtr(target.object.keys().ptr))) continue;
        try c.node(target, 0, false);
    }
    schema.patterns = c.patterns;
    schema.pattern_buffer_len = c.pattern_buffer_len;
    return schema;
}

fn collectAnchors(arena: Allocator, node: Value, anchors: *std.StringHashMapUnmanaged(Value)) CompileError!void {
    switch (node) {
        .object => |obj| {
            if (obj.get("$anchor")) |a| {
                if (a == .string) {
                    const gop = try anchors.getOrPut(arena, a.string);
                    if (gop.found_existing) return error.DuplicateAnchor;
                    gop.value_ptr.* = node;
                }
            }
            var it = obj.iterator();
            while (it.next()) |kv| try collectAnchors(arena, kv.value_ptr.*, anchors);
        },
        .array => |a| for (a.items) |item| try collectAnchors(arena, item, anchors),
        else => {},
    }
}

fn resolveRef(schema: *const Schema, ref: []const u8) ?Value {
    if (ref.len == 0 or std.mem.eql(u8, ref, "#")) return schema.root;
    if (!std.mem.startsWith(u8, ref, "#")) return null;
    const fragment = ref[1..];
    if (fragment[0] != '/') return schema.anchors.get(fragment);
    var current = schema.root;
    var it = std.mem.splitScalar(u8, fragment[1..], '/');
    var buf: [256]u8 = undefined;
    while (it.next()) |raw| {
        const token = unescapeToken(&buf, raw) orelse return null;
        switch (current) {
            .object => |obj| current = obj.get(token) orelse return null,
            .array => |arr| {
                const index = std.fmt.parseInt(usize, token, 10) catch return null;
                if (index >= arr.items.len) return null;
                current = arr.items[index];
            },
            else => return null,
        }
    }
    return switch (current) {
        .object, .bool => current,
        else => null,
    };
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

    fn child(self: *Evaluator, node: Value, inst: Value, seg: Segment, depth: u16, collect: bool) ValidateError!bool {
        if (depth + 1 > self.limits.max_depth) return error.InstanceTooDeep;
        try self.path.append(self.arena, seg);
        defer _ = self.path.pop();
        return self.eval(node, inst, depth + 1, collect);
    }

    fn eval(self: *Evaluator, node: Value, inst: Value, depth: u16, collect: bool) ValidateError!bool {
        switch (node) {
            .bool => |b| {
                if (b) return true;
                return self.fail(collect, "false", "the schema rejects every value", .{});
            },
            .object => |obj| {
                if (self.budget == 0) return error.EvalBudgetExceeded;
                self.budget -= 1;
                var ok = true;
                if (obj.get("$ref")) |r| {
                    if (self.ref_hops >= self.limits.max_ref_hops) return error.TooManyRefHops;
                    self.ref_hops += 1;
                    defer self.ref_hops -= 1;
                    const target = resolveRef(self.schema, r.string) orelse return self.fail(collect, "$ref", "unresolved reference", .{});
                    if (!try self.eval(target, inst, depth, collect)) ok = false;
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
                    .object => if (!try self.checkObject(obj, inst, depth, collect)) {
                        ok = false;
                    },
                    .array => if (!try self.checkArray(obj, inst, depth, collect)) {
                        ok = false;
                    },
                    else => {},
                }
                if (!try self.checkLogic(obj, inst, depth, collect)) ok = false;
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
        if (min) |m| if (len < @as(usize, @intCast(m.integer))) {
            ok = try self.fail(collect, "minLength", "string is shorter than {d} characters", .{m.integer}) and ok;
        };
        if (max) |m| if (len > @as(usize, @intCast(m.integer))) {
            ok = try self.fail(collect, "maxLength", "string is longer than {d} characters", .{m.integer}) and ok;
        };
        return ok;
    }

    fn checkObject(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, depth: u16, collect: bool) ValidateError!bool {
        var ok = true;
        const members = inst.object;
        if (obj.get("required")) |req| for (req.array.items) |name| {
            if (!members.contains(name.string)) {
                ok = try self.fail(collect, "required", "missing required property \"{s}\"", .{name.string}) and ok;
            }
        };
        if (obj.get("minProperties")) |m| if (members.count() < @as(usize, @intCast(m.integer))) {
            ok = try self.fail(collect, "minProperties", "object has fewer than {d} properties", .{m.integer}) and ok;
        };
        if (obj.get("maxProperties")) |m| if (members.count() > @as(usize, @intCast(m.integer))) {
            ok = try self.fail(collect, "maxProperties", "object has more than {d} properties", .{m.integer}) and ok;
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
                if (!try self.eval(kv.value_ptr.*, inst, depth, collect)) ok = false;
            }
        }
        const props = obj.get("properties");
        const pattern_props = obj.get("patternProperties");
        const additional = obj.get("additionalProperties");
        const names_schema = obj.get("propertyNames");
        var it = members.iterator();
        while (it.next()) |kv| {
            const name = kv.key_ptr.*;
            var covered = false;
            if (props) |p| if (p.object.get(name)) |sub| {
                covered = true;
                if (!try self.child(sub, kv.value_ptr.*, .{ .key = name }, depth, collect)) ok = false;
            };
            // A name that a `patternProperties` expression matches is not additional.
            if (pattern_props) |pp| if (pp == .object) {
                var pit = pp.object.iterator();
                while (pit.next()) |entry| {
                    const matched = self.matchPattern(entry.key_ptr.*, name) orelse continue;
                    if (!matched) continue;
                    covered = true;
                    if (!try self.child(entry.value_ptr.*, kv.value_ptr.*, .{ .key = name }, depth, collect)) ok = false;
                }
            };
            if (!covered) if (additional) |a| {
                if (!try self.child(a, kv.value_ptr.*, .{ .key = name }, depth, collect)) ok = false;
            };
            if (names_schema) |ns| {
                if (!try self.child(ns, .{ .string = name }, .{ .key = name }, depth, collect)) ok = false;
            }
        }
        return ok;
    }

    fn checkArray(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, depth: u16, collect: bool) ValidateError!bool {
        var ok = true;
        const items = inst.array.items;
        if (obj.get("minItems")) |m| if (items.len < @as(usize, @intCast(m.integer))) {
            ok = try self.fail(collect, "minItems", "array has fewer than {d} items", .{m.integer}) and ok;
        };
        if (obj.get("maxItems")) |m| if (items.len > @as(usize, @intCast(m.integer))) {
            ok = try self.fail(collect, "maxItems", "array has more than {d} items", .{m.integer}) and ok;
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
            }
        }
        if (obj.get("items")) |sub| {
            var i = prefix_len;
            while (i < items.len) : (i += 1) {
                if (!try self.child(sub, items[i], .{ .index = i }, depth, collect)) ok = false;
            }
        }
        if (obj.get("contains")) |sub| {
            var matched: usize = 0;
            for (items, 0..) |item, i| {
                if (try self.child(sub, item, .{ .index = i }, depth, false)) matched += 1;
            }
            const min: usize = if (obj.get("minContains")) |m| @intCast(m.integer) else 1;
            if (matched < min) {
                ok = try self.fail(collect, "contains", "array needs at least {d} matching items", .{min}) and ok;
            }
            if (obj.get("maxContains")) |m| if (matched > @as(usize, @intCast(m.integer))) {
                ok = try self.fail(collect, "maxContains", "array has more than {d} matching items", .{m.integer}) and ok;
            };
        }
        return ok;
    }

    fn checkLogic(self: *Evaluator, obj: std.json.ObjectMap, inst: Value, depth: u16, collect: bool) ValidateError!bool {
        var ok = true;
        if (obj.get("allOf")) |list| for (list.array.items) |sub| {
            if (!try self.eval(sub, inst, depth, collect)) ok = false;
        };
        if (obj.get("anyOf")) |list| {
            var any = false;
            for (list.array.items) |sub| if (try self.eval(sub, inst, depth, false)) {
                any = true;
                break;
            };
            if (!any) ok = try self.fail(collect, "anyOf", "value matches none of the alternatives", .{}) and ok;
        }
        if (obj.get("oneOf")) |list| {
            var matches: usize = 0;
            for (list.array.items) |sub| if (try self.eval(sub, inst, depth, false)) {
                matches += 1;
            };
            if (matches != 1) ok = try self.fail(collect, "oneOf", "value matches {d} alternatives, expected exactly one", .{matches}) and ok;
        }
        if (obj.get("not")) |sub| if (try self.eval(sub, inst, depth, false)) {
            ok = try self.fail(collect, "not", "value matches the forbidden schema", .{}) and ok;
        };
        if (obj.get("if")) |cond| {
            if (try self.eval(cond, inst, depth, false)) {
                if (obj.get("then")) |sub| if (!try self.eval(sub, inst, depth, collect)) {
                    ok = false;
                };
            } else {
                if (obj.get("else")) |sub| if (!try self.eval(sub, inst, depth, collect)) {
                    ok = false;
                };
            }
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
    const valid = try ev.eval(schema.root, instance, 0, true);
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

test "compile rejects unsupported and remote schemas" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectError(error.UnsupportedKeyword, compileText(arena, "{\"unevaluatedProperties\":false}", .{}));
    try std.testing.expectError(error.UnsupportedKeyword, compileText(arena, "{\"properties\":{\"a\":{\"$id\":\"x\"}}}", .{}));
    try std.testing.expectError(error.RemoteRef, compileText(arena, "{\"$ref\":\"https://example.com/s.json\"}", .{}));
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
    // Allowed when opted in.
    _ = try compileText(arena, "{\"unevaluatedProperties\":false}", .{ .allow_unsupported_keywords = true });
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

    const deep = try compileText(arena, "{\"properties\":{\"n\":{\"$ref\":\"#\"}}}", .{ .limits = .{ .max_depth = 2 } });
    const nested = try std.json.parseFromSliceLeaky(Value, arena, "{\"n\":{\"n\":{\"n\":{}}}}", .{});
    try std.testing.expectError(error.InstanceTooDeep, validate(arena, &deep, nested));
}
