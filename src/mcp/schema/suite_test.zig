//! Runs the draft 2020-12 cases of the JSON Schema Test Suite against the validator.
//!
//! The cases are in `test/fixtures/json_schema_test_suite`. The test reads each file of
//! `files`, compiles each schema and validates each instance.
//!
//! The validator never gets a schema from the network. Some schemas refer to a remote
//! document of the suite. For them, the test puts the documents of `remotes` into `$defs` of
//! the root, each with its URI in `$id`. Section 9.3 of the core specification calls this a
//! bundle. The table `skipped` names the groups that the test cannot run, with the reason.
const std = @import("std");
const Value = std.json.Value;
const validator = @import("validator.zig");

const suite_dir = "test/fixtures/json_schema_test_suite/tests/draft2020-12";
const remotes_dir = "test/fixtures/json_schema_test_suite/remotes/draft2020-12";
const remotes_uri = "http://localhost:1234/draft2020-12/";

const files = [_][]const u8{
    "additionalProperties.json",         "allOf.json",                   "anchor.json",                  "anyOf.json",
    "boolean_schema.json",               "const.json",                   "contains.json",                "content.json",
    "default.json",                      "defs.json",                    "dependentRequired.json",       "dependentSchemas.json",
    "dynamicRef.json",                   "enum.json",                    "exclusiveMaximum.json",        "exclusiveMinimum.json",
    "format.json",                       "if-then-else.json",            "infinite-loop-detection.json", "items.json",
    "maxContains.json",                  "maximum.json",                 "maxItems.json",                "maxLength.json",
    "maxProperties.json",                "minContains.json",             "minimum.json",                 "minItems.json",
    "minLength.json",                    "minProperties.json",           "multipleOf.json",              "not.json",
    "oneOf.json",                        "pattern.json",                 "patternProperties.json",       "prefixItems.json",
    "properties.json",                   "propertyNames.json",           "ref.json",                     "refRemote.json",
    "required.json",                     "type.json",                    "unevaluatedItems.json",        "unevaluatedProperties.json",
    "uniqueItems.json",                  "vocabulary.json",              "optional/anchor.json",         "optional/dynamicRef.json",
    "optional/ecmascript-regex.json",    "optional/id.json",             "optional/non-bmp-regex.json",  "optional/no-schema.json",
    "optional/refOfUnknownKeyword.json", "optional/unknownKeyword.json",
};

/// The remote documents of the suite that a bundle can hold, by path below `remotes_uri`.
const remotes = [_][]const u8{
    "baseUriChange/folderInteger.json", "baseUriChangeFolder/folderInteger.json", "baseUriChangeFolderInSubschema/folderInteger.json",
    "detached-dynamicref.json",         "detached-ref.json",                      "different-id-ref-string.json",
    "extendible-dynamic-ref.json",      "integer.json",                           "locationIndependentIdentifier.json",
    "name-defs.json",                   "nested-absolute-ref-to-string.json",     "nested/foo-ref-string.json",
    "nested/string.json",               "prefixItems.json",                       "ref-and-defs.json",
    "subSchemas.json",                  "tree.json",                              "urn-ref-string.json",
};

const Skip = struct {
    file: []const u8,
    group: []const u8,
    reason: []const u8,
};

const metaschema = "The schema refers to the 2020-12 meta-schema, which the validator does not get from the network.";
const retrieval_uri = "The remote document has an `$id` that is not its retrieval URI, and a bundle cannot keep both URIs.";
const regex_engine = "The regular expression uses a Unicode property escape that `regex.zig` does not support.";

const skipped = [_]Skip{
    .{ .file = "defs.json", .group = "validate definition against metaschema", .reason = metaschema },
    .{ .file = "ref.json", .group = "remote ref, containing refs itself", .reason = metaschema },
    .{ .file = "refRemote.json", .group = "remote HTTP ref with different $id", .reason = retrieval_uri },
    .{ .file = "refRemote.json", .group = "remote HTTP ref with different URN $id", .reason = retrieval_uri },
    .{ .file = "refRemote.json", .group = "retrieved nested refs resolve relative to their URI not $id", .reason = retrieval_uri },
    .{ .file = "vocabulary.json", .group = "schema that uses custom metaschema with with no validation vocabulary", .reason = "A custom meta-schema is a dialect other than 2020-12. MCP requires an error for it." },
    .{ .file = "vocabulary.json", .group = "ignore unrecognized optional vocabulary", .reason = "A custom meta-schema is a dialect other than 2020-12. MCP requires an error for it." },
    .{ .file = "pattern.json", .group = "pattern with Unicode property escape requires unicode mode", .reason = regex_engine },
    .{ .file = "patternProperties.json", .group = "patternProperties with Unicode property escape", .reason = regex_engine },
    .{ .file = "optional/ecmascript-regex.json", .group = "patterns always use unicode semantics with pattern", .reason = regex_engine },
    .{ .file = "optional/ecmascript-regex.json", .group = "pattern with non-ASCII digits", .reason = regex_engine },
    .{ .file = "optional/ecmascript-regex.json", .group = "patterns always use unicode semantics with patternProperties", .reason = regex_engine },
    .{ .file = "optional/ecmascript-regex.json", .group = "patternProperties with non-ASCII digits", .reason = regex_engine },
};

fn isSkipped(file: []const u8, group: []const u8) bool {
    for (skipped) |s| {
        if (std.mem.eql(u8, s.file, file) and std.mem.eql(u8, s.group, group)) return true;
    }
    return false;
}

/// Load the remote documents. A document without `$id` gets its retrieval URI as `$id`.
fn loadRemotes(arena: std.mem.Allocator, io: std.Io) ![]Value {
    var dir = try std.Io.Dir.cwd().openDir(io, remotes_dir, .{});
    defer dir.close(io);
    var list: std.ArrayList(Value) = .empty;
    for (remotes) |path| {
        const text = try dir.readFileAlloc(io, path, arena, .limited(1 << 16));
        var doc = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
        if (doc.object.get("$id") == null) {
            try doc.object.put(arena, "$id", .{ .string = try std.mem.concat(arena, u8, &.{ remotes_uri, path }) });
        }
        try list.append(arena, doc);
    }
    return list.items;
}

/// Return a copy of `schema` with the remote documents in `$defs` of the root.
fn bundle(arena: std.mem.Allocator, schema: Value, docs: []const Value) !Value {
    if (schema != .object) return schema;
    var root = try schema.object.clone(arena);
    var defs: std.json.ObjectMap = if (root.get("$defs")) |d| try d.object.clone(arena) else .empty;
    for (docs, 0..) |doc, i| try defs.put(arena, try std.fmt.allocPrint(arena, "x-suite-remote-{d}", .{i}), doc);
    try root.put(arena, "$defs", .{ .object = defs });
    return .{ .object = root };
}

test "JSON Schema Test Suite draft 2020-12" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var remotes_arena: std.heap.ArenaAllocator = .init(gpa);
    defer remotes_arena.deinit();
    const docs = try loadRemotes(remotes_arena.allocator(), io);
    var dir = try std.Io.Dir.cwd().openDir(io, suite_dir, .{});
    defer dir.close(io);
    var passed: usize = 0;
    var bundled: usize = 0;
    var failed: usize = 0;
    var skipped_cases: usize = 0;
    for (files) |file| {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const text = try dir.readFileAlloc(io, file, arena, .limited(1 << 20));
        const groups = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
        for (groups.array.items) |group| {
            const description = group.object.get("description").?.string;
            const tests = group.object.get("tests").?.array.items;
            if (isSkipped(file, description)) {
                skipped_cases += tests.len;
                continue;
            }
            const raw = group.object.get("schema").?;
            var remote = false;
            const schema = validator.compile(arena, raw, .{}) catch |e| switch (e) {
                error.RemoteRef => blk: {
                    remote = true;
                    break :blk validator.compile(arena, try bundle(arena, raw, docs), .{});
                },
                else => e,
            } catch |e| {
                std.debug.print("suite: {s}: \"{s}\": compile error {t}\n", .{ file, description, e });
                failed += tests.len;
                continue;
            };
            for (tests) |case| {
                const want = case.object.get("valid").?.bool;
                const name = case.object.get("description").?.string;
                const result = validator.validate(arena, &schema, case.object.get("data").?) catch |e| {
                    std.debug.print("suite: {s}: \"{s}\" / \"{s}\": {t}\n", .{ file, description, name, e });
                    failed += 1;
                    continue;
                };
                if (result.valid == want) {
                    passed += 1;
                    if (remote) bundled += 1;
                } else {
                    std.debug.print("suite: {s}: \"{s}\" / \"{s}\": expected valid={}\n", .{ file, description, name, want });
                    failed += 1;
                }
            }
        }
    }
    std.debug.print("suite: {d} passed ({d} with a bundle), {d} failed, {d} skipped\n", .{ passed, bundled, failed, skipped_cases });
    try std.testing.expectEqual(0, failed);
}
