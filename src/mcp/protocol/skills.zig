//! Wire types and shared rules of the Skills extension (`io.modelcontextprotocol/skills`,
//! SEP-2640). A skill is a directory of files with a `SKILL.md` at its root. The server
//! serves each file as a resource. The extension adds `skills/list`, `skills/get` and
//! `resources/directory/read`.
//!
//! This file also holds the parser for the YAML frontmatter of `SKILL.md` and the digest
//! format. It also holds the host checks of a file against the entry of its skill. The server
//! and the client use the same parser. Thus both sides get the same JSON object from the
//! same text.
//!
//! The parser accepts a safe subset of YAML. It rejects all other YAML with
//! `error.UnsupportedYaml`. See `parseFrontmatter`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("types.zig");
const json = @import("../json.zig");

pub const extension_id = "io.modelcontextprotocol/skills";

pub const method_list = "skills/list";
pub const method_get = "skills/get";
pub const method_directory_read = "resources/directory/read";

/// The MIME type of a directory resource.
pub const directory_mime_type = "inode/directory";
/// The MIME type of `SKILL.md`.
pub const skill_md_mime_type = "text/markdown";
pub const skill_md_name = "SKILL.md";
/// The URI scheme that the extension recommends.
pub const default_scheme = "skill";

/// The maximum number of files in one skill, `SKILL.md` included.
pub const max_files_per_skill: u32 = 512;
/// The maximum sum of the file sizes of one skill, in bytes.
pub const max_bytes_per_skill: u64 = 16 << 20;

/// The length of a digest text: `sha256:` and 64 hexadecimal digits.
pub const digest_len = 7 + 64;

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// One file of a skill with the digest and the size of its raw bytes.
pub const SkillResource = struct {
    uri: []const u8,
    /// `sha256:` and 64 lowercase hexadecimal digits.
    digest: []const u8,
    size: i64,
};

/// The `resources` field of a skill entry: the complete file list, or `"dynamic"`.
pub const SkillResources = union(enum) {
    files: []const SkillResource,
    /// The server generates the content. No digests are available.
    dynamic,
    /// Any other value. A host must not load an entry with this value.
    invalid,

    pub fn jsonParse(allocator: Allocator, source: anytype, options: std.json.ParseOptions) !SkillResources {
        const value = try std.json.innerParse(Value, allocator, source, options);
        return jsonParseFromValue(allocator, value, options);
    }

    pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: std.json.ParseOptions) !SkillResources {
        switch (source) {
            .string => |s| return if (std.mem.eql(u8, s, "dynamic")) .dynamic else .invalid,
            .array => {
                const files = std.json.parseFromValueLeaky([]const SkillResource, allocator, source, options) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return .invalid,
                };
                return .{ .files = files };
            },
            else => return .invalid,
        }
    }

    pub fn jsonStringify(self: SkillResources, jws: anytype) !void {
        switch (self) {
            .files => |f| try jws.write(f),
            .dynamic => try jws.write("dynamic"),
            .invalid => try jws.write(null),
        }
    }
};

/// The entry of one skill. `skills/list` and `skills/get` return the same shape.
pub const Skill = struct {
    /// The URI of the `SKILL.md` of the skill.
    uri: []const u8,
    /// The frontmatter of `SKILL.md` as a JSON object. Null only in a malformed entry.
    frontmatter: ?Value = null,
    /// Null only in a malformed entry. A host must not load such an entry.
    resources: ?SkillResources = null,
};

pub const ListSkillsResult = struct {
    _meta: ?types.ResultMetaObject = null,
    resultType: []const u8 = types.result_type_complete,
    nextCursor: ?types.Cursor = null,
    ttlMs: ?i64 = null,
    cacheScope: ?types.CacheScope = null,
    skills: []const Skill,
};

pub const GetSkillParams = struct {
    _meta: types.RequestMetaObject,
    uri: []const u8,
};

pub const GetSkillResult = struct {
    _meta: ?types.ResultMetaObject = null,
    resultType: []const u8 = types.result_type_complete,
    ttlMs: ?i64 = null,
    cacheScope: ?types.CacheScope = null,
    skill: Skill,
};

pub const ReadDirectoryParams = struct {
    _meta: types.RequestMetaObject,
    uri: []const u8,
    cursor: ?types.Cursor = null,
};

/// The result of `resources/directory/read`: the direct children of the directory.
pub const ReadDirectoryResult = struct {
    _meta: ?types.ResultMetaObject = null,
    resultType: []const u8 = types.result_type_complete,
    nextCursor: ?types.Cursor = null,
    resources: []const types.Resource,
};

/// The settings of the extension in the server capabilities.
pub const ServerSettings = struct {
    directoryRead: ?bool = null,
};

/// True when the server capabilities declare the extension.
pub fn serverSupports(caps: types.ServerCapabilities) bool {
    return settingsOf(caps) != null;
}

/// True when the server declares `directoryRead: true`. A client must not send
/// `resources/directory/read` to a server without it.
pub fn serverSupportsDirectoryRead(caps: types.ServerCapabilities) bool {
    const s = settingsOf(caps) orelse return false;
    if (s != .object) return false;
    const v = s.object.get("directoryRead") orelse return false;
    return v == .bool and v.bool;
}

fn settingsOf(caps: types.ServerCapabilities) ?Value {
    const ext = caps.extensions orelse return null;
    if (ext != .object) return null;
    return ext.object.get(extension_id);
}

// ---------------------------------------------------------------------------------------------
// Digests and paths
// ---------------------------------------------------------------------------------------------

/// Write the digest text of `bytes` into `out`.
pub fn digest(bytes: []const u8, out: *[digest_len]u8) void {
    var raw: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &raw, .{});
    @memcpy(out[0..7], "sha256:");
    const hex = std.fmt.bytesToHex(raw, .lower);
    @memcpy(out[7..], &hex);
}

/// The digest text of `bytes`, allocated in `arena`.
pub fn digestAlloc(arena: Allocator, bytes: []const u8) Allocator.Error![]const u8 {
    const out = try arena.alloc(u8, digest_len);
    digest(bytes, out[0..digest_len]);
    return out;
}

/// True when `text` has the digest format of the extension.
pub fn isDigest(text: []const u8) bool {
    if (text.len != digest_len or !std.mem.startsWith(u8, text, "sha256:")) return false;
    for (text[7..]) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

/// True when `name` obeys the name rules of the Agent Skills specification.
pub fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;
    var prev: u8 = 0;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-';
        if (!ok) return false;
        if (c == '-' and prev == '-') return false;
        prev = c;
    }
    return true;
}

/// The parts of a skill URI.
pub const SkillPath = struct {
    /// The root directory of the skill: the URI without `/SKILL.md`.
    root: []const u8,
    /// The last segment of the root: the skill name.
    name: []const u8,
};

/// Split the URI of a `SKILL.md` into its root and name. Null when the URI has no
/// `scheme://`, does not end in `/SKILL.md` or has no skill path.
pub fn splitSkillUri(uri: []const u8) ?SkillPath {
    const sep = std.mem.indexOf(u8, uri, "://") orelse return null;
    if (sep == 0) return null;
    const suffix = "/" ++ skill_md_name;
    if (!std.mem.endsWith(u8, uri, suffix)) return null;
    const root = uri[0 .. uri.len - suffix.len];
    if (root.len <= sep + 3) return null;
    const path = root[sep + 3 ..];
    const slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const name = if (slash) |i| path[i + 1 ..] else path;
    if (name.len == 0) return null;
    return .{ .root = root, .name = name };
}

/// True when `uri` is the `SKILL.md` of the skill or a file inside its root directory.
pub fn isInsideSkill(skill_uri: []const u8, uri: []const u8) bool {
    if (std.mem.eql(u8, skill_uri, uri)) return true;
    const sp = splitSkillUri(skill_uri) orelse return false;
    if (uri.len <= sp.root.len + 1) return false;
    if (!std.mem.startsWith(u8, uri, sp.root) or uri[sp.root.len] != '/') return false;
    return pathIsClean(uri[sp.root.len + 1 ..]);
}

/// True when `path` has no empty, `.` or `..` segment.
fn pathIsClean(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

/// Resolve a relative reference in a skill against the root directory of the skill. The
/// result must stay inside the skill. Else the function returns `error.OutsideSkill`.
pub fn resolveRelative(arena: Allocator, skill_uri: []const u8, reference: []const u8) error{ OutOfMemory, OutsideSkill }![]const u8 {
    const sp = splitSkillUri(skill_uri) orelse return error.OutsideSkill;
    if (reference.len == 0 or reference[0] == '/' or std.mem.indexOf(u8, reference, "://") != null) return error.OutsideSkill;
    var segments: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, reference, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (segments.items.len == 0) return error.OutsideSkill;
            _ = segments.pop();
            continue;
        }
        try segments.append(arena, seg);
    }
    if (segments.items.len == 0) return error.OutsideSkill;
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, sp.root);
    for (segments.items) |seg| {
        try out.append(arena, '/');
        try out.appendSlice(arena, seg);
    }
    return out.items;
}

// ---------------------------------------------------------------------------------------------
// Entry validation and host verification
// ---------------------------------------------------------------------------------------------

pub const EntryError = error{
    /// The URI is not the URI of a `SKILL.md` with a skill path.
    InvalidSkillUri,
    /// The frontmatter is absent, not an object, or has no string `name` or `description`.
    InvalidFrontmatter,
    /// The last segment of the skill path is not equal to `frontmatter.name`.
    NameMismatch,
    /// `resources` is absent or is neither an array nor `"dynamic"`.
    InvalidResources,
    /// A file entry has a bad digest, a negative size, a duplicate URI or a URI outside the skill.
    InvalidFileEntry,
    /// The file list has no entry for `SKILL.md`.
    MissingSkillMd,
    /// The skill has more files or more bytes than the limits.
    SkillTooLarge,
};

/// Check an entry against the rules of the extension. A host must not load an entry that
/// fails. `max_files` and `max_bytes` are the limits of the host. They must be at least the
/// limits of the extension.
pub fn validateEntry(entry: Skill, max_files: u32, max_bytes: u64) EntryError!void {
    const sp = splitSkillUri(entry.uri) orelse return error.InvalidSkillUri;
    const fm = entry.frontmatter orelse return error.InvalidFrontmatter;
    if (fm != .object) return error.InvalidFrontmatter;
    const name = fm.object.get("name") orelse return error.InvalidFrontmatter;
    const description = fm.object.get("description") orelse return error.InvalidFrontmatter;
    if (name != .string or description != .string) return error.InvalidFrontmatter;
    if (!std.mem.eql(u8, name.string, sp.name)) return error.NameMismatch;
    const resources = entry.resources orelse return error.InvalidResources;
    switch (resources) {
        .invalid => return error.InvalidResources,
        .dynamic => return,
        .files => |files| {
            if (files.len > max_files) return error.SkillTooLarge;
            var total: u64 = 0;
            var has_skill_md = false;
            for (files, 0..) |f, i| {
                if (!isDigest(f.digest) or f.size < 0) return error.InvalidFileEntry;
                if (!isInsideSkill(entry.uri, f.uri)) return error.InvalidFileEntry;
                for (files[0..i]) |g| if (std.mem.eql(u8, g.uri, f.uri)) return error.InvalidFileEntry;
                if (std.mem.eql(u8, f.uri, entry.uri)) has_skill_md = true;
                total += @intCast(f.size);
            }
            if (!has_skill_md) return error.MissingSkillMd;
            if (total > max_bytes) return error.SkillTooLarge;
        },
    }
}

/// The file entry for `uri`, or null when the manifest does not list it.
pub fn findFile(entry: Skill, uri: []const u8) ?SkillResource {
    const resources = entry.resources orelse return null;
    switch (resources) {
        .files => |files| {
            for (files) |f| if (std.mem.eql(u8, f.uri, uri)) return f;
            return null;
        },
        else => return null,
    }
}

pub const VerifyError = error{
    OutOfMemory,
    /// The held entry does not list the file. A host treats this as a digest mismatch.
    UnlistedFile,
    /// The URI is outside the skill.
    OutsideSkill,
    SizeMismatch,
    DigestMismatch,
    /// The frontmatter of the read `SKILL.md` is not equal to the frontmatter of the entry.
    FrontmatterMismatch,
    /// The entry has `resources` of an invalid shape.
    InvalidEntry,
};

/// Check that a host can read `uri` under the held entry. For a file list, the URI must be
/// in the list. For a dynamic skill, the URI must be inside the skill.
pub fn checkReadable(entry: Skill, uri: []const u8) VerifyError!void {
    const resources = entry.resources orelse return error.InvalidEntry;
    switch (resources) {
        .invalid => return error.InvalidEntry,
        .files => if (findFile(entry, uri) == null) return error.UnlistedFile,
        .dynamic => if (!isInsideSkill(entry.uri, uri)) return error.OutsideSkill,
    }
}

/// Verify the raw bytes of a file that a host read under the held entry. The function checks
/// the manifest, the size and the digest. For `SKILL.md` it also compares the frontmatter
/// field by field with the entry.
pub fn verifyFile(arena: Allocator, entry: Skill, uri: []const u8, bytes: []const u8) VerifyError!void {
    try checkReadable(entry, uri);
    if (findFile(entry, uri)) |f| {
        if (f.size < 0 or bytes.len != @as(u64, @intCast(f.size))) return error.SizeMismatch;
        var d: [digest_len]u8 = undefined;
        digest(bytes, &d);
        if (!std.mem.eql(u8, &d, f.digest)) return error.DigestMismatch;
    }
    if (std.mem.eql(u8, uri, entry.uri)) {
        const expected = entry.frontmatter orelse return error.FrontmatterMismatch;
        const actual = parseFrontmatter(arena, bytes) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.FrontmatterMismatch,
        };
        if (!jsonEqual(expected, actual)) return error.FrontmatterMismatch;
    }
}

/// The raw bytes of a resource content item: the text, or the decoded blob.
pub fn contentBytes(arena: Allocator, contents: types.ResourceContents) error{ OutOfMemory, InvalidBlob }![]const u8 {
    switch (contents) {
        .text => |t| return t.text,
        .blob => |b| {
            const decoder = std.base64.standard.Decoder;
            const len = decoder.calcSizeForSlice(b.blob) catch return error.InvalidBlob;
            const out = try arena.alloc(u8, len);
            decoder.decode(out, b.blob) catch return error.InvalidBlob;
            return out;
        },
    }
}

/// Deep equality of two JSON values. Object keys can be in any order. Numbers compare by
/// value.
pub fn jsonEqual(a: Value, b: Value) bool {
    if (numberOf(a)) |x| {
        const y = numberOf(b) orelse return false;
        return x == y;
    }
    return switch (a) {
        .null => b == .null,
        .bool => |x| b == .bool and b.bool == x,
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .array => |x| blk: {
            if (b != .array or b.array.items.len != x.items.len) break :blk false;
            for (x.items, b.array.items) |p, q| if (!jsonEqual(p, q)) break :blk false;
            break :blk true;
        },
        .object => |x| blk: {
            if (b != .object or b.object.count() != x.count()) break :blk false;
            var it = x.iterator();
            while (it.next()) |kv| {
                const other = b.object.get(kv.key_ptr.*) orelse break :blk false;
                if (!jsonEqual(kv.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
        .integer, .float, .number_string => unreachable,
    };
}

fn numberOf(v: Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

// ---------------------------------------------------------------------------------------------
// Frontmatter
// ---------------------------------------------------------------------------------------------

pub const FrontmatterError = error{
    OutOfMemory,
    /// The document does not start with a `---` line, or has no second `---` line.
    MissingFrontmatter,
    /// The YAML is not valid.
    InvalidYaml,
    /// The YAML uses a feature that the parser does not accept.
    UnsupportedYaml,
    /// The frontmatter is not a YAML map.
    NotAnObject,
};

/// The text between the `---` delimiter lines at the start of `document`.
pub fn frontmatterText(document: []const u8) error{MissingFrontmatter}![]const u8 {
    const first_end = std.mem.indexOfScalar(u8, document, '\n') orelse return error.MissingFrontmatter;
    if (!std.mem.eql(u8, trimCr(document[0..first_end]), "---")) return error.MissingFrontmatter;
    var pos = first_end + 1;
    while (pos <= document.len) {
        const end = std.mem.indexOfScalarPos(u8, document, pos, '\n') orelse document.len;
        const line = trimCr(document[pos..end]);
        if (std.mem.eql(u8, line, "---")) return document[first_end + 1 .. pos];
        if (end == document.len) break;
        pos = end + 1;
    }
    return error.MissingFrontmatter;
}

/// Parse the YAML frontmatter of a `SKILL.md` into a JSON object.
///
/// The parser accepts block maps, block sequences, plain scalars and comments. It accepts
/// single-quoted and double-quoted scalars on one line. It accepts literal (`|`) and folded
/// (`>`) block scalars and the empty flow collections `[]` and `{}`. Plain scalars resolve
/// with the core schema of YAML 1.2.
///
/// The parser rejects anchors, aliases, tags, directives, flow collections with content,
/// complex keys and duplicate keys. It also rejects plain scalars that YAML 1.1 reads
/// differently from YAML 1.2, such as `yes`, `no`, `on`, `off`, `010`, dates and times. An
/// author quotes such values.
pub fn parseFrontmatter(arena: Allocator, document: []const u8) FrontmatterError!Value {
    const text = try frontmatterText(document);
    return parseYamlMapping(arena, text);
}

/// Parse a YAML text in the subset of `parseFrontmatter` into a JSON object.
pub fn parseYamlMapping(arena: Allocator, text: []const u8) FrontmatterError!Value {
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| try lines.append(arena, trimCr(raw));
    // The split gives an empty last line after the final newline.
    if (lines.items.len > 0 and lines.items[lines.items.len - 1].len == 0) _ = lines.pop();
    var p: YamlParser = .{ .arena = arena, .lines = lines.items };
    p.skipBlank();
    if (p.i >= p.lines.len) return error.NotAnObject;
    const first = p.lines[p.i];
    if (indentOf(first) != 0) return error.InvalidYaml;
    if (isSequenceItem(first)) return error.NotAnObject;
    const map = try p.parseMapping(0, 0);
    p.skipBlank();
    if (p.i < p.lines.len) return error.InvalidYaml;
    return .{ .object = map };
}

fn trimCr(line: []const u8) []const u8 {
    return if (line.len > 0 and line[line.len - 1] == '\r') line[0 .. line.len - 1] else line;
}

fn indentOf(line: []const u8) usize {
    var n: usize = 0;
    while (n < line.len and line[n] == ' ') n += 1;
    return n;
}

fn isBlankOrComment(line: []const u8) bool {
    const t = std.mem.trimStart(u8, line, " \t");
    return t.len == 0 or t[0] == '#';
}

fn isSequenceItem(line: []const u8) bool {
    const c = line[indentOf(line)..];
    return std.mem.eql(u8, c, "-") or std.mem.startsWith(u8, c, "- ");
}

const max_yaml_depth = 16;

const YamlParser = struct {
    arena: Allocator,
    lines: []const []const u8,
    i: usize = 0,

    fn skipBlank(self: *YamlParser) void {
        while (self.i < self.lines.len and isBlankOrComment(self.lines[self.i])) self.i += 1;
    }

    fn checkIndentation(line: []const u8) FrontmatterError!void {
        const n = indentOf(line);
        if (n < line.len and line[n] == '\t') return error.UnsupportedYaml;
    }

    fn parseMapping(self: *YamlParser, indent: usize, depth: usize) FrontmatterError!std.json.ObjectMap {
        if (depth > max_yaml_depth) return error.UnsupportedYaml;
        var map: std.json.ObjectMap = .empty;
        while (true) {
            self.skipBlank();
            if (self.i >= self.lines.len) break;
            const line = self.lines[self.i];
            try checkIndentation(line);
            const ind = indentOf(line);
            if (ind < indent) break;
            if (ind > indent) return error.InvalidYaml;
            const content = line[ind..];
            if (isSequenceItem(line)) {
                if (indent == 0) return error.InvalidYaml;
                break;
            }
            if (std.mem.eql(u8, content, "---") or std.mem.eql(u8, content, "...")) return error.UnsupportedYaml;
            const split = try splitKey(content);
            if (map.get(split.key) != null) return error.InvalidYaml;
            self.i += 1;
            const value = try self.parseValue(split.rest, indent, depth, false);
            try map.put(self.arena, try self.arena.dupe(u8, split.key), value);
        }
        return map;
    }

    fn parseSequence(self: *YamlParser, indent: usize, depth: usize) FrontmatterError!std.json.Array {
        if (depth > max_yaml_depth) return error.UnsupportedYaml;
        var items: std.json.Array = .init(self.arena);
        while (true) {
            self.skipBlank();
            if (self.i >= self.lines.len) break;
            const line = self.lines[self.i];
            try checkIndentation(line);
            const ind = indentOf(line);
            if (ind < indent) break;
            if (ind > indent) return error.InvalidYaml;
            if (!isSequenceItem(line)) break;
            const content = line[ind..];
            const rest = if (content.len > 1) std.mem.trimStart(u8, content[2..], " ") else "";
            // A mapping inside a sequence item is outside the subset.
            if (looksLikeKey(rest)) return error.UnsupportedYaml;
            self.i += 1;
            try items.append(try self.parseValue(rest, indent, depth, true));
        }
        return items;
    }

    /// Parse the value after `key:` or `- `. `rest` is the text after the indicator. `indent`
    /// is the indentation of the line that holds the indicator. `in_sequence` is true for the
    /// value of a sequence item.
    fn parseValue(self: *YamlParser, rest: []const u8, indent: usize, depth: usize, in_sequence: bool) FrontmatterError!Value {
        if (rest.len == 0 or rest[0] == '#') {
            // A nested block, or null.
            self.skipBlank();
            if (self.i >= self.lines.len) return .null;
            const next = self.lines[self.i];
            try checkIndentation(next);
            const ind = indentOf(next);
            if (ind > indent) {
                if (isSequenceItem(next)) return .{ .array = try self.parseSequence(ind, depth + 1) };
                // A mapping inside a sequence item is outside the subset.
                if (in_sequence) return error.UnsupportedYaml;
                return .{ .object = try self.parseMapping(ind, depth + 1) };
            }
            // A sequence can start at the indentation of its key. In a sequence, the next
            // item at the same indentation is a sibling.
            if (ind == indent and isSequenceItem(next) and !in_sequence) {
                return .{ .array = try self.parseSequence(ind, depth + 1) };
            }
            return .null;
        }
        switch (rest[0]) {
            '|', '>' => return .{ .string = try self.parseBlockScalar(rest, indent) },
            '"' => return .{ .string = try parseDoubleQuoted(self.arena, rest) },
            '\'' => return .{ .string = try parseSingleQuoted(self.arena, rest) },
            '[', '{' => {
                const t = stripComment(rest);
                if (std.mem.eql(u8, t, "[]")) return .{ .array = .init(self.arena) };
                if (std.mem.eql(u8, t, "{}")) return .{ .object = .empty };
                return error.UnsupportedYaml;
            },
            '&', '*', '!', '%', '@', '`', '?' => return error.UnsupportedYaml,
            ',', ']', '}' => return error.InvalidYaml,
            else => {},
        }
        var text = stripComment(rest);
        if (hasMappingIndicator(text)) return error.InvalidYaml;
        // A plain scalar can continue on lines with more indentation.
        var folded: ?std.ArrayList(u8) = null;
        while (self.i < self.lines.len) {
            const next = self.lines[self.i];
            if (isBlankOrComment(next)) break;
            const ind = indentOf(next);
            if (ind <= indent) break;
            try checkIndentation(next);
            const part = std.mem.trimEnd(u8, next[ind..], " \t");
            if (hasMappingIndicator(part)) return error.InvalidYaml;
            if (std.mem.indexOf(u8, part, " #") != null) return error.UnsupportedYaml;
            if (folded == null) {
                folded = .empty;
                try folded.?.appendSlice(self.arena, text);
            }
            try folded.?.append(self.arena, ' ');
            try folded.?.appendSlice(self.arena, part);
            self.i += 1;
        }
        if (folded) |f| text = f.items;
        if (text.len > 0 and (text[0] == '-' or text[0] == ':') and (text.len == 1 or text[1] == ' ')) return error.InvalidYaml;
        return resolvePlain(self.arena, text);
    }

    fn parseBlockScalar(self: *YamlParser, header: []const u8, indent: usize) FrontmatterError![]const u8 {
        const folded = header[0] == '>';
        var chomp: enum { clip, strip, keep } = .clip;
        var h = header[1..];
        if (h.len > 0 and (h[0] == '-' or h[0] == '+')) {
            chomp = if (h[0] == '-') .strip else .keep;
            h = h[1..];
        }
        if (h.len > 0 and std.ascii.isDigit(h[0])) return error.UnsupportedYaml;
        const tail = std.mem.trimStart(u8, h, " ");
        if (tail.len > 0 and (tail.len == h.len or tail[0] != '#')) return error.InvalidYaml;

        // The content lines and their indentation.
        var body: std.ArrayList([]const u8) = .empty;
        var content_indent: ?usize = null;
        var max_leading_blank: usize = 0;
        while (self.i < self.lines.len) {
            const line = self.lines[self.i];
            const all_space = std.mem.trimStart(u8, line, " ").len == 0;
            if (content_indent == null) {
                if (all_space) {
                    max_leading_blank = @max(max_leading_blank, line.len);
                    try body.append(self.arena, "");
                    self.i += 1;
                    continue;
                }
                const ind = indentOf(line);
                if (ind <= indent) break;
                if (line[ind] == '\t') return error.UnsupportedYaml;
                if (max_leading_blank > ind) return error.InvalidYaml;
                content_indent = ind;
            }
            const n = content_indent.?;
            if (all_space) {
                try body.append(self.arena, if (line.len > n) line[n..] else "");
                self.i += 1;
                continue;
            }
            if (indentOf(line) < n) break;
            try body.append(self.arena, line[n..]);
            self.i += 1;
        }
        // Blank lines at the end belong to the chomp rule, not to the content.
        var trailing: usize = 0;
        var end = body.items.len;
        while (end > 0 and body.items[end - 1].len == 0) : (end -= 1) trailing += 1;
        const lines = body.items[0..end];

        var out: std.ArrayList(u8) = .empty;
        if (!folded) {
            for (lines, 0..) |l, k| {
                if (k > 0) try out.append(self.arena, '\n');
                try out.appendSlice(self.arena, l);
            }
        } else {
            var pending: usize = 0;
            var prev_more = false;
            var started = false;
            for (lines) |l| {
                if (l.len == 0) {
                    pending += 1;
                    continue;
                }
                const more = l[0] == ' ' or l[0] == '\t';
                if (started) {
                    if (!prev_more and !more) {
                        if (pending == 0) try out.append(self.arena, ' ') else try appendNewlines(self.arena, &out, pending);
                    } else {
                        try appendNewlines(self.arena, &out, pending + 1);
                    }
                } else {
                    try appendNewlines(self.arena, &out, pending);
                }
                try out.appendSlice(self.arena, l);
                started = true;
                prev_more = more;
                pending = 0;
            }
        }
        if (lines.len > 0) {
            switch (chomp) {
                .strip => {},
                .clip => try out.append(self.arena, '\n'),
                .keep => try appendNewlines(self.arena, &out, trailing + 1),
            }
        } else if (chomp == .keep) {
            try appendNewlines(self.arena, &out, trailing);
        }
        return out.items;
    }
};

const KeySplit = struct { key: []const u8, rest: []const u8 };

/// Split `key: rest`. The key must be a plain scalar.
fn splitKey(content: []const u8) FrontmatterError!KeySplit {
    switch (content[0]) {
        '"', '\'', '?', '&', '*', '!', '|', '>', '%', '@', '`', '[', '{' => return error.UnsupportedYaml,
        ',', ']', '}', '#', ':' => return error.InvalidYaml,
        else => {},
    }
    var k: usize = 0;
    while (k < content.len) : (k += 1) {
        if (content[k] == ':' and (k + 1 == content.len or content[k + 1] == ' ')) break;
        if (content[k] == '#' and k > 0 and content[k - 1] == ' ') return error.InvalidYaml;
    }
    if (k == content.len) return error.InvalidYaml;
    const key = std.mem.trimEnd(u8, content[0..k], " ");
    if (key.len == 0) return error.InvalidYaml;
    if (std.mem.eql(u8, key, "<<")) return error.UnsupportedYaml;
    const rest = if (k + 1 < content.len) std.mem.trim(u8, content[k + 1 ..], " ") else "";
    return .{ .key = key, .rest = rest };
}

fn looksLikeKey(text: []const u8) bool {
    if (text.len == 0) return false;
    if (text[0] == '"' or text[0] == '\'' or text[0] == '|' or text[0] == '>' or text[0] == '[' or text[0] == '{') return false;
    return hasMappingIndicator(stripComment(text));
}

/// True when a plain scalar contains `: ` or ends with `:`.
fn hasMappingIndicator(text: []const u8) bool {
    return std.mem.indexOf(u8, text, ": ") != null or (text.len > 0 and text[text.len - 1] == ':');
}

/// Remove a ` #` comment and the spaces at the end.
fn stripComment(text: []const u8) []const u8 {
    var end = text.len;
    if (std.mem.indexOf(u8, text, " #")) |i| end = i;
    if (std.mem.indexOf(u8, text, "\t#")) |i| end = @min(end, i);
    return std.mem.trimEnd(u8, text[0..end], " \t");
}

/// After the quote at the end, only spaces and a comment can follow.
fn checkAfterQuote(tail: []const u8) FrontmatterError!void {
    const t = std.mem.trimStart(u8, tail, " \t");
    if (t.len == 0) return;
    if (t[0] == '#' and t.len < tail.len) return;
    return error.InvalidYaml;
}

fn parseSingleQuoted(arena: Allocator, text: []const u8) FrontmatterError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var k: usize = 1;
    while (k < text.len) : (k += 1) {
        if (text[k] == '\'') {
            if (k + 1 < text.len and text[k + 1] == '\'') {
                try out.append(arena, '\'');
                k += 1;
                continue;
            }
            try checkAfterQuote(text[k + 1 ..]);
            return out.items;
        }
        try out.append(arena, text[k]);
    }
    // A scalar that continues on the next line is outside the subset.
    return error.UnsupportedYaml;
}

fn parseDoubleQuoted(arena: Allocator, text: []const u8) FrontmatterError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var k: usize = 1;
    while (k < text.len) : (k += 1) {
        const c = text[k];
        if (c == '"') {
            try checkAfterQuote(text[k + 1 ..]);
            return out.items;
        }
        if (c != '\\') {
            try out.append(arena, c);
            continue;
        }
        k += 1;
        if (k >= text.len) return error.UnsupportedYaml;
        const e = text[k];
        const simple: ?u8 = switch (e) {
            '0' => 0,
            'a' => 7,
            'b' => 8,
            't', '\t' => '\t',
            'n' => '\n',
            'v' => 11,
            'f' => 12,
            'r' => '\r',
            'e' => 27,
            ' ' => ' ',
            '"' => '"',
            '/' => '/',
            '\\' => '\\',
            else => null,
        };
        if (simple) |s| {
            try out.append(arena, s);
            continue;
        }
        const code: u21, const digits: usize = switch (e) {
            'N' => .{ 0x85, 0 },
            '_' => .{ 0xA0, 0 },
            'L' => .{ 0x2028, 0 },
            'P' => .{ 0x2029, 0 },
            'x' => .{ 0, 2 },
            'u' => .{ 0, 4 },
            'U' => .{ 0, 8 },
            else => return error.InvalidYaml,
        };
        var cp: u32 = code;
        if (digits > 0) {
            if (k + digits >= text.len) return error.InvalidYaml;
            cp = std.fmt.parseInt(u32, text[k + 1 .. k + 1 + digits], 16) catch return error.InvalidYaml;
            k += digits;
        }
        if (cp > 0x10FFFF) return error.InvalidYaml;
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(@intCast(cp), &buf) catch return error.InvalidYaml;
        try out.appendSlice(arena, buf[0..n]);
    }
    return error.UnsupportedYaml;
}

/// Resolve a plain scalar with the core schema of YAML 1.2. Values that YAML 1.1 reads
/// differently give `error.UnsupportedYaml`.
fn resolvePlain(arena: Allocator, text: []const u8) FrontmatterError!Value {
    const nulls = [_][]const u8{ "", "~", "null", "Null", "NULL" };
    for (nulls) |n| if (std.mem.eql(u8, text, n)) return .null;
    const trues = [_][]const u8{ "true", "True", "TRUE" };
    for (trues) |t| if (std.mem.eql(u8, text, t)) return .{ .bool = true };
    const falses = [_][]const u8{ "false", "False", "FALSE" };
    for (falses) |f| if (std.mem.eql(u8, text, f)) return .{ .bool = false };
    const yaml11 = [_][]const u8{ "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF", "=" };
    for (yaml11) |w| if (std.mem.eql(u8, text, w)) return error.UnsupportedYaml;
    if (std.ascii.startsWithIgnoreCase(std.mem.trimStart(u8, text, "+-"), ".inf") or std.ascii.eqlIgnoreCase(text, ".nan")) return error.UnsupportedYaml;

    if (text.len > 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'o')) {
        const base: u8 = if (text[1] == 'x') 16 else 8;
        const v = std.fmt.parseInt(i64, text[2..], base) catch return .{ .string = text };
        return .{ .integer = v };
    }
    const unsigned = if (text[0] == '-' or text[0] == '+') text[1..] else text;
    if (unsigned.len > 0 and allDigits(unsigned)) {
        // YAML 1.1 reads a leading zero as octal.
        if (unsigned.len > 1 and unsigned[0] == '0') return error.UnsupportedYaml;
        const v = std.fmt.parseInt(i64, text, 10) catch return error.UnsupportedYaml;
        return .{ .integer = v };
    }
    if (isYamlFloat(unsigned)) {
        const f = std.fmt.parseFloat(f64, text) catch return error.UnsupportedYaml;
        if (!std.math.isFinite(f)) return error.UnsupportedYaml;
        return .{ .float = f };
    }
    if (looksLikeTimeOrBase60(text)) return error.UnsupportedYaml;
    _ = arena;
    return .{ .string = text };
}

fn appendNewlines(arena: Allocator, out: *std.ArrayList(u8), n: usize) Allocator.Error!void {
    const slot = try out.addManyAsSlice(arena, n);
    @memset(slot, '\n');
}

fn allDigits(text: []const u8) bool {
    for (text) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// True when `text` is a YAML float: `( \. [0-9]+ | [0-9]+ ( \. [0-9]* )? ) ( [eE] [-+]? [0-9]+ )?`.
fn isYamlFloat(text: []const u8) bool {
    var k: usize = 0;
    var mantissa_digits: usize = 0;
    while (k < text.len and std.ascii.isDigit(text[k])) : (k += 1) mantissa_digits += 1;
    if (k < text.len and text[k] == '.') {
        k += 1;
        while (k < text.len and std.ascii.isDigit(text[k])) : (k += 1) mantissa_digits += 1;
    }
    if (mantissa_digits == 0) return false;
    if (k < text.len and (text[k] == 'e' or text[k] == 'E')) {
        k += 1;
        if (k < text.len and (text[k] == '+' or text[k] == '-')) k += 1;
        const start = k;
        while (k < text.len and std.ascii.isDigit(text[k])) k += 1;
        if (k == start) return false;
    }
    return k == text.len;
}

/// Dates, times and base 60 numbers of YAML 1.1: digits with `-` or `:` between them.
fn looksLikeTimeOrBase60(text: []const u8) bool {
    const t = if (text.len > 0 and (text[0] == '-' or text[0] == '+')) text[1..] else text;
    if (t.len == 0 or !std.ascii.isDigit(t[0])) return false;
    var has_sep = false;
    for (t) |c| {
        switch (c) {
            '0'...'9', '.', '_' => {},
            '-', ':' => has_sep = true,
            'T', 't', 'Z', ' ', '+' => {},
            else => return false,
        }
    }
    return has_sep;
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

const testing = std.testing;

fn expectYaml(expected_json: []const u8, doc: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const v = try parseFrontmatter(arena, doc);
    const out = try json.writeAlloc(arena, v);
    try testing.expectEqualStrings(expected_json, out);
}

fn expectYamlError(expected: anyerror, doc: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(expected, parseFrontmatter(arena_state.allocator(), doc));
}

test "frontmatter: scalars and the example of the Agent Skills specification" {
    try expectYaml(
        \\{"name":"pdf-processing","description":"Extract PDF text, fill forms, merge files. Use when handling PDFs.","license":"Apache-2.0","metadata":{"author":"example-org","version":"1.0"}}
    ,
        \\---
        \\name: pdf-processing
        \\description: Extract PDF text, fill forms, merge files. Use when handling PDFs.
        \\license: Apache-2.0
        \\metadata:
        \\  author: example-org
        \\  version: "1.0"
        \\---
        \\# Body
        \\
    );
    try expectYaml(
        \\{"a":null,"b":true,"c":false,"d":42,"e":-7,"g":"it's","h":"tab\there é","i":"x # not a comment","j":"url: http://x","k":[],"l":{},"m":255}
    ,
        "---\r\na:\r\nb: true\r\nc: FALSE\r\nd: 42 # comment\r\ne: -7\r\ng: 'it''s'\r\n" ++
            "h: \"tab\\there \\u00e9\"\r\ni: 'x # not a comment'\r\nj: \"url: http://x\"\r\nk: []\r\nl: {}\r\nm: 0xff\r\n---\r\n",
    );
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const v = try parseYamlMapping(arena_state.allocator(), "f: 1.5\ng: 2e3\n");
    try testing.expectEqual(@as(f64, 1.5), v.object.get("f").?.float);
    try testing.expectEqual(@as(f64, 2000), v.object.get("g").?.float);
}

test "frontmatter: sequences, continuation lines and block scalars" {
    try expectYaml(
        \\{"tags":["a","b c"],"more":["x"],"description":"a long text over two lines","lit":"line one\nline two\n","fold":"one two\nthree\n","strip":"x","keep":"y\n\n"}
    ,
        \\---
        \\tags:
        \\  - a
        \\  - b c
        \\more:
        \\- x
        \\description: a long text
        \\  over two lines
        \\lit: |
        \\  line one
        \\  line two
        \\fold: >
        \\  one
        \\  two
        \\
        \\  three
        \\strip: |-
        \\  x
        \\keep: |+
        \\  y
        \\
        \\---
        \\
    );
}

test "frontmatter: unsupported and invalid YAML fails closed" {
    try expectYamlError(error.MissingFrontmatter, "name: x\n");
    try expectYamlError(error.MissingFrontmatter, "---\nname: x\n");
    try expectYamlError(error.UnsupportedYaml, "---\nname: &a x\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nname: *a\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nname: !!str x\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nlist: [a, b]\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nflag: yes\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nmode: 010\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nday: 2026-07-28\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nlimit: .inf\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\n\"name\": x\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nname: \"open\n  quote\"\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\nitems:\n  - k: v\n---\n");
    try expectYamlError(error.UnsupportedYaml, "---\n\tname: x\n---\n");
    try expectYamlError(error.InvalidYaml, "---\nname: a\nname: b\n---\n");
    try expectYamlError(error.InvalidYaml, "---\nname: a: b\n---\n");
    try expectYamlError(error.InvalidYaml, "---\nname: a\n   bad: indent\n---\n");
    try expectYamlError(error.NotAnObject, "---\n- a\n---\n");
    try expectYamlError(error.NotAnObject, "---\n---\n");
}

test "digests, names and skill paths" {
    var d: [digest_len]u8 = undefined;
    // The supporting file `invoice.md` of the example in the specification.
    digest("# Invoice\n\nCustomer:\nAmount:\n", &d);
    try testing.expectEqualStrings("sha256:61f4ea6d2c75fde1b4977219e7e3107d491c3c26aefb6686e84d6281c088d9ee", &d);
    try testing.expect(isDigest(&d));
    try testing.expect(!isDigest("sha256:ABC"));
    try testing.expect(isValidName("pdf-processing"));
    try testing.expect(!isValidName("PDF"));
    try testing.expect(!isValidName("-pdf"));
    try testing.expect(!isValidName("pdf--x"));
    const sp = splitSkillUri("skill://acme/billing/refunds/SKILL.md").?;
    try testing.expectEqualStrings("skill://acme/billing/refunds", sp.root);
    try testing.expectEqualStrings("refunds", sp.name);
    try testing.expect(splitSkillUri("skill://SKILL.md") == null);
    try testing.expect(isInsideSkill("skill://a/SKILL.md", "skill://a/b/c.md"));
    try testing.expect(!isInsideSkill("skill://a/SKILL.md", "skill://ab/c.md"));
    try testing.expect(!isInsideSkill("skill://a/SKILL.md", "skill://a/../b/c.md"));
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqualStrings("skill://acme/billing/refunds/references/GUIDE.md", try resolveRelative(arena, "skill://acme/billing/refunds/SKILL.md", "references/GUIDE.md"));
    try testing.expectError(error.OutsideSkill, resolveRelative(arena, "skill://a/SKILL.md", "../b/SKILL.md"));
}

test "entry validation and verification" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const skill_md = "---\nname: pdf-processing\ndescription: Extract, fill, and assemble PDF documents\n---\n\n# PDF processing\n\nChoose the matching template from `templates/`.\n";
    const invoice = "# Invoice\n\nCustomer:\nAmount:\n";
    const files = try arena.alloc(SkillResource, 2);
    files[0] = .{ .uri = "skill://pdf-processing/SKILL.md", .digest = try digestAlloc(arena, skill_md), .size = skill_md.len };
    files[1] = .{ .uri = "skill://pdf-processing/templates/invoice.md", .digest = try digestAlloc(arena, invoice), .size = invoice.len };
    // The example of the specification gives 151 bytes and this digest for SKILL.md.
    try testing.expectEqual(151, skill_md.len);
    try testing.expectEqualStrings("sha256:99b737495721155ece826d57521e2d66141ebdc1344a400487481ea2642ab19e", files[0].digest);
    const entry: Skill = .{
        .uri = "skill://pdf-processing/SKILL.md",
        .frontmatter = try parseFrontmatter(arena, skill_md),
        .resources = .{ .files = files },
    };
    try validateEntry(entry, max_files_per_skill, max_bytes_per_skill);
    try verifyFile(arena, entry, entry.uri, skill_md);
    try verifyFile(arena, entry, files[1].uri, invoice);
    try testing.expectError(error.SizeMismatch, verifyFile(arena, entry, files[1].uri, "x"));
    try testing.expectError(error.DigestMismatch, verifyFile(arena, entry, files[1].uri, "# Invoice\n\nCustomer:\nAmount:\t"));
    try testing.expectError(error.UnlistedFile, verifyFile(arena, entry, "skill://pdf-processing/templates/credit-note.md", invoice));
    try testing.expectError(error.SkillTooLarge, validateEntry(entry, 1, max_bytes_per_skill));

    // A frontmatter that differs from the entry fails, also when the digest matches.
    var other = entry;
    other.frontmatter = try parseYamlMapping(arena, "name: pdf-processing\ndescription: other\n");
    try testing.expectError(error.FrontmatterMismatch, verifyFile(arena, other, entry.uri, skill_md));

    var bad = entry;
    bad.resources = .invalid;
    try testing.expectError(error.InvalidResources, validateEntry(bad, 512, max_bytes_per_skill));
    bad.resources = .{ .files = files[1..] };
    try testing.expectError(error.MissingSkillMd, validateEntry(bad, 512, max_bytes_per_skill));
    bad = entry;
    bad.uri = "skill://other/SKILL.md";
    try testing.expectError(error.NameMismatch, validateEntry(bad, 512, max_bytes_per_skill));

    // The wire form of `resources` round-trips, and other shapes parse as invalid.
    const text = try json.writeAlloc(arena, entry);
    const back = try json.parseValue(Skill, arena, try json.parseTree(arena, text));
    try testing.expectEqual(2, back.resources.?.files.len);
    const dyn = try json.parseValue(Skill, arena, try json.parseTree(arena, "{\"uri\":\"skill://d/SKILL.md\",\"frontmatter\":{\"name\":\"d\",\"description\":\"x\"},\"resources\":\"dynamic\"}"));
    try testing.expect(dyn.resources.? == .dynamic);
    const odd = try json.parseValue(Skill, arena, try json.parseTree(arena, "{\"uri\":\"skill://d/SKILL.md\",\"resources\":7}"));
    try testing.expect(odd.resources.? == .invalid);
    try testing.expect(odd.frontmatter == null);
}
