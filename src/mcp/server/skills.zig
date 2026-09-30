//! The server part of the Skills extension (`io.modelcontextprotocol/skills`, SEP-2640). The
//! registry keeps the skill entries and the files of the skills. The server serves each file
//! as a resource through `resources/read`. The registry also answers `skills/list`,
//! `skills/get` and `resources/directory/read`.
//!
//! The extension defines no client declaration. Thus the server does not gate the methods on
//! the client capabilities.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("../protocol/types.zig");
const proto = @import("../protocol/skills.zig");
const mrtr = @import("mrtr.zig");
const RequestContext = @import("RequestContext.zig");

pub const extension_id = proto.extension_id;

pub const Options = struct {
    /// Declare `directoryRead: true` and answer `resources/directory/read`.
    directory_read: bool = true,
};

/// A file of a skill other than `SKILL.md`.
pub const File = struct {
    /// The path relative to the skill root, with `/` between the segments.
    path: []const u8,
    /// The raw bytes of the file.
    content: []const u8,
    /// Null selects a MIME type from the file extension.
    mime_type: ?[]const u8 = null,
};

/// A skill with its files in memory.
pub const SkillDef = struct {
    /// The URI scheme. The extension recommends `skill`.
    scheme: []const u8 = proto.default_scheme,
    /// The organizational prefix of the skill path without a slash at the ends, or empty.
    prefix: []const u8 = "",
    /// The name of the skill directory. It must be equal to `name` in the frontmatter.
    name: []const u8,
    /// The bytes of `SKILL.md`.
    skill_md: []const u8,
    /// The other files of the skill. The files of nested skills are also in this list.
    files: []const File = &.{},
};

/// A skill with generated content. The entry has `"resources": "dynamic"`. The application
/// serves the files with its own resources or resource templates.
pub const DynamicSkillDef = struct {
    scheme: []const u8 = proto.default_scheme,
    prefix: []const u8 = "",
    name: []const u8,
    /// A `SKILL.md` text with the frontmatter of the skill.
    skill_md: []const u8,
};

pub const DefinitionError = error{
    OutOfMemory,
    /// The server has no `skills` option.
    ExtensionNotEnabled,
    /// The name does not obey the naming rules of the Agent Skills specification.
    InvalidSkillName,
    /// The scheme or a segment of the prefix has characters that a URI does not allow.
    InvalidSkillPath,
    /// A file path is empty, absolute, has an empty, `.` or `..` segment, or repeats.
    InvalidFilePath,
    /// `SKILL.md` does not start with a frontmatter block.
    MissingFrontmatter,
    /// The frontmatter is not valid YAML, is not a YAML map, or has no valid `name` or
    /// `description`.
    InvalidFrontmatter,
    /// The frontmatter uses YAML outside the subset of `skills.parseFrontmatter`.
    UnsupportedFrontmatter,
    /// The frontmatter `name` is not equal to the directory name.
    NameMismatch,
    /// The skill has more files than `Limits.skills.max_files`.
    TooManySkillFiles,
    /// The files of the skill have more bytes than `Limits.skills.max_bytes`.
    SkillTooLarge,
    /// A skill with the same URI exists.
    DuplicateSkill,
    /// A file URI exists with different bytes.
    ConflictingSkillFile,
    /// The file list of an outer skill does not list a file of a nested skill.
    IncompleteSkill,
};

/// A file that the server serves. The registry arena owns it.
pub const StoredFile = struct {
    uri: []const u8,
    /// The last path segment, or the skill name for `SKILL.md`.
    name: []const u8,
    description: ?[]const u8 = null,
    mime_type: []const u8,
    content: []const u8,
};

/// The result of `prepare`. The caller registers `new_files` as resources and then calls
/// `commit`.
pub const Prepared = struct {
    entry: proto.Skill,
    new_files: []const *StoredFile,
};

pub const Registry = struct {
    options: Options,
    entries: std.ArrayList(proto.Skill) = .empty,
    files: std.ArrayList(*StoredFile) = .empty,

    pub fn init(options: Options) Registry {
        return .{ .options = options };
    }

    pub fn deinit(self: *Registry, gpa: Allocator) void {
        self.entries.deinit(gpa);
        self.files.deinit(gpa);
    }

    /// The settings object of the extension in the server capabilities.
    pub fn settings(self: *const Registry, arena: Allocator) Allocator.Error!Value {
        var obj: std.json.ObjectMap = .empty;
        if (self.options.directory_read) try obj.put(arena, "directoryRead", .{ .bool = true });
        return .{ .object = obj };
    }

    pub fn findSkill(self: *const Registry, uri: []const u8) ?proto.Skill {
        for (self.entries.items) |e| if (std.mem.eql(u8, e.uri, uri)) return e;
        return null;
    }

    pub fn findFile(self: *const Registry, uri: []const u8) ?*StoredFile {
        for (self.files.items) |f| if (std.mem.eql(u8, f.uri, uri)) return f;
        return null;
    }

    /// Validate a skill and build its entry and files in `arena`. The function registers nothing.
    pub fn prepare(self: *const Registry, arena: Allocator, def: SkillDef, max_files: u32, max_bytes: u64) DefinitionError!Prepared {
        const root = try skillRoot(arena, def.scheme, def.prefix, def.name);
        const skill_uri = try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, proto.skill_md_name });
        if (self.findSkill(skill_uri) != null) return error.DuplicateSkill;
        const fm = try parseAndCheckFrontmatter(arena, def.skill_md, def.name);

        if (def.files.len + 1 > max_files) return error.TooManySkillFiles;
        var total: u64 = def.skill_md.len;
        for (def.files, 0..) |f, i| {
            if (!isCleanFilePath(f.path) or std.mem.eql(u8, f.path, proto.skill_md_name)) return error.InvalidFilePath;
            for (def.files[0..i]) |g| if (std.mem.eql(u8, g.path, f.path)) return error.InvalidFilePath;
            total += f.content.len;
        }
        if (total > max_bytes) return error.SkillTooLarge;

        // Build the stored files and the manifest. `SKILL.md` comes first.
        const manifest = try arena.alloc(proto.SkillResource, def.files.len + 1);
        var stored: std.ArrayList(*StoredFile) = .empty;
        var new_files: std.ArrayList(*StoredFile) = .empty;
        for (0..def.files.len + 1) |k| {
            const is_md = k == 0;
            const path = if (is_md) proto.skill_md_name else def.files[k - 1].path;
            const content = if (is_md) def.skill_md else def.files[k - 1].content;
            const uri = if (is_md) skill_uri else try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, path });
            manifest[k] = .{ .uri = uri, .digest = try proto.digestAlloc(arena, content), .size = @intCast(content.len) };
            if (self.findFile(uri)) |existing| {
                // A nested skill shares its files with the enclosing skill.
                if (!std.mem.eql(u8, existing.content, content)) return error.ConflictingSkillFile;
                try stored.append(arena, existing);
                continue;
            }
            const file = try arena.create(StoredFile);
            file.* = .{
                .uri = uri,
                .name = if (is_md) try arena.dupe(u8, def.name) else baseName(uri),
                .description = if (is_md) fm.object.get("description").?.string else null,
                .mime_type = if (is_md) proto.skill_md_mime_type else if (def.files[k - 1].mime_type) |m| try arena.dupe(u8, m) else mimeTypeFor(path),
                .content = try arena.dupe(u8, content),
            };
            try stored.append(arena, file);
            try new_files.append(arena, file);
        }
        const entry: proto.Skill = .{ .uri = skill_uri, .frontmatter = fm, .resources = .{ .files = manifest } };
        try self.checkNesting(entry, root);
        return .{ .entry = entry, .new_files = new_files.items };
    }

    /// Prepare a dynamic skill. It has no stored files.
    pub fn prepareDynamic(self: *const Registry, arena: Allocator, def: DynamicSkillDef) DefinitionError!Prepared {
        const root = try skillRoot(arena, def.scheme, def.prefix, def.name);
        const skill_uri = try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, proto.skill_md_name });
        if (self.findSkill(skill_uri) != null) return error.DuplicateSkill;
        const fm = try parseAndCheckFrontmatter(arena, def.skill_md, def.name);
        return .{ .entry = .{ .uri = skill_uri, .frontmatter = fm, .resources = .dynamic }, .new_files = &.{} };
    }

    /// Nested skills: the file list of an outer skill lists the files of the skills
    /// inside it. Check both directions.
    fn checkNesting(self: *const Registry, entry: proto.Skill, root: []const u8) DefinitionError!void {
        // Registered files under the new root must be in the new manifest.
        for (self.files.items) |f| {
            if (isUnder(f.uri, root) and proto.findFile(entry, f.uri) == null) return error.IncompleteSkill;
        }
        // An enclosing skill must list every file of the new skill with the same digest.
        for (self.entries.items) |outer| {
            const outer_files = switch (outer.resources.?) {
                .files => |files| files,
                else => continue,
            };
            const outer_root = proto.splitSkillUri(outer.uri).?.root;
            if (!isUnder(root, outer_root)) continue;
            for (entry.resources.?.files) |f| {
                const match = for (outer_files) |g| {
                    if (std.mem.eql(u8, g.uri, f.uri)) break g;
                } else return error.IncompleteSkill;
                if (!std.mem.eql(u8, match.digest, f.digest)) return error.IncompleteSkill;
            }
        }
    }

    /// Add a prepared skill. Call it after the registration of the new files as resources.
    pub fn commit(self: *Registry, gpa: Allocator, prepared: Prepared) Allocator.Error!void {
        try self.files.ensureUnusedCapacity(gpa, prepared.new_files.len);
        try self.entries.append(gpa, prepared.entry);
        self.files.appendSliceAssumeCapacity(prepared.new_files);
    }

    /// The direct children of a directory, sorted by URI. Null when no stored file is under
    /// the directory, thus the URI is not a directory resource.
    pub fn directoryChildren(self: *const Registry, arena: Allocator, dir: []const u8) Allocator.Error!?[]types.Resource {
        if (dir.len == 0 or dir[dir.len - 1] == '/') return null;
        var children: std.ArrayList(types.Resource) = .empty;
        var dirs: std.StringHashMapUnmanaged(void) = .empty;
        for (self.files.items) |f| {
            if (!isUnder(f.uri, dir)) continue;
            const rest = f.uri[dir.len + 1 ..];
            if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
                const child = f.uri[0 .. dir.len + 1 + slash];
                const gop = try dirs.getOrPut(arena, child);
                if (gop.found_existing) continue;
                try children.append(arena, .{ .uri = child, .name = rest[0..slash], .mimeType = proto.directory_mime_type });
            } else {
                try children.append(arena, .{ .uri = f.uri, .name = rest, .mimeType = f.mime_type, .size = @intCast(f.content.len) });
            }
        }
        if (children.items.len == 0) return null;
        std.mem.sort(types.Resource, children.items, {}, lessByUri);
        return children.items;
    }
};

fn lessByUri(_: void, a: types.Resource, b: types.Resource) bool {
    return std.mem.lessThan(u8, a.uri, b.uri);
}

/// True when `uri` is below the directory `dir`.
fn isUnder(uri: []const u8, dir: []const u8) bool {
    return uri.len > dir.len + 1 and std.mem.startsWith(u8, uri, dir) and uri[dir.len] == '/';
}

fn baseName(uri: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, uri, '/') orelse return uri;
    return uri[slash + 1 ..];
}

/// `scheme://prefix/name`, after validation of every part.
fn skillRoot(arena: Allocator, scheme: []const u8, prefix: []const u8, name: []const u8) DefinitionError![]const u8 {
    if (!proto.isValidName(name)) return error.InvalidSkillName;
    if (scheme.len == 0 or !std.ascii.isAlphabetic(scheme[0])) return error.InvalidSkillPath;
    for (scheme) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.')) return error.InvalidSkillPath;
    }
    if (prefix.len > 0) {
        var it = std.mem.splitScalar(u8, prefix, '/');
        var first = true;
        while (it.next()) |seg| {
            if (!isSegment(seg, first)) return error.InvalidSkillPath;
            first = false;
        }
        return std.fmt.allocPrint(arena, "{s}://{s}/{s}", .{ scheme, prefix, name });
    }
    return std.fmt.allocPrint(arena, "{s}://{s}", .{ scheme, name });
}

/// A path segment of unreserved characters and sub-delimiters. The first segment is the
/// authority, thus it must be a `reg-name` without `:` and `@`.
fn isSegment(seg: []const u8, authority: bool) bool {
    if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
    for (seg) |c| {
        const ok = std.ascii.isAlphanumeric(c) or switch (c) {
            '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
            ':', '@' => !authority,
            else => false,
        };
        if (!ok) return false;
    }
    return true;
}

fn isCleanFilePath(path: []const u8) bool {
    if (path.len == 0) return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| if (!isSegment(seg, false)) return false;
    return true;
}

fn parseAndCheckFrontmatter(arena: Allocator, skill_md: []const u8, name: []const u8) DefinitionError!Value {
    const fm = proto.parseFrontmatter(arena, skill_md) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MissingFrontmatter => return error.MissingFrontmatter,
        error.UnsupportedYaml => return error.UnsupportedFrontmatter,
        error.InvalidYaml, error.NotAnObject => return error.InvalidFrontmatter,
    };
    const fm_name = fm.object.get("name") orelse return error.InvalidFrontmatter;
    const description = fm.object.get("description") orelse return error.InvalidFrontmatter;
    if (fm_name != .string or description != .string) return error.InvalidFrontmatter;
    if (description.string.len == 0 or description.string.len > 1024) return error.InvalidFrontmatter;
    if (!std.mem.eql(u8, fm_name.string, name)) return error.NameMismatch;
    return fm;
}

/// A MIME type for common file extensions. Other files get `application/octet-stream`.
pub fn mimeTypeFor(path: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse return "application/octet-stream";
    const ext = path[dot + 1 ..];
    const table = [_]struct { []const u8, []const u8 }{
        .{ "md", "text/markdown" },      .{ "markdown", "text/markdown" },
        .{ "txt", "text/plain" },        .{ "json", "application/json" },
        .{ "yaml", "application/yaml" }, .{ "yml", "application/yaml" },
        .{ "py", "text/x-python" },      .{ "sh", "text/x-shellscript" },
        .{ "js", "text/javascript" },    .{ "ts", "text/x-typescript" },
        .{ "html", "text/html" },        .{ "css", "text/css" },
        .{ "csv", "text/csv" },          .{ "xml", "application/xml" },
        .{ "svg", "image/svg+xml" },     .{ "png", "image/png" },
        .{ "jpg", "image/jpeg" },        .{ "jpeg", "image/jpeg" },
        .{ "gif", "image/gif" },         .{ "pdf", "application/pdf" },
        .{ "zig", "text/x-zig" },        .{ "toml", "application/toml" },
    };
    for (table) |row| if (std.ascii.eqlIgnoreCase(row[0], ext)) return row[1];
    return "application/octet-stream";
}

/// The resource handler of a stored file. Valid UTF-8 goes out as text, other bytes as a
/// base64 blob. The digest covers the raw bytes in both cases.
pub fn readFile(ctx: *RequestContext, uri: []const u8) anyerror!mrtr.Outcome(types.ReadResourceResult) {
    const file: *const StoredFile = @ptrCast(@alignCast(ctx.userdata.?));
    const contents = try ctx.arena.alloc(types.ResourceContents, 1);
    if (std.unicode.utf8ValidateSlice(file.content)) {
        contents[0] = .{ .text = .{ .uri = uri, .mimeType = file.mime_type, .text = file.content } };
    } else {
        const encoder = std.base64.standard.Encoder;
        const out = try ctx.arena.alloc(u8, encoder.calcSize(file.content.len));
        contents[0] = .{ .blob = .{ .uri = uri, .mimeType = file.mime_type, .blob = encoder.encode(out, file.content) } };
    }
    return .{ .complete = .{ .contents = contents } };
}

test "skill roots and file paths" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("skill://acme/billing/refunds", try skillRoot(arena, "skill", "acme/billing", "refunds"));
    try std.testing.expectEqualStrings("skill://git-workflow", try skillRoot(arena, "skill", "", "git-workflow"));
    try std.testing.expectError(error.InvalidSkillName, skillRoot(arena, "skill", "", "Bad"));
    try std.testing.expectError(error.InvalidSkillPath, skillRoot(arena, "skill", "a b", "x"));
    try std.testing.expectError(error.InvalidSkillPath, skillRoot(arena, "skill", "user@host", "x"));
    try std.testing.expect(isCleanFilePath("templates/invoice.md"));
    try std.testing.expect(!isCleanFilePath("../x"));
    try std.testing.expect(!isCleanFilePath("/x"));
    try std.testing.expect(!isCleanFilePath("a//b"));
    try std.testing.expectEqualStrings("text/markdown", mimeTypeFor("a/B.MD"));
    try std.testing.expectEqualStrings("application/octet-stream", mimeTypeFor("bin"));
}
