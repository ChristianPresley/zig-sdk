//! spec-matrix: checks the requirement mapping and renders the conformance matrix.
//!
//! The tool reads the requirements of `docs/spec/requirements.zon` and the mapping of
//! `docs/spec/requirement_tests.zon`. It fails when a requirement has no mapping, when a
//! mapping names an id that is not a requirement, when an id has two mappings, and when a
//! mapping cites a test that does not exist. A Zig test is `path:name` and must match a
//! `test "name"` declaration in that file. A conformance scenario is
//! `conformance:server/NAME` or `conformance:client/NAME` and must be in the scenario list of
//! the mapping. The harness version of the mapping must be the version that CI runs.
//!
//! Usage: spec-matrix [--check] [--fail-on-must-gap] [--out PATH]
//!
//! Without `--check` the tool writes the matrix to `docs/generated/conformance-matrix.md`.
//! With `--check` it does not write. It fails when the file on disk is not equal to a new
//! rendering. `--fail-on-must-gap` also fails when a MUST or MUST NOT requirement has the
//! status `gap`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const extract = @import("extract_requirements.zig");
const Requirement = extract.Requirement;
const Level = extract.Level;

const requirements_path = "docs/spec/requirements.zon";
const mapping_path = "docs/spec/requirement_tests.zon";
const ci_path = ".github/workflows/ci.yml";
const default_out = "docs/generated/conformance-matrix.md";
const spec_site = "https://modelcontextprotocol.io/specification/2026-07-28";

const RequirementsFile = struct {
    repo: []const u8,
    commit: []const u8,
    path: []const u8,
    fixture: []const u8,
    requirements: []const Requirement,
};

pub const Status = enum { tested, na, app, gap };

pub const Mapping = struct {
    id: []const u8,
    status: Status = .tested,
    tests: []const []const u8 = &.{},
    reason: []const u8 = "",
    note: []const u8 = "",
};

pub const MappingFile = struct {
    harness: []const u8,
    scenarios: struct {
        server: []const []const u8,
        client: []const []const u8,
    },
    mappings: []const Mapping,
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    var check = false;
    var fail_on_must_gap = false;
    var out_path: []const u8 = default_out;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--check")) {
            check = true;
        } else if (std.mem.eql(u8, args[i], "--fail-on-must-gap")) {
            fail_on_must_gap = true;
        } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else {
            std.debug.print("spec-matrix: unknown argument {s}\n", .{args[i]});
            return 2;
        }
    }

    const cwd = Io.Dir.cwd();
    const req_text = try cwd.readFileAllocOptions(io, requirements_path, arena, .limited(32 << 20), .of(u8), 0);
    var diag: std.zon.parse.Diagnostics = .{};
    const reqs = std.zon.parse.fromSliceAlloc(RequirementsFile, arena, req_text, &diag, .{}) catch |e| {
        std.debug.print("::error file={s}::cannot parse: {t}\n{f}\n", .{ requirements_path, e, diag });
        return 1;
    };
    const map_text = try cwd.readFileAllocOptions(io, mapping_path, arena, .limited(32 << 20), .of(u8), 0);
    diag = .{};
    const map = std.zon.parse.fromSliceAlloc(MappingFile, arena, map_text, &diag, .{}) catch |e| {
        std.debug.print("::error file={s}::cannot parse: {t}\n{f}\n", .{ mapping_path, e, diag });
        return 1;
    };

    var checker: Checker = .{ .arena = arena, .io = io, .dir = cwd };
    try checker.run(reqs.requirements, map);

    // The scenario list must belong to the harness version that CI runs.
    const ci = cwd.readFileAlloc(io, ci_path, arena, .limited(1 << 20)) catch "";
    if (std.mem.find(u8, ci, map.harness) == null) {
        try checker.problem("the harness {s} of {s} is not the version in {s}", .{ map.harness, mapping_path, ci_path });
    }

    const stats = computeStats(reqs.requirements, checker.by_id);
    if (fail_on_must_gap) {
        for (reqs.requirements) |r| {
            const m = checker.by_id.get(r.id) orelse continue;
            if (m.status == .gap and (r.level == .must or r.level == .must_not)) {
                try checker.problem("{s}: a {s} requirement has the status gap", .{ r.id, levelName(r.level) });
            }
        }
    }

    const page = try render(arena, reqs, map, checker.by_id, stats);
    const must = stats.levels[@intFromEnum(Level.must)].add(stats.levels[@intFromEnum(Level.must_not)]);
    std.debug.print("spec-matrix: {d} requirements, {d} tested, {d} n/a, {d} app, {d} gap. MUST and MUST NOT: {d} of {d} tested, {d} gap.\n", .{
        stats.total.total, stats.total.tested, stats.total.na, stats.total.app, stats.total.gap, must.tested, must.total, must.gap,
    });

    if (check) {
        const current = cwd.readFileAlloc(io, out_path, arena, .limited(32 << 20)) catch "";
        if (!eqlIgnoringCr(current, page)) {
            try checker.problem("{s} is out of date. Run zig build spec-matrix.", .{out_path});
        }
    } else {
        if (std.fs.path.dirname(out_path)) |parent| try cwd.createDirPath(io, parent);
        try cwd.writeFile(io, .{ .sub_path = out_path, .data = page });
        std.debug.print("spec-matrix: wrote {s}\n", .{out_path});
    }
    if (checker.problems > 0) {
        std.debug.print("spec-matrix: {d} problems\n", .{checker.problems});
        return 1;
    }
    return 0;
}

fn eqlIgnoringCr(a: []const u8, b: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (true) {
        while (i < a.len and a[i] == '\r') i += 1;
        while (j < b.len and b[j] == '\r') j += 1;
        if (i == a.len or j == b.len) return i == a.len and j == b.len;
        if (a[i] != b[j]) return false;
        i += 1;
        j += 1;
    }
}

// ----------------------------------------------------------------------------------------
// Checks
// ----------------------------------------------------------------------------------------

const Checker = struct {
    arena: Allocator,
    io: Io,
    dir: Io.Dir,
    problems: usize = 0,
    /// Count problems without a message (for the unit tests).
    quiet: bool = false,
    by_id: std.StringHashMapUnmanaged(Mapping) = .empty,
    /// Test names of each Zig file that a mapping cites. Null when the file cannot be read.
    files: std.StringHashMapUnmanaged(?[]const []const u8) = .empty,

    fn problem(self: *Checker, comptime fmt: []const u8, args: anytype) !void {
        self.problems += 1;
        if (self.quiet) return;
        std.debug.print("::error::" ++ fmt ++ "\n", args);
    }

    fn run(self: *Checker, reqs: []const Requirement, map: MappingFile) !void {
        var known: std.StringHashMapUnmanaged(void) = .empty;
        for (reqs) |r| try known.put(self.arena, r.id, {});

        for (map.mappings) |m| {
            if (!known.contains(m.id)) {
                try self.problem("{s}: the mapping names an id that is not a requirement (stale mapping)", .{m.id});
                continue;
            }
            const entry = try self.by_id.getOrPut(self.arena, m.id);
            if (entry.found_existing) {
                try self.problem("{s}: the id has more than one mapping", .{m.id});
                continue;
            }
            entry.value_ptr.* = m;
            switch (m.status) {
                .tested => if (m.tests.len == 0) try self.problem("{s}: the status tested needs at least one test", .{m.id}),
                .na, .app, .gap => if (m.reason.len == 0) try self.problem("{s}: the status {t} needs a reason", .{ m.id, m.status }),
            }
            for (m.tests) |t| try self.checkTest(m.id, t, map);
        }
        for (reqs) |r| {
            if (!self.by_id.contains(r.id)) try self.problem("{s}: the requirement has no mapping", .{r.id});
        }
    }

    fn checkTest(self: *Checker, id: []const u8, ref: []const u8, map: MappingFile) !void {
        if (std.mem.startsWith(u8, ref, "conformance:")) {
            const rest = ref["conformance:".len..];
            const list, const name = if (std.mem.startsWith(u8, rest, "server/"))
                .{ map.scenarios.server, rest["server/".len..] }
            else if (std.mem.startsWith(u8, rest, "client/"))
                .{ map.scenarios.client, rest["client/".len..] }
            else {
                try self.problem("{s}: {s}: a scenario starts with conformance:server/ or conformance:client/", .{ id, ref });
                return;
            };
            for (list) |s| if (std.mem.eql(u8, s, name)) return;
            try self.problem("{s}: {s}: the scenario is not in the scenario list", .{ id, ref });
            return;
        }
        const split = splitTestRef(ref) orelse {
            try self.problem("{s}: {s}: a test reference is path.zig:name", .{ id, ref });
            return;
        };
        const names = try self.testNames(split.path) orelse {
            try self.problem("{s}: {s}: cannot read {s}", .{ id, ref, split.path });
            return;
        };
        for (names) |n| if (std.mem.eql(u8, n, split.name)) return;
        try self.problem("{s}: {s}: no test with this name in {s}", .{ id, ref, split.path });
    }

    fn testNames(self: *Checker, path: []const u8) !?[]const []const u8 {
        if (self.files.get(path)) |cached| return cached;
        const text = self.dir.readFileAlloc(self.io, path, self.arena, .limited(16 << 20)) catch {
            try self.files.put(self.arena, path, null);
            return null;
        };
        const names = try parseTestNames(self.arena, text);
        try self.files.put(self.arena, path, names);
        return names;
    }
};

pub const TestRef = struct { path: []const u8, name: []const u8 };

/// Splits `path.zig:name` at the first `.zig:`.
pub fn splitTestRef(ref: []const u8) ?TestRef {
    const at = std.mem.find(u8, ref, ".zig:") orelse return null;
    const name = ref[at + ".zig:".len ..];
    if (name.len == 0) return null;
    return .{ .path = ref[0 .. at + ".zig".len], .name = name };
}

/// Returns the names of the `test "name"` declarations of a Zig file.
pub fn parseTestNames(arena: Allocator, text: []const u8) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimStart(u8, raw, " \t");
        if (!std.mem.startsWith(u8, line, "test \"")) continue;
        const start = "test \"".len;
        var j = start;
        var name: std.ArrayList(u8) = .empty;
        while (j < line.len and line[j] != '"') : (j += 1) {
            if (line[j] == '\\' and j + 1 < line.len) {
                j += 1;
                try name.append(arena, switch (line[j]) {
                    'n' => '\n',
                    't' => '\t',
                    else => line[j],
                });
            } else {
                try name.append(arena, line[j]);
            }
        }
        if (j < line.len) try names.append(arena, name.items);
    }
    return names.items;
}

// ----------------------------------------------------------------------------------------
// Statistics
// ----------------------------------------------------------------------------------------

const Counts = struct {
    total: usize = 0,
    tested: usize = 0,
    na: usize = 0,
    app: usize = 0,
    gap: usize = 0,

    fn count(self: *Counts, status: Status) void {
        self.total += 1;
        switch (status) {
            .tested => self.tested += 1,
            .na => self.na += 1,
            .app => self.app += 1,
            .gap => self.gap += 1,
        }
    }

    fn add(a: Counts, b: Counts) Counts {
        return .{ .total = a.total + b.total, .tested = a.tested + b.tested, .na = a.na + b.na, .app = a.app + b.app, .gap = a.gap + b.gap };
    }
};

const level_count = @typeInfo(Level).@"enum".fields.len;

const Stats = struct {
    total: Counts = .{},
    levels: [level_count]Counts = @splat(.{}),
};

fn computeStats(reqs: []const Requirement, by_id: std.StringHashMapUnmanaged(Mapping)) Stats {
    var s: Stats = .{};
    for (reqs) |r| {
        const status = if (by_id.get(r.id)) |m| m.status else .gap;
        s.total.count(status);
        s.levels[@intFromEnum(r.level)].count(status);
    }
    return s;
}

fn levelName(level: Level) []const u8 {
    return switch (level) {
        .must => "MUST",
        .must_not => "MUST NOT",
        .should => "SHOULD",
        .should_not => "SHOULD NOT",
        .may => "MAY",
    };
}

fn statusName(status: Status) []const u8 {
    return switch (status) {
        .tested => "tested",
        .na => "n/a",
        .app => "app",
        .gap => "gap",
    };
}

fn percent(part: usize, whole: usize) usize {
    if (whole == 0) return 100;
    return (part * 100) / whole;
}

// ----------------------------------------------------------------------------------------
// Rendering
// ----------------------------------------------------------------------------------------

fn pageUrl(arena: Allocator, page: []const u8, anchor: []const u8) ![]const u8 {
    const path = if (std.mem.eql(u8, page, "index")) "" else page;
    const sep: []const u8 = if (path.len > 0) "/" else "";
    const hash: []const u8 = if (anchor.len > 0) "#" else "";
    return std.fmt.allocPrint(arena, "{s}{s}{s}{s}{s}", .{ spec_site, sep, path, hash, anchor });
}

/// Writes text into a table cell: escapes the cell separator and HTML outside code spans.
fn writeCell(w: *Io.Writer, text: []const u8) !void {
    var in_code = false;
    for (text) |c| {
        switch (c) {
            '`' => {
                in_code = !in_code;
                try w.writeByte(c);
            },
            '|' => try w.writeAll("\\|"),
            '<' => if (in_code) try w.writeByte(c) else try w.writeAll("&lt;"),
            '\n', '\r' => try w.writeByte(' '),
            else => try w.writeByte(c),
        }
    }
}

fn writeCountsRow(w: *Io.Writer, label: []const u8, c: Counts) !void {
    try w.print("| {s} | {d} | {d} | {d} | {d} | {d} | {d} % |\n", .{ label, c.total, c.tested, c.na, c.app, c.gap, percent(c.tested + c.na + c.app, c.total) });
}

fn writeTestRef(w: *Io.Writer, ref: []const u8) !void {
    if (std.mem.startsWith(u8, ref, "conformance:")) {
        try w.print("`{s}`", .{ref});
        return;
    }
    const split = splitTestRef(ref) orelse {
        try writeCell(w, ref);
        return;
    };
    const base = std.fs.path.basename(split.path);
    try w.print("[{s}](../../{s}): ", .{ base, split.path });
    try writeCell(w, split.name);
}

fn render(arena: Allocator, reqs: RequirementsFile, map: MappingFile, by_id: std.StringHashMapUnmanaged(Mapping), stats: Stats) ![]const u8 {
    var aw: Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("# Conformance matrix\n\n");
    try w.print("<!-- ste: descriptive | generated by zig build spec-matrix from {s} and {s} -->\n\n", .{ requirements_path, mapping_path });
    try w.writeAll("This page maps each normative sentence of MCP specification revision 2026-07-28 to the tests of the SDK. ");
    try w.writeAll("A normative sentence has an RFC 2119 keyword in uppercase. ");
    try w.print("The sentences come from the specification pages at commit `{s}` of {s}, vendored in `{s}`. ", .{ reqs.commit, reqs.repo, reqs.fixture });
    try w.writeAll("The quoted text is licensed by the MCP project under the license in that directory.\n\n");
    try w.print("Tests are Zig tests of this repository and scenarios of the conformance suite `{s}`. The CI job `conformance` runs the scenarios.\n\n", .{map.harness});

    try w.writeAll("## Status values\n\n");
    try w.writeAll("| Status | Meaning |\n| --- | --- |\n");
    try w.writeAll("| tested | One or more tests check the requirement. |\n");
    try w.writeAll("| n/a | The requirement does not apply to the SDK. The reason tells why. |\n");
    try w.writeAll("| app | The application that uses the SDK is responsible. The reason tells what the SDK gives. |\n");
    try w.writeAll("| gap | No test checks the requirement yet. The reason tells what is missing. |\n\n");

    try w.writeAll("## Summary\n\n");
    const must = stats.levels[@intFromEnum(Level.must)].add(stats.levels[@intFromEnum(Level.must_not)]);
    try w.print("The specification has {d} normative sentences. {d} are MUST or MUST NOT requirements. ", .{ stats.total.total, must.total });
    try w.print("Of these, {d} are tested, {d} do not apply, {d} are for the application and {d} are gaps.\n\n", .{ must.tested, must.na, must.app, must.gap });
    try w.writeAll("The column Covered gives the part of the requirements that has a test, an n/a reason or an app reason.\n\n");

    try w.writeAll("### By keyword\n\n");
    try w.writeAll("| Keyword | Total | Tested | n/a | App | Gap | Covered |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for (std.enums.values(Level)) |lv| try writeCountsRow(w, levelName(lv), stats.levels[@intFromEnum(lv)]);
    try writeCountsRow(w, "All", stats.total);
    try w.writeAll("\n");

    try w.writeAll("### By page\n\n");
    try w.writeAll("| Page | Total | Tested | n/a | App | Gap | Covered | MUST gaps |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    {
        var i: usize = 0;
        while (i < reqs.requirements.len) {
            const page = reqs.requirements[i].page;
            var c: Counts = .{};
            var must_gaps: usize = 0;
            var j = i;
            while (j < reqs.requirements.len and std.mem.eql(u8, reqs.requirements[j].page, page)) : (j += 1) {
                const r = reqs.requirements[j];
                const status = if (by_id.get(r.id)) |m| m.status else .gap;
                c.count(status);
                if (status == .gap and (r.level == .must or r.level == .must_not)) must_gaps += 1;
            }
            try w.print("| [{s}](#{s}) | {d} | {d} | {d} | {d} | {d} | {d} % | {d} |\n", .{
                page, try headingAnchor(arena, page), c.total, c.tested, c.na, c.app, c.gap, percent(c.tested + c.na + c.app, c.total), must_gaps,
            });
            i = j;
        }
    }
    try w.writeAll("\n");

    try w.writeAll("## Requirements\n\n");
    var current: ?[]const u8 = null;
    for (reqs.requirements) |r| {
        if (current == null or !std.mem.eql(u8, current.?, r.page)) {
            current = r.page;
            try w.print("### {s}\n\n", .{r.page});
            try w.print("Specification page: <{s}>\n\n", .{try pageUrl(arena, r.page, "")});
            try w.writeAll("| Id | Keyword | Party | Requirement | Status | Tests or reason |\n| --- | --- | --- | --- | --- | --- |\n");
        }
        const m = by_id.get(r.id);
        try w.print("| [{s}]({s}) | {s} | {s} | ", .{ r.id, try pageUrl(arena, r.page, r.anchor), levelName(r.level), switch (r.party) {
            .client => "client",
            .server => "server",
            .both => "both",
            .authorization_server => "authorization server",
        } });
        try writeCell(w, r.text);
        if (m) |mm| {
            try w.print(" | {s} | ", .{statusName(mm.status)});
            if (mm.reason.len > 0) {
                try writeCell(w, mm.reason);
                if (mm.tests.len > 0) try w.writeAll(" Partial: ");
            }
            for (mm.tests, 0..) |t, ti| {
                if (ti > 0) try w.writeAll("<br>");
                try writeTestRef(w, t);
            }
            if (mm.note.len > 0) {
                try w.writeAll(" (");
                try writeCell(w, mm.note);
                try w.writeAll(")");
            }
            try w.writeAll(" |\n");
        } else {
            try w.writeAll(" | unmapped | |\n");
        }
    }
    return aw.toOwnedSlice();
}

/// The anchor that GitHub gives to a heading.
fn headingAnchor(arena: Allocator, heading: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (heading) |c| {
        if (std.ascii.isAlphanumeric(c)) {
            try out.append(arena, std.ascii.toLower(c));
        } else if (c == ' ' or c == '-') {
            try out.append(arena, '-');
        } else if (c == '_') {
            try out.append(arena, '_');
        }
    }
    return out.items;
}

// ----------------------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------------------

test "test declarations and references" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const names = try parseTestNames(arena,
        \\test "a: b" {
        \\    // test "not a declaration"
        \\}
        \\    test "quoted \"x\"" {}
        \\test {}
    );
    try std.testing.expectEqual(2, names.len);
    try std.testing.expectEqualStrings("a: b", names[0]);
    try std.testing.expectEqualStrings("quoted \"x\"", names[1]);
    const ref = splitTestRef("src/a/b.zig:grpc: x.zig: y").?;
    try std.testing.expectEqualStrings("src/a/b.zig", ref.path);
    try std.testing.expectEqualStrings("grpc: x.zig: y", ref.name);
    try std.testing.expect(splitTestRef("src/a/b.zig:") == null);
}

test "the checker finds unmapped, stale and duplicate ids" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const reqs = [_]Requirement{
        .{ .id = "p#001-aaaaaa", .page = "p", .line = 1, .section = "", .anchor = "", .level = .must, .keywords = &.{"MUST"}, .party = .server, .text = "x" },
        .{ .id = "p#002-bbbbbb", .page = "p", .line = 2, .section = "", .anchor = "", .level = .may, .keywords = &.{"MAY"}, .party = .client, .text = "y" },
    };
    const map: MappingFile = .{
        .harness = "h",
        .scenarios = .{ .server = &.{"tools-list"}, .client = &.{} },
        .mappings = &.{
            .{ .id = "p#001-aaaaaa", .tests = &.{"conformance:server/tools-list"} },
            .{ .id = "p#001-aaaaaa", .status = .na, .reason = "twice" },
            .{ .id = "p#009-cccccc", .status = .app, .reason = "stale" },
            .{ .id = "p#002-bbbbbb", .tests = &.{"conformance:client/unknown"} },
        },
    };
    var checker: Checker = .{ .arena = arena, .io = std.testing.io, .dir = Io.Dir.cwd(), .quiet = true };
    try checker.run(&reqs, map);
    // Duplicate, stale and unknown scenario.
    try std.testing.expectEqual(3, checker.problems);
}
