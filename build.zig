const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mcp = b.addModule("mcp", .{
        .root_source_file = b.path("src/mcp.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests.
    const mod_tests = b.addTest(.{ .root_module = mcp });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);

    // Formatting check.
    const fmt_step = b.step("fmt", "Check formatting");
    const fmt = b.addFmt(.{ .paths = &.{ "build.zig", "build.zig.zon", "src", "examples", "tools", "conformance" }, .check = true });
    fmt_step.dependOn(&fmt.step);

    // Examples.
    const examples_step = b.step("examples", "Build all examples");
    const example_names = [_][]const u8{ "stdio_server", "https_server" };
    for (example_names) |name| {
        const exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "mcp", .module = mcp }},
            }),
        });
        const install = b.addInstallArtifact(exe, .{});
        examples_step.dependOn(&install.step);
        // The client tests spawn the stdio example.
        if (std.mem.eql(u8, name, "stdio_server")) run_mod_tests.step.dependOn(&install.step);
        const run = b.addRunArtifact(exe);
        if (b.args) |args| run.addArgs(args);
        b.step(b.fmt("run-{s}", .{name}), b.fmt("Run the {s} example", .{name})).dependOn(&run.step);
    }

    // Conformance fixtures.
    const conformance_server = b.addExecutable(.{
        .name = "mcp-conformance-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("conformance/everything_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mcp", .module = mcp }},
        }),
    });
    b.step("conformance-server", "Build the conformance everything server").dependOn(&b.addInstallArtifact(conformance_server, .{}).step);
    const conformance_client = b.addExecutable(.{
        .name = "mcp-conformance-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("conformance/everything_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mcp", .module = mcp }},
        }),
    });
    b.step("conformance-client", "Build the conformance everything client").dependOn(&b.addInstallArtifact(conformance_client, .{}).step);

    // Autodocs.
    const docs_obj = b.addObject(.{
        .name = "mcp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mcp.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    b.step("docs", "Generate API documentation").dependOn(&install_docs.step);

    // Tools written in Zig and run through `zig build <step>`.
    addTool(b, "lint-docs", "Check prose against the project STE profile", "tools/lint_docs.zig", &.{ "README.md", "docs", "src", "conformance" });
    addTool(b, "census", "Check the schema fixtures against the Zig types", "tools/schema_census.zig", &.{});
    addTool(b, "commit-policy", "Check commits for a sole signed author", "tools/commit_policy.zig", &.{});
    addTool(b, "gen-bibliography", "Check the bibliography and render it", "tools/gen_bibliography.zig", &.{ "--check", "--out", "docs/generated/bibliography.md" });
    addTool(b, "gen-dictionary", "Render the project dictionary", "tools/gen_dictionary.zig", &.{ "--out", "docs/generated/dictionary.md" });
}

fn addTool(b: *std.Build, step_name: []const u8, description: []const u8, source: []const u8, default_args: []const []const u8) void {
    const exe = b.addExecutable(.{
        .name = step_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(source),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const run = b.addRunArtifact(exe);
    run.setCwd(b.path("."));
    if (b.args) |args| run.addArgs(args) else run.addArgs(default_args);
    b.step(step_name, description).dependOn(&run.step);
}
