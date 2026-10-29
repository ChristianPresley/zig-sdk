const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mcp = b.addModule("mcp", .{
        .root_source_file = b.path("src/mcp.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests. `-Dfuzz` prepares them for `zig build test -Dfuzz --fuzz`: it selects the LLVM
    // backend, because the self-hosted backend of Debug builds emits no `__sancov_pcs1` table and
    // the fuzzer then sees no coverage.
    const fuzz = b.option(bool, "fuzz", "Prepare the unit tests for --fuzz") orelse false;
    const use_llvm: ?bool = if (fuzz) true else null;
    const mod_tests = b.addTest(.{ .root_module = mcp, .use_llvm = use_llvm });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);

    // The gRPC transport is its own module; nothing in `mcp` imports it.
    const mcp_grpc = b.addModule("mcp_grpc", .{
        .root_source_file = b.path("src/mcp_grpc.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "mcp", .module = mcp }},
    });
    const grpc_tests = b.addTest(.{ .root_module = mcp_grpc, .use_llvm = use_llvm });
    test_step.dependOn(&b.addRunArtifact(grpc_tests).step);

    // The tests of the documentation tools.
    for ([_][]const u8{ "tools/lint_docs/main.zig", "tools/gen_dictionary.zig" }) |tool_source| {
        const tool_tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path(tool_source),
            .target = b.graph.host,
        }) });
        const run_tool_tests = b.addRunArtifact(tool_tests);
        run_tool_tests.setCwd(b.path("."));
        test_step.dependOn(&run_tool_tests.step);
    }

    // Formatting check.
    const fmt_step = b.step("fmt", "Check formatting");
    const fmt = b.addFmt(.{ .paths = &.{ b.path("build.zig"), b.path("build.zig.zon"), b.path("src"), b.path("examples"), b.path("tools"), b.path("conformance"), b.path("bench") }, .check = true });
    fmt_step.dependOn(&fmt.step);

    // Examples.
    const examples_step = b.step("examples", "Build all examples");
    const example_names = [_][]const u8{ "stdio_server", "https_server", "grpc_server", "grpc_client", "client_cli", "unix_server", "websocket_server", "authorization_server" };
    for (example_names) |name| {
        const exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{ .{ .name = "mcp", .module = mcp }, .{ .name = "mcp_grpc", .module = mcp_grpc } },
            }),
        });
        const install = b.addInstallArtifact(exe, .{});
        examples_step.dependOn(&install.step);
        // The client tests spawn the stdio example.
        if (std.mem.eql(u8, name, "stdio_server")) run_mod_tests.step.dependOn(&install.step);
        // The test of the command line of the gRPC client.
        if (std.mem.eql(u8, name, "grpc_client")) test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = exe.root_module })).step);
        const run = b.addRunArtifact(exe);
        run.addPassthruArgs();
        b.step(b.fmt("run-{s}", .{name}), b.fmt("Run the {s} example", .{name})).dependOn(&run.step);
    }

    // Conformance fixtures.
    const conformance_server = b.addExecutable(.{
        .name = "mcp-conformance-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("conformance/everything_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ .{ .name = "mcp", .module = mcp }, .{ .name = "mcp_grpc", .module = mcp_grpc } },
        }),
    });
    b.step("conformance-server", "Build the conformance everything server").dependOn(&b.addInstallArtifact(conformance_server, .{}).step);
    // The tests of the conformance server run with the other tests.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = conformance_server.root_module })).step);
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
    const conformance_as = b.addExecutable(.{
        .name = "mcp-conformance-authorization-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("conformance/authorization_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mcp", .module = mcp }},
        }),
    });
    b.step("conformance-authorization-server", "Build the conformance authorization server").dependOn(&b.addInstallArtifact(conformance_as, .{}).step);
    // The tests of the conformance authorization server run with the other tests.
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = conformance_as.root_module })).step);

    // Autodocs.
    const docs_obj = b.addObject(.{
        .name = "mcp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mcp.zig"),
            .target = target,
            .optimize = .debug,
        }),
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    b.step("docs", "Generate API documentation").dependOn(&install_docs.step);

    // The documentation site for GitHub Pages: the landing page of docs/site and the API
    // documentation of both modules under api/.
    const grpc_docs_obj = b.addObject(.{
        .name = "mcp_grpc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mcp_grpc.zig"),
            .target = target,
            .optimize = .debug,
            .imports = &.{.{ .name = "mcp", .module = mcp }},
        }),
    });
    const site_step = b.step("site", "Build the documentation site in zig-out/site");
    site_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = b.path("docs/site"),
        .install_dir = .prefix,
        .install_subdir = "site",
    }).step);
    site_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "site/api/mcp",
    }).step);
    site_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = grpc_docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "site/api/mcp_grpc",
    }).step);

    // Benchmarks: ReleaseFast, run with `zig build bench` or `zig build bench -- --smoke`.
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{ .{ .name = "mcp", .module = mcp }, .{ .name = "mcp_grpc", .module = mcp_grpc } },
        }),
    });
    const run_bench = b.addRunArtifact(bench);
    run_bench.setCwd(b.path("."));
    run_bench.addPassthruArgs();
    b.step("bench", "Run the benchmarks").dependOn(&run_bench.step);

    // Tools written in Zig and run through `zig build <step>`.
    addTool(b, "lint-docs", "Check prose against the project STE profile", "tools/lint_docs/main.zig");
    addTool(b, "census", "Check the schema fixtures against the Zig types", "tools/schema_census.zig");
    addTool(b, "commit-policy", "Check commits for a sole signed author", "tools/commit_policy.zig");
    addTool(b, "gen-bibliography", "Check the bibliography and render it", "tools/gen_bibliography.zig");
    addTool(b, "gen-dictionary", "Render the project dictionary", "tools/gen_dictionary.zig");
    addTool(b, "check-version", "Check that a release tag matches the package version", "tools/check_version.zig");
    addTool(b, "changelog-section", "Print the changelog section of a version", "tools/changelog_section.zig");
    addTool(b, "extract-requirements", "Extract the normative sentences of the specification", "tools/extract_requirements.zig");
    addTool(b, "spec-matrix", "Check the requirement mapping and render the conformance matrix", "tools/gen_spec_matrix.zig");

    // Unit tests of the requirement tools and the changelog tool run with the other tests.
    for ([_][]const u8{ "tools/extract_requirements.zig", "tools/gen_spec_matrix.zig", "tools/changelog_section.zig" }) |path| {
        const tool_tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path(path), .target = b.graph.host }) });
        test_step.dependOn(&b.addRunArtifact(tool_tests).step);
    }

    // On Windows, Zig 0.16.0 makes the pipes of a child inheritable and starts each child with
    // all inheritable handles. Thus a child that starts at the same time as a different child
    // can keep the stdout pipe of that child open after it stops. If the long module tests (about
    // one minute) keep the pipe of a short test binary, the build runner gets no end of the
    // output from that binary and stops it with "test runner failed to respond for 1m". Thus
    // on a Windows host, the module tests start only after all the other tests are complete.
    // Keep this after the last `test_step.dependOn`.
    if (b.graph.host.result.os.tag == .windows) {
        for (test_step.dependencies.items) |step| {
            if (step != &run_mod_tests.step) run_mod_tests.step.dependOn(step);
        }
    }
}

fn addTool(b: *std.Build, step_name: []const u8, description: []const u8, source: []const u8) void {
    const exe = b.addExecutable(.{
        .name = step_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(source),
            .target = b.graph.host,
            .optimize = .safe,
        }),
    });
    const run = b.addRunArtifact(exe);
    run.setCwd(b.path("."));
    run.addPassthruArgs();
    b.step(step_name, description).dependOn(&run.step);
}
