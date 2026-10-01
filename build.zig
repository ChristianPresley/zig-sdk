const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mcp = b.addModule("mcp", .{
        .root_source_file = b.path("src/mcp.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests. `-Dfuzz` prepares them for `zig build test -Dfuzz --fuzz` on Zig 0.16.0: a test
    // runner whose fuzz path compiles, and the LLVM backend, because the self-hosted backend of
    // Debug builds emits no `__sancov_pcs1` table and the fuzzer then sees no coverage.
    const fuzz = b.option(bool, "fuzz", "Prepare the unit tests for --fuzz on Zig 0.16.0") orelse false;
    const test_runner: ?std.Build.Step.Compile.TestRunner = if (fuzz) fuzzTestRunner(b) else null;
    const use_llvm: ?bool = if (fuzz) true else null;
    const mod_tests = b.addTest(.{ .root_module = mcp, .test_runner = test_runner, .use_llvm = use_llvm });
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
    const grpc_tests = b.addTest(.{ .root_module = mcp_grpc, .test_runner = test_runner, .use_llvm = use_llvm });
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
    const fmt = b.addFmt(.{ .paths = &.{ "build.zig", "build.zig.zon", "src", "examples", "tools", "conformance", "bench" }, .check = true });
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
            .imports = &.{ .{ .name = "mcp", .module = mcp }, .{ .name = "mcp_grpc", .module = mcp_grpc } },
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

    // The documentation site for GitHub Pages: the landing page of docs/site and the API
    // documentation of both modules under api/.
    const grpc_docs_obj = b.addObject(.{
        .name = "mcp_grpc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mcp_grpc.zig"),
            .target = target,
            .optimize = .Debug,
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
            .optimize = .ReleaseFast,
            .imports = &.{ .{ .name = "mcp", .module = mcp }, .{ .name = "mcp_grpc", .module = mcp_grpc } },
        }),
    });
    const run_bench = b.addRunArtifact(bench);
    run_bench.setCwd(b.path("."));
    if (b.args) |args| run_bench.addArgs(args);
    b.step("bench", "Run the benchmarks").dependOn(&run_bench.step);

    // Tools written in Zig and run through `zig build <step>`.
    addTool(b, "lint-docs", "Check prose against the project STE profile", "tools/lint_docs/main.zig", &.{ "--strict", "--string-literals" });
    addTool(b, "census", "Check the schema fixtures against the Zig types", "tools/schema_census.zig", &.{});
    addTool(b, "commit-policy", "Check commits for a sole signed author", "tools/commit_policy.zig", &.{});
    addTool(b, "gen-bibliography", "Check the bibliography and render it", "tools/gen_bibliography.zig", &.{ "--check", "--out", "docs/generated/bibliography.md" });
    addTool(b, "gen-dictionary", "Render the project dictionary", "tools/gen_dictionary.zig", &.{ "--out", "docs/generated/dictionary.md" });
    addTool(b, "check-version", "Check that a release tag matches the package version", "tools/check_version.zig", &.{});
    addTool(b, "changelog-section", "Print the changelog section of a version", "tools/changelog_section.zig", &.{});
    addTool(b, "extract-requirements", "Extract the normative sentences of the specification", "tools/extract_requirements.zig", &.{});
    addTool(b, "spec-matrix", "Check the requirement mapping and render the conformance matrix", "tools/gen_spec_matrix.zig", &.{});

    // Unit tests of the requirement tools and the changelog tool run with the other tests.
    for ([_][]const u8{ "tools/extract_requirements.zig", "tools/gen_spec_matrix.zig", "tools/changelog_section.zig" }) |path| {
        const tool_tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path(path), .target = b.graph.host }) });
        test_step.dependOn(&b.addRunArtifact(tool_tests).step);
    }
}

/// The fuzz path of the test runner of Zig 0.16.0 gives a `builtin.StackTrace` to
/// `std.debug.writeStackTrace`, which takes a `debug.StackTrace`, so no test with a fuzz
/// target compiles with `-ffuzz`. This makes a copy of the runner of the installed toolchain
/// with `std.debug.writeErrorReturnTrace` in that call. The repository keeps no copy.
fn fuzzTestRunner(b: *std.Build) std.Build.Step.Compile.TestRunner {
    const sub_path = "compiler/test_runner.zig";
    const source = b.graph.zig_lib_directory.handle.readFileAlloc(b.graph.io, sub_path, b.allocator, .limited(1 << 20)) catch |err|
        std.debug.panic("cannot read {s} of the Zig library: {t}", .{ sub_path, err });
    const needle = "std.debug.writeStackTrace(trace, stderr)";
    if (std.mem.count(u8, source, needle) != 1)
        std.debug.panic("{s} of the Zig library does not have one '{s}'; remove -Dfuzz", .{ sub_path, needle });
    const fixed = std.mem.replaceOwned(u8, b.allocator, source, needle, "std.debug.writeErrorReturnTrace(trace, stderr)") catch @panic("OOM");
    const files = b.addWriteFiles();
    return .{ .path = files.add("fuzz_test_runner.zig", fixed), .mode = .server };
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
