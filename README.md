# zig-sdk

The unofficial Zig SDK for the Model Context Protocol (MCP).

This library gives you an MCP server and an MCP client in Zig 0.16.0. It has no dependency other than the Zig toolchain. It obeys MCP specification revision 2026-07-28 only.[^mcp-spec]

## Consume the SDK

`examples/consumer/` is a project that depends on the SDK with `b.dependency("mcp", ...)`. A released consumer fetches a tag:

```bash
zig fetch --save-exact git+https://github.com/ChristianPresley/zig-sdk#v0.5.0
```

## Status

The project is in development. The [Roadmap](https://github.com/ChristianPresley/zig-sdk/wiki/Roadmap) on the wiki shows the milestones, the state of each part and the planned work. The [Release Notes](https://github.com/ChristianPresley/zig-sdk/wiki/Release-Notes) and `CHANGELOG.md` list the changes of each release.

## Requirements

- Zig 0.16.0. The package sets `minimum_zig_version` to this version.
- No other dependency.

## Add the package to your project

1. Fetch the package with the exact tag:

```bash
zig fetch --save-exact git+https://github.com/ChristianPresley/zig-sdk#v0.5.0
```

2. Import the `mcp` module in your `build.zig`:

```zig
const mcp = b.dependency("mcp", .{ .target = target, .optimize = optimize }).module("mcp");
exe.root_module.addImport("mcp", mcp);
```

## Write a server

The example below adds one tool and serves it over stdio.

```zig
const std = @import("std");
const mcp = @import("mcp");

const AddArgs = struct {
    a: i64,
    b: i64,
    pub const json_schema = .{ .description = "Add two integers." };
};

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(mcp.CallToolResult) {
    return .{ .complete = try mcp.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

pub fn main(init: std.process.Init) !void {
    var server = try mcp.Server.init(init.gpa, init.io, .{
        .info = .{ .name = "calc", .version = "0.1.0" },
    });
    defer server.deinit();
    try server.addTool(.{ .name = "add", .description = "Add two integers" }, add);
    try mcp.transport.stdio.serve(init.io, init.gpa, &server);
}
```

The SDK derives the JSON Schema of the tool input from the `AddArgs` struct at compile time.

## Build and test

```bash
zig build test
```

```bash
zig build examples
```

Other build steps: `fmt`, `docs`, `site`, `lint-docs`, `census`, `extract-requirements`, `spec-matrix`, `gen-bibliography`, `gen-dictionary`, `commit-policy`, `bench` (`-- --smoke` for a quick run), and `test -Dfuzz --fuzz` for the fuzz targets (not on Windows).

## Documentation

The wiki holds the guides, the style guide and the bibliography.[^wiki] The [API reference](https://christianpresley.github.io/zig-sdk/) comes from `zig build site`. The [conformance matrix](docs/generated/conformance-matrix.md) maps each requirement of the specification to its tests. Start with these pages:

- [Getting Started](https://github.com/ChristianPresley/zig-sdk/wiki/Getting-Started)
- [Server Guide](https://github.com/ChristianPresley/zig-sdk/wiki/Server-Guide) and [Client Guide](https://github.com/ChristianPresley/zig-sdk/wiki/Client-Guide)
- [Transports](https://github.com/ChristianPresley/zig-sdk/wiki/Transports)
- [Release Notes](https://github.com/ChristianPresley/zig-sdk/wiki/Release-Notes)

All prose in this repository uses ASD-STE100 Simplified Technical English, customized for this project.[^ste] The profile is in `docs/style/ste-profile.md`. `zig build lint-docs` checks the prose.

## License

Apache License 2.0. See `LICENSE`. The file `THIRD_PARTY_LICENSES.md` lists the third-party material.

[^mcp-spec]: Model Context Protocol Specification 2026-07-28. https://modelcontextprotocol.io/specification/2026-07-28
[^wiki]: zig-sdk wiki. https://github.com/ChristianPresley/zig-sdk/wiki
[^ste]: ASD-STE100 Simplified Technical English, Issue 9. https://www.asd-ste100.org/
