# zig-sdk

The unofficial Zig SDK for the Model Context Protocol (MCP).

This library gives you an MCP server and an MCP client in Zig 0.16.0. It has no dependency other than the Zig toolchain. It obeys MCP specification revision 2026-07-28 only.[^mcp-spec]

## Status

The project is in development. The table shows the parts that exist today.

| Part | State |
| --- | --- |
| Protocol types for the full 2026-07-28 schema | Done, tested against the official example fixtures |
| JSON-RPC envelope, request ids, error codes | Done |
| Server engine: tools, resources, resource templates, prompts, completion, pagination | Done |
| JSON Schema 2020-12 validation of tool arguments and structured output | Done, subset without regular expressions |
| Multi round-trip requests with sealed request state | Done |
| Subscriptions (`subscriptions/listen`) | Done |
| stdio transport (server) | Done |
| Streamable HTTP transport (server) | Done, passes all 37 scored scenarios of the official conformance suite |
| TLS 1.3 server (HTTPS) | Done, tested against the std client, curl and openssl |
| TLS 1.3 client | Planned |
| Client: in-memory, stdio and Streamable HTTP transports, multi round-trip driver | Done |
| Authorization (OAuth 2.1) | Planned |
| gRPC transport (JSON-RPC tunnel over HTTP/2) | Planned |
| Tasks extension | Planned |

## Requirements

- Zig 0.16.0. The package sets `minimum_zig_version` to this version.
- No other dependency.

## Add the package to your project

1. Fetch the package with the exact tag:

```bash
zig fetch --save-exact git+https://github.com/ChristianPresley/zig-sdk#v0.1.0
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

Other build steps: `fmt`, `docs`, `lint-docs`, `census`, `commit-policy`.

## Documentation

The wiki holds the guides, the style guide and the bibliography.[^wiki] The API reference comes from `zig build docs`.

All prose in this repository uses ASD-STE100 Simplified Technical English, customized for this project.[^ste]

## License

Apache License 2.0. See `LICENSE`. Third-party material is listed in `THIRD_PARTY_LICENSES.md`.

[^mcp-spec]: Model Context Protocol Specification 2026-07-28. https://modelcontextprotocol.io/specification/2026-07-28
[^wiki]: zig-sdk wiki. https://github.com/ChristianPresley/zig-sdk/wiki
[^ste]: ASD-STE100 Simplified Technical English, Issue 9. https://www.asd-ste100.org/
