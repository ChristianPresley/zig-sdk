# Google Cloud proto files for MCP over gRPC

This directory has a copy of two proto files and the license of the repository `GoogleCloudPlatform/mcp-grpc-transport-proto`:

| File | Upstream path |
| --- | --- |
| `mcp.proto` | `proto/mcp.proto` |
| `mcp_messages.proto` | `proto/mcp_messages.proto` |
| `LICENSE` | `LICENSE` (MIT) |

- Source: https://github.com/GoogleCloudPlatform/mcp-grpc-transport-proto
- Commit: `1d2216c1eca5ac20267f49cd666efaeac2fd2eb9`, release v0.2.0, committed on 2026-08-31.
- Copied on 2026-09-30. The files have no changes. `UPSTREAM.zon` has the git blob ids.

The files are test fixtures. The SDK does not generate code from them. The hand-written encoders and decoders in `src/grpc/protobuf/mcp_messages.zig` follow the field numbers of `mcp_messages.proto`. The interop script `.github/interop/grpc_typed_peer.mjs` loads the files with `@grpc/proto-loader` to call the typed service of the SDK server.
