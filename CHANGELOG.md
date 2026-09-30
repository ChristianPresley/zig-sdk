# Changelog

All notable changes to this project are recorded in this file. The format follows Keep a Changelog 1.1.0. The project uses semantic versioning.

## [Unreleased]

### Added

- Protocol types for MCP specification revision 2026-07-28.
- JSON-RPC envelope parsing and writers.
- Server engine with tools, resources, resource templates, prompts, completion, pagination, multi round-trip requests and subscriptions.
- stdio transport for servers.
- Streamable HTTP transport for servers with SSE responses and header mirroring.
- Client (`mcp.Client`) with typed requests, progress and log callbacks, the multi round-trip driver over application hooks, and three client transports: in-memory, stdio with process management, and Streamable HTTP with header mirroring.
- In-tree TLS 1.3 server (`mcp.tls`) with ECDSA P-256, P-384 and Ed25519 certificates, X25519, P-256 and P-384 key exchange, HelloRetryRequest, ALPN and server name indication. The HTTP transport serves HTTPS with the `tls` option.
- Conformance fixture server and a CI job that runs the official conformance suite.
- Comptime JSON Schema derivation from Zig types.
- JSON Schema 2020-12 subset validator. Tool arguments are checked against the input schema and structured output against the output schema.
- Build steps `test`, `fmt`, `examples`, `docs`, `lint-docs`, `census`, `commit-policy`, `conformance-server`.
- CI workflow with a GitHub-native Zig installation step.
