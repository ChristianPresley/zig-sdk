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
- OAuth 2.1 authorization client (`mcp.auth.OAuthClient`): protected resource and authorization server metadata discovery, pre-registered, client ID metadata document and dynamic registration, PKCE S256, `resource` indicators, `iss` validation, scope selection with step-up limits, and per-issuer credentials. The HTTP client transport answers 401 and 403 challenges with it.
- Resource server helpers (`mcp.auth.ResourceServer`, `mcp.auth.JwtVerifier`): protected resource metadata, bearer token checks with `WWW-Authenticate` challenges, JWT verification with HS256, ES256, RS256 and PS256, and the principal in the request context. The HTTP server serves them with the `auth` option.
- In-tree TLS 1.3 server (`mcp.tls`) with ECDSA P-256, P-384 and Ed25519 certificates, X25519, P-256 and P-384 key exchange, HelloRetryRequest, ALPN and server name indication. The HTTP transport serves HTTPS with the `tls` option.
- Tasks extension for servers (`mcp.tasks`): the `tasks` server option, `task_support` per tool, the `.start_task` outcome, `tasks/get`, `tasks/update` and `tasks/cancel`, input requests inside a task, cancellation and the `-32021` gate.
- Tasks extension for clients: `callTool` waits for a task and answers its input requests with the hooks; `callToolOrTask`, `getTask`, `updateTask`, `cancelTask` and `awaitTask` give full control. The HTTP client mirrors the task id into `Mcp-Name`.
- stdio client process management: process groups on POSIX and a job object on Windows, shutdown escalation (`SIGTERM`, then `SIGKILL`) after `limits.shutdown_grace`, and restarts of a crashed server process with `max_restarts`.
- Client retry of requests whose stream was lost before a response byte: `RequestOptions.retry` (`auto`, `never`, `force`) bounded by `limits.max_lost_stream_retries`. `force` reopens a listen stream after a restart.
- In-tree TLS 1.3 client (`mcp.tls.connect`): chain validation with a CA set, the std bundle, a pinned leaf or a self-signed policy; host name and IP address checks; CA constraints; ALPN; HelloRetryRequest; client certificates. The server can ask for client certificates (`client_auth`, `client_trust`).
- The Streamable HTTP client runs on an SDK-owned HTTP/1.1 connection (`mcp.transport.http1`) and uses the SDK TLS client for `https` (`HttpClient.Options.tls`).
- gRPC transport in the module `mcp_grpc`: a JSON-RPC tunnel over HTTP/2 (`proto/mcp_zig_transport_v1.proto`) with its own protobuf wire format, HPACK with the RFC 7541 tables, an HTTP/2 connection with flow control, and the gRPC server (`mcp_grpc.Server`) and client (`mcp_grpc.Channel`) transports. Metadata mirrors the HTTP headers; errors before the first message travel in the trailers with `mcp-error-code` and `mcp-error-bin`.
- Conformance fixture server and a CI job that runs the official conformance suite.
- Comptime JSON Schema derivation from Zig types.
- JSON Schema 2020-12 subset validator. Tool arguments are checked against the input schema and structured output against the output schema.
- Build steps `test`, `fmt`, `examples`, `docs`, `lint-docs`, `census`, `commit-policy`, `conformance-server`, `conformance-client`, `gen-bibliography`, `gen-dictionary`.
- CI workflow with a GitHub-native Zig installation step, a consumer build through `b.dependency`, a nightly workflow (wiki lint, link check, ReleaseSafe matrix) and a release workflow that verifies the signed tag and publishes the changelog section.
