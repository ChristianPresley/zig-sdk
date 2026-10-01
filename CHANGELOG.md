# Changelog

All notable changes to this project are recorded in this file. The format follows Keep a Changelog 1.1.0. The project uses semantic versioning.

## [Unreleased]

### Added

- Regular expression engine for the JSON Schema keywords `pattern` and `patternProperties` (`mcp.schema.regex`). It is a Pike VM over code points with the ECMA-262 syntax, and the match time is linear in the input length. Backreferences, lookaround and most Unicode property escapes give `error.UnsupportedRegex`. The limits are `limits.schema.max_pattern_bytes` and `limits.schema.max_regex_states`. A derived schema accepts `.pattern` on string fields.
- RSA certificate keys in the TLS server and the TLS client: PKCS#1 and PKCS#8 keys of 2048 to 4096 bits sign with RSA-PSS (`rsa_pss_rsae_sha256`, `sha384`, `sha512`). The private operation uses the Chinese remainder theorem, and the key verifies each signature before it goes out.
- The post-quantum hybrid key exchange group `X25519MLKEM768` (RFC 10024) in the TLS server and the TLS client. It is the first group of the default order. The client also sends an X25519 share, so a server without the hybrid group needs no HelloRetryRequest.
- Unix socket transport (`mcp.transport.unix`) with the stdio framing: a server that accepts many peers on a socket file and a client transport. The limit is `limits.unix_socket.max_connections`. The example `unix_server` and the `client_cli unix` mode use it.
- On Windows the Unix socket server gives the socket file a protected access control list that allows access only to the user of the process. This is the Windows form of the mode `0600`, and Windows checks the list when a client connects. A `mode` with group or other bits keeps the inherited list. A failure gives `BindError.AccessControlFailed`.
- The Unix socket server refuses a directory where other accounts can add, delete or rename entries, because such an account can put its own socket at the path (`BindError.DirectoryNotPrivate`). On POSIX systems it also checks the parent directories. When `mode` gives the group access, the group can also write to the directory. `mcp.transport.unix.createPrivateDirectory` makes a safe directory: mode `0700`, or on Windows an access control list that its files inherit. The example `unix_server` uses it.
- The Unix socket server creates the socket in a new private directory, sets the mode or the access control list, and then moves the socket to its path. Thus no client can connect before the socket has its protection.
- Client icon rules (`mcp.icons`, `Client.fetchIcon`, `Client.selectIcon`): only `https` and `data:` icons, the same origin as the server unless the policy trusts other origins, no credentials, magic byte checks, PNG and JPEG by default, other formats through the `icon_decoder` hook, and the limits `limits.icon`.
- OAuth client credentials extension (`mcp.auth.ClientCredentials`) with client secrets and `private_key_jwt` assertions, token caching and renewal before expiry.
- Enterprise-managed authorization extension: the client (`mcp.auth.EnterpriseClient`) exchanges an identity assertion for an ID-JAG at the enterprise identity provider and the ID-JAG for an access token. `mcp.auth.IdJagValidator` checks ID-JAGs for an application with its own authorization server.
- `mcp.auth.Provider` for the HTTP client transport (`auth_provider`), and `Server.Options.authorization_extensions` to advertise the authorization extensions.
- JWT signing keys (`mcp.auth.jwt.SigningKey`) for ES256, ES384, EdDSA, RS256 and PS256, JWK set parsing, and ES384 and EdDSA verification.
- Skills extension (`io.modelcontextprotocol/skills`): the server option `skills`, `addSkill`, `addDynamicSkill`, `skills/list`, `skills/get` and `resources/directory/read`, and the client methods `listSkills`, `getSkill`, `readDirectory` and `readSkillFile` with manifest checks.
- MCP Apps extension (`io.modelcontextprotocol/ui`): the server option `apps`, UI resources with `addUiResource`, tool UI metadata with `ToolDef.ui`, and the client accessors `toolUi` and `readUiResource`.
- Requirement matrix: `zig build extract-requirements` finds the 733 normative sentences of the vendored specification pages, `docs/spec/requirement_tests.zon` maps each one to tests or to a reason, and `zig build spec-matrix` checks the mapping and renders `docs/generated/conformance-matrix.md`. The CI checks both files. 127 new tests cover requirements that had no test.
- Documentation site: `zig build site` builds a landing page and the API reference of the modules `mcp` and `mcp_grpc`. The workflow `docs.yml` deploys it to GitHub Pages from `main`.
- `zig build lint-docs` has the options `--strict`, `--format`, `--rule`, `--string-literals` and `--wiki-dir`, and the warning rules of the project profile. The project dictionary has all its lists.
- Full JSON Schema 2020-12 support: `unevaluatedProperties`, `unevaluatedItems`, `$id` in subschemas with base URI resolution, `$dynamicRef` and `$dynamicAnchor`. The content keywords are annotations. The draft 2020-12 files of the JSON Schema Test Suite run with the tests.
- `x-mcp-header` annotations on nested properties. The client and the server refuse a tool with an annotation that a chain of `properties` keywords does not reach, and the client logs the refusal.
- The client refreshes `tools/list` and retries a tool call one time after error `-32020`.
- The client validates `structuredContent` against the output schema and reports `Diagnostics.structured_content_invalid`.
- The client and the server validate elicitation URLs, form answers against `requestedSchema`, sampling messages with tool results, and `includeContext` against the client capability.
- The HTTP server cancels a request when the client disconnects. Progress notifications have a rate limit of `limits.max_progress_rate_per_s` on both sides.
- `RequestOptions.max_total_timeout`. A request without a timeout gets `limits.request_timeout` (60 s).
- `OAuthClient.Options.application_type`, `OAuthClient.lastFailure`, `ResourceServer.scope_hierarchy` and `Principal.issuer`.
- DPoP (RFC 9449) for the DPoP extension of MCP (`mcp.auth.dpop`). `DpopProver` makes a proof for each request and keeps the nonces of each server. The option `dpop` of `OAuthClient`, `ClientCredentials`, `EnterpriseClient` and `WorkloadIdentity` requests DPoP-bound tokens. The HTTP client transport sends `Authorization: DPoP` with a new proof and answers `use_dpop_nonce`. `OAuthClient` sends `dpop_jkt` and can register with `dpop_bound_access_tokens`.
- `ResourceServer.dpop` (`DpopPolicy`) accepts DPoP-bound tokens: the checks of RFC 9449 section 4.3 with a window of 5 minutes, the `cnf.jkt` binding, optional nonces without state (`dpop.NonceIssuer`) and an optional replay check. The server refuses a DPoP-bound token with the Bearer scheme. `ResourceServer.authorizeRequest` takes the `DPoP` headers. `Principal.confirmation` has the `jkt`.
- Workload identity federation (`mcp.auth.WorkloadIdentity`): a workload JWT from a value, a file or a callback goes to the token endpoint as a JWT bearer grant without client registration. The client does not send a refused JWT again. `WorkloadJwtValidator` and `KeyDiscovery` (OpenID Connect Discovery) check workload JWTs for an application with its own authorization server.
- `Server.Options.authorization_extensions` has `dpop` and `workload_identity`. The conformance client passes `auth/dpop`, `auth/dpop-nonce` and `auth/wif-jwt-bearer`.
- The CI job `conformance` runs each scenario that the suite does not score alone, with the per-check baseline `conformance/expected-failures-unscored.yml`. A failure of these scenarios now makes the job fail.
- Rate limits for each caller (`limits.rate_limits`): a token bucket for the tool calls of each caller, one for all tool calls together, one for the log messages of each caller, and `ToolDef.rate_limit` for one tool. The caller is the principal, else the IP address (an IPv6 /64 network), else the connection. A refused tool call gets error `-31429` with `data.retryAfterMs`, and on HTTP with a JSON response also status 429 with `Retry-After`. The server drops log messages over the limit and later sends one summary with the count. The limits are off by default. The table of callers has at most `max_callers` entries. `Server.rateLimitStats` gives the counters.
- The TLS cipher suites `TLS_AEGIS_128L_SHA256` and `TLS_AEGIS_256_SHA512` as an option of the TLS client and server (`tls.suites.default_suites_with_aegis`). They are off by default. `HttpClient.TlsSetup.cipher_suites` selects them for the HTTP client.
- Record padding in the TLS client and server (RFC 8446 section 5.4): the option `padding` with the policies `none`, `block` and `random`, and `Connection.setPadding`. Padding stops at an inner plaintext of 2^14 bytes. `HttpClient.TlsSetup.padding` sets it for the HTTP client.
- WebSocket transport (`mcp.transport.websocket`): a custom transport on RFC 6455 connections with the subprotocol `mcp`. Each text message is one JSON-RPC message, one connection carries many requests, and the client cancels a request with `notifications/cancelled`. The server checks `Origin` and `Host`, checks the access token at the upgrade (bearer and DPoP), closes the connection with 1008 when the token expires, and serves `wss` with the SDK TLS server. The limits are `limits.websocket`. The example `websocket_server`, the `client_cli ws` mode and the `--ws-port` option of the conformance server use it. The CI job `websocket-interop` calls the server from the WebSocket client of Node.
- The certificate_authorities extension (RFC 8446 section 4.2.4) in the TLS client and server. The server sends the names of its `client_trust` anchors in the CertificateRequest (`send_client_ca_names`, on by default) and prefers a chain that leads to a name of the client. The client can send the names of its anchors in the ClientHello (`send_ca_names`, off by default). With `identities`, the client chooses the chain that leads to a name of the server, and `identity_fallback` decides when no chain does.
- RSA-PSS keys (`id-RSASSA-PSS`, RFC 4055) in the TLS server and client. The key signs only with the `rsa_pss_pss` schemes and respects the hash of its parameters. Chain validation verifies certificates with RSASSA-PSS signatures. `mcp.auth.jwt` gives PS256 for such a key.
- Name constraints (RFC 5280 section 4.2.1.10) in chain validation for DNS names, IP addresses, directory names, mailboxes and URIs. The constraints of each CA and of the anchor apply to the certificates below it and to the host name. A critical constraint of a form that the SDK cannot check ends the handshake with `bad_certificate`.
- Revocation checks without network access (`tls.Revocation`): CRLs from the application (`tls.Crl`) and stapled OCSP responses (RFC 6960). The client asks for a staple with `ocsp_stapling = .request` or `.require`, and the server staples the response of the selected chain (`ocsp_staples`). The policy has the scope `leaf` or `chain` and the modes `soft_fail` and `hard_fail` for an unknown status. A revoked certificate always ends the handshake with `certificate_revoked`. The server checks client certificates with `client_revocation`, and `HttpClient.TlsSetup.revocation` sets the policy of the HTTP client.

### Changed

- `zig build lint-docs` runs in strict mode by default, and the CI and the nightly wiki lint use strict mode.
- The default TLS group order is X25519MLKEM768, X25519, P-256, P-384.
- Breaking: `tls.verify.verifyChain` takes `(certs, trust, ChainOptions)`. `ChainOptions` has the purpose of the peer (`server` or `client`), the host, the time, the revocation policy and the staples.
- `mcp.tls.PrivateKey.publicKeyBytes` takes a larger buffer, and `max_signature_len` is 512 for RSA keys.
- The TLS client refuses a HelloRetryRequest cookie of more than 8 KiB.
- `Transport.Kind` has the value `unix_socket`.
- `Transport.Kind` has the value `websocket`. The stdio engine takes whole messages from a sink, for the WebSocket transport.
- `OAuthClient` `Registration.pre_registered` is a list of credentials bound to an issuer. A challenge from an authorization server without credentials gives `error.IssuerNotRegistered`.
- Sealed `requestState` is bound to the principal (issuer, subject and client). Another principal gets error `-32602`.
- The authorization clients refuse `http` for metadata, registration, authorization and token endpoints unless `allow_http` is set. `redirect_uri` must be `https` or a loopback `http` address.
- Resource URIs and token audiences compare the scheme and the host without case.
- `RequestError` and `ExchangeError` have `InvalidRequest`: the client refuses to mirror an integer outside the safe range of JavaScript.
- The client cache keys private results by credential, drops them when the credential changes, does not cache requests with `requestState`, and drops the cached pages of a list after an invalid cursor.
- `completion/complete` for an unknown prompt or resource gives error `-32602` before the handler runs.
- A client cancellation with any reason text never looks like a server shutdown. The stdio and Unix socket servers do not write a response for a canceled request.

### Fixed

- The limits `uri_template.max_template_bytes` and `uri_template.max_uri_bytes` had no effect. A longer template now fails at registration with `error.InvalidUriTemplate`, and a longer URI matches no template.
- A TLS peer could stop the process of a TLS server or client of the SDK in Debug and ReleaseSafe, and write out of the bounds of a buffer in ReleaseFast and ReleaseSmall. The record layer decrypted a record into the plaintext buffer after the unread data and only asserted that the record fits. An HTTPS client could send a part of a request head and then one full record. The record layer now decrypts in place and keeps the rest of a record that does not fit. An inner plaintext longer than 2^14 + 1 bytes is a record overflow.
- A JWT with an `exp`, `nbf` or `iat` claim near the limit of `i64`, or with a large float value, could stop the process in Debug and ReleaseSafe. The checks now use saturating arithmetic, and a float claim outside the range of `i64` does not count. The same applies to `expires_in` of a token response. A DPoP proof is a JWT that the client signs, so this fix matters for servers with DPoP.
- `parseChallenge` read only one `Bearer` challenge. It now reads more than one challenge in a value, the `DPoP` scheme and escapes in quoted strings, and the HTTP client joins the values of all `WWW-Authenticate` headers.
- `zig build test --fuzz` did not compile on Zig 0.16.0, because the fuzz path of the test runner of the toolchain gives a `builtin.StackTrace` to `std.debug.writeStackTrace`. The option `-Dfuzz` makes a copy of the runner with `std.debug.writeErrorReturnTrace` in that call. It also builds the tests with the LLVM backend, because the self-hosted backend of Debug builds emits no coverage table for the fuzzer. The nightly `fuzz` job uses the option.
- The HPACK decoder read freed memory when a literal with incremental indexing had the name of a dynamic entry that the new entry evicts. RFC 7541 section 4.4 permits this case. The decoder now copies the name before the eviction. The fuzz job found this defect.
- The TLS parsers of the CertificateRequest and Certificate messages had an integer overflow for a context length of 253 to 255 or a certificate length near 16 MiB. In Debug and ReleaseSafe a peer could stop the process. The parsers now give `decode_error`. The fuzz job found this defect.
- The stdio line framer drops all of a line that is longer than the limit. Before, the rest of the line arrived as a separate frame.
- The JSON Schema compiler compiles the target of each local `$ref`. Before, a reference into an unknown member could reach the validator unchecked and stop the process.
- An HTTP/1.1 GET request of the SDK client has no `content-length` header.
- A stdio or Unix socket server read freed memory when a valid JSON value was not a JSON-RPC message.
- The HTTP client gives each SSE event to the caller when it arrives, not after 4 KiB.
- The client router takes only frames with a top-level `result` or `error` as responses.
- The server shuts down every listen stream at shutdown, not the first 64.
- The HTTP, Unix socket and gRPC servers connect to their own listener at shutdown. On Windows a cancel did not always wake a blocked accept, and `serve` could wait without end.
- The Unix socket transport refuses a path that is longer than the `sockaddr_un` of the target, 104 bytes on macOS.
- The server rejects control characters and bytes that are not ASCII in `Mcp-Param`, `Mcp-Name` and `Mcp-Method` values.
- The TLS chain validation did not check the extended key usage. A client certificate could authenticate a server, and a server certificate could authenticate a client. The leaf and each intermediate must now permit the purpose, or have no extended key usage. A wrong purpose ends the handshake with `unsupported_certificate`.
- The TLS chain validation accepted an intermediate without basic constraints when it had no key usage. Each intermediate must now have basic constraints with `cA` set. Version 1 anchors stay valid.
- The TLS client compared the host name with the common name of a certificate without a subject alternative name. It now uses only the `dNSName` and `iPAddress` entries (RFC 9525), and it refuses partial wildcards.
- The TLS chain validation tried only the first anchor with the name of the issuer. It now tries each anchor with that name, so a root with a new key works.
- The TLS ClientHello parser found duplicate extensions only among the first 32 types and duplicate key shares only among the first 16 groups. It now finds each duplicate, refuses bytes after the structure of an extension, and refuses a key share for a group that `supported_groups` does not have. The client refuses the same defects in ServerHello, EncryptedExtensions and CertificateRequest.

## [0.1.0] - 2026-09-30

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
- Client result cache (`Client.Options.cache`, `RequestOptions.cache_mode`): results with a positive `ttlMs` are served again until they expire, a list-changed notification arrives, or `invalidateCache` runs.
- Client retry of requests whose stream was lost before a response byte: `RequestOptions.retry` (`auto`, `never`, `force`) bounded by `limits.max_lost_stream_retries`. `force` reopens a listen stream after a restart.
- In-tree TLS 1.3 client (`mcp.tls.connect`): chain validation with a CA set, the std bundle, a pinned leaf or a self-signed policy; host name and IP address checks; CA constraints; ALPN; HelloRetryRequest; client certificates. The server can ask for client certificates (`client_auth`, `client_trust`).
- The Streamable HTTP client runs on an SDK-owned HTTP/1.1 connection (`mcp.transport.http1`) and uses the SDK TLS client for `https` (`HttpClient.Options.tls`).
- gRPC transport in the module `mcp_grpc`: a JSON-RPC tunnel over HTTP/2 (`proto/mcp_zig_transport_v1.proto`) with its own protobuf wire format, HPACK with the RFC 7541 tables, an HTTP/2 connection with flow control, and the gRPC server (`mcp_grpc.Server`) and client (`mcp_grpc.Channel`) transports. Metadata mirrors the HTTP headers; errors before the first message travel in the trailers with `mcp-error-code` and `mcp-error-bin`.
- Conformance fixture server and a CI job that runs the official conformance suite. The fixture server serves gRPC with `--grpc-port`; the CI job `grpc-interop` calls it from a Node `http2` peer and from `curl` over HTTP/2.
- Comptime JSON Schema derivation from Zig types.
- JSON Schema 2020-12 subset validator. Tool arguments are checked against the input schema and structured output against the output schema.
- Build steps `test`, `fmt`, `examples`, `docs`, `lint-docs`, `census`, `commit-policy`, `conformance-server`, `conformance-client`, `gen-bibliography`, `gen-dictionary`, `bench`, `check-version`, `changelog-section`.
- Benchmarks (`zig build bench`) for request dispatch, HPACK decoding and the TLS handshake, with the baseline in `docs/generated/bench.md` and a nightly smoke run.
- Fuzz targets for every parser (`zig build test --fuzz`), run nightly. A certificate precheck now rejects malformed peer certificates before the std parser reads them; the first fuzz run found that the std parser reads out of bounds on truncated input.
- CI workflow with a GitHub-native Zig installation step, a consumer build through `b.dependency`, a nightly workflow (wiki lint, link check, ReleaseSafe matrix) and a release workflow that verifies the signed tag and publishes the changelog section.
