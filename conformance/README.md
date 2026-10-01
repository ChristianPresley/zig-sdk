# Conformance

This directory has the fixtures for the official MCP conformance suite. The suite is the npm package `@modelcontextprotocol/conformance`. The CI job `conformance` runs the pinned version `0.2.0-alpha.11` against the fixture server and the fixture client with the requirements for revision 2026-07-28.

## Files

| File | Purpose |
| --- | --- |
| `everything_server.zig` | The fixture server. It has each tool, resource and prompt that the suite expects. |
| `everything_client.zig` | The fixture client. It runs the client scenario that the suite names. |
| `expected-failures-server.yml` | The baseline of known failures of the scored server scenarios. The list is empty. |
| `expected-failures-client.yml` | The baseline of known failures of the scored client scenarios. The list is empty. |
| `expected-failures-unscored.yml` | The baseline of the scenarios that the suite runs but does not score. Each entry names one check. |

## Steps

Do these steps to run the suite on your computer:

1. Build the fixtures: `zig build conformance-server conformance-client`.
2. Start the server: `./zig-out/bin/mcp-conformance-server --port 3000`.
3. Run the server suite: `npx --yes @modelcontextprotocol/conformance@0.2.0-alpha.11 server --url http://127.0.0.1:3000/mcp --requirements 2026-07-28 --expected-failures conformance/expected-failures-server.yml`.
4. Run the client suite: `npx --yes @modelcontextprotocol/conformance@0.2.0-alpha.11 client --command ./zig-out/bin/mcp-conformance-client --requirements 2026-07-28 --timeout 60000 --expected-failures conformance/expected-failures-client.yml`. On Windows, give the command as an absolute path.
5. Read the summary. The suite exits with code 0 when each scored scenario passes.

Add `--stdio` to the start command to serve on standard input and output instead. Add `--grpc-port N` to serve the gRPC binding as well. The CI job `grpc-interop` calls it from a Node `http2` peer and from `curl` with HTTP/2 prior knowledge.

To run one scenario that the suite does not score, use `--scenario NAME --spec-version 2026-07-28 --force --expected-failures conformance/expected-failures-unscored.yml` instead of `--requirements`. The CI job runs each of these scenarios in this way. A failure of one of them makes the job fail.

## Scope

The suite scores 37 server scenarios and 32 client scenarios for revision 2026-07-28. The fixtures pass all of them.

The suite also runs scenarios that it does not score:

- 10 server scenarios of the Tasks extension. The functional checks pass. The check `wire-schema-valid` fails in the 8 scenarios that create a task. The suite validates the task result against the core `CallToolResult` schema, which requires `content`. The baseline `expected-failures-unscored.yml` names these 8 checks.
- 3 pending server scenarios: `json-schema-2020-12`, `http-header-validation` and `http-custom-header-server-validation`. They pass.
- 6 client scenarios of the authorization extensions: `auth/client-credentials-jwt`, `auth/client-credentials-basic`, `auth/enterprise-managed-authorization`, `auth/dpop`, `auth/dpop-nonce` and `auth/wif-jwt-bearer`. They pass.
- 1 client scenario that came after the release of the requirements: `json-schema-2020-12-preservation`. It passes.
