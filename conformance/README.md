# Conformance

This directory has the fixtures for the official MCP conformance suite. The suite is the npm package `@modelcontextprotocol/conformance`. The CI job `conformance` runs the pinned version `0.2.0-alpha.11` against the fixture server with the requirements for revision 2026-07-28.

## Files

| File | Purpose |
| --- | --- |
| `everything_server.zig` | The fixture server. It has each tool, resource and prompt that the suite expects. |
| `expected-failures-server.yml` | The baseline of known failures. The target is an empty list. |

## Steps

Do these steps to run the suite on your computer:

1. Build the fixture server: `zig build conformance-server`.
2. Start it: `./zig-out/bin/mcp-conformance-server --port 3000`.
3. Run the suite: `npx --yes @modelcontextprotocol/conformance@0.2.0-alpha.11 server --url http://127.0.0.1:3000/mcp --requirements 2026-07-28 --expected-failures conformance/expected-failures-server.yml`.
4. Read the summary. The suite exits with code 0 when each scored scenario passes.

Add `--stdio` to the start command to serve on standard input and output instead.

## Scope

The suite scores 37 server scenarios for revision 2026-07-28. The fixture server passes all of them. The suite also runs scenarios that it does not score. The scenarios for the Tasks extension fail until the extension module is available. That is a planned milestone.
