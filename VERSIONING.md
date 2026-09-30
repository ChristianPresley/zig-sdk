# Versioning

zig-sdk uses semantic versioning with a major version of zero.

## Rules

- A minor release (`0.y.0`) can change the public API, move to a new MCP specification revision, or move to a new Zig release.
- A patch release (`0.y.z`) contains fixes only.
- Each release supports exactly one MCP specification revision. There is no overlap window.
- Each release pins one Zig version in `build.zig.zon` (`minimum_zig_version`).

## Move to a new MCP revision

1. Vendor the new schema fixtures under `test/fixtures/` and update `UPSTREAM.zon`.
2. Update `src/mcp/protocol/version.zig`.
3. Update the protocol types until `zig build test census` passes.
4. Update the conformance harness pin in `conformance/README.md`.
5. Record the removed behavior in `CHANGELOG.md` under "Removed".
6. Make a minor release.

## Tags

Release tags have the form `vX.Y.Z` and are GPG-signed.
