# Versioning

zig-sdk uses semantic versioning with a major version of zero.

## Rules

- A minor release (`0.y.0`) can change the public API, move to a new MCP specification revision, or move to a new Zig release.
- A patch release (`0.y.z`) contains fixes only.
- Each release supports exactly one MCP specification revision. There is no overlap window.
- Each release pins one Zig version in `build.zig.zon` (`minimum_zig_version`).

## Move to a new MCP revision

1. Vendor the new schema in `test/fixtures/mcp_schema_<rev>/` and the specification pages in `test/fixtures/mcp_spec_<rev>/`.
2. Put an `UPSTREAM.zon` file in each fixture directory. It records the upstream repository, the commit and the path.
3. Update `src/mcp/protocol/version.zig`.
4. Update the fixture paths in `tools/schema_census.zig`, `tools/extract_requirements.zig` and `src/mcp/golden_test.zig`.
5. Update the protocol types until `zig build test census` passes.
6. Run `zig build extract-requirements` to write `docs/spec/requirements.zon` again.
7. Map each requirement in `docs/spec/requirement_tests.zon`. Then run `zig build spec-matrix`.
8. Update the conformance harness pin in `conformance/README.md`.
9. Record the removed behavior in `CHANGELOG.md` under "Removed".
10. Make a minor release.

## Tags

Release tags have the form `vX.Y.Z` and are GPG-signed.
