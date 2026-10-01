# Instructions for AI agents in this repository

- The only author and committer of every commit is Christian Presley <chrispresley@outlook.com>. Never add `Co-Authored-By`, `Signed-off-by` or other attribution trailers. Every commit and tag is GPG-signed.
- Every commit subject follows Conventional Commits (`type(scope): description`) and the body has one line per changed file (`path: what changed`). Pull request descriptions carry no generator or attribution line.
- Zig 0.16.0 only. No dependencies other than the Zig toolchain. No vendored third-party code except the licensed test fixtures under `test/fixtures/`.
- The SDK implements MCP specification revision 2026-07-28 only. Do not add legacy behaviour (`initialize`, sessions, `Last-Event-ID`).
- Prose (README, wiki, `///` doc comments) follows the project ASD-STE100 profile in `docs/style/ste-profile.md`. Cite STE rules by number only. Never copy ASD-STE100 rule text or dictionary entries.
- `zig build lint-docs` does not check `CHANGELOG.md`. Write new CHANGELOG entries in the profile, but do not rewrite released entries; record a correction under `[Unreleased]`.
- Before you commit, run `zig build fmt test`.
- The plan of record is the approved implementation plan; its milestones and their state are on the wiki page [Roadmap](https://github.com/ChristianPresley/zig-sdk/wiki/Roadmap).
