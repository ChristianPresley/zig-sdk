# Instructions for AI agents in this repository

- The only author and committer of every commit is Christian Presley <chrispresley@outlook.com>. Never add `Co-Authored-By`, `Signed-off-by` or other attribution trailers. Every commit and tag is GPG-signed.
- Zig 0.16.0 only. No dependencies other than the Zig toolchain. No vendored third-party code except the licensed test fixtures under `test/fixtures/`.
- The SDK implements MCP specification revision 2026-07-28 only. Do not add legacy behaviour (`initialize`, sessions, `Last-Event-ID`).
- Prose (README, wiki, CHANGELOG, `///` doc comments) follows the project ASD-STE100 profile in `docs/style/ste-profile.md`. Cite STE rules by number only. Never copy ASD-STE100 rule text or dictionary entries.
- Before you commit, run `zig build fmt test`.
- The plan of record is the approved implementation plan; see `docs/design/`.
