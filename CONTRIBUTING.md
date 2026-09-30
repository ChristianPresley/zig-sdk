# Contributing

Thank you for your interest in zig-sdk. This page tells you how the project accepts changes.

## Rules for commits

- Every commit is GPG-signed by the maintainer, Christian Presley.
- The maintainer is the only author and the only committer.
- Commit messages have no attribution trailer. The `commit-msg` hook rejects them.
- Merges happen on the maintainer's computer with `git merge --ff-only`. The GitHub web interface is not used for merges.

If you send a pull request, the maintainer applies your change as a signed commit and credits you in `CHANGELOG.md`.

## Set up the repository

1. Install Zig 0.16.0.
2. Clone the repository.
3. Run `git config core.hooksPath .githooks`.
4. Run `zig build test`.

## Before you send a change

1. Run `zig build fmt`.
2. Run `zig build test`.
3. Run `zig build lint-docs` when you changed prose.
4. Run `zig build census` when you changed the protocol types.

## Prose

All prose uses the project profile of ASD-STE100 Simplified Technical English. The profile is in `docs/style/ste-profile.md`. The project dictionary is in `docs/dictionary/`.

## Scope

The SDK obeys MCP specification revision 2026-07-28 only. Changes that add behavior from older revisions are not accepted.
