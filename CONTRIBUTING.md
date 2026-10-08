# Contributing

Thank you for your interest in zig-sdk. This page tells you how the project accepts changes.

## Rules for commits

- Every commit is GPG-signed by the maintainer, Christian Presley.
- The maintainer is the only author and the only committer.
- Commit messages have no attribution trailer. The `commit-msg` hook rejects them.
- The subject follows Conventional Commits: `type(scope): description`. The types are feat, fix, docs, style, refactor, perf, test, build, ci, chore and revert.
- The body has one line for each changed file: `path: what changed`. The `commit-msg` hook and the `commit-policy` CI job check this.
- Pull request descriptions do not carry a generator or attribution line.
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

On Windows, add `--test-timeout 10m` to `zig build test`, as CI does. With Zig 0.16.0, a process that the build runner starts at the same time can keep the output pipes of a test binary open. Without the option, the build runner then fails the step 60 seconds after the last test with `test runner failed to respond`.

## Unix sockets on Windows

The Windows driver of Unix sockets (afunix.sys) can lose the close of the peer. This occurs when a receive starts at about the same time as the close. The receive then stays pending until a cancel, but a poll of the socket shows the disconnect. TCP sockets on Windows and Unix sockets on Linux and macOS do not have this problem.

The Unix socket transport gives each reader to `pollBeforeRead` in `src/mcp/transport/windows_afunix.zig`. Then each read first waits in a poll, and the receive starts only when it can complete at once. Do the same in new code that reads a Unix socket on Windows. A test server can also read each connection in its own task and cancel the tasks that remain when it stops.

## Prose

All prose uses the project profile of ASD-STE100 Simplified Technical English. The profile is in `docs/style/ste-profile.md`. The project dictionary is in `docs/dictionary/`.

## Scope

The SDK obeys MCP specification revision 2026-07-28 only. The project does not accept changes that add behavior from older revisions.
