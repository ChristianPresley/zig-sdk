# Security policy

## Report a vulnerability

Use the private vulnerability report form of GitHub on this repository. Do not open a public issue for a vulnerability.

Give these details:

- The version or the commit you tested.
- The steps that show the problem.
- The effect of the problem.

The maintainer answers within seven days.

## Supported versions

Only the newest release receives security fixes.

## Security design

The wiki page `Threat-Model` maps each security requirement of the MCP specification to a module and a test. The defaults of the SDK are secure: the HTTP server binds to `127.0.0.1`, validates the `Origin` header, and seals multi round-trip request state with AES-256-GCM.
