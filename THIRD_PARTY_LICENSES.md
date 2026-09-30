# Third-party material

This repository has no third-party source code. The items below are data files.

| Item | Location | Source | License |
| --- | --- | --- | --- |
| MCP schema examples, `schema.json`, `schema.ts` | `test/fixtures/mcp_schema_2026_07_28/` | https://github.com/modelcontextprotocol/modelcontextprotocol (commit in `UPSTREAM.zon`) | MIT, in transition to Apache-2.0. See `LICENSE` in that directory. |
| MCP specification pages of revision 2026-07-28 (`.mdx`), without `schema.mdx` and `changelog.mdx` | `test/fixtures/mcp_spec_2026_07_28/` | https://github.com/modelcontextprotocol/modelcontextprotocol, directory `docs/specification/2026-07-28` (commit in `UPSTREAM.zon`) | MIT, in transition to Apache-2.0. See `LICENSE` in that directory. |
| Normative sentences quoted from these pages | `docs/spec/requirements.zon`, `docs/generated/conformance-matrix.md` | Extracted from `test/fixtures/mcp_spec_2026_07_28/` by `zig build extract-requirements` | The license of the pages. |
| HPACK static table, Huffman code and the examples of appendix C | `src/grpc/http2/hpack/tables.zig`, `src/grpc/http2/hpack/rfc7541_examples.zig` | RFC 7541, https://www.rfc-editor.org/rfc/rfc7541 | IETF Trust Legal Provisions, code components under the BSD licence. |

The ASD-STE100 standard is cited by rule number only. No rule text and no dictionary entry of the standard is included.
