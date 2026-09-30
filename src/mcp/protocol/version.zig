//! Protocol constants.
const std = @import("std");

/// The only MCP specification revision that this SDK implements.
pub const version = "2026-07-28";
/// All revisions that this SDK supports. Exactly one entry by design.
pub const supported_versions = [_][]const u8{version};
pub const jsonrpc_version = "2.0";

test "version table has one entry" {
    try std.testing.expectEqual(1, supported_versions.len);
    try std.testing.expectEqualStrings("2026-07-28", supported_versions[0]);
}
