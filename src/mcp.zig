//! The unofficial Zig SDK for the Model Context Protocol (MCP).
//!
//! This module implements MCP specification revision 2026-07-28.
const std = @import("std");

pub const protocol = @import("mcp/protocol.zig");

test {
    std.testing.refAllDecls(@This());
}
