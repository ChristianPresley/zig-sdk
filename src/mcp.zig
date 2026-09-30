//! The unofficial Zig SDK for the Model Context Protocol (MCP).
//!
//! This module implements MCP specification revision 2026-07-28.
const std = @import("std");

pub const protocol = @import("mcp/protocol.zig");
pub const json = @import("mcp/json.zig");
pub const jsonrpc = @import("mcp/jsonrpc.zig");

pub const types = protocol.types;
pub const RequestId = jsonrpc.RequestId;

test {
    std.testing.refAllDecls(@This());
    _ = @import("mcp/golden_test.zig");
}
