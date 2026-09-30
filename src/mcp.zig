//! The unofficial Zig SDK for the Model Context Protocol (MCP).
//!
//! This module provides MCP specification revision 2026-07-28.
const std = @import("std");

pub const protocol = @import("mcp/protocol.zig");
pub const json = @import("mcp/json.zig");
pub const jsonrpc = @import("mcp/jsonrpc.zig");
pub const transport = @import("mcp/transport.zig");
pub const Limits = @import("mcp/Limits.zig");
pub const Server = @import("mcp/server/Server.zig");
pub const Client = @import("mcp/client/Client.zig");
pub const auth = @import("mcp/auth.zig");
/// The Tasks extension: task support levels, results and the store.
pub const tasks = @import("mcp/server/tasks.zig");
pub const RequestContext = Server.RequestContext;
pub const Outcome = Server.Outcome;
pub const InputRequired = Server.InputRequired;
pub const schema = struct {
    pub const derive = @import("mcp/schema/derive.zig");
    pub const validator = @import("mcp/schema/validator.zig");
};
pub const UriTemplate = @import("mcp/uri_template/UriTemplate.zig");
/// TLS 1.3 server and certificate handling for HTTPS.
pub const tls = @import("tls/tls.zig");
pub const util = struct {
    pub const line_framer = @import("mcp/util/line_framer.zig");
};

pub const types = protocol.types;
pub const RequestId = jsonrpc.RequestId;
pub const CallToolResult = types.CallToolResult;
pub const ReadResourceResult = types.ReadResourceResult;
pub const GetPromptResult = types.GetPromptResult;

test {
    std.testing.refAllDecls(@This());
    _ = @import("mcp/golden_test.zig");
    _ = @import("mcp/fuzz_test.zig");
    _ = @import("mcp/server/request_state.zig");
    _ = @import("mcp/server/mrtr.zig");
    _ = @import("mcp/server/server_test.zig");
    _ = @import("mcp/client/client_test.zig");
    _ = @import("mcp/transport/http_test.zig");
    _ = @import("mcp/transport/https_test.zig");
    _ = @import("mcp/transport/http_client_test.zig");
    _ = @import("mcp/transport/http_auth_test.zig");
    _ = @import("tls/tls.zig");
}
