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
/// The client rules for icons.
pub const icons = Client.icons;
pub const auth = @import("mcp/auth.zig");
/// The Tasks extension: task support levels, results and the store.
pub const tasks = @import("mcp/server/tasks.zig");
/// The Skills extension: skill definitions and the registry of the server. The wire types,
/// the frontmatter parser and the host checks are in `protocol.skills`.
pub const skills = @import("mcp/server/skills.zig");
/// The MCP Apps extension: view definitions of the server. The UI metadata types and the
/// client helpers are in `protocol.apps`.
pub const apps = @import("mcp/server/apps.zig");
pub const RequestContext = Server.RequestContext;
pub const Outcome = Server.Outcome;
pub const InputRequired = Server.InputRequired;
pub const schema = struct {
    pub const derive = @import("mcp/schema/derive.zig");
    pub const validator = @import("mcp/schema/validator.zig");
    /// The ECMA-262 regular expression engine of the `pattern` keyword.
    pub const regex = @import("mcp/schema/regex.zig");
};
pub const UriTemplate = @import("mcp/uri_template/UriTemplate.zig");
/// TLS 1.3 server, certificates and keys for HTTPS.
pub const tls = @import("tls/tls.zig");
pub const util = struct {
    pub const line_framer = @import("mcp/util/line_framer.zig");
    pub const wake = @import("mcp/util/wake.zig");
    pub const rate_limit = @import("mcp/util/rate_limit.zig");
};

pub const types = protocol.types;
pub const RequestId = jsonrpc.RequestId;
pub const CallToolResult = types.CallToolResult;
pub const ReadResourceResult = types.ReadResourceResult;
pub const GetPromptResult = types.GetPromptResult;

test {
    std.testing.refAllDecls(@This());
    _ = @import("mcp/golden_test.zig");
    _ = @import("mcp/schema/suite_test.zig");
    _ = @import("mcp/fuzz_test.zig");
    _ = @import("mcp/client/cache.zig");
    _ = @import("mcp/server/request_state.zig");
    _ = @import("mcp/server/mrtr.zig");
    _ = @import("mcp/server/rate_limits.zig");
    _ = @import("mcp/server/server_test.zig");
    _ = @import("mcp/client/client_test.zig");
    _ = @import("mcp/extensions_test.zig");
    _ = @import("mcp/client/icons.zig");
    _ = @import("mcp/client/icons_test.zig");
    _ = @import("mcp/transport/http_test.zig");
    _ = @import("mcp/transport/https_test.zig");
    _ = @import("mcp/transport/http_client_test.zig");
    _ = @import("mcp/transport/http_auth_test.zig");
    _ = @import("mcp/transport/router.zig");
    _ = @import("mcp/util/rate_limit.zig");
    _ = @import("mcp/util/wake.zig");
    _ = @import("mcp/transport/unix_test.zig");
    _ = @import("mcp/transport/ws_frame.zig");
    _ = @import("mcp/transport/websocket_test.zig");
    _ = @import("tls/tls.zig");
    _ = @import("mcp/spec_test/base_protocol_test.zig");
    _ = @import("mcp/spec_test/transports_test.zig");
    _ = @import("mcp/spec_test/authorization_test.zig");
    _ = @import("mcp/spec_test/authorization_discovery_test.zig");
    _ = @import("mcp/spec_test/patterns_test.zig");
    _ = @import("mcp/spec_test/server_features_test.zig");
    _ = @import("mcp/spec_test/utilities_test.zig");
    _ = @import("mcp/spec_test/client_features_test.zig");
}
