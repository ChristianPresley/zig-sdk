//! The gRPC transport of the SDK: a JSON-RPC tunnel over HTTP/2 with its own protobuf,
//! HPACK, HTTP/2 and gRPC layers. Nothing in `mcp` imports this module.
const std = @import("std");

pub const protobuf = struct {
    pub const wire = @import("grpc/protobuf/wire.zig");
    pub const messages = @import("grpc/protobuf/messages.zig");
    /// The table-driven codec of the typed messages.
    pub const codec = @import("grpc/protobuf/codec.zig");
    /// `google.protobuf.Struct`, `Value`, `ListValue` and `Duration`.
    pub const well_known = @import("grpc/protobuf/well_known.zig");
    /// The messages of the Google Cloud proto files for MCP.
    pub const mcp_messages = @import("grpc/protobuf/mcp_messages.zig");
};

/// The typed binding: the service `model_context_protocol.Mcp` and the mapping between MCP
/// JSON and its messages.
pub const typed = struct {
    pub const service = @import("grpc/typed/service.zig");
    pub const convert = @import("grpc/typed/convert.zig");
};

pub const http2 = struct {
    pub const hpack = @import("grpc/http2/hpack/hpack.zig");
    pub const huffman = @import("grpc/http2/hpack/huffman.zig");
    pub const frame = @import("grpc/http2/frame.zig");
    pub const Connection = @import("grpc/http2/Connection.zig");
};

pub const grpc = struct {
    pub const status = @import("grpc/grpc/status.zig");
    pub const timeout = @import("grpc/grpc/timeout.zig");
    pub const lpm = @import("grpc/grpc/lpm.zig");
};

pub const server = @import("grpc/transport/grpc_server.zig");
pub const client = @import("grpc/transport/grpc_client.zig");
/// The gRPC server transport for an `mcp.Server`.
pub const Server = server.Server;
/// The gRPC client transport: a channel to one server.
pub const Channel = client.Channel;

test {
    std.testing.refAllDecls(@This());
    _ = protobuf.wire;
    _ = protobuf.messages;
    _ = protobuf.codec;
    _ = protobuf.well_known;
    _ = protobuf.mcp_messages;
    _ = typed.service;
    _ = typed.convert;
    _ = http2.hpack;
    _ = http2.huffman;
    _ = http2.frame;
    _ = http2.Connection;
    _ = grpc.status;
    _ = grpc.timeout;
    _ = @import("grpc/http2/connection_test.zig");
    _ = @import("grpc/grpc_test.zig");
    _ = @import("grpc/fuzz_test.zig");
    _ = @import("grpc/spec_test/authorization_test.zig");
}
