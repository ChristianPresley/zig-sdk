//! The gRPC transport of the SDK: a JSON-RPC tunnel over HTTP/2 with its own protobuf,
//! HPACK, HTTP/2 and gRPC layers. Nothing in `mcp` imports this module.
const std = @import("std");

pub const protobuf = struct {
    pub const wire = @import("grpc/protobuf/wire.zig");
    pub const messages = @import("grpc/protobuf/messages.zig");
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
