//! TLS 1.3 (RFC 8446) for the SDK: a server, and later a client, on top of the primitives
//! in `std.crypto`. Only TLS 1.3 is offered. There is no resumption, no early data and no
//! renegotiation.
const std = @import("std");

pub const suites = @import("suites.zig");
pub const Suite = suites.Suite;
pub const der = @import("der.zig");
pub const pem = @import("pem.zig");
pub const PrivateKey = @import("PrivateKey.zig");
pub const CertChain = @import("CertChain.zig");
pub const Connection = @import("Connection.zig");
pub const key_share = @import("handshake/key_share.zig");
pub const codec = @import("handshake/codec.zig");
pub const server = @import("handshake/server.zig");
pub const Server = server.Server;

/// The std TLS toolbox this implementation reuses: enums, `Decoder` and key derivation.
pub const std_tls = std.crypto.tls;

test {
    std.testing.refAllDecls(@This());
    _ = @import("server_test.zig");
}
