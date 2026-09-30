//! The JSON-RPC 2.0 envelope.
pub const id = @import("jsonrpc/id.zig");
pub const RequestId = id.RequestId;
pub const message = @import("jsonrpc/message.zig");
pub const Message = message.Message;

test {
    @import("std").testing.refAllDecls(@This());
}
