//! Transports: the interfaces and the built-in bindings.
pub const Transport = @import("transport/Transport.zig");
pub const CancelToken = Transport.CancelToken;
pub const Responder = Transport.Responder;
pub const Inbound = Transport.Inbound;
pub const memory = @import("transport/memory.zig");
pub const stdio = @import("transport/stdio.zig");
pub const http = @import("transport/http.zig");
pub const HttpClient = @import("transport/http_client.zig").Client;
pub const sse = @import("transport/sse.zig");
pub const envelope = @import("transport/envelope.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
/// The HTTP/1.1 client connection the Streamable HTTP client uses.
pub const http1 = @import("transport/http1.zig");
