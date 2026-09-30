//! gRPC length-prefixed messages: one byte for the compression flag, four bytes of
//! big-endian length, then the payload.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Connection = @import("../http2/Connection.zig");
const Stream = Connection.Stream;

pub const prefix_len = 5;

pub const Error = Connection.Error || error{
    /// The message is compressed. The SDK negotiates identity only.
    Compressed,
    /// The message is larger than the limit.
    MessageTooLarge,
    /// The stream ended inside a message.
    Truncated,
};

/// Send one message. With `end_stream` the send side closes after it.
pub fn write(stream: *Stream, gpa: Allocator, payload: []const u8, end_stream: bool) Error!void {
    const buf = try gpa.alloc(u8, prefix_len + payload.len);
    defer gpa.free(buf);
    buf[0] = 0;
    std.mem.writeInt(u32, buf[1..5], @intCast(payload.len), .big);
    @memcpy(buf[prefix_len..], payload);
    try stream.sendData(buf, end_stream);
}

/// Receive one message, or null when the stream ended before a message started.
pub fn read(stream: *Stream, gpa: Allocator, max_len: usize) Error!?[]u8 {
    var prefix: [prefix_len]u8 = undefined;
    var got: usize = 0;
    while (got < prefix_len) {
        const n = try stream.read(prefix[got..]);
        if (n == 0) {
            if (got == 0) return null;
            return error.Truncated;
        }
        got += n;
    }
    if (prefix[0] != 0) return error.Compressed;
    const len = std.mem.readInt(u32, prefix[1..5], .big);
    if (len > max_len) return error.MessageTooLarge;
    const payload = try gpa.alloc(u8, len);
    errdefer gpa.free(payload);
    var filled: usize = 0;
    while (filled < len) {
        const n = try stream.read(payload[filled..]);
        if (n == 0) return error.Truncated;
        filled += n;
    }
    return payload;
}
