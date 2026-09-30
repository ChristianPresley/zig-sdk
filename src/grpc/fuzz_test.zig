//! Fuzz targets for the parsers of the gRPC module: HPACK, Huffman, frames, protobuf, the
//! tunnel message, the timeout header and the status message.
const std = @import("std");
const Smith = std.testing.Smith;
const hpack = @import("http2/hpack/hpack.zig");
const huffman = @import("http2/hpack/huffman.zig");
const frame = @import("http2/frame.zig");
const wire = @import("protobuf/wire.zig");
const messages = @import("protobuf/messages.zig");
const timeout = @import("grpc/timeout.zig");
const status = @import("grpc/status.zig");

const max_input = 2048;

fn input(smith: *Smith, buf: *[max_input]u8, hash: u32) []u8 {
    const n = smith.sliceWithHash(buf, hash);
    return buf[0..n];
}

fn hpackDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x2001);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var decoder: hpack.Decoder = .init(std.testing.allocator, .{ .max_table_size = 256 });
    defer decoder.deinit();
    var out: std.ArrayList(hpack.Header) = .empty;
    // Two blocks in a row exercise the dynamic table across blocks.
    const split = bytes.len / 2;
    decoder.decode(arena_state.allocator(), bytes[0..split], &out) catch {};
    decoder.decode(arena_state.allocator(), bytes[split..], &out) catch {};
    var decoded: std.ArrayList(u8) = .empty;
    huffman.decode(arena_state.allocator(), &decoded, bytes) catch {};
}

test "fuzz: HPACK and Huffman" {
    try std.testing.fuzz({}, hpackDecode, .{ .corpus = &.{ "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", "\x3f\xe1\x1f\x40\x0a", "\x00\x81\xff" } });
}

fn frames(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x2002);
    if (bytes.len >= frame.header_len) _ = frame.Header.parse(bytes[0..frame.header_len]);
    var settings: frame.Settings = .{};
    var i: usize = 0;
    while (i + 6 <= bytes.len) : (i += 6) {
        settings.apply(.{ .id = std.mem.readInt(u16, bytes[i..][0..2], .big), .value = std.mem.readInt(u32, bytes[i + 2 ..][0..4], .big) }) catch {};
    }
}

test "fuzz: frame headers and settings" {
    try std.testing.fuzz({}, frames, .{ .corpus = &.{"\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x04\x00\x10\x00\x00"} });
}

fn protobuf(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x2003);
    var r: wire.Reader = .init(bytes);
    while (r.next() catch null) |_| {}
    _ = messages.decodeJsonRpcMessage(bytes) catch {};
}

test "fuzz: protobuf and the tunnel message" {
    try std.testing.fuzz({}, protobuf, .{ .corpus = &.{ "\x0a\x02{}", "\x08\xac\x02\x12\x05hello", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01" } });
}

fn headerText(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x2004);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    _ = timeout.parse(bytes) catch {};
    _ = try status.decodeMessage(arena_state.allocator(), bytes);
    _ = try status.encodeMessage(arena_state.allocator(), bytes);
    _ = status.Code.fromWire(bytes);
}

test "fuzz: timeout, status and message headers" {
    try std.testing.fuzz({}, headerText, .{ .corpus = &.{ "1500m", "%C3%A9%", "12" } });
}
