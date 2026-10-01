//! Fuzz targets for the parsers of the core module. Each target must never crash. Errors
//! are the expected outcome for bad input. `zig build test -Dfuzz --fuzz` explores them, and the
//! plain test run executes each once.
const std = @import("std");
const Smith = std.testing.Smith;
const mcp = @import("../mcp.zig");
const jsonrpc = mcp.jsonrpc;
const sse = mcp.transport.sse;
const envelope = mcp.transport.envelope;
const line_framer = mcp.util.line_framer;
const validator = mcp.schema.validator;
const regex = mcp.schema.regex;
const jwt = mcp.auth.jwt;
const request_state = @import("server/request_state.zig");
const meta_mod = mcp.protocol.meta;
const tls = mcp.tls;

const max_input = 2048;

fn input(smith: *Smith, buf: *[max_input]u8, hash: u32) []u8 {
    const n = smith.sliceWithHash(buf, hash);
    return buf[0..n];
}

fn jsonRpc(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1001);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const msg = jsonrpc.Message.parse(arena, bytes) catch return;
    switch (msg) {
        .request => |r| _ = meta_mod.lift(arena, r.params) catch {},
        else => {},
    }
}

test "fuzz: JSON-RPC message and _meta" {
    try std.testing.fuzz({}, jsonRpc, .{ .corpus = &.{
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"add\"}}",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}",
        "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"error\":{\"code\":-32600,\"message\":\"m\"}}",
    } });
}

fn sseParser(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1002);
    var parser: sse.Parser = .init(std.testing.allocator);
    defer parser.deinit();
    // Feed in two pieces to cover splits.
    const split = bytes.len / 2;
    try parser.feed(bytes[0..split]);
    try parser.feed(bytes[split..]);
    while (parser.next()) |event| parser.release(event);
}

test "fuzz: SSE parser" {
    try std.testing.fuzz({}, sseParser, .{ .corpus = &.{ "data: {\"a\":1}\n\n", ": comment\r\ndata: x\r\ndata: y\r\n\r\n", "\xef\xbb\xbfevent: e\nid: 1\nretry: 5\ndata:\n\n" } });
}

fn framer(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1003);
    var reader: std.Io.Reader = .fixed(bytes);
    var f: line_framer.Framer = .{ .reader = &reader, .max_line_bytes = 256 };
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var lines: usize = 0;
    while (lines < 64) : (lines += 1) {
        _ = f.next(arena_state.allocator()) catch |e| switch (e) {
            error.EndOfStream => return,
            else => continue,
        };
    }
}

test "fuzz: line framer" {
    try std.testing.fuzz({}, framer, .{ .corpus = &.{ "{}\n{}\r\n\n{\"x\":1}", "a\x00b\n", "" } });
}

fn headerValues(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1004);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    _ = envelope.decodeValue(arena, bytes) catch {};
    _ = try envelope.encodeValue(arena, bytes);
    const headers: envelope.Headers = .{ .protocol_version = "2026-07-28", .method = "tools/call", .name = bytes };
    _ = try envelope.verify(arena, headers, "tools/call", null, null);
}

test "fuzz: header values" {
    try std.testing.fuzz({}, headerValues, .{ .corpus = &.{ "=?base64?aGVsbG8=?=", "=?base64?!!?=", "plain value" } });
}

fn uriTemplate(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1005);
    var template = mcp.UriTemplate.parse(std.testing.allocator, bytes, 32) catch return;
    defer template.deinit(std.testing.allocator);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var vars: std.ArrayList(mcp.UriTemplate.Variable) = .empty;
    _ = template.match("file:///a/b?c=d", &vars, arena_state.allocator()) catch {};
}

test "fuzz: URI template" {
    try std.testing.fuzz({}, uriTemplate, .{ .corpus = &.{ "file:///{+path}", "test://{id}/data{?q,r}", "{" } });
}

fn schema(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1006);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var compiled = validator.compileText(arena, bytes, .{}) catch return;
    const instance = mcp.json.parseTree(arena, "{\"a\":1,\"b\":[true,\"x\"],\"c\":{\"d\":null}}") catch return;
    _ = validator.validate(arena, &compiled, instance) catch {};
}

test "fuzz: JSON Schema compile and validate" {
    try std.testing.fuzz({}, schema, .{ .corpus = &.{
        "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"integer\",\"minimum\":0}},\"required\":[\"a\"]}",
        "{\"$ref\":\"#/$defs/x\",\"$defs\":{\"x\":{\"$ref\":\"#\"}}}",
        "{\"allOf\":[{\"not\":{}},true,false]}",
        "{\"patternProperties\":{\"^[a-c]\":{\"pattern\":\"x*\"}},\"propertyNames\":{\"pattern\":\"^\\\\w+$\"}}",
    } });
}

fn regexMatch(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x100A);
    // The pattern ends at the first zero byte. The rest is the subject.
    const split = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    const pattern = bytes[0..split];
    const subject = if (split < bytes.len) bytes[split + 1 ..] else "";
    const gpa = std.testing.allocator;
    const options: regex.Options = .{ .max_pattern_bytes = 512, .max_states = 1024 };
    var re = regex.compile(gpa, pattern, options) catch return;
    defer re.deinit(gpa);
    const matched = try re.isMatch(gpa, subject);
    // A non-capturing group around the pattern does not change the result.
    var wrapped_text: [max_input + 4]u8 = undefined;
    const wrapped = try std.fmt.bufPrint(&wrapped_text, "(?:{s})", .{pattern});
    var re2 = regex.compile(gpa, wrapped, .{ .max_pattern_bytes = max_input + 4, .max_states = 1024 }) catch return;
    defer re2.deinit(gpa);
    try std.testing.expectEqual(matched, try re2.isMatch(gpa, subject));
}

test "fuzz: regular expression compile and match" {
    try std.testing.fuzz({}, regexMatch, .{ .corpus = &.{
        "^(a*)*b$\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaac",
        "[\\w-.]+@[^\\s]{2,}\\.\\p{ASCII}\x00me@example.org",
        "\\bfoo|(?:x{2,3}?)+\\u{1F600}[^\\d\\S]\x00x foo",
        "(?<n>\\x41\\uD83D\\uDE00)\\cJ\x00A\u{1F600}\n",
    } });
}

fn jwtParse(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1007);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const keys = [_]jwt.Key{.{ .kid = null, .alg = .HS256, .material = .{ .secret = "secret" } }};
    _ = jwt.verify(arena_state.allocator(), bytes, .{ .keys = &keys, .audience = "aud" }, 1000) catch {};
}

test "fuzz: JWT" {
    try std.testing.fuzz({}, jwtParse, .{ .corpus = &.{ "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln", "a.b", "..." } });
}

fn sealedState(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1008);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var codec = request_state.Codec.initRandom(std.testing.io, .fromSeconds(60)) catch return;
    defer codec.deinit();
    _ = codec.unseal(arena_state.allocator(), "tools/call|x", bytes, 0) catch {};
}

test "fuzz: sealed request state" {
    try std.testing.fuzz({}, sealedState, .{ .corpus = &.{ "v1.AAAA", "v1.", "" } });
}

fn tlsParsers(_: void, smith: *Smith) anyerror!void {
    var buf: [max_input]u8 = undefined;
    const bytes = input(smith, &buf, 0x1009);
    var copy: [max_input]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    _ = tls.codec.ClientHello.parse(copy[0..bytes.len]) catch {};
    _ = tls.client.ServerHello.parse(copy[0..bytes.len]) catch {};
    _ = tls.client.EncryptedExtensions.parse(copy[0..bytes.len], .{}) catch {};
    _ = tls.client.CertificateRequest.parse(copy[0..bytes.len]) catch {};
    _ = tls.ca_names.parse(bytes) catch {};
    _ = tls.pss.signatureParams(bytes) catch {};
    _ = tls.pss.publicKeyParams(bytes) catch {};
    _ = tls.der.parse(bytes) catch {};
    _ = tls.PrivateKey.parseDer(bytes) catch {};
    _ = tls.rsa.parsePkcs1(bytes) catch {};
    var share_public: [tls.key_share.max_public_len]u8 = undefined;
    var share_secret: [tls.key_share.max_shared_len]u8 = undefined;
    _ = tls.key_share.respond(std.testing.io, .x25519_mlkem768, bytes, &share_public, &share_secret) catch {};
    _ = tls.x509.basicConstraints(bytes) catch {};
    _ = tls.x509.keyUsage(bytes) catch {};
    _ = tls.x509.extendedKeyUsage(bytes) catch {};
    if (tls.name_constraints.NameConstraints.parse(bytes, true)) |nc| {
        nc.checkName(.{ .form = .dns_name, .value = "www.example.com" }) catch {};
        nc.checkName(.{ .form = .directory_name, .value = bytes }) catch {};
        nc.checkName(.{ .form = .uri, .value = bytes }) catch {};
        nc.checkName(.{ .form = .rfc822_name, .value = bytes }) catch {};
    } else |_| {}
    tls.name_constraints.checkPath(&.{bytes}, bytes, "localhost") catch {};
    if (tls.Crl.fromDer(std.testing.allocator, bytes)) |crl_value| {
        var crl = crl_value;
        defer crl.deinit();
        _ = crl.find(bytes);
        _ = crl.isCurrent(0, 0);
    } else |_| {}
    if (tls.der.parse(bytes)) |element| _ = element.time() catch {} else |_| {}
    _ = tls.ocsp.check(bytes, bytes, bytes, 0, 0) catch {};
    _ = tls.verify.verifyChain(&.{bytes}, .self_signed, .{ .purpose = .server, .host = "localhost", .now_sec = 0 }) catch {};
    var it: tls.pem.Iterator = .init(bytes);
    while (it.next()) |block| {
        const decoded = block.decode(std.testing.allocator) catch continue;
        std.testing.allocator.free(decoded);
    }
}

test "fuzz: TLS message, DER, PEM and key parsers" {
    try std.testing.fuzz({}, tlsParsers, .{ .corpus = &.{ "\x03\x03" ++ "\x00" ** 32 ++ "\x00\x00\x02\x13\x01\x01\x00\x00\x00", "0\x82\x01\x00", "0\x82\x04\xa4\x02\x01\x00\x02\x82\x01\x01\x00", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" } });
}

fn recordLayer(_: void, smith: *Smith) anyerror!void {
    const gpa = std.testing.allocator;
    const Connection = tls.Connection;
    const secret = [_]u8{7} ** 32;

    // The sender: messages from the input, with flushes and a padding policy from the input.
    var unused_in: std.Io.Reader = .fixed("");
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    var send_read: [Connection.min_read_buffer_len]u8 = undefined;
    var send_write: [1024]u8 = undefined;
    var sender: Connection = .init(&unused_in, &sink.writer, .server, &send_read, &send_write, false);
    defer sender.deinit();
    sender.write_keys = tls.suites.DirectionKeys.init(.AES_128_GCM_SHA256, secret);
    sender.handshake_complete = true;
    const policy: tls.Padding = switch (smith.valueRangeAtMostWithHash(u8, 0, 2, 0x2001)) {
        0 => .none,
        1 => .{ .block = smith.valueWithHash(u16, 0x2002) },
        else => .{ .random = smith.valueWithHash(u16, 0x2003) },
    };
    try sender.setPadding(std.testing.io, policy);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(gpa);
    var msg_buf: [max_input]u8 = undefined;
    while (expected.items.len < 64 << 10 and !smith.eosWithHash(0x2004)) {
        const msg = input(smith, &msg_buf, 0x2005);
        try sender.writer.writeAll(msg);
        try expected.appendSlice(gpa, msg);
        if (smith.boolWeightedWithHash(1, 1, 0x2006)) try sender.writer.flush();
    }
    try sender.writer.flush();
    try sender.end();
    const wire = sink.written();

    // An optional change of one byte: the receiver must fail without a crash.
    const changed = wire.len > 0 and smith.boolWeightedWithHash(3, 1, 0x2007);
    if (changed) wire[smith.indexWithHash(wire.len, 0x2008)] ^= smith.valueRangeAtMostWithHash(u8, 1, 255, 0x2009);

    // The receiver: the stream gives pieces of a size from the input, and the reads mix lines,
    // short reads and the buffered data, as the HTTP and MCP readers do.
    var input_buf: [Connection.min_input_buffer_len]u8 = undefined;
    const calls = [_]std.testing.Reader.Call{.{ .buffer = wire }};
    var stream: std.testing.Reader = .init(&input_buf, &calls);
    stream.artificial_limit = .limited(smith.valueRangeAtMostWithHash(u16, 1, 20_000, 0x200a));
    var receive_sink: std.Io.Writer.Allocating = .init(gpa);
    defer receive_sink.deinit();
    var receive_read: [Connection.min_read_buffer_len]u8 = undefined;
    var receive_write: [64]u8 = undefined;
    var receiver: Connection = .init(&stream.interface, &receive_sink.writer, .client, &receive_read, &receive_write, false);
    defer receiver.deinit();
    receiver.read_keys = tls.suites.DirectionKeys.init(.AES_128_GCM_SHA256, secret);
    receiver.handshake_complete = true;
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var short_buf: [4096]u8 = undefined;
    while (true) {
        switch (smith.valueRangeAtMostWithHash(u8, 0, 2, 0x200b)) {
            0 => if (receiver.reader.peekDelimiterInclusive('\n')) |line| {
                try got.appendSlice(gpa, line);
                receiver.reader.toss(line.len);
            } else |e| switch (e) {
                error.StreamTooLong => {
                    const all = receiver.reader.buffered();
                    try got.appendSlice(gpa, all);
                    receiver.reader.toss(all.len);
                },
                error.EndOfStream => break,
                error.ReadFailed => break,
            },
            1 => {
                const len = smith.valueRangeAtMostWithHash(u16, 1, short_buf.len, 0x200c);
                const n = receiver.reader.readSliceShort(short_buf[0..len]) catch break;
                if (n == 0) break;
                try got.appendSlice(gpa, short_buf[0..n]);
            },
            else => {
                const all = receiver.reader.buffered();
                if (all.len == 0) {
                    receiver.reader.fillMore() catch break;
                    continue;
                }
                try got.appendSlice(gpa, all);
                receiver.reader.toss(all.len);
            },
        }
    }
    try got.appendSlice(gpa, receiver.reader.buffered());
    if (!changed) {
        if (receiver.read_err) |e| return e;
        try std.testing.expect(receiver.eof());
        try std.testing.expectEqualSlices(u8, expected.items, got.items);
    } else {
        // What arrives before the changed record is a prefix of the sent data.
        try std.testing.expect(got.items.len <= expected.items.len);
        try std.testing.expectEqualSlices(u8, expected.items[0..got.items.len], got.items);
    }
}

test "fuzz: TLS record layer with padding, partial input and one changed byte" {
    try std.testing.fuzz({}, recordLayer, .{ .corpus = &.{ "", "hello\nover tls\n", "\x01\x00\x10" ++ "a" ** 64 ++ "\n" } });
}
