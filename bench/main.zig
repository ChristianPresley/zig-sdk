//! Benchmarks of the hot paths: request dispatch through the in-memory transport, HPACK
//! decoding, the TLS 1.3 handshake on a loopback socket and the HTTP/2 echo path.
//!
//! Usage: zig build bench [-- --smoke]
//! `--smoke` runs a few iterations only, to check that every benchmark still works.
const std = @import("std");
const Io = std.Io;
const mcp = @import("mcp");
const mcp_grpc = @import("mcp_grpc");
const types = mcp.types;

const Result = struct {
    name: []const u8,
    iterations: u64,
    total_ns: u64,
    p50_ns: u64,
    p99_ns: u64,

    fn print(self: Result, w: *Io.Writer) !void {
        const per_s = if (self.total_ns == 0) 0 else self.iterations * std.time.ns_per_s / self.total_ns;
        try w.print("| {s} | {d} | {d} | {d} | {d} |\n", .{ self.name, self.iterations, per_s, self.p50_ns / 1000, self.p99_ns / 1000 });
    }
};

/// Time `iterations` calls of `f` and report the distribution.
fn measure(gpa: std.mem.Allocator, io: Io, name: []const u8, iterations: u64, context: anytype, comptime f: anytype) !Result {
    const samples = try gpa.alloc(u64, iterations);
    defer gpa.free(samples);
    const start_all = Io.Clock.awake.now(io);
    for (samples) |*s| {
        const start = Io.Clock.awake.now(io);
        try f(context);
        s.* = @intCast(@max(start.durationTo(Io.Clock.awake.now(io)).nanoseconds, 0));
    }
    const total: u64 = @intCast(@max(start_all.durationTo(Io.Clock.awake.now(io)).nanoseconds, 0));
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return .{
        .name = name,
        .iterations = iterations,
        .total_ns = total,
        .p50_ns = samples[samples.len / 2],
        .p99_ns = samples[@min(samples.len - 1, samples.len * 99 / 100)],
    };
}

// -- Dispatch --------------------------------------------------------------------------------

const AddArgs = struct { a: i64, b: i64 };

fn add(ctx: *mcp.RequestContext, args: AddArgs) anyerror!mcp.Outcome(types.CallToolResult) {
    return .{ .complete = try types.CallToolResult.text(ctx.arena, "{d}", .{args.a + args.b}) };
}

const Dispatch = struct {
    harness: *mcp.transport.memory.Harness,
    frame: []const u8,

    fn once(self: Dispatch) !void {
        self.harness.clear();
        try self.harness.send(self.frame);
        if (!self.harness.finished) return error.NoResponse;
    }
};

const call_frame =
    \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"add","arguments":{"a":2,"b":3}}}
;

fn benchDispatch(gpa: std.mem.Allocator, io: Io, iterations: u64) !Result {
    var server = try mcp.Server.init(gpa, io, .{ .info = .{ .name = "bench", .version = "1" } });
    defer server.deinit();
    try server.addTool(.{ .name = "add" }, add);
    var harness: mcp.transport.memory.Harness = .init(io, gpa, &server);
    defer harness.deinit();
    return measure(gpa, io, "tools/call through the memory transport", iterations, Dispatch{ .harness = &harness, .frame = call_frame }, Dispatch.once);
}

// -- HPACK -----------------------------------------------------------------------------------

const Hpack = struct {
    gpa: std.mem.Allocator,
    decoder: *mcp_grpc.http2.hpack.Decoder,
    blocks: []const []const u8,

    fn once(self: Hpack) !void {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        for (self.blocks) |block| {
            var out: std.ArrayList(mcp_grpc.http2.hpack.Header) = .empty;
            try self.decoder.decode(arena_state.allocator(), block, &out);
        }
    }
};

fn benchHpack(gpa: std.mem.Allocator, io: Io, iterations: u64) !Result {
    const hpack = mcp_grpc.http2.hpack;
    // A typical gRPC request head, encoded once by the SDK encoder.
    const headers = [_]hpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/mcp.zig.transport.v1.Mcp/Call" },
        .{ .name = ":authority", .value = "127.0.0.1:50051" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = "mcp-protocol-version", .value = "2026-07-28" },
        .{ .name = "mcp-method", .value = "tools/call" },
        .{ .name = "mcp-name", .value = "add" },
    };
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    const encoder: hpack.Encoder = .{};
    try encoder.encodeHeaders(gpa, &block, &headers);
    var decoder: hpack.Decoder = .init(gpa, .{});
    defer decoder.deinit();
    const blocks = [_][]const u8{block.items};
    var result = try measure(gpa, io, "HPACK decode of a gRPC request head", iterations, Hpack{ .gpa = gpa, .decoder = &decoder, .blocks = &blocks }, Hpack.once);
    result.name = "HPACK decode of a gRPC request head";
    return result;
}

// -- TLS handshake ---------------------------------------------------------------------------

const TlsEcho = struct {
    io: Io,
    server: *const mcp.tls.Server,
    listener: *Io.net.Server,
    stop: std.atomic.Value(bool) = .init(false),

    fn serve(self: *TlsEcho) void {
        while (!self.stop.load(.acquire)) {
            var stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            var in_buf: [mcp.tls.Connection.min_input_buffer_len]u8 = undefined;
            var out_buf: [mcp.tls.Connection.min_output_buffer_len]u8 = undefined;
            var reader = stream.reader(self.io, &in_buf);
            var writer = stream.writer(self.io, &out_buf);
            var read_buf: [mcp.tls.Connection.min_read_buffer_len]u8 = undefined;
            var write_buf: [1024]u8 = undefined;
            var conn = self.server.accept(&reader.interface, &writer.interface, .{ .io = self.io, .read_buffer = &read_buf, .write_buffer = &write_buf }) catch continue;
            conn.end() catch {};
            writer.interface.flush() catch {};
            conn.deinit();
        }
    }
};

const TlsClient = struct {
    io: Io,
    port: u16,

    fn once(self: TlsClient) !void {
        const address = Io.net.IpAddress.parse("127.0.0.1", self.port) catch unreachable;
        var stream = try address.connect(self.io, .{ .mode = .stream });
        defer stream.close(self.io);
        var in_buf: [mcp.tls.Connection.min_input_buffer_len]u8 = undefined;
        var out_buf: [mcp.tls.Connection.min_output_buffer_len]u8 = undefined;
        var reader = stream.reader(self.io, &in_buf);
        var writer = stream.writer(self.io, &out_buf);
        var read_buf: [mcp.tls.Connection.min_read_buffer_len]u8 = undefined;
        var write_buf: [1024]u8 = undefined;
        var conn = try mcp.tls.connect(&reader.interface, &writer.interface, .{
            .io = self.io,
            .host = "localhost",
            .trust = .self_signed,
            .read_buffer = &read_buf,
            .write_buffer = &write_buf,
            .allow_truncation_attacks = true,
        });
        conn.end() catch {};
        writer.interface.flush() catch {};
        conn.deinit();
    }
};

fn benchTls(gpa: std.mem.Allocator, io: Io, iterations: u64) !Result {
    var chain = try mcp.tls.CertChain.loadFiles(gpa, io, "test/fixtures/tls/pem/p256.crt", "test/fixtures/tls/pem/p256.key");
    defer chain.deinit();
    const chains = [_]*const mcp.tls.CertChain{&chain};
    const tls_server = try mcp.tls.Server.init(.{ .chains = &chains });
    var listener = try (Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable).listen(io, .{});
    defer listener.deinit(io);
    var echo: TlsEcho = .{ .io = io, .server = &tls_server, .listener = &listener };
    var future = try io.concurrent(TlsEcho.serve, .{&echo});
    defer {
        echo.stop.store(true, .release);
        _ = future.cancel(io);
    }
    return measure(gpa, io, "TLS 1.3 handshake, P-256 certificate, loopback", iterations, TlsClient{ .io = io, .port = listener.socket.address.getPort() }, TlsClient.once);
}

// -- Main ------------------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var smoke = false;
    for (args[1..]) |a| if (std.mem.eql(u8, a, "--smoke")) {
        smoke = true;
    };
    const n_dispatch: u64 = if (smoke) 20 else 20_000;
    const n_hpack: u64 = if (smoke) 20 else 200_000;
    const n_tls: u64 = if (smoke) 3 else 200;

    var out_buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &out_buf);
    const w = &stdout.interface;
    try w.print("| Benchmark | Iterations | Per second | p50 (us) | p99 (us) |\n| --- | --- | --- | --- | --- |\n", .{});
    try (try benchDispatch(gpa, io, n_dispatch)).print(w);
    try (try benchHpack(gpa, io, n_hpack)).print(w);
    try (try benchTls(gpa, io, n_tls)).print(w);
    try w.flush();
}
