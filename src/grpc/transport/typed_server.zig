//! The server side of the typed binding: the unary RPCs of `model_context_protocol.Mcp`. Each
//! RPC carries one MCP request. The server converts the request message into the JSON-RPC
//! request of the MCP method and runs it through the same server engine as the tunnel. Then
//! it converts the result into the response message.
//!
//! - A JSON-RPC error ends the call with headers only: `grpc-status`, `grpc-message`,
//!   `mcp-error-code` and, when it is small, `mcp-error-bin`.
//! - Notifications related to the request, for example progress, have no place in a unary
//!   response. The server drops them.
//! - A list result in pages becomes one response: the server follows `nextCursor` and merges
//!   the pages, because the messages have no cursor.
//! - A result that the messages cannot carry ends with `INTERNAL` and the code `-32603`.
//! - The server keeps the encoded response messages of recent list results. A list result
//!   with the same JSON text gets the same message without a new parse and encode. See
//!   `ResultCache`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("mcp");
const Transport = mcp.transport.Transport;
const jsonrpc = mcp.jsonrpc;
const errors = mcp.protocol.errors;
const version = mcp.protocol.version;
const meta = mcp.protocol.meta;
const envelope = mcp.transport.envelope;
const resource_server = mcp.auth.resource_server;
const Connection = @import("../http2/Connection.zig");
const Stream = Connection.Stream;
const Header = Connection.Header;
const lpm = @import("../grpc/lpm.zig");
const status = @import("../grpc/status.zig");
const timeout = @import("../grpc/timeout.zig");
const grpc_server = @import("grpc_server.zig");
const service = @import("../typed/service.zig");
const convert = @import("../typed/convert.zig");
const Deadlines = @import("deadlines.zig");
const lockfree = @import("mcp").util.lockfree;

const log = std.log.scoped(.mcp_grpc);

/// The most pages that the server merges into one list response. A list with more pages ends
/// with `INTERNAL`, because the rest of the list has no place in the response.
pub const max_list_pages = 1024;

/// The JSON-RPC ids of the requests that the typed binding gives to the server engine.
var next_id: std.atomic.Value(i64) = .init(1);

/// A request of the typed binding that `prepare` read and checked.
pub const Prepared = struct {
    rpc: service.Rpc,
    /// The params of the JSON-RPC request. They point into the payload in the call arena.
    params: Value,
    deadline: ?Io.Duration,
    principal: ?*resource_server.Principal,
    /// The slot of a quick request in `grpc_server.Server.costs`. Null for other requests.
    cost_slot: ?usize = null,
};

/// Read the request message of `rpc` and check it against the metadata. Null when the call
/// ended with an error. The caller checked the method, the content type, the encoding and the
/// bearer token.
pub fn prepare(self: *grpc_server.Server, stream: *Stream, arena: Allocator, headers: []const Header, rpc: service.Rpc, principal: ?*resource_server.Principal) !?Prepared {
    var deadline: ?Io.Duration = null;
    if (Connection.findHeader(headers, "grpc-timeout")) |t| {
        deadline = timeout.parse(t) catch return ended(grpc_server.trailersOnly(stream, arena, .invalid_argument, "Invalid grpc-timeout", null, null));
    }

    // The one request message. It is in the call arena, because the params point into it.
    const payload = lpm.read(stream, arena, self.options.max_message_bytes) catch |e| switch (e) {
        error.MessageTooLarge => return ended(grpc_server.trailersOnly(stream, arena, .resource_exhausted, "Message too large", null, null)),
        error.Compressed => return ended(grpc_server.trailersOnly(stream, arena, .unimplemented, "Compression is not supported", null, null)),
        error.Truncated => return ended(grpc_server.trailersOnly(stream, arena, .invalid_argument, "Truncated message", null, null)),
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    } orelse return ended(grpc_server.trailersOnly(stream, arena, .invalid_argument, "The call carried no message", null, null));

    var cx: convert.Context = .{ .arena = arena, .limits = self.options.typed_limits };
    var params = convert.decodeRequest(&cx, rpc, payload) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Invalid, error.Unexpressible => return ended(rpcError(stream, arena, errors.invalidParams(cx.reason))),
        else => return ended(rpcError(stream, arena, errors.parseError(try std.fmt.allocPrint(arena, "The message is not a valid {s}: {t}", .{ requestName(rpc), e })))),
    };

    // A different revision in `mcp-protocol-version` gets -32022 before the other metadata
    // checks, as on the tunnel. Without the metadata, the version of this SDK applies.
    if (Connection.findHeader(headers, envelope.header_protocol_version)) |pv| {
        if (try envelope.verifyVersion(arena, pv, envelope.metaVersion(params))) |rejection| {
            if (rejection.unsupported_version != null) return ended(rpcError(stream, arena, try rejection.rpcError(arena)));
        }
    }
    // The routing metadata must agree with the message, as `mcp-name` on the tunnel.
    if (rpc.routeHeader()) |name| {
        const expected: ?[]const u8 = if (convert.route(rpc, params)) |r| r.value else null;
        for (headers) |h| {
            if (!std.mem.eql(u8, h.name, name)) continue;
            if (expected == null or !std.mem.eql(u8, h.value, expected.?)) {
                const message = try std.fmt.allocPrint(arena, "Header mismatch: {s} value '{s}' does not match the message value '{s}'", .{ name, h.value, expected orelse "" });
                return ended(rpcError(stream, arena, errors.headerMismatch(message)));
            }
        }
    }
    if (try completeMeta(arena, &params, Connection.findHeader(headers, envelope.header_protocol_version))) |message| {
        return ended(rpcError(stream, arena, errors.headerMismatch(message)));
    }
    return .{ .rpc = rpc, .params = params, .deadline = deadline, .principal = principal };
}

/// The result of a function that ends the call.
fn ended(result: anyerror!void) !?Prepared {
    try result;
    return null;
}

/// True when the request of `p` ends without a wait. See `mcp.Server.isQuick`.
pub fn isQuick(self: *grpc_server.Server, p: Prepared) bool {
    return self.server.isQuick(.{ .request = .{ .id = .{ .integer = 0 }, .method = p.rpc.method(), .params = p.params } });
}

/// Run the request of `p` and send the response. With `no_wait` the read task or a worker runs
/// it: the request is quick and has no reset hook and no deadline. The result is then the
/// response message when it must wait for flow control credit.
pub fn execute(self: *grpc_server.Server, stream: *Stream, arena: Allocator, p: Prepared, no_wait: bool) !?grpc_server.Backlog {
    const io = self.io;
    const gpa = self.gpa;
    const rpc = p.rpc;
    var token: Transport.CancelToken = .{};
    // The connection cancels the request when the client resets the stream or the connection
    // ends. The hook goes before the token does. Before, a second task waited on the stream.
    if (!no_wait) stream.setOnReset(onReset, &token);
    defer if (!no_wait) stream.setOnReset(null, null);
    var deadline_hit: std.atomic.Value(bool) = .init(false);
    var watch: Deadlines.Watch = .{};
    if (p.deadline) |d| if (!no_wait) watch.start(&self.deadlines, io, self.gpa, d, &token, &deadline_hit);
    defer watch.finish(&self.deadlines, io);

    const started = Io.Timestamp.now(io, .awake);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    // The message with its gRPC prefix. It is in `out` or in the cache.
    var framed: []const u8 = undefined;
    // A list result can be the same as a recent one. Then the encoded message is also the same.
    const list = rpc.listKey() != null;
    const first = try runOnce(self, arena, rpc.method(), p.params, &token, p.principal, if (list) rpc else null);
    defer if (first.hit) |h| h.release(gpa);
    if (first.hit) |h| {
        framed = h.framed;
    } else {
        const cache_key: ?[]const u8 = if (list) first.resultText() else null;
        const first_outcome = try first.outcome(arena);
        const one_page = first_outcome == .result and !hasNextPage(first_outcome.result);
        const outcome = try run(self, arena, rpc, first_outcome, p.params, &token, p.principal);
        const result = switch (outcome) {
            .result => |r| r,
            .rpc_error => |e| return endedSend(rpcError(stream, arena, e)),
            .cancelled => {
                const code: status.Code = if (deadline_hit.load(.acquire)) .deadline_exceeded else .cancelled;
                return endedSend(grpc_server.trailersOnly(stream, arena, code, "The request was cancelled", null, null));
            },
        };
        var cx: convert.Context = .{ .arena = arena, .limits = self.options.typed_limits };
        // The JSON text is a good estimate of the size of the message.
        try out.ensureTotalCapacity(gpa, lpm.prefix_len + if (first.frame) |f| f.len else 0);
        _ = try out.addManyAsSlice(gpa, lpm.prefix_len);
        convert.encodeResult(&cx, gpa, &out, rpc, result) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unexpressible, error.Invalid => {
                log.warn("the typed binding cannot express the {s} result: {s}", .{ rpc.method(), cx.reason });
                const message = try std.fmt.allocPrint(arena, "The typed gRPC binding cannot express {s}", .{cx.reason});
                return endedSend(rpcError(stream, arena, errors.internalError(message)));
            },
        };
        lpm.setPrefix(out.items) catch {
            const message = try std.fmt.allocPrint(arena, "The {s} result is too large for one gRPC message", .{rpc.method()});
            return endedSend(rpcError(stream, arena, errors.internalError(message)));
        };
        framed = out.items;
        // Only a result of one page goes in the cache: the key is the text of that page.
        if (cache_key) |key| if (one_page) {
            // Without memory for the copy, the next call encodes the result again.
            self.typed_cache.put(gpa, rpc, key, framed) catch {};
        };
    }
    if (p.cost_slot) |i| self.costs.record(i, grpc_server.nsSince(io, started));
    // The headers, the message and the trailers go out together. See `Stream.cork`.
    stream.cork();
    defer stream.uncork() catch {};
    stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = grpc_server.content_type } }, false) catch return null;
    if (no_wait) {
        lpm.writeFramedNoWait(stream, framed, false) catch |e| switch (e) {
            error.WouldBlock => {
                // A task sends the message and the trailers. The message must live in the
                // call arena.
                var backlog: grpc_server.Backlog = .{ .started = true, .code = .ok };
                try backlog.messages.append(arena, try arena.dupe(u8, framed[lpm.prefix_len..]));
                return backlog;
            },
            else => return null,
        };
    } else {
        lpm.writeFramed(stream, framed, false) catch return null;
    }
    stream.sendHeaders(&.{.{ .name = "grpc-status", .value = status.Code.ok.wire() }}, true) catch return null;
    return null;
}

/// The result of a function that ends the call in `execute`.
fn endedSend(result: anyerror!void) !?grpc_server.Backlog {
    try result;
    return null;
}

fn requestName(rpc: service.Rpc) []const u8 {
    return switch (rpc) {
        .complete => "CompletionRequest",
        inline else => |r| comptime r.rpcName() ++ "Request",
    };
}

/// Add the `_meta` keys that the server engine needs and that a client of the typed binding
/// does not always send. The protocol version comes from `mcp-protocol-version`, else it is
/// the version of this SDK. The client capabilities are empty. Returns a mismatch message
/// when the metadata and `_meta` name different versions.
fn completeMeta(arena: Allocator, params: *Value, header: ?[]const u8) Allocator.Error!?[]const u8 {
    const object = &params.object;
    if (object.getPtr("_meta") == null) try object.put(arena, "_meta", .{ .object = .empty });
    const m = &object.getPtr("_meta").?.object;
    if (m.get(meta.key_protocol_version)) |pv| {
        if (header) |h| if (pv != .string or !std.mem.eql(u8, h, pv.string)) {
            const body = if (pv == .string) pv.string else "?";
            return try std.fmt.allocPrint(arena, "Header mismatch: mcp-protocol-version value '{s}' does not match the _meta value '{s}'", .{ h, body });
        };
    } else {
        try m.put(arena, meta.key_protocol_version, .{ .string = header orelse version.version });
    }
    if (m.get(meta.key_client_capabilities) == null) try m.put(arena, meta.key_client_capabilities, .{ .object = .empty });
    return null;
}

const Outcome = union(enum) {
    result: Value,
    rpc_error: errors.RpcError,
    cancelled,
};

/// True when the list result `r` has a cursor for one more page.
fn hasNextPage(r: Value) bool {
    if (r != .object) return false;
    const next = r.object.get("nextCursor") orelse return false;
    return next == .string and next.string.len > 0;
}

/// Get the pages after the result `first` of a list request and merge them into `first`.
fn run(self: *grpc_server.Server, arena: Allocator, rpc: service.Rpc, first: Outcome, params: Value, token: *Transport.CancelToken, principal: ?*resource_server.Principal) !Outcome {
    const key = rpc.listKey() orelse return first;
    var merged = switch (first) {
        .result => |r| r,
        else => return first,
    };
    if (merged != .object) return first;
    var pages: u32 = 1;
    while (merged.object.get("nextCursor")) |next| {
        if (next != .string or next.string.len == 0) break;
        // The cursor stays in the result, and the conversion refuses it.
        if (pages >= max_list_pages) return .{ .result = merged };
        if (token.isCancelled()) return .cancelled;
        var page_params: std.json.ObjectMap = .empty;
        var it = params.object.iterator();
        while (it.next()) |kv| try page_params.put(arena, kv.key_ptr.*, kv.value_ptr.*);
        try page_params.put(arena, "cursor", next);
        const ran = try runOnce(self, arena, rpc.method(), .{ .object = page_params }, token, principal, null);
        const page = switch (try ran.outcome(arena)) {
            .result => |r| r,
            else => |other| return other,
        };
        pages += 1;
        if (page != .object) return .{ .rpc_error = errors.internalError("A page of the list is not an object") };
        const items = page.object.get(key) orelse Value.null;
        const target = merged.object.getPtr(key);
        if (items == .array and target != null and target.?.* == .array) try target.?.array.appendSlice(items.array.items);
        if (page.object.get("nextCursor")) |n| {
            try merged.object.put(arena, "nextCursor", n);
        } else {
            _ = merged.object.orderedRemove("nextCursor");
        }
    }
    if (merged.object.get("nextCursor")) |n| if (n == .string and n.string.len == 0) {
        _ = merged.object.orderedRemove("nextCursor");
    };
    return .{ .result = merged };
}

/// The final frame of one engine call.
const Ran = struct {
    id: i64,
    /// Null when the engine canceled the request, or when `hit` has the response.
    frame: ?[]const u8,
    /// The encoded response from the cache. The caller releases it.
    hit: ?*ResultCache.Shared = null,

    /// The JSON text of the result, or null when the frame is not a response.
    fn resultText(self: Ran) ?[]const u8 {
        return resultTextOf(self.frame orelse return null, self.id);
    }

    /// Parse the frame.
    fn outcome(self: Ran, arena: Allocator) !Outcome {
        const frame = self.frame orelse return .cancelled;
        const msg = jsonrpc.Message.parse(arena, frame) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .rpc_error = errors.internalError("The server engine wrote a response that is not JSON-RPC") },
        };
        return switch (msg) {
            .response => |r| .{ .result = r.result },
            .error_response => |e| .{ .rpc_error = .{ .code = e.code, .message = e.message, .data = e.data } },
            else => .{ .rpc_error = errors.internalError("The server engine wrote no response") },
        };
    }
};

/// The JSON text of the result in the response `frame` to the request `id`, or null when
/// `frame` is not such a response.
fn resultTextOf(frame: []const u8, id: i64) ?[]const u8 {
    var buf: [64]u8 = undefined;
    const head = std.fmt.bufPrint(&buf, "{{\"jsonrpc\":\"" ++ jsonrpc.message.jsonrpc_version ++ "\",\"id\":{d},\"result\":", .{id}) catch return null;
    const tail = jsonrpc.message.response_tail;
    if (frame.len < head.len + tail.len or !std.mem.startsWith(u8, frame, head) or !std.mem.endsWith(u8, frame, tail)) return null;
    return frame[head.len .. frame.len - tail.len];
}

/// Run one JSON-RPC request through the server engine. With `lookup`, a result that the
/// cache knows gives `Ran.hit` instead of a frame.
fn runOnce(self: *grpc_server.Server, arena: Allocator, method: []const u8, params: Value, token: *Transport.CancelToken, principal: ?*resource_server.Principal, lookup: ?service.Rpc) !Ran {
    const id = next_id.fetchAdd(1, .monotonic);
    if (token.isCancelled()) return .{ .id = id, .frame = null };
    var capture: Capture = .{ .arena = arena, .id = id };
    if (lookup) |rpc| capture.lookup = .{ .cache = &self.typed_cache, .gpa = self.gpa, .rpc = rpc };
    self.server.handle(self.io, .{
        .kind = .grpc,
        .arena = arena,
        .message = .{ .request = .{ .id = .{ .integer = id }, .method = method, .params = params } },
        .responder = .{ .ptr = &capture, .vtable = &capture_vtable },
        .cancel = token,
        .context = principal,
    });
    return .{ .id = id, .frame = capture.frame, .hit = capture.hit };
}

/// The encoded response messages of recent list results. The key is the RPC and the JSON
/// text of the result. The message is a function of that key. Thus an entry never becomes
/// stale, and the cache needs no notice of a change of a list. A changed list result gets a
/// new entry, and the oldest entry goes.
///
/// The cache is lock-free. An entry that leaves its place goes to `retired`, and the cache
/// releases it when no task reads the places. Thus a task can take a reference to an entry
/// that it found in a place. Two calls can put the same result at the same time. Then the
/// cache keeps two copies for a short time.
pub const ResultCache = struct {
    entries: [slots]std.atomic.Value(?*Shared) = @splat(.init(null)),
    /// The place that the next `put` replaces.
    next: std.atomic.Value(usize) = .init(0),
    /// The entries that left their places, with the reference of the cache.
    retired: lockfree.Retired(Shared, "next_retired") = .{},

    /// The count of entries.
    pub const slots = 8;
    /// The largest JSON text that the cache keeps.
    pub const max_key_bytes = 256 * 1024;

    /// One entry. The cache and each call that sends the message have a reference. The
    /// last `release` frees the entry.
    pub const Shared = struct {
        refs: std.atomic.Value(u32) = .init(1),
        rpc: service.Rpc,
        key: []u8,
        /// The message with its gRPC prefix.
        framed: []u8,
        next_retired: ?*Shared = null,

        pub fn release(self: *Shared, gpa: Allocator) void {
            if (self.refs.fetchSub(1, .acq_rel) != 1) return;
            gpa.free(self.key);
            gpa.free(self.framed);
            gpa.destroy(self);
        }
    };

    pub fn deinit(self: *ResultCache, gpa: Allocator) void {
        for (&self.entries) |*e| if (e.load(.acquire)) |s| s.release(gpa);
        self.retired.deinit(gpa, releaseShared);
        self.* = undefined;
    }

    /// The entry in a place for the result text `key` of `rpc`. Call between `retired.enter`
    /// and `retired.leave`.
    fn find(self: *ResultCache, rpc: service.Rpc, key: []const u8) ?*Shared {
        for (&self.entries) |*e| {
            const s = e.load(.seq_cst) orelse continue;
            if (s.rpc == rpc and std.mem.eql(u8, s.key, key)) return s;
        }
        return null;
    }

    fn releaseShared(gpa: Allocator, s: *Shared) void {
        s.release(gpa);
    }

    /// The entry for the result text `key` of `rpc`, or null. Release the entry after use.
    pub fn acquire(self: *ResultCache, gpa: Allocator, rpc: service.Rpc, key: []const u8) ?*Shared {
        if (key.len > max_key_bytes) return null;
        self.retired.enter();
        defer self.retired.leave(gpa, releaseShared);
        const s = self.find(rpc, key) orelse return null;
        _ = s.refs.fetchAdd(1, .monotonic);
        return s;
    }

    /// Keep a copy of the message `framed` for the result text `key` of `rpc`.
    pub fn put(self: *ResultCache, gpa: Allocator, rpc: service.Rpc, key: []const u8, framed: []const u8) Allocator.Error!void {
        if (key.len > max_key_bytes) return;
        {
            self.retired.enter();
            defer self.retired.leave(gpa, releaseShared);
            // Two calls can encode the same result at the same time. The first copy stays.
            if (self.find(rpc, key) != null) return;
        }
        const fresh = try gpa.create(Shared);
        errdefer gpa.destroy(fresh);
        const key_copy = try gpa.dupe(u8, key);
        errdefer gpa.free(key_copy);
        fresh.* = .{ .rpc = rpc, .key = key_copy, .framed = try gpa.dupe(u8, framed) };
        const place = self.next.fetchAdd(1, .monotonic) % slots;
        const old = self.entries[place].swap(fresh, .seq_cst) orelse return;
        self.retired.retire(old, gpa, releaseShared);
    }
};

test "the result cache keeps the newest entries" {
    const gpa = std.testing.allocator;
    var cache: ResultCache = .{};
    defer cache.deinit(gpa);
    try std.testing.expect(cache.acquire(gpa, .list_tools, "{}") == null);
    try cache.put(gpa, .list_tools, "{}", "abc");
    try cache.put(gpa, .list_tools, "{}", "abc");
    const hit = cache.acquire(gpa, .list_tools, "{}").?;
    try std.testing.expectEqualStrings("abc", hit.framed);
    // The key includes the RPC.
    try std.testing.expect(cache.acquire(gpa, .list_prompts, "{}") == null);
    var buf: [8]u8 = undefined;
    for (0..ResultCache.slots) |i| try cache.put(gpa, .list_prompts, try std.fmt.bufPrint(&buf, "{d}", .{i}), "x");
    try std.testing.expect(cache.acquire(gpa, .list_tools, "{}") == null);
    // The entry stays valid until its last reference goes.
    try std.testing.expectEqualStrings("abc", hit.framed);
    hit.release(gpa);
    const last = cache.acquire(gpa, .list_prompts, "7").?;
    defer last.release(gpa);
    try std.testing.expectEqualStrings("x", last.framed);
}

test "the result text of an engine frame" {
    const frame = "{\"jsonrpc\":\"2.0\",\"id\":12,\"result\":{\"tools\":[]}}";
    try std.testing.expectEqualStrings("{\"tools\":[]}", resultTextOf(frame, 12).?);
    try std.testing.expect(resultTextOf(frame, 13) == null);
    try std.testing.expect(resultTextOf("{\"jsonrpc\":\"2.0\",\"id\":12,\"error\":{\"code\":1,\"message\":\"m\"}}", 12) == null);
    const cancelled: Ran = .{ .id = 12, .frame = null };
    try std.testing.expect(cancelled.resultText() == null);
}

/// The responder of one engine call: it keeps the final frame. With `lookup`, it first looks
/// for the result in the cache. A hit needs no copy of the frame.
const Capture = struct {
    arena: Allocator,
    id: i64,
    frame: ?[]const u8 = null,
    lookup: ?struct { cache: *ResultCache, gpa: Allocator, rpc: service.Rpc } = null,
    hit: ?*ResultCache.Shared = null,
};

const capture_vtable: Transport.Responder.VTable = .{
    .notify = captureNotify,
    .finish = captureFinish,
    .abort = captureAbort,
};

/// A unary response has no place for a notification related to the request.
fn captureNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    _ = ptr;
    _ = io;
    _ = frame;
}

fn captureFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    _ = io;
    const c: *Capture = @ptrCast(@alignCast(ptr));
    if (c.frame != null or c.hit != null) return error.Closed;
    if (c.lookup) |l| if (resultTextOf(frame, c.id)) |key| {
        c.hit = l.cache.acquire(l.gpa, l.rpc, key);
        if (c.hit != null) return;
    };
    c.frame = try c.arena.dupe(u8, frame);
}

fn captureAbort(ptr: *anyopaque, io: Io) void {
    _ = ptr;
    _ = io;
}

/// Cancel the request. The connection calls this hook under its lock when the client resets
/// the stream or when the connection ends. The cancel of the token takes no lock.
fn onReset(userdata: ?*anyopaque, stream: *Stream) void {
    const token: *Transport.CancelToken = @ptrCast(@alignCast(userdata.?));
    token.cancel(stream.conn.io, "stream reset");
}

/// End the call with a JSON-RPC error in headers only. The status follows
/// `service.statusForCode`.
pub fn rpcError(stream: *Stream, arena: Allocator, err: errors.RpcError) !void {
    var list: std.ArrayList(Header) = .empty;
    try list.append(arena, .{ .name = ":status", .value = "200" });
    try list.append(arena, .{ .name = "content-type", .value = grpc_server.content_type });
    try list.append(arena, .{ .name = "grpc-status", .value = service.statusForCode(err.code).wire() });
    try list.append(arena, .{ .name = "grpc-message", .value = try status.encodeMessage(arena, service.shorten(err.message, service.max_error_message_bytes)) });
    try list.append(arena, .{ .name = service.header_error_code, .value = try std.fmt.allocPrint(arena, "{d}", .{err.code}) });
    var aw: Io.Writer.Allocating = .init(arena);
    jsonrpc.message.writeErrorResponse(&aw.writer, null, err.toWire()) catch return error.OutOfMemory;
    const encoder = std.base64.standard.Encoder;
    const size = encoder.calcSize(aw.written().len);
    if (size <= service.max_error_bin_bytes) {
        const out = try arena.alloc(u8, size);
        try list.append(arena, .{ .name = service.header_error_bin, .value = encoder.encode(out, aw.written()) });
    }
    try stream.sendHeaders(list.items, true);
}
