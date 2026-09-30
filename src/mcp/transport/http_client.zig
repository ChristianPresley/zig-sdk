//! The Streamable HTTP client transport. Every request is one POST on its own connection.
//! The response is either one JSON message or an SSE stream of messages. The transport
//! mirrors the request into the `Mcp-*` headers, learns `x-mcp-header` annotations from
//! `tools/list` results, and drops tools whose annotations are invalid. HTTPS uses the
//! SDK TLS client.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;
const http1 = @import("http1.zig");
const Transport = @import("Transport.zig");
const envelope = @import("envelope.zig");
const sse = @import("sse.zig");
const json = @import("../json.zig");
const methods = @import("../protocol/methods.zig");
const version = @import("../protocol/version.zig");
const message = @import("../jsonrpc/message.zig");
const OAuthClient = @import("../auth/oauth_client.zig").Client;

const log = std.log.scoped(.mcp_http_client);

pub const Client = struct {
    io: Io,
    gpa: Allocator,
    /// Owns `url` and the parsed target.
    arena_state: std.heap.ArenaAllocator,
    url: []u8,
    target: http1.Target,
    options: Options,
    /// The system trust store, loaded for `https` URLs without an explicit `tls` option.
    system_bundle: ?std.crypto.Certificate.Bundle = null,
    tool_headers: std.StringHashMapUnmanaged(ToolHeaders) = .empty,
    tool_headers_lock: Io.Mutex = .init,

    pub const Options = struct {
        url: []const u8,
        /// Headers added to every request, for example `authorization`.
        extra_headers: []const http.Header = &.{},
        max_response_bytes: usize = 4 << 20,
        /// How often a request checks for cancellation and its deadline.
        poll_interval: Io.Duration = .fromMilliseconds(50),
        /// Answers 401 and 403 challenges with OAuth 2.1. Null sends no credentials.
        auth: ?*OAuthClient = null,
        /// The trust policy and identity for `https` URLs. Null uses the system trust store.
        tls: ?http1.TlsSetup = null,
    };

    pub const TlsSetup = http1.TlsSetup;

    const Binding = struct { param: []u8, header: []u8 };
    const ToolHeaders = struct { name: []u8, bindings: []Binding };

    pub const InitError = error{ OutOfMemory, InvalidUrl, TrustStoreUnavailable };

    pub fn init(io: Io, gpa: Allocator, options: Options) InitError!*Client {
        const self = try gpa.create(Client);
        errdefer gpa.destroy(self);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .arena_state = .init(gpa),
            .url = undefined,
            .target = undefined,
            .options = options,
        };
        errdefer self.arena_state.deinit();
        const arena = self.arena_state.allocator();
        self.url = try arena.dupe(u8, options.url);
        self.target = try http1.Target.parse(arena, self.url);
        if (self.target.secure and options.tls == null) {
            var bundle: std.crypto.Certificate.Bundle = .empty;
            errdefer bundle.deinit(gpa);
            bundle.rescan(gpa, io, Io.Clock.real.now(io)) catch return error.TrustStoreUnavailable;
            self.system_bundle = bundle;
        }
        return self;
    }

    pub fn deinit(self: *Client) void {
        if (self.system_bundle) |*b| b.deinit(self.gpa);
        var it = self.tool_headers.valueIterator();
        while (it.next()) |th| self.freeToolHeaders(th.*);
        self.tool_headers.deinit(self.gpa);
        self.arena_state.deinit();
        self.gpa.destroy(self);
    }

    /// Open one connection to the server, with TLS for `https`.
    fn open(self: *Client) http1.OpenError!*http1.Connection {
        const secure: ?http1.TlsSetup = if (!self.target.secure) null else self.options.tls orelse .{ .trust = .{ .bundle = &self.system_bundle.? } };
        return http1.Connection.open(self.io, self.gpa, self.target.host, self.target.port, secure);
    }

    fn freeToolHeaders(self: *Client, th: ToolHeaders) void {
        for (th.bindings) |b| {
            self.gpa.free(b.param);
            self.gpa.free(b.header);
        }
        self.gpa.free(th.bindings);
        self.gpa.free(th.name);
    }

    pub fn transport(self: *Client) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{
        .kind = .streamable_http,
        .exchange = exchange,
        .notify = notify,
    };

    const Task = struct {
        client: *Client,
        ex: *Transport.Exchange,
        arena: Allocator,
        done: Io.Event = .unset,
        result: Transport.ExchangeError!void = {},

        fn run(t: *Task) void {
            t.result = t.client.perform(t.arena, t.ex);
            t.done.set(t.client.io);
        }
    };

    /// Run the POST in a task so that cancellation and the deadline can interrupt it.
    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        var task: Task = .{ .client = self, .ex = ex, .arena = arena_state.allocator() };
        var future = io.concurrent(Task.run, .{&task}) catch return self.perform(task.arena, ex);
        const deadline = ex.timeout.toTimestamp(io);
        var stop: ?Transport.ExchangeError = null;
        while (true) {
            task.done.waitTimeout(io, .{ .duration = .{ .raw = self.options.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => {
                    stop = error.Canceled;
                    break;
                },
            };
            if (task.done.isSet()) break;
            if (ex.cancel.isCancelled()) {
                stop = error.Canceled;
                break;
            }
            if (deadline) |d| if (Io.Clock.Timestamp.now(io, d.clock).durationTo(d).raw.nanoseconds <= 0) {
                stop = error.Timeout;
                break;
            };
        }
        if (stop) |err| {
            _ = future.cancel(io);
            return err;
        }
        future.await(io);
        return task.result;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = io;
        const self: *Client = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const msg = message.Message.parse(arena, frame) catch return error.WriteFailed;
        const method_name = msg.method() orelse return error.WriteFailed;
        var headers: std.ArrayList(http.Header) = .empty;
        try self.standardHeaders(arena, &headers, method_name);
        const conn = self.open() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.WriteFailed,
        };
        defer conn.close();
        conn.send("POST", self.target.path, self.target.host_header, headers.items, frame) catch return error.WriteFailed;
        const response = conn.receiveHead() catch return error.WriteFailed;
        if (response.head.status != .accepted) return error.WriteFailed;
        _ = conn.bodyReader(&response).discardRemaining() catch {};
    }

    fn standardHeaders(self: *Client, arena: Allocator, headers: *std.ArrayList(http.Header), method_name: []const u8) Allocator.Error!void {
        try headers.append(arena, .{ .name = "accept", .value = "application/json, text/event-stream" });
        try headers.append(arena, .{ .name = "content-type", .value = "application/json" });
        try headers.append(arena, .{ .name = "accept-encoding", .value = "identity" });
        if (self.options.auth) |auth| if (auth.currentToken()) |token| {
            try headers.append(arena, .{ .name = "authorization", .value = try std.mem.concat(arena, u8, &.{ "Bearer ", token }) });
        };
        try headers.append(arena, .{ .name = envelope.header_protocol_version, .value = version.version });
        try headers.append(arena, .{ .name = envelope.header_method, .value = method_name });
        for (self.options.extra_headers) |h| try headers.append(arena, h);
    }

    const Challenge = struct { status: u16, www_authenticate: ?[]const u8 };

    /// Send the request, answering authorization challenges until the attempt limit.
    fn perform(self: *Client, arena: Allocator, ex: *Transport.Exchange) Transport.ExchangeError!void {
        var attempt: u8 = 0;
        while (true) {
            const challenge = (try self.performOnce(arena, ex)) orelse return;
            const auth = self.options.auth orelse {
                ex.http_status = challenge.status;
                return error.HttpStatus;
            };
            attempt += 1;
            _ = auth.handleChallenge(arena, self.url, challenge.status, challenge.www_authenticate, attempt) catch {
                ex.http_status = challenge.status;
                return error.HttpStatus;
            };
        }
    }

    /// One POST. Returns a challenge when the server answered 401 or 403.
    fn performOnce(self: *Client, arena: Allocator, ex: *Transport.Exchange) Transport.ExchangeError!?Challenge {
        const io = self.io;
        var headers: std.ArrayList(http.Header) = .empty;
        try self.standardHeaders(arena, &headers, ex.method);
        try self.mirrorHeaders(arena, &headers, ex);

        const conn = self.open() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            error.TlsFailed => {
                log.warn("TLS handshake with {s} failed", .{self.target.host});
                return error.WriteFailed;
            },
            error.ConnectFailed => return error.WriteFailed,
        };
        defer conn.close();
        conn.send("POST", self.target.path, self.target.host_header, headers.items, ex.frame) catch return error.WriteFailed;
        const response = conn.receiveHead() catch return error.ReadFailed;
        ex.http_status = @intFromEnum(response.head.status);
        if (ex.http_status == 401 or ex.http_status == 403) {
            var www: ?[]const u8 = null;
            var it = response.head.iterateHeaders();
            while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) {
                www = try arena.dupe(u8, h.value);
            };
            _ = conn.bodyReader(&response).discardRemaining() catch {};
            return .{ .status = ex.http_status, .www_authenticate = www };
        }
        const content_type = response.head.content_type orelse "";
        const is_json = std.ascii.startsWithIgnoreCase(content_type, "application/json");
        const is_sse = std.ascii.startsWithIgnoreCase(content_type, sse.content_type);
        const body = conn.bodyReader(&response);
        if (is_json) {
            const text = body.allocRemaining(arena, .limited(self.options.max_response_bytes)) catch return error.ReadFailed;
            try self.deliver(io, arena, ex, text);
            return null;
        }
        if (is_sse) {
            var parser: sse.Parser = .init(self.gpa);
            defer parser.deinit();
            var chunk: [4096]u8 = undefined;
            var total: usize = 0;
            while (true) {
                const n = body.readSliceShort(&chunk) catch return error.ReadFailed;
                if (n == 0) break;
                total += n;
                if (total > self.options.max_response_bytes) return error.ReadFailed;
                try parser.feed(chunk[0..n]);
                while (parser.next()) |event| {
                    defer parser.release(event);
                    try self.deliver(io, arena, ex, event.data);
                }
            }
            return null;
        }
        _ = body.discardRemaining() catch {};
        return error.HttpStatus;
    }

    /// Add `Mcp-Name` and the `Mcp-Param-*` headers the request needs.
    fn mirrorHeaders(self: *Client, arena: Allocator, headers: *std.ArrayList(http.Header), ex: *Transport.Exchange) Allocator.Error!void {
        const params = ex.params orelse return;
        if (params != .object) return;
        const method = methods.Method.fromName(ex.method) orelse {
            if (envelope.isTaskMethod(ex.method)) if (json.getString(params, "taskId")) |value| {
                try headers.append(arena, .{ .name = envelope.header_name, .value = try envelope.encodeValue(arena, value) });
            };
            return;
        };
        const name_key: ?[]const u8 = switch (method.headerNameSource()) {
            .none => null,
            .name => "name",
            .uri => "uri",
            .task_id => "taskId",
        };
        if (name_key) |key| if (json.getString(params, key)) |value| {
            try headers.append(arena, .{ .name = envelope.header_name, .value = try envelope.encodeValue(arena, value) });
        };
        if (method != .@"tools/call") return;
        const tool_name = json.getString(params, "name") orelse return;
        const arguments = params.object.get("arguments") orelse return;
        if (arguments != .object) return;
        self.tool_headers_lock.lockUncancelable(self.io);
        defer self.tool_headers_lock.unlock(self.io);
        const th = self.tool_headers.get(tool_name) orelse return;
        for (th.bindings) |b| {
            const value = arguments.object.get(b.param) orelse continue;
            const encoded = (try envelope.encodeParam(arena, value)) orelse continue;
            const header_name = try std.mem.concat(arena, u8, &.{ envelope.header_param_prefix, b.header });
            try headers.append(arena, .{ .name = header_name, .value = encoded });
        }
    }

    /// Hand a frame to the sink. A `tools/list` result is scanned for header annotations
    /// first, and tools with invalid annotations are removed from it.
    fn deliver(self: *Client, io: Io, arena: Allocator, ex: *Transport.Exchange, frame: []const u8) Transport.ExchangeError!void {
        var out = frame;
        if (std.mem.eql(u8, ex.method, "tools/list")) {
            if (self.learnToolHeaders(arena, frame) catch null) |rewritten| out = rewritten;
        }
        ex.sink.deliver(io, out) catch return error.InvalidFrame;
    }

    /// Returns a rewritten frame when tools were removed, else null.
    fn learnToolHeaders(self: *Client, arena: Allocator, frame: []const u8) !?[]const u8 {
        var tree = try json.parseTree(arena, frame);
        if (tree != .object) return null;
        const result = tree.object.get("result") orelse return null;
        if (result != .object) return null;
        const tools = result.object.get("tools") orelse return null;
        if (tools != .array) return null;
        var kept: std.json.Array = .init(arena);
        var removed = false;
        for (tools.array.items) |tool| {
            if (tool != .object) continue;
            const name = json.getString(tool, "name") orelse continue;
            const schema = tool.object.get("inputSchema") orelse .null;
            if (!envelope.schemaHeadersValid(schema)) {
                removed = true;
                continue;
            }
            try self.storeBindings(name, schema);
            try kept.append(tool);
        }
        if (!removed) return null;
        var new_result = result;
        try new_result.object.put(arena, "tools", .{ .array = kept });
        try tree.object.put(arena, "result", new_result);
        return try json.writeAlloc(arena, tree);
    }

    fn storeBindings(self: *Client, name: []const u8, schema: Value) !void {
        var bindings: std.ArrayList(Binding) = .empty;
        errdefer {
            for (bindings.items) |b| {
                self.gpa.free(b.param);
                self.gpa.free(b.header);
            }
            bindings.deinit(self.gpa);
        }
        if (schema == .object) if (schema.object.get("properties")) |props| if (props == .object) {
            var it = props.object.iterator();
            while (it.next()) |kv| {
                const prop = kv.value_ptr.*;
                if (prop != .object) continue;
                const header = json.getString(prop, "x-mcp-header") orelse continue;
                try bindings.append(self.gpa, .{
                    .param = try self.gpa.dupe(u8, kv.key_ptr.*),
                    .header = try self.gpa.dupe(u8, header),
                });
            }
        };
        const th: ToolHeaders = .{ .name = try self.gpa.dupe(u8, name), .bindings = try bindings.toOwnedSlice(self.gpa) };
        self.tool_headers_lock.lockUncancelable(self.io);
        defer self.tool_headers_lock.unlock(self.io);
        if (self.tool_headers.fetchRemove(name)) |old| self.freeToolHeaders(old.value);
        self.tool_headers.put(self.gpa, th.name, th) catch |e| {
            self.freeToolHeaders(th);
            return e;
        };
    }
};
