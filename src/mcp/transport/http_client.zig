//! The Streamable HTTP client transport. Every request is one `POST` on its own connection.
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
const tool_headers = @import("tool_headers.zig");
const Transport = @import("Transport.zig");
const envelope = @import("envelope.zig");
const sse = @import("sse.zig");
const json = @import("../json.zig");
const methods = @import("../protocol/methods.zig");
const version = @import("../protocol/version.zig");
const message = @import("../jsonrpc/message.zig");
const OAuthClient = @import("../auth/oauth_client.zig").Client;
const auth_common = @import("../auth/common.zig");
const AuthProvider = auth_common.Provider;
const dpop = @import("../auth/dpop.zig");

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
    tool_headers: tool_headers.Map,

    pub const Options = struct {
        url: []const u8,
        /// Headers added to every request, for example `authorization`.
        extra_headers: []const http.Header = &.{},
        max_response_bytes: usize = 4 << 20,
        /// How often a request checks for cancellation and its deadline.
        poll_interval: Io.Duration = .fromMilliseconds(50),
        /// Answers 401 and 403 challenges with OAuth 2.1. Null sends no credentials.
        auth: ?*OAuthClient = null,
        /// Answers 401 and 403 challenges with another flow, for example `ClientCredentials` or
        /// `EnterpriseClient`. It has priority over `auth`.
        auth_provider: ?AuthProvider = null,
        /// The trust policy and identity for `https` URLs. Null uses the system trust store.
        tls: ?http1.TlsSetup = null,
    };

    pub const TlsSetup = http1.TlsSetup;

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
            .tool_headers = .init(gpa, io),
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
        self.tool_headers.deinit();
        self.arena_state.deinit();
        self.gpa.destroy(self);
    }

    /// Open one connection to the server, with TLS for `https`.
    fn open(self: *Client) http1.OpenError!*http1.Connection {
        const secure: ?http1.TlsSetup = if (!self.target.secure) null else self.options.tls orelse .{ .trust = .{ .bundle = &self.system_bundle.? } };
        return http1.Connection.open(self.io, self.gpa, self.target.host, self.target.port, secure);
    }

    pub fn transport(self: *Client) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Transport.ClientTransport.VTable = .{
        .kind = .streamable_http,
        .exchange = exchange,
        .notify = notify,
        .credential = credential,
    };

    /// The bearer token of the auth provider, else the `authorization` header of
    /// `extra_headers`, else null.
    fn credential(ptr: *anyopaque, arena: Allocator) Allocator.Error!?[]const u8 {
        const self: *Client = @ptrCast(@alignCast(ptr));
        if (self.authProvider()) |auth| if (auth.token(arena)) |token| return token;
        for (self.options.extra_headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "authorization")) return h.value;
        return null;
    }

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

    /// Run the `POST` in a task so that cancellation and the deadline can interrupt it.
    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        var task: Task = .{ .client = self, .ex = ex, .arena = arena_state.allocator() };
        var future = io.concurrent(Task.run, .{&task}) catch return self.perform(task.arena, ex);
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
            if (ex.expired(io)) {
                stop = error.Timeout;
                break;
            }
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
        if (self.authProvider()) |auth| if (auth.credentials(arena, "POST", self.url)) |c| {
            try headers.append(arena, .{ .name = "authorization", .value = try c.authorization(arena) });
            if (c.proof) |p| try headers.append(arena, .{ .name = dpop.header_name, .value = p });
        };
        try headers.append(arena, .{ .name = envelope.header_protocol_version, .value = version.version });
        try headers.append(arena, .{ .name = envelope.header_method, .value = method_name });
        for (self.options.extra_headers) |h| try headers.append(arena, h);
    }

    fn authProvider(self: *Client) ?AuthProvider {
        if (self.options.auth_provider) |p| return p;
        if (self.options.auth) |a| return a.provider();
        return null;
    }

    const Challenge = struct {
        status: u16,
        /// The values of all `WWW-Authenticate` headers, joined with a comma.
        www_authenticate: ?[]const u8,
        /// The `DPoP-Nonce` header of the response.
        dpop_nonce: ?[]const u8 = null,
    };

    /// The largest number of new proofs with a new nonce for one request.
    const max_nonce_retries = 2;

    /// Send the request. Answer authorization challenges until the attempt limit.
    fn perform(self: *Client, arena: Allocator, ex: *Transport.Exchange) Transport.ExchangeError!void {
        var attempt: u8 = 0;
        var nonce_retries: u8 = 0;
        while (true) {
            const challenge = (try self.performOnce(arena, ex)) orelse return;
            const auth = self.authProvider() orelse {
                ex.http_status = challenge.status;
                return error.HttpStatus;
            };
            // RFC 9449 section 9: the server wants a proof with its nonce. The token is good,
            // so send the request again with a new proof and do not get a new token.
            if (challenge.dpop_nonce != null and auth.acceptsDpopNonce() and nonce_retries < max_nonce_retries) {
                const parsed = try auth_common.parseChallenge(arena, challenge.www_authenticate orelse "");
                if (parsed.wantsDpopNonce()) {
                    nonce_retries += 1;
                    continue;
                }
            }
            attempt += 1;
            auth.handleChallenge(arena, self.url, challenge.status, challenge.www_authenticate, attempt) catch |e| {
                log.warn("the authorization provider failed for status {d}: {t}", .{ challenge.status, e });
                ex.http_status = challenge.status;
                return error.HttpStatus;
            };
        }
    }

    /// One `POST`. Returns a challenge when the server answered 401 or 403.
    fn performOnce(self: *Client, arena: Allocator, ex: *Transport.Exchange) Transport.ExchangeError!?Challenge {
        const io = self.io;
        var headers: std.ArrayList(http.Header) = .empty;
        try self.standardHeaders(arena, &headers, ex.method);
        self.mirrorHeaders(arena, &headers, ex) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsafeInteger => return error.InvalidRequest,
        };

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
        var nonce: ?[]const u8 = null;
        var www: ?[]const u8 = null;
        var it = response.head.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, dpop.nonce_header_name)) nonce = try arena.dupe(u8, h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) {
                www = if (www) |prev| try std.mem.concat(arena, u8, &.{ prev, ", ", h.value }) else try arena.dupe(u8, h.value);
            }
        }
        // RFC 9449 section 8.2 and 9: a server can give a new nonce with any response.
        if (nonce) |n| if (self.authProvider()) |auth| auth.rememberDpopNonce(self.url, n);
        if (ex.http_status == 401 or ex.http_status == 403) {
            _ = conn.bodyReader(&response).discardRemaining() catch {};
            return .{ .status = ex.http_status, .www_authenticate = www, .dpop_nonce = nonce };
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
            var total: usize = 0;
            while (true) {
                // Take the bytes that arrived, so that each event reaches the sink at once.
                // `readVec` copies the buffered bytes and then waits to fill the rest of its
                // buffer. That holds back an event until more bytes come.
                if (body.bufferedLen() == 0) body.fillMore() catch |e| switch (e) {
                    error.EndOfStream => break,
                    error.ReadFailed => return error.ReadFailed,
                };
                const bytes = body.buffered();
                body.tossBuffered();
                total += bytes.len;
                if (total > self.options.max_response_bytes) return error.ReadFailed;
                try parser.feed(bytes);
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
    fn mirrorHeaders(self: *Client, arena: Allocator, headers: *std.ArrayList(http.Header), ex: *Transport.Exchange) tool_headers.Map.AppendError!void {
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
        try self.tool_headers.appendParamHeaders(arena, headers, tool_name, arguments, false);
    }

    /// Hand a frame to the sink. First, the transport scans a `tools/list` result for header
    /// annotations and removes the tools with invalid annotations.
    fn deliver(self: *Client, io: Io, arena: Allocator, ex: *Transport.Exchange, frame: []const u8) Transport.ExchangeError!void {
        var out = frame;
        if (std.mem.eql(u8, ex.method, "tools/list")) {
            if (self.tool_headers.learn(arena, frame) catch null) |rewritten| out = rewritten;
        }
        ex.deliver(io, out) catch return error.InvalidFrame;
    }
};
