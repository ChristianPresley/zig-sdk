//! Size, count and time limits with their defaults. The doc comment of each limit gives the
//! behavior at overflow, and a test examines that behavior.
const std = @import("std");
const Io = std.Io;

const Limits = @This();

/// Maximum JSON nesting depth of an inbound message. The message object is level 1, thus
/// `params` is level 2. The servers of all transports and the client check the depth before
/// they parse a message, without recursion. A value above `json.max_message_depth` (200)
/// counts as that value. Overflow: the server answers with `-32700` and a null id. On the
/// client, the request of the message fails with `error.InvalidResponse`, and the client
/// drops a notification that belongs to no request.
json_max_depth: u16 = 64,

stdio: struct {
    /// Maximum bytes of one newline-delimited message. Overflow: the transport drops the line
    /// and logs a warning. On the client, the request with the top-level "id" of the line then
    /// fails with `error.InvalidResponse`. The limit also applies to the Unix socket transport.
    max_line_bytes: usize = 16 << 20,
    /// Buffer of the line reader. For a longer line, the reader uses a buffer that grows.
    read_buffer: usize = 64 << 10,
} = .{},

unix_socket: struct {
    /// Maximum open connections of the Unix socket server. Overflow: the server closes the
    /// new connection at once.
    max_connections: u32 = 64,
} = .{},

/// Limits of the WebSocket transport. The server and the client obey the size and time
/// limits. The upgrade request obeys `http.max_head_bytes`.
websocket: struct {
    /// Maximum bytes of one message after the join of its fragments. Overflow: the endpoint
    /// closes the connection with the code 1009.
    max_message_bytes: usize = 4 << 20,
    /// Maximum payload bytes of one frame. Overflow: the endpoint closes the connection with
    /// the code 1009.
    max_frame_bytes: usize = 4 << 20,
    /// Maximum open connections of the WebSocket server, with the connections that are in
    /// the handshake. Overflow: the server closes the new connection at once.
    max_connections: u32 = 256,
    /// Maximum requests in flight on one connection. Overflow: the server answers the new
    /// request with the error `-32603`, and the connection stays open.
    max_in_flight_requests: u32 = 256,
    /// An endpoint sends a ping when no frame came from the peer for this time. Zero
    /// disables the pings.
    ping_interval: Io.Duration = .fromSeconds(30),
    /// An endpoint closes the connection with the code 1001 when no frame came from the peer
    /// for this time. Zero disables the timeout.
    idle_timeout: Io.Duration = .fromSeconds(90),
    /// The time for the TLS handshake and the upgrade request of a new connection.
    /// Overflow: the server closes the connection without a response.
    handshake_timeout: Io.Duration = .fromSeconds(10),
} = .{},

http: struct {
    /// Maximum request body bytes. Overflow: HTTP 413.
    max_body_bytes: usize = 4 << 20,
    /// Maximum request head bytes. Overflow: HTTP 431.
    max_head_bytes: usize = 16 << 10,
    /// Maximum open connections. Overflow: the accept loop waits.
    max_connections: u32 = 256,
    /// Set `SO_REUSEADDR` on the listen socket of the HTTP and WebSocket servers.
    reuse_address: bool = false,
    /// The time that the server waits for the next request on a keep-alive connection. It is
    /// also the time for the body of a request after its head. Zero disables the limit. Overflow: the server closes an idle connection without a
    /// response, and answers a late body with HTTP 408.
    idle_timeout: Io.Duration = .fromSeconds(60),
    /// The time for the head of a request, from its first byte. For the first request of a
    /// connection, the time starts at the accept and includes the TLS handshake. Zero
    /// disables the limit. Overflow: HTTP 408, and the server closes the connection.
    head_timeout: Io.Duration = .fromSeconds(10),
    /// The interval of the SSE comments that keep a listen stream open.
    sse_keepalive: Io.Duration = .fromSeconds(15),
    /// Maximum redirects of one icon fetch. Overflow: `error.TooManyRedirects`.
    max_redirect_hops: u8 = 3,
} = .{},

/// Maximum requests processed at the same time per transport. Overflow: the reader waits.
max_in_flight_requests: u32 = 256,
/// Maximum concurrent `subscriptions/listen` streams. Overflow: `-32603`.
max_listen_subscriptions: u32 = 1024,
/// Maximum URIs in one `resourceSubscriptions` filter. Overflow: `-32603`.
max_resource_subscription_uris: u32 = 1024,
/// Maximum bytes of the `notifications` filter of `subscriptions/listen` as compact JSON.
/// Overflow: `-32603`.
max_filter_bytes: usize = 64 << 10,
/// Maximum progress notifications per second per request, on the server and on the client.
/// Overflow: the server does not send the notification, and the client does not give it to
/// `RequestOptions.on_progress`.
max_progress_rate_per_s: u32 = 50,
/// The timeout of a client request without `RequestOptions.timeout`. A listen stream has no
/// default timeout. Overflow: the client cancels the request and returns `error.Timeout`.
request_timeout: Io.Duration = .fromSeconds(60),
/// The upper limit of the timeout of a client request without
/// `RequestOptions.max_total_timeout`. Progress notifications do not extend a timeout.
/// Overflow: the client cancels the request and returns `error.Timeout`.
max_total_timeout: Io.Duration = .fromSeconds(600),
/// The time that the requests in flight get to end at a shutdown or at the end of a
/// connection. Overflow: the transport cancels them.
shutdown_grace: Io.Duration = .fromSeconds(2),
/// How often the client re-issues a request after it lost the stream before any response
/// byte. The client retries only idempotent methods, unless the caller forces it.
max_lost_stream_retries: u32 = 3,
/// The time that the client waits for `notifications/subscriptions/acknowledged`, the first
/// message of a `subscriptions/listen` stream, from the start of the request. Zero disables
/// the limit. Overflow: the client cancels the stream and returns `error.Timeout`.
listen_ack_timeout: Io.Duration = .fromSeconds(10),
/// The lifetime of a `requestState` that the server seals. Overflow: `-32602` with the
/// reason `invalid_request_state`.
request_state_ttl: Io.Duration = .fromSeconds(600),
/// Maximum entries in one page of a list result. Overflow: the result has a `nextCursor`.
page_size: u32 = 100,
/// Maximum pages that the client reads in one automatic list refresh, for example the
/// `tools/list` refresh after a `-32020` error. Overflow: the client stops the refresh.
max_auto_pages: u32 = 64,
/// Maximum values of one completion result. Overflow: the server sends the first values
/// and sets `hasMore`.
completion_max_values: u32 = 100,
/// Maximum multi round-trip rounds of one client request. Overflow:
/// `error.TooManyRounds`.
mrtr_max_rounds_client: u8 = 10,

/// Rate limits of the server for each caller. All limits are off by default.
rate_limits: RateLimits = .{},

schema: Schema = .{},

/// Limits of one skill of the Skills extension. The defaults are the limits of the extension.
/// A server rejects a larger skill at registration with `error.SkillTooLarge`. A client
/// rejects a larger entry in `skills.validateEntry`. A host must accept skills up to the
/// limits of the extension, thus a client can raise these values but must not lower them.
skills: struct {
    /// Maximum files in one skill, `SKILL.md` included.
    max_files: u32 = 512,
    /// Maximum sum of the file sizes of one skill, in bytes.
    max_bytes: u64 = 16 << 20,
} = .{},
/// Limits of the client icon fetcher and the icon checks.
icon: Icon = .{},

uri_template: struct {
    /// Maximum length of one URI template in bytes. Overflow: the registration fails.
    max_template_bytes: usize = 64 << 10,
    /// Maximum expressions in one template. Overflow: the registration fails.
    max_expressions: u16 = 256,
    /// Maximum length in bytes of a URI that the server matches against its templates. A
    /// longer URI matches no template: `resources/read` gives the error "resource not found",
    /// and a completion reference to it is invalid.
    max_uri_bytes: usize = 64 << 10,
} = .{},

/// The rate of a token bucket. The bucket gets `count` tokens in each `period` at an even rate
/// and holds at most `burst` tokens. Each event takes one token. A new bucket is full.
pub const Rate = struct {
    /// Tokens in each period. Zero disables the limit.
    count: u32 = 0,
    period: Io.Duration = .fromSeconds(1),
    /// The maximum tokens in the bucket, thus the largest burst. Zero means `count`.
    burst: u32 = 0,

    /// True when the rate limits events.
    pub fn enabled(self: Rate) bool {
        return self.count > 0;
    }

    /// The period in nanoseconds, from 1 to the maximum of `u64`.
    pub fn periodNs(self: Rate) u64 {
        const ns = self.period.nanoseconds;
        if (ns <= 0) return 1;
        return std.math.cast(u64, ns) orelse std.math.maxInt(u64);
    }

    /// The maximum tokens in the bucket.
    pub fn capacity(self: Rate) u32 {
        return if (self.burst > 0) self.burst else self.count;
    }
};

/// The rate limits of the server. A limit applies to each caller.
///
/// The caller of a request is the authorization principal: the issuer, the subject and the
/// client of the token. A request without a principal has the IP address of the client as its
/// caller on HTTP, gRPC and WebSocket. The server counts all IPv6 addresses of one /64
/// network as one caller. On stdio and on a Unix socket, the caller is the connection.
/// Requests from a transport without this data share one caller.
pub const RateLimits = struct {
    /// `tools/call` requests of one caller. `ToolDef.rate_limit` replaces this rate for one
    /// tool. Each round of a multi round-trip call counts. Overflow: `-31429` with
    /// `data.retryAfterMs`. On HTTP with a JSON response, also status 429 with `Retry-After`.
    tool_calls: Rate = .{},
    /// `tools/call` requests of all callers together. A call that this limit refuses does not
    /// use a token of its caller. Overflow: the same as `tool_calls`.
    tool_calls_total: Rate = .{},
    /// `notifications/message` of one caller. Overflow: the server drops the message and
    /// counts it. Before the next message that the bucket of the caller admits, the server
    /// sends one summary message with the count.
    log_messages: Rate = .{},
    /// Maximum buckets for the tool calls, and also for the log messages. A caller has one
    /// bucket, plus one bucket for each tool with `ToolDef.rate_limit` that it calls.
    /// Overflow: the server forgets the bucket that it used least recently. The next request
    /// of that caller gets a full bucket.
    max_callers: u32 = 4096,
};

/// Limits of the JSON Schema validator.
pub const Schema = struct {
    /// Maximum nesting depth of a schema and of a validated instance. Overflow: the server
    /// rejects the schema at registration, or the instance is invalid.
    max_depth: u16 = 32,
    /// Maximum subschema objects in one schema. Overflow: rejected at registration.
    max_subschemas: u32 = 4096,
    /// Maximum `$ref` follows that do not use instance depth. Overflow: the instance is
    /// invalid.
    max_ref_hops: u16 = 64,
    /// Maximum failures that one validation records. Overflow: the report stops at the limit.
    max_errors: u16 = 32,
    /// Maximum subschema evaluations per validation. The set of evaluated locations for
    /// `unevaluatedProperties` and `unevaluatedItems` also costs one unit per 64 locations.
    /// Overflow: the instance is invalid.
    eval_budget: u32 = 100_000,
    /// Maximum bytes of one regular expression in `pattern` or in a `patternProperties` key.
    /// Overflow: registration rejects the schema.
    max_pattern_bytes: u32 = 4096,
    /// Maximum instructions of one compiled regular expression. A counted repetition
    /// multiplies the size of its operand. The match time is linear in the input length
    /// multiplied by this size. Overflow: registration rejects the schema.
    max_regex_states: u32 = 4096,
};

/// Limits of the client icon fetcher and the icon checks.
pub const Icon = struct {
    /// Maximum bytes of one icon image, after the decoding of a `data:` URI. Overflow:
    /// `error.TooLarge`, and the fetcher stops the read.
    max_bytes: usize = 1 << 20,
    /// Maximum width and maximum height in pixels that the image header can declare.
    /// Overflow: `error.DimensionsTooLarge`.
    max_dimension: u32 = 4096,
    /// Maximum time for one fetch, redirects included. Overflow: `error.Timeout`.
    timeout: Io.Duration = .fromSeconds(10),
};

pub const default: Limits = .{};

test "defaults are sane" {
    const l: Limits = .{};
    try std.testing.expect(l.stdio.max_line_bytes > l.http.max_body_bytes);
    try std.testing.expectEqual(64, l.json_max_depth);
    // A peer that answers each ping never reaches the idle timeout.
    try std.testing.expect(l.websocket.idle_timeout.nanoseconds > 2 * l.websocket.ping_interval.nanoseconds);
    try std.testing.expect(l.websocket.max_frame_bytes <= l.websocket.max_message_bytes);
}

test "rate limits are off by default" {
    const l: Limits = .{};
    try std.testing.expect(!l.rate_limits.tool_calls.enabled());
    try std.testing.expect(!l.rate_limits.tool_calls_total.enabled());
    try std.testing.expect(!l.rate_limits.log_messages.enabled());
    try std.testing.expectEqual(4096, l.rate_limits.max_callers);
    // A rate without a burst holds `count` tokens. A period of zero counts as 1 ns.
    const r: Rate = .{ .count = 5, .period = .fromSeconds(0) };
    try std.testing.expectEqual(5, r.capacity());
    try std.testing.expectEqual(1, r.periodNs());
}

test "skill limits are the limits of the extension" {
    const skills = @import("protocol/skills.zig");
    const l: Limits = .{};
    try std.testing.expectEqual(skills.max_files_per_skill, l.skills.max_files);
    try std.testing.expectEqual(skills.max_bytes_per_skill, l.skills.max_bytes);
}
