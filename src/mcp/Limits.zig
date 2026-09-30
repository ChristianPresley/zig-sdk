//! Size, count and time limits with their defaults. Every field has one documented overflow
//! behaviour and one test.
const std = @import("std");
const Io = std.Io;

const Limits = @This();

/// Maximum JSON nesting depth of an inbound message. Overflow: `-32700`.
json_max_depth: u16 = 64,

stdio: struct {
    /// Maximum bytes of one newline-delimited message. Overflow: the frame is dropped and,
    /// when the request id can be recovered, `-32600` is returned.
    max_line_bytes: usize = 16 << 20,
    /// Buffer used by the line reader. Longer lines fall back to a growing buffer.
    read_buffer: usize = 64 << 10,
} = .{},

http: struct {
    /// Maximum request body bytes. Overflow: HTTP 413.
    max_body_bytes: usize = 4 << 20,
    /// Maximum request head bytes. Overflow: HTTP 431.
    max_head_bytes: usize = 16 << 10,
    /// Maximum open connections. Overflow: the accept loop waits.
    max_connections: u32 = 256,
    reuse_address: bool = false,
    idle_timeout: Io.Duration = .fromSeconds(60),
    head_timeout: Io.Duration = .fromSeconds(10),
    sse_keepalive: Io.Duration = .fromSeconds(15),
    listen_ack_timeout: Io.Duration = .fromSeconds(10),
    max_redirect_hops: u8 = 3,
} = .{},

/// Maximum requests processed at the same time per transport. Overflow: the reader waits.
max_in_flight_requests: u32 = 256,
/// Maximum concurrent `subscriptions/listen` streams. Overflow: `-32603`.
max_listen_subscriptions: u32 = 1024,
/// Maximum URIs in one `resourceSubscriptions` filter. Overflow: `-32603`.
max_resource_subscription_uris: u32 = 1024,
/// Maximum serialized bytes of a subscription filter. Overflow: `-32603`.
max_filter_bytes: usize = 64 << 10,
/// Maximum progress notifications per second per request. Overflow: dropped.
max_progress_rate_per_s: u32 = 50,
request_timeout: Io.Duration = .fromSeconds(60),
max_total_timeout: Io.Duration = .fromSeconds(600),
shutdown_grace: Io.Duration = .fromSeconds(2),
cancel_notify_timeout: Io.Duration = .fromSeconds(5),
request_state_ttl: Io.Duration = .fromSeconds(600),
page_size: u32 = 100,
max_auto_pages: u32 = 64,
completion_max_values: u32 = 100,
mrtr_max_rounds_client: u8 = 10,
max_step_up_attempts: u8 = 3,

schema: struct {
    max_depth: u16 = 32,
    max_subschemas: u32 = 4096,
    max_ref_hops: u16 = 64,
    max_errors: u16 = 32,
    eval_budget: u32 = 100_000,
} = .{},

uri_template: struct {
    max_template_bytes: usize = 64 << 10,
    max_expressions: u16 = 256,
    max_uri_bytes: usize = 64 << 10,
} = .{},

pub const default: Limits = .{};

test "defaults are sane" {
    const l: Limits = .{};
    try std.testing.expect(l.stdio.max_line_bytes > l.http.max_body_bytes);
    try std.testing.expectEqual(64, l.json_max_depth);
}
