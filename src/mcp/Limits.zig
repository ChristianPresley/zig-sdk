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

unix_socket: struct {
    /// Maximum open connections of the Unix socket server. Overflow: the server closes the
    /// new connection at once.
    max_connections: u32 = 64,
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
/// How often the client re-issues a request after it lost the stream before any response
/// byte. Only idempotent methods are retried unless the caller forces it.
max_lost_stream_retries: u32 = 3,
cancel_notify_timeout: Io.Duration = .fromSeconds(5),
request_state_ttl: Io.Duration = .fromSeconds(600),
page_size: u32 = 100,
max_auto_pages: u32 = 64,
completion_max_values: u32 = 100,
mrtr_max_rounds_client: u8 = 10,
max_step_up_attempts: u8 = 3,

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
    max_template_bytes: usize = 64 << 10,
    max_expressions: u16 = 256,
    max_uri_bytes: usize = 64 << 10,
} = .{},

/// Limits of the JSON Schema validator.
pub const Schema = struct {
    /// Maximum nesting depth of a schema and of a validated instance. Overflow: the schema
    /// is rejected at registration, or the instance is invalid.
    max_depth: u16 = 32,
    /// Maximum subschema objects in one schema. Overflow: rejected at registration.
    max_subschemas: u32 = 4096,
    /// Maximum `$ref` follows without consuming instance depth. Overflow: the instance is
    /// invalid.
    max_ref_hops: u16 = 64,
    /// Maximum failures recorded per validation. Overflow: the report is truncated.
    max_errors: u16 = 32,
    /// Maximum subschema evaluations per validation. Overflow: the instance is invalid.
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
}

test "skill limits are the limits of the extension" {
    const skills = @import("protocol/skills.zig");
    const l: Limits = .{};
    try std.testing.expectEqual(skills.max_files_per_skill, l.skills.max_files);
    try std.testing.expectEqual(skills.max_bytes_per_skill, l.skills.max_bytes);
}
