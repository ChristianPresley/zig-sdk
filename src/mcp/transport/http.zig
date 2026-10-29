//! The Streamable HTTP transport (server side): one `POST` endpoint, JSON or SSE responses,
//! long-lived listen streams, header mirroring, `Origin` and `Host` validation.
//!
//! A plaintext server has shards. Each shard is one task that owns its connections from the
//! accept to the close. The shard waits for their bytes in its own poller, and reads each
//! request without a wait. It runs a quick request itself, and sends the response without a
//! wait. It also watches the time limits. Only the shard changes the state of its
//! connections.
//!
//! A request that is not quick runs in a worker task. The shard gives the task the complete
//! request, and the task gives the connection back through the inbox of the shard. The
//! accept loop gives a new connection to a shard through the same inbox. The inbox is a
//! lock-free queue, and a wake of the poller follows each push. A TLS connection has one task
//! of its own.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const http = std.http;

const Transport = @import("Transport.zig");
const envelope = @import("envelope.zig");
const tls = @import("../../tls/tls.zig");
const resource_server = @import("../auth/resource_server.zig");
const sse = @import("sse.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;
const message = @import("../jsonrpc/message.zig");
const json = @import("../json.zig");
const types = @import("../protocol/types.zig");
const errors = @import("../protocol/errors.zig");
const meta_mod = @import("../protocol/meta.zig");
const version = @import("../protocol/version.zig");
const methods = @import("../protocol/methods.zig");
const Limits = @import("../Limits.zig");
const McpServer = @import("../server/Server.zig");

const log = std.log.scoped(.mcp_http);
const wake = @import("../util/wake.zig");
const park = @import("shard_poll.zig");
const socket_opts = @import("socket_opts.zig");

pub const ResponseMode = enum { auto, sse, json };

pub const Options = struct {
    /// Address to bind. The default is loopback only.
    address: []const u8 = "127.0.0.1",
    port: u16 = 3000,
    /// The MCP endpoint path.
    path: []const u8 = "/mcp",
    response_mode: ResponseMode = .auto,
    /// Origins that the server accepts in an `Origin` header. Empty means loopback only.
    allowed_origins: []const []const u8 = &.{},
    /// Hosts accepted in the `Host` header. Empty means loopback names plus the bound address.
    allowed_hosts: []const []const u8 = &.{},
    /// Send an SSE comment on each listen stream every `limits.http.sse_keepalive`.
    keepalive: bool = true,
    /// Serve HTTPS with this TLS 1.3 server. Null serves plaintext HTTP.
    tls: ?*const tls.Server = null,
    /// Require a bearer token on the endpoint and serve the protected resource metadata.
    auth: ?*const resource_server.ResourceServer = null,
};

/// Counts of the server, for tests and metrics. Each value comes from one atomic load.
pub const Stats = struct {
    /// Open connections.
    connections: u32,
    /// The connections that the shards own, also the ones with a request in a worker task.
    held: u32,
    /// Worker tasks that run now: requests that are not quick, and TLS connections.
    tasks: u32,
};

pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    options: Options,
    limits: Limits,
    listener: ?Io.net.Server = null,
    bound_port: u16 = 0,
    /// The worker tasks: requests that are not quick, and TLS connections.
    workers: Io.Group = .init,
    closing: std.atomic.Value(bool) = .init(false),
    /// Set when the accept loop ended. No connection comes to a shard after it.
    accepting_done: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    /// The shards. Only `serve` changes the slice.
    shards: []Shard = &.{},
    /// The free places of `limits.http.max_connections`.
    free_permits: std.atomic.Value(u32),
    /// True while the accept loop waits for a free place.
    accept_waiting: std.atomic.Value(bool) = .init(false),
    permit_event: Io.Event = .unset,
    /// The worker tasks that run now.
    tasks: std.atomic.Value(u32) = .init(0),
    /// The worker tasks of requests that run now, and their cap (`limits.http.max_in_flight`).
    jobs: std.atomic.Value(u32) = .init(0),
    job_cap: u32,
    /// The shards with requests that wait for a worker task.
    job_waiters: std.atomic.Value(u32) = .init(0),
    /// Set when the last worker task ended during the shutdown.
    tasks_idle: Io.Event = .unset,
    /// For tests: each shard gives each idle connection to the next shard, without a look at
    /// the work of the shards.
    force_moves: bool = false,
    /// The shards that saw the shutdown. After it, a shard starts no worker task.
    closing_acks: std.atomic.Value(u32) = .init(0),
    acks_event: Io.Event = .unset,

    pub fn init(io: Io, gpa: Allocator, server: *McpServer, options: Options) Server {
        const limits = server.options.limits;
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .limits = limits,
            .free_permits = .init(limits.http.max_connections),
            .job_cap = @max(1, if (limits.http.max_in_flight == 0) limits.http.max_connections else limits.http.max_in_flight),
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener) |*l| l.deinit(self.io);
        self.* = undefined;
    }

    /// Bind the listen socket. After this call `bound_port` has the port (useful with port 0).
    pub fn bind(self: *Server) !void {
        var address = try Io.net.IpAddress.parse(self.options.address, self.options.port);
        self.listener = try address.listen(self.io, .{ .reuse_address = self.limits.http.reuse_address, .kernel_backlog = self.limits.http.listen_backlog });
        self.bound_port = self.listener.?.socket.address.getPort();
    }

    /// The counts of the server now.
    pub fn stats(self: *Server) Stats {
        var held: u32 = 0;
        for (self.shards) |*sh| held += sh.assigned.load(.acquire);
        return .{
            .connections = self.limits.http.max_connections - self.free_permits.load(.acquire),
            .held = held,
            .tasks = self.tasks.load(.acquire),
        };
    }

    /// The count of shards for `limits.http.shards`.
    fn shardCount(self: *Server) usize {
        if (self.options.tls != null) return 0;
        if (self.limits.http.shards != 0) return self.limits.http.shards;
        const cpus = std.Thread.getCpuCount() catch 1;
        return std.math.clamp(cpus / 8, 1, 4);
    }

    /// Accept connections until a call to `shutdown`. A cancel also ends `serve`. After a
    /// cancel, the server accepts no more connections.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        try self.startShards();
        var accept_future = self.io.concurrent(acceptLoop, .{self}) catch |e| {
            self.closing.store(true, .seq_cst);
            self.stopShards();
            return e;
        };
        self.stop_event.wait(self.io) catch {};
        // On Windows a cancel can miss an accept that waits. The wake connection ends it.
        wake.cancelAcceptLoop(self.io, &accept_future, self.listener.?.socket.address, &self.closing);
        self.server.shutdownSubscriptions(self.io);
        self.stopShards();
    }

    fn startShards(self: *Server) !void {
        const n = self.shardCount();
        if (n == 0) return;
        const shards = try self.gpa.alloc(Shard, n);
        var ready: usize = 0;
        errdefer {
            for (shards[0..ready]) |*sh| sh.deinit();
            self.gpa.free(shards);
        }
        for (shards) |*sh| {
            sh.* = try Shard.init(self);
            ready += 1;
        }
        self.shards = shards;
        var started: usize = 0;
        for (shards) |*sh| {
            sh.future = self.io.concurrent(Shard.run, .{sh}) catch |e| {
                self.closing.store(true, .seq_cst);
                self.accepting_done.store(true, .seq_cst);
                for (shards[0..started]) |*s| {
                    s.poller.wake();
                    s.future.?.await(self.io);
                }
                self.shards = &.{};
                return e;
            };
            started += 1;
        }
    }

    /// End the shards: they close their idle connections at once. The requests in worker
    /// tasks get `limits.shutdown_grace`, and then the cancel of their tasks.
    fn stopShards(self: *Server) void {
        const io = self.io;
        self.closing.store(true, .seq_cst);
        self.accepting_done.store(true, .seq_cst);
        for (self.shards) |*sh| sh.poller.wake();
        // After its ack a shard starts no worker task. Thus the cancel of the group below
        // does not race a start.
        if (self.shards.len > 0) self.acks_event.waitUncancelable(io);
        if (self.tasks.load(.seq_cst) > 0) {
            self.tasks_idle.waitTimeout(io, .{ .duration = .{ .raw = self.limits.shutdown_grace, .clock = .awake } }) catch {};
        }
        self.workers.cancel(io);
        for (self.shards) |*sh| {
            sh.future.?.await(io);
            sh.deinit();
        }
        if (self.shards.len > 0) self.gpa.free(self.shards);
        self.shards = &.{};
    }

    /// Accept no more connections and end active streams. Safe to call from another task.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .seq_cst);
        self.stop_event.set(self.io);
        self.server.shutdownSubscriptions(self.io);
    }

    fn acceptLoop(self: *Server) void {
        while (!self.closing.load(.acquire)) {
            const stream = self.listener.?.accept(self.io) catch |e| switch (e) {
                error.SocketNotListening, error.Canceled => break,
                else => {
                    log.warn("accept failed: {t}", .{e});
                    continue;
                },
            };
            // The connection of `wake` or a peer that came during the shutdown.
            if (self.closing.load(.acquire)) {
                stream.close(self.io);
                break;
            }
            // Without `TCP_NODELAY`, the Nagle algorithm holds each SSE event after the first,
            // and the end of the stream, until the client acknowledges the data before it. That
            // costs one round trip for each part, or the delayed acknowledgement of the client
            // (40 ms on Linux). A failure costs latency only.
            socket_opts.setNoDelay(self.io, stream.socket) catch {};
            if (!self.takePermit()) {
                stream.close(self.io);
                break;
            }
            const accepted_at = nowNanoseconds(self.io);
            if (self.options.tls != null) {
                self.startTlsTask(stream, accepted_at);
                continue;
            }
            const conn = self.gpa.create(Connection) catch {
                stream.close(self.io);
                self.releasePermit();
                continue;
            };
            const sh = self.pickShard();
            conn.* = .{ .shard = sh, .stream = stream, .accepted_at = accepted_at };
            _ = sh.assigned.fetchAdd(1, .acq_rel);
            sh.post(conn);
        }
    }

    fn pickShard(self: *Server) *Shard {
        return &self.shards[pickIndex(self.shards)];
    }

    /// Take one of the `max_connections` places, and wait for one when none is free. At
    /// `max_connections`, the shard with the idle connection that waited longest closes it.
    /// Thus a client that opens a new pool while its old pool stays open does not wait until
    /// the old connections expire. False at the shutdown.
    fn takePermit(self: *Server) bool {
        while (true) {
            if (self.tryTakePermit()) return true;
            self.accept_waiting.store(true, .seq_cst);
            defer self.accept_waiting.store(false, .seq_cst);
            self.permit_event.reset();
            if (self.tryTakePermit()) return true;
            if (self.closing.load(.acquire)) return false;
            self.requestEvict();
            self.permit_event.waitTimeout(self.io, .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } }) catch {};
            if (self.closing.load(.acquire)) return false;
        }
    }

    fn tryTakePermit(self: *Server) bool {
        var cur = self.free_permits.load(.seq_cst);
        while (cur > 0) cur = self.free_permits.cmpxchgWeak(cur, cur - 1, .seq_cst, .seq_cst) orelse return true;
        return false;
    }

    fn releasePermit(self: *Server) void {
        _ = self.free_permits.fetchAdd(1, .seq_cst);
        if (self.accept_waiting.load(.seq_cst)) self.permit_event.set(self.io);
    }

    /// Ask the shard with the idle connection that waited longest to close it.
    fn requestEvict(self: *Server) void {
        var best: ?*Shard = null;
        var oldest: i64 = Connection.unlimited;
        for (self.shards) |*sh| {
            const t = sh.oldest_idle.load(.acquire);
            if (t < oldest) {
                oldest = t;
                best = sh;
            }
        }
        const sh = best orelse return;
        sh.evict.store(true, .seq_cst);
        sh.notify();
    }

    /// Count a worker task that starts.
    fn startTask(self: *Server) void {
        _ = self.tasks.fetchAdd(1, .seq_cst);
    }

    /// Count a worker task that ends. `job`: a task of a request.
    fn endTask(self: *Server, job: bool) void {
        if (job) {
            _ = self.jobs.fetchSub(1, .seq_cst);
            // Shards with requests that wait for a worker task can start one now.
            if (self.job_waiters.load(.seq_cst) > 0) for (self.shards) |*sh| sh.notify();
        }
        if (self.tasks.fetchSub(1, .seq_cst) == 1 and self.closing.load(.seq_cst)) self.tasks_idle.set(self.io);
    }

    /// Take a place among the worker tasks of requests. False at the cap.
    fn claimJob(self: *Server) bool {
        var cur = self.jobs.load(.seq_cst);
        while (cur < self.job_cap) cur = self.jobs.cmpxchgWeak(cur, cur + 1, .seq_cst, .seq_cst) orelse return true;
        return false;
    }

    fn startTlsTask(self: *Server, stream: Io.net.Stream, accepted_at: i64) void {
        self.startTask();
        self.workers.concurrent(self.io, TlsConn.run, .{ self, stream, accepted_at }) catch {
            stream.close(self.io);
            self.releasePermit();
            self.endTask(false);
        };
    }

    fn originAllowed(self: *Server, origin: []const u8) bool {
        return originInList(self.options.allowed_origins, origin);
    }

    fn hostAllowed(self: *Server, host: []const u8) bool {
        return hostInList(self.options.allowed_hosts, self.options.address, host);
    }

    /// True when a shard runs a quick request itself: without authorization, because a check
    /// of a token can wait for I/O.
    fn inlineEnabled(self: *Server) bool {
        return self.options.auth == null;
    }
};

/// The shard for a new connection. This is the first shard of the slice that was busy for
/// less than `spill_load` percent of its recent time windows. When all are busier, it is the
/// least busy shard. Thus the connections of one client stay on few shards. A sleep and a
/// wake of each shard cost more than the work of a quick request, and a shard with more
/// connections sleeps less. When a shard becomes busy, new connections go to the next one.
fn pickIndex(shards: []Shard) usize {
    var best: usize = 0;
    var best_load: u8 = std.math.maxInt(u8);
    for (shards, 0..) |*sh, i| {
        const load = sh.currentLoad();
        if (load < spill_load) return i;
        if (load < best_load) {
            best = i;
            best_load = load;
        }
    }
    return best;
}

/// See `pickIndex`.
const spill_load = 75;

/// The time window of `Shard.load`.
const load_window_ns: i64 = 50 * std.time.ns_per_ms;

/// The `Origin` check of DNS rebinding protection. True when `origin` is in `allowed`. An
/// empty `allowed` accepts loopback origins only. The WebSocket server uses it too.
pub fn originInList(allowed: []const []const u8, origin: []const u8) bool {
    if (allowed.len > 0) {
        for (allowed) |o| if (std.ascii.eqlIgnoreCase(o, origin)) return true;
        return false;
    }
    return isLoopbackOrigin(origin);
}

/// The `Host` check of DNS rebinding protection. True when the name of `host` is in `allowed`.
/// An empty `allowed` accepts loopback names and `bound_address`. The port does not count.
pub fn hostInList(allowed: []const []const u8, bound_address: []const u8, host: []const u8) bool {
    const name = stripPort(host);
    if (allowed.len > 0) {
        for (allowed) |h| if (std.ascii.eqlIgnoreCase(stripPort(h), name)) return true;
        return false;
    }
    if (isLoopbackName(name)) return true;
    return std.ascii.eqlIgnoreCase(name, bound_address);
}

fn stripPort(host: []const u8) []const u8 {
    if (host.len > 0 and host[0] == '[') {
        const close = std.mem.findScalar(u8, host, ']') orelse return host;
        return host[0 .. close + 1];
    }
    if (std.mem.findScalar(u8, host, ':')) |i| return host[0..i];
    return host;
}

fn isLoopbackName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "localhost") or std.mem.eql(u8, name, "127.0.0.1") or std.mem.eql(u8, name, "[::1]") or std.mem.eql(u8, name, "::1");
}

fn isLoopbackOrigin(origin: []const u8) bool {
    const rest = if (std.mem.startsWith(u8, origin, "http://")) origin[7..] else if (std.mem.startsWith(u8, origin, "https://")) origin[8..] else return false;
    return isLoopbackName(stripPort(rest));
}

/// The awake clock in nanoseconds.
fn nowNanoseconds(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
}

/// A duration in nanoseconds, from 0 to the maximum of `i64`.
fn nanoseconds(d: Io.Duration) i64 {
    if (d.nanoseconds <= 0) return 0;
    return @intCast(@min(d.nanoseconds, std.math.maxInt(i64)));
}

/// The awake time `limit` after `from`, or `unlimited` for a zero limit.
fn deadlineAfter(from: i64, limit: Io.Duration) i64 {
    const ns = nanoseconds(limit);
    return if (ns == 0) Connection.unlimited else from +| ns;
}

/// The response to a request that did not arrive in its time limit (RFC 9110 section 15.5.9).
const request_timeout_response = "HTTP/1.1 408 Request Timeout\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// The response to a request that did not get a worker task in `head_timeout`.
const busy_response = "HTTP/1.1 503 Service Unavailable\r\nretry-after: 1\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// The time that the server keeps a TLS connection open after a response without
/// keep-alive, for the close by the client. Overflow: the server closes the connection.
const close_linger: Io.Duration = .fromSeconds(2);

/// The most requests of one connection that a shard serves before it looks at its other
/// connections.
const max_requests_per_turn = 16;

/// The spin of a shard. The events of a shard can come from more than one connection, with
/// a mean gap below `spin_gap_ns`. Then the shard looks for the next events without a sleep.
/// It looks for `spin_gaps` times the mean gap, and at most for `spin_max_ns`.
///
/// A sleep and a wake cost the shard a context switch. Also, a client that sends to a shard
/// in a sleep pays for the wake of its thread. In a virtual machine, a wake of a thread on
/// another processor can cost more than a quick request. A single connection with one
/// request at a time gets no spin: its next request comes only after the response. The spin
/// applies only on Linux. In the Windows benchmark, the spin used more server CPU and gave
/// no more calls each second.
const spin_gap_ns: i64 = 500 * std.time.ns_per_us;
const spin_max_ns: i64 = 2000 * std.time.ns_per_us;
const spin_gaps = 8;
const spin_enabled = park.is_linux;

/// The size of the read buffer of a shard: the bytes of one receive.
const scratch_len = 64 * 1024;

// -- Shards ----------------------------------------------------------------------------------

/// A lock-free queue of connections with many producers and one consumer. A push is one
/// compare-and-swap. The consumer takes all entries at once, thus no entry returns to the
/// head while a push looks at it.
const Inbox = struct {
    head: std.atomic.Value(?*Connection) = .init(null),

    /// The head of an inbox whose shard ended. Only its address counts.
    var closed_mark: Connection = undefined;

    /// Push `conn`. False when the shard of the inbox ended (see `close`).
    fn push(q: *Inbox, conn: *Connection) bool {
        var old = q.head.load(.monotonic);
        while (true) {
            if (old == &closed_mark) return false;
            conn.inbox_next = old;
            old = q.head.cmpxchgWeak(old, conn, .seq_cst, .monotonic) orelse return true;
        }
    }

    /// End the inbox of a shard that ends. False when an entry came first: the shard must
    /// take it.
    fn close(q: *Inbox) bool {
        return q.head.cmpxchgStrong(null, &closed_mark, .seq_cst, .monotonic) == null;
    }

    /// All entries, in the order of their push.
    fn takeAll(q: *Inbox) ?*Connection {
        var it = q.head.swap(null, .acquire);
        var out: ?*Connection = null;
        while (it) |c| {
            it = c.inbox_next;
            c.inbox_next = out;
            out = c;
        }
        return out;
    }

    fn isEmpty(q: *Inbox) bool {
        return q.head.load(.seq_cst) == null;
    }
};

/// An intrusive list of connections in the order of insertion. A connection is in one list
/// at most. In the lists with a time limit, the head expires first.
const List = struct {
    head: ?*Connection = null,
    tail: ?*Connection = null,
    len: usize = 0,

    fn push(l: *List, c: *Connection) void {
        std.debug.assert(c.list == null);
        c.prev = l.tail;
        c.next = null;
        if (l.tail) |t| t.next = c else l.head = c;
        l.tail = c;
        c.list = l;
        l.len += 1;
    }

    fn remove(l: *List, c: *Connection) void {
        std.debug.assert(c.list == l);
        if (c.prev) |p| p.next = c.next else l.head = c.next;
        if (c.next) |n| n.prev = c.prev else l.tail = c.prev;
        c.prev = null;
        c.next = null;
        c.list = null;
        l.len -= 1;
    }

    /// Insert `c` after the last connection that parked at the same time or before it.
    fn insertByParkedAt(l: *List, c: *Connection) void {
        var after = l.tail;
        while (after) |a| : (after = a.prev) if (a.parked_at <= c.parked_at) break;
        const a = after orelse {
            c.prev = null;
            c.next = l.head;
            if (l.head) |h| h.prev = c else l.tail = c;
            l.head = c;
            c.list = l;
            l.len += 1;
            return;
        };
        c.prev = a;
        c.next = a.next;
        if (a.next) |n| n.prev = c else l.tail = c;
        a.next = c;
        c.list = l;
        l.len += 1;
    }

    fn pop(l: *List) ?*Connection {
        const c = l.head orelse return null;
        l.remove(c);
        return c;
    }
};

/// One task that owns a part of the plaintext connections. Only this task reads or changes
/// the fields after `assigned` and the connections in its lists.
const Shard = struct {
    server: *Server,
    poller: park.Poller,
    future: ?Io.Future(void) = null,
    /// New connections from the accept loop, and connections whose worker task ended.
    inbox: Inbox = .{},
    /// True while the task waits in its poller, or is about to. A push wakes the poller then.
    sleeping: std.atomic.Value(bool) = .init(false),
    /// Set by the accept loop at `max_connections`: close the oldest idle connection.
    evict: std.atomic.Value(bool) = .init(false),
    /// The park time of the oldest idle connection, or `unlimited`, for the accept loop.
    oldest_idle: std.atomic.Value(i64) = .init(Connection.unlimited),
    /// The connections of the shard: in its lists, in a worker task, or in its inbox. The
    /// accept loop adds one, and the shard removes one when it frees it.
    assigned: std.atomic.Value(u32) = .init(0),
    /// The percent of the time that the shard worked, without its waits. It is an average of
    /// its recent time windows, for the accept loop (see `pickIndex`).
    load: std.atomic.Value(u8) = .init(0),

    /// New connections, and connections with a part of a request head
    /// (`limits.http.head_timeout`).
    heads: List = .{},
    /// Idle connections after a response (`limits.http.idle_timeout`).
    parked: List = .{},
    /// Connections with a part of a request body (`limits.http.idle_timeout`).
    bodies: List = .{},
    /// Complete requests that wait for a worker task (`limits.http.head_timeout`).
    ready: List = .{},
    /// Responses that the shard sends (`limits.http.idle_timeout` from the last progress).
    sending: List = .{},
    /// Responses that the shard sends at the shutdown (`limits.shutdown_grace`).
    draining: List = .{},
    /// Connections with more requests in their buffer, for the next turn of the loop.
    again: List = .{},
    /// Closed connections. The shard frees them after the events of a wait: an event of that
    /// wait can still name them. On Windows also after the end of their polls.
    graveyard: List = .{},
    closing_seen: bool = false,
    /// True while the shard counts in `Server.job_waiters`.
    waits_for_job: bool = false,
    /// The bytes of one receive.
    scratch: []u8,
    /// The response of a request that the shard runs itself.
    out: ?Io.Writer.Allocating = null,
    /// Connections to give to other shards after the events of a wait.
    to_move: std.ArrayList(*Connection) = .empty,
    /// The connections that the shard can still give away in this time window.
    moves_left: u32 = 0,
    /// Free write buffers of worker tasks.
    free_buffers: ?*FreeBuffer = null,
    free_buffer_count: u32 = 0,

    const FreeBuffer = struct { next: ?*FreeBuffer };
    const buffer_len = tls.Connection.min_output_buffer_len;
    const max_free_buffers = 16;

    fn init(server: *Server) !Shard {
        var poller = try park.Poller.init(server.gpa);
        errdefer poller.deinit();
        const scratch = try server.gpa.alloc(u8, scratch_len);
        return .{ .server = server, .poller = poller, .scratch = scratch };
    }

    fn deinit(sh: *Shard) void {
        const gpa = sh.server.gpa;
        while (sh.free_buffers) |b| {
            sh.free_buffers = b.next;
            const bytes: [*]align(@alignOf(FreeBuffer)) u8 = @ptrCast(b);
            const slice: []align(@alignOf(FreeBuffer)) u8 = bytes[0..buffer_len];
            gpa.free(slice);
        }
        if (sh.out) |*aw| aw.deinit();
        sh.to_move.deinit(gpa);
        gpa.free(sh.scratch);
        sh.poller.deinit();
    }

    /// Give `conn` to the shard. Safe from any task. The shard runs still: the accept
    /// loop ends before the shards, and a shard with a connection in a worker task does not
    /// end.
    fn post(sh: *Shard, conn: *Connection) void {
        const ok = sh.inbox.push(conn);
        std.debug.assert(ok);
        sh.notify();
    }

    /// Wake the task of the shard when it waits. Safe from any task.
    fn notify(sh: *Shard) void {
        if (sh.sleeping.load(.seq_cst)) sh.poller.wake();
    }

    fn run(sh: *Shard) void {
        const self = sh.server;
        const io = self.io;
        var events: [256]park.Event = undefined;
        // The mean gap between two waits with events (see `spin_gap_ns`).
        var gap: i64 = std.time.ns_per_ms;
        // The part of the events, in 1/256, that came from another connection than the event
        // before them, as a moving average.
        var mixed: u32 = 0;
        var last_slot: ?*park.Slot = null;
        // The time of work in the window that starts at `window_start` (see `load`).
        var window_start = nowNanoseconds(io);
        var worked: i64 = 0;
        var woke = window_start;
        while (true) {
            sh.drainInbox();
            if (!sh.closing_seen and self.closing.load(.seq_cst)) sh.startClosing();
            const now = nowNanoseconds(io);
            sh.expire(now);
            if (sh.evict.swap(false, .seq_cst)) sh.evictOldest();
            sh.startReady();
            sh.serveAgain();
            sh.bury();
            sh.oldest_idle.store(if (sh.parked.head) |c| c.parked_at else Connection.unlimited, .release);
            // A shard can give a connection to this shard until the close of the inbox.
            if (sh.closing_seen and self.accepting_done.load(.seq_cst) and sh.assigned.load(.seq_cst) == 0 and sh.inbox.close()) return;

            const before = nowNanoseconds(io);
            worked += before - woke;
            if (before - window_start >= load_window_ns) {
                // A moving average over the windows: a short burst, for example the accept of
                // many connections, does not make the shard look busy.
                const percent = std.math.clamp(@divTrunc(worked * 100, before - window_start), 0, 100);
                const old: i64 = sh.load.load(.monotonic);
                sh.load.store(@intCast(@divTrunc(3 * old + percent, 4)), .monotonic);
                window_start = before;
                worked = 0;
                sh.moves_left = @max(1, sh.assigned.load(.monotonic) / 16);
            }
            var n: usize = 0;
            if (spin_enabled and gap < spin_gap_ns and mixed > 64) {
                const end = before +| @min(spin_gaps * gap, spin_max_ns);
                while (true) {
                    n = sh.poller.wait(0, &events) catch 0;
                    if (n > 0 or !sh.inbox.isEmpty() or nowNanoseconds(io) >= end) break;
                }
            }
            if (n == 0) {
                var timeout = sh.waitMilliseconds(now);
                sh.sleeping.store(true, .seq_cst);
                // A connection in `to_move` has no poll: it moves after this wait.
                if (!sh.inbox.isEmpty() or sh.again.head != null or sh.to_move.items.len > 0 or sh.evict.load(.seq_cst) or
                    (!sh.closing_seen and self.closing.load(.seq_cst)) or
                    (sh.ready.head != null and self.jobs.load(.seq_cst) < self.job_cap)) timeout = 0;
                n = sh.poller.wait(timeout, &events) catch 0;
                sh.sleeping.store(false, .seq_cst);
            }
            woke = nowNanoseconds(io);
            if (n > 0) gap = @divTrunc(3 * gap + @min(woke - before, std.time.ns_per_s), 4);
            for (events[0..n]) |ev| {
                const other: u32 = if (ev.slot != last_slot) 256 else 0;
                mixed = (mixed * 7 + other) / 8;
                last_slot = ev.slot;
                sh.handleEvent(ev);
            }
            sh.moveConnections();
            sh.bury();
        }
    }

    /// The wait of the poller until the nearest time limit, in milliseconds, or -1.
    fn waitMilliseconds(sh: *Shard, now: i64) i32 {
        var next: i64 = Connection.unlimited;
        for ([_]*List{ &sh.heads, &sh.parked, &sh.bodies, &sh.ready, &sh.sending, &sh.draining }) |l| {
            if (l.head) |c| next = @min(next, c.deadline);
        }
        // The worker task of a TLS connection, or a closed connection on Windows, does not
        // need a time limit here.
        if (next == Connection.unlimited) return -1;
        const ms = @divFloor(@max(next - now, 0) +| (std.time.ns_per_ms - 1), std.time.ns_per_ms);
        return @intCast(@min(ms, std.math.maxInt(i32)));
    }

    fn drainInbox(sh: *Shard) void {
        var it = sh.inbox.takeAll();
        while (it) |conn| {
            it = conn.inbox_next;
            conn.inbox_next = null;
            switch (conn.state) {
                .new => sh.admit(conn),
                .busy => sh.endJob(conn),
                .moved => sh.adopt(conn),
                else => unreachable,
            }
        }
    }

    /// The shutdown: close each connection without a worker task. A response that the shard
    /// sends gets `limits.shutdown_grace`.
    fn startClosing(sh: *Shard) void {
        const self = sh.server;
        sh.closing_seen = true;
        if (self.closing_acks.fetchAdd(1, .seq_cst) + 1 == self.shards.len) self.acks_event.set(self.io);
        for ([_]*List{ &sh.heads, &sh.parked, &sh.bodies, &sh.ready, &sh.again }) |l| {
            while (l.head) |c| sh.close(c);
        }
        if (nanoseconds(self.limits.shutdown_grace) == 0) {
            while (sh.sending.head) |c| sh.close(c);
        } else {
            const end = deadlineAfter(nowNanoseconds(self.io), self.limits.shutdown_grace);
            while (sh.sending.head) |c| sh.setTimer(c, &sh.draining, end);
        }
        sh.leaveJobWaiters();
    }

    fn admit(sh: *Shard, conn: *Connection) void {
        const self = sh.server;
        conn.state = .reading;
        if (sh.closing_seen or !park.Poller.prepareNow(conn.stream.socket.handle)) return sh.close(conn);
        sh.poller.add(&conn.slot, conn.stream.socket.handle) catch return sh.close(conn);
        conn.in_poller = true;
        // The head of the first request has its time limit from the accept.
        sh.setTimer(conn, &sh.heads, deadlineAfter(conn.accepted_at, self.limits.http.head_timeout));
        // The client sends its first request with the connect, frequently: no wait for it.
        sh.pump(conn);
    }

    fn setTimer(sh: *Shard, conn: *Connection, list: *List, deadline: i64) void {
        _ = sh;
        if (conn.list) |l| l.remove(conn);
        conn.deadline = deadline;
        list.push(conn);
    }

    fn unlist(conn: *Connection) void {
        if (conn.list) |l| l.remove(conn);
    }

    /// Close the connections whose time limit passed. A request head or body that did not
    /// arrive in time gets 408. A request that did not get a worker task in time gets 503. An
    /// idle connection closes without a response (RFC 9112 section 9.6).
    fn expire(sh: *Shard, now: i64) void {
        const answer = !sh.closing_seen;
        const none: []const u8 = "";
        for ([_]struct { *List, []const u8 }{
            .{ &sh.heads, if (answer) request_timeout_response else none },
            .{ &sh.bodies, if (answer) request_timeout_response else none },
            .{ &sh.ready, if (answer) busy_response else none },
            .{ &sh.parked, none },
            .{ &sh.sending, none },
            .{ &sh.draining, none },
        }) |entry| {
            const l, const response = entry;
            while (l.head) |c| {
                if (c.deadline > now) break;
                if (response.len > 0) _ = park.Poller.sendNow(c.stream.socket.handle, response);
                sh.close(c);
            }
        }
    }

    /// Close the idle connection that waited longest, for a new connection at
    /// `max_connections`.
    fn evictOldest(sh: *Shard) void {
        const conn = sh.parked.head orelse return;
        sh.close(conn);
    }

    fn handleEvent(sh: *Shard, ev: park.Event) void {
        const conn: *Connection = @alignCast(@fieldParentPtr("slot", ev.slot));
        switch (conn.state) {
            .new, .moved, .closed => {},
            .reading => {
                if (ev.hangup) conn.peer_closed = true;
                if (ev.readable or ev.hangup) sh.pump(conn);
            },
            // The request waits for a worker task. The bytes after it stay in the socket.
            .ready => if (ev.hangup) {
                conn.peer_closed = true;
            },
            .busy => sh.watchBusy(conn, ev),
            .sending => {
                if (ev.readable) conn.data_seen = true;
                if (ev.hangup) conn.hangup_seen = true;
                if (ev.writable or ev.hangup) sh.flushOut(conn);
            },
        }
    }

    /// An event on the socket of a connection whose request runs in a worker task. A close by
    /// the peer cancels the request. Bytes of a next request stay in the socket until the
    /// task ends.
    fn watchBusy(sh: *Shard, conn: *Connection, ev: park.Event) void {
        var hangup = ev.hangup;
        if (ev.readable and !hangup and !conn.data_seen) {
            if (park.is_linux or park.is_windows) {
                // `epoll` and `AFD_POLL` report the close by the peer as its own event.
                conn.data_seen = true;
            } else {
                // `poll` gives "readable" for bytes and for the close by the peer. A peek
                // tells them apart and leaves the bytes in the socket.
                var byte: [1]u8 = undefined;
                switch (park.Poller.peekNow(conn.stream.socket.handle, &byte)) {
                    .done => |n| if (n == 0) {
                        hangup = true;
                    } else {
                        conn.data_seen = true;
                    },
                    .would_block => {},
                    .failed => hangup = true,
                }
            }
        }
        if (hangup and !conn.hangup_seen) {
            conn.hangup_seen = true;
            log.debug("the client of a request disconnected", .{});
            conn.job.token.cancel(sh.server.io, disconnect_reason);
        }
        // Without more interest, the poller does not report the same state again.
        sh.poller.want(&conn.slot, .{ .read = !conn.data_seen and !conn.hangup_seen }) catch {};
    }

    /// Read and serve the requests of `conn` until it waits for bytes, sends a response,
    /// waits for a worker task, or closes.
    fn pump(sh: *Shard, conn: *Connection) void {
        const self = sh.server;
        var budget: u32 = max_requests_per_turn;
        if (conn.in.items.len > 0) {
            if (sh.consume(conn, conn.in.items, false, &budget) == .stop) return;
        }
        while (true) {
            const from_scratch = conn.in.items.len == 0;
            const buf: []u8 = if (from_scratch) sh.scratch else buf: {
                const limit = self.limits.http.max_head_bytes +| self.limits.http.max_body_bytes +| 4096;
                const want = @min(@max(conn.in.items.len, 4096), limit -| conn.in.items.len);
                // Chunks and trailers can make a body longer than the limit with its framing.
                if (want == 0) return sh.reject(conn, if (conn.in_body) .body_too_large else .head_too_large);
                conn.in.ensureUnusedCapacity(self.gpa, want) catch return sh.close(conn);
                break :buf conn.in.unusedCapacitySlice();
            };
            switch (park.Poller.recvNow(conn.stream.socket.handle, buf)) {
                .would_block => return sh.waitForBytes(conn),
                // The end of the connection, also within a request.
                .failed => return sh.close(conn),
                .done => |n| {
                    if (n == 0) return sh.close(conn);
                    if (from_scratch) {
                        if (sh.consume(conn, sh.scratch[0..n], true, &budget) == .stop) return;
                    } else {
                        conn.in.items.len += n;
                        if (sh.consume(conn, conn.in.items, false, &budget) == .stop) return;
                    }
                    // A receive that did not fill the buffer took all bytes of the socket.
                    // A byte that arrives later wakes the poller: on Linux the edge of
                    // `epoll` comes after the receive, on Windows the poll sees the byte at
                    // once. Thus one more receive, which would fail, is not necessary. After
                    // the close by the peer, no edge follows: the next receive sees the end.
                    if (n < buf.len and !conn.peer_closed) {
                        // A full buffer gets no more bytes (see above).
                        if (conn.in.items.len >= self.limits.http.max_head_bytes +| self.limits.http.max_body_bytes +| 4096)
                            return sh.reject(conn, if (conn.in_body) .body_too_large else .head_too_large);
                        return sh.waitForBytes(conn);
                    }
                },
            }
        }
    }

    const Step = enum { more, stop };

    /// Serve the complete requests at the start of `buf`, and keep the rest in `conn.in`.
    /// `buf` is `sh.scratch` or `conn.in.items`. `.stop`: the connection does not read now.
    fn consume(sh: *Shard, conn: *Connection, buf: []u8, from_scratch: bool, budget: *u32) Step {
        const self = sh.server;
        var off: usize = 0;
        while (off < buf.len) {
            const rest = buf[off..];
            // The state of the last look applies to a request at the start of `conn.in`.
            var local: Scan = .{};
            const scan = if (off == 0 and !from_scratch) &conn.scan else &local;
            switch (frameRequest(self, rest, scan)) {
                .need_more => |more| {
                    // `keep` moves `rest` to the start of `conn.in`.
                    conn.scan = scan.*;
                    conn.in_body = more.in_body;
                    if (more.expect_continue and !conn.continue_sent) {
                        const text = "HTTP/1.1 100 Continue\r\n\r\n";
                        switch (park.Poller.sendNow(conn.stream.socket.handle, text)) {
                            .done => |n| if (n == text.len) {
                                conn.continue_sent = true;
                            } else {
                                // A part of the line would corrupt the stream of responses.
                                sh.close(conn);
                                return .stop;
                            },
                            // The client sends the body without it after a time.
                            .would_block => {},
                            .failed => {
                                sh.close(conn);
                                return .stop;
                            },
                        }
                    }
                    break;
                },
                .reject => |status| {
                    sh.reject(conn, status);
                    return .stop;
                },
                .complete => |f| {
                    if (sh.closing_seen) {
                        sh.close(conn);
                        return .stop;
                    }
                    if (budget.* == 0) {
                        // Other connections first. The rest waits in the buffer.
                        if (!sh.keep(conn, buf, off, from_scratch)) return .stop;
                        unlist(conn);
                        sh.again.push(conn);
                        return .stop;
                    }
                    budget.* -= 1;
                    conn.continue_sent = false;
                    conn.in_body = false;
                    conn.scan = .{};
                    // The time limit of the last wait ends with a complete request.
                    unlist(conn);
                    if (f.quick and self.inlineEnabled()) {
                        const end = sh.serveInline(conn, rest[0..f.len]);
                        off += f.len;
                        conn.served = true;
                        switch (end) {
                            .next => continue,
                            .sending => {
                                _ = sh.keep(conn, buf, off, from_scratch);
                                return .stop;
                            },
                            .close => {
                                sh.close(conn);
                                return .stop;
                            },
                        }
                    }
                    // The worker task reads the request from `conn.in`.
                    if (!sh.keep(conn, buf, off, from_scratch)) return .stop;
                    conn.job.len = f.len;
                    conn.job.body_skipped = f.body_skipped;
                    sh.startJob(conn);
                    return .stop;
                },
            }
        }
        if (!sh.keep(conn, buf, off, from_scratch)) return .stop;
        return .more;
    }

    /// Keep `buf[off..]` at the start of `conn.in`. False when the shard has no memory: it
    /// closed the connection.
    fn keep(sh: *Shard, conn: *Connection, buf: []u8, off: usize, from_scratch: bool) bool {
        const gpa = sh.server.gpa;
        if (from_scratch) {
            if (off == buf.len) return true;
            conn.in.appendSlice(gpa, buf[off..]) catch {
                sh.close(conn);
                return false;
            };
            return true;
        }
        if (off == 0) return true;
        const items = conn.in.items;
        std.mem.copyForwards(u8, items[0 .. items.len - off], items[off..]);
        conn.in.items.len -= off;
        // An idle connection holds no buffer.
        if (conn.in.items.len == 0) conn.in.clearAndFree(gpa);
        return true;
    }

    /// The socket has no more bytes now. Wait for them, with the time limit of the part of
    /// the request that waits.
    fn waitForBytes(sh: *Shard, conn: *Connection) void {
        const self = sh.server;
        if (sh.closing_seen) return sh.close(conn);
        const now = nowNanoseconds(self.io);
        if (conn.in.items.len == 0) {
            // Between requests. A new connection keeps the time limit of its first head.
            if (conn.served and conn.list != &sh.parked) {
                sh.setTimer(conn, &sh.parked, deadlineAfter(now, self.limits.http.idle_timeout));
                conn.parked_at = now;
            }
        } else if (conn.in_body) {
            // The body obeys `idle_timeout` from the end of the head.
            if (conn.list != &sh.bodies) sh.setTimer(conn, &sh.bodies, deadlineAfter(now, self.limits.http.idle_timeout));
        } else if (conn.list != &sh.heads) {
            // The head obeys `head_timeout` from its first byte.
            sh.setTimer(conn, &sh.heads, deadlineAfter(now, self.limits.http.head_timeout));
        }
        // A busy shard gives an idle connection to a shard with less work, after the events of
        // this wait (see `moveConnections`). The poll of the socket waits until then. Only a
        // connection between two requests moves: it keeps its idle time limit.
        if (conn.moving) return;
        if (conn.list == &sh.parked and sh.shouldShed()) {
            if (sh.to_move.append(self.gpa, conn)) |_| {
                conn.moving = true;
                return;
            } else |_| {}
        }
        sh.poller.want(&conn.slot, .{ .read = true }) catch sh.close(conn);
    }

    /// True when this shard must give an idle connection to another shard. The shard is
    /// busy for `spill_load` percent of its time or more, and another shard for less than
    /// `spill_load - 25` percent. In one time window, at most one sixteenth of the
    /// connections move, so that the work of the shards comes nearer in steps.
    fn shouldShed(sh: *Shard) bool {
        if (sh.server.force_moves) return sh.target() != null;
        if (sh.moves_left == 0 or sh.load.load(.monotonic) < spill_load) return false;
        if (sh.target() == null) return false;
        sh.moves_left -= 1;
        return true;
    }

    /// The load of the shard for other tasks: zero while it waits in its poller, else the
    /// average of its recent time windows. A shard without work does not update its load.
    fn currentLoad(sh: *Shard) u8 {
        if (sh.sleeping.load(.monotonic)) return 0;
        return sh.load.load(.monotonic);
    }

    /// The shard with the least work, when it is not busy.
    fn target(sh: *Shard) ?*Shard {
        const shards = sh.server.shards;
        if (sh.server.force_moves) {
            if (shards.len < 2) return null;
            const i = (@intFromPtr(sh) - @intFromPtr(shards.ptr)) / @sizeOf(Shard);
            return &shards[(i + 1) % shards.len];
        }
        var best: ?*Shard = null;
        var best_load: u8 = spill_load - 25;
        for (sh.server.shards) |*other| {
            if (other == sh) continue;
            const load = other.currentLoad();
            if (load < best_load) {
                best = other;
                best_load = load;
            }
        }
        return best;
    }

    /// Give the connections of `to_move` to other shards, through their inbox. Only the
    /// shard that owns a connection moves it, after the events of a wait. Thus no event of
    /// that wait names a connection that another shard owns.
    fn moveConnections(sh: *Shard) void {
        defer sh.to_move.clearRetainingCapacity();
        // A connection is in the list one time (see `Connection.moving`). After the push to
        // the other shard, this shard does not touch it.
        for (sh.to_move.items) |conn| {
            conn.moving = false;
            // `close` removes a closed connection from the list. A connection that got bytes
            // after its entry went on: it is not idle now.
            if (conn.state != .reading) continue;
            if (conn.list != &sh.parked) {
                sh.poller.want(&conn.slot, .{ .read = true }) catch sh.close(conn);
                continue;
            }
            const other = sh.target();
            if (other == null or !conn.slot.quiet() or sh.closing_seen or sh.server.closing.load(.seq_cst)) {
                sh.poller.want(&conn.slot, .{ .read = true }) catch sh.close(conn);
                continue;
            }
            const to = other.?;
            // The idle time limit (`deadline`) stays with the connection.
            unlist(conn);
            sh.poller.detach(&conn.slot);
            conn.in_poller = false;
            conn.state = .moved;
            conn.shard = to;
            _ = to.assigned.fetchAdd(1, .seq_cst);
            _ = sh.assigned.fetchSub(1, .seq_cst);
            if (to.inbox.push(conn)) {
                to.notify();
                continue;
            }
            // The other shard ended at the shutdown: keep the connection. The poll shows
            // the bytes that came meanwhile. No pump here: it could add to `to_move`.
            _ = sh.assigned.fetchAdd(1, .seq_cst);
            _ = to.assigned.fetchSub(1, .seq_cst);
            conn.shard = sh;
            if (sh.attach(conn)) sh.poller.want(&conn.slot, .{ .read = true }) catch sh.close(conn);
        }
    }

    /// Put an idle connection from another shard in the poller and in `parked`, with its idle
    /// time limit. False when the shard closed it.
    fn attach(sh: *Shard, conn: *Connection) bool {
        conn.state = .reading;
        if (sh.closing_seen) {
            sh.close(conn);
            return false;
        }
        sh.poller.add(&conn.slot, conn.stream.socket.handle) catch {
            sh.close(conn);
            return false;
        };
        conn.in_poller = true;
        // Eviction takes the head of `parked`: keep the list in the order of the parks. With
        // `idle_timeout` zero all the deadlines are equal, and that order differs.
        sh.parked.insertByParkedAt(conn);
        return true;
    }

    /// Take an idle connection from another shard.
    fn adopt(sh: *Shard, conn: *Connection) void {
        if (!sh.attach(conn)) return;
        // Bytes can wait in the socket: the poll of the old shard ended without them.
        sh.pump(conn);
    }

    /// Answer a request that the server does not read, and close the connection.
    fn reject(sh: *Shard, conn: *Connection, status: Reject) void {
        const text = switch (status) {
            .bad_request => "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            .head_too_large => "HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            .body_too_large => "HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            .expectation_failed => "HTTP/1.1 417 Expectation Failed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        };
        _ = park.Poller.sendNow(conn.stream.socket.handle, text);
        sh.close(conn);
    }

    const InlineEnd = enum { next, sending, close };

    /// Run a quick request in the shard: `McpServer.isQuickMethod` accepts its `Mcp-Method`
    /// and `Mcp-Name` headers, and its bytes are complete. The response goes to a buffer, and
    /// then to the socket without a wait. A rest that does not fit waits for space in the
    /// send buffer (`.sending`). A new task and its thread wake cost more than a quick
    /// handler.
    fn serveInline(sh: *Shard, conn: *Connection, bytes: []const u8) InlineEnd {
        const self = sh.server;
        const aw = if (sh.out) |*w| w else blk: {
            sh.out = Io.Writer.Allocating.initCapacity(self.gpa, 16 * 1024) catch return .close;
            break :blk &sh.out.?;
        };
        aw.clearRetainingCapacity();
        defer if (aw.writer.buffer.len > 1024 * 1024) {
            aw.deinit();
            sh.out = null;
        };
        var reader: Io.Reader = .fixed(bytes);
        var http_server: http.Server = .init(&reader, &aw.writer);
        var request = http_server.receiveHead() catch return .close;
        var rc: RequestContext = .{ .owner = self, .mode = .inline_, .peer = conn.stream.socket.address };
        const keep_alive = handleRequest(&rc, &request) catch false;
        const reuse = keep_alive and request.head.keep_alive;
        aw.writer.flush() catch return .close;
        return sh.send(conn, aw.written(), reuse);
    }

    /// Send `data` without a wait. The rest waits in `conn.pending_out`.
    fn send(sh: *Shard, conn: *Connection, data: []const u8, reuse: bool) InlineEnd {
        var sent: usize = 0;
        while (sent < data.len) {
            switch (park.Poller.sendNow(conn.stream.socket.handle, data[sent..])) {
                .done => |n| {
                    if (n == 0) return .close;
                    sent += n;
                },
                .would_block => break,
                .failed => return .close,
            }
        }
        if (sent == data.len) return if (reuse) .next else .close;
        // The client does not read now. The shard sends the rest when the socket has space.
        conn.pending_out = sh.server.gpa.dupe(u8, data[sent..]) catch return .close;
        conn.pending_sent = 0;
        conn.close_after_send = !reuse;
        conn.state = .sending;
        conn.data_seen = false;
        conn.hangup_seen = false;
        // The client must read the rest in `idle_timeout` (from the last progress).
        sh.setTimer(conn, &sh.sending, deadlineAfter(nowNanoseconds(sh.server.io), sh.server.limits.http.idle_timeout));
        sh.poller.want(&conn.slot, .{ .write = true }) catch return .close;
        return .sending;
    }

    /// Send more of `conn.pending_out`. After the last byte, the connection reads again.
    fn flushOut(sh: *Shard, conn: *Connection) void {
        const self = sh.server;
        const data = conn.pending_out.?;
        const sent_before = conn.pending_sent;
        while (conn.pending_sent < data.len) {
            switch (park.Poller.sendNow(conn.stream.socket.handle, data[conn.pending_sent..])) {
                .done => |n| {
                    if (n == 0) return sh.close(conn);
                    conn.pending_sent += n;
                },
                .would_block => {
                    // The send obeys `idle_timeout` from its last progress. At the shutdown the
                    // connection stays in `draining` with its grace deadline: a client that
                    // reads a little at a time must not keep the shard alive.
                    if (conn.pending_sent != sent_before and !sh.closing_seen) sh.setTimer(conn, &sh.sending, deadlineAfter(nowNanoseconds(self.io), self.limits.http.idle_timeout));
                    // After the end of the input of the peer, a poll for its end would
                    // complete at once, again and again.
                    sh.poller.want(&conn.slot, .{ .write = true, .no_end = conn.hangup_seen }) catch sh.close(conn);
                    return;
                },
                .failed => return sh.close(conn),
            }
        }
        self.gpa.free(data);
        conn.pending_out = null;
        if (conn.close_after_send) return sh.close(conn);
        unlist(conn);
        conn.state = .reading;
        sh.pump(conn);
    }

    /// Give the request at the start of `conn.in` (`conn.job.len` bytes) a worker task, or a
    /// place in `ready` at the cap of the worker tasks.
    fn startJob(sh: *Shard, conn: *Connection) void {
        const self = sh.server;
        if (!self.claimJob()) {
            conn.state = .ready;
            sh.setTimer(conn, &sh.ready, deadlineAfter(nowNanoseconds(self.io), self.limits.http.head_timeout));
            if (!sh.waits_for_job) {
                sh.waits_for_job = true;
                _ = self.job_waiters.fetchAdd(1, .seq_cst);
            }
            // The bytes after the request stay in the socket until the task. On Linux a close
            // by the peer still shows (see `peer_closed`). On the other systems the poll of
            // the task shows it.
            sh.poller.want(&conn.slot, .{}) catch {};
            return;
        }
        sh.launchJob(conn);
    }

    /// Start the worker task of `conn`. The caller claimed a place.
    fn launchJob(sh: *Shard, conn: *Connection) void {
        const self = sh.server;
        const buffer = sh.takeBuffer() orelse {
            _ = self.jobs.fetchSub(1, .seq_cst);
            return sh.close(conn);
        };
        unlist(conn);
        conn.state = .busy;
        conn.data_seen = false;
        conn.hangup_seen = false;
        conn.job.token = .{};
        conn.job.reuse = false;
        conn.job.buffer = buffer;
        if (conn.peer_closed) {
            conn.hangup_seen = true;
            conn.job.token.cancel(self.io, disconnect_reason);
        }
        // The poller watches the socket for a close by the peer while the task runs.
        sh.poller.want(&conn.slot, .{ .read = true }) catch {};
        self.startTask();
        self.workers.concurrent(self.io, Connection.runJob, .{conn}) catch {
            conn.job.reuse = false;
            self.endTask(true);
            sh.endJob(conn);
        };
    }

    /// The worker task of `conn` ended.
    fn endJob(sh: *Shard, conn: *Connection) void {
        if (conn.job.buffer) |b| sh.giveBuffer(b);
        conn.job.buffer = null;
        const len = conn.job.len;
        conn.job.len = 0;
        conn.state = .reading;
        if (!conn.job.reuse or sh.closing_seen) return sh.close(conn);
        conn.served = true;
        _ = sh.keep(conn, conn.in.items, len, false);
        // Bytes of the next request can wait in the socket. The poll of the task does not
        // report them again.
        sh.pump(conn);
    }

    /// Give the requests in `ready` a worker task, up to the cap.
    fn startReady(sh: *Shard) void {
        const self = sh.server;
        while (sh.ready.head) |conn| {
            if (!self.claimJob()) return;
            sh.ready.remove(conn);
            sh.launchJob(conn);
        }
        sh.leaveJobWaiters();
    }

    fn leaveJobWaiters(sh: *Shard) void {
        if (!sh.waits_for_job) return;
        sh.waits_for_job = false;
        _ = sh.server.job_waiters.fetchSub(1, .seq_cst);
    }

    /// Serve the connections with more requests in their buffer.
    fn serveAgain(sh: *Shard) void {
        var list = sh.again;
        sh.again = .{};
        // `List.push` set `list` of each connection to `&sh.again`: move them.
        var it = list.head;
        while (it) |c| : (it = c.next) c.list = &list;
        while (list.pop()) |c| sh.pump(c);
    }

    fn takeBuffer(sh: *Shard) ?[]u8 {
        if (sh.free_buffers) |b| {
            sh.free_buffers = b.next;
            sh.free_buffer_count -= 1;
            const bytes: [*]align(@alignOf(FreeBuffer)) u8 = @ptrCast(b);
            return bytes[0..buffer_len];
        }
        const bytes = sh.server.gpa.alignedAlloc(u8, .of(FreeBuffer), buffer_len) catch return null;
        return bytes;
    }

    fn giveBuffer(sh: *Shard, buffer: []u8) void {
        if (sh.free_buffer_count == max_free_buffers) {
            const bytes: []align(@alignOf(FreeBuffer)) u8 = @alignCast(buffer);
            sh.server.gpa.free(bytes);
            return;
        }
        const b: *FreeBuffer = @ptrCast(@alignCast(buffer.ptr));
        b.* = .{ .next = sh.free_buffers };
        sh.free_buffers = b;
        sh.free_buffer_count += 1;
    }

    /// Close `conn`. The shard frees it later (see `bury`).
    fn close(sh: *Shard, conn: *Connection) void {
        if (conn.state == .closed) return;
        std.debug.assert(conn.state != .busy);
        if (conn.moving) {
            // `bury` can free the connection before `moveConnections` runs.
            for (sh.to_move.items, 0..) |c, i| if (c == conn) {
                _ = sh.to_move.swapRemove(i);
                break;
            };
            conn.moving = false;
        }
        unlist(conn);
        if (conn.in_poller) sh.poller.remove(&conn.slot);
        conn.stream.close(sh.server.io);
        conn.state = .closed;
        sh.graveyard.push(conn);
    }

    /// Free the closed connections whose socket the poller does not use any more.
    fn bury(sh: *Shard) void {
        const self = sh.server;
        var it = sh.graveyard.head;
        while (it) |conn| {
            it = conn.next;
            if (!conn.slot.quiet()) continue;
            sh.graveyard.remove(conn);
            conn.in.deinit(self.gpa);
            if (conn.pending_out) |p| self.gpa.free(p);
            self.gpa.destroy(conn);
            self.releasePermit();
            _ = sh.assigned.fetchSub(1, .seq_cst);
        }
    }
};

/// One plaintext connection. Its shard owns it. While a worker task runs a request of the
/// connection, the task uses only `job`, `in` and the socket for its writes. The shard does
/// not change them then.
const Connection = struct {
    shard: *Shard,
    stream: Io.net.Stream,
    /// The awake time of the accept, in nanoseconds.
    accepted_at: i64,
    state: State = .new,
    /// The readiness state of the socket in the poller of the shard.
    slot: park.Slot = .{},
    in_poller: bool = false,
    /// The list of the shard that has the connection, and the links in it.
    list: ?*List = null,
    prev: ?*Connection = null,
    next: ?*Connection = null,
    /// The time limit of the list, an awake time in nanoseconds or `unlimited`.
    deadline: i64 = unlimited,
    /// The awake time at which the connection went to `Shard.parked` (for the eviction at
    /// `max_connections`: also without `idle_timeout`, the oldest one goes first).
    parked_at: i64 = 0,
    /// The link in `Shard.inbox`.
    inbox_next: ?*Connection = null,
    /// The bytes of a request that are not complete, or of the requests after one that runs.
    in: std.ArrayList(u8) = .empty,
    /// True when the head of the request in `in` is complete.
    in_body: bool = false,
    /// What the last look found in `in`.
    scan: Scan = .{},
    /// The peer closed its side, or the connection. A request that comes after it, or with
    /// it, gets the cancel at its start (as before the shards: the read of the task saw the
    /// end).
    peer_closed: bool = false,
    /// The connection served one request or more.
    served: bool = false,
    /// `100 Continue` went out for the request in `in`.
    continue_sent: bool = false,
    /// Bytes arrived while a worker task ran, or while the shard sent a response.
    data_seen: bool = false,
    /// The peer closed while a worker task ran.
    hangup_seen: bool = false,
    /// The part of a response that the shard could not send without a wait.
    pending_out: ?[]u8 = null,
    pending_sent: usize = 0,
    /// Close the connection after `pending_out`.
    close_after_send: bool = false,
    /// The request in a worker task.
    job: Job = .{},
    /// The connection is in `Shard.to_move`.
    moving: bool = false,

    const State = enum(u8) {
        /// In the inbox, from the accept loop.
        new,
        /// The shard waits for bytes, or reads them.
        reading,
        /// A complete request waits for a worker task.
        ready,
        /// A worker task runs a request.
        busy,
        /// The shard sends the rest of a response.
        sending,
        /// In the inbox of another shard, which takes the connection.
        moved,
        closed,
    };

    const Job = struct {
        /// The length of the request at the start of `in`.
        len: usize = 0,
        /// The body was larger than `max_body_bytes` and is not in `in`. The connection
        /// closes after the response.
        body_skipped: bool = false,
        /// The cancel token of the request. The shard cancels it when the peer closes.
        token: Transport.CancelToken = .{},
        /// The write buffer of the task.
        buffer: ?[]u8 = null,
        /// Set by the task: the connection can carry one more request.
        reuse: bool = false,
    };

    /// No time limit.
    const unlimited: i64 = std.math.maxInt(i64);

    /// The worker task of one request that is not quick. It writes the response to the
    /// socket, and gives the connection back to its shard.
    fn runJob(conn: *Connection) void {
        const sh = conn.shard;
        const self = sh.server;
        const io = self.io;
        var reuse = false;
        {
            var reader: Io.Reader = .fixed(conn.in.items[0..conn.job.len]);
            var writer = conn.stream.writer(io, conn.job.buffer.?);
            var http_server: http.Server = .init(&reader, &writer.interface);
            if (http_server.receiveHead()) |head| {
                var request = head;
                var rc: RequestContext = .{ .owner = self, .mode = .job, .peer = conn.stream.socket.address, .token = &conn.job.token };
                const keep_alive = handleRequest(&rc, &request) catch false;
                reuse = keep_alive and request.head.keep_alive and !conn.job.body_skipped;
                writer.interface.flush() catch {
                    reuse = false;
                };
            } else |_| {}
        }
        conn.job.reuse = reuse;
        self.endTask(true);
        // The last use of `conn` in this task.
        sh.post(conn);
    }
};

// -- Request framing ---------------------------------------------------------------------------

const Reject = enum { bad_request, head_too_large, body_too_large, expectation_failed };

const Frame = union(enum) {
    /// The request is not complete. `in_body`: its head is.
    need_more: struct { in_body: bool, expect_continue: bool },
    /// A complete request of `len` bytes at the start of the data.
    complete: struct {
        len: usize,
        /// `McpServer.isQuickMethod` accepts its `Mcp-Method` and `Mcp-Name` headers.
        quick: bool,
        /// Only the head is in `len`: the body is larger than `max_body_bytes`.
        body_skipped: bool,
    },
    reject: Reject,
};

/// Find the end of the request at the start of `data`.
fn frameRequest(self: *Server, data: []const u8, scan: *Scan) Frame {
    const limits = self.limits.http;
    // The bytes of the last look did not complete the request: look only at the new bytes.
    if (scan.need != 0) {
        if (data.len < scan.need) return .{ .need_more = .{ .in_body = true, .expect_continue = false } };
    } else if (!scan.head_done) {
        if (!hasHeadEnd(data, scan.head_checked -| 3)) {
            if (data.len >= limits.max_head_bytes) return .{ .reject = .head_too_large };
            scan.head_checked = data.len;
            return .{ .need_more = .{ .in_body = false, .expect_continue = false } };
        }
    }
    const head = switch (scanHead(data, limits.max_head_bytes)) {
        .need_more => return .{ .need_more = .{ .in_body = false, .expect_continue = false } },
        .reject => |r| return .{ .reject = r },
        .head => |h| h,
    };
    scan.head_done = true;
    if (head.chunked) {
        return switch (chunkedLength(data[head.len..], limits.max_body_bytes, &scan.chunk)) {
            .need_more => .{ .need_more = .{ .in_body = true, .expect_continue = head.expect_continue } },
            .bad => .{ .reject = .bad_request },
            .too_large => .{ .reject = .body_too_large },
            .done => |n| .{ .complete = .{ .len = head.len + n, .quick = false, .body_skipped = false } },
        };
    }
    const length = head.content_length orelse 0;
    if (length > limits.max_body_bytes) return .{ .complete = .{ .len = head.len, .quick = false, .body_skipped = true } };
    const total = head.len + length;
    if (data.len < total) {
        scan.need = total;
        return .{ .need_more = .{ .in_body = true, .expect_continue = head.expect_continue } };
    }
    const quick = !head.expect_continue and head.method != null and self.server.isQuickMethod(head.method.?, head.name);
    return .{ .complete = .{ .len = total, .quick = quick, .body_skipped = false } };
}

/// What the shard knows about the request at the start of `Connection.in` from its last
/// look. Thus a request that arrives in many small parts costs no new scan from its start
/// for each part.
const Scan = struct {
    /// The count of bytes without the end of the head.
    head_checked: usize = 0,
    head_done: bool = false,
    /// The length of the request with `Content-Length`, or zero.
    need: usize = 0,
    /// The chunks of a chunked body that are complete.
    chunk: ChunkState = .{},
};

/// True when `data[from..]` has the end of a request head: an empty line, also after a bare
/// LF, as `std.http.HeadParser` finds it.
fn hasHeadEnd(data: []const u8, from: usize) bool {
    var i = from;
    while (std.mem.findScalarPos(u8, data, i, '\n')) |nl| : (i = nl + 1) {
        if (nl + 1 < data.len and data[nl + 1] == '\n') return true;
        if (nl + 2 < data.len and data[nl + 1] == '\r' and data[nl + 2] == '\n') return true;
    }
    return false;
}

/// The fields of a request head that the shard needs.
const HeadInfo = struct {
    /// The length of the head with its last empty line.
    len: usize,
    content_length: ?usize = null,
    chunked: bool = false,
    expect_continue: bool = false,
    /// `Mcp-Method` and `Mcp-Name`. Null when absent or present two times.
    method: ?[]const u8 = null,
    name: ?[]const u8 = null,
};

const HeadScan = union(enum) { need_more, reject: Reject, head: HeadInfo };

/// Read the head at the start of `data`. The head must end with the first `"\r\n\r\n"`, as
/// `std.http.HeadParser` finds it, and each line must end with `"\r\n"`. Thus this scan and
/// the HTTP parser of the request see the same header lines.
fn scanHead(data: []const u8, max_head: usize) HeadScan {
    var parser: http.HeadParser = .{};
    const head_len = parser.feed(data);
    if (parser.state != .finished) return if (data.len >= max_head) .{ .reject = .head_too_large } else .need_more;
    if (head_len > max_head) return .{ .reject = .head_too_large };
    const head = data[0..head_len];
    if (head_len < 4 or !std.mem.endsWith(u8, head, "\r\n\r\n")) return .{ .reject = .bad_request };
    // A bare LF or CR: other parsers can end a line there.
    for (head, 0..) |c, i| switch (c) {
        '\n' => if (i == 0 or head[i - 1] != '\r') return .{ .reject = .bad_request },
        '\r' => if (i + 1 == head.len or head[i + 1] != '\n') return .{ .reject = .bad_request },
        else => {},
    };
    var info: HeadInfo = .{ .len = head_len };
    var have_transfer = false;
    var methods_seen: u8 = 0;
    var names_seen: u8 = 0;
    var lines = std.mem.splitSequence(u8, head[0 .. head_len - 4], "\r\n");
    const request_line = lines.next() orelse return .{ .reject = .bad_request };
    if (request_line.len == 0) return .{ .reject = .bad_request };
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse return .{ .reject = .bad_request };
        const key = line[0..colon];
        // A field name is a token: no white space before the colon (RFC 9112 section 5.1).
        if (key.len == 0 or std.mem.findAny(u8, key, " \t") != null) return .{ .reject = .bad_request };
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(key, "content-length")) {
            if (info.content_length != null) return .{ .reject = .bad_request };
            info.content_length = parseDigits(value, 10) orelse return .{ .reject = .bad_request };
        } else if (std.ascii.eqlIgnoreCase(key, "transfer-encoding")) {
            if (have_transfer or !std.ascii.eqlIgnoreCase(value, "chunked")) return .{ .reject = .bad_request };
            have_transfer = true;
            info.chunked = true;
        } else if (std.ascii.eqlIgnoreCase(key, "expect")) {
            if (info.expect_continue or !std.ascii.eqlIgnoreCase(value, "100-continue")) return .{ .reject = .expectation_failed };
            info.expect_continue = true;
        } else if (std.ascii.eqlIgnoreCase(key, envelope.header_method)) {
            methods_seen +|= 1;
            info.method = value;
        } else if (std.ascii.eqlIgnoreCase(key, envelope.header_name)) {
            names_seen +|= 1;
            info.name = value;
        }
    }
    // Both framings: a request smuggling attempt (RFC 9112 section 6.1).
    if (info.chunked and info.content_length != null) return .{ .reject = .bad_request };
    if (methods_seen != 1) info.method = null;
    if (names_seen > 1) info.method = null;
    return .{ .head = info };
}

const Chunked = union(enum) { need_more, bad, too_large, done: usize };

/// The chunks of a chunked body that are complete: the bytes, and their data bytes.
const ChunkState = struct { pos: usize = 0, total: usize = 0 };

/// A number of digits only, without a sign or a separator, as `Content-Length` and a chunk
/// size have it (RFC 9112 sections 6.2 and 7.1). Null for another text or an overflow.
fn parseDigits(text: []const u8, base: u8) ?usize {
    if (text.len == 0) return null;
    var n: usize = 0;
    for (text) |c| {
        const d = std.fmt.charToDigit(c, base) catch return null;
        n = std.math.mul(usize, n, base) catch return null;
        n = std.math.add(usize, n, d) catch return null;
    }
    return n;
}

/// True when `line` has no CR, LF or other control byte, except a tab.
fn isPlainLine(line: []const u8) bool {
    for (line) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return false;
    return true;
}

/// The length of the chunked body at the start of `data`, with its trailer section (RFC 9112
/// section 7.1). The data bytes of the chunks must not pass `max_body`.
fn chunkedLength(data: []const u8, max_body: usize, state: *ChunkState) Chunked {
    // The longest chunk size line, and the longest trailer section.
    const max_line = 1024;
    const max_trailers = 16 * 1024;
    var pos: usize = state.pos;
    var total: usize = state.total;
    while (true) {
        const end = std.mem.findPos(u8, data, pos, "\r\n") orelse return if (data.len - pos > max_line) .bad else .need_more;
        const line = data[pos..end];
        if (!isPlainLine(line)) return .bad;
        const size_text = line[0 .. std.mem.findScalar(u8, line, ';') orelse line.len];
        const size = parseDigits(size_text, 16) orelse return if (size_text.len > 16 and std.mem.trimStart(u8, size_text, "0").len > 16) .too_large else .bad;
        pos = end + 2;
        if (size == 0) {
            const trailers_start = pos;
            while (true) {
                const e = std.mem.findPos(u8, data, pos, "\r\n") orelse return if (data.len - trailers_start > max_trailers) .bad else .need_more;
                if (!isPlainLine(data[pos..e])) return .bad;
                if (e == pos) return .{ .done = e + 2 };
                pos = e + 2;
            }
        }
        total = std.math.add(usize, total, size) catch return .too_large;
        if (total > max_body) return .too_large;
        if (data.len - pos < size +| 2) return .need_more;
        if (!std.mem.eql(u8, data[pos + size .. pos + size + 2], "\r\n")) return .bad;
        pos += size + 2;
        state.* = .{ .pos = pos, .total = total };
    }
}

// -- TLS connections ---------------------------------------------------------------------------

/// A TLS connection, with one task that does the TLS handshake, reads the requests and runs
/// them. The reads of the socket obey the time limits themselves (see `awaitInput`). The
/// handler of a request runs in a task of its own. Meanwhile the task of the connection
/// reads the socket, and a disconnect of the client cancels the request.
const TlsConn = struct {
    owner: *Server,
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader = undefined,
    /// The time limit of the read that the task does now: an awake time in nanoseconds,
    /// `busy` or `unlimited`. The task and its handler change it.
    deadline: std.atomic.Value(i64) = .init(busy),
    /// What the task waits for.
    phase: std.atomic.Value(Phase) = .init(.busy),
    /// A read did not end in its time limit.
    timed_out: std.atomic.Value(bool) = .init(false),

    const Phase = enum(u8) {
        /// The TLS handshake or a request head.
        head,
        /// The first byte of the next request.
        idle,
        /// The rest of a request body.
        body,
        /// The close by the client, after a response without keep-alive.
        close,
        busy,
    };

    /// The task runs a handler or writes a response. No time limit applies, and the shutdown
    /// does not stop a read.
    const busy: i64 = 0;
    const unlimited: i64 = std.math.maxInt(i64);
    /// The longest wait of one poll in `awaitInput`. The task looks at the shutdown after it.
    const poll_slice_ns: i64 = 250 * std.time.ns_per_ms;

    fn run(owner: *Server, stream: Io.net.Stream, accepted_at: i64) void {
        var tc: TlsConn = .{ .owner = owner, .stream = stream };
        _ = tc.serve(accepted_at) catch {};
        stream.close(owner.io);
        owner.releasePermit();
        owner.endTask(false);
    }

    /// Set the time limit of the next read to `limit` from now. Zero means no limit.
    fn startTimer(tc: *TlsConn, phase: Phase, limit: Io.Duration) void {
        tc.phase.store(phase, .release);
        tc.deadline.store(deadlineAfter(nowNanoseconds(tc.owner.io), limit), .release);
    }

    /// As `startTimer`, but keep a time limit that runs already.
    fn continueTimer(tc: *TlsConn, phase: Phase, limit: Io.Duration) void {
        if (tc.deadline.load(.acquire) != busy) return;
        tc.startTimer(phase, limit);
    }

    /// Remove the time limit while the task is busy.
    fn stopTimer(tc: *TlsConn) void {
        tc.phase.store(.busy, .release);
        tc.deadline.store(busy, .release);
    }

    fn timedOut(tc: *TlsConn) bool {
        return tc.timed_out.load(.acquire);
    }

    /// Tell the client about a request head or body that did not arrive in time. The server
    /// closes an idle connection without a response (RFC 9112 section 9.6), and sends nothing
    /// at the shutdown.
    fn sendTimeout(tc: *TlsConn, out: *Io.Writer) void {
        const phase = tc.phase.load(.acquire);
        if (phase != .head and phase != .body) return;
        if (tc.owner.closing.load(.acquire)) return;
        out.writeAll(request_timeout_response) catch return;
        out.flush() catch {};
    }

    const std_vtable: *const Io.Reader.VTable = Io.net.Stream.Reader.init(undefined, undefined, &.{}).interface.vtable;

    const timed_vtable: Io.Reader.VTable = .{
        .stream = timedStream,
        .discard = std_vtable.discard,
        .readVec = timedReadVec,
        .rebase = std_vtable.rebase,
    };

    fn timedStream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        try awaitInput(io_r);
        return std_vtable.stream(io_r, io_w, limit);
    }

    fn timedReadVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        try awaitInput(io_r);
        return std_vtable.readVec(io_r, data);
    }

    /// Wait until the socket has bytes, the peer closed, the time limit passed, or the
    /// server stops. A busy connection reads without a wait: its read is the disconnect
    /// watch of a handler, and the task of the connection cancels it.
    fn awaitInput(io_r: *Io.Reader) error{ReadFailed}!void {
        const r: *Io.net.Stream.Reader = @alignCast(@fieldParentPtr("interface", io_r));
        const tc: *TlsConn = @alignCast(@fieldParentPtr("reader", r));
        const io = tc.owner.io;
        while (true) {
            const d = tc.deadline.load(.acquire);
            if (d == busy) return;
            if (tc.owner.closing.load(.acquire)) {
                r.err = error.Canceled;
                return error.ReadFailed;
            }
            const now = nowNanoseconds(io);
            if (d != unlimited and now >= d) {
                tc.timed_out.store(true, .release);
                r.err = error.ConnectionTimedOut;
                return error.ReadFailed;
            }
            const wait_ns = @min(if (d == unlimited) poll_slice_ns else d - now, poll_slice_ns);
            if (waitReadable(io, tc.stream.socket.handle, wait_ns)) return else |e| switch (e) {
                error.Timeout => {},
                error.Canceled => {
                    r.err = error.Canceled;
                    return error.ReadFailed;
                },
            }
        }
    }

    /// Read and handle requests until the connection ends. The TLS handshake and the head
    /// of the first request obey `limits.http.head_timeout` from the accept. The wait for
    /// the next request obeys `limits.http.idle_timeout`, and its head obeys `head_timeout`
    /// from its first byte.
    fn serve(tc: *TlsConn, accepted_at: i64) !void {
        const self = tc.owner;
        const io = self.io;
        tc.phase.store(.head, .release);
        tc.deadline.store(deadlineAfter(accepted_at, self.limits.http.head_timeout), .release);
        const read_buf = try self.gpa.alloc(u8, @max(self.limits.http.max_head_bytes + 4096, tls.Connection.min_input_buffer_len));
        defer self.gpa.free(read_buf);
        const write_buf = try self.gpa.alloc(u8, tls.Connection.min_output_buffer_len);
        defer self.gpa.free(write_buf);
        tc.reader = tc.stream.reader(io, read_buf);
        tc.reader.interface.vtable = &timed_vtable;
        var writer = tc.stream.writer(io, write_buf);

        // With TLS, the HTTP server reads and writes plaintext through the TLS connection.
        const s = try self.gpa.create(TlsState);
        defer self.gpa.destroy(s);
        s.conn = try self.options.tls.?.accept(&tc.reader.interface, &writer.interface, .{
            .io = io,
            .read_buffer = &s.read_buf,
            .write_buffer = &s.write_buf,
            .allow_truncation_attacks = true,
        });
        defer {
            s.conn.end() catch {};
            s.conn.deinit();
        }
        const in: *Io.Reader = &s.conn.reader;
        const out: *Io.Writer = &s.conn.writer;
        var http_server: http.Server = .init(in, out);
        var first = true;
        while (!self.closing.load(.acquire)) {
            if (!first) {
                // Wait for the first byte of the next request. A time limit that runs already
                // (from the end of the last handler) continues.
                tc.continueTimer(.idle, self.limits.http.idle_timeout);
                _ = in.peekByte() catch return;
                tc.startTimer(.head, self.limits.http.head_timeout);
            }
            first = false;
            var request = http_server.receiveHead() catch |e| switch (e) {
                error.HttpConnectionClosing => return,
                error.HttpHeadersOversize => {
                    out.writeAll("HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                    out.flush() catch {};
                    return;
                },
                else => {
                    if (tc.timedOut()) tc.sendTimeout(out);
                    return;
                },
            };
            tc.stopTimer();
            var rc: RequestContext = .{ .owner = self, .mode = .stream, .peer = tc.stream.socket.address, .tls = tc };
            const keep_alive = handleRequest(&rc, &request) catch false;
            if (tc.timedOut()) {
                tc.sendTimeout(out);
                return;
            }
            if (!keep_alive or !request.head.keep_alive) return;
        }
    }

    /// Watch the socket while the handler of a request runs, in a task. A close by the peer
    /// cancels the request. The read fills only the free space at the end of the buffer.
    /// Thus the bytes of a pipelined next request stay for the next read. The task of the
    /// connection cancels this task when the handler ends. The cancel of the read does not
    /// look like a disconnect, because `ended` is set.
    fn watch(tc: *TlsConn, dispatch: *Dispatch) void {
        const io = tc.owner.io;
        const socket = &tc.reader;
        const r = &socket.interface;
        while (r.end < r.buffer.len) {
            if (dispatch.exchange.token.isCancelled() or dispatch.ended.load(.acquire)) return;
            r.fillMore() catch |e| {
                if (e == error.ReadFailed) if (socket.err) |err| if (err == error.Canceled) return;
                if (dispatch.ended.load(.acquire)) return;
                log.debug("the client of request {f} disconnected", .{dispatch.exchange.id});
                dispatch.exchange.token.cancel(io, disconnect_reason);
                return;
            };
            if (dispatch.ended.load(.acquire)) return;
        }
    }
};

/// Wait at most `ns` nanoseconds until `handle` has bytes or the peer closed. A cancel of
/// the task ends the wait.
fn waitReadable(io: Io, handle: Io.net.Socket.Handle, ns: i64) error{ Timeout, Canceled }!void {
    if (park.is_windows) {
        const windows = std.os.windows;
        const PollInfo = extern struct {
            timeout: i64,
            count: u32,
            exclusive: u32,
            handle: windows.HANDLE,
            events: u32,
            status: windows.NTSTATUS,
        };
        // A negative value is a relative time in units of 100 nanoseconds.
        var info: PollInfo = .{ .timeout = -@as(i64, @max(1, @divTrunc(ns, 100))), .count = 1, .exclusive = 0, .handle = handle, .events = 0x1 | 0x8 | 0x10 | 0x20, .status = .SUCCESS };
        const result = io.operate(.{ .device_io_control = .{
            .file = .{ .handle = handle, .flags = .{ .nonblocking = true } },
            .code = windows.IOCTL.AFD.POLL,
            .in = std.mem.asBytes(&info),
            .out = std.mem.asBytes(&info),
        } }) catch return error.Canceled;
        return switch (result.device_io_control.u.Status) {
            .TIMEOUT => error.Timeout,
            .SUCCESS => if (info.count == 0 or info.events == 0) error.Timeout else {},
            // The read after it reports the failure.
            else => {},
        };
    }
    const posix = std.posix;
    var fds = [1]posix.pollfd{.{ .fd = handle, .events = posix.POLL.IN, .revents = 0 }};
    const ms: i32 = @intCast(@max(1, @divFloor(ns + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
    const rc = posix.system.poll(&fds, 1, ms);
    io.checkCancel() catch return error.Canceled;
    switch (posix.errno(rc)) {
        .SUCCESS => return if (rc == 0) error.Timeout else {},
        .INTR => return error.Timeout,
        else => return,
    }
}

/// The TLS state of one connection.
const TlsState = struct {
    conn: tls.Connection,
    read_buf: [tls.Connection.min_read_buffer_len]u8,
    write_buf: [16 * 1024]u8,
};

// -- Requests ----------------------------------------------------------------------------------

/// Where a request runs.
const RequestContext = struct {
    owner: *Server,
    mode: Mode,
    /// The address of the client.
    peer: Io.net.IpAddress,
    /// `.job`: the cancel token in the connection. The shard cancels it when the peer closes.
    token: ?*Transport.CancelToken = null,
    /// `.stream`: the TLS connection.
    tls: ?*TlsConn = null,

    const Mode = enum {
        /// In the shard, with the complete request in memory and the response to a buffer.
        inline_,
        /// In a worker task, with the complete request in memory and the response to the
        /// socket. The shard watches the socket.
        job,
        /// In the task of a TLS connection, with the body from the socket.
        stream,
    };
};

/// Everything the transport needs from the request head, copied before the body is read.
const Head = struct {
    method: http.Method,
    path: []const u8,
    content_type: ?[]const u8 = null,
    accept: ?[]const u8 = null,
    origin: ?[]const u8 = null,
    host: ?[]const u8 = null,
    authorization: ?[]const u8 = null,
    /// The values of the `DPoP` headers.
    dpop: []const []const u8 = &.{},
    content_length: ?u64 = null,
    envelope_headers: envelope.Headers = .{},
};

fn copyHead(arena: Allocator, request: *http.Server.Request) !Head {
    const target = request.head.target;
    const path_end = std.mem.findScalar(u8, target, '?') orelse target.len;
    var head: Head = .{
        .method = request.head.method,
        .path = try arena.dupe(u8, target[0..path_end]),
        .content_length = request.head.content_length,
    };
    var params: std.ArrayList(envelope.Headers.Param) = .empty;
    var proofs: std.ArrayList([]const u8) = .empty;
    var it = request.iterateHeaders();
    while (it.next()) |h| {
        var name_buf: [128]u8 = undefined;
        if (h.name.len > name_buf.len) continue;
        const name = std.ascii.lowerString(&name_buf, h.name);
        const value = try arena.dupe(u8, h.value);
        if (std.mem.eql(u8, name, "content-type")) head.content_type = value;
        if (std.mem.eql(u8, name, "accept")) head.accept = value;
        if (std.mem.eql(u8, name, "origin")) head.origin = value;
        if (std.mem.eql(u8, name, "host")) head.host = value;
        if (std.mem.eql(u8, name, "authorization")) head.authorization = value;
        if (std.mem.eql(u8, name, "dpop")) try proofs.append(arena, value);
        if (std.mem.eql(u8, name, envelope.header_protocol_version)) head.envelope_headers.protocol_version = value;
        if (std.mem.eql(u8, name, envelope.header_method)) head.envelope_headers.method = value;
        if (std.mem.eql(u8, name, envelope.header_name)) head.envelope_headers.name = value;
        if (std.mem.startsWith(u8, name, envelope.header_param_prefix)) {
            try params.append(arena, .{ .name = try arena.dupe(u8, name[envelope.header_param_prefix.len..]), .value = value });
        }
    }
    head.envelope_headers.params = params.items;
    head.dpop = proofs.items;
    return head;
}

fn acceptsBoth(accept: []const u8) bool {
    return std.mem.find(u8, accept, "application/json") != null and std.mem.find(u8, accept, "text/event-stream") != null or std.mem.find(u8, accept, "*/*") != null;
}

const json_headers = [_]http.Header{.{ .name = "content-type", .value = "application/json" }};

fn statusForCode(code: i64) http.Status {
    return switch (code) {
        -32700, -32600, -32602, -32020, -32021, -32022 => .bad_request,
        -32601 => .not_found,
        @backingInt(errors.Code.rate_limited) => .too_many_requests,
        else => .ok,
    };
}

/// The value of `Retry-After` for an error with `data.retryAfterMs`: whole seconds, rounded
/// up, at least 1 (RFC 9110 section 10.2.3). Null when the error has no such field.
fn retryAfterSeconds(err: Value) ?u64 {
    const data = err.object.get("data") orelse return null;
    if (data != .object) return null;
    const ms = data.object.get("retryAfterMs") orelse return null;
    if (ms != .integer or ms.integer < 0) return null;
    const ms_u: u64 = @intCast(ms.integer);
    return @max(1, ms_u / std.time.ms_per_s + @intFromBool(ms_u % std.time.ms_per_s != 0));
}

/// Handle one request. Returns whether the connection can carry one more request.
fn handleRequest(rc: *RequestContext, request: *http.Server.Request) !bool {
    const self = rc.owner;
    var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const head = try copyHead(arena, request);

    // Router. The protected resource metadata lives at the path-inserted well-known location.
    if (self.options.auth) |auth| {
        const prm_path = try std.mem.concat(arena, u8, &.{ "/.well-known/oauth-protected-resource", self.options.path });
        if (std.mem.eql(u8, head.path, prm_path)) {
            if (head.method != .GET) {
                try request.respond("", .{ .status = .method_not_allowed, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "allow", .value = "GET" }} });
                return true;
            }
            const doc = try auth.metadataJson(arena);
            try request.respond(doc, .{ .status = .ok, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }} });
            return true;
        }
    }
    if (!std.mem.eql(u8, head.path, self.options.path)) {
        try request.respond("Not Found", .{ .status = .not_found, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "content-type", .value = "text/plain" }} });
        return true;
    }
    if (head.method != .POST) {
        try request.respond("", .{ .status = .method_not_allowed, .keep_alive = request.head.keep_alive, .extra_headers = &.{.{ .name = "allow", .value = "POST" }} });
        return true;
    }
    // Origin and Host validation (DNS rebinding protection).
    if (head.origin) |origin| {
        if (!self.originAllowed(origin)) {
            try respondErrorOptions(request, .forbidden, null, errors.invalidRequest("Origin not allowed"), false);
            return false;
        }
    }
    if (head.host) |host| {
        if (!self.hostAllowed(host)) {
            try respondErrorOptions(request, .forbidden, null, errors.invalidRequest("Host not allowed"), false);
            return false;
        }
    }
    // Authorization comes before any look at the body.
    var principal: ?*resource_server.Principal = null;
    if (self.options.auth) |auth| {
        switch (try auth.authorizeRequest(arena, .{ .authorization = head.authorization, .dpop = head.dpop, .method = @tagName(head.method) })) {
            .ok => |p| {
                const owned = try arena.create(resource_server.Principal);
                owned.* = p;
                principal = owned;
            },
            .challenge => |c| {
                var buf: [3]http.Header = undefined;
                var headers: std.ArrayList(http.Header) = .empty;
                try headers.appendSlice(arena, c.headers(&buf));
                try headers.append(arena, .{ .name = "content-type", .value = "application/json" });
                try request.respond(c.body, .{
                    .status = @fromBackingInt(@intCast(c.status)),
                    .keep_alive = request.head.keep_alive,
                    .extra_headers = headers.items,
                });
                return true;
            },
        }
    }
    if (head.content_type) |ct| {
        if (!std.ascii.startsWithIgnoreCase(ct, "application/json")) {
            try request.respond("", .{ .status = .unsupported_media_type, .keep_alive = request.head.keep_alive });
            return true;
        }
    }
    if (self.options.response_mode != .json) {
        if (head.accept) |accept| {
            if (!acceptsBoth(accept)) {
                try request.respond("", .{ .status = .not_acceptable, .keep_alive = request.head.keep_alive });
                return true;
            }
        }
    }
    if (head.content_length) |len| {
        if (len > self.limits.http.max_body_bytes) {
            try request.respond("", .{ .status = .payload_too_large, .keep_alive = false });
            return false;
        }
    }
    // Body. A request without Content-Length and without Transfer-Encoding has an empty
    // body (RFC 9112 section 6.3). Without this, std reads the connection until EOF.
    if (request.head.transfer_encoding == .none and request.head.content_length == null) {
        request.head.content_length = 0;
    }
    // The shard read the whole request, and sent `100 Continue` for a body that waited. A
    // TLS connection sends it now.
    if (request.head.expect != null) {
        if (rc.mode == .stream) request.writeExpectContinue() catch return false;
        request.head.expect = null;
    }
    // The body obeys `limits.http.idle_timeout` from the end of the head.
    if (rc.tls) |t| t.startTimer(.body, self.limits.http.idle_timeout);
    // `allocRemaining` streams the body into `arena` and does not use the buffer of the
    // reader. Without a buffer, a safe build does not fill one on each request.
    const body_reader = request.readerExpectNone(&.{});
    const body = body_reader.allocRemaining(arena, .limited(self.limits.http.max_body_bytes)) catch |e| switch (e) {
        error.StreamTooLong => {
            try request.respond("", .{ .status = .payload_too_large, .keep_alive = false });
            return false;
        },
        error.OutOfMemory => return error.OutOfMemory,
        error.ReadFailed => return false,
    };
    if (rc.tls) |t| {
        if (t.timedOut()) return false;
        t.stopTimer();
    }
    const msg = jsonrpc.Message.parseMaxDepth(arena, body, self.limits.json_max_depth) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Syntax => {
            try respondError(request, .bad_request, null, errors.parseError("Parse error"));
            return true;
        },
        error.Invalid, error.InvalidId => {
            try respondError(request, .bad_request, null, errors.invalidRequest("Invalid Request"));
            return true;
        },
    };
    switch (msg) {
        .notification => {
            try request.respond("", .{ .status = .accepted, .keep_alive = request.head.keep_alive });
            return true;
        },
        .response, .error_response => {
            try respondError(request, .bad_request, null, errors.invalidRequest("Clients must not send responses"));
            return true;
        },
        .request => |req| return handleRpcRequest(rc, request, arena, head, req, principal),
    }
}

fn respondError(request: *http.Server.Request, status: http.Status, id: ?RequestId, err: errors.RpcError) !void {
    try respondErrorOptions(request, status, id, err, true);
}

fn respondErrorOptions(request: *http.Server.Request, status: http.Status, id: ?RequestId, err: errors.RpcError, keep_alive: bool) !void {
    var buf: [2048]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var aw: Io.Writer.Allocating = .init(fba.allocator());
    message.writeErrorResponse(&aw.writer, id, err.toWire()) catch return;
    try request.respond(aw.written(), .{ .status = status, .keep_alive = keep_alive and request.head.keep_alive, .extra_headers = &json_headers });
}

fn handleRpcRequest(rc: *RequestContext, request: *http.Server.Request, arena: Allocator, head: Head, req: jsonrpc.Message.Request, principal: ?*resource_server.Principal) !bool {
    const self = rc.owner;
    // Header presence, mirror validation and version support run before dispatch on HTTP.
    const annotations = if (std.mem.eql(u8, req.method, "tools/call")) toolHeaders(self, req.params) else null;
    if (try envelope.verifyAnnotated(arena, head.envelope_headers, req.method, req.params, annotations)) |rejection| {
        // A legacy client without headers gets a clear version message.
        if (head.envelope_headers.protocol_version == null and std.mem.eql(u8, req.method, "initialize")) {
            const err = try errors.unsupportedProtocolVersion(arena, &version.supported_versions, "unknown");
            try respondError(request, .bad_request, req.id, err);
            return true;
        }
        try respondError(request, .bad_request, req.id, try rejection.rpcError(arena));
        return true;
    }

    var local_token: Transport.CancelToken = .{};
    const token = rc.token orelse &local_token;
    var exchange: Exchange = .{
        .owner = self,
        .request = request,
        .arena = arena,
        .id = req.id,
        .token = token,
        .long_lived = std.mem.eql(u8, req.method, "subscriptions/listen"),
        .force_sse = self.options.response_mode == .sse,
        // In a shard, only this task writes the response.
        .shared = rc.mode != .inline_,
    };
    var dispatch: Dispatch = .{ .rc = rc, .exchange = &exchange, .req = req, .principal = principal, .arena = arena };
    switch (rc.mode) {
        .inline_ => {
            // The headers said quick. The shard runs only a request that is quick by its body
            // too. A request that is not ends with an error and the close of the connection.
            const tool = if (req.params) |params| json.getString(params, "name") else null;
            if (!self.server.isQuickMethod(req.method, tool)) {
                try respondErrorOptions(request, .service_unavailable, req.id, errors.internalError("the request does not match its Mcp-Method and Mcp-Name headers"), false);
                return false;
            }
            // Nothing cancels the handler, as on the reader of a stream transport.
            dispatch.run();
        },
        // The shard watches the socket, and cancels `token` when the client disconnects. A
        // cancel of this task (at the end of the shutdown grace) cancels the handler.
        .job => dispatch.run(),
        .stream => {
            // The handler runs in a task of its own. Meanwhile a watch task reads the socket,
            // and the task of the connection cancels it when the handler ends.
            const tc = rc.tls.?;
            var handler: ?Io.Future(void) = self.io.concurrent(Dispatch.run, .{&dispatch}) catch null;
            if (handler) |*h| {
                var watcher: ?Io.Future(void) = self.io.concurrent(TlsConn.watch, .{ tc, &dispatch }) catch null;
                if (watcher == null) tc.watch(&dispatch);
                if (dispatch.done.wait(self.io)) |_| {
                    h.await(self.io);
                } else |_| {
                    h.cancel(self.io);
                }
                // Stop the watch task. The handler ended, thus `ended` is set and the cancel of
                // the read does not look like a disconnect. The bytes it read stay in the buffer.
                if (watcher) |*w| {
                    dispatch.ended.store(true, .release);
                    w.cancel(self.io);
                }
            } else dispatch.run();
        },
    }
    // The connection of a canceled request does not carry one more request.
    return exchange.reusable and !token.isCancelled() and request.head.keep_alive;
}

/// The cancellation reason of a request whose client closed the connection.
pub const disconnect_reason = "client disconnected";

/// The handler of a request and the end of its response.
const Dispatch = struct {
    rc: *RequestContext,
    exchange: *Exchange,
    req: jsonrpc.Message.Request,
    principal: ?*resource_server.Principal,
    arena: Allocator,
    /// Set when the run ended.
    ended: std.atomic.Value(bool) = .init(false),
    /// Set when the run ended. The task of a TLS connection waits on it, and a cancel of that
    /// task ends the wait.
    done: Io.Event = .unset,

    fn run(d: *Dispatch) void {
        const self = d.rc.owner;
        const io = self.io;
        const exchange = d.exchange;
        self.server.handle(io, .{
            .kind = .streamable_http,
            .arena = d.arena,
            .message = .{ .request = d.req },
            .responder = .{ .ptr = exchange, .vtable = &exchange_vtable },
            .cancel = exchange.token,
            .context = d.principal,
            .peer = .{ .address = d.rc.peer },
        });
        if (exchange.keepalive_future) |*f| {
            exchange.keepalive_stop.store(true, .release);
            _ = f.cancel(io);
        }
        if (!exchange.done) {
            // The handler ended without a response (cancelled): close the stream.
            if (exchange.body_writer) |*bw| bw.end() catch {} else exchange.request.respond("", .{ .status = .service_unavailable }) catch {};
        }
        // The task of a TLS connection reads the socket. From now on it waits for the next
        // request, or for the close by the client after a response without keep-alive.
        if (d.rc.tls) |tc| {
            const reuse = exchange.reusable and !exchange.token.isCancelled() and exchange.request.head.keep_alive;
            if (reuse) tc.startTimer(.idle, self.limits.http.idle_timeout) else tc.startTimer(.close, close_linger);
        }
        d.ended.store(true, .release);
        d.done.set(io);
    }
};

/// The `x-mcp-header` annotations of the tool that `params` names, or null when no tool has
/// that name.
fn toolHeaders(self: *Server, params: ?Value) ?[]const envelope.HeaderAnnotation {
    const p = params orelse return null;
    const name = json.getString(p, "name") orelse return null;
    for (self.server.tools.items) |t| if (std.mem.eql(u8, t.def.name, name)) return t.header_annotations;
    return null;
}

/// The response side of one HTTP request.
const Exchange = struct {
    owner: *Server,
    request: *http.Server.Request,
    arena: Allocator,
    id: RequestId,
    token: *Transport.CancelToken,
    long_lived: bool,
    force_sse: bool,
    body_writer: ?http.BodyWriter = null,
    done: bool = false,
    reusable: bool = true,
    /// True when another task can write too (the keep-alive task of a listen stream). A
    /// response in a shard has one writer and needs no lock.
    shared: bool,
    write_lock: Io.Mutex = .init,
    keepalive_future: ?Io.Future(void) = null,
    keepalive_stop: std.atomic.Value(bool) = .init(false),

    const sse_headers = [_]http.Header{
        .{ .name = "content-type", .value = sse.content_type },
        .{ .name = "cache-control", .value = "no-cache, no-transform" },
        .{ .name = "x-accel-buffering", .value = "no" },
    };

    fn startSse(self: *Exchange) Transport.SendError!void {
        if (self.body_writer != null) return;
        // The chunked body of a request stream ends with the response, thus the connection
        // can carry the next request. A listen stream ends only at the close or the shutdown.
        const keep_alive = !self.long_lived and self.request.head.keep_alive;
        self.body_writer = self.request.respondStreaming(&.{}, .{ .respond_options = .{ .status = .ok, .keep_alive = keep_alive, .extra_headers = &sse_headers } }) catch return error.WriteFailed;
        if (!keep_alive) self.reusable = false;
        if (self.long_lived and self.owner.options.keepalive) {
            self.keepalive_future = self.owner.io.concurrent(keepaliveLoop, .{self}) catch null;
        }
    }

    fn keepaliveLoop(self: *Exchange) void {
        const io = self.owner.io;
        while (!self.keepalive_stop.load(.acquire)) {
            io.sleep(self.owner.limits.http.sse_keepalive, .awake) catch return;
            if (self.keepalive_stop.load(.acquire)) return;
            self.lock(io);
            defer self.unlock(io);
            if (self.done) return;
            const bw = &(self.body_writer orelse return);
            sse.writeComment(&bw.writer, "keepalive") catch return;
            bw.flush() catch return;
        }
    }

    fn lock(self: *Exchange, io: Io) void {
        if (self.shared) self.write_lock.lockUncancelable(io);
    }

    fn unlock(self: *Exchange, io: Io) void {
        if (self.shared) self.write_lock.unlock(io);
    }

    fn writeSse(self: *Exchange, frame: []const u8) Transport.SendError!void {
        const bw = &self.body_writer.?;
        sse.writeEvent(&bw.writer, frame) catch return error.WriteFailed;
        bw.flush() catch return error.WriteFailed;
    }
};

const exchange_vtable: Transport.Responder.VTable = .{
    .notify = exchangeNotify,
    .finish = exchangeFinish,
    .abort = exchangeAbort,
};

fn exchangeNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.lock(io);
    defer self.unlock(io);
    if (self.done) return error.Closed;
    // After a cancellation by the client, the server sends nothing more for the request.
    if (self.token.isCancelledByPeer()) return error.Closed;
    try self.startSse();
    try self.writeSse(frame);
}

fn exchangeFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.lock(io);
    defer self.unlock(io);
    if (self.done) return error.Closed;
    if (self.token.isCancelledByPeer()) return error.Closed;
    self.done = true;
    if (self.body_writer != null or self.force_sse or self.long_lived) {
        try self.startSse();
        // The last event and the end of the chunked body go out in one write.
        const bw = &self.body_writer.?;
        sse.writeEvent(&bw.writer, frame) catch return error.WriteFailed;
        bw.end() catch return error.WriteFailed;
        return;
    }
    // JSON mode: the HTTP status follows the error code for status-bearing codes. A rate
    // limit error also gets `Retry-After`.
    var status: http.Status = .ok;
    var retry_after: ?u64 = null;
    // Only an error response has a status other than 200. A frame without the `"error":` key
    // is a result: it needs no parse. A result that has the text gets the parse, as before.
    const maybe_error = std.mem.find(u8, frame, "\"error\":") != null;
    if (maybe_error) if (json.parseTree(self.arena, frame)) |tree| {
        if (tree == .object) {
            if (tree.object.get("error")) |e| {
                if (e == .object) {
                    if (e.object.get("code")) |c| if (c == .integer) {
                        status = statusForCode(c.integer);
                        if (status == .too_many_requests) retry_after = retryAfterSeconds(e);
                    };
                }
            }
        }
    } else |_| {};
    var headers: [2]http.Header = .{ json_headers[0], undefined };
    var count: usize = 1;
    var seconds_buf: [20]u8 = undefined;
    if (retry_after) |s| {
        headers[1] = .{ .name = "retry-after", .value = std.fmt.bufPrint(&seconds_buf, "{d}", .{s}) catch unreachable };
        count = 2;
    }
    self.request.respond(frame, .{ .status = status, .keep_alive = self.request.head.keep_alive, .extra_headers = headers[0..count] }) catch return error.WriteFailed;
}

fn exchangeAbort(ptr: *anyopaque, io: Io) void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.lock(io);
    defer self.unlock(io);
    if (self.done) return;
    self.done = true;
    if (self.body_writer) |*bw| {
        bw.end() catch {};
    } else {
        self.request.respond("", .{ .status = .service_unavailable }) catch {};
    }
    self.reusable = false;
}

test "a rate limit error maps to status 429 and Retry-After in whole seconds" {
    try std.testing.expectEqual(http.Status.too_many_requests, statusForCode(-31429));
    try std.testing.expectEqual(http.Status.bad_request, statusForCode(-32602));
    try std.testing.expectEqual(http.Status.ok, statusForCode(-32603));
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cases = [_]struct { text: []const u8, seconds: ?u64 }{
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":1}}", .seconds = 1 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":1000}}", .seconds = 1 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":1001}}", .seconds = 2 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":0}}", .seconds = 1 },
        .{ .text = "{\"code\":-31429,\"message\":\"m\",\"data\":{\"retryAfterMs\":-5}}", .seconds = null },
        .{ .text = "{\"code\":-31429,\"message\":\"m\"}", .seconds = null },
    };
    for (cases) |c| try std.testing.expectEqual(c.seconds, retryAfterSeconds(try json.parseTree(arena, c.text)));
}

test "the head scan of a shard accepts only a strict head, and finds the end of each body" {
    const ok = "POST /mcp HTTP/1.1\r\nmcp-method: tools/call\r\nmcp-name: t\r\ncontent-length: 2\r\n\r\n{}";
    const head = scanHead(ok, 1000).head;
    try std.testing.expectEqual(ok.len - 2, head.len);
    try std.testing.expectEqual(2, head.content_length.?);
    try std.testing.expectEqualStrings("tools/call", head.method.?);
    try std.testing.expectEqualStrings("t", head.name.?);
    // A length that overflows is a bad request.
    try std.testing.expectEqual(Reject.bad_request, scanHead("POST /mcp HTTP/1.1\r\ncontent-length: 18446744073709551616\r\n\r\n", 1000).reject);
    // A bare LF ends the head earlier for std: the lines after it are the body.
    try std.testing.expectEqual(Reject.bad_request, scanHead("POST /mcp HTTP/1.1\nmcp-method: tools/call\nmcp-name: slow\ncontent-length: 40\n\nx\r\nmcp-method: tools/list\r\n\r\n", 1000).reject);
    try std.testing.expectEqual(Reject.bad_request, scanHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\ncontent-length: 0\r\n\r\n", 1000).reject);
    // Two values of Mcp-Method: not quick. Two lengths, or a length and chunked: rejected.
    try std.testing.expect(scanHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\r\nmcp-method: tools/call\r\n\r\n", 1000).head.method == null);
    try std.testing.expectEqual(Reject.bad_request, scanHead("POST /mcp HTTP/1.1\r\ncontent-length: 1\r\ncontent-length: 1\r\n\r\n", 1000).reject);
    try std.testing.expectEqual(Reject.bad_request, scanHead("POST /mcp HTTP/1.1\r\ncontent-length: 1\r\ntransfer-encoding: chunked\r\n\r\n", 1000).reject);
    try std.testing.expectEqual(Reject.bad_request, scanHead("POST /mcp HTTP/1.1\r\ntransfer-encoding: gzip\r\n\r\n", 1000).reject);
    try std.testing.expectEqual(Reject.expectation_failed, scanHead("POST /mcp HTTP/1.1\r\nexpect: 200-ok\r\n\r\n", 1000).reject);
    // An incomplete head, and a head over the limit.
    try std.testing.expect(scanHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\r\n", 1000) == .need_more);
    try std.testing.expectEqual(Reject.head_too_large, scanHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\r\n", 20).reject);
    try std.testing.expectEqual(Reject.head_too_large, scanHead("POST /mcp HTTP/1.1\r\nx: y\r\n\r\n", 20).reject);
}

test "the chunked body of a request ends after its last chunk and its trailers" {
    var st: ChunkState = .{};
    try std.testing.expectEqual(Chunked{ .done = 13 }, chunkedLength("3\r\nabc\r\n0\r\n\r\nNEXT", 100, &st));
    // The state lets a later look start after the complete chunks.
    st = .{};
    try std.testing.expectEqual(Chunked.need_more, chunkedLength("3\r\nabc\r\n2\r\nx", 100, &st));
    try std.testing.expectEqual(ChunkState{ .pos = 8, .total = 3 }, st);
    try std.testing.expectEqual(Chunked{ .done = 20 }, chunkedLength("3\r\nabc\r\n2\r\nxy\r\n0\r\n\r\n", 100, &st));
    // A sign, a separator, white space, or a bare LF in a chunk line or a trailer.
    for ([_][]const u8{ "+3\r\nabc\r\n0\r\n\r\n", "1_0\r\n", " 3\r\n", "3;a\nb\r\nabc\r\n0\r\n\r\n", "0\r\nt: v\nx\r\n\r\n" }) |bad| {
        st = .{};
        try std.testing.expectEqual(Chunked.bad, chunkedLength(bad, 100, &st));
    }
    st = .{};
    try std.testing.expectEqual(Chunked{ .done = 23 }, chunkedLengthFresh("3;x=1\r\nabc\r\n0\r\nt: v\r\n\r\n", 100));
    try std.testing.expectEqual(Chunked.need_more, chunkedLengthFresh("3\r\nab", 100));
    try std.testing.expectEqual(Chunked.need_more, chunkedLengthFresh("3\r\nabc\r\n0\r\n", 100));
    try std.testing.expectEqual(Chunked.bad, chunkedLengthFresh("3\r\nabcd\r\n0\r\n\r\n", 100));
    try std.testing.expectEqual(Chunked.bad, chunkedLengthFresh("zz\r\n", 100));
    try std.testing.expectEqual(Chunked.too_large, chunkedLengthFresh("65\r\n", 100));
    try std.testing.expectEqual(Chunked.too_large, chunkedLengthFresh("ffffffffffffffff\r\n", 1 << 40));
    // A size near the end of the integer range does not overflow.
    try std.testing.expectEqual(Chunked.need_more, chunkedLengthFresh("ffffffffffffffff\r\nab", std.math.maxInt(usize)));
}

fn chunkedLengthFresh(data: []const u8, max_body: usize) Chunked {
    var st: ChunkState = .{};
    return chunkedLength(data, max_body, &st);
}

test "a new connection goes to the first shard that is not busy" {
    // `pickIndex` reads `load` and `sleeping` only. Both must be set: a read of an undefined
    // `bool` crashed this test in ReleaseFast.
    var shards: [3]Shard = undefined;
    for (&shards) |*sh| {
        sh.load = .init(0);
        sh.sleeping = .init(false);
    }
    try std.testing.expectEqual(0, pickIndex(&shards));
    shards[0].load.store(80, .monotonic);
    try std.testing.expectEqual(1, pickIndex(&shards));
    shards[1].load.store(spill_load, .monotonic);
    try std.testing.expectEqual(2, pickIndex(&shards));
    // All are busy: the least busy one.
    shards[2].load.store(90, .monotonic);
    try std.testing.expectEqual(1, pickIndex(&shards));
}

test "the inbox of a shard gives its connections back in the order of their push" {
    var inbox: Inbox = .{};
    var conns: [3]Connection = undefined;
    try std.testing.expect(inbox.isEmpty());
    for (&conns) |*c| try std.testing.expect(inbox.push(c));
    var it = inbox.takeAll();
    for (&conns) |*c| {
        try std.testing.expectEqual(c, it.?);
        it = c.inbox_next;
    }
    try std.testing.expect(it == null);
    try std.testing.expect(inbox.isEmpty());
    // A closed inbox takes nothing more, and an inbox with an entry does not close.
    try std.testing.expect(inbox.push(&conns[0]));
    try std.testing.expect(!inbox.close());
    _ = inbox.takeAll();
    try std.testing.expect(inbox.close());
    try std.testing.expect(!inbox.push(&conns[1]));
}

test "many tasks push to one inbox at the same time, and the consumer gets each connection one time" {
    const io = std.testing.io;
    const producers = 4;
    const per = 2000;
    const conns = try std.testing.allocator.alloc(Connection, producers * per);
    defer std.testing.allocator.free(conns);
    var inbox: Inbox = .{};
    const Push = struct {
        fn run(q: *Inbox, part: []Connection) void {
            for (part) |*c| std.debug.assert(q.push(c));
        }
    };
    var group: Io.Group = .init;
    for (0..producers) |p| try group.concurrent(io, Push.run, .{ &inbox, conns[p * per .. (p + 1) * per] });
    var seen: usize = 0;
    var last = @as([producers]usize, @splat(0));
    while (seen < conns.len) {
        var it = inbox.takeAll();
        while (it) |c| : (it = c.inbox_next) {
            // The order of the pushes of one task stays.
            const index = (@intFromPtr(c) - @intFromPtr(conns.ptr)) / @sizeOf(Connection);
            const p = index / per;
            try std.testing.expect(index + 1 > last[p]);
            last[p] = index + 1;
            seen += 1;
        }
    }
    try group.await(io);
    try std.testing.expect(inbox.isEmpty());
}

test {
    std.testing.refAllDecls(@This());
    _ = park;
}
