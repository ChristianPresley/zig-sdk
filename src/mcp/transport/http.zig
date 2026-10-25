//! The Streamable HTTP transport (server side): one `POST` endpoint, JSON or SSE responses,
//! long-lived listen streams, header mirroring, `Origin` and `Host` validation.
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
const park = @import("park.zig");
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

pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    options: Options,
    limits: Limits,
    listener: ?Io.net.Server = null,
    bound_port: u16 = 0,
    /// The tasks that cancel a connection at a time limit or at the shutdown.
    group: Io.Group = .init,
    permits: Io.Semaphore,
    closing: std.atomic.Value(bool) = .init(false),
    /// Set when the accept loop ended. The supervisor then ends with the last connection.
    accepting_done: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    /// The connections with a task: the supervisor watches their time limits.
    connections: std.ArrayList(*Connection) = .empty,
    connections_lock: Io.Mutex = .init,
    /// The idle connections without a task, and the cap of the worker tasks.
    parker: Parker = .{},
    /// The read and write buffers of the connection tasks.
    buffers: BufferPool,
    /// Wakes the supervisor: a connection has a nearer time limit, a connection ended, or the
    /// server stops.
    supervisor_wake: Io.Event = .unset,
    /// The awake time in nanoseconds at which the supervisor wakes by itself. `unlimited`
    /// while it looks at the connections, thus each new time limit wakes it.
    next_deadline: std.atomic.Value(i64) = .init(Connection.unlimited),

    pub fn init(io: Io, gpa: Allocator, server: *McpServer, options: Options) Server {
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .limits = server.options.limits,
            .permits = .{ .permits = server.options.limits.http.max_connections },
            .buffers = .init(server.options.limits),
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener) |*l| l.deinit(self.io);
        self.connections.deinit(self.gpa);
        self.parker.snapshot.deinit(self.gpa);
        self.buffers.deinit(self.gpa);
        self.* = undefined;
    }

    /// Add `conn` to the connections with a task. The caller holds no lock of the server.
    fn track(self: *Server, conn: *Connection) !void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        conn.index = self.connections.items.len;
        try self.connections.append(self.gpa, conn);
    }

    /// Remove `conn` from the connections with a task. The caller holds `connections_lock`.
    fn untrackLocked(self: *Server, conn: *Connection) void {
        const i = conn.index;
        _ = self.connections.swapRemove(i);
        if (i < self.connections.items.len) self.connections.items[i].index = i;
    }

    fn untrack(self: *Server, conn: *Connection) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        self.untrackLocked(conn);
    }

    /// Bind the listen socket. After this call `bound_port` has the port (useful with port 0).
    pub fn bind(self: *Server) !void {
        var address = try Io.net.IpAddress.parse(self.options.address, self.options.port);
        self.listener = try address.listen(self.io, .{ .reuse_address = self.limits.http.reuse_address, .kernel_backlog = self.limits.http.listen_backlog });
        self.bound_port = self.listener.?.socket.address.getPort();
    }

    /// Accept connections until a call to `shutdown`. A cancel also ends `serve`. After a
    /// cancel, the server accepts no more connections.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        const cap = if (self.limits.http.max_in_flight == 0) self.limits.http.max_connections else self.limits.http.max_in_flight;
        try self.parker.start(self.gpa, cap);
        defer self.parker.stop();
        var supervisor = try self.io.concurrent(supervise, .{self});
        var parker_task = self.io.concurrent(runParker, .{self}) catch |e| {
            self.closing.store(true, .release);
            self.endSupervisor(&supervisor);
            return e;
        };
        var accept_future = self.io.concurrent(acceptLoop, .{self}) catch |e| {
            self.closing.store(true, .release);
            self.endSupervisor(&supervisor);
            parker_task.await(self.io);
            return e;
        };
        self.stop_event.wait(self.io) catch {};
        // On Windows a cancel can miss an accept that waits. The wake connection ends it.
        wake.cancelAcceptLoop(self.io, &accept_future, self.listener.?.socket.address, &self.closing);
        self.server.shutdownSubscriptions(self.io);
        self.endSupervisor(&supervisor);
        parker_task.await(self.io);
        self.group.await(self.io) catch {};
    }

    /// Tell the supervisor and the parker that no more connections come, and wait until the
    /// supervisor ended the last connection.
    fn endSupervisor(self: *Server, supervisor: *Io.Future(void)) void {
        self.accepting_done.store(true, .release);
        self.supervisor_wake.set(self.io);
        self.parker.wakeTask();
        supervisor.await(self.io);
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
            if (!self.tryTakePermit()) {
                // At `max_connections`, the parker closes the oldest idle connection. Thus a
                // client that opens a new pool while its old pool stays open does not wait
                // until the old connections expire.
                self.parker.evict.store(true, .release);
                self.parker.wakeTask();
                self.permits.waitUncancelable(self.io);
                self.parker.evict.store(false, .release);
            }
            if (!self.startConnection(stream)) {
                self.permits.post(self.io);
                var s = stream;
                s.close(self.io);
            }
        }
    }

    /// Take one of the `max_connections` permits without a wait. False when none is free.
    fn tryTakePermit(self: *Server) bool {
        const s = &self.permits;
        s.mutex.lockUncancelable(self.io);
        defer s.mutex.unlock(self.io);
        if (s.permits == 0) return false;
        s.permits -= 1;
        return true;
    }

    /// Free the memory of a connection that ended.
    fn freeConnection(self: *Server, conn: *Connection) void {
        if (conn.pending_out) |pending| self.gpa.free(pending);
        self.gpa.destroy(conn);
    }

    /// Give a new connection a task, or a place in the queue of the parker when the worker
    /// tasks are at their cap. False when the server has no memory for the connection.
    fn startConnection(self: *Server, stream: Io.net.Stream) bool {
        const conn = self.gpa.create(Connection) catch return false;
        conn.* = .{ .owner = self, .stream = stream };
        if (!self.parker.admit(self, conn)) {
            self.freeConnection(conn);
            return false;
        }
        return true;
    }

    /// One task for all connections. It cancels the task of a connection when a time limit
    /// passes or when the server stops. It frees a connection when its task ended. A
    /// connection task thus waits only in its reads, and an idle connection holds one task.
    fn supervise(self: *Server) void {
        const io = self.io;
        const grace = nanoseconds(self.limits.shutdown_grace);
        var shutdown_end: ?i64 = null;
        var due: [16]*Connection = undefined;
        while (true) {
            const now = nowNanoseconds(io);
            var next: i64 = Connection.unlimited;
            var due_count: usize = 0;
            var again = false;
            var empty = false;
            var no_more = false;
            {
                self.connections_lock.lockUncancelable(io);
                defer self.connections_lock.unlock(io);
                // The accept loop adds a connection under the lock. After `accepting_done`,
                // no connection comes, thus an empty list is final.
                no_more = self.accepting_done.load(.acquire);
                self.next_deadline.store(Connection.unlimited, .release);
                var i = self.connections.items.len;
                while (i > 0) {
                    i -= 1;
                    const conn = self.connections.items[i];
                    switch (conn.state.load(.acquire)) {
                        .finished => {
                            conn.worker.await(io);
                            self.untrackLocked(conn);
                            self.freeConnection(conn);
                            // At the shutdown the parker waits for the last task to end.
                            if (self.closing.load(.acquire)) self.parker.wakeTask();
                            continue;
                        },
                        .canceling => continue,
                        // On the way to the parker, which removes it from this list.
                        .queued, .parked, .parked_closing => continue,
                        .running => {},
                    }
                    const d = conn.deadline.load(.acquire);
                    if (d == Connection.expired) continue;
                    const limit: i64 = if (self.closing.load(.acquire)) limit: {
                        if (d != Connection.busy) break :limit now;
                        const end = shutdown_end orelse now +| grace;
                        shutdown_end = end;
                        break :limit end;
                    } else if (d != Connection.busy and d != Connection.unlimited) d else continue;
                    if (now < limit) {
                        next = @min(next, limit);
                        continue;
                    }
                    if (due_count == due.len) {
                        again = true;
                        continue;
                    }
                    if (conn.expire(d) and conn.state.cmpxchgStrong(.running, .canceling, .acq_rel, .acquire) == null) {
                        due[due_count] = conn;
                        due_count += 1;
                    } else {
                        // The task changed the time limit or ended. Look again.
                        again = true;
                    }
                }
                empty = self.connections.items.len == 0;
                if (!again) self.next_deadline.store(next, .release);
            }
            for (due[0..due_count]) |conn| self.group.concurrent(io, Connection.cancelWorker, .{conn}) catch conn.cancelWorker();
            // The parker holds its connections until they end; it wakes the supervisor then.
            if (empty and no_more and self.parker.held.load(.acquire) == 0) return;
            if (again) continue;
            const wait_ns: i64 = if (next == Connection.unlimited) 60 * std.time.ns_per_s else @max(next - now, 1);
            self.supervisor_wake.waitTimeout(io, .{ .duration = .{ .raw = .fromNanoseconds(wait_ns), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => {},
            };
            self.supervisor_wake.reset();
        }
    }

    /// Accept no more connections and end active streams. Safe to call from another task.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .release);
        self.stop_event.set(self.io);
        self.server.shutdownSubscriptions(self.io);
        // The supervisor cancels the connections that wait for a request at once, and the
        // busy connections after `limits.shutdown_grace`. The parker closes the parked ones.
        self.supervisor_wake.set(self.io);
        self.parker.wakeTask();
    }

    /// The task of the parker. It waits for bytes on the parked sockets and gives a ready
    /// connection a worker task. It closes a parked connection at its idle time limit and
    /// at the shutdown. It frees the connections that end without a task.
    fn runParker(self: *Server) void {
        const io = self.io;
        const p = &self.parker;
        const poller = &p.poller.?;
        var events: [256]park.Event = undefined;
        // True after the parker ran requests itself. Other requests can arrive meanwhile, thus
        // the next wait looks without a wait first.
        var look_again = false;
        while (true) {
            p.lock.lockUncancelable(io);
            p.freeClosedLocked(self);
            if (self.closing.load(.acquire)) p.closeAllLocked(self);
            const now = nowNanoseconds(io);
            p.expireLocked(self, now);
            p.evictLocked(self);
            p.spawnReadyLocked(self);
            const next = p.nextDeadlineLocked();
            // The parker ends after the last connection: the ones it holds, the ones it
            // watches for a handler, and the ones with a task, which can still hand over.
            var done = self.closing.load(.acquire) and self.accepting_done.load(.acquire) and p.held.load(.acquire) == 0 and p.watching.head == null;
            if (done) {
                self.connections_lock.lockUncancelable(io);
                done = self.connections.items.len == 0;
                self.connections_lock.unlock(io);
            }
            if (!park.is_windows) {
                p.snapshot.clearRetainingCapacity();
                var it = p.parked.head;
                while (it) |c| : (it = c.next) p.snapshot.append(self.gpa, &c.slot) catch break;
                it = p.watching.head;
                while (it) |c| : (it = c.next) p.snapshot.append(self.gpa, &c.slot) catch break;
            }
            p.lock.unlock(io);
            if (done) return;
            // On Windows, a connection that parks during the wait expires `idle_timeout` after
            // the start of the wait or later. Thus the parker wakes in time for it, and the park
            // of a connection costs no wake of the parker. On POSIX systems the parker wakes for
            // each park, to poll the new socket.
            const wake_at = if (park.is_windows) @min(next, deadlineFrom(io, self.limits.http.idle_timeout)) else next;
            const timeout_ms: i32 = if (wake_at == Connection.unlimited) -1 else @intCast(@min(std.math.maxInt(i32), @divFloor(@max(wake_at - now, 0) + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
            const n = poller.wait(if (look_again) 0 else timeout_ms, p.snapshot.items, &events) catch 0;
            look_again = false;
            if (n == 0) continue;
            p.lock.lockUncancelable(io);
            for (events[0..n]) |ev| p.handleEventLocked(self, ev);
            p.lock.unlock(io);
            var served: usize = 0;
            while (true) : (served += 1) {
                p.lock.lockUncancelable(io);
                if (served == max_inline_per_wait) {
                    // Many requests at once: the rest get worker tasks, which run in parallel.
                    while (p.candidates.pop()) |c| p.ready.push(c);
                    p.lock.unlock(io);
                    break;
                }
                const conn = p.candidates.pop();
                p.lock.unlock(io);
                p.serveInline(self, conn orelse break);
                look_again = true;
            }
        }
    }

    fn originAllowed(self: *Server, origin: []const u8) bool {
        return originInList(self.options.allowed_origins, origin);
    }

    fn hostAllowed(self: *Server, host: []const u8) bool {
        return hostInList(self.options.allowed_hosts, self.options.address, host);
    }
};

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

/// The response to a request that did not arrive in its time limit (RFC 9110 section 15.5.9).
const request_timeout_response = "HTTP/1.1 408 Request Timeout\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// The time that the server keeps a connection open after a response without keep-alive, for
/// the close by the client. Overflow: the server closes the connection.
const close_linger: Io.Duration = .fromSeconds(2);

/// One connection, with one task that does the TLS handshake, reads the requests and runs
/// them. The supervisor of the server watches its time limits. When a limit passes or the
/// server stops, the supervisor cancels the task: on Windows, a shutdown of the socket does
/// not stop a read. The handler of a request runs in a task of its own. Meanwhile the task
/// of the connection reads the socket, and a disconnect of the client cancels the request.
/// Thus an idle connection holds one task, and a request in flight holds two.
const Connection = struct {
    owner: *Server,
    stream: Io.net.Stream,
    /// The task of the connection. The supervisor awaits or cancels it one time while the
    /// connection has a task. The parker awaits it after a park.
    worker: Io.Future(void) = undefined,
    /// True while `worker` holds a task that nobody awaited or canceled.
    future_live: bool = false,
    /// The position in `Server.connections` while the connection has a task.
    index: usize = undefined,
    /// The links of the lists of the parker.
    prev: ?*Connection = null,
    next: ?*Connection = null,
    /// The awake time in nanoseconds at which the parker closes the connection, or
    /// `unlimited`.
    park_deadline: i64 = unlimited,
    /// The readiness state of the parked socket.
    slot: park.Slot = .{},
    /// True after the stream was closed.
    closed: bool = false,
    /// What the poll of the parker on this socket is for. The parker writes it under its
    /// lock.
    poll_phase: PollPhase = .none,
    /// Set by the parker when bytes arrived, or when the peer closed, while a handler ran.
    data_seen: bool = false,
    hangup_seen: bool = false,
    /// The cancel token of the request that runs, for a disconnect that the parker sees.
    cancel_token: ?*Transport.CancelToken = null,
    /// True while the parker runs a request of the connection itself (see
    /// `Parker.serveInline`). The time limits then do not apply.
    inline_mode: bool = false,
    /// The part of a response that the parker could not send without a wait. The task of
    /// the connection sends it first.
    pending_out: ?[]u8 = null,
    /// Close the connection after `pending_out`.
    pending_close: bool = false,
    /// True for a plaintext connection: the parker watches its socket. A TLS connection
    /// keeps its task as the watch, and never parks.
    use_poll: bool = false,
    /// The time limit of the read that the task does now: an awake time in nanoseconds,
    /// `busy`, `unlimited` or `expired`. Only the task and its handler change a value other
    /// than `expired`. Only the supervisor sets `expired`.
    deadline: std.atomic.Value(i64) = .init(busy),
    /// What the task waits for.
    phase: std.atomic.Value(Phase) = .init(.busy),
    /// `running` until the task ends by itself (`finished`), or until the supervisor cancels
    /// it (`canceling`, then `finished`).
    state: std.atomic.Value(State) = .init(.running),

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

    const State = enum(u8) {
        /// The connection has a task. The supervisor watches it.
        running,
        canceling,
        finished,
        /// The connection waits in the queue of the parker for a worker task.
        queued,
        /// The connection is idle and has no task. The parker waits for its bytes.
        parked,
        /// The parker closed the socket. The completion of the poll frees the connection.
        parked_closing,
    };

    const PollPhase = enum(u8) {
        /// No poll is pending.
        none,
        /// The poll watches the socket while a handler runs.
        handler,
        /// The poll is the idle wait of a parked connection.
        idle,
        /// The parker closed the socket. The completion of the poll frees the connection
        /// (Windows).
        closing,
    };

    /// The task runs a handler or writes a response. No time limit applies.
    const busy: i64 = 0;
    /// The task waits for bytes from the client, without a time limit.
    const unlimited: i64 = std.math.maxInt(i64);
    /// The time limit passed, or the server stops. The task must stop.
    const expired: i64 = -1;

    /// The task of the connection. It ends when the connection closes, or when the connection
    /// is idle and the parker takes it.
    fn work(conn: *Connection) void {
        const self = conn.owner;
        const io = self.io;
        const parked = conn.serve() catch false;
        if (parked) return;
        // A poll that is still pending references the connection: the parker closes it.
        if (self.parker.takeOverPending(self, conn)) return;
        conn.stream.close(io);
        conn.closed = true;
        self.permits.post(io);
        self.parker.release(self);
        // The supervisor frees the connection. After a cancel, the canceller marks the end.
        if (conn.state.cmpxchgStrong(.running, .finished, .acq_rel, .acquire) == null) self.supervisor_wake.set(io);
    }

    /// Cancel the task and mark the end. The supervisor runs it in a task of the group. Thus
    /// a slow end of one connection does not delay the time limits of the others.
    fn cancelWorker(conn: *Connection) void {
        const self = conn.owner;
        conn.worker.cancel(self.io);
        conn.state.store(.finished, .release);
        self.supervisor_wake.set(self.io);
    }

    /// Mark the deadline `d` as passed. False when the task changed the deadline first.
    fn expire(conn: *Connection, d: i64) bool {
        return conn.deadline.cmpxchgStrong(d, expired, .acq_rel, .acquire) == null;
    }

    /// Set the time limit of the next read to `limit` from now. Zero means no limit. False
    /// when the connection expired: the task must stop.
    fn startTimer(conn: *Connection, phase: Phase, limit: Io.Duration) bool {
        if (conn.inline_mode) return true;
        conn.phase.store(phase, .release);
        const ns = nanoseconds(limit);
        const self = conn.owner;
        const value = if (ns == 0) unlimited else @max(nowNanoseconds(self.io) +| ns, 1);
        if (!conn.setDeadline(value)) return false;
        // Wake the supervisor for a time limit before its next wake.
        if (value < self.next_deadline.load(.acquire)) self.supervisor_wake.set(self.io);
        return true;
    }

    /// As `startTimer`, but keep a time limit that runs already.
    fn continueTimer(conn: *Connection, phase: Phase, limit: Io.Duration) bool {
        if (conn.inline_mode) return true;
        const d = conn.deadline.load(.acquire);
        if (d == expired) return false;
        if (d != busy) return true;
        return conn.startTimer(phase, limit);
    }

    /// Remove the time limit while the task is busy. False when the connection expired.
    fn stopTimer(conn: *Connection) bool {
        if (conn.inline_mode) return true;
        conn.phase.store(.busy, .release);
        return conn.setDeadline(busy);
    }

    fn setDeadline(conn: *Connection, value: i64) bool {
        var cur = conn.deadline.load(.acquire);
        while (cur != expired) {
            cur = conn.deadline.cmpxchgWeak(cur, value, .acq_rel, .acquire) orelse return true;
        }
        return false;
    }

    /// On a POSIX system, wait at most `park_linger_ms` for bytes of the next request. True
    /// when bytes arrived. A park and the new task after it cost two wakes of other threads.
    /// On Windows the function returns false at once: the parker there costs no wake.
    fn lingerForNext(conn: *Connection) bool {
        if (park.is_windows) return false;
        const posix = std.posix;
        var fds = [_]posix.pollfd{.{ .fd = conn.stream.socket.handle, .events = posix.POLL.IN, .revents = 0 }};
        const rc = posix.system.poll(&fds, fds.len, park_linger_ms);
        if (posix.errno(rc) != .SUCCESS or rc == 0) return false;
        return fds[0].revents & posix.POLL.IN != 0;
    }

    fn timedOut(conn: *Connection) bool {
        return conn.deadline.load(.acquire) == expired;
    }

    /// Tell the client about a request head or body that did not arrive in time. The server
    /// closes an idle connection without a response (RFC 9112 section 9.6), and sends nothing
    /// at the shutdown.
    fn sendTimeout(conn: *Connection, out: *Io.Writer) void {
        const phase = conn.phase.load(.acquire);
        if (phase != .head and phase != .body) return;
        if (conn.owner.closing.load(.acquire)) return;
        out.writeAll(request_timeout_response) catch return;
        out.flush() catch {};
    }

    /// Watch the socket of `conn` while the handler of its request runs, in a task. A close
    /// by the peer cancels the request. The read fills only the free space at the end of the
    /// buffer. Thus the bytes of a pipelined next request stay for the next read. The task of
    /// the connection cancels this task when the handler ends. The cancel of the read does
    /// not look like a disconnect, because `ended` is set.
    fn watch(conn: *Connection, socket: *Io.net.Stream.Reader, dispatch: *Dispatch) void {
        const io = conn.owner.io;
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

    /// Read and handle requests until the connection ends or the parker takes it. The TLS
    /// handshake and the head of the first request obey `limits.http.head_timeout`. The wait
    /// for the next request obeys `limits.http.idle_timeout`, and its head obeys
    /// `head_timeout` from its first byte. True when the parker took the connection.
    fn serve(conn: *Connection) Io.Cancelable!bool {
        const self = conn.owner;
        if (!conn.startTimer(.head, self.limits.http.head_timeout)) return false;
        // The buffers come from the pool of the server. A new task for a parked connection
        // thus does not allocate them again.
        const bufs = self.buffers.take(self) orelse return false;
        defer self.buffers.give(self, bufs);
        var reader = conn.stream.reader(self.io, bufs.read);
        var writer = conn.stream.writer(self.io, bufs.write);

        // With TLS, the HTTP server reads and writes plaintext through the TLS connection.
        // Its state is on the heap. Thus a plaintext connection does not fill it.
        var tls_state: ?*TlsState = null;
        defer if (tls_state) |s| {
            s.conn.end() catch {};
            s.conn.deinit();
            self.gpa.destroy(s);
        };
        if (self.options.tls) |tls_server| {
            const s = self.gpa.create(TlsState) catch return false;
            s.conn = tls_server.accept(&reader.interface, &writer.interface, .{
                .io = self.io,
                .read_buffer = &s.read_buf,
                .write_buffer = &s.write_buf,
                .allow_truncation_attacks = true,
            }) catch {
                self.gpa.destroy(s);
                return false;
            };
            tls_state = s;
        }
        const in: *Io.Reader = if (tls_state) |s| &s.conn.reader else &reader.interface;
        const out: *Io.Writer = if (tls_state) |s| &s.conn.writer else &writer.interface;
        // The parker watches the socket of a plaintext connection while it is idle, so the
        // connection holds no task between requests. A TLS connection keeps its task: its
        // state is in the buffers.
        conn.use_poll = tls_state == null;
        var http_server: http.Server = .init(in, out);
        var first = true;
        if (conn.pending_out) |pending| {
            // The rest of a response of the parker (see `Parker.serveInline`).
            conn.pending_out = null;
            defer self.gpa.free(pending);
            out.writeAll(pending) catch return false;
            out.flush() catch return false;
            if (conn.pending_close) return false;
            first = false;
            // Then the connection goes back to the parker, as after a request.
            if (conn.use_poll) switch (self.parker.afterRequest(self, conn, true, in.bufferedLen() == 0)) {
                .parked => return true,
                .close => return false,
                .read_next => {},
            };
        }
        while (!self.closing.load(.acquire)) {
            if (!first) {
                // Wait for the first byte of the next request. A time limit that runs already
                // (from the end of the last handler) continues.
                if (!conn.continueTimer(.idle, self.limits.http.idle_timeout)) return false;
                _ = in.peekByte() catch return false;
                if (!conn.startTimer(.head, self.limits.http.head_timeout)) return false;
            }
            first = false;
            var request = http_server.receiveHead() catch |e| switch (e) {
                error.HttpConnectionClosing => return false,
                error.HttpHeadersOversize => {
                    out.writeAll("HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                    out.flush() catch {};
                    return false;
                },
                else => {
                    if (conn.timedOut()) conn.sendTimeout(out);
                    return false;
                },
            };
            if (!conn.stopTimer()) return false;
            const keep_alive = handleRequest(conn, &request, &reader) catch |err| switch (err) {
                error.OutOfMemory => false,
                else => false,
            };
            const timed_out = conn.timedOut();
            if (timed_out) conn.sendTimeout(out);
            const reuse = keep_alive and request.head.keep_alive and !timed_out;
            if (conn.use_poll) {
                const idle = in.bufferedLen() == 0;
                // A client under load sends its next request at once. Then the task reads
                // it, and the connection does not go to the parker and back to a new task.
                if (reuse and idle and conn.lingerForNext()) continue;
                // An idle plaintext connection goes to the parker and holds no task.
                switch (self.parker.afterRequest(self, conn, reuse, idle)) {
                    .parked => return true,
                    .close => return false,
                    .read_next => continue,
                }
            }
            if (!reuse) return false;
        }
        return false;
    }
};

/// The TLS state of one connection.
const TlsState = struct {
    conn: tls.Connection,
    read_buf: [tls.Connection.min_read_buffer_len]u8,
    write_buf: [16 * 1024]u8,
};

/// The read and write buffers of the connection tasks. A task that ends gives its pair of
/// buffers back, and the next task takes it. Thus a request on a parked connection does not
/// allocate and fill 36 KiB again. The pool keeps at most `max_kept` free pairs. A parked
/// connection holds no buffers.
///
/// Each buffer is a separate allocation. One block of both is larger than the largest size
/// class of `std.heap.smp_allocator` (32 KiB). Each allocation of such a block maps memory.
const BufferPool = struct {
    lock: Io.Mutex = .init,
    free: ?*Node = null,
    free_count: u32 = 0,
    read_len: usize = 0,
    write_len: usize = 0,

    const max_kept = 32;
    const alignment: std.mem.Alignment = .of(Node);
    /// The first bytes of a free read buffer.
    const Node = struct { next: ?*Node, write: [*]u8 };

    const Pair = struct {
        read: []align(alignment.toByteUnits()) u8,
        write: []u8,
    };

    fn init(limits: Limits) BufferPool {
        return .{
            .read_len = @max(limits.http.max_head_bytes + 4096, tls.Connection.min_input_buffer_len, @sizeOf(Node)),
            .write_len = tls.Connection.min_output_buffer_len,
        };
    }

    fn deinit(pool: *BufferPool, gpa: Allocator) void {
        while (pool.free) |node| {
            pool.free = node.next;
            const pair = pool.pairOf(node);
            gpa.free(pair.read);
            gpa.free(pair.write);
        }
        pool.free_count = 0;
    }

    fn pairOf(pool: *BufferPool, node: *Node) Pair {
        const read: [*]align(alignment.toByteUnits()) u8 = @ptrCast(node);
        return .{ .read = read[0..pool.read_len], .write = node.write[0..pool.write_len] };
    }

    /// The buffers for a task, or null when the server has no memory for them.
    fn take(pool: *BufferPool, self: *Server) ?Pair {
        {
            pool.lock.lockUncancelable(self.io);
            defer pool.lock.unlock(self.io);
            if (pool.free) |node| {
                pool.free = node.next;
                pool.free_count -= 1;
                return pool.pairOf(node);
            }
        }
        const read = self.gpa.alignedAlloc(u8, alignment, pool.read_len) catch return null;
        const write = self.gpa.alloc(u8, pool.write_len) catch {
            self.gpa.free(read);
            return null;
        };
        return .{ .read = read, .write = write };
    }

    fn give(pool: *BufferPool, self: *Server, pair: Pair) void {
        {
            pool.lock.lockUncancelable(self.io);
            defer pool.lock.unlock(self.io);
            if (pool.free_count < max_kept) {
                const node: *Node = @ptrCast(pair.read.ptr);
                node.* = .{ .next = pool.free, .write = pair.write.ptr };
                pool.free = node;
                pool.free_count += 1;
                return;
            }
        }
        self.gpa.free(pair.read);
        self.gpa.free(pair.write);
    }
};

/// The head of a request that the parker can run itself (see `Parker.serveInline`).
const InlineHead = struct {
    /// The length of the head and the body.
    len: usize,
    method: []const u8,
    name: ?[]const u8,
};

/// Read the head at the start of `data` for `Parker.serveInline`, or null. The head must end
/// with the first `"\r\n\r\n"`, as `std.http.HeadParser` finds it, and each line must end
/// with `"\r\n"`. Thus this scan and the HTTP parser see the same header lines. The body must have a
/// `Content-Length` of at most `max_body`, without `Transfer-Encoding` and `Expect`. The head
/// must have `Mcp-Method`.
fn scanInlineHead(data: []const u8, max_body: usize) ?InlineHead {
    var parser: http.HeadParser = .{};
    const head_len = parser.feed(data);
    if (parser.state != .finished or head_len < 4) return null;
    const head = data[0..head_len];
    if (!std.mem.endsWith(u8, head, "\r\n\r\n")) return null;
    // A bare LF or CR: other parsers can end a line there.
    for (head, 0..) |c, i| switch (c) {
        '\n' => if (i == 0 or head[i - 1] != '\r') return null,
        '\r' => if (i + 1 == head.len or head[i + 1] != '\n') return null,
        else => {},
    };
    var content_length: usize = 0;
    var have_length = false;
    var method: ?[]const u8 = null;
    var name: ?[]const u8 = null;
    var lines = std.mem.splitSequence(u8, head[0 .. head_len - 4], "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse return null;
        const key = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(key, "content-length")) {
            if (have_length) return null;
            have_length = true;
            content_length = std.fmt.parseInt(usize, value, 10) catch return null;
            if (content_length > max_body) return null;
        } else if (std.ascii.eqlIgnoreCase(key, "transfer-encoding") or std.ascii.eqlIgnoreCase(key, "expect")) {
            return null;
        } else if (std.ascii.eqlIgnoreCase(key, envelope.header_method)) {
            if (method != null) return null;
            method = value;
        } else if (std.ascii.eqlIgnoreCase(key, envelope.header_name)) {
            if (name != null) return null;
            name = value;
        }
    }
    const len = std.math.add(usize, head_len, content_length) catch return null;
    return .{ .len = len, .method = method orelse return null, .name = name };
}

/// The length of the request at the start of `data` when the parker can run it itself (see
/// `Parker.serveInline`), or null.
fn inlineRequestLength(self: *Server, data: []const u8) ?usize {
    const head = scanInlineHead(data, self.limits.http.max_body_bytes) orelse return null;
    if (!self.server.isQuickMethod(head.method, head.name)) return null;
    return head.len;
}

/// The most requests that the parker runs itself after one wait (see `Parker.serveInline`).
const max_inline_per_wait = 16;

const Peek = enum { bytes, closed, nothing };

/// Look at the socket without a wait (POSIX). The bytes stay in the socket. `closed`: the
/// peer closed or reset the connection.
fn peekSocket(handle: Io.net.Socket.Handle) Peek {
    if (park.is_windows) unreachable;
    const posix = std.posix;
    var byte: [1]u8 = undefined;
    const rc = posix.system.recvfrom(handle, &byte, 1, posix.MSG.PEEK | posix.MSG.DONTWAIT, null, null);
    return switch (posix.errno(rc)) {
        .SUCCESS => if (rc == 0) .closed else .bytes,
        .AGAIN, .INTR => .nothing,
        else => .closed,
    };
}

/// The awake time in nanoseconds `limit` from now, or `unlimited` for a zero limit.
fn deadlineFrom(io: Io, limit: Io.Duration) i64 {
    const ns = nanoseconds(limit);
    return if (ns == 0) Connection.unlimited else nowNanoseconds(io) +| ns;
}

/// The idle keep-alive connections of the server, without a task each, and the cap of the
/// worker tasks. One task of the server, `Server.runParker`, waits for bytes on all parked
/// sockets. A connection with bytes gets a worker task again, or waits in `ready` when the
/// worker tasks are at `cap`. New connections pass the same cap. The parker closes a parked
/// connection at its idle time limit, when its peer closed, and at the shutdown.
const Parker = struct {
    lock: Io.Mutex = .init,
    poller: ?park.Poller = null,
    /// The parked connections in the order of their park time: the head expires first.
    parked: List = .{},
    parked_count: usize = 0,
    /// The connections that wait for a worker task, in the order of arrival.
    ready: List = .{},
    /// The parked connections with bytes that the parker looks at after its wait (see
    /// `serveInline`). The list is empty at the start of each loop of the parker.
    candidates: List = .{},
    /// The response of a request that the parker runs itself. The parker keeps its memory.
    inline_out: ?Io.Writer.Allocating = null,
    /// The connections whose socket the parker watches while a handler runs.
    watching: List = .{},
    /// The connections whose socket this side closed while a poll was pending (Windows). The
    /// completion of the poll frees them.
    closing_count: usize = 0,
    /// On POSIX systems: the connections whose socket this side closed while the parker
    /// watched it. The parker frees them before its next wait.
    closed: List = .{},
    /// The connections the parker owns: parked, in `ready`, or with a closed socket. The
    /// supervisor ends after the parker gave up the last one.
    held: std.atomic.Value(usize) = .init(0),
    /// The worker tasks that run now.
    active: u32 = 0,
    cap: u32 = 1,
    /// The slots of the POSIX wait.
    snapshot: std.ArrayList(*park.Slot) = .empty,
    /// Set by the accept loop while a new connection waits for a permit. The parker then
    /// closes the parked connection that waited longest. Only the parker task closes a parked
    /// connection: on POSIX systems its wait uses the slots without the lock.
    evict: std.atomic.Value(bool) = .init(false),

    /// An intrusive list in the order of insertion.
    const List = struct {
        head: ?*Connection = null,
        tail: ?*Connection = null,

        fn push(l: *List, c: *Connection) void {
            c.prev = l.tail;
            c.next = null;
            if (l.tail) |t| t.next = c else l.head = c;
            l.tail = c;
        }

        fn remove(l: *List, c: *Connection) void {
            if (c.prev) |p| p.next = c.next else l.head = c.next;
            if (c.next) |n| n.prev = c.prev else l.tail = c.prev;
            c.prev = null;
            c.next = null;
        }

        fn pop(l: *List) ?*Connection {
            const c = l.head orelse return null;
            l.remove(c);
            return c;
        }
    };

    fn start(p: *Parker, gpa: Allocator, cap: u32) !void {
        p.poller = try park.Poller.init(gpa);
        p.cap = @max(cap, 1);
    }

    fn stop(p: *Parker) void {
        if (p.poller) |*poller| poller.deinit();
        p.poller = null;
        if (p.inline_out) |*aw| aw.deinit();
        p.inline_out = null;
    }

    /// True when the parker can run a quick request itself: on Linux, for plaintext without
    /// authorization. A check of a token can wait for I/O.
    fn inlineEnabled(p: *Parker, self: *Server) bool {
        _ = p;
        return builtin.os.tag == .linux and self.options.tls == null and self.options.auth == null and !self.closing.load(.acquire);
    }

    const InlineEnd = enum { parked, close, task };

    /// Run the request of a ready connection in the task of the parker, without a new task.
    /// This happens only when the socket holds exactly one complete request (one look with
    /// `MSG_PEEK`, without a wait) and `McpServer.isQuickMethod` accepts its `Mcp-Method` and
    /// `Mcp-Name` headers. The response goes to a buffer, and then to the socket without a
    /// wait. The connection task sends a rest that does not fit. Each other request gets a
    /// task, as before. A new task and its thread wake cost more than a quick handler.
    fn serveInline(p: *Parker, self: *Server, conn: *Connection) void {
        const end = p.runInline(self, conn);
        const io = self.io;
        p.lock.lockUncancelable(io);
        defer p.lock.unlock(io);
        switch (end) {
            .parked => {
                p.poller.?.arm(&conn.slot, conn.stream.socket.handle) catch {
                    p.finishLocked(self, conn);
                    return;
                };
                conn.data_seen = false;
                conn.hangup_seen = false;
                conn.poll_phase = .idle;
                conn.park_deadline = deadlineFrom(io, self.limits.http.idle_timeout);
                conn.state.store(.parked, .release);
                p.parked.push(conn);
                p.parked_count += 1;
            },
            .close => p.finishLocked(self, conn),
            .task => {
                conn.park_deadline = deadlineFrom(io, self.limits.http.head_timeout);
                p.ready.push(conn);
            },
        }
    }

    fn runInline(p: *Parker, self: *Server, conn: *Connection) InlineEnd {
        if (builtin.os.tag != .linux) return .task;
        // At the shutdown, the connection goes the usual way.
        if (self.closing.load(.acquire)) return .task;
        const linux = std.os.linux;
        const bufs = self.buffers.take(self) orelse return .task;
        defer self.buffers.give(self, bufs);
        const fd = conn.stream.socket.handle;
        const rc = linux.recvfrom(fd, bufs.read.ptr, bufs.read.len, linux.MSG.PEEK | linux.MSG.DONTWAIT, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) return .close,
            else => return .task,
        }
        if (rc >= bufs.read.len) return .task;
        const total = inlineRequestLength(self, bufs.read[0..rc]) orelse return .task;
        if (total != rc) return .task;

        // From here on the bytes leave the socket. An error closes the connection.
        const aw = if (p.inline_out) |*w| w else blk: {
            p.inline_out = Io.Writer.Allocating.initCapacity(self.gpa, 16 * 1024) catch return .task;
            break :blk &p.inline_out.?;
        };
        aw.clearRetainingCapacity();
        defer if (aw.writer.buffer.len > 1024 * 1024) {
            aw.deinit();
            p.inline_out = null;
        };
        var reader = conn.stream.reader(self.io, bufs.read[0..total]);
        conn.inline_mode = true;
        defer conn.inline_mode = false;
        var http_server: http.Server = .init(&reader.interface, &aw.writer);
        var request = http_server.receiveHead() catch return .close;
        const keep_alive = handleRequest(conn, &request, &reader) catch false;
        const reuse = keep_alive and request.head.keep_alive and reader.interface.bufferedLen() == 0;
        aw.writer.flush() catch return .close;
        const data = aw.written();
        var sent: usize = 0;
        while (sent < data.len) {
            const n = linux.sendto(fd, data[sent..].ptr, data.len - sent, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(n)) {
                .SUCCESS => sent += n,
                .INTR => {},
                .AGAIN => break,
                else => return .close,
            }
        }
        if (sent < data.len) {
            // The client does not read now. The task of the connection sends the rest, and
            // the parker does not wait.
            conn.pending_out = self.gpa.dupe(u8, data[sent..]) catch return .close;
            conn.pending_close = !reuse;
            return .task;
        }
        return if (reuse) .parked else .close;
    }

    /// Wake the task of the parker. Safe from any task.
    fn wakeTask(p: *Parker) void {
        if (p.poller) |*poller| poller.wake();
    }

    /// Give a new connection a worker task, or a place in `ready` when the tasks are at the
    /// cap. False when the server has no memory for it.
    fn admit(p: *Parker, self: *Server, conn: *Connection) bool {
        const io = self.io;
        p.lock.lockUncancelable(io);
        defer p.lock.unlock(io);
        if (p.active < p.cap) return p.spawnLocked(self, conn, false);
        conn.park_deadline = deadlineFrom(io, self.limits.http.head_timeout);
        conn.state.store(.queued, .release);
        p.ready.push(conn);
        _ = p.held.fetchAdd(1, .acq_rel);
        if (p.ready.head == conn) p.wakeTask();
        return true;
    }

    /// A worker task ended. Give the next ready connection a task.
    fn release(p: *Parker, self: *Server) void {
        p.lock.lockUncancelable(self.io);
        defer p.lock.unlock(self.io);
        p.active -= 1;
        p.spawnReadyLocked(self);
    }

    /// Watch the socket of `conn` while the handler of its request runs. A close by the peer
    /// cancels the request through `token`. The parker notes the bytes that arrive, for the
    /// read after the handler. False when the parker cannot watch the socket now. The task
    /// then reads the socket itself.
    fn watchHandler(p: *Parker, self: *Server, conn: *Connection, token: *Transport.CancelToken) bool {
        // On Windows `AFD_POLL` tells a disconnect from bytes. On a POSIX system `poll` gives
        // only "readable", and the parker peeks at one byte (`MSG_PEEK`) to tell them apart.
        // The peek does not take bytes from the socket.
        p.lock.lockUncancelable(self.io);
        defer p.lock.unlock(self.io);
        const poller = &(p.poller orelse return false);
        conn.cancel_token = token;
        // A poll from the previous request can still be pending, when its bytes arrived in
        // the buffer of the task. It watches the socket the same way.
        if (conn.poll_phase == .handler) return true;
        if (conn.poll_phase != .none) return false;
        conn.data_seen = false;
        conn.hangup_seen = false;
        poller.arm(&conn.slot, conn.stream.socket.handle) catch {
            conn.cancel_token = null;
            return false;
        };
        conn.poll_phase = .handler;
        p.watching.push(conn);
        if (!park.is_windows) poller.wake();
        return true;
    }

    /// The handler of `conn` ended. A disconnect from now on cancels no request.
    fn forgetToken(p: *Parker, self: *Server, conn: *Connection) void {
        p.lock.lockUncancelable(self.io);
        defer p.lock.unlock(self.io);
        conn.cancel_token = null;
    }

    const After = enum {
        /// The parker owns the connection. The task ends.
        parked,
        /// The task closes the connection (through `takeOverPending` when a poll is pending).
        close,
        /// The task reads the next request.
        read_next,
    };

    /// Decide what the task does after a request. `reuse`: the connection can carry one more
    /// request. `empty`: no bytes wait in the buffer of the task.
    fn afterRequest(p: *Parker, self: *Server, conn: *Connection, reuse: bool, empty: bool) After {
        const io = self.io;
        p.lock.lockUncancelable(io);
        defer p.lock.unlock(io);
        conn.cancel_token = null;
        const poller = &(p.poller orelse return if (reuse) .read_next else .close);
        const keep = reuse and !self.closing.load(.acquire);
        switch (conn.poll_phase) {
            .handler => {
                // The poll is pending: nothing arrived while the handler ran.
                if (!keep) return .close;
                if (empty) {
                    p.watching.remove(conn);
                    p.parkLocked(self, conn);
                    if (!park.is_windows and p.parked.head == conn) poller.wake();
                    return .parked;
                }
                // Bytes wait in the buffer of the task. The poll stays pending and watches
                // the socket for the next request too.
                return .read_next;
            },
            .none => {
                if (!keep or conn.hangup_seen) return .close;
                if (conn.data_seen or !empty) return .read_next;
                // No poll ran, for a response without a handler: park with a new poll.
                poller.arm(&conn.slot, conn.stream.socket.handle) catch return .read_next;
                p.parkLocked(self, conn);
                if (!park.is_windows) poller.wake();
                return .parked;
            },
            .idle, .closing => unreachable,
        }
    }

    /// The poll of `conn` runs. Make the connection a parked one and end its task.
    fn parkLocked(p: *Parker, self: *Server, conn: *Connection) void {
        conn.poll_phase = .idle;
        conn.park_deadline = deadlineFrom(self.io, self.limits.http.idle_timeout);
        conn.state.store(.parked, .release);
        p.parked.push(conn);
        p.parked_count += 1;
        // A new connection waits for a permit: the parker can close this one now.
        if (p.evict.load(.acquire)) p.wakeTask();
        p.handOverLocked(self, conn);
    }

    /// The task of `conn` ends. The parker owns the connection from now on.
    fn handOverLocked(p: *Parker, self: *Server, conn: *Connection) void {
        _ = p.held.fetchAdd(1, .acq_rel);
        p.active -= 1;
        p.spawnReadyLocked(self);
        self.untrack(conn);
    }

    /// The task of `conn` ends with a close. When a poll is pending for the socket, the parker
    /// takes the connection and closes the socket. The completion of the poll then frees the
    /// connection. True in that case. False when the task closes the connection itself.
    fn takeOverPending(p: *Parker, self: *Server, conn: *Connection) bool {
        const io = self.io;
        p.lock.lockUncancelable(io);
        defer p.lock.unlock(io);
        conn.cancel_token = null;
        switch (conn.poll_phase) {
            .none => return false,
            .handler => p.watching.remove(conn),
            .idle, .closing => unreachable,
        }
        p.closeWithPollLocked(self, conn);
        p.handOverLocked(self, conn);
        return true;
    }

    /// Close the socket of `conn` while its poll is pending. On Windows the close completes
    /// the poll, and the completion frees the connection. A cancel of the poll would make
    /// the kernel walk every pending poll of the helper handle. That is slow with many
    /// parked connections. On POSIX systems the parker frees the connection in its next
    /// loop, after the `poll` that can still have the socket returned.
    fn closeWithPollLocked(p: *Parker, self: *Server, conn: *Connection) void {
        conn.stream.close(self.io);
        conn.closed = true;
        conn.poll_phase = .closing;
        conn.state.store(.parked_closing, .release);
        p.closing_count += 1;
        if (!park.is_windows) {
            p.closed.push(conn);
            p.wakeTask();
        }
    }

    /// Free the connections that `closeWithPollLocked` closed (POSIX). The parker calls it
    /// between two waits: no `poll` has their slots then.
    fn freeClosedLocked(p: *Parker, self: *Server) void {
        while (p.closed.pop()) |conn| {
            conn.poll_phase = .none;
            p.closing_count -= 1;
            p.finishLocked(self, conn);
        }
    }

    /// Start the worker task of `conn`, which then has the state `running` and is in
    /// `Server.connections`. `was_held`: the parker owned the connection before.
    fn spawnLocked(p: *Parker, self: *Server, conn: *Connection, was_held: bool) bool {
        const io = self.io;
        if (conn.future_live) {
            conn.worker.await(io);
            conn.future_live = false;
        }
        self.track(conn) catch return false;
        conn.worker = io.concurrent(Connection.work, .{conn}) catch {
            self.untrack(conn);
            return false;
        };
        conn.future_live = true;
        conn.state.store(.running, .release);
        p.active += 1;
        if (was_held) _ = p.held.fetchSub(1, .acq_rel);
        return true;
    }

    /// Give the ready connections a worker task, up to the cap.
    fn spawnReadyLocked(p: *Parker, self: *Server) void {
        while (p.active < p.cap) {
            const conn = p.ready.pop() orelse return;
            if (!p.spawnLocked(self, conn, true)) p.finishLocked(self, conn);
        }
    }

    /// Free a connection the parker owns: no poll is pending for it.
    fn finishLocked(p: *Parker, self: *Server, conn: *Connection) void {
        const io = self.io;
        if (conn.future_live) {
            conn.worker.await(io);
            conn.future_live = false;
        }
        if (!conn.closed) {
            conn.stream.close(io);
            conn.closed = true;
        }
        self.permits.post(io);
        _ = p.held.fetchSub(1, .acq_rel);
        self.freeConnection(conn);
        self.supervisor_wake.set(io);
    }

    /// Close a parked connection. On Windows the poll of the socket is pending: close the
    /// socket, and free the connection when the completion arrives.
    fn closeParkedLocked(p: *Parker, self: *Server, conn: *Connection) void {
        p.parked.remove(conn);
        p.parked_count -= 1;
        if (park.is_windows) {
            p.closeWithPollLocked(self, conn);
        } else {
            conn.poll_phase = .none;
            p.finishLocked(self, conn);
        }
    }

    fn handleEventLocked(p: *Parker, self: *Server, ev: park.Event) void {
        const conn: *Connection = @alignCast(@fieldParentPtr("slot", ev.slot));
        switch (conn.poll_phase) {
            .closing => {
                // On POSIX systems `freeClosedLocked` frees the connection after this wait.
                if (!park.is_windows) return;
                conn.poll_phase = .none;
                p.closing_count -= 1;
                p.finishLocked(self, conn);
            },
            .idle => {
                if (ev.readable) {
                    p.parked.remove(conn);
                    p.parked_count -= 1;
                    conn.poll_phase = .none;
                    conn.park_deadline = deadlineFrom(self.io, self.limits.http.head_timeout);
                    conn.state.store(.queued, .release);
                    // The parker looks at the bytes after this wait, and runs a quick request
                    // itself.
                    if (p.inlineEnabled(self)) p.candidates.push(conn) else p.ready.push(conn);
                } else if (ev.hangup) {
                    p.parked.remove(conn);
                    p.parked_count -= 1;
                    conn.poll_phase = .none;
                    p.finishLocked(self, conn);
                } else {
                    // The wait ended for another reason. Watch the socket again.
                    p.poller.?.arm(&conn.slot, conn.stream.socket.handle) catch {
                        p.parked.remove(conn);
                        p.parked_count -= 1;
                        conn.poll_phase = .none;
                        p.finishLocked(self, conn);
                    };
                }
            },
            .handler => {
                var readable = ev.readable;
                var hangup = ev.hangup;
                // `poll` gives "readable" for bytes and for the close by the peer. A peek
                // tells them apart and leaves the bytes for the task of the connection.
                if (!park.is_windows and readable and !hangup) switch (peekSocket(conn.stream.socket.handle)) {
                    .bytes => {},
                    .closed => {
                        readable = false;
                        hangup = true;
                    },
                    .nothing => readable = false,
                };
                if (readable or hangup) {
                    conn.poll_phase = .none;
                    p.watching.remove(conn);
                    if (readable) conn.data_seen = true;
                    if (hangup) {
                        conn.hangup_seen = true;
                        if (conn.cancel_token) |token| {
                            log.debug("the client of a request disconnected", .{});
                            token.cancel(self.io, disconnect_reason);
                        }
                    }
                } else {
                    p.poller.?.arm(&conn.slot, conn.stream.socket.handle) catch {
                        conn.poll_phase = .none;
                        p.watching.remove(conn);
                    };
                }
            },
            .none => {},
        }
    }

    /// Close the connections whose time limit passed: parked ones at `idle_timeout`, queued
    /// ones at `head_timeout`.
    fn expireLocked(p: *Parker, self: *Server, now: i64) void {
        while (p.parked.head) |c| {
            if (c.park_deadline > now) break;
            p.closeParkedLocked(self, c);
        }
        while (p.ready.head) |c| {
            if (c.park_deadline > now) break;
            p.ready.remove(c);
            p.finishLocked(self, c);
        }
    }

    /// Close the parked connection that waited longest when a new connection waits for a
    /// permit. Its close gives the permit back. RFC 9112 section 9.6 lets a server close an
    /// idle connection at any time.
    fn evictLocked(p: *Parker, self: *Server) void {
        const conn = p.parked.head orelse return;
        if (p.evict.cmpxchgStrong(true, false, .acq_rel, .acquire) != null) return;
        p.closeParkedLocked(self, conn);
    }

    /// The nearest time limit of the parked and the queued connections, or `unlimited`.
    fn nextDeadlineLocked(p: *Parker) i64 {
        var next: i64 = Connection.unlimited;
        if (p.parked.head) |c| next = @min(next, c.park_deadline);
        if (p.ready.head) |c| next = @min(next, c.park_deadline);
        return next;
    }

    /// At the shutdown: close every parked and queued connection at once.
    fn closeAllLocked(p: *Parker, self: *Server) void {
        while (p.parked.head) |c| p.closeParkedLocked(self, c);
        while (p.ready.pop()) |c| p.finishLocked(self, c);
    }
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
        @intFromEnum(errors.Code.rate_limited) => .too_many_requests,
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

/// Handle one request on a connection. Returns whether the connection can carry one more request.
/// `socket` is the reader of the socket. It detects a disconnect while a handler runs.
fn handleRequest(conn: *Connection, request: *http.Server.Request, socket: *Io.net.Stream.Reader) !bool {
    const self = conn.owner;
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
                    .status = @enumFromInt(c.status),
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
    // The body obeys `limits.http.idle_timeout` from the end of the head.
    if (!conn.startTimer(.body, self.limits.http.idle_timeout)) return false;
    var body_buf: [4096]u8 = undefined;
    const body_reader = request.readerExpectNone(&body_buf);
    const body = body_reader.allocRemaining(arena, .limited(self.limits.http.max_body_bytes)) catch |e| switch (e) {
        error.StreamTooLong => {
            try request.respond("", .{ .status = .payload_too_large, .keep_alive = false });
            return false;
        },
        error.OutOfMemory => return error.OutOfMemory,
        error.ReadFailed => return false,
    };
    if (!conn.stopTimer()) return false;
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
        .request => |req| return handleRpcRequest(conn, request, socket, arena, head, req, principal),
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

fn handleRpcRequest(conn: *Connection, request: *http.Server.Request, socket: *Io.net.Stream.Reader, arena: Allocator, head: Head, req: jsonrpc.Message.Request, principal: ?*resource_server.Principal) !bool {
    const self = conn.owner;
    // Header presence, mirror validation and version support run before dispatch on HTTP.
    const schema = if (std.mem.eql(u8, req.method, "tools/call")) toolSchema(self, req.params) else null;
    if (try envelope.verify(arena, head.envelope_headers, req.method, req.params, schema)) |rejection| {
        // A legacy client without headers gets a clear version message.
        if (head.envelope_headers.protocol_version == null and std.mem.eql(u8, req.method, "initialize")) {
            const err = try errors.unsupportedProtocolVersion(arena, &version.supported_versions, "unknown");
            try respondError(request, .bad_request, req.id, err);
            return true;
        }
        try respondError(request, .bad_request, req.id, try rejection.rpcError(arena));
        return true;
    }

    var token: Transport.CancelToken = .{};
    var exchange: Exchange = .{
        .owner = self,
        .request = request,
        .arena = arena,
        .id = req.id,
        .token = &token,
        .long_lived = std.mem.eql(u8, req.method, "subscriptions/listen"),
        .force_sse = self.options.response_mode == .sse,
    };
    var dispatch: Dispatch = .{ .conn = conn, .exchange = &exchange, .socket = socket, .req = req, .principal = principal, .arena = arena };
    // The parker runs a quick request itself (see `Parker.serveInline`). No poll watches the
    // socket, and nothing cancels the handler, as on the reader of a stream transport.
    if (conn.inline_mode) {
        // The headers said quick. The parker runs only a request that is quick by its body
        // too. A request that is not ends with an error and the close of the connection.
        const tool = if (req.params) |params| json.getString(params, "name") else null;
        if (!self.server.isQuickMethod(req.method, tool)) {
            try respondErrorOptions(request, .service_unavailable, req.id, errors.internalError("the request does not match its Mcp-Method and Mcp-Name headers"), false);
            return false;
        }
        dispatch.run();
        return exchange.reusable and !token.isCancelled() and request.head.keep_alive;
    }
    // A disconnect of the client cancels the request, also while the handler does not write.
    // For a plaintext connection, the poll of the parker watches the socket, and the handler
    // runs in this task. A cancel of this task (a time limit or the shutdown) then cancels
    // the handler. Each other task would cost a thread wake and a cancel per request.
    if (conn.use_poll and self.parker.watchHandler(self, conn, &token)) {
        // `token` is in this frame. The parker must not cancel it after the return.
        defer self.parker.forgetToken(self, conn);
        dispatch.run();
        return exchange.reusable and !token.isCancelled() and request.head.keep_alive;
    }
    // Otherwise (TLS) the handler runs in a task of its own. Meanwhile a watch task reads the
    // socket, and the task of the connection cancels it when the handler ends.
    var handler: ?Io.Future(void) = self.io.concurrent(Dispatch.run, .{&dispatch}) catch null;
    if (handler) |*h| {
        var watcher: ?Io.Future(void) = self.io.concurrent(Connection.watch, .{ conn, socket, &dispatch }) catch null;
        if (watcher == null) conn.watch(socket, &dispatch);
        if (conn.timedOut()) {
            // A time limit or the shutdown canceled this task. The handler gets the cancel.
            h.cancel(self.io);
        } else if (dispatch.done.wait(self.io)) |_| {
            h.await(self.io);
        } else |_| {
            h.cancel(self.io);
        }
        // Stop the watch task. The handler ended, thus `ended` is set and the cancel of the
        // read does not look like a disconnect. The bytes it read stay in the buffer.
        if (watcher) |*w| {
            dispatch.ended.store(true, .release);
            w.cancel(self.io);
        }
    } else dispatch.run();
    // The connection of a canceled request does not carry one more request.
    return exchange.reusable and !token.isCancelled() and request.head.keep_alive;
}

/// The cancellation reason of a request whose client closed the connection.
pub const disconnect_reason = "client disconnected";

/// The time that a connection waits for its next request before it goes to the parker.
const park_linger_ms = 2;

/// The part of a request that runs in a task of its own: the handler and the end of the
/// response. Meanwhile the task of the connection reads the socket.
const Dispatch = struct {
    conn: *Connection,
    exchange: *Exchange,
    socket: *Io.net.Stream.Reader,
    req: jsonrpc.Message.Request,
    principal: ?*resource_server.Principal,
    arena: Allocator,
    /// Set when the task ended.
    ended: std.atomic.Value(bool) = .init(false),
    /// Set when the task ended. The task of the connection waits on it, and a cancel of that
    /// task ends the wait.
    done: Io.Event = .unset,

    fn run(d: *Dispatch) void {
        const self = d.conn.owner;
        const io = self.io;
        const exchange = d.exchange;
        self.server.handle(io, .{
            .kind = .streamable_http,
            .arena = d.arena,
            .message = .{ .request = d.req },
            .responder = .{ .ptr = exchange, .vtable = &exchange_vtable },
            .cancel = exchange.token,
            .context = d.principal,
            .peer = .{ .address = d.socket.stream.socket.address },
        });
        if (exchange.keepalive_future) |*f| {
            exchange.keepalive_stop.store(true, .release);
            _ = f.cancel(io);
        }
        if (!exchange.done) {
            // The handler ended without a response (cancelled): close the stream.
            if (exchange.body_writer) |*bw| bw.end() catch {} else exchange.request.respond("", .{ .status = .service_unavailable }) catch {};
        }
        // The task of the connection reads the socket. From now on it waits for the next
        // request, or for the close by the client after a response without keep-alive.
        const reuse = exchange.reusable and !exchange.token.isCancelled() and exchange.request.head.keep_alive;
        if (reuse) {
            _ = d.conn.startTimer(.idle, self.limits.http.idle_timeout);
        } else {
            _ = d.conn.startTimer(.close, close_linger);
        }
        d.ended.store(true, .release);
        d.done.set(io);
    }
};

fn toolSchema(self: *Server, params: ?Value) ?Value {
    const p = params orelse return null;
    const name = json.getString(p, "name") orelse return null;
    for (self.server.tools.items) |t| if (std.mem.eql(u8, t.def.name, name)) return t.def.inputSchema;
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
            self.write_lock.lockUncancelable(io);
            defer self.write_lock.unlock(io);
            if (self.done) return;
            const bw = &(self.body_writer orelse return);
            sse.writeComment(&bw.writer, "keepalive") catch return;
            bw.flush() catch return;
        }
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
    self.write_lock.lockUncancelable(io);
    defer self.write_lock.unlock(io);
    if (self.done) return error.Closed;
    // After a cancellation by the client, the server sends nothing more for the request.
    if (self.token.isCancelledByPeer()) return error.Closed;
    try self.startSse();
    try self.writeSse(frame);
}

fn exchangeFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const self: *Exchange = @ptrCast(@alignCast(ptr));
    self.write_lock.lockUncancelable(io);
    defer self.write_lock.unlock(io);
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
    self.write_lock.lockUncancelable(io);
    defer self.write_lock.unlock(io);
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

test "the head scan of the parker accepts only a strict head with a bounded body" {
    const ok = "POST /mcp HTTP/1.1\r\nmcp-method: tools/call\r\nmcp-name: t\r\ncontent-length: 2\r\n\r\n{}";
    const head = scanInlineHead(ok, 100).?;
    try std.testing.expectEqual(ok.len, head.len);
    try std.testing.expectEqualStrings("tools/call", head.method);
    try std.testing.expectEqualStrings("t", head.name.?);
    // A length that overflows, or that is larger than the limit.
    try std.testing.expect(scanInlineHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\r\ncontent-length: 18446744073709551615\r\n\r\n", std.math.maxInt(usize)) == null);
    try std.testing.expect(scanInlineHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\r\ncontent-length: 101\r\n\r\n", 100) == null);
    // A bare LF ends the head earlier for std: the lines after it are the body.
    try std.testing.expect(scanInlineHead("POST /mcp HTTP/1.1\nmcp-method: tools/call\nmcp-name: slow\ncontent-length: 40\n\nx\r\nmcp-method: tools/list\r\n\r\n", 100) == null);
    try std.testing.expect(scanInlineHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\ncontent-length: 0\r\n\r\n", 100) == null);
    // Two values of a header, an incomplete head, and a head without Mcp-Method.
    try std.testing.expect(scanInlineHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\r\nmcp-method: tools/call\r\n\r\n", 100) == null);
    try std.testing.expect(scanInlineHead("POST /mcp HTTP/1.1\r\nmcp-method: tools/list\r\n", 100) == null);
    try std.testing.expect(scanInlineHead("POST /mcp HTTP/1.1\r\ncontent-length: 0\r\n\r\n", 100) == null);
}

test {
    std.testing.refAllDecls(@This());
}
