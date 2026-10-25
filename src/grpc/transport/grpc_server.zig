//! The gRPC server transport: one HTTP/2 listener, one `Call` per JSON-RPC request. The
//! request metadata mirrors the Streamable HTTP headers. A JSON-RPC error that ends a call
//! before any message travels in the trailers. With `bindings.typed`, the listener also
//! serves the typed service of `typed_server.zig`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const mcp = @import("mcp");
const Transport = mcp.transport.Transport;
const envelope = mcp.transport.envelope;
const jsonrpc = mcp.jsonrpc;
const RequestId = jsonrpc.RequestId;
const errors = mcp.protocol.errors;
const version = mcp.protocol.version;
const json = mcp.json;
const tls = mcp.tls;
const resource_server = mcp.auth.resource_server;
const Connection = @import("../http2/Connection.zig");
const Stream = Connection.Stream;
const Header = Connection.Header;
const lpm = @import("../grpc/lpm.zig");
const status = @import("../grpc/status.zig");
const timeout = @import("../grpc/timeout.zig");
const messages = @import("../protobuf/messages.zig");
const codec = @import("../protobuf/codec.zig");
const service = @import("../typed/service.zig");
const typed_server = @import("typed_server.zig");
const socket_opts = mcp.transport.socket_opts;
const Deadlines = @import("deadlines.zig");

const log = std.log.scoped(.mcp_grpc);

pub const call_path = "/mcp.zig.transport.v1.Mcp/Call";
pub const content_type = "application/grpc+proto";
pub const header_error_code = "mcp-error-code";
pub const header_error_bin = "mcp-error-bin";

/// The services that the server answers. A call to a service that is off ends with
/// `UNIMPLEMENTED`.
pub const Bindings = struct {
    /// The JSON-RPC tunnel `mcp.zig.transport.v1.Mcp`.
    tunnel: bool = true,
    /// The typed service `model_context_protocol.Mcp` of the Google Cloud proto files.
    typed: bool = false,
};

pub const Options = struct {
    /// Address to bind. The default is loopback only.
    address: []const u8 = "127.0.0.1",
    port: u16 = 50051,
    /// Serve over TLS with ALPN `h2`. Null serves cleartext HTTP/2 with prior knowledge.
    tls: ?*const tls.Server = null,
    /// Require a bearer token on every call.
    auth: ?*const resource_server.ResourceServer = null,
    /// The largest request message. Overflow: `RESOURCE_EXHAUSTED`.
    max_message_bytes: usize = 4 << 20,
    /// Open connections. Overflow: the accept loop waits.
    max_connections: u32 = 256,
    /// The queue of the listen socket, as `Limits.http.listen_backlog` is for the HTTP server.
    listen_backlog: u31 = 1024,
    /// The services of the server. The default is the tunnel only.
    bindings: Bindings = .{},
    /// Set `SO_REUSEADDR` on the listen socket, as `Limits.http.reuse_address` does for the
    /// HTTP server. On POSIX, std also sets `SO_REUSEPORT`. Then a new server can bind the port
    /// while old connections of the port are in `TIME_WAIT`.
    reuse_address: bool = false,
    /// The nesting depth and the element count of a request message of the typed binding.
    /// Overflow: `INVALID_ARGUMENT`.
    typed_limits: codec.Limits = .{},
};

pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *mcp.Server,
    options: Options,
    listener: ?Io.net.Server = null,
    bound_port: u16 = 0,
    group: Io.Group = .init,
    permits: Io.Semaphore,
    closing: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    connections: std.ArrayList(*Conn) = .empty,
    connections_lock: Io.Mutex = .init,
    /// The `grpc-timeout` of the calls of every connection.
    deadlines: Deadlines = .{},
    /// The arenas of the calls that ended, for the next calls.
    arenas: ArenaPool = .{},
    /// The recent run times of the quick requests.
    costs: CallCosts = .{},
    /// The most workers of one connection. See `Conn.enqueue`.
    max_workers: u32,

    pub fn init(io: Io, gpa: Allocator, server: *mcp.Server, options: Options) Server {
        const cpus = std.Thread.getCpuCount() catch 4;
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .permits = .{ .permits = options.max_connections },
            .max_workers = @intCast(std.math.clamp(cpus, 1, max_workers_per_connection)),
        };
    }

    /// The most workers of one connection on a computer with many processors.
    pub const max_workers_per_connection = 8;

    pub fn deinit(self: *Server) void {
        if (self.listener) |*l| l.deinit(self.io);
        // Normally `serve` stopped the task already.
        self.deadlines.stop(self.io);
        // Normally `serve` stopped the task already.
        self.deadlines.stop(self.io);
        self.arenas.deinit(self.gpa);
        self.connections.deinit(self.gpa);
        self.* = undefined;
    }

    fn track(self: *Server, conn: *Conn) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        self.connections.append(self.gpa, conn) catch {};
    }

    fn untrack(self: *Server, conn: *Conn) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items, 0..) |c, i| if (c == conn) {
            _ = self.connections.swapRemove(i);
            return;
        };
    }

    /// Bind the listen socket. After this call `bound_port` has the port.
    pub fn bind(self: *Server) !void {
        var address = try Io.net.IpAddress.parse(self.options.address, self.options.port);
        self.listener = try address.listen(self.io, .{ .reuse_address = self.options.reuse_address, .kernel_backlog = self.options.listen_backlog });
        self.bound_port = self.listener.?.socket.address.getPort();
    }

    /// Accept connections until a call to `shutdown`. A cancel also ends `serve`. After a
    /// cancel, the server accepts no more connections.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        var accept_future = try self.io.concurrent(acceptLoop, .{self});
        self.stop_event.wait(self.io) catch {};
        // On Windows a cancel can miss an accept that waits. The wake connection ends it.
        mcp.util.wake.cancelAcceptLoop(self.io, &accept_future, self.listener.?.socket.address, &self.closing);
        self.server.shutdownSubscriptions(self.io);
        self.group.await(self.io) catch {};
        self.deadlines.stop(self.io);
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
            // Without `TCP_NODELAY`, the Nagle algorithm holds the data and the trailers of a
            // response until the client acknowledges the headers. A failure costs latency only,
            // and `setNoDelay` logs it. After a cancel, the next accept ends the loop.
            socket_opts.setNoDelay(self.io, stream.socket) catch {};
            self.permits.waitUncancelable(self.io);
            const conn = self.gpa.create(Conn) catch {
                stream.close(self.io);
                self.permits.post(self.io);
                continue;
            };
            conn.* = .{ .owner = self, .stream = stream };
            self.track(conn);
            self.group.concurrent(self.io, Conn.run, .{conn}) catch {
                self.untrack(conn);
                stream.close(self.io);
                self.permits.post(self.io);
                self.gpa.destroy(conn);
            };
        }
    }

    /// Accept no more connections and end the open connections. Safe to call from another task.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .release);
        self.stop_event.set(self.io);
        self.server.shutdownSubscriptions(self.io);
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items) |c| {
            if (c.h2_ready.load(.acquire)) c.h2.shutdown();
            c.stream.shutdown(self.io, .both) catch {};
        }
    }
};

/// The arenas of calls that ended. A call takes one and gives it back with its memory, up to
/// `keep_bytes`. Before, each call started an empty arena and freed it at the end. A call of
/// the typed binding that grew its arena past 64 KiB, for example `ListTools`, then mapped
/// and unmapped pages each time. On Linux that was one `mmap` and one `munmap` for each call.
const ArenaPool = struct {
    lock: Io.Mutex = .init,
    free: std.ArrayList(*std.heap.ArenaAllocator) = .empty,

    /// The memory that an arena keeps for the next call.
    const keep_bytes = 256 * 1024;
    /// The most arenas that the pool keeps.
    const max_kept = 64;

    fn acquire(p: *ArenaPool, io: Io, gpa: Allocator) Allocator.Error!*std.heap.ArenaAllocator {
        {
            p.lock.lockUncancelable(io);
            defer p.lock.unlock(io);
            if (p.free.pop()) |a| return a;
        }
        const a = try gpa.create(std.heap.ArenaAllocator);
        a.* = .init(gpa);
        return a;
    }

    fn release(p: *ArenaPool, io: Io, gpa: Allocator, a: *std.heap.ArenaAllocator) void {
        _ = a.reset(.{ .retain_with_limit = keep_bytes });
        {
            p.lock.lockUncancelable(io);
            defer p.lock.unlock(io);
            if (p.free.items.len < max_kept) {
                if (p.free.append(gpa, a)) |_| return else |_| {}
            }
        }
        a.deinit();
        gpa.destroy(a);
    }

    fn deinit(p: *ArenaPool, gpa: Allocator) void {
        for (p.free.items) |a| {
            a.deinit();
            gpa.destroy(a);
        }
        p.free.deinit(gpa);
    }
};

/// The recent run times of the quick requests, by method and tool name. Some quick requests
/// take long, for example `tools/list` of the typed binding with a large result. Such a
/// request does not run in the read task, because there it holds the calls after it. In the
/// read task, 64 calls of the typed `ListTools` ran 5 times slower than in tasks of their own.
pub const CallCosts = struct {
    /// An average of the run time in nanoseconds for each slot.
    slots: [slot_count]std.atomic.Value(u32) = @splat(.init(0)),

    const slot_count = 64;
    /// A quick request with a longer average run time runs in a worker of the connection.
    pub const slow_ns = 25 * std.time.ns_per_us;

    /// The slot of a request. Two kinds of requests can share a slot.
    pub fn slot(method: []const u8, params: ?Value) usize {
        var h: std.hash.Wyhash = .init(0);
        h.update(method);
        if (params) |p| if (json.getString(p, "name")) |name| {
            h.update("/");
            h.update(name);
        };
        return @intCast(h.final() % slot_count);
    }

    pub fn isSlow(c: *const CallCosts, i: usize) bool {
        return c.slots[i].load(.monotonic) > slow_ns;
    }

    /// Add the run time of one request to the average of its slot. One sample moves the
    /// average by an eighth of the difference. Because of the limit on the sample, one late
    /// call does not make the slot slow. The tasks race on a slot, and a lost sample is no
    /// problem.
    pub fn record(c: *CallCosts, i: usize, ns: u64) void {
        const sample: i64 = @intCast(@min(ns, 2 * slow_ns));
        const old: i64 = c.slots[i].load(.monotonic);
        c.slots[i].store(@intCast(old + @divTrunc(sample - old, 8)), .monotonic);
    }
};

/// The nanoseconds from `start` to now.
pub fn nsSince(io: Io, start: Io.Timestamp) u64 {
    return @intCast(@max(0, start.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds));
}

const Conn = struct {
    owner: *Server,
    stream: Io.net.Stream,
    group: Io.Group = .init,
    h2: *Connection = undefined,
    h2_ready: std.atomic.Value(bool) = .init(false),
    /// The burst of frames of `reader_spent_ns`. See `Connection.burst`.
    reader_burst: u32 = 0,
    /// The time that the calls of this burst took in the read task. Only the read task uses
    /// the field.
    reader_spent_ns: u64 = 0,
    /// Guards the queue and `workers`.
    queue_lock: Io.Mutex = .init,
    /// The quick calls for the workers, in order. See `enqueue`.
    queue_head: ?*Moved = null,
    queue_tail: ?*Moved = null,
    /// The workers that run.
    workers: u32 = 0,

    /// The most time that the calls of one burst take in the read task. The next calls of
    /// the burst go to the workers, which run at the same time.
    const reader_budget_ns = 1 * std.time.ns_per_ms;

    /// True when a call of the current burst can start in the read task.
    fn readerHasBudget(conn: *Conn) bool {
        const b = conn.h2.burst();
        if (b != conn.reader_burst) {
            conn.reader_burst = b;
            conn.reader_spent_ns = 0;
        }
        return conn.reader_spent_ns < reader_budget_ns;
    }

    /// Give a quick call to the workers of the connection. A worker takes the calls of the
    /// queue in order, and it ends when the queue is empty. A new worker starts only when
    /// fewer than `Server.max_workers` run. Thus a burst of quick calls wakes a few workers,
    /// and a worker that ends a call takes the next one without a wake-up. Before, each call
    /// started a task: under a load of 64 calls on Linux, the server grew to more than 150
    /// threads. A worker runs only quick calls, which do not wait, thus a call in the queue
    /// waits only for the calls before it.
    fn enqueue(conn: *Conn, m: *Moved) void {
        const io = conn.owner.io;
        m.next = null;
        m.queued_at = .now(io, .awake);
        var start = false;
        {
            conn.queue_lock.lockUncancelable(io);
            defer conn.queue_lock.unlock(io);
            if (conn.queue_tail) |t| t.next = m else conn.queue_head = m;
            conn.queue_tail = m;
            if (conn.workers < conn.owner.max_workers) {
                conn.workers += 1;
                start = true;
            }
        }
        // Without a task, the read task runs the queue itself.
        if (start) conn.group.concurrent(io, workerRun, .{conn}) catch workerRun(conn);
    }

    /// The next call of the queue, or null when the queue is empty. Then the worker ends.
    fn dequeue(conn: *Conn) ?*Moved {
        const io = conn.owner.io;
        conn.queue_lock.lockUncancelable(io);
        defer conn.queue_lock.unlock(io);
        const m = conn.queue_head orelse {
            conn.workers -= 1;
            return null;
        };
        conn.queue_head = m.next;
        if (m.next == null) conn.queue_tail = null;
        return m;
    }

    fn workerRun(conn: *Conn) void {
        while (conn.dequeue()) |m| m.runQueued();
    }

    fn run(conn: *Conn) Io.Cancelable!void {
        const self = conn.owner;
        const io = self.io;
        defer {
            self.untrack(conn);
            conn.stream.close(io);
            self.permits.post(io);
            self.gpa.destroy(conn);
        }
        const in_buf = self.gpa.alloc(u8, tls.Connection.min_input_buffer_len) catch return;
        defer self.gpa.free(in_buf);
        const out_buf = self.gpa.alloc(u8, tls.Connection.min_output_buffer_len) catch return;
        defer self.gpa.free(out_buf);
        var reader = conn.stream.reader(io, in_buf);
        var writer = conn.stream.writer(io, out_buf);

        var tls_conn: tls.Connection = undefined;
        var tls_active = false;
        var tls_read_buf: []u8 = &.{};
        var tls_write_buf: []u8 = &.{};
        defer if (tls_active) {
            tls_conn.end() catch {};
            writer.interface.flush() catch {};
            tls_conn.deinit();
            self.gpa.free(tls_read_buf);
            self.gpa.free(tls_write_buf);
        };
        if (self.options.tls) |tls_server| {
            tls_read_buf = self.gpa.alloc(u8, tls.Connection.min_read_buffer_len) catch return;
            tls_write_buf = self.gpa.alloc(u8, 16 * 1024) catch {
                self.gpa.free(tls_read_buf);
                return;
            };
            tls_conn = tls_server.accept(&reader.interface, &writer.interface, .{
                .io = io,
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .allow_truncation_attacks = true,
            }) catch {
                self.gpa.free(tls_read_buf);
                self.gpa.free(tls_write_buf);
                return;
            };
            tls_active = true;
            // A client that negotiated another protocol gets no HTTP/2.
            if (tls_conn.alpn()) |alpn| if (!std.mem.eql(u8, alpn, "h2")) return;
        }
        const in: *Io.Reader = if (tls_active) &tls_conn.reader else &reader.interface;
        const out: *Io.Writer = if (tls_active) &tls_conn.writer else &writer.interface;
        conn.h2 = Connection.init(self.gpa, io, in, out, .{
            .role = .server,
            .on_stream = onStream,
            .userdata = conn,
            .max_concurrent_streams = self.server.options.limits.max_in_flight_requests,
        }) catch return;
        defer conn.h2.deinit();
        conn.h2_ready.store(true, .release);
        defer conn.h2_ready.store(false, .release);
        conn.h2.handshake() catch return;
        conn.h2.run();
        conn.group.await(io) catch {};
    }

    /// The read task calls this function for each new call. A complete request that can be
    /// quick starts in the read task: see `serveOnReader`. After the budget of the burst, it
    /// goes to the workers. Else the call gets a task of its own.
    fn onStream(userdata: ?*anyopaque, stream: *Stream) void {
        const conn: *Conn = @ptrCast(@alignCast(userdata.?));
        // The check of a bearer token can wait for the network, thus such a call always gets
        // a task.
        if (conn.owner.options.auth == null) {
            if (stream.peerEnded()) {
                if (mayBeQuick(conn.owner, stream.headers.items)) {
                    if (conn.readerHasBudget()) return serveOnReader(conn, stream);
                    return queueStream(conn, stream);
                }
            } else {
                // Each call has one request message. The connection gives the stream again
                // when the message is complete, thus no task waits for it. A call that ends
                // from its headers alone gets a task at once: the client can wait for that
                // answer before it sends the message.
                if (!endsFromHeaders(conn.owner, stream.headers.items) and stream.dispatchAtEnd()) return;
            }
        }
        conn.group.concurrent(conn.owner.io, handleStream, .{ conn, stream }) catch {
            stream.cancel();
            stream.close();
        };
    }
};

/// True when the call ends from its headers alone, before a look at the message. The checks
/// are the first checks of `startCall`.
fn endsFromHeaders(self: *Server, headers: []const Header) bool {
    const method = Connection.findHeader(headers, ":method") orelse "";
    const path = Connection.findHeader(headers, ":path") orelse "";
    const ct = Connection.findHeader(headers, "content-type") orelse "";
    if (!std.mem.eql(u8, method, "POST")) return true;
    if (!std.ascii.startsWithIgnoreCase(ct, "application/grpc")) return true;
    const typed = self.options.bindings.typed and service.Rpc.fromPath(path) != null;
    const tunnel = self.options.bindings.tunnel and std.mem.eql(u8, path, call_path);
    if (!tunnel and !typed) return true;
    if (Connection.findHeader(headers, "grpc-encoding")) |encoding| {
        if (!std.mem.eql(u8, encoding, "identity")) return true;
    }
    if (Connection.findHeader(headers, "grpc-timeout")) |t| _ = timeout.parse(t) catch return true;
    return false;
}

/// False when the metadata of the call tells that the request is not quick. Then the read
/// task does not read the request, and the call gets a task at once. Without the metadata, the
/// result is true, and the read task reads the request to know. The metadata of the tunnel
/// must agree with the message, else the call ends with an error. Thus the metadata steers
/// only where a call runs.
fn mayBeQuick(self: *Server, headers: []const Header) bool {
    const path = Connection.findHeader(headers, ":path") orelse return true;
    if (self.options.bindings.tunnel and std.mem.eql(u8, path, call_path)) {
        const method = Connection.findHeader(headers, envelope.header_method) orelse return true;
        if (!std.mem.eql(u8, method, "tools/call")) return self.server.isQuickMethod(method, null);
        const name = Connection.findHeader(headers, envelope.header_name) orelse return true;
        return self.server.isQuickMethod(method, name);
    }
    if (self.options.bindings.typed) if (service.Rpc.fromPath(path)) |rpc| {
        if (rpc != .call_tool) return self.server.isQuickMethod(rpc.method(), null);
        const name = Connection.findHeader(headers, rpc.routeHeader().?) orelse return true;
        return self.server.isQuickMethod(rpc.method(), name);
    };
    return true;
}

fn handleStream(conn: *Conn, stream: *Stream) void {
    const self = conn.owner;
    defer stream.close();
    const arena_state = self.arenas.acquire(self.io, self.gpa) catch return logCallError(error.OutOfMemory);
    defer self.arenas.release(self.io, self.gpa, arena_state);
    _ = serveCall(conn, stream, arena_state, .task) catch |e| logCallError(e);
}

/// Give a call with a complete request to the workers before a look at the request. A worker
/// runs it as the read task does: a call that is not quick then gets a task of its own.
fn queueStream(conn: *Conn, stream: *Stream) void {
    const self = conn.owner;
    const arena_state = self.arenas.acquire(self.io, self.gpa) catch {
        logCallError(error.OutOfMemory);
        stream.cancel();
        stream.close();
        return;
    };
    const m = arena_state.allocator().create(Moved) catch {
        logCallError(error.OutOfMemory);
        stream.cancel();
        stream.close();
        self.arenas.release(self.io, self.gpa, arena_state);
        return;
    };
    m.* = .{ .conn = conn, .stream = stream, .arena_state = arena_state, .work = .raw };
    conn.enqueue(m);
}

/// Start a call with a complete request in the read task. The read task reads and checks
/// the request. Then a quick request (`mcp.Server.isQuick`) runs to its end in the read task,
/// as on stdio. Its response goes out with the responses of the other calls of the burst. A
/// quick request of a slow kind goes to the workers (see `CallCosts`). Each other request
/// continues in a task of its own.
///
/// Before, each call started a task, and the wake-up of that task cost more than the call. On
/// Linux under a hypervisor, each wake-up of another thread is a call to the hypervisor.
///
/// The read task does not read while a quick request runs, thus a reset or a `grpc-timeout`
/// does not stop such a request.
fn serveOnReader(conn: *Conn, stream: *Stream) void {
    const self = conn.owner;
    const started = Io.Timestamp.now(self.io, .awake);
    defer conn.reader_spent_ns += nsSince(self.io, started);
    const arena_state = self.arenas.acquire(self.io, self.gpa) catch {
        logCallError(error.OutOfMemory);
        stream.cancel();
        stream.close();
        return;
    };
    const moved = serveCall(conn, stream, arena_state, .reader) catch |e| moved: {
        logCallError(e);
        break :moved false;
    };
    if (moved) return;
    stream.close();
    self.arenas.release(self.io, self.gpa, arena_state);
}

fn logCallError(e: anyerror) void {
    if (e == error.OutOfMemory) log.warn("out of memory on a call", .{});
}

/// Where a call runs.
const Mode = enum {
    /// A task of its own: the call can wait.
    task,
    /// The read task: see `serveOnReader`. The call must not wait.
    reader,
    /// A worker of the connection: see `Conn.enqueue`. The call must not wait.
    worker,
};

/// The part of a call that continues in a task or in a worker after the read task started it.
const Moved = struct {
    conn: *Conn,
    stream: *Stream,
    arena_state: *std.heap.ArenaAllocator,
    work: Work,
    /// The next call in the queue of the workers.
    next: ?*Moved = null,
    /// When the call went into the queue of the workers.
    queued_at: Io.Timestamp = undefined,

    const Work = union(enum) {
        /// A complete request that the read task did not read, for the workers.
        raw,
        /// A request of the tunnel. A quick request (with `cost_slot`) goes to the workers,
        /// another request to a task.
        tunnel: struct {
            env: envelope.Headers,
            deadline: ?Io.Duration,
            req: jsonrpc.Message.Request,
            principal: ?*resource_server.Principal,
            cost_slot: ?usize,
        },
        /// A request of the typed binding, as `tunnel`.
        typed: typed_server.Prepared,
        /// The rest of a response that must wait for flow control credit, for a task.
        sends: Backlog,

        fn forWorkers(w: Work) bool {
            return switch (w) {
                .raw => true,
                .tunnel => |t| t.cost_slot != null,
                .typed => |p| p.cost_slot != null,
                .sends => false,
            };
        }
    };

    /// True when the `grpc-timeout` of the call passed since the call went into the queue.
    fn expired(m: *const Moved, io: Io) bool {
        const t = Connection.findHeader(m.stream.headers.items, "grpc-timeout") orelse return false;
        const d = timeout.parse(t) catch return false;
        return nsSince(io, m.queued_at) >= d.nanoseconds;
    }

    /// Run a call of the queue in a worker.
    fn runQueued(m: *Moved) void {
        // The arena holds `m`.
        const conn = m.conn;
        const stream = m.stream;
        const arena_state = m.arena_state;
        const self = conn.owner;
        const arena = arena_state.allocator();
        const moved = moved: {
            // A call that got a reset or passed its `grpc-timeout` in the queue does not run.
            if (stream.wasReset() != null) break :moved false;
            if (m.expired(self.io)) {
                trailersOnly(stream, arena, .deadline_exceeded, "The deadline passed before the call started", null, null) catch {};
                break :moved false;
            }
            const backlog = switch (m.work) {
                .raw => break :moved serveCall(conn, stream, arena_state, .worker) catch |e| {
                    logCallError(e);
                    break :moved false;
                },
                .tunnel => |t| handleRequest(conn, stream, arena, t.env, t.deadline, t.req, t.principal, true, t.cost_slot),
                .typed => |p| typed_server.execute(self, stream, arena, p, true),
                .sends => unreachable,
            } catch |e| {
                logCallError(e);
                break :moved false;
            } orelse break :moved false;
            break :moved moveToTask(conn, stream, arena_state, .{ .sends = backlog }) catch false;
        };
        if (moved) return;
        stream.close();
        self.arenas.release(self.io, self.gpa, arena_state);
    }

    /// Run a call in a task of its own.
    fn run(m: *Moved) void {
        // The arena holds `m`.
        const conn = m.conn;
        const stream = m.stream;
        const arena_state = m.arena_state;
        const self = conn.owner;
        defer self.arenas.release(self.io, self.gpa, arena_state);
        defer stream.close();
        const arena = arena_state.allocator();
        switch (m.work) {
            .raw => _ = serveCall(conn, stream, arena_state, .task) catch |e| logCallError(e),
            .tunnel => |t| _ = handleRequest(conn, stream, arena, t.env, t.deadline, t.req, t.principal, false, t.cost_slot) catch |e| logCallError(e),
            .typed => |p| _ = typed_server.execute(self, stream, arena, p, false) catch |e| logCallError(e),
            .sends => |b| sendBacklog(self, stream, b),
        }
    }
};

/// Give the call to a task of its own. True when the task took the call, with the stream and
/// the arena. When no task can start, the stream gets a reset and the caller ends the call.
fn moveToTask(conn: *Conn, stream: *Stream, arena_state: *std.heap.ArenaAllocator, work: Moved.Work) !bool {
    const m = try arena_state.allocator().create(Moved);
    m.* = .{ .conn = conn, .stream = stream, .arena_state = arena_state, .work = work };
    conn.group.concurrent(conn.owner.io, Moved.run, .{m}) catch {
        stream.cancel();
        return false;
    };
    return true;
}

/// The messages of a response that must wait for flow control credit. A call in the read task
/// or in a worker cannot wait for it. Only the read task gets the credit, and a worker must
/// not wait. Thus a task sends them.
pub const Backlog = struct {
    /// The response headers went out.
    started: bool,
    /// The encoded messages, in the call arena.
    messages: std.ArrayList([]const u8) = .empty,
    /// The status of the trailers.
    code: status.Code = .cancelled,
};

fn sendBacklog(self: *Server, stream: *Stream, b: Backlog) void {
    if (!b.started) {
        stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = content_type } }, false) catch return;
    }
    for (b.messages.items) |m| lpm.write(stream, self.gpa, m, false) catch return;
    stream.sendHeaders(&.{.{ .name = "grpc-status", .value = b.code.wire() }}, true) catch {};
}

/// Serve one call in `mode`. True when a task or a worker took the rest of the call, with
/// the stream and the arena. Never in `.task` mode.
fn serveCall(conn: *Conn, stream: *Stream, arena_state: *std.heap.ArenaAllocator, mode: Mode) !bool {
    const work = (try startCall(conn, stream, arena_state.allocator(), mode)) orelse return false;
    if (mode == .reader and work.forWorkers()) {
        const m = try arena_state.allocator().create(Moved);
        m.* = .{ .conn = conn, .stream = stream, .arena_state = arena_state, .work = work };
        conn.enqueue(m);
        return true;
    }
    return moveToTask(conn, stream, arena_state, work);
}

/// The result of a function that ends the call: no part of the call moves to a task.
fn ended(result: anyerror!void) !?Moved.Work {
    try result;
    return null;
}

/// Read and check the request, and run it when it can run in `mode`. Else the result is the
/// part of the call that must move. See `runsIn`.
fn startCall(conn: *Conn, stream: *Stream, arena: Allocator, mode: Mode) !?Moved.Work {
    const self = conn.owner;
    const no_wait = mode != .task;
    const headers = try stream.waitHeaders();

    const method = Connection.findHeader(headers, ":method") orelse "";
    const path = Connection.findHeader(headers, ":path") orelse "";
    const ct = Connection.findHeader(headers, "content-type") orelse "";
    if (!std.mem.eql(u8, method, "POST")) return ended(respondHttp(stream, "405"));
    if (!std.ascii.startsWithIgnoreCase(ct, "application/grpc")) return ended(respondHttp(stream, "415"));
    const typed_rpc: ?service.Rpc = if (self.options.bindings.typed) service.Rpc.fromPath(path) else null;
    const tunnel_call = self.options.bindings.tunnel and std.mem.eql(u8, path, call_path);
    if (!tunnel_call and typed_rpc == null) return ended(trailersOnly(stream, arena, .unimplemented, "Unknown service or method", null, null));
    if (Connection.findHeader(headers, "grpc-encoding")) |encoding| {
        if (!std.mem.eql(u8, encoding, "identity")) return ended(trailersOnly(stream, arena, .unimplemented, "Compression is not supported", null, null));
    }

    // Authorization comes before any look at the message.
    var principal: ?*resource_server.Principal = null;
    if (self.options.auth) |auth| {
        switch (try auth.authorize(arena, Connection.findHeader(headers, "authorization"))) {
            .ok => |p| {
                const owned = try arena.create(resource_server.Principal);
                owned.* = p;
                principal = owned;
            },
            .challenge => |c| return ended(challenge(stream, arena, c)),
        }
    }
    if (typed_rpc) |rpc| {
        var prepared = try typed_server.prepare(self, stream, arena, headers, rpc, principal) orelse return null;
        if (typed_server.isQuick(self, prepared)) prepared.cost_slot = CallCosts.slot(rpc.method(), prepared.params);
        if (!runsIn(self, mode, prepared.cost_slot)) return .{ .typed = prepared };
        const backlog = try typed_server.execute(self, stream, arena, prepared, no_wait) orelse return null;
        return .{ .sends = backlog };
    }

    // The mirrored request metadata.
    var env: envelope.Headers = .{};
    var params: std.ArrayList(envelope.Headers.Param) = .empty;
    for (headers) |h| {
        if (std.mem.eql(u8, h.name, envelope.header_protocol_version)) env.protocol_version = h.value;
        if (std.mem.eql(u8, h.name, envelope.header_method)) env.method = h.value;
        if (std.mem.eql(u8, h.name, envelope.header_name)) env.name = h.value;
        if (std.mem.startsWith(u8, h.name, envelope.header_param_prefix)) {
            try params.append(arena, .{ .name = h.name[envelope.header_param_prefix.len..], .value = h.value });
        }
    }
    env.params = params.items;
    var deadline: ?Io.Duration = null;
    if (Connection.findHeader(headers, "grpc-timeout")) |t| {
        deadline = timeout.parse(t) catch return ended(trailersOnly(stream, arena, .invalid_argument, "Invalid grpc-timeout", null, null));
    }

    // The one request message. It is in the call arena, because the message can point into it.
    const payload = lpm.read(stream, arena, self.options.max_message_bytes) catch |e| switch (e) {
        error.MessageTooLarge => return ended(trailersOnly(stream, arena, .resource_exhausted, "Message too large", null, null)),
        error.Compressed => return ended(trailersOnly(stream, arena, .unimplemented, "Compression is not supported", null, null)),
        error.Truncated => return ended(trailersOnly(stream, arena, .invalid_argument, "Truncated message", null, null)),
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    } orelse return ended(trailersOnly(stream, arena, .invalid_argument, "The call carried no message", null, null));
    const text = messages.decodeJsonRpcMessage(payload) catch return ended(trailersOnly(stream, arena, .invalid_argument, "The message is not a JsonRpcMessage", null, null));
    const msg = jsonrpc.Message.parseMaxDepth(arena, text, self.server.options.limits.json_max_depth) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Syntax => return ended(rpcErrorOnly(stream, arena, errors.parseError("Parse error"), null)),
        error.Invalid, error.InvalidId => return ended(rpcErrorOnly(stream, arena, errors.invalidRequest("Invalid Request"), null)),
    };
    switch (msg) {
        // A notification is accepted and dropped, as on Streamable HTTP.
        .notification => return ended(trailersOnly(stream, arena, .ok, null, null, null)),
        .response, .error_response => return ended(rpcErrorOnly(stream, arena, errors.invalidRequest("Clients must not send responses"), null)),
        .request => |req| {
            const cost_slot: ?usize = if (self.server.isQuick(msg)) CallCosts.slot(req.method, req.params) else null;
            if (!runsIn(self, mode, cost_slot)) {
                return .{ .tunnel = .{ .env = env, .deadline = deadline, .req = req, .principal = principal, .cost_slot = cost_slot } };
            }
            const backlog = try handleRequest(conn, stream, arena, env, deadline, req, principal, no_wait, cost_slot) orelse return null;
            return .{ .sends = backlog };
        },
    }
}

/// True when a request can run in `mode`. A quick request has a `cost_slot`. The read task
/// runs only the quick requests whose kind does not take long. A worker runs each quick
/// request. A task runs each request.
fn runsIn(self: *Server, mode: Mode, cost_slot: ?usize) bool {
    return switch (mode) {
        .task => true,
        .reader => if (cost_slot) |i| !self.costs.isSlow(i) else false,
        .worker => cost_slot != null,
    };
}

/// Run a request of the tunnel. With `no_wait` the read task or a worker runs it: the request
/// is quick and has no reset hook and no deadline. The result is then the rest of the response
/// that must wait for flow control credit, if any. A quick request has a `cost_slot` and adds
/// its run time there.
fn handleRequest(conn: *Conn, stream: *Stream, arena: Allocator, env: envelope.Headers, deadline: ?Io.Duration, req: jsonrpc.Message.Request, principal: ?*resource_server.Principal, no_wait: bool, cost_slot: ?usize) !?Backlog {
    const self = conn.owner;
    const io = self.io;
    const schema = toolSchema(self, req.params);
    if (try envelope.verify(arena, env, req.method, req.params, schema)) |rejection| {
        if (env.protocol_version == null and std.mem.eql(u8, req.method, "initialize")) {
            const err = try errors.unsupportedProtocolVersion(arena, &version.supported_versions, "unknown");
            try rpcErrorOnly(stream, arena, err, req.id);
            return null;
        }
        try rpcErrorOnly(stream, arena, try rejection.rpcError(arena), req.id);
        return null;
    }

    var token: Transport.CancelToken = .{};
    // The connection cancels the request when the client resets the stream or the connection
    // ends. The hook goes before the token does. Before, a second task waited on the stream.
    if (!no_wait) stream.setOnReset(onReset, &token);
    defer if (!no_wait) stream.setOnReset(null, null);

    var exchange: Exchange = .{ .stream = stream, .gpa = self.gpa, .arena = arena, .no_wait = no_wait };
    var outbox: Outbox = .{};
    if (std.mem.eql(u8, req.method, "subscriptions/listen")) exchange.outbox = &outbox;
    // Before the return: the drain task uses `exchange`.
    defer if (exchange.outbox) |out| out.close(io, &exchange);
    var watch: Deadlines.Watch = .{};
    if (deadline) |d| if (!no_wait) watch.start(&self.deadlines, io, d, &token, &exchange.deadline_hit);
    defer watch.finish(&self.deadlines, io);
    const started = Io.Timestamp.now(io, .awake);
    self.server.handle(io, .{
        .kind = .grpc,
        .arena = arena,
        .message = .{ .request = req },
        .responder = .{ .ptr = &exchange, .vtable = &exchange_vtable },
        .cancel = &token,
        .context = principal,
        .peer = .{ .address = conn.stream.socket.address },
    });
    if (cost_slot) |i| self.costs.record(i, nsSince(io, started));
    if (exchange.backlog) |b| return b;
    if (exchange.outbox) |out| out.close(io, &exchange);
    if (!exchange.done) {
        // The handler ended without a response: the request was cancelled.
        const code: status.Code = if (exchange.deadline_hit.load(.acquire)) .deadline_exceeded else .cancelled;
        if (exchange.started) {
            stream.sendHeaders(&.{.{ .name = "grpc-status", .value = code.wire() }}, true) catch {};
        } else {
            trailersOnly(stream, arena, code, "The request was cancelled", null, req.id) catch {};
        }
    }
    return null;
}

/// Cancel the request. The connection calls this hook under its lock when the client resets
/// the stream or when the connection ends. The cancel of the token takes no lock.
fn onReset(userdata: ?*anyopaque, stream: *Stream) void {
    const token: *Transport.CancelToken = @ptrCast(@alignCast(userdata.?));
    token.cancel(stream.conn.io, "stream reset");
}

fn toolSchema(self: *Server, params: ?Value) ?Value {
    const p = params orelse return null;
    const name = json.getString(p, "name") orelse return null;
    for (self.server.tools.items) |t| if (std.mem.eql(u8, t.def.name, name)) return t.def.inputSchema;
    return null;
}

// -- Responses -------------------------------------------------------------------------------

fn respondHttp(stream: *Stream, status_text: []const u8) !void {
    try stream.sendHeaders(&.{ .{ .name = ":status", .value = status_text }, .{ .name = "content-length", .value = "0" } }, true);
}

/// End the call with headers only: a status, and with `err` the JSON-RPC error as well.
pub fn trailersOnly(stream: *Stream, arena: Allocator, code: status.Code, message_text: ?[]const u8, err: ?errors.RpcError, id: ?RequestId) !void {
    var list: std.ArrayList(Header) = .empty;
    try list.append(arena, .{ .name = ":status", .value = "200" });
    try list.append(arena, .{ .name = "content-type", .value = content_type });
    try list.append(arena, .{ .name = "grpc-status", .value = code.wire() });
    if (message_text) |m| try list.append(arena, .{ .name = "grpc-message", .value = try status.encodeMessage(arena, m) });
    if (err) |e| {
        try list.append(arena, .{ .name = header_error_code, .value = try std.fmt.allocPrint(arena, "{d}", .{e.code}) });
        var aw: Io.Writer.Allocating = .init(arena);
        jsonrpc.message.writeErrorResponse(&aw.writer, id, e.toWire()) catch return error.OutOfMemory;
        const encoder = std.base64.standard.Encoder;
        const out = try arena.alloc(u8, encoder.calcSize(aw.written().len));
        try list.append(arena, .{ .name = header_error_bin, .value = encoder.encode(out, aw.written()) });
    }
    try stream.sendHeaders(list.items, true);
}

/// End the call with headers only for a JSON-RPC error that the server finds before the
/// handler runs. The status comes from the error code.
fn rpcErrorOnly(stream: *Stream, arena: Allocator, err: errors.RpcError, id: ?RequestId) !void {
    return trailersOnly(stream, arena, status.forJsonRpcCode(err.code), err.message, err, id);
}

fn challenge(stream: *Stream, arena: Allocator, c: resource_server.Challenge) !void {
    const code: status.Code = switch (c.status) {
        401 => .unauthenticated,
        403 => .permission_denied,
        else => .invalid_argument,
    };
    var buf: [3]std.http.Header = undefined;
    var headers: std.ArrayList(Header) = .empty;
    try headers.appendSlice(arena, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = content_type },
        .{ .name = "grpc-status", .value = code.wire() },
        .{ .name = "grpc-message", .value = try status.encodeMessage(arena, "Authorization required") },
    });
    for (c.headers(&buf)) |h| try headers.append(arena, .{ .name = h.name, .value = h.value });
    try stream.sendHeaders(headers.items, true);
}

/// The responder of one call.
const Exchange = struct {
    stream: *Stream,
    gpa: Allocator,
    arena: Allocator,
    started: bool = false,
    done: bool = false,
    /// Set by the deadline task before it cancels the request.
    deadline_hit: std.atomic.Value(bool) = .init(false),
    /// The read task or a worker runs the request. A send then does not wait for flow control
    /// credit.
    no_wait: bool = false,
    /// With `no_wait`: the messages from the first send that did not have the credit. A
    /// task sends them after the handler. See `Backlog`.
    backlog: ?Backlog = null,
    /// The events of a `subscriptions/listen` call. See `Outbox`.
    outbox: ?*Outbox = null,

    fn ensureHeaders(self: *Exchange) Transport.SendError!void {
        if (self.started) return;
        self.stream.sendHeaders(&.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = content_type } }, false) catch |e| return mapSend(e);
        self.started = true;
    }

    fn sendMessage(self: *Exchange, frame: []const u8) Transport.SendError!void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        try messages.encodeJsonRpcMessage(self.gpa, &out, frame);
        if (!self.no_wait) return lpm.write(self.stream, self.gpa, out.items, false) catch |e| mapSend(e);
        if (self.backlog == null) {
            lpm.writeNoWait(self.stream, self.gpa, out.items, false) catch |e| switch (e) {
                error.WouldBlock => self.backlog = .{ .started = self.started },
                else => return mapSend(e),
            };
            if (self.backlog == null) return;
        }
        try self.backlog.?.messages.append(self.arena, try self.arena.dupe(u8, out.items));
    }
};

/// The events of a `subscriptions/listen` call. Other tasks send them, for example the read
/// task of a connection in a quick call that changes the tools. Such a send must not wait for
/// flow control credit. The read task could wait for credit that only it reads, and a slow
/// subscriber could hold the task that sends. Thus an event without the credit waits in the
/// outbox, and a drain task of the outbox sends it.
const Outbox = struct {
    lock: Io.Mutex = .init,
    /// The encoded messages that wait, in order. They are from `Exchange.gpa`.
    queue: std.ArrayList([]u8) = .empty,
    bytes: usize = 0,
    /// A drain task runs.
    draining: bool = false,
    drain: ?Io.Future(void) = null,
    closed: bool = false,

    /// The most bytes that wait in the outbox. When a subscriber reads slower, its listen
    /// stream ends.
    const max_bytes = 1 << 20;

    fn notify(out: *Outbox, io: Io, ex: *Exchange, frame: []const u8) Transport.SendError!void {
        const gpa = ex.gpa;
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        try messages.encodeJsonRpcMessage(gpa, &msg, frame);
        out.lock.lockUncancelable(io);
        defer out.lock.unlock(io);
        if (out.closed or ex.done) return error.Closed;
        // A header block does not wait for credit.
        try ex.ensureHeaders();
        if (!out.draining) {
            if (lpm.writeNoWait(ex.stream, gpa, msg.items, false)) |_| {
                return;
            } else |e| switch (e) {
                error.WouldBlock => {},
                else => return mapSend(e),
            }
        }
        if (out.bytes + msg.items.len > max_bytes) return error.Closed;
        const copy = try msg.toOwnedSlice(gpa);
        out.queue.append(gpa, copy) catch {
            gpa.free(copy);
            return error.OutOfMemory;
        };
        out.bytes += copy.len;
        if (out.draining) return;
        // The last drain task ended. It holds no lock at its end, thus the wait is short.
        if (out.drain) |*f| f.await(io);
        out.drain = io.concurrent(drainRun, .{ out, io, ex }) catch {
            out.drain = null;
            _ = out.queue.pop();
            out.bytes -= copy.len;
            gpa.free(copy);
            return error.Closed;
        };
        out.draining = true;
    }

    /// Send the messages of the queue. A send of this task can wait for credit.
    fn drainRun(out: *Outbox, io: Io, ex: *Exchange) void {
        while (true) {
            const m = m: {
                out.lock.lockUncancelable(io);
                defer out.lock.unlock(io);
                if (out.queue.items.len == 0) {
                    out.draining = false;
                    return;
                }
                const m = out.queue.orderedRemove(0);
                out.bytes -= m.len;
                break :m m;
            };
            defer ex.gpa.free(m);
            lpm.write(ex.stream, ex.gpa, m, false) catch {
                out.lock.lockUncancelable(io);
                defer out.lock.unlock(io);
                out.closed = true;
                out.draining = false;
                return;
            };
        }
    }

    /// Accept no more events and stop the drain task. The outbox drops the events that still
    /// wait for credit. The listen call ends, thus the stream ends too. Call this function from the task
    /// of the call, before the last frames of the call.
    fn close(out: *Outbox, io: Io, ex: *Exchange) void {
        var drain: ?Io.Future(void) = null;
        var running = false;
        {
            out.lock.lockUncancelable(io);
            defer out.lock.unlock(io);
            out.closed = true;
            running = out.draining;
            drain = out.drain;
            out.drain = null;
        }
        if (drain) |*f| {
            // A drain task that waits for credit stops with `error.Canceled`.
            if (running) ex.stream.stopWaits();
            f.await(io);
        }
        for (out.queue.items) |m| ex.gpa.free(m);
        out.queue.clearAndFree(ex.gpa);
        out.bytes = 0;
    }
};

fn mapSend(e: anyerror) Transport.SendError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.Closed, error.StreamReset => error.Closed,
        else => error.WriteFailed,
    };
}

const exchange_vtable: Transport.Responder.VTable = .{
    .notify = exchangeNotify,
    .finish = exchangeFinish,
    .abort = exchangeAbort,
};

fn exchangeNotify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const ex: *Exchange = @ptrCast(@alignCast(ptr));
    if (ex.outbox) |out| return out.notify(io, ex, frame);
    if (ex.done) return error.Closed;
    try ex.ensureHeaders();
    try ex.sendMessage(frame);
}

fn exchangeFinish(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
    const ex: *Exchange = @ptrCast(@alignCast(ptr));
    if (ex.outbox) |out| out.close(io, ex);
    if (ex.done) return error.Closed;
    // The headers, the message and the trailers go out together. See `Stream.cork`.
    ex.stream.cork();
    errdefer ex.stream.uncork() catch {};
    try ex.ensureHeaders();
    try ex.sendMessage(frame);
    if (ex.backlog) |*b| {
        // A task sends the trailers after the messages.
        b.code = .ok;
    } else {
        ex.stream.sendHeaders(&.{.{ .name = "grpc-status", .value = status.Code.ok.wire() }}, true) catch |e| return mapSend(e);
    }
    ex.stream.uncork() catch |e| return mapSend(e);
    ex.done = true;
}

fn exchangeAbort(ptr: *anyopaque, io: Io) void {
    const ex: *Exchange = @ptrCast(@alignCast(ptr));
    if (ex.outbox) |out| out.close(io, ex);
    if (ex.done) return;
    ex.done = true;
    const code: status.Code = if (ex.deadline_hit.load(.acquire)) .deadline_exceeded else .cancelled;
    if (ex.backlog) |*b| {
        b.code = code;
    } else if (ex.started) {
        ex.stream.sendHeaders(&.{.{ .name = "grpc-status", .value = code.wire() }}, true) catch {};
    } else {
        trailersOnly(ex.stream, ex.arena, code, "The request was cancelled", null, null) catch {};
    }
}

test "a kind of request becomes slow after some long runs and fast after short runs" {
    var costs: CallCosts = .{};
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const params = try json.parseTree(arena_state.allocator(), "{\"name\":\"t\"}");
    const i = CallCosts.slot("tools/call", params);
    // One late call does not make the kind slow.
    costs.record(i, std.time.ns_per_s);
    try std.testing.expect(!costs.isSlow(i));
    for (0..9) |_| costs.record(i, std.time.ns_per_ms);
    try std.testing.expect(costs.isSlow(i));
    for (0..20) |_| costs.record(i, std.time.ns_per_us);
    try std.testing.expect(!costs.isSlow(i));
}
