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
const park = mcp.transport.park;
const Deadlines = @import("deadlines.zig");
const lockfree = mcp.util.lockfree;

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
    permits: lockfree.Permits,
    closing: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    /// The open connections, one in each used place. A place changes with one atomic
    /// operation. `serve` makes the places: one for each of `max_connections`.
    connections: []std.atomic.Value(?*Conn) = &.{},
    /// The count of the open connections.
    connection_count: std.atomic.Value(u32) = .init(0),
    /// The place where the next search for a free place starts.
    next_place: std.atomic.Value(usize) = .init(0),
    /// The connections that ended. A task that reads `connections` can still use one of them,
    /// thus the server frees them when no task reads.
    retired_conns: lockfree.Retired(Conn, "next_retired") = .{},
    /// The `grpc-timeout` of the calls of every connection.
    deadlines: Deadlines = .{},
    /// The arenas of the calls that ended, for the next calls.
    arenas: ArenaPool = .{},
    /// The recent run times of the quick requests.
    costs: CallCosts = .{},
    /// The most workers of one connection. See `Conn.enqueue`.
    max_workers: u32,
    /// The idle plaintext connections. See `Parker`.
    parker: Parker = .{},
    /// The encoded responses of recent list results of the typed binding.
    typed_cache: typed_server.ResultCache = .{},

    pub fn init(io: Io, gpa: Allocator, server: *mcp.Server, options: Options) Server {
        const cpus = std.Thread.getCpuCount() catch 4;
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .permits = .init(options.max_connections),
            .max_workers = @intCast(std.math.clamp(cpus, 1, max_workers_per_connection)),
        };
    }

    /// The most workers of one connection on a computer with many processors.
    pub const max_workers_per_connection = 8;

    pub fn deinit(self: *Server) void {
        if (self.listener) |*l| l.deinit(self.io);
        // Normally `serve` stopped the task already.
        self.deadlines.stop(self.io);
        self.arenas.deinit(self.gpa);
        self.parker.deinit(self.gpa);
        self.typed_cache.deinit(self.gpa);
        self.retired_conns.deinit(self.gpa, freeConn);
        self.gpa.free(self.connections);
        self.* = undefined;
    }

    fn freeConn(gpa: Allocator, conn: *Conn) void {
        gpa.destroy(conn);
    }

    /// Put `conn` in a free place of `connections`. The permits of the accept loop bound the
    /// connections, thus a place is free.
    fn track(self: *Server, conn: *Conn) void {
        const len = self.connections.len;
        const first = self.next_place.fetchAdd(1, .monotonic);
        for (0..len) |i| {
            const at = (first + i) % len;
            if (self.connections[at].load(.monotonic) != null) continue;
            if (self.connections[at].cmpxchgStrong(null, conn, .seq_cst, .monotonic) == null) {
                conn.place = at;
                _ = self.connection_count.fetchAdd(1, .seq_cst);
                return;
            }
        }
    }

    fn untrack(self: *Server, conn: *Conn) void {
        const at = conn.place orelse return;
        conn.place = null;
        self.connections[at].store(null, .seq_cst);
        _ = self.connection_count.fetchSub(1, .seq_cst);
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
        if (self.connections.len == 0) {
            self.connections = try self.gpa.alloc(std.atomic.Value(?*Conn), self.options.max_connections);
            @memset(self.connections, .init(null));
        }
        self.parker.start(self);
        var accept_future = self.io.concurrent(acceptLoop, .{self}) catch |e| {
            self.parker.stop(self);
            self.group.await(self.io) catch {};
            return e;
        };
        self.stop_event.wait(self.io) catch {};
        // The parker ends after the last parked connection.
        self.parker.stop(self);
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
            self.permits.take(self.io);
            const conn = self.gpa.create(Conn) catch {
                stream.close(self.io);
                self.permits.give(self.io);
                continue;
            };
            conn.* = .{ .owner = self, .stream = stream };
            self.track(conn);
            // A new plaintext connection waits in the parker for its first bytes. When many
            // clients connect at the same time, a task per connection that waits for the
            // preface made the thread pool grow to one thread per client.
            if (self.parker.admit(self, conn)) continue;
            self.group.concurrent(self.io, Conn.run, .{conn}) catch conn.end();
        }
    }

    /// Accept no more connections and end the open connections. Safe to call from another task.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .release);
        self.stop_event.set(self.io);
        self.server.shutdownSubscriptions(self.io);
        self.retired_conns.enter();
        defer self.retired_conns.leave(self.gpa, freeConn);
        var batch: GoawayBatch = .{};
        for (self.connections) |*place| {
            const c = place.load(.seq_cst) orelse continue;
            if (batch.len == batch.conns.len) batch.finish(self);
            batch.add(self, c);
        }
        batch.finish(self);
    }

    /// The `GOAWAY` frames of `shutdown`, in tasks of their own. A `GOAWAY` can wait for a
    /// peer that does not read. On Windows, only a cancel of the task ends such a write. A
    /// shutdown of the socket does not end it. A close of the socket ends it, but then std stops
    /// the process. Thus `finish` waits a short time for the frames, then cancels the tasks
    /// that still wait.
    const GoawayBatch = struct {
        conns: [64]*Conn = undefined,
        tasks: [64]?Io.Future(void) = undefined,
        done: [64]std.atomic.Value(bool) = undefined,
        len: usize = 0,

        /// How long `finish` waits for the frames.
        const grace_ms = 200;

        fn add(b: *GoawayBatch, self: *Server, c: *Conn) void {
            b.conns[b.len] = c;
            b.done[b.len] = .init(true);
            b.tasks[b.len] = null;
            // The batch holds the socket and the HTTP/2 state until `finish`. Thus the parker
            // does not close the socket while the frame waits: a close then ends the write, and
            // on Windows std stops the process at that end.
            _ = c.socket_users.fetchAdd(1, .seq_cst);
            if (c.socket_open.load(.seq_cst) and c.useH2()) {
                b.done[b.len] = .init(false);
                b.tasks[b.len] = self.io.concurrent(sendGoaway, .{ c, &b.done[b.len] }) catch null;
                if (b.tasks[b.len] == null) {
                    // Without a task, the frame does not go out. The close of the socket
                    // still ends the connection.
                    b.done[b.len] = .init(true);
                    c.releaseH2();
                }
            }
            b.len += 1;
        }

        fn sendGoaway(c: *Conn, done: *std.atomic.Value(bool)) void {
            defer done.store(true, .release);
            c.h2.shutdown();
        }

        fn finish(b: *GoawayBatch, self: *Server) void {
            var waited: u32 = 0;
            while (waited < grace_ms) : (waited += 1) {
                const all = for (b.done[0..b.len]) |*d| {
                    if (!d.load(.acquire)) break false;
                } else true;
                if (all) break;
                self.io.sleep(.fromMilliseconds(1), .awake) catch break;
            }
            for (b.conns[0..b.len], b.tasks[0..b.len]) |c, *task| {
                if (task.*) |*f| {
                    // A task that ended: the cancel only collects it.
                    f.cancel(self.io);
                    c.releaseH2();
                }
                // A closed socket: the handle can belong to a new socket now. See
                // `Conn.closeSocket`.
                if (c.socket_open.load(.seq_cst)) c.stream.shutdown(self.io, .both) catch {};
                _ = c.socket_users.fetchSub(1, .seq_cst);
            }
            b.len = 0;
        }
    };
};

/// A call that comes sooner than this after the last call or after a park makes the connection
/// busy. See `Conn.onIdle`.
const busy_gap_ms = 2;
/// The length of the HTTP/2 connection preface.
const frame_preface_len = 24;
/// The quick calls in a row (see `busy_gap_ms`) that make a connection busy. One quick call
/// does not. Many clients can make one call each at the same time, and each busy connection
/// holds a thread until the `PING` of the parker.
const busy_after_calls = 3;
/// The parker sends a `PING` to a connection whose read without a park (see `Conn.onIdle`)
/// waits longer than this.
const nudge_after_ms = 50;

/// The awake clock in nanoseconds.
fn nowNs(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
}

/// The idle plaintext connections, without a task. One task of the server, `runParker`, waits
/// for bytes on their sockets with `park.Poller`, as the parker of the Streamable HTTP server
/// does. A ready connection gets a new task. Before, each idle connection held a task and its
/// thread. On Linux, 200 idle clients of VS Code held 206 threads and 70 MiB. A TLS connection
/// keeps its task.
///
/// The parker has no lock. Only its task uses the list of parked connections. A connection
/// that parks goes into the lock-free queue `admissions`, and the task takes it from there. A
/// ready connection goes into the lock-free queue `ready`, and a runner or the task takes it.
const Parker = struct {
    poller: ?park.Poller = null,
    /// The task runs and accepts parks.
    running: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),
    /// The connections that parked since the last look of the task, the newest first.
    admissions: lockfree.Stack(Conn, "next_admitted") = .{},
    /// The calls of `admit` that run now. The task ends only when no call runs.
    admitting: std.atomic.Value(u32) = .init(0),
    /// The parked connections. Only the task uses the field.
    parked: std.ArrayList(*Conn) = .empty,
    /// The count of `parked`, for the tests.
    parked_count: std.atomic.Value(usize) = .init(0),
    /// Ready connections that did not get a task yet. The runners and the task take them.
    ready: lockfree.Ring(Conn, ready_capacity) = .{},
    /// Ready connections that did not fit into `ready`. Only the task uses the field.
    overflow: std.ArrayList(*Conn) = .empty,
    /// The connections in `ready` and in `overflow`.
    ready_count: std.atomic.Value(u32) = .init(0),
    /// The slots of the parked connections for the `poll` of POSIX systems. Only the task uses
    /// the field.
    snapshot: std.ArrayList(*park.Slot) = .empty,
    /// On Windows, the parked connections that the parker closed at the stop. The parker frees
    /// each one at the completion of its poll. Only the task uses the field.
    closing: usize = 0,
    /// The runners (see `runner`) that do not wait for a socket now. The parker starts a new
    /// runner only while this count is below `max_runs`. A ready connection waits in `ready`
    /// until a runner takes it.
    runs: std.atomic.Value(u32) = .init(0),
    /// The count of processors.
    max_runs: u32 = 1,
    /// The `PING` tasks of `nudgeIdleReads`. Only the task of the parker uses the field. See
    /// `reapNudges`.
    nudges: std.ArrayList(*Nudge) = .empty,

    const ready_capacity = 1024;

    /// One `PING` task. It holds the HTTP/2 state of its connection until the parker collects
    /// it, thus the connection exists while the entry exists.
    const Nudge = struct {
        conn: *Conn,
        future: Io.Future(void) = undefined,
        done: std.atomic.Value(bool) = .init(false),
    };

    /// Collect the `PING` tasks that ended. Cancel a task whose connection ends, or each task
    /// with `all`. On Windows, only a cancel ends a write that waits for a peer that does not
    /// read. Only the task of the parker calls this function.
    fn reapNudges(p: *Parker, self: *Server, all: bool) void {
        var i: usize = 0;
        while (i < p.nudges.items.len) {
            const n = p.nudges.items[i];
            if (!n.done.load(.acquire)) {
                if (!all and n.conn.h2_ready.load(.seq_cst)) {
                    i += 1;
                    continue;
                }
            }
            // A task that ended: the cancel only collects it.
            n.future.cancel(self.io);
            n.conn.releaseH2();
            _ = p.nudges.swapRemove(i);
            self.gpa.destroy(n);
        }
    }

    fn isRunning(p: *const Parker) bool {
        return p.running.load(.acquire);
    }

    /// Start the task. Without it, the connections do not park.
    fn start(p: *Parker, self: *Server) void {
        if (self.options.tls != null) return;
        p.max_runs = @intCast(std.math.clamp(std.Thread.getCpuCount() catch 4, 1, 64));
        p.poller = park.Poller.init(self.gpa) catch return;
        p.running.store(true, .release);
        self.group.concurrent(self.io, runParker, .{self}) catch {
            p.running.store(false, .release);
            p.poller.?.deinit();
            p.poller = null;
        };
    }

    /// Accept no more parks, and close the parked connections. The task ends after them.
    fn stop(p: *Parker, self: *Server) void {
        _ = self;
        const poller = if (p.poller) |*q| q else return;
        p.stopping.store(true, .seq_cst);
        poller.wake();
    }

    fn deinit(p: *Parker, gpa: Allocator) void {
        if (p.poller) |*q| q.deinit();
        p.nudges.deinit(gpa);
        p.parked.deinit(gpa);
        p.overflow.deinit(gpa);
        p.snapshot.deinit(gpa);
    }

    /// Watch the socket of `conn`, which has no task now. False when the parker does not take
    /// the connection: the task of the connection then continues.
    fn admit(p: *Parker, self: *Server, conn: *Conn) bool {
        const poller = if (p.poller) |*q| q else return false;
        _ = p.admitting.fetchAdd(1, .seq_cst);
        defer if (p.admitting.fetchSub(1, .seq_cst) == 1 and p.stopping.load(.seq_cst)) poller.wake();
        if (p.stopping.load(.seq_cst) or !p.isRunning()) return false;
        conn.parked_at = nowNs(self.io);
        conn.arm_state.store(.pending, .release);
        // On Windows an event of the socket can come at once after the arm. The task takes the
        // admissions before it handles the events, thus the admission comes first.
        p.admissions.push(conn);
        poller.arm(&conn.slot, conn.stream.socket.handle) catch {
            // The connection belongs to the parker now. The task gives it a runner again.
            conn.arm_state.store(.failed, .release);
            poller.wake();
            return true;
        };
        conn.arm_state.store(.armed, .release);
        // On POSIX systems the parker polls a copy of the parked set: it takes a new copy.
        if (!park.is_windows) poller.wake();
        return true;
    }

    /// Take the connections that parked since the last call. Only the task calls this function.
    fn takeAdmissions(p: *Parker, self: *Server) void {
        var list = p.admissions.takeAll() orelse return;
        // An armed connection has a poll that runs, thus it must go into `parked`. Without the
        // space, the admissions wait for the next pass.
        var count: usize = 0;
        var it: ?*Conn = list;
        while (it) |c| : (it = c.next_admitted) count += 1;
        p.parked.ensureUnusedCapacity(self.gpa, count) catch {
            while (true) {
                const after = list.next_admitted;
                p.admissions.push(list);
                list = after orelse return;
            }
        };
        var pending: ?*Conn = list;
        while (pending) |conn| {
            pending = conn.next_admitted;
            // The task can see an admission before the arm of its poll ends. The arm is one
            // call to the system, thus the wait is short.
            while (conn.arm_state.load(.acquire) == .pending) std.Thread.yield() catch {};
            if (conn.arm_state.load(.acquire) == .failed) {
                // The connection does not park again. Its next read waits without a run.
                conn.park_off = true;
                p.makeReady(self, conn, true);
                continue;
            }
            p.parked.appendAssumeCapacity(conn);
            conn.park_index = p.parked.items.len - 1;
        }
        p.parked_count.store(p.parked.items.len, .release);
    }

    fn removeParked(p: *Parker, conn: *Conn) void {
        const i = conn.park_index;
        _ = p.parked.swapRemove(i);
        if (i < p.parked.items.len) p.parked.items[i].park_index = i;
        p.parked_count.store(p.parked.items.len, .release);
    }

    /// Give a ready connection to the runners. With `unready`, no bytes wait: the first read
    /// of the runner waits without a run. Only the task calls this function. A runner can take
    /// the connection at once, thus the task does not touch it after the push.
    fn makeReady(p: *Parker, self: *Server, conn: *Conn, unready: bool) void {
        conn.wake_unready = unready;
        conn.first_read = true;
        conn.quick_wake = nowNs(self.io) - conn.parked_at < busy_gap_ms * std.time.ns_per_ms;
        p.pushReady(self, conn);
    }

    fn pushReady(p: *Parker, self: *Server, conn: *Conn) void {
        _ = p.ready_count.fetchAdd(1, .seq_cst);
        // The order stays: a connection goes to `ready` only after the older ones of
        // `overflow`.
        if (p.overflow.items.len == 0 and p.ready.push(conn)) return;
        p.overflow.append(self.gpa, conn) catch {
            // Without memory and without a task, the connection ends. Its end must not wait
            // for a `PING` task of the parker.
            _ = p.ready_count.fetchSub(1, .seq_cst);
            p.reapNudges(self, true);
            conn.endParked();
        };
    }

    /// Move the connections of `overflow` to `ready` while it has space.
    fn moveOverflow(p: *Parker) void {
        var n: usize = 0;
        while (n < p.overflow.items.len and p.ready.push(p.overflow.items[n])) n += 1;
        if (n == 0) return;
        const rest = p.overflow.items.len - n;
        std.mem.copyForwards(*Conn, p.overflow.items[0..rest], p.overflow.items[n..]);
        p.overflow.shrinkRetainingCapacity(rest);
    }

    /// Take a ready connection, or null.
    fn popReady(p: *Parker) ?*Conn {
        const conn = p.ready.pop() orelse return null;
        _ = p.ready_count.fetchSub(1, .seq_cst);
        return conn;
    }

    /// Take the ready connections, in their order, that get a run now. The caller starts
    /// their tasks.
    fn takeStarts(p: *Parker, out: []*Conn) usize {
        var n: usize = 0;
        while (n < out.len) : (n += 1) {
            var runs = p.runs.load(.seq_cst);
            while (true) {
                if (runs >= p.max_runs) return n;
                runs = p.runs.cmpxchgWeak(runs, runs + 1, .seq_cst, .seq_cst) orelse break;
            }
            const conn = p.popReady() orelse {
                _ = p.runs.fetchSub(1, .seq_cst);
                return n;
            };
            conn.holds_run = true;
            out[n] = conn;
        }
        return n;
    }

    /// Start a runner for each connection of `starts`. A connection without a runner goes back
    /// to `ready`. Only the task calls this function.
    fn startTasks(p: *Parker, self: *Server, starts: []*Conn) void {
        for (starts) |conn| {
            self.group.concurrent(self.io, runner, .{ self, conn }) catch {
                conn.holds_run = false;
                _ = p.runs.fetchSub(1, .seq_cst);
                p.pushReady(self, conn);
            };
        }
    }

    /// A runner waits for the socket of its connection: its run is free until the read ends.
    fn releaseRun(p: *Parker) void {
        _ = p.runs.fetchSub(1, .seq_cst);
        if (p.ready_count.load(.seq_cst) > 0) p.poller.?.wake();
    }

    /// The next ready connection for a runner that holds a run, or null. With null, the
    /// runner ends, and its run is free.
    fn next(p: *Parker) ?*Conn {
        // A runner took its run again after a read, thus there can be one run too many.
        if (p.runs.load(.seq_cst) <= p.max_runs) if (p.popReady()) |conn| {
            conn.holds_run = true;
            return conn;
        };
        p.releaseRun();
        return null;
    }

    /// Only the task calls this function.
    fn handleEvent(p: *Parker, self: *Server, ev: park.Event) void {
        const conn: *Conn = @alignCast(@fieldParentPtr("slot", ev.slot));
        if (conn.socket_closed) {
            // Windows: the poll of a socket that the stop closed ended.
            p.closing -= 1;
            conn.endParked();
            return;
        }
        if (park.is_windows and !ev.readable and !ev.hangup) {
            // The wait ended for another reason. Watch the socket again.
            p.poller.?.arm(&conn.slot, conn.stream.socket.handle) catch {
                p.removeParked(conn);
                // No bytes wait: the first read of the task waits without a run.
                p.makeReady(self, conn, true);
            };
            return;
        }
        // Bytes or a close of the peer: the new task reads them, or reads the end.
        p.removeParked(conn);
        p.makeReady(self, conn, false);
    }

    /// At the stop: end the parked connections. On Windows the poll of a socket is pending:
    /// close the socket, and end the connection at the completion of the poll. On POSIX
    /// systems no `poll` runs now. Only the task calls this function.
    fn closeAll(p: *Parker, self: *Server) void {
        // No `PING` task writes to a socket that the parker closes, and the end of a connection
        // in the parker does not wait for such a task.
        p.reapNudges(self, true);
        while (p.parked.pop()) |conn| {
            if (park.is_windows) {
                // A `GOAWAY` of `shutdown` that did not start yet must not write to the closed
                // handle. `endH2` waits for the users of the HTTP/2 state at the completion of
                // the poll.
                if (conn.started) {
                    conn.h2_ready.store(false, .seq_cst);
                    conn.h2.failWrites();
                }
                conn.closeSocket();
                conn.socket_closed = true;
                p.closing += 1;
            } else {
                conn.endParked();
            }
        }
        p.parked_count.store(0, .release);
        for (p.overflow.items) |conn| conn.endParked();
        _ = p.ready_count.fetchSub(@intCast(p.overflow.items.len), .seq_cst);
        p.overflow.clearRetainingCapacity();
        // A runner can take a ready connection at the same time. Each one takes it once.
        while (p.popReady()) |conn| conn.endParked();
    }
};

/// Send a `PING` to each connection without open streams whose read without the wait runs
/// longer than `nudge_after_ms`. The answer of the client ends the read.
///
/// The write of a `PING` can wait, for example for a client that does not read. Thus a task of
/// its own sends each `PING`, and the parker never waits for it. The task holds a reference
/// to the HTTP/2 state (`Conn.useH2`), and `Conn.endH2` waits for it. The parker collects
/// each task and releases the reference. At the end of a connection or at the stop, it
/// cancels a task that still waits. On Windows only a cancel ends such a write.
fn nudgeIdleReads(self: *Server) void {
    const io = self.io;
    const now = nowNs(io);
    var targets: [64]*Conn = undefined;
    var n: usize = 0;
    {
        self.retired_conns.enter();
        defer self.retired_conns.leave(self.gpa, Server.freeConn);
        for (self.connections) |*place| {
            if (n == targets.len) break;
            const c = place.load(.seq_cst) orelse continue;
            if (!c.h2_ready.load(.acquire)) continue;
            const since = c.read_since.load(.acquire);
            if (since == 0 or now - since < nudge_after_ms * std.time.ns_per_ms) continue;
            if (!c.useH2()) continue;
            // A read of a connection with open streams continues: the streams can still get
            // frames.
            if (c.h2.ownedStreams() > 0 or c.pinged.swap(true, .acq_rel)) {
                c.releaseH2();
                continue;
            }
            targets[n] = c;
            n += 1;
        }
    }
    const p = &self.parker;
    for (targets[0..n]) |c| {
        const started = start: {
            const nudge = self.gpa.create(Parker.Nudge) catch break :start false;
            nudge.* = .{ .conn = c };
            p.nudges.append(self.gpa, nudge) catch {
                self.gpa.destroy(nudge);
                break :start false;
            };
            nudge.future = io.concurrent(sendNudge, .{nudge}) catch {
                _ = p.nudges.pop();
                self.gpa.destroy(nudge);
                break :start false;
            };
            break :start true;
        };
        if (!started) {
            // Without a task, the next scan tries again.
            c.pinged.store(false, .release);
            c.releaseH2();
        }
    }
}

fn sendNudge(nudge: *Parker.Nudge) void {
    // The parker releases the HTTP/2 state when it collects the task.
    defer nudge.done.store(true, .release);
    nudge.conn.h2.ping(.{ 'm', 'c', 'p', 'n', 'u', 'd', 'g', 'e' }) catch {};
}

/// A task that serves ready connections of the parker, one after the other. The parker starts
/// at most `Parker.max_runs` runners that do not wait for a socket. A runner ends when no
/// connection is ready. Before, the parker started a task for each ready connection. Then 50
/// clients made a call at the same time. The starts came faster than the ends of the tasks,
/// and the thread pool of `std.Io.Threaded` grew to about one thread for each connection.
fn runner(self: *Server, first: *Conn) void {
    var conn = first;
    while (true) {
        if (!conn.serveOnce()) return;
        conn = self.parker.next() orelse return;
    }
}

/// The task of the parker. See `Parker`.
fn runParker(self: *Server) void {
    const p = &self.parker;
    const poller = &p.poller.?;
    var events: [256]park.Event = undefined;
    while (true) {
        p.takeAdmissions(self);
        const stopping = p.stopping.load(.seq_cst);
        p.reapNudges(self, false);
        if (stopping) p.closeAll(self);
        p.moveOverflow();
        var starts: [64]*Conn = undefined;
        const n_starts = p.takeStarts(&starts);
        // A park that runs now comes into `admissions` before its end.
        const done = stopping and p.admitting.load(.seq_cst) == 0 and p.admissions.isEmpty() and
            p.parked.items.len == 0 and p.ready_count.load(.seq_cst) == 0 and p.closing == 0;
        if (done) p.running.store(false, .release);
        if (!park.is_windows) {
            p.snapshot.clearRetainingCapacity();
            for (p.parked.items) |c| p.snapshot.append(self.gpa, &c.slot) catch break;
        }
        const parked = p.parked.items.len;
        // Admissions that waited for memory also try again soon.
        const waiting = p.ready_count.load(.seq_cst) > 0 or !p.admissions.isEmpty() or (stopping and p.admitting.load(.seq_cst) > 0);
        p.startTasks(self, starts[0..n_starts]);
        if (done) return;
        // A connection without a task waits for the next try. A connection with a task can
        // need a `PING` (see `Conn.onIdle`).
        const active = self.connection_count.load(.seq_cst) > parked;
        const timeout_ms: i32 = if (waiting) 10 else if (active) nudge_after_ms / 2 else -1;
        const n = poller.wait(timeout_ms, p.snapshot.items, &events) catch 0;
        if (!p.stopping.load(.seq_cst)) nudgeIdleReads(self);
        if (n == 0) continue;
        // The admission of a connection comes before the events of its socket.
        p.takeAdmissions(self);
        for (events[0..n]) |ev| p.handleEvent(self, ev);
    }
}

/// The arenas of calls that ended. A call takes one and gives it back with its memory, up to
/// `keep_bytes`. Before, each call started an empty arena and freed it at the end. A call of
/// the typed binding that grew its arena past 64 KiB, for example `ListTools`, then mapped
/// and unmapped pages each time. On Linux that was one `mmap` and one `munmap` for each call.
///
/// The pool is lock-free: each place holds one arena, and a task takes or puts an arena with
/// one atomic operation on a place.
const ArenaPool = struct {
    free: lockfree.Pool(std.heap.ArenaAllocator, max_kept) = .{},

    /// The memory that an arena keeps for the next call.
    const keep_bytes = 256 * 1024;
    /// The most arenas that the pool keeps.
    const max_kept = 64;

    fn acquire(p: *ArenaPool, gpa: Allocator) Allocator.Error!*std.heap.ArenaAllocator {
        if (p.free.take()) |a| return a;
        const a = try gpa.create(std.heap.ArenaAllocator);
        a.* = .init(gpa);
        return a;
    }

    fn release(p: *ArenaPool, gpa: Allocator, a: *std.heap.ArenaAllocator) void {
        _ = a.reset(.{ .retain_with_limit = keep_bytes });
        if (p.free.put(a)) return;
        a.deinit();
        gpa.destroy(a);
    }

    fn deinit(p: *ArenaPool, gpa: Allocator) void {
        while (p.free.take()) |a| {
            a.deinit();
            gpa.destroy(a);
        }
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
    /// The socket buffers. They stay in place while the connection parks.
    in_buf: []u8 = &.{},
    out_buf: []u8 = &.{},
    reader: Io.net.Stream.Reader = undefined,
    writer: Io.net.Stream.Writer = undefined,
    /// The state of the connection in the poll of the parker.
    slot: park.Slot = .{},
    /// The place of the connection in `Parker.parked`.
    park_index: usize = 0,
    /// The connection does not park again, because a park failed.
    park_off: bool = false,
    /// The parker closed the socket at the shutdown. Only the parker uses the field.
    socket_closed: bool = false,
    /// The socket is open. See `closeSocket`.
    socket_open: std.atomic.Value(bool) = .init(true),
    /// The tasks that use the socket handle from `Server.connections`. See `closeSocket`.
    socket_users: std.atomic.Value(u32) = .init(0),
    /// The place in `Server.connections`, or null.
    place: ?usize = null,
    /// The link of `Parker.admissions`.
    next_admitted: ?*Conn = null,
    /// The link of `Server.retired_conns`.
    next_retired: ?*Conn = null,
    /// The arm of the poll in `Parker.admit`.
    arm_state: std.atomic.Value(ArmState) = .init(.armed),
    /// A task ran `run`: the buffers and the HTTP/2 state exist.
    started: bool = false,
    /// The task of the connection holds a run of the parker (`Parker.runs`).
    holds_run: bool = false,
    /// The task gave its run back for a read, and takes it again after the read.
    run_lent: bool = false,
    /// The last idle read of the connection started a call in less than `busy_gap_ms`. See
    /// `onIdle`.
    busy: bool = false,
    /// The next idle read is the first read of a new task: the new connection or the
    /// connection after a park. It does not park.
    first_read: bool = true,
    /// The bytes after the last park came in less than `busy_gap_ms`.
    quick_wake: bool = false,
    /// The calls in a row that came less than `busy_gap_ms` after the call or the park
    /// before them.
    quick_calls: u8 = 0,
    /// The parker gave the connection a task without bytes in the socket.
    wake_unready: bool = false,
    /// When the connection parked.
    parked_at: i64 = 0,
    /// The last stream of the peer at the start of the last idle read.
    idle_stream_id: u31 = 0,
    /// The start of an idle read without the wait before a park, or zero. See `onIdle`.
    read_since: std.atomic.Value(i64) = .init(0),
    /// The parker sent a `PING` for the idle read that runs.
    pinged: std.atomic.Value(bool) = .init(false),
    /// The tasks of other connections that use the HTTP/2 state: `PING` tasks and `shutdown`.
    /// See `useH2`.
    h2_users: std.atomic.Value(u32) = .init(0),
    /// The quick calls for the workers, in order. See `enqueue`.
    queue: lockfree.Ring(Moved, queue_capacity) = .{},
    /// The workers that run.
    workers: std.atomic.Value(u32) = .init(0),

    /// The most calls in the queue of the workers. A connection has at most
    /// `max_concurrent_streams` calls, thus the queue is rarely full. A call that finds the
    /// queue full gets a task of its own.
    const queue_capacity = 64;

    const ArmState = enum(u8) { pending, armed, failed };

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
    ///
    /// The queue and the count of workers are lock-free. The read task and the workers never
    /// wait for each other.
    fn enqueue(conn: *Conn, m: *Moved) void {
        const io = conn.owner.io;
        m.queued_at = .now(io, .awake);
        if (!conn.queue.push(m)) {
            // The queue is full: the call gets a task of its own. Without a task, it runs here.
            conn.group.concurrent(io, Moved.run, .{m}) catch m.runQueued();
            return;
        }
        if (conn.joinWorkers()) {
            // Without a task, the read task runs the queue itself.
            conn.group.concurrent(io, workerRun, .{conn}) catch workerRun(conn);
        }
    }

    /// Count one more worker when fewer than `Server.max_workers` run. True when the caller
    /// is that worker.
    fn joinWorkers(conn: *Conn) bool {
        const max = conn.owner.max_workers;
        var n = conn.workers.load(.seq_cst);
        while (n < max) n = conn.workers.cmpxchgWeak(n, n + 1, .seq_cst, .seq_cst) orelse return true;
        return false;
    }

    fn workerRun(conn: *Conn) void {
        while (true) {
            while (conn.queue.pop()) |m| m.runQueued();
            _ = conn.workers.fetchSub(1, .seq_cst);
            // A call can come after the last pop, while each worker still counted. Its
            // `enqueue` then started no worker. Thus the worker looks again after it left the
            // count, and stays for such a call.
            if (!conn.queue.hasItems() or !conn.joinWorkers()) return;
        }
    }

    /// The task of a connection that does not use the parker: a TLS connection, or a
    /// plaintext connection without the parker.
    fn run(conn: *Conn) Io.Cancelable!void {
        if (conn.owner.options.tls) |tls_server| {
            if (!conn.allocBuffers()) return conn.end();
            return conn.runTls(tls_server);
        }
        if (conn.setup()) _ = conn.serveLoop();
    }

    fn allocBuffers(conn: *Conn) bool {
        const self = conn.owner;
        conn.started = true;
        conn.in_buf = self.gpa.alloc(u8, tls.Connection.min_input_buffer_len) catch return false;
        conn.out_buf = self.gpa.alloc(u8, tls.Connection.min_output_buffer_len) catch return false;
        conn.reader = conn.stream.reader(self.io, conn.in_buf);
        conn.writer = conn.stream.writer(self.io, conn.out_buf);
        return true;
    }

    /// Make the buffers and the HTTP/2 state, and read the preface. False when the connection
    /// ended: then it is free.
    fn setup(conn: *Conn) bool {
        if (!conn.allocBuffers()) {
            conn.end();
            return false;
        }
        return conn.setupH2();
    }

    /// The part of `setup` after the buffers.
    fn setupH2(conn: *Conn) bool {
        const self = conn.owner;
        conn.h2 = Connection.init(self.gpa, self.io, &conn.reader.interface, &conn.writer.interface, conn.h2Options()) catch {
            conn.end();
            return false;
        };
        conn.h2_ready.store(true, .release);
        conn.h2.handshake() catch {
            conn.endH2();
            return false;
        };
        // The handshake read the bytes of the client. A client sends its first call after it
        // read the settings of the server. Until then the connection parks: a task that waits
        // for the call holds a thread.
        conn.first_read = false;
        return true;
    }

    /// Serve a connection that the parker gave to a runner, until it parks or ends. True when
    /// the runner still holds its run of the parker.
    fn serveOnce(conn: *Conn) bool {
        if (!conn.started) {
            if (!conn.allocBuffers()) {
                conn.end();
                return true;
            }
            // The socket is ready, thus the first read does not wait. When the preface is not
            // complete after it, the handshake can wait long: the runner gives its run back
            // for that time. Without a poll (`wake_unready`), even the first read can wait.
            var lent = conn.wake_unready;
            conn.wake_unready = false;
            if (!lent) {
                conn.reader.interface.fillMore() catch {};
                lent = conn.reader.interface.bufferedLen() < frame_preface_len;
            }
            if (lent) conn.lendRun();
            // When the run went back, the connection ends without it.
            if (!conn.setupH2()) return !lent;
            if (lent) conn.retakeRun();
        }
        return conn.serveLoop();
    }

    /// End a connection that has no task, in the parker.
    fn endParked(conn: *Conn) void {
        if (conn.started) return conn.endH2();
        conn.end();
    }

    fn h2Options(conn: *Conn) Connection.Options {
        return .{
            .role = .server,
            .on_stream = onStream,
            .userdata = conn,
            .max_concurrent_streams = conn.owner.server.options.limits.max_in_flight_requests,
        };
    }

    /// Read the connection until it ends or until it parks. See `onIdle`. True when the task
    /// holds a run of the parker at the end (see `runner`).
    fn serveLoop(conn: *Conn) bool {
        const self = conn.owner;
        while (true) {
            switch (conn.h2.runUntilIdle(.{ .userdata = conn, .idle = onIdle, .waiting = onWaiting, .resumed = onResumed })) {
                .idle => {
                    // After the park, another task can own the connection at once.
                    const had_run = conn.takeRun();
                    if (self.parker.admit(self, conn)) return had_run;
                    conn.holds_run = had_run;
                    conn.park_off = true;
                },
                .closed => break,
            }
        }
        const had_run = conn.takeRun();
        conn.endH2();
        return had_run;
    }

    /// Take the run of the parker from the connection, for its runner.
    fn takeRun(conn: *Conn) bool {
        const had = conn.holds_run;
        conn.holds_run = false;
        conn.run_lent = false;
        return had;
    }

    /// The read ended: the task takes its run again. It can go over `max_runs` for a short time.
    fn retakeRun(conn: *Conn) void {
        if (!conn.run_lent) return;
        conn.run_lent = false;
        conn.holds_run = true;
        _ = conn.owner.parker.runs.fetchAdd(1, .acq_rel);
    }

    /// The task waits for the socket: its run of the parker is free until the read ends.
    fn lendRun(conn: *Conn) void {
        if (!conn.holds_run) return;
        conn.holds_run = false;
        conn.run_lent = true;
        conn.owner.parker.releaseRun();
    }

    /// The read task asks if the connection can park: it has no open stream. True when the
    /// connection parks at once. Then the read task ends, and the parker of the server watches
    /// the socket. A connection with a worker that runs does not park.
    ///
    /// A busy connection does not park: `busy_after_calls` calls in a row came less than
    /// `busy_gap_ms` after the call or the park before them. A park and the new task after it
    /// cost two wakes of other threads, thus a sequential client pays for a few parks only.
    /// The read task then reads the socket.
    ///
    /// When such a read waits long, the parker sends a `PING` (`nudge_after_ms`). The answer
    /// of the client ends the read, and the connection parks. Before, the read task waited
    /// 2 ms for bytes before each park, and kept its thread for that time. When 200 clients
    /// made their first call at the same time, the thread pool grew to 200 threads.
    fn onIdle(userdata: ?*anyopaque) bool {
        const conn: *Conn = @ptrCast(@alignCast(userdata.?));
        const self = conn.owner;
        // Each read without a park can wait long, thus the runner gives its run back first.
        if (conn.park_off or !self.parker.isRunning() or self.closing.load(.acquire)) {
            conn.lendRun();
            return false;
        }
        if (conn.workers.load(.seq_cst) > 0 or conn.queue.hasItems()) {
            onWaiting(conn);
            return false;
        }
        conn.idle_stream_id = conn.h2.last_peer_stream_id;
        // The bytes that woke the connection, or the first bytes of a new connection.
        if (conn.first_read) {
            conn.first_read = false;
            if (conn.wake_unready) {
                conn.wake_unready = false;
                conn.lendRun();
                return false;
            }
            // The socket is ready, thus this read does not wait. A client can send a part of
            // a frame and stop: then the read of the rest waits without the run.
            conn.reader.interface.fillMore() catch {};
            if (!conn.h2.frameBuffered()) conn.lendRun();
            return false;
        }
        if (conn.busy) {
            conn.read_since.store(nowNs(self.io), .release);
            conn.lendRun();
            return false;
        }
        return true;
    }

    /// A read of a connection with open streams starts. When the streams end during the read,
    /// the connection is idle, and the parker sends a `PING` to end the read.
    fn onWaiting(userdata: ?*anyopaque) void {
        const conn: *Conn = @ptrCast(@alignCast(userdata.?));
        conn.lendRun();
        if (conn.park_off or !conn.owner.parker.isRunning()) return;
        conn.idle_stream_id = conn.h2.last_peer_stream_id;
        conn.read_since.store(nowNs(conn.owner.io), .release);
    }

    /// The read after `onIdle` or `onWaiting` gave a frame. The connection is busy when the
    /// frame came in less than `busy_gap_ms` and a new call started. A control frame, for
    /// example the answer to a `PING` or to the settings, does not count.
    fn onResumed(userdata: ?*anyopaque) void {
        const conn: *Conn = @ptrCast(@alignCast(userdata.?));
        conn.retakeRun();
        const since = conn.read_since.swap(0, .acq_rel);
        const quick = if (since != 0) nowNs(conn.owner.io) - since < busy_gap_ms * std.time.ns_per_ms else conn.quick_wake;
        conn.quick_wake = false;
        if (!quick) {
            conn.quick_calls = 0;
        } else if (conn.h2.last_peer_stream_id != conn.idle_stream_id) {
            conn.quick_calls +|= 1;
        }
        conn.busy = conn.quick_calls >= busy_after_calls;
        conn.pinged.store(false, .release);
    }

    /// The TLS connection keeps its task, also while it is idle: the TLS state can hold bytes
    /// that the socket does not show.
    fn runTls(conn: *Conn, tls_server: *const tls.Server) void {
        const self = conn.owner;
        const io = self.io;
        defer conn.end();
        const tls_read_buf = self.gpa.alloc(u8, tls.Connection.min_read_buffer_len) catch return;
        defer self.gpa.free(tls_read_buf);
        const tls_write_buf = self.gpa.alloc(u8, 16 * 1024) catch return;
        defer self.gpa.free(tls_write_buf);
        var tls_conn = tls_server.accept(&conn.reader.interface, &conn.writer.interface, .{
            .io = io,
            .read_buffer = tls_read_buf,
            .write_buffer = tls_write_buf,
            .allow_truncation_attacks = true,
        }) catch return;
        defer {
            tls_conn.end() catch {};
            conn.writer.interface.flush() catch {};
            tls_conn.deinit();
        }
        // A client that negotiated another protocol gets no HTTP/2.
        if (tls_conn.alpn()) |alpn| if (!std.mem.eql(u8, alpn, "h2")) return;
        conn.h2 = Connection.init(self.gpa, io, &tls_conn.reader, &tls_conn.writer, conn.h2Options()) catch return;
        defer conn.h2.deinit();
        conn.h2_ready.store(true, .release);
        defer conn.stopH2();
        conn.h2.handshake() catch return;
        conn.h2.run();
        conn.group.await(io) catch {};
    }

    /// Take a reference to the HTTP/2 state for a task of another connection. False when the
    /// state does not exist or ends. Call `releaseH2` after the use.
    fn useH2(conn: *Conn) bool {
        _ = conn.h2_users.fetchAdd(1, .seq_cst);
        if (conn.h2_ready.load(.seq_cst)) return true;
        conn.releaseH2();
        return false;
    }

    fn releaseH2(conn: *Conn) void {
        _ = conn.h2_users.fetchSub(1, .seq_cst);
    }

    /// No new task takes the HTTP/2 state from now on. Wait for the tasks that use it: a
    /// `PING` or the `GOAWAY` of `shutdown`.
    fn stopH2(conn: *Conn) void {
        conn.h2_ready.store(false, .seq_cst);
        while (conn.h2_users.load(.seq_cst) != 0) conn.owner.io.sleep(.fromMilliseconds(1), .awake) catch {};
    }

    /// Close the socket once. A `shutdown` can use the handle at the same time, thus wait for
    /// it. After the close, the handle can belong to a new socket. The wait is short and comes
    /// only at the shutdown of the server.
    fn closeSocket(conn: *Conn) void {
        if (!conn.socket_open.swap(false, .seq_cst)) return;
        while (conn.socket_users.load(.seq_cst) != 0) std.Thread.yield() catch {};
        conn.stream.close(conn.owner.io);
    }

    /// End a plaintext connection with its HTTP/2 state.
    fn endH2(conn: *Conn) void {
        const self = conn.owner;
        conn.group.await(self.io) catch {};
        // A `PING` task of the parker can wait for a peer that does not read. The parker
        // cancels it when it sees the end (`Parker.reapNudges`), thus wake the parker. On POSIX
        // systems the shutdown of the socket also ends such a write.
        conn.h2_ready.store(false, .seq_cst);
        conn.h2.failWrites();
        if (self.parker.poller) |*poller| poller.wake();
        if (conn.socket_open.load(.seq_cst)) conn.stream.shutdown(self.io, .both) catch {};
        conn.stopH2();
        conn.h2.deinit();
        conn.end();
    }

    /// Free the connection. A socket that the parker closed stays closed.
    fn end(conn: *Conn) void {
        const self = conn.owner;
        if (conn.in_buf.len > 0) self.gpa.free(conn.in_buf);
        if (conn.out_buf.len > 0) self.gpa.free(conn.out_buf);
        self.untrack(conn);
        conn.closeSocket();
        self.permits.give(self.io);
        // A task that reads `Server.connections` can still use the connection.
        self.retired_conns.retire(conn, self.gpa, Server.freeConn);
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
    const arena_state = self.arenas.acquire(self.gpa) catch return logCallError(error.OutOfMemory);
    defer self.arenas.release(self.gpa, arena_state);
    _ = serveCall(conn, stream, arena_state, .task) catch |e| logCallError(e);
}

/// Give a call with a complete request to the workers before a look at the request. A worker
/// runs it as the read task does: a call that is not quick then gets a task of its own.
fn queueStream(conn: *Conn, stream: *Stream) void {
    const self = conn.owner;
    const arena_state = self.arenas.acquire(self.gpa) catch {
        logCallError(error.OutOfMemory);
        stream.cancel();
        stream.close();
        return;
    };
    const m = arena_state.allocator().create(Moved) catch {
        logCallError(error.OutOfMemory);
        stream.cancel();
        stream.close();
        self.arenas.release(self.gpa, arena_state);
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
    const arena_state = self.arenas.acquire(self.gpa) catch {
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
    self.arenas.release(self.gpa, arena_state);
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
        self.arenas.release(self.gpa, arena_state);
    }

    /// Run a call in a task of its own.
    fn run(m: *Moved) void {
        // The arena holds `m`.
        const conn = m.conn;
        const stream = m.stream;
        const arena_state = m.arena_state;
        const self = conn.owner;
        defer self.arenas.release(self.gpa, arena_state);
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
    if (deadline) |d| if (!no_wait) watch.start(&self.deadlines, io, self.gpa, d, &token, &exchange.deadline_hit);
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
///
/// The outbox has no lock. The server engine gives the events of one subscription one after
/// the other, and `close` comes after the last event. Only the drain task runs at the same
/// time. One task at a time is the sender: the task of an event or the drain task. A task that
/// finds another sender leaves its event in the queue, and the sender sends it.
const Outbox = struct {
    /// The events that wait for the sender, the newest first.
    queue: lockfree.Stack(Msg, "next") = .{},
    /// The events that the sender took from `queue`, the oldest first. Only the sender uses
    /// the fields.
    backlog: ?*Msg = null,
    backlog_tail: ?*Msg = null,
    sender: std.atomic.Value(Sender) = .init(.idle),
    /// The bytes of the events in the queue and in the backlog.
    bytes: std.atomic.Value(usize) = .init(0),
    closed: std.atomic.Value(bool) = .init(false),
    /// The last drain task. Only the tasks of the events and `close` use the field, one after
    /// the other.
    drain: ?Io.Future(void) = null,

    /// The most bytes that wait in the outbox. When a subscriber reads slower, its listen
    /// stream ends.
    const max_bytes = 1 << 20;

    const Sender = enum(u32) {
        idle,
        /// The task of an event sends. It does not wait for credit.
        event,
        /// The drain task sends. It can wait for credit.
        drain,
    };

    /// One encoded event from `Exchange.gpa`. The bytes follow the struct.
    const Msg = struct {
        next: ?*Msg = null,
        len: usize,

        fn create(gpa: Allocator, bytes: []const u8) Allocator.Error!*Msg {
            const mem = try gpa.alignedAlloc(u8, .of(Msg), @sizeOf(Msg) + bytes.len);
            const m: *Msg = @ptrCast(mem.ptr);
            m.* = .{ .len = bytes.len };
            @memcpy(mem[@sizeOf(Msg)..], bytes);
            return m;
        }

        fn payload(m: *Msg) []const u8 {
            const base: [*]u8 = @ptrCast(m);
            return base[@sizeOf(Msg)..][0..m.len];
        }

        fn free(m: *Msg, gpa: Allocator) void {
            const base: [*]align(@alignOf(Msg)) u8 = @ptrCast(m);
            gpa.free(base[0 .. @sizeOf(Msg) + m.len]);
        }
    };

    fn notify(out: *Outbox, io: Io, ex: *Exchange, frame: []const u8) Transport.SendError!void {
        const gpa = ex.gpa;
        if (out.closed.load(.acquire) or ex.done) return error.Closed;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(gpa);
        try messages.encodeJsonRpcMessage(gpa, &encoded, frame);
        if (out.bytes.fetchAdd(encoded.items.len, .monotonic) + encoded.items.len > max_bytes) {
            _ = out.bytes.fetchSub(encoded.items.len, .monotonic);
            return error.Closed;
        }
        const m = Msg.create(gpa, encoded.items) catch |e| {
            _ = out.bytes.fetchSub(encoded.items.len, .monotonic);
            return e;
        };
        out.queue.push(m);
        try out.pump(io, ex);
    }

    /// Send the events as the sender, when no other task is the sender. An event without the
    /// credit goes to a new drain task.
    fn pump(out: *Outbox, io: Io, ex: *Exchange) Transport.SendError!void {
        while (true) {
            if (out.sender.cmpxchgStrong(.idle, .event, .seq_cst, .seq_cst) != null) return;
            const blocked = out.sendReady(ex) catch |e| {
                out.closed.store(true, .release);
                out.sender.store(.idle, .seq_cst);
                return mapSend(e);
            };
            if (blocked) {
                // The last drain task stopped as the sender already. It ends without a wait.
                if (out.drain) |*f| f.await(io);
                out.drain = null;
                out.sender.store(.drain, .seq_cst);
                out.drain = io.concurrent(drainRun, .{ out, io, ex }) catch {
                    out.closed.store(true, .release);
                    out.sender.store(.idle, .seq_cst);
                    return error.Closed;
                };
                return;
            }
            out.sender.store(.idle, .seq_cst);
            // An event that came while this task was the sender found the sender busy.
            if (out.queue.isEmpty()) return;
        }
    }

    /// Move the events of the queue to the end of the backlog. Only the sender calls this
    /// function.
    fn takeQueue(out: *Outbox) void {
        var list = out.queue.takeAllInOrder() orelse return;
        if (out.backlog_tail) |t| t.next = list else out.backlog = list;
        while (list.next) |n| list = n;
        out.backlog_tail = list;
    }

    fn popBacklog(out: *Outbox, gpa: Allocator) void {
        const m = out.backlog.?;
        out.backlog = m.next;
        if (out.backlog == null) out.backlog_tail = null;
        _ = out.bytes.fetchSub(m.len, .monotonic);
        m.free(gpa);
    }

    /// Send the headers and the events without a wait. True when an event waits for credit.
    /// Only the sender of the events calls this function.
    fn sendReady(out: *Outbox, ex: *Exchange) !bool {
        // A header block does not wait for credit.
        try ex.ensureHeaders();
        out.takeQueue();
        while (out.backlog) |m| {
            lpm.writeNoWait(ex.stream, ex.gpa, m.payload(), false) catch |e| switch (e) {
                error.WouldBlock => return true,
                else => return e,
            };
            out.popBacklog(ex.gpa);
        }
        return false;
    }

    /// Send the events of the backlog and of the queue. A send of this task can wait for credit.
    fn drainRun(out: *Outbox, io: Io, ex: *Exchange) void {
        _ = io;
        while (!out.closed.load(.acquire)) {
            out.takeQueue();
            const m = out.backlog orelse {
                out.sender.store(.idle, .seq_cst);
                // An event that came before the store found the sender busy.
                if (out.queue.isEmpty()) return;
                if (out.sender.cmpxchgStrong(.idle, .drain, .seq_cst, .seq_cst) != null) return;
                continue;
            };
            lpm.write(ex.stream, ex.gpa, m.payload(), false) catch {
                out.closed.store(true, .release);
                break;
            };
            out.popBacklog(ex.gpa);
        }
        out.sender.store(.idle, .seq_cst);
    }

    /// Accept no more events and stop the drain task. The outbox drops the events that still
    /// wait for credit. The listen call ends, thus the stream ends too. Call this function from the task
    /// of the call, before the last frames of the call.
    fn close(out: *Outbox, io: Io, ex: *Exchange) void {
        out.closed.store(true, .seq_cst);
        if (out.drain) |*f| {
            // A drain task that waits for credit stops with `error.Canceled`.
            if (out.sender.load(.seq_cst) == .drain) ex.stream.stopWaits();
            f.await(io);
            out.drain = null;
        }
        // No task sends now: the events came before this call.
        out.takeQueue();
        while (out.backlog != null) out.popBacklog(ex.gpa);
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
