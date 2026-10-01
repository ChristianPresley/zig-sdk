//! The Unix socket transport: the stdio framing (newline-delimited JSON-RPC) over a stream
//! socket at a file system path. It is a custom transport. It keeps the JSON-RPC format, the
//! message patterns and the request metadata of the specification.
//!
//! The server accepts many connections. Each connection is one stdio peer: requests run
//! concurrently, `notifications/cancelled` cancels a request, and listen streams work. When a
//! peer closes its connection, the server cancels the requests of that peer.
//!
//! The file mode and the directory of the socket control access, because the server does not
//! check the peer. On POSIX systems the server sets the mode `0600` on the socket file. On
//! Windows it gives the socket file a protected access control list that allows access only
//! to the user of the process. Windows checks this list when a client connects.
//!
//! `bind` creates the socket in a new private directory next to the path and sets the mode or
//! the list. Then it moves the socket to the path. Thus no client can connect before the
//! socket has its protection. `bind` refuses a directory where other accounts can add, delete
//! or rename entries, because such an account can put its own socket at the path. Use
//! `createPrivateDirectory` to make a safe directory.
//!
//! The server refuses a path that is not a socket. It removes a stale socket file at start
//! and its own socket file at shutdown.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("Transport.zig");
const framer = @import("../util/line_framer.zig");
const wake = @import("../util/wake.zig");
const jsonrpc = @import("../jsonrpc.zig");
const RequestId = jsonrpc.RequestId;
const types = @import("../protocol/types.zig");
const message = @import("../jsonrpc/message.zig");
const Limits = @import("../Limits.zig");
const McpServer = @import("../server/Server.zig");
const stdio = @import("stdio.zig");
const router_mod = @import("router.zig");
const Router = router_mod.Router;

const log = std.log.scoped(.mcp_unix);
const windows_acl = if (builtin.os.tag == .windows) @import("windows_acl.zig") else struct {};
const socket_dir = @import("socket_dir.zig");

/// True when the target has Unix domain sockets. Windows has them from Windows 10 version
/// 1803. When this is false, `Server.bind` and `Client.connect` return `error.Unsupported`.
pub const supported = Io.net.has_unix_sockets;

pub const Options = struct {
    /// The file system path of the socket. On Windows the server resolves a relative path
    /// against the current directory. The path has 108 bytes or less on Linux and 104 bytes
    /// or less on macOS. During `bind` the socket is in a directory with an 11-byte name next
    /// to the path. Thus the path of the directory of the socket plus 14 bytes must also fit.
    path: []const u8,
    /// The permission bits of the socket file on POSIX systems. On Windows a value without
    /// group and other bits (`mode & 0o077 == 0`) allows access only to the user of the
    /// process. Another value keeps the access control list that the file inherits from the
    /// directory.
    mode: u32 = 0o600,
};

pub const BindError = error{
    /// The target has no Unix domain sockets.
    Unsupported,
    /// A file that is not a socket is at the path. The server does not touch it.
    PathNotSocket,
    /// A server listens on the path.
    AddressInUse,
    NameTooLong,
    OutOfMemory,
    /// Windows did not set the access control list of the socket file. The log has the
    /// Windows error code.
    AccessControlFailed,
    /// Other accounts can add, delete or rename entries in the directory of the socket.
    DirectoryNotPrivate,
} || Io.net.UnixAddress.ListenError || Io.Dir.StatFileError || Io.File.OpenError || Io.Dir.DeleteFileError || Io.Dir.SetFilePermissionsError || std.process.CurrentPathAllocError || socket_dir.TempError || Io.Dir.RenameError;

/// Create a private directory for sockets at `path`. On POSIX systems it has the mode `0700`.
/// On Windows it has an access control list that allows access only to the user of the
/// process. A directory that is already at `path` must be private, or the call gives
/// `error.DirectoryNotPrivate`. The parent directories must exist.
pub fn createPrivateDirectory(io: Io, path: []const u8) socket_dir.CreateError!void {
    return socket_dir.createPrivate(io, path);
}

/// Serves one MCP server on a Unix domain socket.
pub const Server = struct {
    io: Io,
    gpa: Allocator,
    server: *McpServer,
    options: Options,
    limits: Limits,
    /// The resolved path of the socket, owned. Set by `bind`.
    path: ?[]u8 = null,
    listener: ?Io.net.Server = null,
    group: Io.Group = .init,
    closing: std.atomic.Value(bool) = .init(false),
    stop_event: Io.Event = .unset,
    connections: std.ArrayList(*Connection) = .empty,
    connections_lock: Io.Mutex = .init,

    pub fn init(io: Io, gpa: Allocator, server: *McpServer, options: Options) Server {
        return .{
            .io = io,
            .gpa = gpa,
            .server = server,
            .options = options,
            .limits = server.options.limits,
        };
    }

    /// Close the socket and remove the socket file, when `serve` did not do it.
    pub fn deinit(self: *Server) void {
        self.closeListener();
        if (self.path) |p| self.gpa.free(p);
        self.connections.deinit(self.gpa);
        self.* = undefined;
    }

    /// Create the socket. This call removes a stale socket file at the path. A file that is
    /// not a socket, a socket with a live server, or a directory that is not private makes the
    /// call fail.
    pub fn bind(self: *Server) BindError!void {
        if (!supported) return error.Unsupported;
        const io = self.io;
        if (self.path == null) self.path = try resolvePath(io, self.gpa, self.options.path);
        const path = self.path.?;
        const dir = std.fs.path.dirname(path) orelse ".";
        if (!try socket_dir.isPrivate(io, dir, self.options.mode)) return error.DirectoryNotPrivate;
        switch (try pathState(io, path)) {
            .absent => {},
            .other => return error.PathNotSocket,
            .socket => {
                try refuseLiveServer(io, path);
                try Io.Dir.cwd().deleteFile(io, path);
            },
        }
        const address = try unixAddress(path);
        if (builtin.os.tag == .windows and self.options.mode & 0o077 != 0) {
            // A shared socket keeps the list that it inherits from the directory, so it has
            // no protection to apply.
            self.listener = try listen(io, address);
            return;
        }
        // Create the socket in a new private directory, protect it, and then move it to
        // `path`. Before the move, only the user of the process can reach it.
        const temp = try socket_dir.createTemp(io, self.gpa, dir);
        defer self.gpa.free(temp);
        defer Io.Dir.cwd().deleteDir(io, temp) catch |e| log.warn("could not remove the directory {s}: {t}", .{ temp, e });
        const inner = try std.fs.path.join(self.gpa, &.{ temp, "s" });
        defer self.gpa.free(inner);
        var listener = try listen(io, try unixAddress(inner));
        errdefer {
            listener.deinit(io);
            Io.Dir.cwd().deleteFile(io, inner) catch {};
        }
        if (builtin.os.tag == .windows) {
            try windows_acl.restrictToCurrentUser(inner);
        } else {
            try Io.Dir.cwd().setFilePermissions(io, inner, .fromMode(@intCast(self.options.mode)), .{});
        }
        try Io.Dir.rename(Io.Dir.cwd(), inner, Io.Dir.cwd(), path, io);
        self.listener = listener;
    }

    fn listen(io: Io, address: Io.net.UnixAddress) BindError!Io.net.Server {
        return address.listen(io, .{}) catch |e| switch (e) {
            error.AddressFamilyUnsupported => error.Unsupported,
            else => |err| err,
        };
    }

    /// Accept connections until a call to `shutdown`. Then remove the socket file.
    pub fn serve(self: *Server) !void {
        if (self.listener == null) try self.bind();
        var accept_future = try self.io.concurrent(acceptLoop, .{self});
        self.stop_event.wait(self.io) catch {};
        if (self.path) |p| wake.wakeUnix(self.io, p);
        _ = accept_future.cancel(self.io);
        // A connection accepted during the shutdown also gets the end of its input.
        self.endInputs();
        if (builtin.os.tag == .windows) {
            // On Windows the end of the input side does not wake a blocked read. The
            // cancellation of the connection tasks does.
            self.group.cancel(self.io);
        } else {
            self.group.await(self.io) catch {};
        }
        self.closeListener();
    }

    /// Stop the accept loop, end the listen streams and cancel the requests in flight. Another
    /// task can call this function.
    pub fn shutdown(self: *Server) void {
        self.closing.store(true, .release);
        self.server.shutdownSubscriptions(self.io);
        self.endInputs();
        self.stop_event.set(self.io);
    }

    /// End the input side of every connection. The connection task then cancels the
    /// requests of its peer, writes what remains and closes.
    fn endInputs(self: *Server) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items) |c| c.stream.shutdown(self.io, .recv) catch {};
    }

    fn closeListener(self: *Server) void {
        if (self.listener) |*l| {
            l.deinit(self.io);
            self.listener = null;
            if (self.path) |p| Io.Dir.cwd().deleteFile(self.io, p) catch |e| {
                log.warn("could not remove the socket file {s}: {t}", .{ p, e });
            };
        }
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
            const conn = self.admit(stream) orelse {
                stream.close(self.io);
                continue;
            };
            self.group.concurrent(self.io, Connection.run, .{conn}) catch {
                self.untrack(conn);
                stream.close(self.io);
                self.gpa.destroy(conn);
            };
        }
    }

    /// Track a new connection. Return null when the server is full or stops.
    fn admit(self: *Server, stream: Io.net.Stream) ?*Connection {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        if (self.closing.load(.acquire)) return null;
        if (self.connections.items.len >= self.limits.unix_socket.max_connections) {
            log.warn("refused a connection: {d} connections are open", .{self.connections.items.len});
            return null;
        }
        const conn = self.gpa.create(Connection) catch return null;
        conn.* = .{ .owner = self, .stream = stream };
        self.connections.append(self.gpa, conn) catch {
            self.gpa.destroy(conn);
            return null;
        };
        return conn;
    }

    fn untrack(self: *Server, conn: *Connection) void {
        self.connections_lock.lockUncancelable(self.io);
        defer self.connections_lock.unlock(self.io);
        for (self.connections.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.connections.swapRemove(i);
                return;
            }
        }
    }
};

const Connection = struct {
    owner: *Server,
    stream: Io.net.Stream,

    fn run(conn: *Connection) Io.Cancelable!void {
        const self = conn.owner;
        const io = self.io;
        defer {
            self.untrack(conn);
            conn.stream.close(io);
            self.gpa.destroy(conn);
        }
        const read_buf = self.gpa.alloc(u8, self.limits.stdio.read_buffer) catch return;
        defer self.gpa.free(read_buf);
        const write_buf = self.gpa.alloc(u8, 64 * 1024) catch return;
        defer self.gpa.free(write_buf);
        var reader = conn.stream.reader(io, read_buf);
        var writer = conn.stream.writer(io, write_buf);
        var peer: stdio.Server = .init(io, self.gpa, self.server, &writer.interface);
        defer peer.deinit();
        peer.kind = .unix_socket;
        peer.on_close = .cancel_requests;
        peer.stop = &self.closing;
        peer.run(&reader.interface) catch |e| log.warn("connection ended: {t}", .{e});
    }
};

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

/// Connects to a server on a Unix domain socket and speaks MCP with the stdio framing. One
/// reader task routes the frames to the requests in flight.
pub const Client = struct {
    io: Io,
    gpa: Allocator,
    options: ConnectOptions,
    stream: Io.net.Stream,
    in_buf: []u8,
    out_buf: []u8,
    stream_reader: Io.net.Stream.Reader,
    stream_writer: Io.net.Stream.Writer,
    out_lock: Io.Mutex = .init,
    router: Router,
    reader_future: ?Io.Future(void) = null,
    closed: std.atomic.Value(bool) = .init(false),
    /// True once the reader task saw the end of the stream.
    reader_done: std.atomic.Value(bool) = .init(false),
    stream_open: bool = true,

    pub const ConnectOptions = struct {
        /// The path of the socket. On Windows the client resolves a relative path against the
        /// current directory.
        path: []const u8,
        limits: Limits = .{},
        /// How often a request that waits checks for cancellation.
        poll_interval: Io.Duration = .fromMilliseconds(50),
        /// Receives notifications that belong to no request in flight.
        on_notification: ?router_mod.NotificationFn = null,
        userdata: ?*anyopaque = null,
    };

    pub const ConnectError = error{
        /// The target has no Unix domain sockets.
        Unsupported,
        NameTooLong,
    } || Io.net.UnixAddress.ConnectError || Io.ConcurrentError || std.process.CurrentPathAllocError;

    /// Connect to the socket and start the reader task.
    pub fn connect(io: Io, gpa: Allocator, options: ConnectOptions) ConnectError!*Client {
        if (!supported) return error.Unsupported;
        const path = try resolvePath(io, gpa, options.path);
        defer gpa.free(path);
        const address = try unixAddress(path);
        const stream = address.connect(io) catch |e| switch (e) {
            error.AddressFamilyUnsupported => return error.Unsupported,
            else => |err| return err,
        };
        errdefer stream.close(io);
        const self = try gpa.create(Client);
        errdefer gpa.destroy(self);
        const in_buf = try gpa.alloc(u8, options.limits.stdio.read_buffer);
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(out_buf);
        self.* = .{
            .io = io,
            .gpa = gpa,
            .options = options,
            .stream = stream,
            .in_buf = in_buf,
            .out_buf = out_buf,
            .stream_reader = stream.reader(io, in_buf),
            .stream_writer = stream.writer(io, out_buf),
            .router = .init(io, gpa, options.limits.json_max_depth),
        };
        self.reader_future = try io.concurrent(readerLoop, .{self});
        return self;
    }

    pub fn transport(self: *Client) Transport.ClientTransport {
        return .{ .ptr = self, .vtable = &client_vtable };
    }

    /// End the output side of the connection and wait for the server to close its side. The
    /// server cancels the requests in flight. After `limits.shutdown_grace` the reader stops
    /// without the server.
    pub fn close(self: *Client) void {
        const io = self.io;
        if (!self.closed.swap(true, .acq_rel)) {
            self.out_lock.lockUncancelable(io);
            self.stream_writer.interface.flush() catch {};
            self.out_lock.unlock(io);
            self.stream.shutdown(io, .send) catch {};
        }
        if (self.reader_future) |*f| {
            if (self.waitReader(self.options.limits.shutdown_grace)) f.await(io) else f.cancel(io);
            self.reader_future = null;
        }
        if (self.stream_open) {
            self.stream.close(io);
            self.stream_open = false;
        }
    }

    pub fn deinit(self: *Client) void {
        self.close();
        self.gpa.free(self.in_buf);
        self.gpa.free(self.out_buf);
        self.router.deinit();
        self.gpa.destroy(self);
    }

    /// Wait until the reader saw the end of the stream, at most `grace`.
    fn waitReader(self: *Client, grace: Io.Duration) bool {
        const io = self.io;
        const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = grace, .clock = .awake });
        while (!self.reader_done.load(.acquire)) {
            if (Io.Clock.Timestamp.now(io, .awake).durationTo(deadline).raw.nanoseconds <= 0) return false;
            io.sleep(.fromMilliseconds(10), .awake) catch return false;
        }
        return true;
    }

    const client_vtable: Transport.ClientTransport.VTable = .{
        .kind = .unix_socket,
        .exchange = exchange,
        .notify = notify,
    };

    fn writeFrame(self: *Client, frame: []const u8) Transport.SendError!void {
        if (self.closed.load(.acquire)) return error.Closed;
        self.out_lock.lockUncancelable(self.io);
        defer self.out_lock.unlock(self.io);
        framer.writeFrame(&self.stream_writer.interface, frame) catch return error.WriteFailed;
    }

    fn notify(ptr: *anyopaque, io: Io, frame: []const u8) Transport.SendError!void {
        _ = io;
        const self: *Client = @ptrCast(@alignCast(ptr));
        return self.writeFrame(frame);
    }

    fn exchange(ptr: *anyopaque, io: Io, ex: *Transport.Exchange) Transport.ExchangeError!void {
        const self: *Client = @ptrCast(@alignCast(ptr));
        var pending: Router.Pending = .{ .id = ex.id };
        defer pending.deinit(self.gpa);
        try self.router.register(&pending);
        defer self.router.unregister(&pending);
        self.writeFrame(ex.frame) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            error.WriteFailed => return error.WriteFailed,
            error.Closed => return error.Closed,
        };
        while (true) {
            // Deliver everything that arrived.
            while (self.router.takeFrame(&pending)) |frame| {
                defer self.gpa.free(frame);
                const is_response = router_mod.frameIsResponse(frame);
                ex.deliver(io, frame) catch return error.InvalidFrame;
                if (is_response) return;
            }
            if (ex.cancel.isCancelled()) {
                self.sendCancelled(ex.id, ex.cancel.reason);
                return error.Canceled;
            }
            if (ex.expired(io)) {
                self.sendCancelled(ex.id, "timeout");
                return error.Timeout;
            }
            if (self.closed.load(.acquire)) return error.Closed;
            pending.event.waitTimeout(io, .{ .duration = .{ .raw = self.options.poll_interval, .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {},
                error.Canceled => return error.Canceled,
            };
            pending.event.reset();
        }
    }

    fn sendCancelled(self: *Client, id: RequestId, reason: ?[]const u8) void {
        var buf: [512]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        var aw: Io.Writer.Allocating = .init(fba.allocator());
        message.writeNotification(&aw.writer, "notifications/cancelled", types.CancelledNotificationParams{ .requestId = id, .reason = reason }) catch return;
        self.writeFrame(aw.written()) catch {};
    }

    fn readerLoop(self: *Client) void {
        self.router.readUntilEof(&self.stream_reader.interface, self.options.limits.stdio.max_line_bytes, self.options.on_notification, self.options.userdata);
        self.closed.store(true, .release);
        self.reader_done.store(true, .release);
        self.router.wakeAll();
    }
};

// ---------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------

/// Return an owned copy of `path`. On Windows a relative path becomes absolute, because the
/// Windows socket calls accept absolute paths only.
fn resolvePath(io: Io, gpa: Allocator, path: []const u8) (Allocator.Error || std.process.CurrentPathAllocError)![]u8 {
    if (builtin.os.tag != .windows or std.fs.path.isAbsolute(path)) return gpa.dupe(u8, path);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    defer gpa.free(cwd);
    return std.fs.path.resolve(gpa, &.{ cwd, path });
}

const PathState = enum { absent, socket, other };

/// Tell what is at `path` without a follow of symbolic links.
fn pathState(io: Io, path: []const u8) !PathState {
    if (builtin.os.tag == .windows) return windowsPathState(io, path);
    const st = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |e| switch (e) {
        error.FileNotFound => return .absent,
        else => |err| return err,
    };
    return if (st.kind == .unix_domain_socket) .socket else .other;
}

/// On Windows a socket file is a reparse point with the tag `IO_REPARSE_TAG_AF_UNIX`. The
/// std stat calls report it as an unknown kind, so the tag is read here.
fn windowsPathState(io: Io, path: []const u8) !PathState {
    const windows = std.os.windows;
    const file = Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch |e| switch (e) {
        error.FileNotFound => return .absent,
        error.IsDir => return .other,
        else => |err| return err,
    };
    defer file.close(io);
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    var info: windows.FILE.ATTRIBUTE_TAG_INFO = undefined;
    const status = windows.ntdll.NtQueryInformationFile(file.handle, &iosb, &info, @sizeOf(windows.FILE.ATTRIBUTE_TAG_INFO), .AttributeTag);
    if (status != .SUCCESS) return .other;
    const Tag = @typeInfo(windows.IO_REPARSE_TAG).@"struct".backing_integer.?;
    const af_unix: Tag = @bitCast(windows.IO_REPARSE_TAG.AF_UNIX);
    return if (@as(Tag, @bitCast(info.ReparseTag)) == af_unix) .socket else .other;
}

/// The longest socket path that the `sockaddr_un` of the target holds. The std check allows
/// 108 bytes on every POSIX target, but macOS and the BSD systems have 104 bytes.
pub const max_path_len: usize = switch (builtin.os.tag) {
    .windows => Io.net.UnixAddress.max_len,
    else => if (@hasDecl(std.posix.sockaddr, "un")) @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len else 0,
};

/// Make the socket address. A path that does not fit the `sockaddr_un` of the target gives
/// `error.NameTooLong`.
fn unixAddress(path: []const u8) error{NameTooLong}!Io.net.UnixAddress {
    if (path.len > max_path_len) return error.NameTooLong;
    return Io.net.UnixAddress.init(path);
}

/// Fail when a server accepts connections on the socket at `path`. A refused connection
/// means that the socket file is stale.
fn refuseLiveServer(io: Io, path: []const u8) error{ AddressInUse, AccessDenied, NameTooLong }!void {
    const address = try unixAddress(path);
    if (address.connect(io)) |stream| {
        stream.close(io);
        return error.AddressInUse;
    } else |e| switch (e) {
        error.AccessDenied, error.PermissionDenied => return error.AccessDenied,
        else => {},
    }
}

test "a socket path longer than sockaddr_un gives NameTooLong" {
    if (!supported) return error.SkipZigTest;
    const long = try std.testing.allocator.alloc(u8, max_path_len + 1);
    defer std.testing.allocator.free(long);
    @memset(long, 'a');
    try std.testing.expectError(error.NameTooLong, unixAddress(long));
    _ = try unixAddress(long[0..max_path_len]);
    if (builtin.os.tag.isDarwin()) try std.testing.expectEqual(104, max_path_len);
}
