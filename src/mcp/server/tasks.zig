//! The Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663): long tool calls that
//! the server turns into tasks. The server creates the task before it sends the
//! `CreateTaskResult`. The task runs in its own concurrent task and can wait for input.
//! The client reads it with `tasks/get`, answers with `tasks/update` and stops it with
//! `tasks/cancel`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const types = @import("../protocol/types.zig");
const errors = @import("../protocol/errors.zig");
const json = @import("../json.zig");
const Transport = @import("../transport/Transport.zig");

pub const extension_id = "io.modelcontextprotocol/tasks";

pub const Options = struct {
    /// How long a task stays readable after creation.
    ttl_ms: i64 = 600_000,
    /// The poll interval the server advises.
    poll_interval_ms: i64 = 1000,
    /// Tasks kept at the same time. Overflow: `-32603`.
    max_tasks: u32 = 1024,
};

/// How a tool relates to tasks. Set at registration.
pub const TaskSupport = enum {
    /// The tool never becomes a task.
    none,
    /// The tool can become a task when the client declared the extension.
    optional,
    /// The tool needs the extension. A client without it gets `-32021`.
    required,
};

pub const Status = enum { working, input_required, completed, failed, cancelled };

/// The result of `tools/call` when the server created a task (`Result & Task`).
pub const CreateTaskResult = struct {
    _meta: ?types.ResultMetaObject = null,
    resultType: []const u8 = "task",
    taskId: []const u8,
    status: []const u8,
    createdAt: []const u8,
    lastUpdatedAt: []const u8,
    ttlMs: i64,
    pollIntervalMs: ?i64 = null,
};

/// The result of `tasks/get`.
pub const DetailedTask = struct {
    _meta: ?types.ResultMetaObject = null,
    resultType: []const u8 = types.result_type_complete,
    taskId: []const u8,
    status: []const u8,
    createdAt: []const u8,
    lastUpdatedAt: []const u8,
    ttlMs: i64,
    pollIntervalMs: ?i64 = null,
    statusMessage: ?[]const u8 = null,
    inputRequests: ?Value = null,
    result: ?Value = null,
    @"error": ?types.Error = null,
};

pub const GetParams = struct {
    _meta: types.RequestMetaObject,
    taskId: []const u8,
};

pub const UpdateParams = struct {
    _meta: types.RequestMetaObject,
    taskId: []const u8,
    inputResponses: ?types.InputResponses = null,
};

pub const CancelParams = struct {
    _meta: types.RequestMetaObject,
    taskId: []const u8,
};

/// One task. The `lock` guards every field except `cancel`.
pub const Task = struct {
    arena_state: std.heap.ArenaAllocator,
    id: []const u8,
    tool: []const u8,
    /// The `tools/call` params that created the task, copied into the task arena.
    params: Value,
    kind: Transport.Kind,
    created_ms: i64,
    updated_ms: i64,
    ttl_ms: i64,
    status: Status = .working,
    /// The pending input requests (an object keyed by request key), or null.
    input_requests: ?Value = null,
    /// The answers collected so far, keyed by request key.
    input_responses: std.json.ObjectMap = .empty,
    /// The `CallToolResult` as JSON, once completed.
    result: ?Value = null,
    err: ?types.Error = null,
    cancel: Transport.CancelToken = .{},
    future: ?Io.Future(void) = null,
    lock: Io.Mutex = .init,

    pub fn arena(self: *Task) Allocator {
        return self.arena_state.allocator();
    }

    pub fn isTerminal(self: *const Task) bool {
        return switch (self.status) {
            .completed, .failed, .cancelled => true,
            .working, .input_required => false,
        };
    }
};

/// Keeps the tasks of one server.
pub const Store = struct {
    gpa: Allocator,
    io: Io,
    options: Options,
    tasks: std.StringHashMapUnmanaged(*Task) = .empty,
    lock: Io.Mutex = .init,

    pub fn init(gpa: Allocator, io: Io, options: Options) Store {
        return .{ .gpa = gpa, .io = io, .options = options };
    }

    /// Cancel every task that runs, wait for it, and free everything.
    pub fn deinit(self: *Store) void {
        var it = self.tasks.valueIterator();
        while (it.next()) |task_ptr| {
            const task = task_ptr.*;
            task.cancel.cancel(self.io, "server shutdown");
            if (task.future) |*f| {
                _ = f.cancel(self.io);
                task.future = null;
            }
            task.arena_state.deinit();
            self.gpa.destroy(task);
        }
        self.tasks.deinit(self.gpa);
    }

    /// Create a task for a `tools/call`. The store copies the params into the task arena.
    pub fn create(self: *Store, tool: []const u8, params: Value, kind: Transport.Kind) error{ OutOfMemory, TooManyTasks, EntropyUnavailable }!*Task {
        const task = try self.gpa.create(Task);
        errdefer self.gpa.destroy(task);
        task.* = .{
            .arena_state = .init(self.gpa),
            .id = undefined,
            .tool = undefined,
            .params = undefined,
            .kind = kind,
            .created_ms = nowMs(self.io),
            .updated_ms = 0,
            .ttl_ms = self.options.ttl_ms,
        };
        errdefer task.arena_state.deinit();
        const arena = task.arena();
        task.updated_ms = task.created_ms;
        var raw: [16]u8 = undefined;
        self.io.randomSecure(&raw) catch return error.EntropyUnavailable;
        task.id = try std.fmt.allocPrint(arena, "{x}", .{raw});
        task.tool = try arena.dupe(u8, tool);
        const text = try json.writeAlloc(arena, params);
        task.params = json.parseTree(arena, text) catch return error.OutOfMemory;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.sweepLocked();
        if (self.tasks.count() >= self.options.max_tasks) return error.TooManyTasks;
        try self.tasks.put(self.gpa, task.id, task);
        return task;
    }

    /// Find a task that is not expired.
    pub fn get(self: *Store, id: []const u8) ?*Task {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.sweepLocked();
        return self.tasks.get(id);
    }

    /// Drop terminal tasks whose lifetime ended. A task never expires before its `ttlMs`.
    fn sweepLocked(self: *Store) void {
        const now = nowMs(self.io);
        var expired: std.ArrayList([]const u8) = .empty;
        defer expired.deinit(self.gpa);
        var it = self.tasks.iterator();
        while (it.next()) |kv| {
            const task = kv.value_ptr.*;
            if (task.isTerminal() and task.future == null and now - task.created_ms > task.ttl_ms) {
                expired.append(self.gpa, kv.key_ptr.*) catch return;
            }
        }
        for (expired.items) |id| {
            const task = self.tasks.fetchRemove(id).?.value;
            task.arena_state.deinit();
            self.gpa.destroy(task);
        }
    }
};

pub fn nowMs(io: Io) i64 {
    const ts = Io.Clock.Timestamp.now(io, .real).raw;
    return @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_ms));
}

/// RFC 3339 UTC timestamp with milliseconds, for `createdAt` and `lastUpdatedAt`.
pub fn formatTimestamp(arena: Allocator, ms: i64) Allocator.Error![]u8 {
    const secs = @divFloor(ms, 1000);
    const millis: u64 = @intCast(@mod(ms, 1000));
    const days = @divFloor(secs, std.time.s_per_day);
    const rem: u64 = @intCast(@mod(secs, std.time.s_per_day));
    const date = civilFromDays(days);
    const year: u64 = @intCast(@max(date.year, 0));
    return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year, date.month, date.day, rem / 3600, (rem % 3600) / 60, rem % 60, millis,
    });
}

const Civil = struct { year: i64, month: u8, day: u8 };

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn civilFromDays(days: i64) Civil {
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe: i64 = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d: u8 = @intCast(doy - @divFloor(153 * mp + 2, 5) + 1);
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    return .{ .year = if (m <= 2) y + 1 else y, .month = m, .day = d };
}

/// The `requiredCapabilities` error for a client that did not declare the extension.
pub fn missingExtensionError(arena: Allocator) Allocator.Error!errors.RpcError {
    var ext: std.json.ObjectMap = .empty;
    try ext.put(arena, extension_id, .{ .object = .empty });
    var caps: std.json.ObjectMap = .empty;
    try caps.put(arena, "extensions", .{ .object = ext });
    var data: std.json.ObjectMap = .empty;
    try data.put(arena, "requiredCapabilities", .{ .object = caps });
    return .{
        .code = errors.Code.missing_required_client_capability.int(),
        .message = "Missing required client capability: the io.modelcontextprotocol/tasks extension",
        .data = .{ .object = data },
    };
}

test "timestamps" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectEqualStrings("1970-01-01T00:00:00.000Z", try formatTimestamp(arena, 0));
    try std.testing.expectEqualStrings("2026-07-28T12:34:56.789Z", try formatTimestamp(arena, 1785242096789));
    try std.testing.expectEqualStrings("2000-02-29T23:59:59.000Z", try formatTimestamp(arena, 951868799000));
}
