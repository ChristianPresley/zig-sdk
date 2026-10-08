//! The Secret Service backend of `KeychainTokenStorage` for Linux and the other POSIX systems.
//! It talks to the service `org.freedesktop.secrets` on the D-Bus bus of the user. Each
//! operation opens its own D-Bus connection and closes it at the end. Each answer of the bus,
//! of the service and of the user has a time limit (`Options.timeout`, `Options.prompt_timeout`).
//!
//! The items are in the collection with the alias `default`. An item has the attributes
//! `xdg:schema`, `service` and `account`. The `account` is the name of the key, a hash. The
//! secret is the serialized record.
//!
//! The backend transfers secrets with the algorithm `plain`, so the secrets go to the service
//! without encryption. This is acceptable, because the bus is a local Unix socket that only the
//! user and the administrator can reach. The other algorithm of the API encrypts the secret for
//! the transfer. That does not stop a peer on the bus, because the peer can ask for the secret.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const dbus = @import("dbus.zig");
const token_storage = @import("../token_storage.zig");
const Error = token_storage.TokenStorage.Error;
const Key = token_storage.Key;

const log = std.log.scoped(.mcp_keychain);

pub const bus_name = "org.freedesktop.secrets";
pub const service_path = "/org/freedesktop/secrets";
pub const service_interface = "org.freedesktop.Secret.Service";
pub const collection_interface = "org.freedesktop.Secret.Collection";
pub const item_interface = "org.freedesktop.Secret.Item";
pub const prompt_interface = "org.freedesktop.Secret.Prompt";
/// The `xdg:schema` attribute of the items.
pub const schema = "io.modelcontextprotocol.zig-sdk.TokenRecord";
pub const content_type = "application/json";

pub const Options = struct {
    /// The D-Bus address of the bus, for example `unix:path=/run/user/1000/bus`.
    address: []const u8,
    /// The user ID for the SASL mechanism `EXTERNAL`, as decimal digits.
    user_id: []const u8,
    /// The `service` attribute of the items.
    service: []const u8,
    /// Show the unlock prompt of the service for a locked collection.
    allow_prompt: bool = true,
    /// The time limit for each answer of the bus and of the service. Null waits without a
    /// limit. A service that does not answer in time gives `error.KeychainUnavailable`.
    ///
    /// Each wait with a limit runs in a task of its own. When `io` cannot run a task
    /// concurrently (`error.ConcurrencyUnavailable`), the backend can wait without a limit. The
    /// first such wait of the process writes a message to the log of the scope `mcp_dbus`.
    timeout: ?Io.Duration = dbus.default_timeout,
    /// The time limit for the answer of the user to a prompt of the service. Null waits without
    /// a limit. A prompt without an answer in time gives `error.KeychainLocked`.
    ///
    /// When `io` cannot run a task concurrently (`error.ConcurrencyUnavailable`), this wait
    /// also has no limit, as for `timeout`.
    prompt_timeout: ?Io.Duration = default_prompt_timeout,
};

/// The time limit for the answer of the user to a prompt that `Options` uses by default: 5
/// minutes.
pub const default_prompt_timeout: Io.Duration = .fromSeconds(5 * 60);

/// Make sure that the service answers and has a default collection.
pub fn probe(io: Io, gpa: Allocator, options: Options) Error!void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var op = try Op.begin(io, gpa, arena_state.allocator(), options);
    op.conn.close();
}

/// The secret of the item of `key`, or null.
pub fn load(io: Io, gpa: Allocator, options: Options, key: Key) Error!?[]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var op = try Op.begin(io, gpa, arena_state.allocator(), options);
    defer op.conn.close();
    const name = key.name();
    const items = try op.search(&name);
    if (items.len == 0) return null;
    try op.unlockCollection();
    var body: dbus.Encoder = .{ .gpa = gpa };
    defer body.deinit();
    try body.string(op.session);
    const reply = op.callOn(items[0], item_interface, "GetSecret", "o", body.written()) catch |e| return op.failed(e);
    defer reply.erase();
    if (!std.mem.eql(u8, reply.signature, "(oayays)")) return error.StorageFailed;
    var d = reply.decoder();
    const value = readSecret(&d) catch return error.StorageFailed;
    return try gpa.dupe(u8, value);
}

/// Create or replace the item of `key` with the secret `data`.
pub fn save(io: Io, gpa: Allocator, options: Options, key: Key, data: []const u8) Error!void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var op = try Op.begin(io, gpa, arena, options);
    defer op.conn.close();
    try op.unlockCollection();
    const name = key.name();
    const label = try std.fmt.allocPrint(arena, "{s}: MCP authorization for {s}", .{ options.service, key.resource });
    // A buffer that does not grow leaves no copy of the secret in freed memory.
    var body: dbus.Encoder = try .initCapacity(gpa, data.len + label.len + 1024);
    defer body.deinit();
    const properties = try body.beginArray(8);
    try body.beginStruct();
    try body.string("org.freedesktop.Secret.Item.Label");
    try body.signature("s");
    try body.string(label);
    try body.beginStruct();
    try body.string("org.freedesktop.Secret.Item.Attributes");
    try body.signature("a{ss}");
    try body.stringDict(&op.attributes(&name));
    body.endArray(properties);
    try body.beginStruct();
    try body.string(op.session);
    try body.bytes("");
    try body.bytes(data);
    try body.string(content_type);
    try body.boolean(true);
    const reply = op.callOn(op.collection, collection_interface, "CreateItem", "a{sv}(oayays)b", body.written()) catch |e| return op.failed(e);
    if (!std.mem.eql(u8, reply.signature, "oo")) return error.StorageFailed;
    var d = reply.decoder();
    _ = d.string() catch return error.StorageFailed;
    const prompt = d.string() catch return error.StorageFailed;
    if (!std.mem.eql(u8, prompt, "/")) try op.runPrompt(prompt);
}

/// Delete the items of `key`.
pub fn delete(io: Io, gpa: Allocator, options: Options, key: Key) Error!void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var op = try Op.begin(io, gpa, arena_state.allocator(), options);
    defer op.conn.close();
    const name = key.name();
    const items = try op.search(&name);
    if (items.len == 0) return;
    try op.unlockCollection();
    for (items) |item| {
        const reply = op.callOn(item, item_interface, "Delete", "", "") catch |e| return op.failed(e);
        if (!std.mem.eql(u8, reply.signature, "o")) return error.StorageFailed;
        var d = reply.decoder();
        const prompt = d.string() catch return error.StorageFailed;
        if (!std.mem.eql(u8, prompt, "/")) try op.runPrompt(prompt);
    }
}

/// The value of a `(oayays)` secret.
fn readSecret(d: *dbus.Decoder) dbus.Error![]const u8 {
    try d.beginStruct();
    _ = try d.string();
    _ = try d.bytes();
    const value = try d.bytes();
    _ = try d.string();
    return value;
}

/// An open D-Bus connection with a `plain` transfer and the default collection.
const Op = struct {
    conn: *dbus.Connection,
    arena: Allocator,
    options: Options,
    session: []const u8 = "",
    collection: []const u8 = "",

    fn begin(io: Io, gpa: Allocator, arena: Allocator, options: Options) Error!Op {
        const address = dbus.parseAddress(arena, options.address) catch |e| return unavailable(e);
        const conn = dbus.Connection.open(io, gpa, address, options.user_id, options.timeout) catch |e| return unavailable(e);
        errdefer conn.close();
        var op: Op = .{ .conn = conn, .arena = arena, .options = options };
        var body: dbus.Encoder = .{ .gpa = arena };
        try body.string("plain");
        try body.signature("s");
        try body.string("");
        const session = op.callOn(service_path, service_interface, "OpenSession", "sv", body.written()) catch |e| return op.unavailableCall(e);
        if (!std.mem.eql(u8, session.signature, "vo")) return error.KeychainUnavailable;
        var d = session.decoder();
        d.skip("v") catch return error.KeychainUnavailable;
        op.session = d.string() catch return error.KeychainUnavailable;

        var alias: dbus.Encoder = .{ .gpa = arena };
        try alias.string("default");
        const collection = op.callOn(service_path, service_interface, "ReadAlias", "s", alias.written()) catch |e| return op.unavailableCall(e);
        if (!std.mem.eql(u8, collection.signature, "o")) return error.KeychainUnavailable;
        var c = collection.decoder();
        op.collection = c.string() catch return error.KeychainUnavailable;
        if (std.mem.eql(u8, op.collection, "/")) {
            log.info("the Secret Service has no default collection", .{});
            return error.KeychainUnavailable;
        }
        return op;
    }

    fn callOn(self: *Op, path: []const u8, interface: []const u8, member: []const u8, sig: []const u8, body: []const u8) dbus.Error!dbus.Message {
        return self.conn.call(self.arena, .{ .destination = bus_name, .path = path, .interface = interface, .member = member, .signature = sig, .body = body });
    }

    fn attributes(self: *const Op, account: []const u8) [3][2][]const u8 {
        return .{ .{ "xdg:schema", schema }, .{ "service", self.options.service }, .{ "account", account } };
    }

    /// The items of the collection with the attributes of `account`.
    fn search(self: *Op, account: []const u8) Error![]const []const u8 {
        var body: dbus.Encoder = .{ .gpa = self.arena };
        try body.stringDict(&self.attributes(account));
        const reply = self.callOn(self.collection, collection_interface, "SearchItems", "a{ss}", body.written()) catch |e| return self.failed(e);
        if (!std.mem.eql(u8, reply.signature, "ao")) return error.StorageFailed;
        var d = reply.decoder();
        return d.objectPaths(self.arena) catch error.StorageFailed;
    }

    /// Unlock a locked collection. The service can show a prompt to the user.
    fn unlockCollection(self: *Op) Error!void {
        var body: dbus.Encoder = .{ .gpa = self.arena };
        try body.string(collection_interface);
        try body.string("Locked");
        const reply = self.conn.call(self.arena, .{ .destination = bus_name, .path = self.collection, .interface = "org.freedesktop.DBus.Properties", .member = "Get", .signature = "ss", .body = body.written() }) catch |e| return self.failed(e);
        var d = reply.decoder();
        const sig = d.signature() catch return error.StorageFailed;
        if (!std.mem.eql(u8, reply.signature, "v") or !std.mem.eql(u8, sig, "b")) return error.StorageFailed;
        if (!(d.boolean() catch return error.StorageFailed)) return;

        var objects: dbus.Encoder = .{ .gpa = self.arena };
        const mark = try objects.beginArray(4);
        try objects.string(self.collection);
        objects.endArray(mark);
        const unlock = self.callOn(service_path, service_interface, "Unlock", "ao", objects.written()) catch |e| return self.failed(e);
        if (!std.mem.eql(u8, unlock.signature, "aoo")) return error.StorageFailed;
        var u = unlock.decoder();
        const unlocked = u.objectPaths(self.arena) catch return error.StorageFailed;
        const prompt = u.string() catch return error.StorageFailed;
        if (!std.mem.eql(u8, prompt, "/")) return self.runPrompt(prompt);
        for (unlocked) |p| if (std.mem.eql(u8, p, self.collection)) return;
        return error.KeychainLocked;
    }

    /// Show a prompt of the service and wait for its `Completed` signal.
    fn runPrompt(self: *Op, prompt: []const u8) Error!void {
        if (!self.options.allow_prompt) return error.KeychainLocked;
        var rule: dbus.Encoder = .{ .gpa = self.arena };
        try rule.string(try std.fmt.allocPrint(self.arena, "type='signal',interface='{s}',member='Completed',path='{s}'", .{ prompt_interface, prompt }));
        _ = self.conn.call(self.arena, .{ .destination = "org.freedesktop.DBus", .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "AddMatch", .signature = "s", .body = rule.written() }) catch |e| return self.failed(e);
        var window: dbus.Encoder = .{ .gpa = self.arena };
        try window.string("");
        _ = self.callOn(prompt, prompt_interface, "Prompt", "s", window.written()) catch |e| return self.failed(e);
        const done = self.conn.waitSignal(self.arena, prompt, prompt_interface, "Completed", self.options.prompt_timeout) catch |e| switch (e) {
            error.Timeout => {
                log.info("the user did not answer the prompt of the Secret Service in the time limit", .{});
                return error.KeychainLocked;
            },
            else => return self.failed(e),
        };
        if (!std.mem.eql(u8, done.signature, "bv")) return error.StorageFailed;
        var d = done.decoder();
        if (d.boolean() catch return error.StorageFailed) return error.KeychainLocked;
    }

    /// An error of `OpenSession` or `ReadAlias`: the bus has no usable service.
    fn unavailableCall(self: *Op, e: dbus.Error) Error {
        if (e == error.CallFailed) log.info("the Secret Service is not available: {s}", .{self.conn.error_name orelse ""});
        return unavailable(e);
    }

    fn failed(self: *Op, e: dbus.Error) Error {
        switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            error.Timeout => {
                log.warn("the Secret Service did not answer in the time limit", .{});
                return error.KeychainUnavailable;
            },
            error.CallFailed => {
                const name = self.conn.error_name orelse "";
                if (std.mem.eql(u8, name, "org.freedesktop.Secret.Error.IsLocked")) return error.KeychainLocked;
                if (std.mem.eql(u8, name, "org.freedesktop.DBus.Error.ServiceUnknown")) return error.KeychainUnavailable;
                log.warn("the Secret Service refused a call: {s}", .{name});
                return error.StorageFailed;
            },
            else => {
                log.warn("the D-Bus connection failed: {t}", .{e});
                return error.StorageFailed;
            },
        }
    }
};

fn unavailable(e: dbus.Error) Error {
    switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        else => {
            log.info("no Secret Service on the bus: {t}", .{e});
            return error.KeychainUnavailable;
        },
    }
}
