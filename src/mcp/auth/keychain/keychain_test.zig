//! Tests of the keychain backends. A fake bus with a fake Secret Service runs in the process on
//! a Unix socket in a private temporary directory. It tests the D-Bus client, the SASL exchange
//! and the Secret Service backend on each host with Unix sockets. The last test uses the keychain
//! of the host when the host has one, and removes its items at the end.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mcp = @import("../../../mcp.zig");
const keychain = @import("../keychain.zig");
const token_storage = @import("../token_storage.zig");
const dbus = keychain.dbus;
const secret_service = keychain.secret_service;

const gpa = std.testing.allocator;
const test_user = "1000";
const unique_name = ":1.42";
const session_path = "/org/freedesktop/secrets/session/s1";
const collection_path = "/org/freedesktop/secrets/collection/login";
const prompt_path = "/org/freedesktop/secrets/prompt/p1";

const Item = struct {
    path: []u8,
    label: []u8,
    attributes: [][2][]u8,
    secret: []u8,

    fn deinit(self: Item) void {
        gpa.free(self.path);
        gpa.free(self.label);
        for (self.attributes) |a| {
            gpa.free(a[0]);
            gpa.free(a[1]);
        }
        gpa.free(self.attributes);
        std.crypto.secureZero(u8, self.secret);
        gpa.free(self.secret);
    }

    fn matches(self: Item, wanted: []const [2][]const u8) bool {
        for (wanted) |w| {
            const found = for (self.attributes) |a| {
                if (std.mem.eql(u8, a[0], w[0]) and std.mem.eql(u8, a[1], w[1])) break true;
            } else false;
            if (!found) return false;
        }
        return true;
    }

    fn attribute(self: Item, name: []const u8) ?[]const u8 {
        for (self.attributes) |a| if (std.mem.eql(u8, a[0], name)) return a[1];
        return null;
    }
};

/// A bus with `org.freedesktop.DBus` and a Secret Service that keeps its items in memory.
const FakeBus = struct {
    io: Io,
    tmp: std.testing.TmpDir,
    socket_path: []u8,
    address: []u8,
    listener: Io.net.Server,
    future: Io.Future(void),
    stopping: std.atomic.Value(bool) = .init(false),
    lock: Io.Mutex = .init,

    // Behaviour.
    has_service: bool = true,
    has_default: bool = true,
    locked: bool = false,
    dismiss_prompt: bool = false,

    // State.
    items: std.ArrayList(Item) = .empty,
    next_item: u32 = 1,
    prompts: u32 = 0,
    /// The first problem that the fake found in a request.
    failure: ?[]const u8 = null,

    fn start(self: *FakeBus) !void {
        const io = std.testing.io;
        self.* = .{ .io = io, .tmp = std.testing.tmpDir(.{}), .socket_path = undefined, .address = undefined, .listener = undefined, .future = undefined };
        errdefer self.tmp.cleanup();
        const dir = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/run", .{self.tmp.sub_path});
        defer gpa.free(dir);
        try mcp.transport.unix.createPrivateDirectory(io, dir);
        // Windows connects to absolute socket paths only.
        self.socket_path = if (builtin.os.tag == .windows) blk: {
            const cwd = try std.process.currentPathAlloc(io, gpa);
            defer gpa.free(cwd);
            break :blk try std.fs.path.resolve(gpa, &.{ cwd, dir, "bus" });
        } else try std.fmt.allocPrint(gpa, "{s}/bus", .{dir});
        errdefer gpa.free(self.socket_path);
        self.address = try std.fmt.allocPrint(gpa, "unix:path={s}", .{self.socket_path});
        errdefer gpa.free(self.address);
        const ua = try Io.net.UnixAddress.init(self.socket_path);
        self.listener = try ua.listen(io, .{});
        self.future = try io.concurrent(acceptLoop, .{self});
    }

    fn stop(self: *FakeBus) void {
        mcp.util.wake.cancelUnixAcceptLoop(self.io, &self.future, self.socket_path, &self.stopping);
        self.listener.deinit(self.io);
        for (self.items.items) |i| i.deinit();
        self.items.deinit(gpa);
        gpa.free(self.address);
        gpa.free(self.socket_path);
        self.tmp.cleanup();
    }

    fn fail(self: *FakeBus, why: []const u8) void {
        if (self.failure == null) self.failure = why;
    }

    fn options(self: *FakeBus) secret_service.Options {
        return .{ .address = self.address, .user_id = test_user, .service = "zig-sdk-test" };
    }

    fn acceptLoop(self: *FakeBus) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch |e| switch (e) {
                error.Canceled => return,
                else => continue,
            };
            defer stream.close(self.io);
            if (self.stopping.load(.acquire)) return;
            self.serve(stream) catch {};
        }
    }

    fn serve(self: *FakeBus, stream: Io.net.Stream) !void {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var read_buf: [8192]u8 = undefined;
        var write_buf: [8192]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        var writer = stream.writer(self.io, &write_buf);
        const r = &reader.interface;
        const w = &writer.interface;
        if ((try r.takeByte()) != 0) return self.fail("no zero byte before the authentication");
        const auth = try r.takeDelimiterInclusive('\n');
        // The user ID "1000" in hexadecimal digits.
        if (!std.mem.eql(u8, auth, "AUTH EXTERNAL 31303030\r\n")) {
            try w.writeAll("REJECTED EXTERNAL\r\n");
            return w.flush();
        }
        try w.writeAll("OK 0123456789abcdef0123456789abcdef\r\n");
        try w.flush();
        if (!std.mem.eql(u8, try r.takeDelimiterInclusive('\n'), "BEGIN\r\n")) return self.fail("no BEGIN");
        var serial: u32 = 0;
        while (true) {
            const m = dbus.readMessage(arena, r) catch return;
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            try self.handle(arena, w, &serial, m);
            try w.flush();
        }
    }

    fn send(w: *Io.Writer, serial: *u32, message: dbus.Outgoing) !void {
        serial.* += 1;
        var m = message;
        m.destination = unique_name;
        try dbus.writeMessage(gpa, w, serial.*, m);
    }

    fn reply(w: *Io.Writer, serial: *u32, to: dbus.Message, sig: []const u8, body: []const u8) !void {
        try send(w, serial, .{ .kind = .method_return, .reply_serial = to.serial, .sender = to.destination, .signature = sig, .body = body });
    }

    fn replyError(w: *Io.Writer, serial: *u32, to: dbus.Message, name: []const u8) !void {
        try send(w, serial, .{ .kind = .error_reply, .reply_serial = to.serial, .error_name = name, .sender = to.destination });
    }

    fn handle(self: *FakeBus, arena: Allocator, w: *Io.Writer, serial: *u32, m: dbus.Message) !void {
        if (m.kind != .method_call) return self.fail("not a method call");
        const member = m.member orelse return self.fail("no member");
        var body: dbus.Encoder = .{ .gpa = arena };
        var d = m.decoder();
        if (std.mem.eql(u8, m.destination orelse "", "org.freedesktop.DBus")) {
            if (std.mem.eql(u8, member, "Hello")) {
                try body.string(unique_name);
                try reply(w, serial, m, "s", body.written());
                // The real bus sends this signal after the reply. The client keeps it.
                var name: dbus.Encoder = .{ .gpa = arena };
                try name.string(unique_name);
                return send(w, serial, .{ .kind = .signal, .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "NameAcquired", .signature = "s", .body = name.written() });
            }
            if (std.mem.eql(u8, member, "AddMatch")) return reply(w, serial, m, "", "");
            return replyError(w, serial, m, "org.freedesktop.DBus.Error.UnknownMethod");
        }
        if (!std.mem.eql(u8, m.destination orelse "", secret_service.bus_name)) return self.fail("unknown destination");
        if (!self.has_service) return replyError(w, serial, m, "org.freedesktop.DBus.Error.ServiceUnknown");

        if (std.mem.eql(u8, member, "OpenSession")) {
            if (!std.mem.eql(u8, m.signature, "sv")) return self.fail("OpenSession signature");
            if (!std.mem.eql(u8, try d.string(), "plain")) return replyError(w, serial, m, "org.freedesktop.DBus.Error.NotSupported");
            try body.signature("s");
            try body.string("");
            try body.string(session_path);
            return reply(w, serial, m, "vo", body.written());
        }
        if (std.mem.eql(u8, member, "ReadAlias")) {
            if (!std.mem.eql(u8, try d.string(), "default")) return self.fail("alias");
            try body.string(if (self.has_default) collection_path else "/");
            return reply(w, serial, m, "o", body.written());
        }
        if (std.mem.eql(u8, member, "Get")) {
            if (!std.mem.eql(u8, try d.string(), secret_service.collection_interface) or !std.mem.eql(u8, try d.string(), "Locked")) return self.fail("property");
            try body.signature("b");
            try body.boolean(self.locked);
            return reply(w, serial, m, "v", body.written());
        }
        if (std.mem.eql(u8, member, "Unlock")) {
            const objects = try d.objectPaths(arena);
            const mark = try body.beginArray(4);
            if (!self.locked) for (objects) |o| try body.string(o);
            body.endArray(mark);
            try body.string(if (self.locked) prompt_path else "/");
            return reply(w, serial, m, "aoo", body.written());
        }
        if (std.mem.eql(u8, member, "Prompt")) {
            if (!std.mem.eql(u8, m.path orelse "", prompt_path)) return self.fail("prompt path");
            self.prompts += 1;
            try reply(w, serial, m, "", "");
            if (!self.dismiss_prompt) self.locked = false;
            try body.boolean(self.dismiss_prompt);
            try body.signature("ao");
            const mark = try body.beginArray(4);
            body.endArray(mark);
            return send(w, serial, .{ .kind = .signal, .path = prompt_path, .interface = secret_service.prompt_interface, .member = "Completed", .signature = "bv", .body = body.written() });
        }
        if (std.mem.eql(u8, member, "SearchItems")) {
            const wanted = try readStringDict(arena, &d);
            const mark = try body.beginArray(4);
            for (self.items.items) |i| if (i.matches(wanted)) try body.string(i.path);
            body.endArray(mark);
            return reply(w, serial, m, "ao", body.written());
        }
        if (std.mem.eql(u8, member, "CreateItem")) {
            if (self.locked) return replyError(w, serial, m, "org.freedesktop.Secret.Error.IsLocked");
            if (!std.mem.eql(u8, m.signature, "a{sv}(oayays)b")) return self.fail("CreateItem signature");
            var label: []const u8 = "";
            var attributes: []const [2][]const u8 = &.{};
            const end = try d.beginArray(8);
            while (d.pos < end) {
                try d.beginStruct();
                const name = try d.string();
                const sig = try d.signature();
                if (std.mem.eql(u8, name, "org.freedesktop.Secret.Item.Label") and std.mem.eql(u8, sig, "s")) {
                    label = try d.string();
                } else if (std.mem.eql(u8, name, "org.freedesktop.Secret.Item.Attributes") and std.mem.eql(u8, sig, "a{ss}")) {
                    attributes = try readStringDict(arena, &d);
                } else try d.skip(sig);
            }
            try d.beginStruct();
            if (!std.mem.eql(u8, try d.string(), session_path)) return self.fail("session of the secret");
            _ = try d.bytes();
            const secret = try d.bytes();
            if (!std.mem.eql(u8, try d.string(), secret_service.content_type)) return self.fail("content type");
            if (!try d.boolean()) return self.fail("replace");
            defer m.erase();
            const path = try self.put(label, attributes, secret);
            try body.string(path);
            try body.string("/");
            return reply(w, serial, m, "oo", body.written());
        }
        if (std.mem.eql(u8, member, "GetSecret")) {
            if (self.locked) return replyError(w, serial, m, "org.freedesktop.Secret.Error.IsLocked");
            if (!std.mem.eql(u8, try d.string(), session_path)) return self.fail("session of GetSecret");
            const item = self.find(m.path orelse "") orelse return replyError(w, serial, m, "org.freedesktop.Secret.Error.NoSuchObject");
            try body.beginStruct();
            try body.string(session_path);
            try body.bytes("");
            try body.bytes(item.secret);
            try body.string(secret_service.content_type);
            return reply(w, serial, m, "(oayays)", body.written());
        }
        if (std.mem.eql(u8, member, "Delete")) {
            for (self.items.items, 0..) |i, n| if (std.mem.eql(u8, i.path, m.path orelse "")) {
                self.items.orderedRemove(n).deinit();
                try body.string("/");
                return reply(w, serial, m, "o", body.written());
            };
            return replyError(w, serial, m, "org.freedesktop.Secret.Error.NoSuchObject");
        }
        return replyError(w, serial, m, "org.freedesktop.DBus.Error.UnknownMethod");
    }

    fn find(self: *FakeBus, path: []const u8) ?Item {
        for (self.items.items) |i| if (std.mem.eql(u8, i.path, path)) return i;
        return null;
    }

    /// Replace the item with the same attributes, or add a new item.
    fn put(self: *FakeBus, label: []const u8, attributes: []const [2][]const u8, secret: []const u8) ![]const u8 {
        for (self.items.items, 0..) |i, n| if (i.matches(attributes) and i.attributes.len == attributes.len) {
            self.items.orderedRemove(n).deinit();
            break;
        };
        const owned = try gpa.alloc([2][]u8, attributes.len);
        for (attributes, owned) |a, *o| o.* = .{ try gpa.dupe(u8, a[0]), try gpa.dupe(u8, a[1]) };
        const path = try std.fmt.allocPrint(gpa, "{s}/i{d}", .{ collection_path, self.next_item });
        self.next_item += 1;
        try self.items.append(gpa, .{ .path = path, .label = try gpa.dupe(u8, label), .attributes = owned, .secret = try gpa.dupe(u8, secret) });
        return path;
    }
};

fn readStringDict(arena: Allocator, d: *dbus.Decoder) ![]const [2][]const u8 {
    var out: std.ArrayList([2][]const u8) = .empty;
    const end = try d.beginArray(8);
    while (d.pos < end) {
        try d.beginStruct();
        try out.append(arena, .{ try d.string(), try d.string() });
    }
    return out.items;
}

const test_key: token_storage.Key = .{ .issuer = "https://as.example", .resource = "https://mcp.example/mcp", .client = "client-1" };

test "d-bus client authenticates with EXTERNAL and keeps a signal of the bus" {
    if (!Io.net.has_unix_sockets) return error.SkipZigTest;
    var bus: FakeBus = undefined;
    try bus.start();
    defer bus.stop();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const address = try dbus.parseAddress(arena_state.allocator(), bus.address);

    const conn = try dbus.Connection.open(std.testing.io, gpa, address, test_user);
    try std.testing.expectEqualStrings(unique_name, conn.unique_name.?);
    // The `NameAcquired` signal comes after the reply of `Hello`. The next call keeps it.
    _ = try conn.call(arena_state.allocator(), .{ .destination = "org.freedesktop.DBus", .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "AddMatch", .signature = "s", .body = &.{ 0, 0, 0, 0, 0 } });
    const signal = try conn.waitSignal(arena_state.allocator(), "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameAcquired");
    var d = signal.decoder();
    try std.testing.expectEqualStrings(unique_name, try d.string());
    // An unknown method gives an error reply with its name.
    try std.testing.expectError(error.CallFailed, conn.call(arena_state.allocator(), .{ .destination = "org.freedesktop.DBus", .path = "/", .member = "Nothing" }));
    try std.testing.expectEqualStrings("org.freedesktop.DBus.Error.UnknownMethod", conn.error_name.?);
    conn.close();

    // The bus refuses another user.
    try std.testing.expectError(error.AuthenticationFailed, dbus.Connection.open(std.testing.io, gpa, address, "1001"));
    try std.testing.expect(bus.failure == null);
}

test "secret service backend keeps, replaces and deletes a record on a fake bus" {
    if (!Io.net.has_unix_sockets) return error.SkipZigTest;
    const io = std.testing.io;
    var bus: FakeBus = undefined;
    try bus.start();
    defer bus.stop();
    const options = bus.options();

    try secret_service.probe(io, gpa, options);
    try std.testing.expect((try secret_service.load(io, gpa, options, test_key)) == null);
    try secret_service.save(io, gpa, options, test_key, "{\"record\":1}");
    try secret_service.save(io, gpa, options, test_key, "{\"record\":2}");
    const data = (try secret_service.load(io, gpa, options, test_key)).?;
    defer gpa.free(data);
    try std.testing.expectEqualStrings("{\"record\":2}", data);
    try std.testing.expectEqual(1, bus.items.items.len);
    const item = bus.items.items[0];
    try std.testing.expectEqualStrings("zig-sdk-test", item.attribute("service").?);
    try std.testing.expectEqualStrings(&test_key.name(), item.attribute("account").?);
    try std.testing.expectEqualStrings(secret_service.schema, item.attribute("xdg:schema").?);
    try std.testing.expect(std.mem.indexOf(u8, item.label, test_key.resource) != null);

    // A record of another service is a separate item.
    var other = options;
    other.service = "zig-sdk-test-other";
    try std.testing.expect((try secret_service.load(io, gpa, other, test_key)) == null);

    try secret_service.delete(io, gpa, options, test_key);
    try secret_service.delete(io, gpa, options, test_key);
    try std.testing.expect((try secret_service.load(io, gpa, options, test_key)) == null);
    try std.testing.expectEqual(0, bus.items.items.len);
    try std.testing.expect(bus.failure == null);
}

test "secret service backend unlocks a locked collection with the prompt of the service" {
    if (!Io.net.has_unix_sockets) return error.SkipZigTest;
    const io = std.testing.io;
    var bus: FakeBus = undefined;
    try bus.start();
    defer bus.stop();
    var options = bus.options();

    bus.locked = true;
    try secret_service.save(io, gpa, options, test_key, "{\"record\":1}");
    try std.testing.expectEqual(1, bus.prompts);
    try std.testing.expect(!bus.locked);

    // The user dismisses the prompt.
    bus.locked = true;
    bus.dismiss_prompt = true;
    try std.testing.expectError(error.KeychainLocked, secret_service.load(io, gpa, options, test_key));
    try std.testing.expectEqual(2, bus.prompts);
    // Without prompts, a locked collection gives `KeychainLocked` at once.
    options.allow_prompt = false;
    try std.testing.expectError(error.KeychainLocked, secret_service.load(io, gpa, options, test_key));
    try std.testing.expectEqual(2, bus.prompts);
    try std.testing.expect(bus.failure == null);
}

test "secret service backend reports a missing bus, service or collection as unavailable" {
    if (!Io.net.has_unix_sockets) return error.SkipZigTest;
    const io = std.testing.io;
    var bus: FakeBus = undefined;
    try bus.start();
    defer bus.stop();
    var options = bus.options();

    bus.has_default = false;
    try std.testing.expectError(error.KeychainUnavailable, secret_service.probe(io, gpa, options));
    bus.has_service = false;
    try std.testing.expectError(error.KeychainUnavailable, secret_service.probe(io, gpa, options));
    options.user_id = "1001";
    try std.testing.expectError(error.KeychainUnavailable, secret_service.probe(io, gpa, options));
    options.address = "tcp:host=localhost,port=1";
    try std.testing.expectError(error.KeychainUnavailable, secret_service.probe(io, gpa, options));
    // On Windows the std library prints a stack trace for a refused connection, so only POSIX
    // systems run this check.
    if (builtin.os.tag != .windows) {
        const missing = try std.fmt.allocPrint(gpa, "{s}-missing", .{bus.address});
        defer gpa.free(missing);
        options.address = missing;
        try std.testing.expectError(error.KeychainUnavailable, secret_service.probe(io, gpa, options));
    }

    // The options of the storage: no bus address and no environment.
    if (keychain.backend == .secret_service) {
        try std.testing.expectError(error.KeychainUnavailable, keychain.KeychainTokenStorage.init(io, gpa, .{}));
    }
}

test "keychain token storage keeps a large record in the keychain of this host" {
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(gpa);
    defer env.deinit();
    // A name of its own, so the test touches no item of a real application.
    var random: [6]u8 = undefined;
    io.random(&random);
    var service_buf: [32]u8 = undefined;
    const service = try std.fmt.bufPrint(&service_buf, "zig-sdk-test-{s}", .{&std.fmt.bytesToHex(random, .lower)});
    var storage = keychain.KeychainTokenStorage.init(io, gpa, .{ .service = service, .environ_map = &env, .allow_prompt = false }) catch |e| switch (e) {
        error.KeychainUnavailable, error.KeychainLocked => return error.SkipZigTest,
        else => return e,
    };
    defer storage.deinit();
    const s = storage.storage();
    defer s.delete(test_key) catch {};

    // A made-up token of 6000 bytes. The Windows backend splits it into three chunks.
    const big = try gpa.alloc(u8, 6000);
    defer gpa.free(big);
    for (big, 0..) |*c, i| c.* = "abcdefghijklmnopqrstuvwxyz0123456789"[i % 36];
    const record: token_storage.Record = .{
        .registration = .{ .client_id = "client-1", .client_secret = "made-up-secret", .auth_method = .client_secret_post },
        .access_token = big,
        .expires_at = 1_700_000_000,
        .refresh_token = "made-up-refresh-token",
        .scopes = &.{"mcp:read"},
    };
    // A locked keychain cannot take the record without a prompt, and the test shows none.
    s.save(gpa, test_key, record) catch |e| switch (e) {
        error.KeychainLocked, error.KeychainUnavailable => return error.SkipZigTest,
        else => return e,
    };
    var loaded = (try s.load(gpa, test_key)).?;
    defer loaded.deinit(gpa);
    try std.testing.expectEqualStrings(big, loaded.access_token.?);
    try std.testing.expectEqualStrings("made-up-secret", loaded.registration.?.client_secret.?);

    // A smaller record replaces it, and the old chunks go away.
    var small = record;
    small.access_token = "made-up-access-token";
    try s.save(gpa, test_key, small);
    var again = (try s.load(gpa, test_key)).?;
    defer again.deinit(gpa);
    try std.testing.expectEqualStrings("made-up-access-token", again.access_token.?);
    if (keychain.backend == .credential_manager) {
        const cm = @import("credential_manager.zig");
        const target = try cm.targetName(gpa, service, &test_key.name(), 1);
        defer gpa.free(target);
        try std.testing.expect((try cm.readTarget(gpa, target)) == null);
    }

    try s.delete(test_key);
    try std.testing.expect((try s.load(gpa, test_key)) == null);
}
