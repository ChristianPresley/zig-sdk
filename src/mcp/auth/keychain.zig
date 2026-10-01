//! `KeychainTokenStorage` keeps the records of `OAuthClient` in the keychain of the host. It
//! has one backend for each system, and no backend needs a C library:
//!
//! - Windows: generic credentials of the Credential Manager (`advapi32`).
//! - macOS: generic password items of Keychain Services. The backend loads the Security and
//!   CoreFoundation frameworks at run time.
//! - Linux and the other POSIX systems: the Secret Service API on the D-Bus bus of the user,
//!   with a small D-Bus client of the SDK.
//!
//! `init` makes sure that the keychain answers. When the host has no keychain, `init` gives
//! `error.KeychainUnavailable`, and the application can use `FileTokenStorage`.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const token_storage = @import("token_storage.zig");
const TokenStorage = token_storage.TokenStorage;
const Key = token_storage.Key;
const Error = TokenStorage.Error;

/// The D-Bus client of the Secret Service backend.
pub const dbus = @import("keychain/dbus.zig");
/// The Secret Service backend. It works on each system with Unix sockets, so tests can use it
/// with a fake bus on any host.
pub const secret_service = @import("keychain/secret_service.zig");

/// The backend of the target.
pub const Backend = enum { credential_manager, keychain_services, secret_service };

pub const backend: Backend = switch (builtin.os.tag) {
    .windows => .credential_manager,
    .macos => .keychain_services,
    else => .secret_service,
};

const credential_manager = if (backend == .credential_manager) @import("keychain/credential_manager.zig") else struct {
    pub const Persist = enum { local_machine, enterprise };
};
const macos = if (backend == .keychain_services) @import("keychain/macos.zig") else struct {
    pub const Api = void;
};

pub const KeychainTokenStorage = struct {
    io: Io,
    gpa: Allocator,
    options: Options,
    /// The address of the bus of the Secret Service backend, owned.
    bus_address: ?[]u8 = null,
    /// The frameworks of the macOS backend.
    api: macos.Api,

    pub const Persist = credential_manager.Persist;

    pub const Options = struct {
        /// The name of the application. The items of two applications with two names stay
        /// apart. Tests use a name of their own.
        service: []const u8 = "zig-sdk",
        /// Linux and the other POSIX systems: the environment of the process. The backend
        /// reads `DBUS_SESSION_BUS_ADDRESS` from it, else it uses `$XDG_RUNTIME_DIR/bus`.
        environ_map: ?*const std.process.Environ.Map = null,
        /// The D-Bus address of the bus of the user. It has priority over `environ_map`.
        bus_address: ?[]const u8 = null,
        /// Secret Service: show the unlock prompt of the service for a locked collection.
        /// False gives `error.KeychainLocked`.
        allow_prompt: bool = true,
        /// Windows: `local_machine` keeps the credentials on this computer. `enterprise` also
        /// copies them to the other computers of the user in a domain.
        persist: Persist = .local_machine,
    };

    /// Find the keychain and make sure that it answers. A host without a keychain gives
    /// `error.KeychainUnavailable`.
    pub fn init(io: Io, gpa: Allocator, options: Options) Error!KeychainTokenStorage {
        var self: KeychainTokenStorage = .{ .io = io, .gpa = gpa, .options = options, .api = undefined };
        switch (backend) {
            .credential_manager => try credential_manager.probe(gpa, self.windowsOptions()),
            .keychain_services => {
                self.api = try macos.Api.load();
                errdefer self.api.close();
                try macos.probe(&self.api, options.service);
            },
            .secret_service => {
                self.bus_address = try busAddress(gpa, options);
                errdefer gpa.free(self.bus_address.?);
                var id_buf: [16]u8 = undefined;
                try secret_service.probe(io, gpa, self.secretOptions(&id_buf));
            },
        }
        return self;
    }

    pub fn deinit(self: *KeychainTokenStorage) void {
        switch (backend) {
            .keychain_services => self.api.close(),
            .secret_service => if (self.bus_address) |a| self.gpa.free(a),
            .credential_manager => {},
        }
    }

    pub fn storage(self: *KeychainTokenStorage) TokenStorage {
        return .{ .ptr = self, .vtable = &.{ .load = load, .save = save, .delete = delete } };
    }

    fn windowsOptions(self: *const KeychainTokenStorage) credential_manager.Options {
        return .{ .service = self.options.service, .persist = self.options.persist };
    }

    fn secretOptions(self: *const KeychainTokenStorage, id_buf: *[16]u8) secret_service.Options {
        return .{
            .address = self.bus_address.?,
            .user_id = dbus.userId(id_buf),
            .service = self.options.service,
            .allow_prompt = self.options.allow_prompt,
        };
    }

    fn load(ptr: *anyopaque, gpa: Allocator, key: Key) Error!?[]u8 {
        const self: *KeychainTokenStorage = @ptrCast(@alignCast(ptr));
        var id_buf: [16]u8 = undefined;
        return switch (backend) {
            .credential_manager => credential_manager.load(self.io, gpa, self.windowsOptions(), key),
            .keychain_services => macos.load(&self.api, gpa, self.options.service, key),
            .secret_service => secret_service.load(self.io, gpa, self.secretOptions(&id_buf), key),
        };
    }

    fn save(ptr: *anyopaque, key: Key, data: []const u8) Error!void {
        const self: *KeychainTokenStorage = @ptrCast(@alignCast(ptr));
        var id_buf: [16]u8 = undefined;
        return switch (backend) {
            .credential_manager => credential_manager.save(self.io, self.gpa, self.windowsOptions(), key, data),
            .keychain_services => macos.save(&self.api, self.options.service, key, data),
            .secret_service => secret_service.save(self.io, self.gpa, self.secretOptions(&id_buf), key, data),
        };
    }

    fn delete(ptr: *anyopaque, key: Key) Error!void {
        const self: *KeychainTokenStorage = @ptrCast(@alignCast(ptr));
        var id_buf: [16]u8 = undefined;
        return switch (backend) {
            .credential_manager => credential_manager.delete(self.io, self.gpa, self.windowsOptions(), key),
            .keychain_services => macos.delete(&self.api, self.options.service, key),
            .secret_service => secret_service.delete(self.io, self.gpa, self.secretOptions(&id_buf), key),
        };
    }
};

/// The bus address of the options, else of `DBUS_SESSION_BUS_ADDRESS`, else the socket `bus` in
/// `XDG_RUNTIME_DIR`. Owned by the caller.
fn busAddress(gpa: Allocator, options: KeychainTokenStorage.Options) Error![]u8 {
    if (options.bus_address) |a| return gpa.dupe(u8, a);
    const env = options.environ_map orelse return error.KeychainUnavailable;
    if (env.get("DBUS_SESSION_BUS_ADDRESS")) |a| if (a.len > 0) return gpa.dupe(u8, a);
    if (env.get("XDG_RUNTIME_DIR")) |dir| if (dir.len > 0) {
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        const w = &out.writer;
        w.writeAll("unix:path=") catch return error.OutOfMemory;
        // The D-Bus address format needs escapes for all bytes but these.
        for (dir) |c| {
            if (std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "-_/.\\*", c) != null) {
                w.writeByte(c) catch return error.OutOfMemory;
            } else {
                w.print("%{x:0>2}", .{c}) catch return error.OutOfMemory;
            }
        }
        w.writeAll("/bus") catch return error.OutOfMemory;
        return out.toOwnedSlice() catch error.OutOfMemory;
    };
    return error.KeychainUnavailable;
}

test {
    _ = dbus;
    _ = secret_service;
    _ = @import("keychain/keychain_test.zig");
}
