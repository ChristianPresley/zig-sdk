//! Token storage for `OAuthClient`. A storage keeps one record for each key. The key is the
//! issuer of the authorization server, the resource and the identity of the client. The record
//! has the client registration, the tokens and the granted scopes. Thus a new process of the
//! application can use the tokens of an earlier process without a new authorization.
//!
//! `TokenStorage` is an interface. `MemoryTokenStorage` keeps the records in memory, and
//! `FileTokenStorage` keeps them encrypted in files. `KeychainTokenStorage` in `keychain.zig`
//! keeps them in the keychain of the host. The interface gives each implementation the
//! serialized record, a versioned JSON text. Both sides erase the buffers with secrets after use.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const socket_dir = @import("../transport/socket_dir.zig");
const windows_acl = if (builtin.os.tag == .windows) @import("../transport/windows_acl.zig") else struct {};

const log = std.log.scoped(.mcp_auth);

/// How the client authenticates at the token endpoint.
pub const AuthMethod = enum { client_secret_basic, client_secret_post, none };

/// The key of a record.
pub const Key = struct {
    /// The `issuer` identifier of the authorization server.
    issuer: []const u8,
    /// The resource indicator of the tokens (RFC 8707).
    resource: []const u8,
    /// The identity of the client: a client ID, a client ID metadata document URL, or a name
    /// that the application selects.
    client: []const u8,

    /// A SHA-256 hash of the three parts. The storages use it as the name of a record.
    pub fn digest(self: Key) [32]u8 {
        var h: Sha256 = .init(.{});
        h.update("zig-sdk token record key 1");
        for ([_][]const u8{ self.issuer, self.resource, self.client }) |part| {
            var len: [8]u8 = undefined;
            std.mem.writeInt(u64, &len, part.len, .little);
            h.update(&len);
            h.update(part);
        }
        return h.finalResult();
    }

    /// The digest as 64 lowercase hexadecimal digits.
    pub fn name(self: Key) [64]u8 {
        return std.fmt.bytesToHex(self.digest(), .lower);
    }
};

/// The data of one key. The slices of a record from `TokenStorage.load` belong to the record.
/// Free them with `deinit`. A record for `TokenStorage.save` can borrow its slices.
pub const Record = struct {
    /// The client registration. Null when the client has none.
    registration: ?Registration = null,
    access_token: ?[]const u8 = null,
    /// The expiry of the access token in Unix seconds. Null when the server gave no expiry.
    expires_at: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    /// The scopes that the authorization server granted.
    scopes: []const []const u8 = &.{},
    /// The access token is DPoP-bound.
    dpop_bound: bool = false,
    /// The JWK thumbprint of the DPoP key of the token request. Null when the request had no
    /// proof. A DPoP-bound token works only with this key.
    dpop_jkt: ?[]const u8 = null,

    pub const Registration = struct {
        client_id: []const u8,
        client_secret: ?[]const u8 = null,
        auth_method: AuthMethod = .none,
    };

    /// The version of the serialized record.
    pub const version = 1;

    /// The JSON form. The parser ignores unknown members.
    const Wire = struct {
        version: u32,
        issuer: []const u8,
        resource: []const u8,
        client: []const u8,
        registration: ?struct {
            client_id: []const u8,
            client_secret: ?[]const u8 = null,
            auth_method: AuthMethod = .none,
        } = null,
        access_token: ?[]const u8 = null,
        expires_at: ?i64 = null,
        refresh_token: ?[]const u8 = null,
        scopes: []const []const u8 = &.{},
        dpop_bound: bool = false,
        dpop_jkt: ?[]const u8 = null,
    };

    /// Free a record from `parse` or `TokenStorage.load`. The function erases the secrets first.
    pub fn deinit(self: *Record, gpa: Allocator) void {
        if (self.registration) |r| {
            gpa.free(r.client_id);
            if (r.client_secret) |s| freeSecret(gpa, s);
        }
        if (self.access_token) |t| freeSecret(gpa, t);
        if (self.refresh_token) |t| freeSecret(gpa, t);
        for (self.scopes) |s| gpa.free(s);
        gpa.free(self.scopes);
        if (self.dpop_jkt) |j| gpa.free(j);
        self.* = .{};
    }

    /// The JSON text of the record for `key`, owned by the caller. Erase it after use.
    pub fn serialize(self: Record, gpa: Allocator, key: Key) Allocator.Error![]u8 {
        const wire: Wire = .{
            .version = version,
            .issuer = key.issuer,
            .resource = key.resource,
            .client = key.client,
            .registration = if (self.registration) |r| .{ .client_id = r.client_id, .client_secret = r.client_secret, .auth_method = r.auth_method } else null,
            .access_token = self.access_token,
            .expires_at = self.expires_at,
            .refresh_token = self.refresh_token,
            .scopes = self.scopes,
            .dpop_bound = self.dpop_bound,
            .dpop_jkt = self.dpop_jkt,
        };
        // A JSON escape has six bytes or less for each byte of a string. A fixed buffer of that
        // size never grows, so no copy of a secret stays in freed memory.
        var size: usize = 512 + key.issuer.len + key.resource.len + key.client.len;
        for ([_]?[]const u8{ self.access_token, self.refresh_token, self.dpop_jkt }) |s| size += if (s) |v| v.len else 0;
        if (self.registration) |r| size += r.client_id.len + if (r.client_secret) |s| s.len else 0;
        for (self.scopes) |s| size += s.len + 3;
        size *= 6;
        const buf = try gpa.alloc(u8, size);
        defer freeSecret(gpa, buf);
        var w: Io.Writer = .fixed(buf);
        std.json.Stringify.value(wire, .{ .emit_null_optional_fields = false }, &w) catch unreachable;
        return gpa.dupe(u8, w.buffered());
    }

    pub const ParseError = Allocator.Error || error{InvalidRecord};

    /// Parse a serialized record for `key`. A record of another version or of another key gives
    /// `error.InvalidRecord`. Free the result with `deinit`.
    pub fn parse(gpa: Allocator, text: []const u8, key: Key) ParseError!Record {
        // The parser works in a fixed buffer, and the function erases the buffer at the end.
        const scratch = try gpa.alloc(u8, text.len * 8 + 16 * 1024);
        defer freeSecret(gpa, scratch);
        var fba: std.heap.FixedBufferAllocator = .init(scratch);
        const wire = std.json.parseFromSliceLeaky(Wire, fba.allocator(), text, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch
            return error.InvalidRecord;
        if (wire.version != version) return error.InvalidRecord;
        if (!std.mem.eql(u8, wire.issuer, key.issuer) or !std.mem.eql(u8, wire.resource, key.resource) or !std.mem.eql(u8, wire.client, key.client)) return error.InvalidRecord;
        var out: Record = .{ .expires_at = wire.expires_at, .dpop_bound = wire.dpop_bound };
        errdefer out.deinit(gpa);
        if (wire.registration) |r| {
            const id = try gpa.dupe(u8, r.client_id);
            out.registration = .{ .client_id = id, .client_secret = null, .auth_method = r.auth_method };
            if (r.client_secret) |s| out.registration.?.client_secret = try gpa.dupe(u8, s);
        }
        if (wire.access_token) |t| out.access_token = try gpa.dupe(u8, t);
        if (wire.refresh_token) |t| out.refresh_token = try gpa.dupe(u8, t);
        if (wire.dpop_jkt) |j| out.dpop_jkt = try gpa.dupe(u8, j);
        const scopes = try gpa.alloc([]const u8, wire.scopes.len);
        var done: usize = 0;
        errdefer {
            for (scopes[0..done]) |s| gpa.free(s);
            gpa.free(scopes);
        }
        for (wire.scopes) |s| {
            scopes[done] = try gpa.dupe(u8, s);
            done += 1;
        }
        out.scopes = scopes;
        return out;
    }
};

fn freeSecret(gpa: Allocator, secret: []const u8) void {
    std.crypto.secureZero(u8, @constCast(secret));
    gpa.free(secret);
}

/// The interface of a token storage. An implementation keeps serialized records. The methods of
/// the interface serialize and parse them.
pub const TokenStorage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Error = error{
        OutOfMemory,
        /// The keychain of the host does not answer, or the host has no keychain. Use
        /// `FileTokenStorage` then.
        KeychainUnavailable,
        /// The user did not unlock the keychain.
        KeychainLocked,
        /// The stored data does not decrypt, does not parse, or is for another key.
        InvalidRecord,
        /// The record is larger than the storage accepts.
        RecordTooLarge,
        /// The system refused the operation. The log has the details.
        StorageFailed,
        Canceled,
    };

    pub const VTable = struct {
        /// The serialized record of `key` in memory from `gpa`, or null when the storage has
        /// none. The caller erases and frees it.
        load: *const fn (ptr: *anyopaque, gpa: Allocator, key: Key) Error!?[]u8,
        /// Keep `data` as the record of `key`. It replaces the old record.
        save: *const fn (ptr: *anyopaque, key: Key, data: []const u8) Error!void,
        /// Remove the record of `key`. A missing record is not an error.
        delete: *const fn (ptr: *anyopaque, key: Key) Error!void,
    };

    /// The record of `key`, or null. Free it with `Record.deinit`.
    pub fn load(self: TokenStorage, gpa: Allocator, key: Key) Error!?Record {
        const data = (try self.vtable.load(self.ptr, gpa, key)) orelse return null;
        defer freeSecret(gpa, data);
        return try Record.parse(gpa, data, key);
    }

    /// Keep `record` for `key`. The function erases the serialized record after use.
    pub fn save(self: TokenStorage, gpa: Allocator, key: Key, record: Record) Error!void {
        const data = try record.serialize(gpa, key);
        defer freeSecret(gpa, data);
        return self.vtable.save(self.ptr, key, data);
    }

    /// Remove the record of `key`.
    pub fn delete(self: TokenStorage, key: Key) Error!void {
        return self.vtable.delete(self.ptr, key);
    }
};

// -- Memory ------------------------------------------------------------------------------------

/// Keeps the records in the memory of the process. The records go away with the process. The
/// storage erases each record when it replaces or removes it.
pub const MemoryTokenStorage = struct {
    io: Io,
    gpa: Allocator,
    lock: Io.Mutex = .init,
    records: std.AutoHashMapUnmanaged([32]u8, []u8) = .empty,

    pub fn init(io: Io, gpa: Allocator) MemoryTokenStorage {
        return .{ .io = io, .gpa = gpa };
    }

    pub fn deinit(self: *MemoryTokenStorage) void {
        var it = self.records.valueIterator();
        while (it.next()) |v| freeSecret(self.gpa, v.*);
        self.records.deinit(self.gpa);
    }

    pub fn storage(self: *MemoryTokenStorage) TokenStorage {
        return .{ .ptr = self, .vtable = &.{ .load = load, .save = save, .delete = delete } };
    }

    /// The number of records.
    pub fn count(self: *MemoryTokenStorage) usize {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        return self.records.count();
    }

    fn load(ptr: *anyopaque, gpa: Allocator, key: Key) TokenStorage.Error!?[]u8 {
        const self: *MemoryTokenStorage = @ptrCast(@alignCast(ptr));
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const data = self.records.get(key.digest()) orelse return null;
        return try gpa.dupe(u8, data);
    }

    fn save(ptr: *anyopaque, key: Key, data: []const u8) TokenStorage.Error!void {
        const self: *MemoryTokenStorage = @ptrCast(@alignCast(ptr));
        const copy = try self.gpa.dupe(u8, data);
        errdefer freeSecret(self.gpa, copy);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const slot = try self.records.getOrPut(self.gpa, key.digest());
        if (slot.found_existing) freeSecret(self.gpa, slot.value_ptr.*);
        slot.value_ptr.* = copy;
    }

    fn delete(ptr: *anyopaque, key: Key) TokenStorage.Error!void {
        const self: *MemoryTokenStorage = @ptrCast(@alignCast(ptr));
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.records.fetchRemove(key.digest())) |kv| freeSecret(self.gpa, kv.value);
    }
};

// -- Files -------------------------------------------------------------------------------------

/// Keeps each record in its own file in a private directory. AES-256-GCM encrypts each file with
/// a key of the application and a random nonce. The name of a file is an HMAC of the key of the
/// record, so the names do not tell the issuers.
///
/// The directory has the mode `0700` on POSIX systems, and the files have the mode `0600`. On
/// Windows the directory and each file have a protected access control list that allows access
/// only to the user of the process. A write goes to a temporary file first. Then a rename puts
/// it in place, so a reader never sees a partial record.
///
/// File format: the 4 bytes `MCPT`, the format version 1, a nonce of 12 bytes, the ciphertext
/// and the tag of 16 bytes. The additional data of the encryption is the first 5 bytes and the
/// HMAC of the file name. Thus a file that moves to the name of another key does not decrypt.
pub const FileTokenStorage = struct {
    io: Io,
    gpa: Allocator,
    dir: []u8,
    encryption_key: [32]u8,
    name_key: [32]u8,
    lock: Io.Mutex = .init,

    pub const Options = struct {
        /// The directory of the files. `init` creates it when it is not there. Its parent must
        /// exist. Other accounts must not be able to add, delete or rename entries in it.
        dir: []const u8,
        /// The key of the application. The storage derives an AES-256-GCM key and an HMAC key
        /// from it. Keep it in a safe location, for example in the keychain of the host.
        key: [32]u8,
    };

    pub const InitError = socket_dir.CreateError || Allocator.Error;

    const magic = "MCPT";
    const format_version: u8 = 1;
    const header_len = magic.len + 1 + Aes256Gcm.nonce_length;
    const max_file_bytes = 1 << 20;
    const extension = ".token";

    /// Create the private directory when it is not there, and derive the keys. A directory that
    /// other accounts can write to gives `error.DirectoryNotPrivate`.
    pub fn init(io: Io, gpa: Allocator, options: Options) InitError!FileTokenStorage {
        try socket_dir.createPrivate(io, options.dir);
        if (builtin.os.tag != .windows) {
            // An old directory can have the mode `0755`. The files stay `0600` when this fails.
            Io.Dir.cwd().setFilePermissions(io, options.dir, .fromMode(0o700), .{}) catch |e|
                log.warn("could not set the mode 0700 on {s}: {t}", .{ options.dir, e });
        }
        var prk = HkdfSha256.extract("zig-sdk FileTokenStorage", &options.key);
        defer std.crypto.secureZero(u8, &prk);
        var self: FileTokenStorage = .{ .io = io, .gpa = gpa, .dir = try gpa.dupe(u8, options.dir), .encryption_key = undefined, .name_key = undefined };
        HkdfSha256.expand(&self.encryption_key, "encryption", prk);
        HkdfSha256.expand(&self.name_key, "file name", prk);
        return self;
    }

    pub fn deinit(self: *FileTokenStorage) void {
        std.crypto.secureZero(u8, &self.encryption_key);
        std.crypto.secureZero(u8, &self.name_key);
        self.gpa.free(self.dir);
    }

    pub fn storage(self: *FileTokenStorage) TokenStorage {
        return .{ .ptr = self, .vtable = &.{ .load = load, .save = save, .delete = delete } };
    }

    /// The path of the file of `key`, owned by the caller.
    pub fn pathOf(self: *FileTokenStorage, gpa: Allocator, key: Key) Allocator.Error![]u8 {
        const mac = self.fileMac(key);
        const hex = std.fmt.bytesToHex(mac, .lower);
        return std.fmt.allocPrint(gpa, "{s}{c}{s}" ++ extension, .{ self.dir, std.fs.path.sep, &hex });
    }

    fn fileMac(self: *FileTokenStorage, key: Key) [32]u8 {
        var mac: [32]u8 = undefined;
        HmacSha256.create(&mac, &key.digest(), &self.name_key);
        return mac;
    }

    fn additionalData(buf: *[magic.len + 1 + 32]u8, mac: [32]u8) []const u8 {
        buf[0..magic.len].* = magic.*;
        buf[magic.len] = format_version;
        buf[magic.len + 1 ..].* = mac;
        return buf;
    }

    fn openDir(self: *FileTokenStorage) TokenStorage.Error!Io.Dir {
        return Io.Dir.cwd().openDir(self.io, self.dir, .{}) catch |e| storageError("open the directory", e);
    }

    fn load(ptr: *anyopaque, gpa: Allocator, key: Key) TokenStorage.Error!?[]u8 {
        const self: *FileTokenStorage = @ptrCast(@alignCast(ptr));
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const mac = self.fileMac(key);
        const file_name = std.fmt.bytesToHex(mac, .lower) ++ extension.*;
        var dir = try self.openDir();
        defer dir.close(self.io);
        const bytes = dir.readFileAlloc(self.io, &file_name, gpa, .limited(max_file_bytes)) catch |e| switch (e) {
            error.FileNotFound => return null,
            error.StreamTooLong => return error.InvalidRecord,
            error.OutOfMemory => return error.OutOfMemory,
            else => |err| return storageError("read a token file", err),
        };
        defer gpa.free(bytes);
        if (bytes.len < header_len + Aes256Gcm.tag_length) return error.InvalidRecord;
        if (!std.mem.eql(u8, bytes[0..magic.len], magic) or bytes[magic.len] != format_version) return error.InvalidRecord;
        const nonce = bytes[magic.len + 1 ..][0..Aes256Gcm.nonce_length].*;
        const cipher = bytes[header_len .. bytes.len - Aes256Gcm.tag_length];
        const tag = bytes[bytes.len - Aes256Gcm.tag_length ..][0..Aes256Gcm.tag_length].*;
        const plain = try gpa.alloc(u8, cipher.len);
        errdefer freeSecret(gpa, plain);
        var ad_buf: [magic.len + 1 + 32]u8 = undefined;
        Aes256Gcm.decrypt(plain, cipher, tag, additionalData(&ad_buf, mac), nonce, self.encryption_key) catch return error.InvalidRecord;
        return plain;
    }

    fn save(ptr: *anyopaque, key: Key, data: []const u8) TokenStorage.Error!void {
        const self: *FileTokenStorage = @ptrCast(@alignCast(ptr));
        if (data.len > max_file_bytes - header_len - Aes256Gcm.tag_length) return error.RecordTooLarge;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const mac = self.fileMac(key);
        const hex = std.fmt.bytesToHex(mac, .lower);
        const file_name = hex ++ extension.*;

        const out = try self.gpa.alloc(u8, header_len + data.len + Aes256Gcm.tag_length);
        defer self.gpa.free(out);
        out[0..magic.len].* = magic.*;
        out[magic.len] = format_version;
        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        self.io.randomSecure(&nonce) catch return error.StorageFailed;
        out[magic.len + 1 ..][0..nonce.len].* = nonce;
        var ad_buf: [magic.len + 1 + 32]u8 = undefined;
        Aes256Gcm.encrypt(out[header_len..][0..data.len], out[header_len + data.len ..][0..Aes256Gcm.tag_length], data, additionalData(&ad_buf, mac), nonce, self.encryption_key);

        var random: [6]u8 = undefined;
        self.io.random(&random);
        var temp_buf: [96]u8 = undefined;
        const temp_name = std.fmt.bufPrint(&temp_buf, "{s}.{s}.tmp", .{ &hex, &std.fmt.bytesToHex(random, .lower) }) catch unreachable;
        var dir = try self.openDir();
        defer dir.close(self.io);
        const permissions: Io.File.Permissions = if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
        var file = dir.createFile(self.io, temp_name, .{ .exclusive = true, .permissions = permissions }) catch |e| return storageError("create a token file", e);
        var placed = false;
        defer if (!placed) dir.deleteFile(self.io, temp_name) catch {};
        {
            defer file.close(self.io);
            file.writeStreamingAll(self.io, out) catch |e| return storageError("write a token file", e);
            file.sync(self.io) catch |e| return storageError("write a token file", e);
        }
        if (builtin.os.tag == .windows) {
            // The file inherits the list of a directory from `init`. An older directory can have
            // another list, so the file gets its own list.
            const path = std.fs.path.join(self.gpa, &.{ self.dir, temp_name }) catch return error.OutOfMemory;
            defer self.gpa.free(path);
            windows_acl.restrictToCurrentUser(path) catch return error.StorageFailed;
        }
        Io.Dir.rename(dir, temp_name, dir, &file_name, self.io) catch |e| return storageError("rename a token file", e);
        placed = true;
    }

    fn delete(ptr: *anyopaque, key: Key) TokenStorage.Error!void {
        const self: *FileTokenStorage = @ptrCast(@alignCast(ptr));
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const file_name = std.fmt.bytesToHex(self.fileMac(key), .lower) ++ extension.*;
        var dir = try self.openDir();
        defer dir.close(self.io);
        dir.deleteFile(self.io, &file_name) catch |e| switch (e) {
            error.FileNotFound => {},
            else => |err| return storageError("delete a token file", err),
        };
    }
};

fn storageError(comptime what: []const u8, err: anyerror) TokenStorage.Error {
    if (err == error.Canceled) return error.Canceled;
    if (err == error.OutOfMemory) return error.OutOfMemory;
    log.warn("could not " ++ what ++ ": {t}", .{err});
    return error.StorageFailed;
}

// -- Tests -------------------------------------------------------------------------------------

const test_key: Key = .{ .issuer = "https://as.example", .resource = "https://mcp.example/mcp", .client = "client-1" };

fn testRecord() Record {
    return .{
        .registration = .{ .client_id = "client-1", .client_secret = "made-up-secret", .auth_method = .client_secret_basic },
        .access_token = "made-up-access-token",
        .expires_at = 1_700_000_000,
        .refresh_token = "made-up-refresh-token",
        .scopes = &.{ "mcp:read", "offline_access" },
        .dpop_bound = true,
        .dpop_jkt = "jkt-1",
    };
}

fn expectRecord(want: Record, got: Record) !void {
    try std.testing.expectEqualStrings(want.registration.?.client_id, got.registration.?.client_id);
    try std.testing.expectEqualStrings(want.registration.?.client_secret.?, got.registration.?.client_secret.?);
    try std.testing.expectEqual(want.registration.?.auth_method, got.registration.?.auth_method);
    try std.testing.expectEqualStrings(want.access_token.?, got.access_token.?);
    try std.testing.expectEqual(want.expires_at, got.expires_at);
    try std.testing.expectEqualStrings(want.refresh_token.?, got.refresh_token.?);
    try std.testing.expectEqual(want.scopes.len, got.scopes.len);
    for (want.scopes, got.scopes) |a, b| try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqual(want.dpop_bound, got.dpop_bound);
    try std.testing.expectEqualStrings(want.dpop_jkt.?, got.dpop_jkt.?);
}

test "a record serializes to versioned JSON and parses back for its key only" {
    const gpa = std.testing.allocator;
    const text = try testRecord().serialize(gpa, test_key);
    defer freeSecret(gpa, text);
    try std.testing.expect(std.mem.startsWith(u8, text, "{\"version\":1,"));
    var back = try Record.parse(gpa, text, test_key);
    defer back.deinit(gpa);
    try expectRecord(testRecord(), back);

    // Another key, another version and a damaged text give `InvalidRecord`.
    var other = test_key;
    other.resource = "https://other.example/mcp";
    try std.testing.expectError(error.InvalidRecord, Record.parse(gpa, text, other));
    const v2 = try std.mem.replaceOwned(u8, gpa, text, "\"version\":1", "\"version\":2");
    defer gpa.free(v2);
    try std.testing.expectError(error.InvalidRecord, Record.parse(gpa, v2, test_key));
    try std.testing.expectError(error.InvalidRecord, Record.parse(gpa, text[0 .. text.len / 2], test_key));

    // An empty record, and strings that need escapes.
    var odd = test_key;
    odd.client = "a \"quoted\" name\n\u{e9}";
    const empty = try (Record{}).serialize(gpa, odd);
    defer freeSecret(gpa, empty);
    var parsed = try Record.parse(gpa, empty, odd);
    defer parsed.deinit(gpa);
    try std.testing.expect(parsed.registration == null and parsed.access_token == null and parsed.scopes.len == 0);
}

test "the key digest separates its parts" {
    const a: Key = .{ .issuer = "ab", .resource = "c", .client = "" };
    const b: Key = .{ .issuer = "a", .resource = "bc", .client = "" };
    try std.testing.expect(!std.mem.eql(u8, &a.digest(), &b.digest()));
    try std.testing.expectEqual(64, test_key.name().len);
}

test "memory token storage keeps, replaces and deletes records" {
    const gpa = std.testing.allocator;
    var memory: MemoryTokenStorage = .init(std.testing.io, gpa);
    defer memory.deinit();
    const s = memory.storage();
    try std.testing.expect((try s.load(gpa, test_key)) == null);
    try s.save(gpa, test_key, testRecord());
    var first = (try s.load(gpa, test_key)).?;
    defer first.deinit(gpa);
    try expectRecord(testRecord(), first);
    var changed = testRecord();
    changed.access_token = "made-up-access-token-2";
    try s.save(gpa, test_key, changed);
    try std.testing.expectEqual(1, memory.count());
    var second = (try s.load(gpa, test_key)).?;
    defer second.deinit(gpa);
    try std.testing.expectEqualStrings("made-up-access-token-2", second.access_token.?);
    try s.delete(test_key);
    try s.delete(test_key);
    try std.testing.expect((try s.load(gpa, test_key)) == null);
}

/// A private directory `tokens` in a temporary directory, as a path from the current directory.
fn testDir(tmp: *std.testing.TmpDir) ![]u8 {
    return std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/tokens", .{tmp.sub_path});
}

test "file token storage encrypts each record and detects a change" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testDir(&tmp);
    defer gpa.free(dir);
    const key = [_]u8{7} ** 32;

    var files: FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = key });
    defer files.deinit();
    const s = files.storage();
    try std.testing.expect((try s.load(gpa, test_key)) == null);
    try s.save(gpa, test_key, testRecord());
    try s.save(gpa, test_key, testRecord());

    // A second storage with the same directory and key reads the record.
    var again: FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = key });
    defer again.deinit();
    var loaded = (try again.storage().load(gpa, test_key)).?;
    defer loaded.deinit(gpa);
    try expectRecord(testRecord(), loaded);

    // The file has neither the secrets nor the issuer in clear text, and its name has no issuer.
    const path = try files.pathOf(gpa, test_key);
    defer gpa.free(path);
    const bytes = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
    defer gpa.free(bytes);
    for ([_][]const u8{ "made-up", "as.example", "mcp:read" }) |needle| try std.testing.expect(std.mem.indexOf(u8, bytes, needle) == null);
    try std.testing.expect(std.mem.indexOf(u8, path, "example") == null);
    // Two writes of the same record use two nonces. One file stays, without temporary files.
    var entries: usize = 0;
    var d = try Io.Dir.cwd().openDir(io, dir, .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    while (try it.next(io)) |_| entries += 1;
    try std.testing.expectEqual(1, entries);

    // A changed byte, a wrong key and a file under the name of another key do not decrypt.
    bytes[bytes.len / 2] ^= 1;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
    try std.testing.expectError(error.InvalidRecord, s.load(gpa, test_key));
    bytes[bytes.len / 2] ^= 1;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
    var wrong: FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = [_]u8{8} ** 32 });
    defer wrong.deinit();
    const wrong_path = try wrong.pathOf(gpa, test_key);
    defer gpa.free(wrong_path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = wrong_path, .data = bytes });
    try std.testing.expectError(error.InvalidRecord, wrong.storage().load(gpa, test_key));
    var other = test_key;
    other.client = "client-2";
    const other_path = try files.pathOf(gpa, other);
    defer gpa.free(other_path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = other_path, .data = bytes });
    try std.testing.expectError(error.InvalidRecord, s.load(gpa, other));

    try s.delete(test_key);
    try s.delete(test_key);
    try std.testing.expect((try s.load(gpa, test_key)) == null);
}

test "file token storage gives the owner only access to the directory and the files" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testDir(&tmp);
    defer gpa.free(dir);
    var files: FileTokenStorage = try .init(io, gpa, .{ .dir = dir, .key = [_]u8{9} ** 32 });
    defer files.deinit();
    try files.storage().save(gpa, test_key, testRecord());
    const path = try files.pathOf(gpa, test_key);
    defer gpa.free(path);
    if (builtin.os.tag == .windows) {
        const report = try windows_acl.inspect(path);
        try std.testing.expect(report.protected and report.only_current_user);
        try std.testing.expect(try windows_acl.directoryIsPrivate(dir));
    } else {
        const file_stat = try Io.Dir.cwd().statFile(io, path, .{});
        try std.testing.expectEqual(0o600, file_stat.permissions.toMode() & 0o777);
        const dir_stat = try Io.Dir.cwd().statFile(io, dir, .{});
        try std.testing.expectEqual(0o700, dir_stat.permissions.toMode() & 0o777);
    }
}
