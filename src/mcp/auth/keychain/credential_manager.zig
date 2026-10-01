//! The Windows backend of `KeychainTokenStorage`: generic credentials of the Credential Manager.
//! Windows encrypts them with the data protection key of the user.
//!
//! The blob of one credential has 2560 bytes or less. A record with a large access token does
//! not fit, so the backend splits the record into chunks. Chunk 0 has the target name
//! `{service}/{key}`, and chunk `i` has the name `{service}/{key}/{i}`.
//!
//! Each chunk starts with a header of 11 bytes. The header has the format version 1, a random
//! generation of 8 bytes, the index and the number of chunks. A write puts the last chunk first
//! and chunk 0 last. A read accepts only chunks of one generation. Thus a read during a write
//! gives no mix of two records.
const std = @import("std");
const windows = std.os.windows;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const token_storage = @import("../token_storage.zig");
const Error = token_storage.TokenStorage.Error;
const Key = token_storage.Key;

const log = std.log.scoped(.mcp_keychain);

/// Where the Credential Manager keeps a credential.
pub const Persist = enum(windows.DWORD) {
    /// On this computer, also after a new logon.
    local_machine = 2,
    /// On this computer and on the other computers of the user in a domain.
    enterprise = 3,
};

pub const Options = struct {
    /// The prefix of the target names.
    service: []const u8,
    persist: Persist = .local_machine,
};

pub const max_blob_bytes = 2560;
const header_len = 11;
const chunk_payload = max_blob_bytes - header_len;
const format_version = 1;
/// The largest number of chunks of one record, about 160 KiB.
pub const max_chunks = 64;

/// Make sure that the Credential Manager answers for the user of the process.
pub fn probe(gpa: Allocator, options: Options) Error!void {
    const target = try targetName(gpa, options.service, "probe", 0);
    defer gpa.free(target);
    const blob = try readTarget(gpa, target);
    if (blob) |b| freeSecret(gpa, b);
}

pub fn load(io: Io, gpa: Allocator, options: Options, key: Key) Error!?[]u8 {
    _ = io;
    const name = key.name();
    // A write can change the chunks during the read. One more read then sees the new record.
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        if (try loadOnce(gpa, options, &name)) |result| switch (result) {
            .record => |r| return r,
            .torn => if (attempt > 0) return error.InvalidRecord,
        } else return null;
    }
}

const LoadResult = union(enum) { record: []u8, torn };

fn loadOnce(gpa: Allocator, options: Options, name: []const u8) Error!?LoadResult {
    const first_target = try targetName(gpa, options.service, name, 0);
    defer gpa.free(first_target);
    const first = (try readTarget(gpa, first_target)) orelse return null;
    defer freeSecret(gpa, first);
    const head = try parseHeader(first, 0);
    // The size is known at the start, so the buffer never grows and leaves no copy behind.
    const out = try gpa.alloc(u8, @as(usize, head.count) * chunk_payload);
    var len: usize = 0;
    errdefer freeSecret(gpa, out);
    @memcpy(out[0 .. first.len - header_len], first[header_len..]);
    len += first.len - header_len;
    for (1..head.count) |i| {
        const target = try targetName(gpa, options.service, name, i);
        defer gpa.free(target);
        const chunk = (try readTarget(gpa, target)) orelse {
            freeSecret(gpa, out);
            return .torn;
        };
        defer freeSecret(gpa, chunk);
        const h = parseHeader(chunk, i) catch {
            freeSecret(gpa, out);
            return .torn;
        };
        if (!std.mem.eql(u8, &h.generation, &head.generation) or h.count != head.count) {
            freeSecret(gpa, out);
            return .torn;
        }
        @memcpy(out[len..][0 .. chunk.len - header_len], chunk[header_len..]);
        len += chunk.len - header_len;
    }
    const result = try gpa.dupe(u8, out[0..len]);
    freeSecret(gpa, out);
    return .{ .record = result };
}

const Header = struct { generation: [8]u8, count: u8 };

fn parseHeader(blob: []const u8, index: usize) Error!Header {
    if (blob.len < header_len or blob[0] != format_version) return error.InvalidRecord;
    if (blob[9] != index or blob[10] == 0 or blob[10] > max_chunks or index >= blob[10]) return error.InvalidRecord;
    return .{ .generation = blob[1..9].*, .count = blob[10] };
}

pub fn save(io: Io, gpa: Allocator, options: Options, key: Key, data: []const u8) Error!void {
    const name = key.name();
    const count = @max(1, std.math.divCeil(usize, data.len, chunk_payload) catch unreachable);
    if (count > max_chunks) return error.RecordTooLarge;
    // The number of chunks of the old record. The function removes the chunks that the new
    // record does not use.
    var old_count: usize = 0;
    {
        const target = try targetName(gpa, options.service, &name, 0);
        defer gpa.free(target);
        if (try readTarget(gpa, target)) |old| {
            defer freeSecret(gpa, old);
            if (parseHeader(old, 0)) |h| {
                old_count = h.count;
            } else |_| {}
        }
    }
    var generation: [8]u8 = undefined;
    io.random(&generation);
    var blob: [max_blob_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &blob);
    var i = count;
    while (i > 0) {
        i -= 1;
        const part = data[@min(data.len, i * chunk_payload)..@min(data.len, (i + 1) * chunk_payload)];
        blob[0] = format_version;
        blob[1..9].* = generation;
        blob[9] = @intCast(i);
        blob[10] = @intCast(count);
        @memcpy(blob[header_len..][0..part.len], part);
        const target = try targetName(gpa, options.service, &name, i);
        defer gpa.free(target);
        try writeTarget(target, blob[0 .. header_len + part.len], options.persist);
    }
    for (count..@max(count, old_count)) |j| {
        const target = try targetName(gpa, options.service, &name, j);
        defer gpa.free(target);
        deleteTarget(target) catch {};
    }
}

pub fn delete(io: Io, gpa: Allocator, options: Options, key: Key) Error!void {
    _ = io;
    const name = key.name();
    const first_target = try targetName(gpa, options.service, &name, 0);
    defer gpa.free(first_target);
    var count: usize = 1;
    if (try readTarget(gpa, first_target)) |first| {
        defer freeSecret(gpa, first);
        if (parseHeader(first, 0)) |h| {
            count = h.count;
        } else |_| {}
    } else return;
    // Chunk 0 goes first, so a reader sees no record during the delete.
    try deleteTarget(first_target);
    for (1..count) |i| {
        const target = try targetName(gpa, options.service, &name, i);
        defer gpa.free(target);
        try deleteTarget(target);
    }
}

/// The target name of chunk `index` as UTF-16 with a zero at the end.
pub fn targetName(gpa: Allocator, service: []const u8, name: []const u8, index: usize) Error![:0]u16 {
    var buf: [512]u8 = undefined;
    const text = (if (index == 0)
        std.fmt.bufPrint(&buf, "{s}/{s}", .{ service, name })
    else
        std.fmt.bufPrint(&buf, "{s}/{s}/{d}", .{ service, name, index })) catch return error.StorageFailed;
    return std.unicode.wtf8ToWtf16LeAllocZ(gpa, text) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidWtf8 => error.StorageFailed,
    };
}

pub fn readTarget(gpa: Allocator, target: [:0]const u16) Error!?[]u8 {
    var credential: ?*CREDENTIALW = null;
    if (CredReadW(target.ptr, CRED_TYPE_GENERIC, 0, &credential) == 0) {
        return switch (windows.GetLastError()) {
            .NOT_FOUND => null,
            else => |code| failure("CredReadW", code),
        };
    }
    const c = credential.?;
    defer CredFree(c);
    const blob: []u8 = if (c.CredentialBlob) |b| b[0..c.CredentialBlobSize] else &.{};
    defer std.crypto.secureZero(u8, blob);
    return try gpa.dupe(u8, blob);
}

fn writeTarget(target: [:0]const u16, blob: []u8, persist: Persist) Error!void {
    var credential: CREDENTIALW = std.mem.zeroes(CREDENTIALW);
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = @constCast(target.ptr);
    credential.CredentialBlobSize = @intCast(blob.len);
    credential.CredentialBlob = blob.ptr;
    credential.Persist = @intFromEnum(persist);
    if (CredWriteW(&credential, 0) == 0) return failure("CredWriteW", windows.GetLastError());
}

fn deleteTarget(target: [:0]const u16) Error!void {
    if (CredDeleteW(target.ptr, CRED_TYPE_GENERIC, 0) == 0) switch (windows.GetLastError()) {
        .NOT_FOUND => {},
        else => |code| return failure("CredDeleteW", code),
    };
}

fn failure(comptime function: []const u8, code: windows.Win32Error) Error {
    switch (code) {
        // A logon without a profile, for example a service or a network logon.
        .NO_SUCH_LOGON_SESSION => return error.KeychainUnavailable,
        .NOT_ENOUGH_MEMORY, .OUTOFMEMORY => return error.OutOfMemory,
        else => {
            log.warn(function ++ " failed with Windows error {d}", .{@intFromEnum(code)});
            return error.StorageFailed;
        },
    }
}

fn freeSecret(gpa: Allocator, secret: []u8) void {
    std.crypto.secureZero(u8, secret);
    gpa.free(secret);
}

const CRED_TYPE_GENERIC: windows.DWORD = 1;

const FILETIME = extern struct { dwLowDateTime: windows.DWORD, dwHighDateTime: windows.DWORD };

const CREDENTIAL_ATTRIBUTEW = extern struct {
    Keyword: ?[*:0]u16,
    Flags: windows.DWORD,
    ValueSize: windows.DWORD,
    Value: ?[*]u8,
};

const CREDENTIALW = extern struct {
    Flags: windows.DWORD,
    Type: windows.DWORD,
    TargetName: ?[*:0]u16,
    Comment: ?[*:0]u16,
    LastWritten: FILETIME,
    CredentialBlobSize: windows.DWORD,
    CredentialBlob: ?[*]u8,
    Persist: windows.DWORD,
    AttributeCount: windows.DWORD,
    Attributes: ?[*]CREDENTIAL_ATTRIBUTEW,
    TargetAlias: ?[*:0]u16,
    UserName: ?[*:0]u16,
};

extern "advapi32" fn CredWriteW(Credential: *const CREDENTIALW, Flags: windows.DWORD) callconv(.winapi) c_int;
extern "advapi32" fn CredReadW(TargetName: [*:0]const u16, Type: windows.DWORD, Flags: windows.DWORD, Credential: *?*CREDENTIALW) callconv(.winapi) c_int;
extern "advapi32" fn CredDeleteW(TargetName: [*:0]const u16, Type: windows.DWORD, Flags: windows.DWORD) callconv(.winapi) c_int;
extern "advapi32" fn CredFree(Buffer: ?*anyopaque) callconv(.winapi) void;
