//! The directory of a Unix socket. Some accounts can add, delete or rename entries in a
//! directory. Such an account can put its own socket at the path of the server, so the server
//! refuses such a directory. `createPrivate` makes a directory that only the user of the process can use.
//!
//! On POSIX systems `isPrivate` also checks each parent directory up to the root. A parent
//! that other accounts can write to must have the sticky bit, so that they cannot rename the
//! directory. On Windows it checks the directory only.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const windows_acl = if (builtin.os.tag == .windows) @import("windows_acl.zig") else struct {};

pub const CheckError = error{ NameTooLong, AccessControlFailed, AccessDenied, FileNotFound, Unexpected } || Io.Dir.OpenError || Io.Dir.RealPathError;
pub const CreateError = CheckError || Io.Dir.CreateDirError || error{DirectoryNotPrivate};
pub const TempError = CreateError || Allocator.Error;

/// Tell if the directory at `path` is safe for a socket with the file mode `mode`. Only the
/// user of the process and the administrators (root, or the local system account, the
/// Administrators group and TrustedInstaller on Windows) can add, delete or rename entries in it. When `mode` gives
/// access to the group, the group of the directory can also write to it on POSIX systems.
pub fn isPrivate(io: Io, path: []const u8, mode: u32) CheckError!bool {
    if (builtin.os.tag == .windows) return windows_acl.directoryIsPrivate(path);
    var dir = try Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    const len = try dir.realPath(io, &buf);
    const euid = geteuid();
    var current: []const u8 = buf[0..len];
    var first = true;
    while (true) {
        const st = try statPath(current);
        if (st.uid != euid and st.uid != 0) return false;
        const perm = st.mode & 0o7777;
        if (first) {
            if (perm & 0o002 != 0) return false;
            if (perm & 0o020 != 0 and mode & 0o070 == 0) return false;
        } else if (perm & 0o022 != 0 and perm & 0o1000 == 0) return false;
        first = false;
        current = std.fs.path.dirname(current) orelse break;
    }
    return true;
}

/// Create a private directory at `path`. On POSIX systems it has the mode `0700`. On Windows
/// it has a protected access control list that allows access only to the user of the process.
/// The files in the directory inherit this list. A directory that is already at `path` must be
/// private, or the call gives `error.DirectoryNotPrivate`.
pub fn createPrivate(io: Io, path: []const u8) CreateError!void {
    createExclusive(io, path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => |err| return err,
    };
    if (!try isPrivate(io, path, 0o600)) return error.DirectoryNotPrivate;
}

/// Create a new private directory with a random name in `dir` and return its path, owned by
/// the caller. The name has 11 bytes.
pub fn createTemp(io: Io, gpa: Allocator, dir: []const u8) TempError![]u8 {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        var bytes: [3]u8 = undefined;
        io.random(&bytes);
        const path = try std.fmt.allocPrint(gpa, "{s}{c}.mcp-{s}", .{ dir, std.fs.path.sep, std.fmt.bytesToHex(bytes, .lower) });
        createExclusive(io, path) catch |e| {
            gpa.free(path);
            if (e == error.PathAlreadyExists and attempt < 16) continue;
            return e;
        };
        return path;
    }
}

fn createExclusive(io: Io, path: []const u8) CreateError!void {
    if (builtin.os.tag == .windows) {
        windows_acl.createPrivateDirectory(path) catch |e| switch (e) {
            error.PathAlreadyExists => return error.PathAlreadyExists,
            error.NameTooLong => return error.NameTooLong,
            error.AccessControlFailed => return error.AccessControlFailed,
        };
    } else {
        // The umask can only remove bits, so the mode is `0700` or stricter.
        try Io.Dir.cwd().createDir(io, path, .fromMode(0o700));
    }
}

const Stat = struct { uid: u32, mode: u32 };

/// The owner and the mode of the file at `path`, with a follow of symbolic links.
fn statPath(path: []const u8) error{ NameTooLong, AccessDenied, FileNotFound, Unexpected }!Stat {
    var buf: [std.posix.PATH_MAX]u8 = undefined;
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = buf[0..path.len :0];
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var sx = std.mem.zeroes(linux.Statx);
        return switch (linux.errno(linux.statx(linux.AT.FDCWD, path_z, 0, .{ .TYPE = true, .MODE = true, .UID = true }, &sx))) {
            .SUCCESS => .{ .uid = sx.uid, .mode = sx.mode },
            .ACCES => error.AccessDenied,
            .NOENT, .NOTDIR => error.FileNotFound,
            else => error.Unexpected,
        };
    }
    var st: std.c.Stat = undefined;
    return switch (std.c.errno(std.c.fstatat(std.c.AT.FDCWD, path_z, &st, 0))) {
        .SUCCESS => .{ .uid = st.uid, .mode = st.mode },
        .ACCES => error.AccessDenied,
        .NOENT, .NOTDIR => error.FileNotFound,
        else => error.Unexpected,
    };
}

fn geteuid() u32 {
    return if (builtin.os.tag == .linux) std.os.linux.geteuid() else std.c.geteuid();
}
