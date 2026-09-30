//! Access control lists for Unix socket files on Windows. `restrictToCurrentUser` gives a
//! socket file a protected access control list with one entry: full access for the user of
//! the process. This is the Windows form of the file mode `0600`. The socket file is a
//! reparse point, so this file opens it with `FILE_FLAG_OPEN_REPARSE_POINT` and sets the list
//! on the handle. `createPrivateDirectory` and `directoryIsPrivate` give the directory of the
//! socket the same protection.
const std = @import("std");
const windows = std.os.windows;

pub const Error = error{ NameTooLong, AccessControlFailed };
pub const DirectoryError = Error || error{PathAlreadyExists};

/// The access control list of a file, for tests.
pub const Report = struct {
    /// The list does not inherit entries from the directory.
    protected: bool,
    ace_count: u16,
    /// The list has exactly one entry, and it allows full access for the user of the process.
    only_current_user: bool,
};

/// Give the file at `path` a protected access control list that allows access only to the
/// user of the process. `path` is an absolute path.
pub fn restrictToCurrentUser(path: []const u8) Error!void {
    return allowCurrentUser(path, FILE_ALL_ACCESS);
}

/// Give the file at `path` a protected access control list without the data rights. The user
/// of the process can read and change the list and delete the file. Then no client can
/// connect, and the server can still remove the file. For tests.
pub fn refuseConnections(path: []const u8) Error!void {
    return allowCurrentUser(path, DELETE | READ_CONTROL | WRITE_DAC | SYNCHRONIZE | FILE_READ_ATTRIBUTES);
}

fn allowCurrentUser(path: []const u8, mask: windows.DWORD) Error!void {
    var token_user: TokenUserBuffer align(@alignOf(TOKEN_USER)) = undefined;
    const sid = try currentUserSid(&token_user);
    var acl_buf: [256]u8 align(@alignOf(u32)) = undefined;
    const acl_len: windows.DWORD = @sizeOf(ACL) + @sizeOf(ACCESS_ALLOWED_ACE) - @sizeOf(windows.DWORD) + GetLengthSid(sid);
    if (acl_len > acl_buf.len) return error.AccessControlFailed;
    if (InitializeAcl(&acl_buf, acl_len, ACL_REVISION) == 0) return fail("InitializeAcl");
    if (AddAccessAllowedAce(&acl_buf, ACL_REVISION, mask, sid) == 0) return fail("AddAccessAllowedAce");
    const handle = try openForSecurity(path, READ_CONTROL | WRITE_DAC);
    defer windows.CloseHandle(handle);
    const status = SetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null, null, &acl_buf, null);
    if (status != 0) return failCode("SetSecurityInfo", status);
}

/// Read the access control list of the file at `path`.
pub fn inspect(path: []const u8) Error!Report {
    var token_user: TokenUserBuffer align(@alignOf(TOKEN_USER)) = undefined;
    const sid = try currentUserSid(&token_user);
    const handle = try openForSecurity(path, READ_CONTROL);
    defer windows.CloseHandle(handle);
    var dacl: ?*ACL = null;
    var descriptor: ?*anyopaque = null;
    const status = GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null, null, &dacl, null, &descriptor);
    if (status != 0) return failCode("GetSecurityInfo", status);
    defer _ = LocalFree(descriptor);
    var control: u16 = 0;
    var revision: windows.DWORD = 0;
    if (GetSecurityDescriptorControl(descriptor.?, &control, &revision) == 0) return fail("GetSecurityDescriptorControl");
    const acl = dacl orelse return .{ .protected = control & SE_DACL_PROTECTED != 0, .ace_count = 0, .only_current_user = false };
    var only = false;
    if (acl.AceCount == 1) {
        const ace: *const ACCESS_ALLOWED_ACE = @ptrCast(@alignCast(@as([*]const u8, @ptrCast(acl)) + @sizeOf(ACL)));
        only = ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE and ace.Mask == FILE_ALL_ACCESS and
            EqualSid(@ptrCast(@constCast(&ace.SidStart)), sid) != 0;
    }
    return .{ .protected = control & SE_DACL_PROTECTED != 0, .ace_count = acl.AceCount, .only_current_user = only };
}

/// Create the directory at `path` with a protected access control list that allows access only
/// to the user of the process. The files and directories in it inherit this entry, so a socket
/// file in it allows access only to the user from its creation. The list is part of the
/// creation, so the directory never has the list of its parent.
pub fn createPrivateDirectory(path: []const u8) DirectoryError!void {
    var token_user: TokenUserBuffer align(@alignOf(TOKEN_USER)) = undefined;
    const sid = try currentUserSid(&token_user);
    var acl_buf: [256]u8 align(@alignOf(u32)) = undefined;
    const acl_len: windows.DWORD = @sizeOf(ACL) + @sizeOf(ACCESS_ALLOWED_ACE) - @sizeOf(windows.DWORD) + GetLengthSid(sid);
    if (acl_len > acl_buf.len) return error.AccessControlFailed;
    if (InitializeAcl(&acl_buf, acl_len, ACL_REVISION) == 0) return fail("InitializeAcl");
    if (AddAccessAllowedAceEx(&acl_buf, ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, sid) == 0) return fail("AddAccessAllowedAceEx");
    var descriptor: [64]u8 align(@alignOf(usize)) = undefined;
    if (InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) == 0) return fail("InitializeSecurityDescriptor");
    if (SetSecurityDescriptorDacl(&descriptor, 1, &acl_buf, 0) == 0) return fail("SetSecurityDescriptorDacl");
    if (SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED) == 0) return fail("SetSecurityDescriptorControl");
    var attributes: windows.SECURITY_ATTRIBUTES = .{ .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES), .lpSecurityDescriptor = &descriptor, .bInheritHandle = .FALSE };
    var path_w: [512:0]u16 = undefined;
    if (CreateDirectoryW(try toWide(path, &path_w), &attributes) == 0) {
        const code = windows.GetLastError();
        if (code == .ALREADY_EXISTS) return error.PathAlreadyExists;
        return failCode("CreateDirectoryW", @intFromEnum(code));
    }
}

/// Tell if only trusted accounts can add, delete or rename entries in the directory at `path`,
/// or change its list. The trusted accounts are the user of the process, the local system
/// account, the Administrators group and TrustedInstaller. The owner of the directory must also be one of
/// them. The check skips entries that only give inheritance, because they do not apply to the directory.
pub fn directoryIsPrivate(path: []const u8) Error!bool {
    var token_user: TokenUserBuffer align(@alignOf(TOKEN_USER)) = undefined;
    const user = try currentUserSid(&token_user);
    const handle = try openForSecurity(path, READ_CONTROL);
    defer windows.CloseHandle(handle);
    var owner: ?*anyopaque = null;
    var dacl: ?*ACL = null;
    var descriptor: ?*anyopaque = null;
    const status = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, null, &dacl, null, &descriptor);
    if (status != 0) return failCode("GetSecurityInfo", status);
    defer _ = LocalFree(descriptor);
    if (!trusted(owner orelse return false, user)) return false;
    // A null list gives every account all rights.
    const acl = dacl orelse return false;
    const bytes: [*]const u8 = @ptrCast(acl);
    var offset: usize = @sizeOf(ACL);
    for (0..acl.AceCount) |_| {
        const header: *const ACE_HEADER = @ptrCast(@alignCast(bytes + offset));
        defer offset += header.AceSize;
        if (header.AceFlags & INHERIT_ONLY_ACE != 0) continue;
        const ace: *const ACCESS_ALLOWED_ACE = @ptrCast(@alignCast(header));
        switch (header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => if (ace.Mask & directory_write_rights != 0 and !trusted(@ptrCast(@constCast(&ace.SidStart)), user)) return false,
            // These types keep the SID at another offset. They are rare on files, so refuse
            // them when they give a write right.
            ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => if (ace.Mask & directory_write_rights != 0) return false,
            else => {},
        }
    }
    return true;
}

/// Give the directory at `path` a protected list that lets the user do all and lets Everyone
/// add files. The directory is then not private. For tests.
pub fn openToEveryone(path: []const u8) Error!void {
    var token_user: TokenUserBuffer align(@alignOf(TOKEN_USER)) = undefined;
    const user = try currentUserSid(&token_user);
    var world: [SECURITY_MAX_SID_SIZE]u8 align(@alignOf(u32)) = undefined;
    var world_len: windows.DWORD = world.len;
    if (CreateWellKnownSid(WinWorldSid, null, &world, &world_len) == 0) return fail("CreateWellKnownSid");
    var acl_buf: [512]u8 align(@alignOf(u32)) = undefined;
    const ace_len = @sizeOf(ACCESS_ALLOWED_ACE) - @sizeOf(windows.DWORD);
    const acl_len: windows.DWORD = @sizeOf(ACL) + 2 * ace_len + GetLengthSid(user) + GetLengthSid(&world);
    if (InitializeAcl(&acl_buf, acl_len, ACL_REVISION) == 0) return fail("InitializeAcl");
    if (AddAccessAllowedAce(&acl_buf, ACL_REVISION, FILE_ALL_ACCESS, user) == 0) return fail("AddAccessAllowedAce");
    if (AddAccessAllowedAce(&acl_buf, ACL_REVISION, FILE_ADD_FILE, &world) == 0) return fail("AddAccessAllowedAce");
    const handle = try openForSecurity(path, READ_CONTROL | WRITE_DAC);
    defer windows.CloseHandle(handle);
    const status = SetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null, null, &acl_buf, null);
    if (status != 0) return failCode("SetSecurityInfo", status);
}

fn trusted(sid: *anyopaque, user: *anyopaque) bool {
    if (EqualSid(sid, user) != 0) return true;
    inline for (.{ WinLocalSystemSid, WinBuiltinAdministratorsSid, WinCreatorOwnerSid }) |kind| {
        if (IsWellKnownSid(sid, kind) != 0) return true;
    }
    return EqualSid(sid, @ptrCast(@constCast(&trusted_installer))) != 0;
}

/// The security identifier of the account TrustedInstaller, S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464.
const trusted_installer: extern struct { revision: u8, count: u8, authority: [6]u8, sub: [6]u32 } = .{
    .revision = 1,
    .count = 6,
    .authority = .{ 0, 0, 0, 0, 0, 5 },
    .sub = .{ 80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464 },
};

/// Rights on a directory that let an account add, delete or rename entries or change the list.
const directory_write_rights = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;

fn toWide(path: []const u8, buf: *[512:0]u16) Error![:0]const u16 {
    // A UTF-16 path has no more code units than the WTF-8 path has bytes.
    if (path.len > buf.len) return error.NameTooLong;
    const len = std.unicode.wtf8ToWtf16Le(buf, path) catch return error.NameTooLong;
    if (len >= buf.len) return error.NameTooLong;
    buf[len] = 0;
    return buf[0..len :0];
}
const TokenUserBuffer = [@sizeOf(TOKEN_USER) + SECURITY_MAX_SID_SIZE]u8;

fn currentUserSid(buf: *align(@alignOf(TOKEN_USER)) TokenUserBuffer) Error!*anyopaque {
    var token: windows.HANDLE = undefined;
    if (OpenProcessToken(windows.GetCurrentProcess(), TOKEN_QUERY, &token) == 0) return fail("OpenProcessToken");
    defer windows.CloseHandle(token);
    var len: windows.DWORD = 0;
    if (GetTokenInformation(token, TokenUser, buf, buf.len, &len) == 0) return fail("GetTokenInformation");
    // The SID lies in `buf` after the structure.
    const user: *const TOKEN_USER = @ptrCast(buf);
    return user.User.Sid;
}

fn openForSecurity(path: []const u8, access: windows.DWORD) Error!windows.HANDLE {
    var path_w: [512:0]u16 = undefined;
    const handle = CreateFileW(try toWide(path, &path_w), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, null, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, null);
    if (handle == windows.INVALID_HANDLE_VALUE) return fail("CreateFileW");
    return handle;
}

fn fail(comptime function: []const u8) error{AccessControlFailed} {
    return failCode(function, @intFromEnum(windows.GetLastError()));
}

fn failCode(comptime function: []const u8, code: windows.DWORD) error{AccessControlFailed} {
    std.log.scoped(.mcp_unix).err(function ++ " failed with Windows error {d}", .{code});
    return error.AccessControlFailed;
}

const ACL = extern struct { AclRevision: u8, Sbz1: u8, AclSize: u16, AceCount: u16, Sbz2: u16 };
const ACE_HEADER = extern struct { AceType: u8, AceFlags: u8, AceSize: u16 };
const ACCESS_ALLOWED_ACE = extern struct { Header: ACE_HEADER, Mask: windows.DWORD, SidStart: windows.DWORD };
const SID_AND_ATTRIBUTES = extern struct { Sid: *anyopaque, Attributes: windows.DWORD };
const TOKEN_USER = extern struct { User: SID_AND_ATTRIBUTES };

const ACL_REVISION = 2;
const ACCESS_ALLOWED_ACE_TYPE = 0;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE = 5;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 9;
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 11;
const OBJECT_INHERIT_ACE = 0x1;
const CONTAINER_INHERIT_ACE = 0x2;
const INHERIT_ONLY_ACE = 0x8;
const SECURITY_DESCRIPTOR_REVISION = 1;
const OWNER_SECURITY_INFORMATION = 0x00000001;
const WinWorldSid = 1;
const WinCreatorOwnerSid = 3;
const WinLocalSystemSid = 22;
const WinBuiltinAdministratorsSid = 26;
const FILE_ADD_FILE = 0x0002;
const FILE_ADD_SUBDIRECTORY = 0x0004;
const FILE_DELETE_CHILD = 0x0040;
const WRITE_OWNER = 0x00080000;
const GENERIC_WRITE = 0x40000000;
const GENERIC_ALL = 0x10000000;
const SECURITY_MAX_SID_SIZE = 68;
const TokenUser = 1;
const TOKEN_QUERY = 0x0008;
const SE_FILE_OBJECT = 1;
const DACL_SECURITY_INFORMATION = 0x00000004;
const PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
const SE_DACL_PROTECTED = 0x1000;
const DELETE = 0x00010000;
const READ_CONTROL = 0x00020000;
const SYNCHRONIZE = 0x00100000;
const FILE_READ_ATTRIBUTES = 0x0080;
const WRITE_DAC = 0x00040000;
const FILE_ALL_ACCESS = 0x001F01FF;
const FILE_SHARE_READ = 0x1;
const FILE_SHARE_WRITE = 0x2;
const FILE_SHARE_DELETE = 0x4;
const OPEN_EXISTING = 3;
const FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
const FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

extern "advapi32" fn OpenProcessToken(ProcessHandle: windows.HANDLE, DesiredAccess: windows.DWORD, TokenHandle: *windows.HANDLE) callconv(.winapi) c_int;
extern "advapi32" fn GetTokenInformation(TokenHandle: windows.HANDLE, TokenInformationClass: c_int, TokenInformation: ?*anyopaque, TokenInformationLength: windows.DWORD, ReturnLength: *windows.DWORD) callconv(.winapi) c_int;
extern "advapi32" fn GetLengthSid(pSid: *anyopaque) callconv(.winapi) windows.DWORD;
extern "advapi32" fn EqualSid(pSid1: *anyopaque, pSid2: *anyopaque) callconv(.winapi) c_int;
extern "advapi32" fn InitializeAcl(pAcl: *anyopaque, nAclLength: windows.DWORD, dwAclRevision: windows.DWORD) callconv(.winapi) c_int;
extern "advapi32" fn AddAccessAllowedAce(pAcl: *anyopaque, dwAceRevision: windows.DWORD, AccessMask: windows.DWORD, pSid: *anyopaque) callconv(.winapi) c_int;
extern "advapi32" fn AddAccessAllowedAceEx(pAcl: *anyopaque, dwAceRevision: windows.DWORD, AceFlags: windows.DWORD, AccessMask: windows.DWORD, pSid: *anyopaque) callconv(.winapi) c_int;
extern "advapi32" fn InitializeSecurityDescriptor(pSecurityDescriptor: *anyopaque, dwRevision: windows.DWORD) callconv(.winapi) c_int;
extern "advapi32" fn SetSecurityDescriptorDacl(pSecurityDescriptor: *anyopaque, bDaclPresent: c_int, pDacl: ?*anyopaque, bDaclDefaulted: c_int) callconv(.winapi) c_int;
extern "advapi32" fn SetSecurityDescriptorControl(pSecurityDescriptor: *anyopaque, ControlBitsOfInterest: u16, ControlBitsToSet: u16) callconv(.winapi) c_int;
extern "advapi32" fn IsWellKnownSid(pSid: *anyopaque, WellKnownSidType: c_int) callconv(.winapi) c_int;
extern "advapi32" fn CreateWellKnownSid(WellKnownSidType: c_int, DomainSid: ?*anyopaque, pSid: *anyopaque, cbSid: *windows.DWORD) callconv(.winapi) c_int;
extern "advapi32" fn SetSecurityInfo(handle: windows.HANDLE, ObjectType: c_int, SecurityInfo: windows.DWORD, psidOwner: ?*anyopaque, psidGroup: ?*anyopaque, pDacl: ?*anyopaque, pSacl: ?*anyopaque) callconv(.winapi) windows.DWORD;
extern "advapi32" fn GetSecurityInfo(handle: windows.HANDLE, ObjectType: c_int, SecurityInfo: windows.DWORD, ppsidOwner: ?*?*anyopaque, ppsidGroup: ?*?*anyopaque, ppDacl: ?*?*ACL, ppSacl: ?*?*ACL, ppSecurityDescriptor: *?*anyopaque) callconv(.winapi) windows.DWORD;
extern "advapi32" fn GetSecurityDescriptorControl(pSecurityDescriptor: *anyopaque, pControl: *u16, lpdwRevision: *windows.DWORD) callconv(.winapi) c_int;
extern "kernel32" fn CreateFileW(lpFileName: windows.LPCWSTR, dwDesiredAccess: windows.DWORD, dwShareMode: windows.DWORD, lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES, dwCreationDisposition: windows.DWORD, dwFlagsAndAttributes: windows.DWORD, hTemplateFile: ?windows.HANDLE) callconv(.winapi) windows.HANDLE;
extern "kernel32" fn CreateDirectoryW(lpPathName: windows.LPCWSTR, lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES) callconv(.winapi) c_int;
extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;
