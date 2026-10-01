//! The macOS backend of `KeychainTokenStorage`: generic password items of Keychain Services in
//! the default keychain of the user. The backend loads the Security and CoreFoundation
//! frameworks at run time with `std.DynLib`. Thus a build for macOS needs no SDK of Apple, and
//! a cross-compilation works.
//!
//! An item has the attributes `kSecAttrService` (the service of the options) and
//! `kSecAttrAccount` (the name of the key, a hash). Its data is the serialized record. The
//! keychain gives access to the item without a prompt only to the program that created it.
const std = @import("std");
const Allocator = std.mem.Allocator;
const token_storage = @import("../token_storage.zig");
const Error = token_storage.TokenStorage.Error;
const Key = token_storage.Key;

const log = std.log.scoped(.mcp_keychain);

const CFTypeRef = *const anyopaque;
const CFIndex = isize;
const CFTypeID = usize;
const OSStatus = i32;
const kCFStringEncodingUTF8: u32 = 0x08000100;

const errSecSuccess: OSStatus = 0;
const errSecUserCanceled: OSStatus = -128;
const errSecNotAvailable: OSStatus = -25291;
const errSecAuthFailed: OSStatus = -25293;
const errSecNoSuchKeychain: OSStatus = -25294;
const errSecDuplicateItem: OSStatus = -25299;
const errSecItemNotFound: OSStatus = -25300;
const errSecInteractionNotAllowed: OSStatus = -25308;
const errSecMissingEntitlement: OSStatus = -34018;

pub const core_foundation_path = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
pub const security_path = "/System/Library/Frameworks/Security.framework/Security";

/// The functions and the constants of the two frameworks.
pub const Api = struct {
    core_foundation: std.DynLib,
    security: std.DynLib,

    CFRelease: *const fn (CFTypeRef) callconv(.c) void,
    CFGetTypeID: *const fn (CFTypeRef) callconv(.c) CFTypeID,
    CFDataGetTypeID: *const fn () callconv(.c) CFTypeID,
    CFDataCreate: *const fn (?*const anyopaque, [*]const u8, CFIndex) callconv(.c) ?CFTypeRef,
    CFDataGetLength: *const fn (CFTypeRef) callconv(.c) CFIndex,
    CFDataGetBytePtr: *const fn (CFTypeRef) callconv(.c) [*]const u8,
    CFStringCreateWithBytes: *const fn (?*const anyopaque, [*]const u8, CFIndex, u32, u8) callconv(.c) ?CFTypeRef,
    CFDictionaryCreate: *const fn (?*const anyopaque, [*]const CFTypeRef, [*]const CFTypeRef, CFIndex, *const anyopaque, *const anyopaque) callconv(.c) ?CFTypeRef,
    SecItemAdd: *const fn (CFTypeRef, ?*?CFTypeRef) callconv(.c) OSStatus,
    SecItemCopyMatching: *const fn (CFTypeRef, *?CFTypeRef) callconv(.c) OSStatus,
    SecItemUpdate: *const fn (CFTypeRef, CFTypeRef) callconv(.c) OSStatus,
    SecItemDelete: *const fn (CFTypeRef) callconv(.c) OSStatus,

    /// The dictionary callbacks are structures. The dictionary functions take their addresses.
    key_callbacks: *const anyopaque,
    value_callbacks: *const anyopaque,
    true_value: CFTypeRef,
    kSecClass: CFTypeRef,
    kSecClassGenericPassword: CFTypeRef,
    kSecAttrService: CFTypeRef,
    kSecAttrAccount: CFTypeRef,
    kSecAttrLabel: CFTypeRef,
    kSecValueData: CFTypeRef,
    kSecReturnData: CFTypeRef,
    kSecMatchLimit: CFTypeRef,
    kSecMatchLimitOne: CFTypeRef,

    const functions = .{
        .{ "CFRelease", false },               .{ "CFGetTypeID", false },        .{ "CFDataGetTypeID", false },
        .{ "CFDataCreate", false },            .{ "CFDataGetLength", false },    .{ "CFDataGetBytePtr", false },
        .{ "CFStringCreateWithBytes", false }, .{ "CFDictionaryCreate", false }, .{ "SecItemAdd", true },
        .{ "SecItemCopyMatching", true },      .{ "SecItemUpdate", true },       .{ "SecItemDelete", true },
    };
    const constants = .{
        "kSecClass",     "kSecClassGenericPassword", "kSecAttrService", "kSecAttrAccount",   "kSecAttrLabel",
        "kSecValueData", "kSecReturnData",           "kSecMatchLimit",  "kSecMatchLimitOne",
    };

    /// Load the frameworks. A host without them gives `error.KeychainUnavailable`.
    pub fn load() Error!Api {
        var api: Api = undefined;
        api.core_foundation = std.DynLib.open(core_foundation_path) catch return unavailable(core_foundation_path);
        errdefer api.core_foundation.close();
        api.security = std.DynLib.open(security_path) catch return unavailable(security_path);
        errdefer api.security.close();
        inline for (functions) |f| {
            const lib = if (f[1]) &api.security else &api.core_foundation;
            @field(api, f[0]) = lib.lookup(@FieldType(Api, f[0]), f[0]) orelse return unavailable(f[0]);
        }
        api.key_callbacks = api.core_foundation.lookup(*const anyopaque, "kCFTypeDictionaryKeyCallBacks") orelse return unavailable("kCFTypeDictionaryKeyCallBacks");
        api.value_callbacks = api.core_foundation.lookup(*const anyopaque, "kCFTypeDictionaryValueCallBacks") orelse return unavailable("kCFTypeDictionaryValueCallBacks");
        // A constant of a framework is a variable that holds a reference.
        api.true_value = (api.core_foundation.lookup(*const CFTypeRef, "kCFBooleanTrue") orelse return unavailable("kCFBooleanTrue")).*;
        inline for (constants) |name| {
            @field(api, name) = (api.security.lookup(*const CFTypeRef, name) orelse return unavailable(name)).*;
        }
        return api;
    }

    pub fn close(self: *Api) void {
        self.security.close();
        self.core_foundation.close();
    }

    fn string(self: *const Api, text: []const u8) Error!CFTypeRef {
        return self.CFStringCreateWithBytes(null, text.ptr, @intCast(text.len), kCFStringEncodingUTF8, 0) orelse error.OutOfMemory;
    }

    fn data(self: *const Api, bytes: []const u8) Error!CFTypeRef {
        return self.CFDataCreate(null, bytes.ptr, @intCast(bytes.len)) orelse error.OutOfMemory;
    }

    fn dictionary(self: *const Api, keys: []const CFTypeRef, values: []const CFTypeRef) Error!CFTypeRef {
        std.debug.assert(keys.len == values.len);
        return self.CFDictionaryCreate(null, keys.ptr, values.ptr, @intCast(keys.len), self.key_callbacks, self.value_callbacks) orelse error.OutOfMemory;
    }
};

fn unavailable(what: []const u8) Error {
    log.info("Keychain Services are not available: {s}", .{what});
    return error.KeychainUnavailable;
}

/// The query attributes of the item of `account`.
const Query = struct {
    api: *const Api,
    service: CFTypeRef,
    account: CFTypeRef,

    fn init(api: *const Api, service: []const u8, account: []const u8) Error!Query {
        const s = try api.string(service);
        errdefer api.CFRelease(s);
        return .{ .api = api, .service = s, .account = try api.string(account) };
    }

    fn deinit(self: Query) void {
        self.api.CFRelease(self.service);
        self.api.CFRelease(self.account);
    }

    /// A dictionary with the class, the service and the account, and then `keys` and `values`.
    fn with(self: Query, keys: []const CFTypeRef, values: []const CFTypeRef) Error!CFTypeRef {
        var k: [8]CFTypeRef = undefined;
        var v: [8]CFTypeRef = undefined;
        k[0..3].* = .{ self.api.kSecClass, self.api.kSecAttrService, self.api.kSecAttrAccount };
        v[0..3].* = .{ self.api.kSecClassGenericPassword, self.service, self.account };
        @memcpy(k[3..][0..keys.len], keys);
        @memcpy(v[3..][0..values.len], values);
        return self.api.dictionary(k[0 .. 3 + keys.len], v[0 .. 3 + values.len]);
    }
};

/// Make sure that the keychain answers. A missing item is the expected answer.
pub fn probe(api: *const Api, service: []const u8) Error!void {
    const query = try Query.init(api, service, "probe");
    defer query.deinit();
    const dict = try query.with(&.{}, &.{});
    defer api.CFRelease(dict);
    var result: ?CFTypeRef = null;
    const status = api.SecItemCopyMatching(dict, &result);
    if (result) |r| api.CFRelease(r);
    if (status != errSecSuccess and status != errSecItemNotFound) return statusError("SecItemCopyMatching", status);
}

pub fn load(api: *const Api, gpa: Allocator, service: []const u8, key: Key) Error!?[]u8 {
    const name = key.name();
    const query = try Query.init(api, service, &name);
    defer query.deinit();
    const dict = try query.with(&.{ api.kSecReturnData, api.kSecMatchLimit }, &.{ api.true_value, api.kSecMatchLimitOne });
    defer api.CFRelease(dict);
    var result: ?CFTypeRef = null;
    const status = api.SecItemCopyMatching(dict, &result);
    if (status == errSecItemNotFound) return null;
    if (status != errSecSuccess) return statusError("SecItemCopyMatching", status);
    const value = result orelse return error.StorageFailed;
    defer api.CFRelease(value);
    if (api.CFGetTypeID(value) != api.CFDataGetTypeID()) return error.StorageFailed;
    const len: usize = @intCast(api.CFDataGetLength(value));
    return try gpa.dupe(u8, api.CFDataGetBytePtr(value)[0..len]);
}

pub fn save(api: *const Api, service: []const u8, key: Key, record: []const u8) Error!void {
    const name = key.name();
    const query = try Query.init(api, service, &name);
    defer query.deinit();
    const value = try api.data(record);
    defer api.CFRelease(value);
    var label_buf: [256]u8 = undefined;
    const label = std.fmt.bufPrint(&label_buf, "{s}: MCP authorization", .{service}) catch "MCP authorization";
    const label_ref = try api.string(label);
    defer api.CFRelease(label_ref);

    const match = try query.with(&.{}, &.{});
    defer api.CFRelease(match);
    const changes = try api.dictionary(&.{ api.kSecValueData, api.kSecAttrLabel }, &.{ value, label_ref });
    defer api.CFRelease(changes);
    var status = api.SecItemUpdate(match, changes);
    if (status == errSecItemNotFound) {
        const item = try query.with(&.{ api.kSecValueData, api.kSecAttrLabel }, &.{ value, label_ref });
        defer api.CFRelease(item);
        status = api.SecItemAdd(item, null);
        // Another process added the item between the two calls.
        if (status == errSecDuplicateItem) status = api.SecItemUpdate(match, changes);
    }
    if (status != errSecSuccess) return statusError("SecItemAdd", status);
}

pub fn delete(api: *const Api, service: []const u8, key: Key) Error!void {
    const name = key.name();
    const query = try Query.init(api, service, &name);
    defer query.deinit();
    const match = try query.with(&.{}, &.{});
    defer api.CFRelease(match);
    const status = api.SecItemDelete(match);
    if (status != errSecSuccess and status != errSecItemNotFound) return statusError("SecItemDelete", status);
}

fn statusError(comptime function: []const u8, status: OSStatus) Error {
    switch (status) {
        errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled => return error.KeychainLocked,
        errSecNotAvailable, errSecNoSuchKeychain, errSecMissingEntitlement => return error.KeychainUnavailable,
        else => {
            log.warn(function ++ " gave the status {d}", .{status});
            return error.StorageFailed;
        },
    }
}
