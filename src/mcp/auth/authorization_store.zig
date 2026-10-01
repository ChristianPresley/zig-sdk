//! The storage of the authorization server: clients, authorization codes, refresh tokens and the
//! `jti` values of client assertions and authorization grants. `Store` is an interface, so an
//! application can keep the records in a database. `MemoryStore` keeps them in memory with
//! limits and expiry.
//!
//! The store never holds a client secret, an authorization code or a refresh token. It holds
//! their SHA-256 hashes. The server compares the hashes in constant time.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// The SHA-256 hash of a secret value: a client secret, a code or a refresh token.
pub const Hash = [Sha256.digest_length]u8;

/// The identifier of a grant family: the authorization code and all refresh tokens that come
/// from it.
pub const FamilyId = [16]u8;

/// The SHA-256 hash of `secret`.
pub fn hashSecret(secret: []const u8) Hash {
    var out: Hash = undefined;
    Sha256.hash(secret, &out, .{});
    return out;
}

/// True when the hash of `secret` is `expected`. The comparison takes constant time.
pub fn secretMatches(expected: Hash, secret: []const u8) bool {
    return std.crypto.timing_safe.eql(Hash, expected, hashSecret(secret));
}

/// How a client authenticates at the token endpoint.
pub const AuthMethod = enum {
    /// A public client. It sends only its `client_id`.
    none,
    client_secret_basic,
    client_secret_post,
    /// A JWT assertion that a key of the client signs (RFC 7523 section 2.2).
    private_key_jwt,

    /// True for the methods with a client secret.
    pub fn hasSecret(self: AuthMethod) bool {
        return self == .client_secret_basic or self == .client_secret_post;
    }
};

/// The grant types that a client can use.
pub const GrantTypes = struct {
    authorization_code: bool = false,
    refresh_token: bool = false,
    client_credentials: bool = false,
    /// `urn:ietf:params:oauth:grant-type:jwt-bearer`: ID-JAGs and workload JWTs.
    jwt_bearer: bool = false,
};

/// A registered client.
pub const Client = struct {
    client_id: []const u8,
    auth_method: AuthMethod = .none,
    /// The SHA-256 hash of the client secret. Only the methods with a secret have one.
    secret_hash: ?Hash = null,
    redirect_uris: []const []const u8 = &.{},
    grant_types: GrantTypes = .{ .authorization_code = true, .refresh_token = true },
    /// The scopes that the client can get. Empty permits each scope of the server.
    scopes: []const []const u8 = &.{},
    /// The keys of `private_key_jwt`: a JWK set as JSON text.
    jwks: ?[]const u8 = null,
    /// The keys of `private_key_jwt`: the https URL of a JWK set.
    jwks_uri: ?[]const u8 = null,
    client_name: ?[]const u8 = null,
    /// Refuse token requests of the client without a DPoP proof (RFC 9449 section 5.2).
    dpop_bound_access_tokens: bool = false,
    /// The Unix seconds of the registration.
    issued_at: i64 = 0,
};

/// An authorization code. The store keys it by the hash of the code.
pub const CodeRecord = struct {
    client_id: []const u8,
    /// The redirect URI of the authorization response.
    redirect_uri: []const u8,
    /// The authorization request had a `redirect_uri` parameter. Then the token request must
    /// send the same value (RFC 6749 section 4.1.3).
    redirect_uri_given: bool,
    /// The PKCE challenge, S256 only.
    code_challenge: []const u8,
    resource: []const u8,
    /// The granted scopes, separated by spaces.
    scope: []const u8,
    subject: []const u8,
    /// The `dpop_jkt` of the authorization request (RFC 9449 section 10).
    dpop_jkt: ?[]const u8 = null,
    family: FamilyId,
    /// The Unix seconds of the authentication of the user.
    auth_time: i64,
    expires_at: i64,
};

/// A refresh token. The store keys it by the hash of the token.
pub const RefreshRecord = struct {
    client_id: []const u8,
    subject: []const u8,
    /// The scopes of the grant, separated by spaces. A refresh request can ask for fewer.
    scope: []const u8,
    resource: []const u8,
    /// The thumbprint of the DPoP key of a public client. A refresh request needs a proof
    /// with this key.
    dpop_jkt: ?[]const u8 = null,
    family: FamilyId,
    auth_time: i64,
    /// A rotation keeps this time. Thus a grant family has a fixed lifetime.
    expires_at: i64,
};

/// The state of a code or a refresh token before a call of `take`.
pub const TokenState = enum {
    /// Not used before. The call of `take` marks it as used.
    active,
    /// Used before: a replay.
    used,
    /// Revoked with its family.
    revoked,
};

pub fn Taken(comptime T: type) type {
    return struct { record: T, state: TokenState };
}

pub const Error = error{
    OutOfMemory,
    /// The store is full of records that did not expire.
    StoreFull,
    /// The store failed, for example a database is not available.
    StoreFailed,
    /// The store revoked the family of the refresh token.
    FamilyRevoked,
};

/// The interface of a store. All functions are safe to call from more than one task. The
/// records that a function returns are copies in `arena`. `now` is the time in Unix seconds:
/// a store can remove the records that expired before it.
pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        get_client: *const fn (ptr: *anyopaque, arena: Allocator, client_id: []const u8) Error!?Client,
        /// Add a client, or replace the client with the same `client_id`.
        put_client: *const fn (ptr: *anyopaque, client: *const Client) Error!void,
        put_code: *const fn (ptr: *anyopaque, hash: *const Hash, record: *const CodeRecord, now: i64) Error!void,
        /// Find a code that did not expire and mark it as used. The state tells if it was
        /// used before. The store keeps a used code until it expires.
        take_code: *const fn (ptr: *anyopaque, arena: Allocator, hash: *const Hash, now: i64) Error!?Taken(CodeRecord),
        put_refresh_token: *const fn (ptr: *anyopaque, hash: *const Hash, record: *const RefreshRecord, now: i64) Error!void,
        /// Find a refresh token that did not expire and mark it as used. The state tells if it
        /// was used or revoked before. The store keeps a used token until it expires.
        take_refresh_token: *const fn (ptr: *anyopaque, arena: Allocator, hash: *const Hash, now: i64) Error!?Taken(RefreshRecord),
        /// Revoke all refresh tokens of a family, and refuse new tokens of the family.
        revoke_family: *const fn (ptr: *anyopaque, family: *const FamilyId, now: i64) Error!void,
        /// Record a `jti` until `expires_at`. Return false when the store has it already.
        record_jti: *const fn (ptr: *anyopaque, key: *const Hash, expires_at: i64, now: i64) Error!bool,
    };

    pub fn getClient(self: Store, arena: Allocator, client_id: []const u8) Error!?Client {
        return self.vtable.get_client(self.ptr, arena, client_id);
    }

    pub fn putClient(self: Store, client: *const Client) Error!void {
        return self.vtable.put_client(self.ptr, client);
    }

    pub fn putCode(self: Store, hash: *const Hash, record: *const CodeRecord, now: i64) Error!void {
        return self.vtable.put_code(self.ptr, hash, record, now);
    }

    pub fn takeCode(self: Store, arena: Allocator, hash: *const Hash, now: i64) Error!?Taken(CodeRecord) {
        return self.vtable.take_code(self.ptr, arena, hash, now);
    }

    pub fn putRefreshToken(self: Store, hash: *const Hash, record: *const RefreshRecord, now: i64) Error!void {
        return self.vtable.put_refresh_token(self.ptr, hash, record, now);
    }

    pub fn takeRefreshToken(self: Store, arena: Allocator, hash: *const Hash, now: i64) Error!?Taken(RefreshRecord) {
        return self.vtable.take_refresh_token(self.ptr, arena, hash, now);
    }

    pub fn revokeFamily(self: Store, family: *const FamilyId, now: i64) Error!void {
        return self.vtable.revoke_family(self.ptr, family, now);
    }

    /// Record the `jti` of `issuer` until `expires_at`. Return false for a replay.
    pub fn recordJti(self: Store, issuer: []const u8, jti: []const u8, expires_at: i64, now: i64) Error!bool {
        var h = Sha256.init(.{});
        h.update(issuer);
        h.update(&.{0});
        h.update(jti);
        const key = h.finalResult();
        return self.vtable.record_jti(self.ptr, &key, expires_at, now);
    }
};

/// A copy of a value with all slices in its own arena.
fn Owned(comptime T: type) type {
    return struct {
        state: std.heap.ArenaAllocator.State,
        value: T,

        fn init(gpa: Allocator, value: *const T) Allocator.Error!@This() {
            var arena: std.heap.ArenaAllocator = .init(gpa);
            errdefer arena.deinit();
            const copy = try clone(T, arena.allocator(), value.*);
            return .{ .state = arena.state, .value = copy };
        }

        fn deinit(self: *@This(), gpa: Allocator) void {
            self.state.promote(gpa).deinit();
        }
    };
}

/// A copy of `value` with each string and string list in `arena`.
pub fn clone(comptime T: type, arena: Allocator, value: T) Allocator.Error!T {
    var out = value;
    inline for (@typeInfo(T).@"struct".fields) |f| {
        switch (f.type) {
            []const u8 => @field(out, f.name) = try arena.dupe(u8, @field(value, f.name)),
            ?[]const u8 => if (@field(value, f.name)) |s| {
                @field(out, f.name) = try arena.dupe(u8, s);
            },
            []const []const u8 => {
                const list = @field(value, f.name);
                const copy = try arena.alloc([]const u8, list.len);
                for (list, copy) |s, *d| d.* = try arena.dupe(u8, s);
                @field(out, f.name) = copy;
            },
            else => {},
        }
    }
    return out;
}

/// The limits of a `MemoryStore`.
pub const Limits = struct {
    max_clients: usize = 10_000,
    max_codes: usize = 10_000,
    max_refresh_tokens: usize = 100_000,
    max_jti: usize = 100_000,
};

/// A store in memory. It loses its records at the end of the process. Each map has a limit. When
/// a map is full, the store removes the expired records. When no record expired, the store
/// refuses the new record with `error.StoreFull`.
pub const MemoryStore = struct {
    io: Io,
    gpa: Allocator,
    limits: Limits,
    lock: Io.Mutex = .init,
    clients: std.StringHashMapUnmanaged(Owned(Client)) = .empty,
    codes: std.AutoHashMapUnmanaged(Hash, CodeEntry) = .empty,
    refresh_tokens: std.AutoHashMapUnmanaged(Hash, RefreshEntry) = .empty,
    jtis: std.AutoHashMapUnmanaged(Hash, i64) = .empty,
    /// The revoked families and the time until which the revocation applies.
    revoked: std.AutoHashMapUnmanaged(FamilyId, i64) = .empty,

    const CodeEntry = struct { owned: Owned(CodeRecord), used: bool = false };
    const RefreshEntry = struct { owned: Owned(RefreshRecord), state: TokenState = .active };

    pub fn init(io: Io, gpa: Allocator, limits: Limits) MemoryStore {
        return .{ .io = io, .gpa = gpa, .limits = limits };
    }

    pub fn deinit(self: *MemoryStore) void {
        var ci = self.clients.valueIterator();
        while (ci.next()) |v| v.deinit(self.gpa);
        self.clients.deinit(self.gpa);
        var it = self.codes.valueIterator();
        while (it.next()) |v| v.owned.deinit(self.gpa);
        self.codes.deinit(self.gpa);
        var rt = self.refresh_tokens.valueIterator();
        while (rt.next()) |v| v.owned.deinit(self.gpa);
        self.refresh_tokens.deinit(self.gpa);
        self.jtis.deinit(self.gpa);
        self.revoked.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn store(self: *MemoryStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Store.VTable = .{
        .get_client = getClient,
        .put_client = putClient,
        .put_code = putCode,
        .take_code = takeCode,
        .put_refresh_token = putRefreshToken,
        .take_refresh_token = takeRefreshToken,
        .revoke_family = revokeFamily,
        .record_jti = recordJti,
    };

    fn cast(ptr: *anyopaque) *MemoryStore {
        return @ptrCast(@alignCast(ptr));
    }

    fn getClient(ptr: *anyopaque, arena: Allocator, client_id: []const u8) Error!?Client {
        const self = cast(ptr);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const entry = self.clients.get(client_id) orelse return null;
        return try clone(Client, arena, entry.value);
    }

    fn putClient(ptr: *anyopaque, client: *const Client) Error!void {
        const self = cast(ptr);
        var owned: Owned(Client) = try .init(self.gpa, client);
        errdefer owned.deinit(self.gpa);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.clients.getPtr(client.client_id)) |existing| {
            var old = existing.*;
            // The key is the `client_id` of the value, so it changes with the value.
            const key_ptr = self.clients.getKeyPtr(client.client_id).?;
            existing.* = owned;
            key_ptr.* = owned.value.client_id;
            old.deinit(self.gpa);
            return;
        }
        if (self.clients.count() >= self.limits.max_clients) return error.StoreFull;
        try self.clients.put(self.gpa, owned.value.client_id, owned);
    }

    fn putCode(ptr: *anyopaque, hash: *const Hash, record: *const CodeRecord, now: i64) Error!void {
        const self = cast(ptr);
        var owned: Owned(CodeRecord) = try .init(self.gpa, record);
        errdefer owned.deinit(self.gpa);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.codes.count() >= self.limits.max_codes) self.purgeCodes(now);
        if (self.codes.count() >= self.limits.max_codes) return error.StoreFull;
        const gop = try self.codes.getOrPut(self.gpa, hash.*);
        if (gop.found_existing) gop.value_ptr.owned.deinit(self.gpa);
        gop.value_ptr.* = .{ .owned = owned };
    }

    fn takeCode(ptr: *anyopaque, arena: Allocator, hash: *const Hash, now: i64) Error!?Taken(CodeRecord) {
        const self = cast(ptr);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const entry = self.codes.getPtr(hash.*) orelse return null;
        if (entry.owned.value.expires_at < now) return null;
        const state: TokenState = if (entry.used) .used else .active;
        entry.used = true;
        return .{ .record = try clone(CodeRecord, arena, entry.owned.value), .state = state };
    }

    fn putRefreshToken(ptr: *anyopaque, hash: *const Hash, record: *const RefreshRecord, now: i64) Error!void {
        const self = cast(ptr);
        var owned: Owned(RefreshRecord) = try .init(self.gpa, record);
        errdefer owned.deinit(self.gpa);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.revoked.get(record.family) != null) return error.FamilyRevoked;
        if (self.refresh_tokens.count() >= self.limits.max_refresh_tokens) self.purgeRefreshTokens(now, false);
        // The used tokens serve the reuse detection only. When the map is full, they go first.
        if (self.refresh_tokens.count() >= self.limits.max_refresh_tokens) self.purgeRefreshTokens(now, true);
        if (self.refresh_tokens.count() >= self.limits.max_refresh_tokens) return error.StoreFull;
        const gop = try self.refresh_tokens.getOrPut(self.gpa, hash.*);
        if (gop.found_existing) gop.value_ptr.owned.deinit(self.gpa);
        gop.value_ptr.* = .{ .owned = owned };
    }

    fn takeRefreshToken(ptr: *anyopaque, arena: Allocator, hash: *const Hash, now: i64) Error!?Taken(RefreshRecord) {
        const self = cast(ptr);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        const entry = self.refresh_tokens.getPtr(hash.*) orelse return null;
        if (entry.owned.value.expires_at < now) return null;
        const state = entry.state;
        if (state == .active) entry.state = .used;
        return .{ .record = try clone(RefreshRecord, arena, entry.owned.value), .state = state };
    }

    fn revokeFamily(ptr: *anyopaque, family: *const FamilyId, now: i64) Error!void {
        const self = cast(ptr);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        var until: i64 = now;
        var it = self.refresh_tokens.valueIterator();
        while (it.next()) |entry| {
            if (!std.mem.eql(u8, &entry.owned.value.family, family)) continue;
            entry.state = .revoked;
            until = @max(until, entry.owned.value.expires_at);
        }
        var codes = self.codes.valueIterator();
        while (codes.next()) |entry| {
            if (!std.mem.eql(u8, &entry.owned.value.family, family)) continue;
            entry.used = true;
        }
        // Refuse new tokens of the family: a token request can run at the same time.
        if (self.revoked.count() >= self.limits.max_refresh_tokens) self.purgeRevoked(now);
        const gop = try self.revoked.getOrPut(self.gpa, family.*);
        gop.value_ptr.* = if (gop.found_existing) @max(gop.value_ptr.*, until) else until;
    }

    fn recordJti(ptr: *anyopaque, key: *const Hash, expires_at: i64, now: i64) Error!bool {
        const self = cast(ptr);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        if (self.jtis.get(key.*)) |until| {
            if (until >= now) return false;
        }
        if (self.jtis.count() >= self.limits.max_jti) self.purgeJtis(now);
        if (self.jtis.count() >= self.limits.max_jti) return error.StoreFull;
        try self.jtis.put(self.gpa, key.*, expires_at);
        return true;
    }

    fn purgeCodes(self: *MemoryStore, now: i64) void {
        // A removal leaves a tombstone and moves no entry, so the iteration can go on.
        var it = self.codes.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.owned.value.expires_at >= now) continue;
            kv.value_ptr.owned.deinit(self.gpa);
            _ = self.codes.remove(kv.key_ptr.*);
        }
    }

    /// Remove the expired tokens. With `used`, also remove the used and revoked tokens.
    fn purgeRefreshTokens(self: *MemoryStore, now: i64, used: bool) void {
        var it = self.refresh_tokens.iterator();
        while (it.next()) |kv| {
            const gone = kv.value_ptr.owned.value.expires_at < now or (used and kv.value_ptr.state != .active);
            if (!gone) continue;
            kv.value_ptr.owned.deinit(self.gpa);
            _ = self.refresh_tokens.remove(kv.key_ptr.*);
        }
    }

    fn purgeJtis(self: *MemoryStore, now: i64) void {
        var it = self.jtis.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.* >= now) continue;
            _ = self.jtis.remove(kv.key_ptr.*);
        }
    }

    fn purgeRevoked(self: *MemoryStore, now: i64) void {
        var it = self.revoked.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.* >= now) continue;
            _ = self.revoked.remove(kv.key_ptr.*);
        }
    }
};

test "the memory store: codes are single use and expire" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mem: MemoryStore = .init(std.testing.io, gpa, .{ .max_codes = 2 });
    defer mem.deinit();
    const s = mem.store();
    const record: CodeRecord = .{
        .client_id = "c1",
        .redirect_uri = "http://127.0.0.1/cb",
        .redirect_uri_given = true,
        .code_challenge = "x",
        .resource = "https://rs.example/mcp",
        .scope = "mcp:read",
        .subject = "alice",
        .family = @splat(1),
        .auth_time = 1000,
        .expires_at = 1060,
    };
    const h1 = hashSecret("code-1");
    try s.putCode(&h1, &record, 1000);
    const first = (try s.takeCode(arena, &h1, 1010)).?;
    try std.testing.expectEqual(TokenState.active, first.state);
    try std.testing.expectEqualStrings("alice", first.record.subject);
    try std.testing.expectEqual(TokenState.used, (try s.takeCode(arena, &h1, 1010)).?.state);
    // An expired code does not count.
    try std.testing.expect((try s.takeCode(arena, &h1, 1061)) == null);
    // The map is full of codes that did not expire, then the expired ones go.
    const h2 = hashSecret("code-2");
    const h3 = hashSecret("code-3");
    try s.putCode(&h2, &record, 1000);
    try std.testing.expectError(error.StoreFull, s.putCode(&h3, &record, 1000));
    try s.putCode(&h3, &record, 2000);
    try std.testing.expect((try s.takeCode(arena, &h3, 1050)) != null);
}

test "the memory store: refresh tokens, family revocation and jti values" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var mem: MemoryStore = .init(std.testing.io, gpa, .{ .max_jti = 1, .max_refresh_tokens = 3 });
    defer mem.deinit();
    const s = mem.store();
    const family: FamilyId = @splat(7);
    const record: RefreshRecord = .{ .client_id = "c1", .subject = "alice", .scope = "a b", .resource = "https://rs.example/mcp", .family = family, .auth_time = 1, .expires_at = 5000 };
    const a = hashSecret("rt-a");
    const b = hashSecret("rt-b");
    try s.putRefreshToken(&a, &record, 1000);
    try s.putRefreshToken(&b, &record, 1000);
    try std.testing.expectEqual(TokenState.active, (try s.takeRefreshToken(arena, &a, 1000)).?.state);
    try std.testing.expectEqual(TokenState.used, (try s.takeRefreshToken(arena, &a, 1000)).?.state);
    try s.revokeFamily(&family, 1000);
    try std.testing.expectEqual(TokenState.revoked, (try s.takeRefreshToken(arena, &b, 1000)).?.state);
    // A revoked family gets no new token.
    const c = hashSecret("rt-c");
    try std.testing.expectError(error.FamilyRevoked, s.putRefreshToken(&c, &record, 1000));
    // A full map removes the used and revoked tokens before it refuses a new token.
    var other = record;
    other.family = @splat(8);
    const d = hashSecret("rt-d");
    const e = hashSecret("rt-e");
    const f = hashSecret("rt-f");
    try s.putRefreshToken(&d, &other, 1000);
    try s.putRefreshToken(&e, &other, 1000);
    try std.testing.expect((try s.takeRefreshToken(arena, &a, 1000)) == null);
    try std.testing.expectEqual(TokenState.active, (try s.takeRefreshToken(arena, &d, 1000)).?.state);
    try s.putRefreshToken(&f, &other, 1000);
    // The used token d goes. Then the map has e, f and a, and no token is used.
    try s.putRefreshToken(&a, &other, 1000);
    try std.testing.expect((try s.takeRefreshToken(arena, &d, 1000)) == null);
    const g = hashSecret("rt-g");
    try std.testing.expectError(error.StoreFull, s.putRefreshToken(&g, &other, 1000));

    try std.testing.expect(try s.recordJti("https://idp.example", "j1", 2000, 1000));
    try std.testing.expect(!try s.recordJti("https://idp.example", "j1", 2000, 1500));
    try std.testing.expectError(error.StoreFull, s.recordJti("https://idp.example", "j2", 2000, 1500));
    // After the expiry, the store forgets the first value.
    try std.testing.expect(try s.recordJti("https://idp.example", "j2", 3000, 2001));

    // Clients: a new registration with the same id replaces the old one.
    try s.putClient(&.{ .client_id = "c1", .redirect_uris = &.{"http://127.0.0.1/cb"} });
    try s.putClient(&.{ .client_id = "c1", .client_name = "second" });
    const got = (try s.getClient(arena, "c1")).?;
    try std.testing.expectEqualStrings("second", got.client_name.?);
    try std.testing.expectEqual(0, got.redirect_uris.len);
    try std.testing.expect((try s.getClient(arena, "c2")) == null);
    try std.testing.expect(secretMatches(hashSecret("s3cret"), "s3cret"));
    try std.testing.expect(!secretMatches(hashSecret("s3cret"), "s3cret!"));
}
