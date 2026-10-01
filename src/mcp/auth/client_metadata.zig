//! The documents that the authorization server gets from the URLs of clients: client ID
//! metadata documents (CIMD) and the JWK sets of `jwks_uri`.
//!
//! The fetcher protects the network of the server from server-side request forgery. It accepts
//! https URLs only. It resolves the host name, refuses loopback, private, link-local and other
//! special addresses, and connects to an address that it checked. Thus a second answer of the
//! DNS cannot move the request to another address. It does not follow redirects, and it limits
//! the size of each document. The documents stay in a cache with the lifetime of their
//! `Cache-Control` header.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = std.http;
const json = @import("../json.zig");
const common = @import("common.zig");
const jwt = @import("jwt.zig");
const store_mod = @import("authorization_store.zig");

const log = std.log.scoped(.mcp_auth);

/// Decides if the server fetches a document from a URL, for example with an allow list of
/// domains.
pub const Policy = struct {
    userdata: ?*anyopaque = null,
    /// Return true when the server can fetch the document at `url`.
    allow: *const fn (userdata: ?*anyopaque, url: []const u8) bool,
};

pub const Options = struct {
    /// Accept loopback and private addresses. Tests only.
    allow_private_addresses: bool = false,
    /// Trust only the CA certificates of this PEM file. Null uses the CA store of the system.
    ca_file: ?[]const u8 = null,
    /// The largest client ID metadata document. The draft recommends 5 KiB.
    max_document_bytes: usize = 5 * 1024,
    /// The largest JWK set of `jwks_uri`.
    max_jwks_bytes: usize = 64 * 1024,
    /// The cache lifetime of a document without a `max-age`.
    cache_seconds: i64 = 300,
    /// The longest cache lifetime, also for a larger `max-age`.
    max_cache_seconds: i64 = 86_400,
    /// The largest number of documents in the cache.
    max_entries: usize = 1024,
    /// The time limit of one fetch, from the name lookup to the end of the body.
    timeout_seconds: i64 = 10,
    policy: ?Policy = null,
};

pub const FetchError = error{
    OutOfMemory,
    /// The URL does not use https, has user information or a fragment, or the policy refuses it.
    NotPermitted,
    /// The host has a loopback, private or other special address.
    PrivateAddress,
    /// The host name did not resolve, the connection failed, or the status is not 200.
    FetchFailed,
    /// The document is larger than the limit.
    TooLarge,
};

/// Fetches documents from the URLs of clients. All functions are safe to call from more than
/// one task.
pub const Fetcher = struct {
    io: Io,
    gpa: Allocator,
    options: Options,
    http_client: http.Client,
    /// The CA certificates are in the HTTP client.
    ready: bool = false,
    setup_lock: Io.Mutex = .init,
    cache_lock: Io.Mutex = .init,
    cache: std.StringHashMapUnmanaged(Entry) = .empty,

    const Entry = struct { body: []u8, expires_at: i64 };

    pub fn init(io: Io, gpa: Allocator, options: Options) Fetcher {
        return .{ .io = io, .gpa = gpa, .options = options, .http_client = .{ .allocator = gpa, .io = io } };
    }

    pub fn deinit(self: *Fetcher) void {
        var it = self.cache.iterator();
        while (it.next()) |kv| {
            self.gpa.free(kv.key_ptr.*);
            self.gpa.free(kv.value_ptr.body);
        }
        self.cache.deinit(self.gpa);
        self.http_client.deinit();
        self.* = undefined;
    }

    /// The document at `url`, from the cache or from the network, copied into `arena`.
    /// `max_bytes` limits its size. `now` is the time in Unix seconds.
    pub fn get(self: *Fetcher, arena: Allocator, url: []const u8, max_bytes: usize, now: i64) FetchError![]const u8 {
        if (try self.cached(arena, url, now)) |body| return body;
        const doc = try self.downloadInTime(arena, url, max_bytes);
        const lifetime: i64 = if (doc.no_store) 0 else @min(doc.max_age orelse self.options.cache_seconds, self.options.max_cache_seconds);
        if (lifetime > 0) self.remember(url, doc.body, now + lifetime) catch {};
        return doc.body;
    }

    fn cached(self: *Fetcher, arena: Allocator, url: []const u8, now: i64) Allocator.Error!?[]const u8 {
        self.cache_lock.lockUncancelable(self.io);
        defer self.cache_lock.unlock(self.io);
        const entry = self.cache.get(url) orelse return null;
        if (entry.expires_at <= now) return null;
        return try arena.dupe(u8, entry.body);
    }

    fn remember(self: *Fetcher, url: []const u8, body: []const u8, expires_at: i64) Allocator.Error!void {
        self.cache_lock.lockUncancelable(self.io);
        defer self.cache_lock.unlock(self.io);
        if (self.cache.getPtr(url)) |entry| {
            const copy = try self.gpa.dupe(u8, body);
            self.gpa.free(entry.body);
            entry.* = .{ .body = copy, .expires_at = expires_at };
            return;
        }
        if (self.cache.count() >= self.options.max_entries) self.evict();
        const key = try self.gpa.dupe(u8, url);
        errdefer self.gpa.free(key);
        const copy = try self.gpa.dupe(u8, body);
        errdefer self.gpa.free(copy);
        try self.cache.put(self.gpa, key, .{ .body = copy, .expires_at = expires_at });
    }

    /// Remove the entry that expires first.
    fn evict(self: *Fetcher) void {
        var it = self.cache.iterator();
        var oldest: ?*[]const u8 = null;
        var oldest_time: i64 = std.math.maxInt(i64);
        while (it.next()) |kv| if (kv.value_ptr.expires_at < oldest_time) {
            oldest_time = kv.value_ptr.expires_at;
            oldest = kv.key_ptr;
        };
        const key = (oldest orelse return).*;
        const body = self.cache.get(key).?.body;
        _ = self.cache.remove(key);
        self.gpa.free(key);
        self.gpa.free(body);
    }

    /// Load the CA certificates one time.
    fn prepare(self: *Fetcher) FetchError!void {
        self.setup_lock.lockUncancelable(self.io);
        defer self.setup_lock.unlock(self.io);
        if (self.ready) return;
        const now = Io.Clock.real.now(self.io);
        var bundle: std.crypto.Certificate.Bundle = .empty;
        errdefer bundle.deinit(self.gpa);
        if (self.options.ca_file) |path| {
            bundle.addCertsFromFilePath(self.gpa, self.io, now, Io.Dir.cwd(), path) catch |e| {
                log.warn("cannot load the CA file for client documents: {t}", .{e});
                return error.FetchFailed;
            };
        } else {
            bundle.rescan(self.gpa, self.io, now) catch |e| {
                log.warn("cannot load the CA store of the system: {t}", .{e});
                return error.FetchFailed;
            };
        }
        self.http_client.ca_bundle.deinit(self.gpa);
        self.http_client.ca_bundle = bundle;
        self.http_client.now = now;
        self.ready = true;
    }

    const Download = struct { body: []u8, max_age: ?i64 = null, no_store: bool = false };

    /// Download with the time limit of the options. A slow server cannot hold the task of a
    /// request of the authorization server.
    fn downloadInTime(self: *Fetcher, arena: Allocator, url: []const u8, max_bytes: usize) FetchError!Download {
        const Result = union(enum) { done: FetchError!Download, timer: Io.Cancelable!void };
        var buffer: [2]Result = undefined;
        var select: Io.Select(Result) = .init(self.io, &buffer);
        // Without a unit of concurrency, the download runs without a time limit.
        select.concurrent(.done, download, .{ self, arena, url, max_bytes }) catch return self.download(arena, url, max_bytes);
        defer select.cancelDiscard();
        select.concurrent(.timer, sleepSeconds, .{ self.io, self.options.timeout_seconds }) catch {};
        const first = select.await() catch return error.FetchFailed;
        return switch (first) {
            .done => |result| result,
            .timer => error.FetchFailed,
        };
    }

    fn sleepSeconds(io: Io, seconds: i64) Io.Cancelable!void {
        return io.sleep(.fromSeconds(seconds), .awake);
    }

    fn download(self: *Fetcher, arena: Allocator, url: []const u8, max_bytes: usize) FetchError!Download {
        const target = try checkUrl(url);
        if (self.options.policy) |p| if (!p.allow(p.userdata, url)) return error.NotPermitted;
        const addresses = try self.resolve(arena, target);
        try self.prepare();

        // Connect to a checked address. The TLS handshake and the certificate check use the name.
        const conn = for (addresses) |address| {
            var text_buf: [64]u8 = undefined;
            const text = addressText(&text_buf, address);
            break self.http_client.connectTcpOptions(.{
                .host = .{ .bytes = text },
                .port = target.port,
                .protocol = .tls,
                .proxied_host = .{ .bytes = target.host },
                .proxied_port = target.port,
            }) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
        } else return error.FetchFailed;

        var req = self.http_client.request(.GET, target.uri, .{
            .connection = conn,
            .keep_alive = false,
            .redirect_behavior = .unhandled,
            .headers = .{ .accept_encoding = .{ .override = "identity" } },
            .extra_headers = &.{.{ .name = "accept", .value = "application/json" }},
        }) catch return error.FetchFailed;
        defer req.deinit();
        req.sendBodiless() catch return error.FetchFailed;
        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch return error.FetchFailed;
        // The fetcher does not follow redirects: a redirect could go to an internal address.
        if (response.head.status != .ok) return error.FetchFailed;
        var out: Download = .{ .body = &.{} };
        var it = response.head.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "cache-control")) {
            parseCacheControl(h.value, &out);
        };
        if (response.head.content_length) |len| if (len > max_bytes) return error.TooLarge;
        var transfer: [4096]u8 = undefined;
        const reader = response.reader(&transfer);
        out.body = reader.allocRemaining(arena, .limited(max_bytes)) catch |e| switch (e) {
            error.StreamTooLong => return error.TooLarge,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.FetchFailed,
        };
        return out;
    }

    /// The addresses of the host, or `error.PrivateAddress` when one address is not public.
    fn resolve(self: *Fetcher, arena: Allocator, target: Target) FetchError![]const Io.net.IpAddress {
        if (Io.net.IpAddress.parse(target.host, target.port)) |address| {
            if (!self.options.allow_private_addresses and !isPublicAddress(address)) return error.PrivateAddress;
            const one = try arena.alloc(Io.net.IpAddress, 1);
            one[0] = address;
            return one;
        } else |_| {}
        const name = Io.net.HostName.init(target.host) catch return error.NotPermitted;
        var buffer: [32]Io.net.HostName.LookupResult = undefined;
        var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&buffer);
        var lookup = self.io.async(Io.net.HostName.lookup, .{ name, self.io, &queue, .{ .port = target.port } });
        defer lookup.cancel(self.io) catch {};
        var list: std.ArrayList(Io.net.IpAddress) = .empty;
        while (queue.getOne(self.io)) |result| switch (result) {
            .address => |a| if (list.items.len < 16) try list.append(arena, a),
            .canonical_name => continue,
        } else |err| switch (err) {
            error.Canceled => return error.FetchFailed,
            error.Closed => {},
        }
        lookup.await(self.io) catch return error.FetchFailed;
        if (list.items.len == 0) return error.FetchFailed;
        // IPv4 first: a server often listens on one family only.
        std.mem.sort(Io.net.IpAddress, list.items, {}, ip4First);
        // Refuse the host when one of its addresses is not public. A host with a mix of
        // addresses is a sign of DNS rebinding.
        if (!self.options.allow_private_addresses) for (list.items) |a| {
            if (!isPublicAddress(a)) return error.PrivateAddress;
        };
        return list.items;
    }
};

fn ip4First(_: void, a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    return a == .ip4 and b == .ip6;
}

fn parseCacheControl(value: []const u8, out: *Fetcher.Download) void {
    var it = std.mem.tokenizeAny(u8, value, ", \t");
    while (it.next()) |directive| {
        if (std.ascii.eqlIgnoreCase(directive, "no-store") or std.ascii.eqlIgnoreCase(directive, "no-cache")) out.no_store = true;
        const prefix = "max-age=";
        if (directive.len > prefix.len and std.ascii.startsWithIgnoreCase(directive, prefix)) {
            out.max_age = std.fmt.parseInt(i64, std.mem.trim(u8, directive[prefix.len..], "\""), 10) catch null;
            if (out.max_age) |m| if (m < 0) {
                out.max_age = 0;
            };
        }
    }
}

const Target = struct {
    uri: std.Uri,
    /// The host without the brackets of an IPv6 address.
    host: []const u8,
    port: u16,
};

/// Check the form of a URL: https, a host, no user information and no fragment.
fn checkUrl(url: []const u8) FetchError!Target {
    const uri = std.Uri.parse(url) catch return error.NotPermitted;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.NotPermitted;
    if (uri.user != null or uri.password != null or uri.fragment != null) return error.NotPermitted;
    const parts = common.splitUri(url) orelse return error.NotPermitted;
    const host = parts.host();
    if (host.len == 0) return error.NotPermitted;
    return .{ .uri = uri, .host = host, .port = uri.port orelse 443 };
}

/// The text of an IP address without the port.
fn addressText(buf: *[64]u8, address: Io.net.IpAddress) []const u8 {
    switch (address) {
        .ip4 => |a| return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] }) catch unreachable,
        .ip6 => |a| {
            var w: Io.Writer = .fixed(buf);
            var i: usize = 0;
            while (i < 16) : (i += 2) {
                if (i > 0) w.writeByte(':') catch unreachable;
                w.print("{x}", .{std.mem.readInt(u16, a.bytes[i..][0..2], .big)}) catch unreachable;
            }
            return w.buffered();
        },
    }
}

/// True for a global unicast address. The function refuses loopback, private, link-local,
/// shared, multicast, documentation and reserved addresses, and IPv6 addresses that carry such
/// an IPv4 address.
pub fn isPublicAddress(address: Io.net.IpAddress) bool {
    return switch (address) {
        .ip4 => |a| isPublicIp4(a.bytes),
        .ip6 => |a| isPublicIp6(a.bytes),
    };
}

fn isPublicIp4(b: [4]u8) bool {
    return switch (b[0]) {
        0, 10, 127 => false,
        100 => b[1] & 0xc0 != 64, // 100.64.0.0/10, shared address space
        169 => b[1] != 254, // link-local
        172 => b[1] & 0xf0 != 16, // 172.16.0.0/12
        192 => !(b[1] == 168 or (b[1] == 0 and (b[2] == 0 or b[2] == 2))), // private, special, documentation
        198 => !(b[1] & 0xfe == 18 or (b[1] == 51 and b[2] == 100)), // benchmarks, documentation
        203 => !(b[1] == 0 and b[2] == 113), // documentation
        else => b[0] < 224, // multicast and reserved
    };
}

fn isPublicIp6(b: [16]u8) bool {
    // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96): check the IPv4 address.
    const mapped_prefix = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff };
    const nat64_prefix = [_]u8{ 0, 0x64, 0xff, 0x9b } ++ [_]u8{0} ** 8;
    if (std.mem.eql(u8, b[0..12], &mapped_prefix) or std.mem.eql(u8, b[0..12], &nat64_prefix)) return isPublicIp4(b[12..16].*);
    // 6to4 (2002::/16) carries an IPv4 address in the next 32 bits.
    if (b[0] == 0x20 and b[1] == 0x02) return isPublicIp4(b[2..6].*);
    // Only global unicast (2000::/3) counts. That excludes the unspecified and loopback
    // addresses, unique local (fc00::/7), link-local (fe80::/10) and multicast (ff00::/8).
    if (b[0] & 0xe0 != 0x20) return false;
    // Teredo (2001::/32), the IETF protocol block (2001::/23) and documentation (2001:db8::/32).
    if (b[0] == 0x20 and b[1] == 0x01 and b[2] < 0x02) return false;
    if (b[0] == 0x20 and b[1] == 0x01 and b[2] == 0x0d and b[3] == 0xb8) return false;
    return true;
}

// -- Client ID metadata documents ----------------------------------------------------------------

pub const DocumentError = error{
    OutOfMemory,
    /// The document is not a JSON object.
    Malformed,
    /// The `client_id` of the document is not the URL of the document.
    ClientIdMismatch,
    /// `redirect_uris` is missing or has a URI without https or a loopback host.
    InvalidRedirectUri,
    /// `client_name` is missing.
    MissingClientName,
    /// The document asks for a client secret, which a document cannot have.
    SecretNotPermitted,
    /// The document has an authentication method, a grant type or a response type that the
    /// server does not offer.
    Unsupported,
    /// `private_key_jwt` needs `jwks` or `jwks_uri`.
    MissingKeys,
};

/// The most redirect URIs of one client.
pub const max_redirect_uris = 16;

/// Read a client ID metadata document of `url` (draft-ietf-oauth-client-id-metadata-document
/// and the MCP client registration rules). The client is in `arena`.
pub fn parseDocument(arena: Allocator, url: []const u8, body: []const u8) DocumentError!store_mod.Client {
    const tree = json.parseTree(arena, body) catch return error.Malformed;
    if (tree != .object) return error.Malformed;
    // The `client_id` must be the URL of the document, byte for byte.
    const client_id = json.getString(tree, "client_id") orelse return error.ClientIdMismatch;
    if (!std.mem.eql(u8, client_id, url)) return error.ClientIdMismatch;
    const name = json.getString(tree, "client_name") orelse return error.MissingClientName;
    // A document is public: it cannot carry a secret.
    if (tree.object.get("client_secret") != null or tree.object.get("client_secret_expires_at") != null) return error.SecretNotPermitted;
    const redirect_uris = try redirectUris(arena, tree);
    if (redirect_uris.len == 0) return error.InvalidRedirectUri;

    var client: store_mod.Client = .{ .client_id = client_id, .client_name = name, .redirect_uris = redirect_uris };
    const method = json.getString(tree, "token_endpoint_auth_method") orelse "none";
    client.auth_method = if (std.mem.eql(u8, method, "none"))
        .none
    else if (std.mem.eql(u8, method, "private_key_jwt"))
        .private_key_jwt
    else if (std.mem.startsWith(u8, method, "client_secret"))
        return error.SecretNotPermitted
    else
        return error.Unsupported;
    client.grant_types = try grantTypes(tree, .{ .authorization_code = true });
    if (client.grant_types.client_credentials or client.grant_types.jwt_bearer) return error.Unsupported;
    if (!client.grant_types.authorization_code) return error.Unsupported;
    try checkResponseTypes(tree);
    if (json.getString(tree, "scope")) |s| client.scopes = try splitScope(arena, s);
    if (common.boolField(tree, "dpop_bound_access_tokens")) |b| client.dpop_bound_access_tokens = b;
    try readKeys(arena, tree, &client);
    return client;
}

/// The `redirect_uris` of a client document. Each URI must use https, or `http` with a loopback
/// host, and must not have a fragment.
pub fn redirectUris(arena: Allocator, tree: std.json.Value) DocumentError![]const []const u8 {
    const v = tree.object.get("redirect_uris") orelse return &.{};
    if (v != .array) return error.InvalidRedirectUri;
    if (v.array.items.len > max_redirect_uris) return error.InvalidRedirectUri;
    var out: std.ArrayList([]const u8) = .empty;
    for (v.array.items) |item| {
        if (item != .string) return error.InvalidRedirectUri;
        if (item.string.len > 2048 or !common.validRedirectUri(item.string)) return error.InvalidRedirectUri;
        try out.append(arena, item.string);
    }
    return out.items;
}

/// The `grant_types` of a client document, or `default` without the member.
pub fn grantTypes(tree: std.json.Value, default: store_mod.GrantTypes) DocumentError!store_mod.GrantTypes {
    const v = tree.object.get("grant_types") orelse return default;
    if (v != .array) return error.Malformed;
    var out: store_mod.GrantTypes = .{};
    for (v.array.items) |item| {
        if (item != .string) return error.Malformed;
        const g = item.string;
        if (std.mem.eql(u8, g, "authorization_code")) {
            out.authorization_code = true;
        } else if (std.mem.eql(u8, g, "refresh_token")) {
            out.refresh_token = true;
        } else if (std.mem.eql(u8, g, "client_credentials")) {
            out.client_credentials = true;
        } else if (std.mem.eql(u8, g, "urn:ietf:params:oauth:grant-type:jwt-bearer")) {
            out.jwt_bearer = true;
        } else return error.Unsupported;
    }
    return out;
}

/// Refuse a `response_types` member with another type than `code`.
pub fn checkResponseTypes(tree: std.json.Value) DocumentError!void {
    const v = tree.object.get("response_types") orelse return;
    if (v != .array) return error.Malformed;
    for (v.array.items) |item| {
        if (item != .string or !std.mem.eql(u8, item.string, "code")) return error.Unsupported;
    }
}

/// Read `jwks` or `jwks_uri` into the client. `private_key_jwt` needs one of them.
pub fn readKeys(arena: Allocator, tree: std.json.Value, client: *store_mod.Client) DocumentError!void {
    if (tree.object.get("jwks")) |set| {
        if (set != .object) return error.Malformed;
        const text = std.json.Stringify.valueAlloc(arena, set, .{}) catch return error.OutOfMemory;
        _ = jwt.parseJwks(arena, text) catch return error.Malformed;
        client.jwks = text;
    }
    if (json.getString(tree, "jwks_uri")) |uri| {
        if (client.jwks != null) return error.Malformed;
        _ = checkUrl(uri) catch return error.Malformed;
        client.jwks_uri = uri;
    }
    if (client.auth_method == .private_key_jwt and client.jwks == null and client.jwks_uri == null) return error.MissingKeys;
}

/// Split a space-separated scope list.
pub fn splitScope(arena: Allocator, text: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, ' ');
    while (it.next()) |s| try common.appendUnique(arena, &out, s);
    return out.items;
}

/// The description of a document error for the `error_description` of a response.
pub fn describe(err: DocumentError) []const u8 {
    return switch (err) {
        error.OutOfMemory => "The server is out of memory",
        error.Malformed => "The client metadata document is not a valid JSON object",
        error.ClientIdMismatch => "The client_id of the client metadata document is not its URL",
        error.InvalidRedirectUri => "The redirect_uris of the client metadata document are not valid",
        error.MissingClientName => "The client metadata document has no client_name",
        error.SecretNotPermitted => "A client metadata document cannot use a client secret",
        error.Unsupported => "The client metadata document asks for a method or a grant that the server does not offer",
        error.MissingKeys => "The client metadata document has private_key_jwt without jwks or jwks_uri",
    };
}

test "public addresses" {
    const Case = struct { text: []const u8, public: bool };
    const cases = [_]Case{
        .{ .text = "93.184.216.34", .public = true },
        .{ .text = "8.8.8.8", .public = true },
        .{ .text = "127.0.0.1", .public = false },
        .{ .text = "10.1.2.3", .public = false },
        .{ .text = "172.16.0.1", .public = false },
        .{ .text = "172.32.0.1", .public = true },
        .{ .text = "192.168.1.1", .public = false },
        .{ .text = "169.254.169.254", .public = false },
        .{ .text = "100.64.0.1", .public = false },
        .{ .text = "100.128.0.1", .public = true },
        .{ .text = "0.0.0.0", .public = false },
        .{ .text = "224.0.0.1", .public = false },
        .{ .text = "255.255.255.255", .public = false },
        .{ .text = "198.18.0.1", .public = false },
        .{ .text = "203.0.113.5", .public = false },
        .{ .text = "::1", .public = false },
        .{ .text = "::", .public = false },
        .{ .text = "fe80::1", .public = false },
        .{ .text = "fd00::1", .public = false },
        .{ .text = "ff02::1", .public = false },
        .{ .text = "::ffff:127.0.0.1", .public = false },
        .{ .text = "::ffff:8.8.8.8", .public = true },
        .{ .text = "64:ff9b::a00:1", .public = false },
        .{ .text = "2002:a00:1::", .public = false },
        .{ .text = "2001:db8::1", .public = false },
        .{ .text = "2001::1", .public = false },
        .{ .text = "2606:4700::1111", .public = true },
    };
    for (cases) |c| {
        const address = try Io.net.IpAddress.parse(c.text, 443);
        if (isPublicAddress(address) != c.public) {
            std.debug.print("wrong class for {s}\n", .{c.text});
            return error.TestUnexpectedResult;
        }
    }
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("0:0:0:0:0:0:0:1", addressText(&buf, try Io.net.IpAddress.parse("::1", 1)));
    try std.testing.expectEqualStrings("10.0.0.2", addressText(&buf, try Io.net.IpAddress.parse("10.0.0.2", 1)));
}

test "the URL check and the refusal of private addresses" {
    try std.testing.expectError(error.NotPermitted, checkUrl("http://example.com/c.json"));
    try std.testing.expectError(error.NotPermitted, checkUrl("https://u:p@example.com/c.json"));
    try std.testing.expectError(error.NotPermitted, checkUrl("https://example.com/c.json#f"));
    const t = try checkUrl("https://[::1]:8443/c.json");
    try std.testing.expectEqualStrings("::1", t.host);
    try std.testing.expectEqual(8443, t.port);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var fetcher: Fetcher = .init(std.testing.io, std.testing.allocator, .{});
    defer fetcher.deinit();
    try std.testing.expectError(error.PrivateAddress, fetcher.get(arena_state.allocator(), "https://127.0.0.1:9/c.json", 100, 0));
    try std.testing.expectError(error.PrivateAddress, fetcher.get(arena_state.allocator(), "https://[::1]:9/c.json", 100, 0));
    try std.testing.expectError(error.PrivateAddress, fetcher.get(arena_state.allocator(), "https://localhost:9/c.json", 100, 0));
}

test "a server that does not answer reaches the time limit" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // The connection waits in the backlog of the listener: the TLS handshake gets no answer.
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
    defer listener.deinit(io);
    var fetcher: Fetcher = .init(io, gpa, .{ .allow_private_addresses = true, .timeout_seconds = 1, .ca_file = "test/fixtures/tls/pem/ca.crt" });
    defer fetcher.deinit();
    const url = try std.fmt.allocPrint(arena, "https://127.0.0.1:{d}/client.json", .{listener.socket.address.getPort()});
    const start = Io.Clock.Timestamp.now(io, .awake);
    try std.testing.expectError(error.FetchFailed, fetcher.get(arena, url, 100, 0));
    const elapsed = start.durationTo(Io.Clock.Timestamp.now(io, .awake));
    try std.testing.expect(elapsed.raw.toSeconds() < 5);
}

test "the cache keeps documents until they expire and evicts the oldest" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var fetcher: Fetcher = .init(std.testing.io, std.testing.allocator, .{ .max_entries = 2 });
    defer fetcher.deinit();
    try fetcher.remember("https://a.example/c.json", "a", 100);
    try fetcher.remember("https://b.example/c.json", "b", 200);
    try fetcher.remember("https://b.example/c.json", "b2", 300);
    try std.testing.expectEqualStrings("a", (try fetcher.cached(arena, "https://a.example/c.json", 50)).?);
    try std.testing.expect((try fetcher.cached(arena, "https://a.example/c.json", 100)) == null);
    // A third document evicts the one that expires first.
    try fetcher.remember("https://c.example/c.json", "c", 400);
    try std.testing.expect((try fetcher.cached(arena, "https://a.example/c.json", 50)) == null);
    try std.testing.expectEqualStrings("b2", (try fetcher.cached(arena, "https://b.example/c.json", 50)).?);
    try std.testing.expectEqualStrings("c", (try fetcher.get(arena, "https://c.example/c.json", 10, 50)));
}

test "client ID metadata documents" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const url = "https://app.example.com/oauth/client.json";
    const good =
        \\{"client_id":"https://app.example.com/oauth/client.json","client_name":"App","redirect_uris":["http://127.0.0.1:3000/callback","https://app.example.com/cb"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none","scope":"mcp:read mcp:read"}
    ;
    const c = try parseDocument(arena, url, good);
    try std.testing.expectEqualStrings("App", c.client_name.?);
    try std.testing.expectEqual(2, c.redirect_uris.len);
    try std.testing.expect(c.grant_types.refresh_token);
    try std.testing.expectEqual(1, c.scopes.len);
    try std.testing.expectEqual(store_mod.AuthMethod.none, c.auth_method);

    const Case = struct { body: []const u8, err: DocumentError };
    const cases = [_]Case{
        .{ .body = "[]", .err = error.Malformed },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json/\",\"client_name\":\"A\",\"redirect_uris\":[\"https://a/cb\"]}", .err = error.ClientIdMismatch },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"redirect_uris\":[\"https://a/cb\"]}", .err = error.MissingClientName },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"A\",\"redirect_uris\":[\"http://evil.example/cb\"]}", .err = error.InvalidRedirectUri },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"A\",\"redirect_uris\":[]}", .err = error.InvalidRedirectUri },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"A\",\"redirect_uris\":[\"https://a/cb\"],\"token_endpoint_auth_method\":\"client_secret_basic\"}", .err = error.SecretNotPermitted },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"A\",\"redirect_uris\":[\"https://a/cb\"],\"client_secret\":\"x\"}", .err = error.SecretNotPermitted },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"A\",\"redirect_uris\":[\"https://a/cb\"],\"grant_types\":[\"client_credentials\"]}", .err = error.Unsupported },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"A\",\"redirect_uris\":[\"https://a/cb\"],\"response_types\":[\"token\"]}", .err = error.Unsupported },
        .{ .body = "{\"client_id\":\"https://app.example.com/oauth/client.json\",\"client_name\":\"A\",\"redirect_uris\":[\"https://a/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"}", .err = error.MissingKeys },
    };
    for (cases) |case| try std.testing.expectError(case.err, parseDocument(arena, url, case.body));
    for (cases) |case| _ = describe(case.err);

    var download: Fetcher.Download = .{ .body = &.{} };
    parseCacheControl("public, max-age=600", &download);
    try std.testing.expectEqual(600, download.max_age.?);
    parseCacheControl("no-store", &download);
    try std.testing.expect(download.no_store);
}
