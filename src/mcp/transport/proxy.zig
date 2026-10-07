//! HTTP proxies for the client connections of the SDK: the Streamable HTTP client transport and
//! the fetcher of the OAuth clients. The client asks the proxy for a tunnel with a `CONNECT`
//! request (RFC 9110 section 9.3.6), also for an `http` URL. Then it speaks TLS and HTTP to the
//! server through the tunnel. Thus the proxy sees the host and the port of the server, but not
//! the requests and the tokens.
//!
//! By default, the client reads the proxy from the environment that the application gives
//! (`Config.environment`):
//!
//! - For an `https` URL: the first of `https_proxy`, `HTTPS_PROXY`, `all_proxy` and `ALL_PROXY`
//!   that has a value.
//! - For an `http` URL: the first of `http_proxy`, `HTTP_PROXY`, `all_proxy` and `ALL_PROXY` that
//!   has a value. When `REQUEST_METHOD` has a value, a web server started the process for a
//!   request. The `Proxy` header of that request can set `HTTP_PROXY`. Thus the client then
//!   ignores `http_proxy` and `HTTP_PROXY`.
//! - `no_proxy`, else `NO_PROXY`: the hosts that the client connects to directly (`bypasses`).
//!
//! A proxy from the environment never gets a loopback host (`isLoopback`). The proxy URL must
//! use `http`: the SDK has no TLS to the proxy and no `socks5` proxy.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http_syntax = @import("../util/http_syntax.zig");

const log = std.log.scoped(.mcp_proxy);

/// Where a client gets its proxy.
pub const Config = union(enum) {
    /// The proxy variables of this environment, for example `std.process.Init.environ_map`. Null
    /// gives no variables, thus a direct connection to each host. Zig gives a library no other
    /// access to the environment of the process. The map must stay valid and unchanged until
    /// the client stops.
    environment: ?*const std.process.Environ.Map,
    /// This proxy, and not the environment.
    explicit: Explicit,
    /// No proxy: the client connects directly to each host.
    none,

    /// True when `select` gives null for each host: `none`, or an environment of null.
    pub fn alwaysDirect(self: Config) bool {
        return switch (self) {
            .none => true,
            .environment => |env| env == null,
            .explicit => false,
        };
    }
};

/// A proxy that the application sets.
pub const Explicit = struct {
    /// The URL of the proxy: `http://host:port`, or `http://user:password@host:port` for a proxy
    /// that wants Basic authentication. Encode a reserved character of the user or the password
    /// with a percent sign. Without a scheme, the client adds `http://`. Without a port, the
    /// client uses port 80.
    url: []const u8,
    /// The hosts that the client connects to directly, in the format of `NO_PROXY`.
    no_proxy: []const u8 = "",
    /// Also send the loopback hosts to the proxy, for example to a proxy that records the
    /// traffic, or in a test.
    loopback: bool = false,
};

/// The proxy of one connection.
pub const Proxy = struct {
    /// The host of the proxy. An IPv6 address has its brackets.
    host: []const u8,
    port: u16,
    /// The value of the `proxy-authorization` header: `Basic` and the user and the password of the
    /// URL in base64 (RFC 7617). Null when the URL has no user. The client sends it only to the
    /// proxy, in the `CONNECT` request. The log lines of the SDK never show it.
    authorization: ?[]const u8 = null,

    /// The host and the port, for a log line.
    pub fn format(self: Proxy, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{s}:{d}", .{ self.host, self.port });
    }
};

pub const SelectError = error{
    OutOfMemory,
    /// The proxy URL does not use `http`, or it is not a URL. The log names the source of the URL.
    InvalidProxy,
};

/// The proxy for a connection to `host:port`, or null for a direct connection. `secure` tells
/// that the URL uses `https`. The function checks the loopback rule and the `no_proxy` list
/// before it reads the proxy URL. Thus a bad proxy URL does not stop a direct connection.
/// The strings of the result are in `arena`.
pub fn select(arena: Allocator, config: Config, host: []const u8, port: u16, secure: bool) SelectError!?Proxy {
    switch (config) {
        .none => return null,
        .explicit => |e| {
            if (!e.loopback and isLoopback(host)) return null;
            if (bypasses(e.no_proxy, host, port)) return null;
            return parseUrl(arena, e.url) catch |err| {
                if (err == error.InvalidProxy) log.warn("the explicit proxy URL is not an http URL", .{});
                return err;
            };
        },
        .environment => |maybe_env| {
            const env = maybe_env orelse return null;
            if (isLoopback(host)) return null;
            const found = fromEnvironment(env, secure) orelse return null;
            const no_proxy = variable(env, "no_proxy") orelse variable(env, "NO_PROXY");
            if (bypasses(if (no_proxy) |v| v.value else "", host, port)) return null;
            return parseUrl(arena, found.value) catch |err| {
                // The value can have a password, thus the log has only the name.
                if (err == error.InvalidProxy) log.warn("the variable {s} has no http proxy URL", .{found.name});
                return err;
            };
        },
    }
}

/// A variable of the environment, with the name as the map has it.
const Variable = struct { name: []const u8, value: []const u8 };

const https_names = [_][]const u8{ "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY" };
const http_names = [_][]const u8{ "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY" };

/// The first proxy variable with a value for the scheme.
fn fromEnvironment(env: *const std.process.Environ.Map, secure: bool) ?Variable {
    const request_of_web_server = !secure and variable(env, "REQUEST_METHOD") != null;
    const names: []const []const u8 = if (secure) &https_names else &http_names;
    for (names, 0..) |name, i| {
        if (request_of_web_server and i < 2) continue;
        if (variable(env, name)) |found| return found;
    }
    return null;
}

/// The variable `name`, or null when it is not there or empty. On Windows, the names of the
/// map ignore case, thus `https_proxy` also finds `HTTPS_PROXY`.
fn variable(env: *const std.process.Environ.Map, name: []const u8) ?Variable {
    const entry = env.array_hash_map.getEntry(name) orelse return null;
    const value = std.mem.trim(u8, entry.value_ptr.*, " \t");
    return if (value.len == 0) null else .{ .name = entry.key_ptr.*, .value = value };
}

/// Parse a proxy URL. See `Explicit.url`. The strings of the result are in `arena`.
pub fn parseUrl(arena: Allocator, text: []const u8) SelectError!Proxy {
    const trimmed = std.mem.trim(u8, text, " \t");
    const url = if (std.mem.find(u8, trimmed, "://") == null) try std.mem.concat(arena, u8, &.{ "http://", trimmed }) else trimmed;
    if (!http_syntax.isVisibleAscii(url)) return error.InvalidProxy;
    const uri = std.Uri.parse(url) catch return error.InvalidProxy;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.InvalidProxy;
    const host = try (uri.host orelse return error.InvalidProxy).toRawMaybeAlloc(arena);
    if (host.len == 0 or !http_syntax.isVisibleAscii(host)) return error.InvalidProxy;
    const port = uri.port orelse 80;
    if (port == 0) return error.InvalidProxy;
    var authorization: ?[]const u8 = null;
    if (uri.user) |u| {
        const user = try u.toRawMaybeAlloc(arena);
        const password = if (uri.password) |p| try p.toRawMaybeAlloc(arena) else "";
        // RFC 7617 section 2: the user ID cannot have a colon.
        if (std.mem.findScalar(u8, user, ':') != null) return error.InvalidProxy;
        authorization = try basicAuthorization(arena, user, password);
    }
    // The host of the result must not point into the text: an environment can change.
    return .{ .host = try arena.dupe(u8, host), .port = port, .authorization = authorization };
}

/// `Basic` and base64 of `user:password` (RFC 7617 section 2).
fn basicAuthorization(arena: Allocator, user: []const u8, password: []const u8) Allocator.Error![]const u8 {
    const raw = try std.mem.concat(arena, u8, &.{ user, ":", password });
    const encoder = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, "Basic ".len + encoder.calcSize(raw.len));
    @memcpy(out[0.."Basic ".len], "Basic ");
    _ = encoder.encode(out["Basic ".len..], raw);
    return out;
}

/// True for a host name or an address of the loopback interface. These are `localhost`, a name
/// under `.localhost` (RFC 6761 section 6.3) and an IPv4 address in 127.0.0.0/8. The IPv6
/// address ::1 and an IPv6 address that maps an IPv4 loopback address are loopback addresses
/// too. The client does not resolve names.
pub fn isLoopback(host: []const u8) bool {
    const name = trimDot(unbracket(host));
    if (std.ascii.eqlIgnoreCase(name, "localhost") or std.ascii.endsWithIgnoreCase(name, ".localhost")) return true;
    const address = Io.net.IpAddress.parse(name, 0) catch return false;
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| std.mem.eql(u8, &a.bytes, &([_]u8{0} ** 15 ++ [_]u8{1})) or
            (std.mem.eql(u8, a.bytes[0..12], &([_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff })) and a.bytes[12] == 127),
    };
}

/// True when the `NO_PROXY` list `list` names the host `host` with the port `port`. A comma, a
/// space or a tab separates the entries. The match ignores case and a dot at the end of a name.
/// The client does not resolve names.
///
/// - `*` matches each host.
/// - A name matches the same host and each host under it. Thus `example.com` and `.example.com`
///   match `example.com` and `api.example.com`, but not `badexample.com`. A `*.` at the start is
///   the same as a dot.
/// - An IP address matches the same address. With a prefix length, such as `10.0.0.0/8` or
///   `fd00::/8`, it matches each address in the range.
/// - An entry with a port, such as `example.com:8443` or `[::1]:8080`, matches only that port.
pub fn bypasses(list: []const u8, host: []const u8, port: u16) bool {
    const name = trimDot(unbracket(host));
    const host_address: ?Io.net.IpAddress = Io.net.IpAddress.parse(name, 0) catch null;
    var it = std.mem.tokenizeAny(u8, list, ", \t");
    while (it.next()) |raw| {
        if (std.mem.eql(u8, raw, "*")) return true;
        const entry = Entry.parse(raw) orelse continue;
        if (entry.port) |p| if (p != port) continue;
        if (entry.matches(name, host_address)) return true;
    }
    return false;
}

/// One entry of a `NO_PROXY` list.
const Entry = struct {
    /// Without brackets, without the `*.` or the dot at the start, and without the dot at the end.
    name: []const u8,
    port: ?u16 = null,
    /// The prefix length of an address range.
    prefix_len: ?u8 = null,

    fn parse(raw: []const u8) ?Entry {
        var text = raw;
        var port: ?u16 = null;
        if (text[0] == '[') {
            const close = std.mem.findScalar(u8, text, ']') orelse return null;
            const rest = text[close + 1 ..];
            if (rest.len > 0) {
                if (rest[0] != ':') return null;
                port = std.fmt.parseInt(u16, rest[1..], 10) catch return null;
            }
            text = text[1..close];
        } else if (std.mem.countScalar(u8, text, ':') == 1) {
            // One colon: a name or an IPv4 address with a port. More colons: an IPv6 address.
            const colon = std.mem.findScalar(u8, text, ':').?;
            port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return null;
            text = text[0..colon];
        }
        var prefix_len: ?u8 = null;
        if (std.mem.findScalar(u8, text, '/')) |slash| {
            prefix_len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return null;
            text = text[0..slash];
        }
        if (std.mem.startsWith(u8, text, "*.")) {
            text = text[2..];
        } else if (std.mem.startsWith(u8, text, ".")) {
            text = text[1..];
        }
        text = trimDot(text);
        if (text.len == 0) return null;
        return .{ .name = text, .port = port, .prefix_len = prefix_len };
    }

    fn matches(self: Entry, name: []const u8, host_address: ?Io.net.IpAddress) bool {
        const entry_address = Io.net.IpAddress.parse(self.name, 0) catch {
            // A name. A prefix length needs an address.
            if (self.prefix_len != null or host_address != null) return false;
            if (std.ascii.eqlIgnoreCase(name, self.name)) return true;
            return name.len > self.name.len and name[name.len - self.name.len - 1] == '.' and
                std.ascii.endsWithIgnoreCase(name, self.name);
        };
        const address = host_address orelse return false;
        return switch (entry_address) {
            .ip4 => |e| address == .ip4 and inRange(&address.ip4.bytes, &e.bytes, self.prefix_len orelse 32),
            .ip6 => |e| address == .ip6 and inRange(&address.ip6.bytes, &e.bytes, self.prefix_len orelse 128),
        };
    }
};

/// True when the first `prefix_len` bits of `address` and `range` are equal.
fn inRange(address: []const u8, range: []const u8, prefix_len: u8) bool {
    if (prefix_len > address.len * 8) return false;
    const whole = prefix_len / 8;
    if (!std.mem.eql(u8, address[0..whole], range[0..whole])) return false;
    const rest: u3 = @intCast(prefix_len % 8);
    if (rest == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rest));
    return address[whole] & mask == range[whole] & mask;
}

fn unbracket(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
}

fn trimDot(name: []const u8) []const u8 {
    return if (name.len > 1 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

pub const ConnectError = error{ConnectFailed} || Io.Cancelable;

/// Open a TCP connection to the proxy. A failure gets a warning in the log with the host and the
/// port of the proxy.
pub fn connect(io: Io, proxy: Proxy) ConnectError!Io.net.Stream {
    const host = unbracket(proxy.host);
    if (Io.net.IpAddress.parse(host, proxy.port)) |address| {
        return address.connect(io, .{ .mode = .stream }) catch |e| return failed(proxy, e);
    } else |_| {}
    const name = Io.net.HostName.init(host) catch return failed(proxy, error.InvalidHostName);
    return name.connect(io, proxy.port, .{ .mode = .stream }) catch |e| return failed(proxy, e);
}

fn failed(proxy: Proxy, err: anyerror) ConnectError {
    if (err == error.Canceled) return error.Canceled;
    log.warn("the client cannot connect to the proxy {f}: {t}", .{ proxy, err });
    return error.ConnectFailed;
}

pub const TunnelError = error{
    /// The proxy refused the tunnel, or it gave no HTTP answer. The log has the reason.
    ProxyRefused,
    /// The host has a character that is not visible ASCII. Nothing goes out.
    InvalidRequestHead,
    /// The connection to the proxy failed, or a cancel stopped the task. The reader or the
    /// writer of the stream has the cause.
    ReadFailed,
    WriteFailed,
};

/// The largest head of an answer to `CONNECT` that `tunnel` reads.
pub const max_answer_head_len = 16 << 10;

/// Ask the proxy for a tunnel to `host:port` with a `CONNECT` request, and read the answer. `in`
/// and `out` are the stream of `connect`. The buffer of `in` must hold the head of the answer.
/// After a success, the bytes on `in` and `out` are the bytes of the server. A host with a colon
/// is an IPv6 address and gets brackets.
pub fn tunnel(in: *Io.Reader, out: *Io.Writer, proxy: Proxy, host: []const u8, port: u16) TunnelError!void {
    const bare = unbracket(host);
    if (bare.len == 0 or !http_syntax.isVisibleAscii(bare)) return error.InvalidRequestHead;
    const v6 = std.mem.findScalar(u8, bare, ':') != null;
    const open = if (v6) "[" else "";
    const close = if (v6) "]" else "";
    try out.print("CONNECT {s}{s}{s}:{d} HTTP/1.1\r\nhost: {s}{s}{s}:{d}\r\n", .{ open, bare, close, port, open, bare, close, port });
    if (proxy.authorization) |value| try out.print("proxy-authorization: {s}\r\n", .{value});
    try out.writeAll("\r\n");
    try out.flush();

    var reader: std.http.Reader = .{ .in = in, .interface = undefined, .state = .ready, .max_head_len = @min(in.buffer.len, max_answer_head_len) };
    const head = reader.receiveHead() catch |e| switch (e) {
        error.ReadFailed => return error.ReadFailed,
        error.HttpConnectionClosing, error.HttpRequestTruncated => {
            log.warn("the proxy {f} closed the connection before its answer to CONNECT {s}:{d}", .{ proxy, host, port });
            return error.ProxyRefused;
        },
        error.HttpHeadersOversize => {
            log.warn("the answer of the proxy {f} to CONNECT {s}:{d} has a head over {d} bytes", .{ proxy, host, port, reader.max_head_len });
            return error.ProxyRefused;
        },
    };
    const status = answerStatus(head) orelse {
        log.warn("the proxy {f} gave an answer to CONNECT {s}:{d} that is not HTTP", .{ proxy, host, port });
        return error.ProxyRefused;
    };
    // RFC 9110 section 9.3.6: each 2xx status opens the tunnel.
    if (status / 100 == 2) return;
    // The phrase comes from the table of std, not from the proxy.
    const known: std.http.Status = @enumFromInt(status);
    const text = known.phrase() orelse "";
    if (status == 407) {
        log.warn("the proxy {f} refused the tunnel to {s}:{d} with status 407 {s}: the proxy URL has no user and password, or wrong ones", .{ proxy, host, port, text });
    } else {
        log.warn("the proxy {f} refused the tunnel to {s}:{d} with status {d} {s}", .{ proxy, host, port, status, text });
    }
    return error.ProxyRefused;
}

/// The status code of the status line `HTTP/1.x NNN ...`, or null.
fn answerStatus(head: []const u8) ?u16 {
    const line_end = std.mem.find(u8, head, "\r\n") orelse head.len;
    const line = head[0..line_end];
    if (line.len < 12 or !std.mem.startsWith(u8, line, "HTTP/1.") or line[8] != ' ') return null;
    if (line.len > 12 and line[12] != ' ') return null;
    return std.fmt.parseInt(u16, line[9..12], 10) catch null;
}

test "a proxy URL with a user, without a scheme and without a port" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const full = try parseUrl(arena, "http://us%40er:pa%3Ass@proxy.example:3128/");
    try std.testing.expectEqualStrings("proxy.example", full.host);
    try std.testing.expectEqual(3128, full.port);
    // base64 of "us@er:pa:ss".
    try std.testing.expectEqualStrings("Basic dXNAZXI6cGE6c3M=", full.authorization.?);
    const bare = try parseUrl(arena, " proxy.example:8080 ");
    try std.testing.expectEqualStrings("proxy.example", bare.host);
    try std.testing.expectEqual(8080, bare.port);
    try std.testing.expect(bare.authorization == null);
    try std.testing.expectEqual(80, (try parseUrl(arena, "http://proxy.example")).port);
    try std.testing.expectEqualStrings("[::1]", (try parseUrl(arena, "http://[::1]:3128")).host);
    // A user without a password.
    try std.testing.expectEqualStrings("Basic dXNlcjo=", (try parseUrl(arena, "http://user@p:1")).authorization.?);
    var buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try w.print("{f}", .{full});
    try std.testing.expectEqualStrings("proxy.example:3128", w.buffered());

    try std.testing.expectError(error.InvalidProxy, parseUrl(arena, "https://proxy.example:443"));
    try std.testing.expectError(error.InvalidProxy, parseUrl(arena, "socks5://proxy.example:1080"));
    try std.testing.expectError(error.InvalidProxy, parseUrl(arena, "http://:3128"));
    try std.testing.expectError(error.InvalidProxy, parseUrl(arena, "http://proxy.example:0"));
    try std.testing.expectError(error.InvalidProxy, parseUrl(arena, "http://pro xy:1"));
    try std.testing.expectError(error.InvalidProxy, parseUrl(arena, "http://a%3Ab:c@proxy.example:1"));
    try std.testing.expectError(error.InvalidProxy, parseUrl(arena, ""));
}

test "loopback hosts" {
    for ([_][]const u8{ "localhost", "LOCALHOST", "localhost.", "api.localhost", "127.0.0.1", "127.1.2.3", "::1", "[::1]", "[::ffff:127.0.0.1]" }) |h| {
        try std.testing.expect(isLoopback(h));
    }
    for ([_][]const u8{ "example.com", "localhost.example.com", "mylocalhost", "128.0.0.1", "10.0.0.1", "[::2]", "[::ffff:10.0.0.1]" }) |h| {
        try std.testing.expect(!isLoopback(h));
    }
}

test "the NO_PROXY match" {
    // `*` matches each host.
    try std.testing.expect(bypasses("*", "example.com", 443));
    try std.testing.expect(bypasses("a.test, *", "example.com", 443));
    // A name matches the host and the hosts under it, with or without a dot or `*.` at the start.
    for ([_][]const u8{ "example.com", ".example.com", "*.example.com", "EXAMPLE.COM.", "other.test,example.com", "other.test example.com" }) |list| {
        try std.testing.expect(bypasses(list, "example.com", 443));
        try std.testing.expect(bypasses(list, "api.example.com", 443));
        try std.testing.expect(bypasses(list, "Deep.API.Example.Com.", 443));
        try std.testing.expect(!bypasses(list, "badexample.com", 443));
        try std.testing.expect(!bypasses(list, "example.com.evil.test", 443));
    }
    try std.testing.expect(!bypasses("api.example.com", "example.com", 443));
    // An entry with a port matches only that port.
    try std.testing.expect(bypasses("example.com:8443", "api.example.com", 8443));
    try std.testing.expect(!bypasses("example.com:8443", "api.example.com", 443));
    try std.testing.expect(bypasses("10.1.2.3:8080", "10.1.2.3", 8080));
    try std.testing.expect(!bypasses("10.1.2.3:8080", "10.1.2.3", 80));
    try std.testing.expect(bypasses("[fd00::1]:8080", "[fd00::1]", 8080));
    try std.testing.expect(!bypasses("[fd00::1]:8080", "[fd00::1]", 443));
    // An IP address matches the same address, not a name and not a part of an address.
    try std.testing.expect(bypasses("10.1.2.3", "10.1.2.3", 443));
    try std.testing.expect(!bypasses("10.1.2.3", "110.1.2.3", 443));
    try std.testing.expect(!bypasses("1.2.3", "10.1.2.3", 443));
    try std.testing.expect(bypasses("fd00::1", "[fd00:0::1]", 443));
    try std.testing.expect(bypasses("[fd00::1]", "[fd00::1]", 443));
    try std.testing.expect(!bypasses("fd00::1", "[fd00::2]", 443));
    try std.testing.expect(!bypasses("10.1.2.3", "host.example", 443));
    // A prefix length gives a range.
    try std.testing.expect(bypasses("10.0.0.0/8", "10.200.3.4", 443));
    try std.testing.expect(!bypasses("10.0.0.0/8", "11.0.0.1", 443));
    try std.testing.expect(bypasses("192.168.0.0/20", "192.168.15.255", 443));
    try std.testing.expect(!bypasses("192.168.0.0/20", "192.168.16.0", 443));
    try std.testing.expect(bypasses("fd00::/8", "[fd12:3456::1]", 443));
    try std.testing.expect(!bypasses("fd00::/8", "[fe80::1]", 443));
    try std.testing.expect(bypasses("0.0.0.0/0", "8.8.8.8", 443));
    try std.testing.expect(!bypasses("10.0.0.0/8", "ten.example", 443));
    try std.testing.expect(!bypasses("10.0.0.0/33", "10.0.0.1", 443));
    try std.testing.expect(!bypasses("example.com/8", "example.com", 443));
    // Empty lists and entries that do not parse match nothing.
    try std.testing.expect(!bypasses("", "example.com", 443));
    try std.testing.expect(!bypasses(" , ,", "example.com", 443));
    try std.testing.expect(!bypasses(".", "example.com", 443));
    try std.testing.expect(!bypasses("example.com:x", "example.com", 443));
    try std.testing.expect(!bypasses("[fd00::1", "[fd00::1]", 443));
}

test "the proxy of the environment" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var env: std.process.Environ.Map = .init(gpa);
    defer env.deinit();

    // No variables, or no environment: a direct connection.
    try std.testing.expect(try select(arena, .{ .environment = &env }, "mcp.example.com", 443, true) == null);
    try std.testing.expect(try select(arena, .{ .environment = null }, "mcp.example.com", 443, true) == null);

    try env.put("ALL_PROXY", "http://all.example:1080");
    try std.testing.expectEqualStrings("all.example", (try select(arena, .{ .environment = &env }, "mcp.example.com", 443, true)).?.host);
    try std.testing.expectEqualStrings("all.example", (try select(arena, .{ .environment = &env }, "mcp.example.com", 80, false)).?.host);
    try env.put("HTTPS_PROXY", "http://secure.example:3128");
    try env.put("HTTP_PROXY", "plain.example:3128");
    const secure = (try select(arena, .{ .environment = &env }, "mcp.example.com", 443, true)).?;
    try std.testing.expectEqualStrings("secure.example", secure.host);
    try std.testing.expectEqual(3128, secure.port);
    try std.testing.expectEqualStrings("plain.example", (try select(arena, .{ .environment = &env }, "mcp.example.com", 80, false)).?.host);

    // An empty variable counts as absent.
    try env.put("HTTPS_PROXY", "");
    try std.testing.expectEqualStrings("all.example", (try select(arena, .{ .environment = &env }, "mcp.example.com", 443, true)).?.host);
    try env.put("HTTPS_PROXY", "http://secure.example:3128");

    // A request of a web server can set HTTP_PROXY, thus the client ignores it then.
    try env.put("REQUEST_METHOD", "GET");
    try std.testing.expectEqualStrings("all.example", (try select(arena, .{ .environment = &env }, "mcp.example.com", 80, false)).?.host);
    try std.testing.expectEqualStrings("secure.example", (try select(arena, .{ .environment = &env }, "mcp.example.com", 443, true)).?.host);
    _ = env.swapRemove("REQUEST_METHOD");

    // Loopback hosts and the hosts of NO_PROXY get a direct connection.
    try std.testing.expect(try select(arena, .{ .environment = &env }, "localhost", 443, true) == null);
    try std.testing.expect(try select(arena, .{ .environment = &env }, "127.0.0.1", 443, true) == null);
    try env.put("NO_PROXY", "internal.example, 10.0.0.0/8");
    try std.testing.expect(try select(arena, .{ .environment = &env }, "mcp.internal.example", 443, true) == null);
    try std.testing.expect(try select(arena, .{ .environment = &env }, "10.1.1.1", 443, true) == null);
    try std.testing.expect(try select(arena, .{ .environment = &env }, "mcp.example.com", 443, true) != null);

    // A proxy URL that the client cannot use is an error, but not for a host of NO_PROXY.
    try env.put("HTTPS_PROXY", "socks5://user:secret@socks.example:1080");
    try std.testing.expectError(error.InvalidProxy, select(arena, .{ .environment = &env }, "mcp.example.com", 443, true));
    try std.testing.expect(try select(arena, .{ .environment = &env }, "mcp.internal.example", 443, true) == null);

    // The explicit setting and `none` ignore the environment.
    const explicit: Config = .{ .explicit = .{ .url = "http://explicit.example:8080", .no_proxy = "skip.example" } };
    try std.testing.expectEqualStrings("explicit.example", (try select(arena, explicit, "mcp.example.com", 443, true)).?.host);
    try std.testing.expect(try select(arena, explicit, "skip.example", 443, true) == null);
    try std.testing.expect(try select(arena, explicit, "localhost", 443, true) == null);
    const with_loopback: Config = .{ .explicit = .{ .url = "http://explicit.example:8080", .loopback = true } };
    try std.testing.expect(try select(arena, with_loopback, "localhost", 443, true) != null);
    try std.testing.expect(try select(arena, .none, "mcp.example.com", 443, true) == null);
    try std.testing.expect(Config.alwaysDirect(.none));
    try std.testing.expect(Config.alwaysDirect(.{ .environment = null }));
    try std.testing.expect(!Config.alwaysDirect(.{ .environment = &env }));
    try std.testing.expect(!explicit.alwaysDirect());

    // The lowercase name has priority. On Windows, the names ignore case: one variable.
    if (builtin.os.tag != .windows) {
        try env.put("https_proxy", "http://lower.example:3128");
        try env.put("HTTPS_PROXY", "http://upper.example:3128");
        try std.testing.expectEqualStrings("lower.example", (try select(arena, .{ .environment = &env }, "mcp.example.com", 443, true)).?.host);
    }
}

/// A reader that gives `answer` in parts of at most 7 bytes through a buffer of 512 bytes, as a
/// socket can.
const AnswerReader = struct {
    buffer: [512]u8 = undefined,
    calls: [1]std.testing.Reader.Call = undefined,
    reader: std.testing.Reader = undefined,

    fn init(self: *AnswerReader, answer: []const u8) *Io.Reader {
        self.calls = .{.{ .buffer = answer }};
        self.reader = .init(&self.buffer, if (answer.len == 0) &.{} else &self.calls);
        self.reader.artificial_limit = .limited(7);
        return &self.reader.interface;
    }
};

test "the CONNECT request and its answer" {
    const proxy: Proxy = .{ .host = "proxy.example", .port = 3128, .authorization = "Basic dTpw" };
    var out_buf: [256]u8 = undefined;
    var answer: AnswerReader = .{};
    {
        const in = answer.init("HTTP/1.1 200 Connection established\r\n\r\n\x16\x03\x01");
        var out: Io.Writer = .fixed(&out_buf);
        try tunnel(in, &out, proxy, "mcp.example.com", 443);
        try std.testing.expectEqualStrings("CONNECT mcp.example.com:443 HTTP/1.1\r\nhost: mcp.example.com:443\r\nproxy-authorization: Basic dTpw\r\n\r\n", out.buffered());
        // The bytes after the head belong to the server.
        var rest: [8]u8 = undefined;
        try std.testing.expectEqualStrings("\x16\x03\x01", rest[0..try in.readSliceShort(&rest)]);
    }
    {
        const in = answer.init("HTTP/1.0 200 OK\r\nproxy-agent: test\r\n\r\n");
        var out: Io.Writer = .fixed(&out_buf);
        try tunnel(in, &out, .{ .host = "p", .port = 1 }, "[fd00::1]", 8443);
        try std.testing.expectEqualStrings("CONNECT [fd00::1]:8443 HTTP/1.1\r\nhost: [fd00::1]:8443\r\n\r\n", out.buffered());
    }
    for ([_][]const u8{
        "HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic\r\ncontent-length: 0\r\n\r\n",
        "HTTP/1.1 403 Forbidden\r\n\r\n",
        "HTTP/1.1 502\r\n\r\n",
        "SSH-2.0-OpenSSH\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1 200",
        "",
        "HTTP/1.1 200 OK\r\nx: " ++ "a" ** 600 ++ "\r\n\r\n",
    }) |text| {
        const in = answer.init(text);
        var out: Io.Writer = .fixed(&out_buf);
        try std.testing.expectError(error.ProxyRefused, tunnel(in, &out, proxy, "mcp.example.com", 443));
    }
    const in = answer.init("HTTP/1.1 200 OK\r\n\r\n");
    var out: Io.Writer = .fixed(&out_buf);
    try std.testing.expectError(error.InvalidRequestHead, tunnel(in, &out, proxy, "a\r\nb", 443));
    try std.testing.expectEqual(0, out.buffered().len);
}
