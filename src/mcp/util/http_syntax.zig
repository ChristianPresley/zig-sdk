//! The character rules of HTTP/1.1 request heads (RFC 9110 section 5.6, RFC 9112 section 3).
//! The clients of the SDK check each part of a request head with these rules before they
//! write it. A value from a peer, for example an access token or a URL from metadata, thus
//! cannot add a header or a request.
const std = @import("std");

/// True for a `tchar` of RFC 9110 section 5.6.2.
pub fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// True when `s` is a `token` (RFC 9110 section 5.6.2): a method or a field name.
pub fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!isTokenChar(c)) return false;
    return true;
}

/// True when `s` is a field value (RFC 9110 section 5.5): visible ASCII, space, horizontal
/// tab and `obs-text`. The rule does not permit CR, LF, NUL, DEL and the other control characters.
pub fn isFieldValue(s: []const u8) bool {
    for (s) |c| switch (c) {
        '\t', ' '...'~', 0x80...0xff => {},
        else => return false,
    };
    return true;
}

/// True when `s` has only visible ASCII characters and is not empty. A request target and a
/// `host` value obey this rule.
pub fn isVisibleAscii(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < '!' or c > '~') return false;
    return true;
}

/// True when `s` is a `token68` (RFC 9110 section 11.2), the syntax of the credentials of the
/// `Bearer` and `DPoP` schemes (RFC 6750 section 2.1, RFC 9449 section 7.1).
pub fn isToken68(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) : (i += 1) switch (s[i]) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_', '~', '+', '/' => {},
        else => break,
    };
    if (i == 0) return false;
    while (i < s.len) : (i += 1) if (s[i] != '=') return false;
    return true;
}

/// True when the raw form of `url` has only visible ASCII characters and its host has no
/// percent-encoded byte outside visible ASCII. `std.Uri.parse` accepts CR and LF, so a client
/// checks a URL from a peer with this function before it sends a request.
pub fn isRequestUrl(url: []const u8) bool {
    if (!isVisibleAscii(url)) return false;
    const uri = std.Uri.parse(url) catch return false;
    const host = uri.host orelse return false;
    const raw = switch (host) {
        .raw => |r| r,
        .percent_encoded => |p| p,
    };
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        if (raw[i] != '%') continue;
        if (i + 2 >= raw.len) return false;
        const byte = std.fmt.parseInt(u8, raw[i + 1 .. i + 3], 16) catch return false;
        if (byte < '!' or byte > '~') return false;
        i += 2;
    }
    return true;
}

test "tokens and field values" {
    try std.testing.expect(isToken("POST"));
    try std.testing.expect(isToken("mcp-param-x"));
    try std.testing.expect(!isToken(""));
    try std.testing.expect(!isToken("a b"));
    try std.testing.expect(!isToken("a:b"));
    try std.testing.expect(!isToken("a\r\nb"));
    try std.testing.expect(isFieldValue("Bearer abc.def"));
    try std.testing.expect(isFieldValue("a\tb \xc3\xa9"));
    try std.testing.expect(isFieldValue(""));
    try std.testing.expect(!isFieldValue("a\r\nx-injected: 1"));
    try std.testing.expect(!isFieldValue("a\nb"));
    try std.testing.expect(!isFieldValue("a\x00b"));
    try std.testing.expect(!isFieldValue("a\x7fb"));
}

test "token68" {
    try std.testing.expect(isToken68("eyJhbGciOi.eyJzdWIi.c2ln"));
    try std.testing.expect(isToken68("abc+/~-_.=="));
    try std.testing.expect(!isToken68(""));
    try std.testing.expect(!isToken68("=abc"));
    try std.testing.expect(!isToken68("ab=c"));
    try std.testing.expect(!isToken68("a b"));
    try std.testing.expect(!isToken68("abc\r\nx-injected: 1"));
}

test "request URLs" {
    try std.testing.expect(isRequestUrl("https://as.example/token?x=%20"));
    try std.testing.expect(isRequestUrl("http://127.0.0.1:8080/mcp"));
    try std.testing.expect(isRequestUrl("https://[::1]:8443/mcp"));
    try std.testing.expect(!isRequestUrl("https://as.example/token\r\nx-injected: 1"));
    try std.testing.expect(!isRequestUrl("https://as.example/a b"));
    try std.testing.expect(!isRequestUrl("https://as%0d%0aexample/token"));
    try std.testing.expect(!isRequestUrl("https://as%2/token"));
    try std.testing.expect(!isRequestUrl("/relative"));
    try std.testing.expect(!isRequestUrl(""));
}
