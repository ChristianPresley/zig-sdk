//! The client rules for icons. A server can attach `icons` to `Implementation`, `Tool`,
//! `Resource`, `ResourceTemplate` and `Prompt`. The client treats the icon metadata and the
//! icon bytes as untrusted input.
//!
//! The rules:
//! - The `src` is an `https` URL or a `data:` URI. The client rejects every other scheme.
//! - An `https` icon comes from the origin of the MCP endpoint, or from an origin that the
//!   application trusts. The client rejects a redirect to a different origin or scheme.
//! - The fetch sends no cookies, no `Authorization` header and no client credentials.
//! - The magic bytes set the image format. The declared media type is advisory. The client
//!   rejects a mismatch and an unknown format.
//! - PNG and JPEG are always available. GIF, WebP and SVG are off by default. They pass only
//!   when the policy turns them on and the application gives a decoder. SVG can contain script.
//! - The size, the dimensions and the time of a fetch have limits (`Limits.Icon`).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const types = @import("../protocol/types.zig");
const Limits = @import("../Limits.zig");
const http1 = @import("../transport/http1.zig");

/// The background theme that the icon design expects.
pub const Theme = @typeInfo(@FieldType(types.Icon, "theme")).optional.child;

/// The trust policy and identity for `https` icons.
pub const TlsSetup = http1.TlsSetup;

/// The image formats that the magic bytes identify.
pub const Format = enum {
    png,
    jpeg,
    gif,
    webp,
    svg,

    /// The canonical media type of the format.
    pub fn mimeType(f: Format) []const u8 {
        return switch (f) {
            .png => "image/png",
            .jpeg => "image/jpeg",
            .gif => "image/gif",
            .webp => "image/webp",
            .svg => "image/svg+xml",
        };
    }

    /// True for the formats that every client that shows icons must accept.
    pub fn isRequired(f: Format) bool {
        return f == .png or f == .jpeg;
    }

    /// The format that a media type names, or null for other types. The function ignores the
    /// parameters after `;`. `image/jpg` is an alias of `image/jpeg`.
    pub fn fromMimeType(mime: []const u8) ?Format {
        const e = essence(mime);
        const table = [_]struct { []const u8, Format }{
            .{ "image/png", .png },
            .{ "image/jpeg", .jpeg },
            .{ "image/jpg", .jpeg },
            .{ "image/gif", .gif },
            .{ "image/webp", .webp },
            .{ "image/svg+xml", .svg },
        };
        for (table) |entry| if (std.ascii.eqlIgnoreCase(e, entry[0])) return entry[1];
        return null;
    }
};

/// The image formats that the client accepts.
pub const Formats = struct {
    png: bool = true,
    jpeg: bool = true,
    /// Needs a decoder.
    gif: bool = false,
    /// Needs a decoder.
    webp: bool = false,
    /// Needs a decoder. An SVG image can contain script and references to other resources.
    svg: bool = false,

    pub fn allows(self: Formats, f: Format) bool {
        return switch (f) {
            inline else => |tag| @field(self, @tagName(tag)),
        };
    }

    /// The same set without the formats that need a decoder.
    pub fn requiredOnly(self: Formats) Formats {
        return .{ .png = self.png, .jpeg = self.jpeg };
    }
};

/// Where `https` icons can come from.
pub const Origins = enum {
    /// The origin of the MCP endpoint and the trusted origins of the policy.
    same_origin,
    /// Every `https` origin. This disables the same-origin rule of the specification.
    any,
    /// No `https` icon. Only `data:` icons pass.
    none,
};

pub const Policy = struct {
    /// Accept `data:` icons.
    allow_data: bool = true,
    origins: Origins = .same_origin,
    /// Other origins that the application trusts, as `https://host` or `https://host:port`.
    /// The comparison of the host ignores case.
    trusted_origins: []const []const u8 = &.{},
    formats: Formats = .{},

    /// The policy without the formats that need a decoder, when there is no decoder.
    pub fn effective(self: Policy, has_decoder: bool) Policy {
        var p = self;
        if (!has_decoder) p.formats = self.formats.requiredOnly();
        return p;
    }
};

pub const Error = error{
    OutOfMemory,
    /// The `src` does not parse as a URI, or an `https` URL has no host or has user information.
    InvalidUri,
    /// The scheme is not `https` or `data`, or the policy turns the scheme off.
    UnsupportedScheme,
    /// The `https` origin is not the server origin and not a trusted origin.
    OriginNotAllowed,
    /// The `data:` URI has no comma, or its Base64 text is not valid.
    InvalidDataUri,
    /// The image is larger than `Limits.Icon.max_bytes`.
    TooLarge,
    /// The magic bytes match no known image format.
    UnknownFormat,
    /// The declared media type names a different format than the magic bytes.
    MimeMismatch,
    /// The policy does not accept the format.
    FormatNotAllowed,
    /// The format needs a decoder and the application gave none.
    DecoderRequired,
    /// The decoder of the application returned an error.
    DecoderFailed,
    /// The image header is not valid.
    InvalidImage,
    /// The width or the height is larger than `Limits.Icon.max_dimension`.
    DimensionsTooLarge,
    /// A redirect goes to a different origin or scheme, or has no `Location` header.
    RedirectRefused,
    /// More redirects than the limit.
    TooManyRedirects,
    /// The server answered with a status that is not 200 or a redirect.
    HttpStatus,
    /// The response has a content encoding that is not `identity`.
    InvalidResponse,
    ConnectFailed,
    TlsFailed,
    /// The connection failed after the handshake.
    TransportFailed,
    TrustStoreUnavailable,
    /// The fetch took longer than `Limits.Icon.timeout`.
    Timeout,
    Canceled,
};

/// A checked icon image.
pub const Image = struct {
    format: Format,
    bytes: []const u8,
    /// The width from the image header. Null for SVG.
    width: ?u32 = null,
    /// The height from the image header. Null for SVG.
    height: ?u32 = null,

    pub fn mimeType(self: Image) []const u8 {
        return self.format.mimeType();
    }
};

/// A hook that the application gives to decode, sanitize or convert an image. The SDK calls
/// it for every checked image. The formats that need a decoder pass only when it is present.
/// The returned image goes to the caller. The hook returns an error to reject the image.
pub const Decoder = struct {
    userdata: ?*anyopaque = null,
    decode: *const fn (userdata: ?*anyopaque, arena: Allocator, image: Image) anyerror!Image,
};

// -- Sources and origins ------------------------------------------------------------------------

/// The scheme, the host and the port of a URL.
pub const Origin = struct {
    scheme: []const u8,
    /// The host as the URL writes it.
    host: []const u8,
    port: u16,

    pub fn parse(url: []const u8) error{InvalidUri}!Origin {
        const uri = std.Uri.parse(url) catch return error.InvalidUri;
        const component = uri.host orelse return error.InvalidUri;
        const host = switch (component) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        };
        if (host.len == 0) return error.InvalidUri;
        const port = uri.port orelse defaultPort(uri.scheme) orelse return error.InvalidUri;
        return .{ .scheme = uri.scheme, .host = host, .port = port };
    }

    /// True when the scheme, the host and the port are equal. The comparison ignores case.
    pub fn eql(a: Origin, b: Origin) bool {
        return std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and std.ascii.eqlIgnoreCase(a.host, b.host) and a.port == b.port;
    }

    fn defaultPort(scheme: []const u8) ?u16 {
        if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
        if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
        return null;
    }
};

/// The kind of an icon `src`.
pub const Source = union(enum) {
    /// An `https` URL.
    https: []const u8,
    /// A `data:` URI.
    data: []const u8,
};

/// Classify an icon `src` by its scheme. Only `https` and `data` pass. The check does not
/// look at the origin.
pub fn classify(src: []const u8) Error!Source {
    if (std.ascii.startsWithIgnoreCase(src, "data:")) return .{ .data = src };
    const colon = std.mem.indexOfScalar(u8, src, ':') orelse return error.InvalidUri;
    const scheme = src[0..colon];
    if (scheme.len == 0 or !std.ascii.isAlphabetic(scheme[0])) return error.InvalidUri;
    for (scheme) |c| if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') return error.InvalidUri;
    if (!std.ascii.eqlIgnoreCase(scheme, "https")) return error.UnsupportedScheme;
    const uri = std.Uri.parse(src) catch return error.InvalidUri;
    if (uri.user != null or uri.password != null) return error.InvalidUri;
    _ = Origin.parse(src) catch return error.InvalidUri;
    return .{ .https = src };
}

/// Classify an icon `src` and apply the scheme and origin rules of the policy. `server_url` is
/// the URL of the MCP endpoint. It is null for a server without a URL, for example on stdio.
/// Then only the trusted origins pass.
pub fn checkSource(src: []const u8, server_url: ?[]const u8, policy: Policy) Error!Source {
    const source = try classify(src);
    switch (source) {
        .data => if (!policy.allow_data) return error.UnsupportedScheme,
        .https => |url| try checkOrigin(url, server_url, policy),
    }
    return source;
}

fn checkOrigin(url: []const u8, server_url: ?[]const u8, policy: Policy) Error!void {
    switch (policy.origins) {
        .none => return error.OriginNotAllowed,
        .any => return,
        .same_origin => {},
    }
    const origin = Origin.parse(url) catch return error.InvalidUri;
    if (server_url) |s| if (Origin.parse(s)) |server| {
        if (origin.eql(server)) return;
    } else |_| {};
    for (policy.trusted_origins) |t| {
        const trusted = Origin.parse(t) catch continue;
        if (origin.eql(trusted)) return;
    }
    return error.OriginNotAllowed;
}

// -- data: URIs ---------------------------------------------------------------------------------

pub const DataUri = struct {
    /// The media type of the URI without parameters. Empty when the URI has none.
    media_type: []const u8,
    bytes: []u8,
};

/// Decode a `data:` URI with Base64 or percent encoding. The decoded bytes are in `arena`.
/// Returns `error.TooLarge` before the decode when the bytes cannot fit in `max_bytes`.
pub fn decodeData(arena: Allocator, uri: []const u8, max_bytes: usize) Error!DataUri {
    if (!std.ascii.startsWithIgnoreCase(uri, "data:")) return error.UnsupportedScheme;
    const rest = uri["data:".len..];
    const comma = std.mem.indexOfScalar(u8, rest, ',') orelse return error.InvalidDataUri;
    const header = rest[0..comma];
    const payload = rest[comma + 1 ..];
    // Percent encoding makes a byte at most three characters, and Base64 makes three bytes four.
    if (payload.len / 4 > max_bytes) return error.TooLarge;

    var base64 = false;
    var media_type: []const u8 = "";
    var it = std.mem.splitScalar(u8, header, ';');
    var first = true;
    while (it.next()) |part| {
        if (first) {
            media_type = std.mem.trim(u8, part, " \t");
            first = false;
        } else if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), "base64")) {
            base64 = true;
        }
    }

    const text = try arena.dupe(u8, payload);
    const decoded = std.Uri.percentDecodeInPlace(text);
    if (!base64) {
        if (decoded.len > max_bytes) return error.TooLarge;
        return .{ .media_type = media_type, .bytes = decoded };
    }
    // Remove white space, then the padding, and decode without padding.
    var n: usize = 0;
    for (decoded) |c| if (!std.ascii.isWhitespace(c)) {
        decoded[n] = c;
        n += 1;
    };
    var clean = decoded[0..n];
    var pad: usize = 0;
    while (clean.len > 0 and clean[clean.len - 1] == '=') : (pad += 1) clean = clean[0 .. clean.len - 1];
    if (pad > 2) return error.InvalidDataUri;
    const decoder = std.base64.standard_no_pad.Decoder;
    const size = decoder.calcSizeForSlice(clean) catch return error.InvalidDataUri;
    if (size > max_bytes) return error.TooLarge;
    const out = try arena.alloc(u8, size);
    decoder.decode(out, clean) catch return error.InvalidDataUri;
    return .{ .media_type = media_type, .bytes = out };
}

// -- Content checks -----------------------------------------------------------------------------

/// Identify the image format from the magic bytes.
pub fn sniff(bytes: []const u8) ?Format {
    if (std.mem.startsWith(u8, bytes, "\x89PNG\r\n\x1a\n")) return .png;
    if (std.mem.startsWith(u8, bytes, "\xff\xd8\xff")) return .jpeg;
    if (std.mem.startsWith(u8, bytes, "GIF87a") or std.mem.startsWith(u8, bytes, "GIF89a")) return .gif;
    if (bytes.len >= 12 and std.mem.eql(u8, bytes[0..4], "RIFF") and std.mem.eql(u8, bytes[8..12], "WEBP")) return .webp;
    if (looksLikeSvg(bytes)) return .svg;
    return null;
}

fn looksLikeSvg(bytes: []const u8) bool {
    var t = bytes;
    if (std.mem.startsWith(u8, t, "\xef\xbb\xbf")) t = t[3..];
    t = std.mem.trimStart(u8, t, " \t\r\n");
    if (t.len == 0 or t[0] != '<') return false;
    return std.mem.indexOf(u8, t[0..@min(t.len, 1024)], "<svg") != null;
}

pub const Size = struct { width: u32, height: u32 };

/// Read the width and the height from the image header. Returns null for SVG, which has no
/// fixed size.
pub fn dimensions(format: Format, b: []const u8) Error!?Size {
    const size: Size = switch (format) {
        .svg => return null,
        .png => blk: {
            if (b.len < 24 or !std.mem.eql(u8, b[12..16], "IHDR")) return error.InvalidImage;
            break :blk .{ .width = std.mem.readInt(u32, b[16..20], .big), .height = std.mem.readInt(u32, b[20..24], .big) };
        },
        .gif => blk: {
            if (b.len < 10) return error.InvalidImage;
            break :blk .{ .width = std.mem.readInt(u16, b[6..8], .little), .height = std.mem.readInt(u16, b[8..10], .little) };
        },
        .jpeg => try jpegSize(b),
        .webp => try webpSize(b),
    };
    if (size.width == 0 or size.height == 0) return error.InvalidImage;
    return size;
}

fn jpegSize(b: []const u8) Error!Size {
    var i: usize = 2;
    while (i + 4 <= b.len) {
        if (b[i] != 0xff) return error.InvalidImage;
        const marker = b[i + 1];
        if (marker == 0xff) {
            i += 1;
            continue;
        }
        i += 2;
        if (marker == 0x01 or (marker >= 0xd0 and marker <= 0xd7)) continue;
        // The image data or the end came before a frame header.
        if (marker == 0xd9 or marker == 0xda) return error.InvalidImage;
        const len = std.mem.readInt(u16, b[i..][0..2], .big);
        if (len < 2) return error.InvalidImage;
        const is_frame = marker >= 0xc0 and marker <= 0xcf and marker != 0xc4 and marker != 0xc8 and marker != 0xcc;
        if (is_frame) {
            if (len < 7 or i + 7 > b.len) return error.InvalidImage;
            return .{ .height = std.mem.readInt(u16, b[i + 3 ..][0..2], .big), .width = std.mem.readInt(u16, b[i + 5 ..][0..2], .big) };
        }
        i += len;
    }
    return error.InvalidImage;
}

fn webpSize(b: []const u8) Error!Size {
    if (b.len < 16) return error.InvalidImage;
    const chunk = b[12..16];
    if (std.mem.eql(u8, chunk, "VP8 ")) {
        if (b.len < 30 or !std.mem.eql(u8, b[23..26], "\x9d\x01\x2a")) return error.InvalidImage;
        return .{
            .width = std.mem.readInt(u16, b[26..28], .little) & 0x3fff,
            .height = std.mem.readInt(u16, b[28..30], .little) & 0x3fff,
        };
    }
    if (std.mem.eql(u8, chunk, "VP8L")) {
        if (b.len < 25 or b[20] != 0x2f) return error.InvalidImage;
        const bits = std.mem.readInt(u32, b[21..25], .little);
        return .{ .width = (bits & 0x3fff) + 1, .height = ((bits >> 14) & 0x3fff) + 1 };
    }
    if (std.mem.eql(u8, chunk, "VP8X")) {
        if (b.len < 30) return error.InvalidImage;
        return .{ .width = std.mem.readInt(u24, b[24..27], .little) + 1, .height = std.mem.readInt(u24, b[27..30], .little) + 1 };
    }
    return error.InvalidImage;
}

fn essence(mime: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, mime, ';') orelse mime.len;
    return std.mem.trim(u8, mime[0..end], " \t");
}

/// True for an absent type and for the types that name no format.
fn isGeneric(mime: []const u8) bool {
    const e = essence(mime);
    return e.len == 0 or std.ascii.eqlIgnoreCase(e, "application/octet-stream") or std.ascii.eqlIgnoreCase(e, "binary/octet-stream");
}

/// The declared media type to compare with the magic bytes. The type of the response or of
/// the `data:` URI wins. The `mimeType` of the icon applies when that type is absent or generic.
pub fn declaredType(transport_type: ?[]const u8, icon_type: ?[]const u8) ?[]const u8 {
    if (transport_type) |t| if (!isGeneric(t)) return t;
    if (icon_type) |t| if (!isGeneric(t)) return t;
    return null;
}

/// Check image bytes: the size, the magic bytes against the declared type, the policy formats
/// and the dimensions. The decoder rule is not part of this check.
pub fn inspect(bytes: []const u8, declared: ?[]const u8, formats: Formats, limits: Limits.Icon) Error!Image {
    if (bytes.len > limits.max_bytes) return error.TooLarge;
    const format = sniff(bytes) orelse return error.UnknownFormat;
    if (declared) |d| if (!isGeneric(d)) {
        const named = Format.fromMimeType(d) orelse return error.MimeMismatch;
        if (named != format) return error.MimeMismatch;
    };
    if (!formats.allows(format)) return error.FormatNotAllowed;
    const size = try dimensions(format, bytes);
    if (size) |s| if (s.width > limits.max_dimension or s.height > limits.max_dimension) return error.DimensionsTooLarge;
    return .{
        .format = format,
        .bytes = bytes,
        .width = if (size) |s| s.width else null,
        .height = if (size) |s| s.height else null,
    };
}

/// Apply the decoder rule. A format that needs a decoder fails without one. When a decoder is
/// present, it receives every image and its result goes to the caller.
pub fn finish(arena: Allocator, image: Image, decoder: ?Decoder) Error!Image {
    const d = decoder orelse {
        if (!image.format.isRequired()) return error.DecoderRequired;
        return image;
    };
    return d.decode(d.userdata, arena, image) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.DecoderFailed,
    };
}

// -- Selection ----------------------------------------------------------------------------------

pub const Want = struct {
    /// The edge length in pixels that the interface shows. Null prefers an icon for every
    /// size (`any` or no `sizes`), then the largest icon.
    size: ?u32 = null,
    /// The background of the interface. Null accepts every theme equally.
    theme: ?Theme = null,
};

/// Select the icon that fits `want` best. Icons that fail the scheme, origin or format rules of
/// `policy` are not candidates. Use `Policy.effective` to remove the formats that need a
/// decoder when there is none. The rank is the theme first, then the size, then the order.
pub fn select(list: ?[]const types.Icon, want: Want, server_url: ?[]const u8, policy: Policy) ?types.Icon {
    var best: ?types.Icon = null;
    var best_score: u64 = 0;
    for (list orelse return null) |icon| {
        _ = checkSource(icon.src, server_url, policy) catch continue;
        if (icon.mimeType) |m| if (!isGeneric(m)) {
            const f = Format.fromMimeType(m) orelse continue;
            if (!policy.formats.allows(f)) continue;
        };
        const theme_rank: u64 = if (want.theme) |t| (if (icon.theme) |it| (if (it == t) @as(u64, 2) else 0) else 1) else 0;
        const score = (theme_rank << 40) | sizeScore(icon.sizes, want.size);
        if (best == null or score > best_score) {
            best = icon;
            best_score = score;
        }
    }
    return best;
}

/// A higher score is a better fit. Absent sizes mean every size.
fn sizeScore(sizes: ?[]const []const u8, want: ?u32) u64 {
    const any_score: u64 = 3 << 32;
    const list = sizes orelse return any_score;
    if (list.len == 0) return any_score;
    var best: u64 = 0;
    for (list) |entry| {
        var tokens = std.mem.tokenizeAny(u8, entry, " \t");
        while (tokens.next()) |token| {
            const score: u64 = if (std.ascii.eqlIgnoreCase(token, "any")) any_score else blk: {
                const edge: u64 = parseEdge(token) orelse continue;
                const w: u64 = want orelse break :blk (2 << 32) + edge;
                if (edge == w) break :blk 4 << 32;
                if (edge > w) break :blk (2 << 32) + (std.math.maxInt(u32) - edge);
                break :blk (1 << 32) + edge;
            };
            best = @max(best, score);
        }
    }
    return best;
}

/// The longer edge of a `WxH` size.
fn parseEdge(token: []const u8) ?u32 {
    const x = std.mem.indexOfAny(u8, token, "xX") orelse return null;
    const w = std.fmt.parseInt(u32, token[0..x], 10) catch return null;
    const h = std.fmt.parseInt(u32, token[x + 1 ..], 10) catch return null;
    if (w == 0 or h == 0) return null;
    return @max(w, h);
}

// -- Fetch --------------------------------------------------------------------------------------

pub const FetchOptions = struct {
    /// The URL of the MCP endpoint. Its origin is the origin that `https` icons must have.
    /// Null for a server without a URL: then only the trusted origins pass.
    server_url: ?[]const u8 = null,
    policy: Policy = .{},
    limits: Limits.Icon = .{},
    max_redirect_hops: u8 = 3,
    /// The trust policy for `https` icons. Null uses the system trust store.
    tls: ?TlsSetup = null,
    decoder: ?Decoder = null,
};

/// Get the image of an icon. The function decodes a `data:` icon. It gets an `https` icon with
/// a GET request without credentials. The image bytes are in `arena`. `gpa` must be thread-safe,
/// because the fetch runs in a concurrent task for the timeout.
pub fn fetch(io: Io, gpa: Allocator, arena: Allocator, icon: types.Icon, options: FetchOptions) Error!Image {
    const policy = options.policy.effective(options.decoder != null);
    const source = try checkSource(icon.src, options.server_url, policy);
    const bytes: []const u8, const transport_type: ?[]const u8 = switch (source) {
        .data => |uri| blk: {
            const data = try decodeData(arena, uri, options.limits.max_bytes);
            break :blk .{ data.bytes, data.media_type };
        },
        .https => |url| blk: {
            const body = try download(io, gpa, arena, url, policy, options);
            break :blk .{ body.bytes, body.content_type };
        },
    };
    const image = try inspect(bytes, declaredType(transport_type, icon.mimeType), policy.formats, options.limits);
    return finish(arena, image, options.decoder);
}

const Body = struct { bytes: []const u8, content_type: ?[]const u8 };

const Download = struct {
    io: Io,
    gpa: Allocator,
    arena: Allocator,
    url: []const u8,
    origin: Origin,
    accept: []const u8,
    options: *const FetchOptions,
    body: Body = .{ .bytes = &.{}, .content_type = null },
    result: Error!void = {},
    done: Io.Event = .unset,

    fn run(d: *Download) void {
        d.result = d.perform();
        d.done.set(d.io);
    }

    fn perform(d: *Download) Error!void {
        var bundle: ?std.crypto.Certificate.Bundle = null;
        defer if (bundle) |*b| b.deinit(d.gpa);
        const setup: TlsSetup = d.options.tls orelse blk: {
            bundle = .empty;
            bundle.?.rescan(d.gpa, d.io, Io.Clock.real.now(d.io)) catch return error.TrustStoreUnavailable;
            break :blk .{ .trust = .{ .bundle = &bundle.? } };
        };
        const max = d.options.limits.max_bytes;
        // Only these headers go out. There is no cookie, no authorization and no credential.
        const headers = [_]http1.Header{
            .{ .name = "accept", .value = d.accept },
            .{ .name = "accept-encoding", .value = "identity" },
        };
        var url = d.url;
        var hops: u8 = 0;
        while (true) {
            const target = http1.Target.parse(d.arena, url) catch return error.InvalidUri;
            if (!target.secure) return error.RedirectRefused;
            const conn = http1.Connection.open(d.io, d.gpa, target.host, target.port, setup) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.Canceled => error.Canceled,
                error.ConnectFailed => error.ConnectFailed,
                error.TlsFailed => error.TlsFailed,
            };
            defer conn.close();
            conn.send("GET", target.path, target.host_header, &headers, "") catch return error.TransportFailed;
            const response = conn.receiveHead() catch return error.TransportFailed;
            switch (@intFromEnum(response.head.status)) {
                200 => {},
                301, 302, 303, 307, 308 => {
                    const location = response.head.location orelse return error.RedirectRefused;
                    const next = try resolveRedirect(d.arena, url, location);
                    const next_origin = Origin.parse(next) catch return error.RedirectRefused;
                    if (!std.ascii.eqlIgnoreCase(next_origin.scheme, "https") or !next_origin.eql(d.origin)) return error.RedirectRefused;
                    hops += 1;
                    if (hops > d.options.max_redirect_hops) return error.TooManyRedirects;
                    url = next;
                    continue;
                },
                else => return error.HttpStatus,
            }
            if (response.head.content_encoding != .identity) return error.InvalidResponse;
            if (response.head.content_length) |n| if (n > max) return error.TooLarge;
            // The head is not valid after the body reader starts.
            if (response.head.content_type) |ct| d.body.content_type = try d.arena.dupe(u8, ct);
            const reader = conn.bodyReader(&response);
            d.body.bytes = reader.allocRemaining(d.arena, .limited(max + 1)) catch |e| return switch (e) {
                error.StreamTooLong => error.TooLarge,
                error.OutOfMemory => error.OutOfMemory,
                else => error.TransportFailed,
            };
            if (d.body.bytes.len > max) return error.TooLarge;
            return;
        }
    }
};

/// Resolve a `Location` header against the current URL. The function refuses user information.
fn resolveRedirect(arena: Allocator, base_url: []const u8, location: []const u8) Error![]const u8 {
    const base = std.Uri.parse(base_url) catch return error.InvalidUri;
    const buf = try arena.alloc(u8, location.len * 2 + base_url.len + 64);
    @memcpy(buf[0..location.len], location);
    var aux: []u8 = buf;
    const resolved = base.resolveInPlace(location.len, &aux) catch return error.RedirectRefused;
    if (resolved.user != null or resolved.password != null) return error.RedirectRefused;
    if (resolved.host == null) return error.RedirectRefused;
    return std.fmt.allocPrint(arena, "{f}", .{resolved.fmt(.{ .scheme = true, .authority = true, .path = true, .query = true })});
}

fn download(io: Io, gpa: Allocator, arena: Allocator, url: []const u8, policy: Policy, options: FetchOptions) Error!Body {
    var accept: std.ArrayList(u8) = .empty;
    inline for (@typeInfo(Format).@"enum".fields) |field| {
        const f: Format = @enumFromInt(field.value);
        if (policy.formats.allows(f)) {
            if (accept.items.len > 0) try accept.appendSlice(arena, ", ");
            try accept.appendSlice(arena, f.mimeType());
        }
    }
    var d: Download = .{
        .io = io,
        .gpa = gpa,
        .arena = arena,
        .url = url,
        .origin = Origin.parse(url) catch return error.InvalidUri,
        .accept = accept.items,
        .options = &options,
    };
    const deadline = Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = options.limits.timeout, .clock = .awake });
    var future = io.concurrent(Download.run, .{&d}) catch {
        d.run();
        try d.result;
        return d.body;
    };
    d.done.waitTimeout(io, .{ .deadline = deadline }) catch |e| {
        _ = future.cancel(io);
        return if (e == error.Timeout) error.Timeout else error.Canceled;
    };
    future.await(io);
    try d.result;
    return d.body;
}

// -- Tests --------------------------------------------------------------------------------------

const testing = std.testing;

/// A 1x1 PNG image.
pub const test_png = "\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89" ++
    "\x00\x00\x00\x0dIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82";
/// The header of a 2x3 GIF image.
pub const test_gif = "GIF89a\x02\x00\x03\x00\x00\x00\x00;";
/// The start of a JPEG image with a 5x4 frame header.
pub const test_jpeg = "\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" ++
    "\xff\xc0\x00\x0b\x08\x00\x04\x00\x05\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\xff\xd9";

test "icon schemes" {
    try testing.expect(try classify("https://example.com/i.png") == .https);
    try testing.expect(try classify("HTTPS://example.com/i.png") == .https);
    try testing.expect(try classify("data:image/png;base64,AAAA") == .data);
    try testing.expect(try classify("DATA:,x") == .data);
    for ([_][]const u8{ "http://example.com/i.png", "javascript:alert(1)", "file:///etc/passwd", "ftp://example.com/i.png", "ws://example.com/", "wss://example.com/", "myapp://icon", "blob:https://example.com/x" }) |src| {
        try testing.expectError(error.UnsupportedScheme, classify(src));
    }
    try testing.expectError(error.InvalidUri, classify("no scheme"));
    try testing.expectError(error.InvalidUri, classify(" https://example.com/"));
    try testing.expectError(error.InvalidUri, classify("https:///nohost"));
    try testing.expectError(error.InvalidUri, classify("https://user:pw@example.com/i.png"));
}

test "icon origins" {
    const server = "https://mcp.example.com/mcp";
    const p: Policy = .{};
    _ = try checkSource("https://MCP.example.com:443/icons/a.png", server, p);
    try testing.expectError(error.OriginNotAllowed, checkSource("https://cdn.example.com/a.png", server, p));
    try testing.expectError(error.OriginNotAllowed, checkSource("https://mcp.example.com:8443/a.png", server, p));
    // An http endpoint never matches an https icon.
    try testing.expectError(error.OriginNotAllowed, checkSource("https://127.0.0.1/a.png", "http://127.0.0.1/mcp", p));
    // Without a server URL only the trusted origins pass.
    try testing.expectError(error.OriginNotAllowed, checkSource("https://mcp.example.com/a.png", null, p));
    const trusted: Policy = .{ .trusted_origins = &.{ "https://cdn.example.com", "not a url" } };
    _ = try checkSource("https://cdn.example.com/a.png", null, trusted);
    _ = try checkSource("https://anywhere.example.org/a.png", server, .{ .origins = .any });
    try testing.expectError(error.OriginNotAllowed, checkSource("https://mcp.example.com/a.png", server, .{ .origins = .none }));
    // data: icons have no origin.
    _ = try checkSource("data:image/png;base64,AAAA", null, p);
    try testing.expectError(error.UnsupportedScheme, checkSource("data:image/png;base64,AAAA", null, .{ .allow_data = false }));
}

test "data uris" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const b64 = try decodeData(arena, "data:image/png;base64,aGVs bG8=", 100);
    try testing.expectEqualStrings("image/png", b64.media_type);
    try testing.expectEqualStrings("hello", b64.bytes);
    const no_pad = try decodeData(arena, "data:;base64,aGVsbG8", 100);
    try testing.expectEqualStrings("", no_pad.media_type);
    try testing.expectEqualStrings("hello", no_pad.bytes);
    const pct = try decodeData(arena, "data:image/svg+xml;charset=utf-8,%3Csvg%2F%3E", 100);
    try testing.expectEqualStrings("image/svg+xml", pct.media_type);
    try testing.expectEqualStrings("<svg/>", pct.bytes);
    const pct_b64 = try decodeData(arena, "data:image/png;base64,aGVsbG8%3D", 100);
    try testing.expectEqualStrings("hello", pct_b64.bytes);
    try testing.expectError(error.InvalidDataUri, decodeData(arena, "data:image/png;base64", 100));
    try testing.expectError(error.InvalidDataUri, decodeData(arena, "data:;base64,a$b=", 100));
    try testing.expectError(error.InvalidDataUri, decodeData(arena, "data:;base64,aGVsbG8===", 100));
    try testing.expectError(error.TooLarge, decodeData(arena, "data:;base64,aGVsbG8=", 4));
    try testing.expectError(error.TooLarge, decodeData(arena, "data:,hello", 4));
    // The size check comes before any allocation.
    const huge = "data:;base64," ++ "A" ** 64;
    try testing.expectError(error.TooLarge, decodeData(testing.failing_allocator, huge, 8));
}

test "magic bytes and dimensions" {
    const l: Limits.Icon = .{};
    const png = try inspect(test_png, "image/png", .{}, l);
    try testing.expectEqual(Format.png, png.format);
    try testing.expectEqual(@as(?u32, 1), png.width);
    const jpeg = try inspect(test_jpeg, "image/jpg", .{}, l);
    try testing.expectEqual(Format.jpeg, jpeg.format);
    try testing.expectEqual(@as(?u32, 5), jpeg.width);
    try testing.expectEqual(@as(?u32, 4), jpeg.height);
    const gif = try inspect(test_gif, null, .{ .gif = true }, l);
    try testing.expectEqual(@as(?u32, 3), gif.height);
    const webp = try inspect("RIFF\x00\x00\x00\x00WEBPVP8X\x0a\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x1f\x00\x00", null, .{ .webp = true }, l);
    try testing.expectEqual(@as(?u32, 16), webp.width);
    try testing.expectEqual(@as(?u32, 32), webp.height);
    const svg = try inspect("\xef\xbb\xbf <?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>", "image/svg+xml", .{ .svg = true }, l);
    try testing.expectEqual(Format.svg, svg.format);
    try testing.expectEqual(@as(?u32, null), svg.width);

    // The declared type is advisory, but a mismatch is an error.
    try testing.expectError(error.MimeMismatch, inspect(test_png, "image/jpeg", .{}, l));
    try testing.expectError(error.MimeMismatch, inspect(test_png, "text/html", .{}, l));
    _ = try inspect(test_png, "application/octet-stream", .{}, l);
    _ = try inspect(test_png, "Image/PNG; charset=binary", .{}, l);
    try testing.expectError(error.UnknownFormat, inspect("<html><script>x</script></html>", "image/png", .{}, l));
    try testing.expectError(error.UnknownFormat, inspect("", null, .{}, l));
    // SVG, GIF and WebP are off by default.
    try testing.expectError(error.FormatNotAllowed, inspect("<svg onload=\"x()\"/>", null, .{}, l));
    try testing.expectError(error.FormatNotAllowed, inspect(test_gif, null, .{}, l));
    // Size and dimensions.
    try testing.expectError(error.TooLarge, inspect(test_png, null, .{}, .{ .max_bytes = 10 }));
    var big = test_png[0..].*;
    std.mem.writeInt(u32, big[16..20], 100_000, .big);
    try testing.expectError(error.DimensionsTooLarge, inspect(&big, null, .{}, l));
    try testing.expectError(error.InvalidImage, inspect(test_png[0..20], null, .{}, l));
    try testing.expectError(error.InvalidImage, inspect("\xff\xd8\xff\xda\x00\x02", null, .{}, l));
}

test "declared type precedence" {
    try testing.expectEqualStrings("image/png", declaredType("image/png", "image/jpeg").?);
    try testing.expectEqualStrings("image/jpeg", declaredType("application/octet-stream", "image/jpeg").?);
    try testing.expectEqualStrings("image/jpeg", declaredType(null, "image/jpeg").?);
    try testing.expectEqual(@as(?[]const u8, null), declaredType("", null));
}

fn svgToPng(userdata: ?*anyopaque, arena: Allocator, image: Image) anyerror!Image {
    _ = userdata;
    if (std.mem.indexOf(u8, image.bytes, "script") != null) return error.Unsafe;
    // A sanitizer returns new bytes. This one converts the SVG to a PNG.
    _ = arena;
    return .{ .format = .png, .bytes = test_png, .width = 1, .height = 1 };
}

test "decoder rule" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const svg: Image = .{ .format = .svg, .bytes = "<svg/>" };
    try testing.expectError(error.DecoderRequired, finish(arena, svg, null));
    const decoder: Decoder = .{ .decode = svgToPng };
    const out = try finish(arena, svg, decoder);
    try testing.expectEqual(Format.png, out.format);
    try testing.expectError(error.DecoderFailed, finish(arena, .{ .format = .svg, .bytes = "<svg><script/></svg>" }, decoder));
    const png: Image = .{ .format = .png, .bytes = test_png };
    try testing.expectEqual(png.bytes.ptr, (try finish(arena, png, null)).bytes.ptr);

    // Through fetch with a data: URI. The policy turns SVG on, and the decoder is required.
    const icon: types.Icon = .{ .src = "data:image/svg+xml,%3Csvg%2F%3E" };
    try testing.expectError(error.FormatNotAllowed, fetch(testing.io, testing.allocator, arena, icon, .{ .policy = .{ .formats = .{ .svg = true } } }));
    const converted = try fetch(testing.io, testing.allocator, arena, icon, .{ .policy = .{ .formats = .{ .svg = true } }, .decoder = decoder });
    try testing.expectEqual(Format.png, converted.format);
    try testing.expectError(error.FormatNotAllowed, fetch(testing.io, testing.allocator, arena, icon, .{ .decoder = decoder }));
}

test "fetch of data icons" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const encoder = std.base64.standard.Encoder;
    var b64_buf: [256]u8 = undefined;
    var buf: [256]u8 = undefined;
    const src = try std.fmt.bufPrint(&buf, "data:image/png;base64,{s}", .{encoder.encode(&b64_buf, test_png)});
    const image = try fetch(testing.io, testing.allocator, arena, .{ .src = src }, .{});
    try testing.expectEqualStrings(test_png, image.bytes);
    try testing.expectEqualStrings("image/png", image.mimeType());
    // The data URI says PNG, the bytes are GIF.
    try testing.expectError(error.MimeMismatch, fetch(testing.io, testing.allocator, arena, .{ .src = "data:image/png," ++ test_gif }, .{}));
    // The icon says JPEG and the data URI has no type.
    try testing.expectError(error.MimeMismatch, fetch(testing.io, testing.allocator, arena, .{ .src = "data:;base64,R0lGODlh", .mimeType = "image/jpeg" }, .{}));
    try testing.expectError(error.UnsupportedScheme, fetch(testing.io, testing.allocator, arena, .{ .src = "javascript:alert(1)" }, .{}));
    try testing.expectError(error.TooLarge, fetch(testing.io, testing.allocator, arena, .{ .src = src }, .{ .limits = .{ .max_bytes = 16 } }));
}

test "icon selection" {
    const server = "https://mcp.example.com/mcp";
    const list = [_]types.Icon{
        .{ .src = "https://mcp.example.com/16.png", .sizes = &.{"16x16"} },
        .{ .src = "https://mcp.example.com/48.png", .sizes = &.{ "48x48", "96x96" } },
        .{ .src = "https://mcp.example.com/any.svg", .mimeType = "image/svg+xml", .sizes = &.{"any"} },
        .{ .src = "https://mcp.example.com/dark.png", .sizes = &.{"32x32"}, .theme = .dark },
        .{ .src = "https://evil.example.org/64.png", .sizes = &.{"64x64"} },
        .{ .src = "javascript:alert(1)", .sizes = &.{"64x64"} },
    };
    const p: Policy = .{};
    try testing.expectEqualStrings("https://mcp.example.com/48.png", select(&list, .{ .size = 48 }, server, p).?.src);
    try testing.expectEqualStrings("https://mcp.example.com/48.png", select(&list, .{ .size = 40 }, server, p).?.src);
    try testing.expectEqualStrings("https://mcp.example.com/48.png", select(&list, .{ .size = 200 }, server, p).?.src);
    try testing.expectEqualStrings("https://mcp.example.com/16.png", select(&list, .{ .size = 16 }, server, p).?.src);
    try testing.expectEqualStrings("https://mcp.example.com/dark.png", select(&list, .{ .size = 48, .theme = .dark }, server, p).?.src);
    try testing.expectEqualStrings("https://mcp.example.com/48.png", select(&list, .{ .size = 48, .theme = .light }, server, p).?.src);
    // With SVG on, the scalable icon wins over the smaller and larger ones.
    const svg_on: Policy = .{ .formats = .{ .svg = true } };
    try testing.expectEqualStrings("https://mcp.example.com/any.svg", select(&list, .{ .size = 40 }, server, svg_on).?.src);
    try testing.expectEqualStrings("https://mcp.example.com/48.png", select(&list, .{ .size = 40 }, server, svg_on.effective(false)).?.src);
    try testing.expect(select(&list, .{}, "https://other.example.com/", p) == null);
    try testing.expect(select(null, .{}, server, p) == null);
}
