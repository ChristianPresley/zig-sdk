//! The TLS 1.3 client handshake (RFC 8446 section 4): ClientHello, HelloRetryRequest,
//! server certificate verification, the Finished exchange and the optional client
//! certificate.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Decoder = tls.Decoder;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const suites = @import("../suites.zig");
const Suite = suites.Suite;
const codec = @import("codec.zig");
const common = @import("common.zig");
const ca_names = @import("ca_names.zig");
const key_share = @import("key_share.zig");
const Connection = @import("../Connection.zig");
const CertChain = @import("../CertChain.zig");
const PrivateKey = @import("../PrivateKey.zig");
const verify = @import("../verify.zig");

pub const Trust = verify.Trust;

/// The largest server flight the client accepts: certificate chains up to 64 KiB.
pub const max_handshake_bytes = CertChain.max_chain_bytes + 4096;

pub const Options = struct {
    io: std.Io,
    /// The host name for server name indication and for the certificate check. The client
    /// checks an IP address literal against the certificate but does not send it as SNI.
    host: []const u8,
    trust: Trust,
    /// Application protocols in preference order. Empty sends no ALPN extension.
    alpn: []const []const u8 = &.{},
    /// Cipher suites in preference order. The default has no AEGIS suite. To offer AEGIS
    /// too, use `suites.default_suites_with_aegis` or a list of your own.
    cipher_suites: []const Suite = suites.default_suites,
    /// Groups in preference order. The client sends a key share for the first group. When
    /// the first group is a hybrid group, the client also sends a key share for the first
    /// group without a post-quantum part. A server without the hybrid group then needs no
    /// HelloRetryRequest.
    groups: []const key_share.Group = key_share.default_groups,
    /// The certificate chain to present when the server asks for one. Without it and without
    /// `identities`, the client answers a request with an empty certificate list.
    identity: ?*const CertChain = null,
    /// The padding of the encrypted records that the client sends (RFC 8446 section 5.4).
    /// It starts with the first encrypted handshake record.
    padding: Connection.Padding = .none,
    /// More certificate chains, after `identity` in preference order. When the request of the
    /// server has the certificate_authorities extension (RFC 8446 section 4.2.4), the client
    /// takes the first chain that leads to one of the names. Without a match,
    /// `identity_fallback` decides. Without names, the client takes the first chain.
    identities: []const *const CertChain = &.{},
    /// The answer when the server names certificate authorities and no chain leads to one of
    /// them. `first` sends the first chain, and `none` sends an empty certificate list.
    identity_fallback: enum { first, none } = .first,
    /// Send the subject names of the `trust` anchors in the certificate_authorities extension
    /// of the ClientHello. A server with more than one chain can then choose a chain that the
    /// client trusts. Only the `ca_set` and `bundle` policies have anchors. The list can be
    /// large, so the default is off. When the names do not fit in
    /// `ca_names.max_hello_list_len` bytes or in a ClientHello of 16 KiB, the client sends no
    /// names.
    send_ca_names: bool = false,
    /// Plaintext buffer for the application. At least `Connection.min_read_buffer_len`.
    read_buffer: []u8,
    /// Plaintext buffer for the application.
    write_buffer: []u8,
    allow_truncation_attacks: bool = false,
    /// Receives the alert that ended a failed handshake, sent or received.
    alert: ?*tls.Alert = null,
    /// The current time in seconds since the epoch for the certificate validity. Null
    /// reads the real clock of `io`.
    now_sec: ?i64 = null,
};

pub const ConnectError = common.Error;

const offered_schemes = common.signature_schemes;
const client_verify_context = codec.client_certificate_verify_context;

/// The largest HelloRetryRequest cookie the client echoes. A larger cookie ends the
/// handshake with `illegal_parameter`.
pub const max_cookie_len = 8 << 10;
/// The ClientHello buffer: two key shares, the cookie, the names of the certificate
/// authorities and the other extensions.
const client_hello_buffer_len = max_cookie_len + 2 * (4 + key_share.max_public_len) + (6 + ca_names.max_hello_list_len) + 2048;

/// The key shares of a ClientHello: one, or a hybrid share and a fallback share.
const Shares = struct {
    items: [2]key_share.KeyShare = undefined,
    len: usize = 0,

    fn slice(self: *const Shares) []const key_share.KeyShare {
        return self.items[0..self.len];
    }

    fn find(self: *const Shares, group: key_share.Group) ?*const key_share.KeyShare {
        for (self.items[0..self.len]) |*s| if (s.group() == group) return s;
        return null;
    }

    fn wipe(self: *Shares) void {
        for (self.items[0..self.len]) |*s| s.wipe();
        self.len = 0;
    }

    /// The shares for the first ClientHello.
    fn generate(self: *Shares, io: std.Io, groups: []const key_share.Group) error{EntropyUnavailable}!void {
        self.items[0] = try key_share.KeyShare.generate(io, groups[0]);
        self.len = 1;
        if (!groups[0].isHybrid()) return;
        for (groups[1..]) |g| {
            if (g.isHybrid()) continue;
            self.items[1] = try key_share.KeyShare.generate(io, g);
            self.len = 2;
            return;
        }
    }
};

/// Run the client side of a handshake on a connected stream.
pub fn connect(input: *Reader, output: *Writer, options: Options) ConnectError!Connection {
    if (options.cipher_suites.len == 0 or options.groups.len == 0) return error.TlsInternalError;
    var c: Connection = .init(input, output, .client, options.read_buffer, options.write_buffer, options.allow_truncation_attacks);
    errdefer c.deinit();
    try c.setPadding(options.io, options.padding);
    var hs_buf: [max_handshake_bytes]u8 = undefined;
    var reader: common.MessageReader = .init(&hs_buf);

    var random: [32]u8 = undefined;
    options.io.randomSecure(&random) catch return error.EntropyUnavailable;
    var session_id: [32]u8 = undefined;
    options.io.randomSecure(&session_id) catch return error.EntropyUnavailable;
    var shares: Shares = .{};
    defer shares.wipe();
    shares.generate(options.io, options.groups) catch return error.EntropyUnavailable;

    var ch_buf: [client_hello_buffer_len]u8 = undefined;
    const first_hello = clientHello(&ch_buf, random, &session_id, options, shares.slice(), null, options.send_ca_names);
    const hello1 = first_hello.bytes;
    c.writeRecord(.handshake, hello1) catch return error.WriteFailed;
    c.output.flush() catch return error.WriteFailed;

    const first = try reader.next(&c, options.alert);
    if (first.kind != .server_hello) return common.abort(&c, options.alert, .unexpected_message, error.TlsUnexpectedMessage);
    const sh = ServerHello.parse(first.body) catch |e| return common.abortParse(&c, options.alert, e);
    const suite = offeredSuite(options, sh.cipher_suite) orelse return common.abort(&c, options.alert, .illegal_parameter, error.TlsIllegalParameter);
    switch (suite) {
        inline else => |s| return run(Suite.Type(s), s, &c, &reader, options, &shares, random, &session_id, &ch_buf, first_hello, first, sh),
    }
}

fn run(
    comptime S: type,
    comptime suite: Suite,
    c: *Connection,
    reader: *common.MessageReader,
    options: Options,
    shares: *Shares,
    random: [32]u8,
    session_id: *const [32]u8,
    ch_buf: *[client_hello_buffer_len]u8,
    first_hello: Hello,
    first: common.Message,
    first_sh: ServerHello,
) ConnectError!Connection {
    const hello1 = first_hello.bytes;
    const K = suites.Schedule(S);
    const alert_out = options.alert;
    var transcript: suites.Transcript = .init(S);
    var msg_buf: [1024]u8 = undefined;
    var sh = first_sh;
    var ccs_sent = false;

    if (sh.is_hrr) {
        // HelloRetryRequest: the server wants a key share for another group.
        if (!std.mem.eql(u8, sh.session_id, session_id)) return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
        const wanted = sh.key_share_group orelse return common.abort(c, alert_out, .missing_extension, error.TlsMissingExtension);
        const group = key_share.Group.fromWire(wanted) orelse return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
        // The group must be offered, and must not be one that already has a key share.
        if (!offersGroup(options, group) or shares.find(group) != null) return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
        if (sh.cookie) |cookie| if (cookie.len > max_cookie_len) return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
        transcript.update(hello1);
        const ch1_hash = transcript.peek(S);
        transcript = .init(S);
        transcript.update(codec.messageHash(&msg_buf, &ch1_hash));
        transcript.update(first.raw);

        shares.wipe();
        shares.items[0] = key_share.KeyShare.generate(options.io, group) catch return common.abort(c, alert_out, .internal_error, error.EntropyUnavailable);
        shares.len = 1;
        // The first ClientHello is in the transcript, so its buffer is free again. The second
        // ClientHello has the names of the first one (RFC 8446 section 4.1.2).
        const hello2 = clientHello(ch_buf, random, session_id, options, shares.slice(), sh.cookie, first_hello.names_sent).bytes;
        c.writeChangeCipherSpec() catch return error.WriteFailed;
        ccs_sent = true;
        c.writeRecord(.handshake, hello2) catch return error.WriteFailed;
        c.output.flush() catch return error.WriteFailed;
        transcript.update(hello2);

        const second = try reader.next(c, alert_out);
        if (second.kind != .server_hello) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
        sh = ServerHello.parse(second.body) catch |e| return common.abortParse(c, alert_out, e);
        if (sh.is_hrr) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
        if (sh.cipher_suite != suite.wire()) return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
        transcript.update(second.raw);
    } else {
        transcript.update(hello1);
        transcript.update(first.raw);
    }
    if (!std.mem.eql(u8, sh.session_id, session_id)) return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
    // A TLS 1.3 server never sets the downgrade sentinel (section 4.1.3).
    if (std.mem.eql(u8, sh.random[24..31], "DOWNGRD")) return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);

    // Key exchange.
    const peer_group = sh.key_share_group orelse return common.abort(c, alert_out, .missing_extension, error.TlsMissingExtension);
    const selected = key_share.Group.fromWire(peer_group) orelse return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
    const share = shares.find(selected) orelse return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
    const peer_public = sh.key_share_public orelse return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
    var shared_buf: [key_share.max_shared_len]u8 = undefined;
    defer crypto.secureZero(u8, &shared_buf);
    const shared = share.sharedSecret(peer_public, &shared_buf) catch |e| switch (e) {
        error.IllegalParameter => return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter),
        error.DecryptError => return common.abort(c, alert_out, .decrypt_error, error.TlsDecryptError),
    };
    var handshake_secret = K.handshakeSecret(shared);
    defer crypto.secureZero(u8, &handshake_secret);
    const hello_hash = transcript.peek(S);
    var client_hs = K.trafficSecret(handshake_secret, "c hs traffic", hello_hash);
    defer crypto.secureZero(u8, &client_hs);
    var server_hs = K.trafficSecret(handshake_secret, "s hs traffic", hello_hash);
    defer crypto.secureZero(u8, &server_hs);
    if (reader.pendingBytes() != 0) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
    c.read_keys = suites.DirectionKeys.init(suite, server_hs);

    // EncryptedExtensions.
    const ee = try reader.next(c, alert_out);
    if (ee.kind != .encrypted_extensions) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
    const ee_parsed = EncryptedExtensions.parse(ee.body) catch |e| return common.abortParse(c, alert_out, e);
    if (ee_parsed.alpn) |name| {
        if (!offersAlpn(options, name)) return common.abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter);
        c.setAlpn(name);
    }
    transcript.update(ee.raw);

    // Optional CertificateRequest, then Certificate.
    var msg = try reader.next(c, alert_out);
    var cert_request: ?CertificateRequest = null;
    var identity: ?*const CertChain = null;
    if (msg.kind == .certificate_request) {
        var req = CertificateRequest.parse(msg.body) catch |e| return common.abortParse(c, alert_out, e);
        // The names point into the message buffer, which the next message overwrites.
        identity = chooseIdentity(options, req.authorities);
        req.authorities = null;
        cert_request = req;
        transcript.update(msg.raw);
        msg = try reader.next(c, alert_out);
    }
    if (msg.kind != .certificate) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
    const chain = common.CertificateMessage.parse(msg.body) catch |e| return common.abortParse(c, alert_out, e);
    if (chain.count == 0 or chain.context.len != 0) return common.abort(c, alert_out, .decode_error, error.TlsDecodeError);
    const now_sec = options.now_sec orelse std.Io.Clock.real.now(options.io).toSeconds();
    const leaf = verify.verifyChain(chain.certs[0..chain.count], options.trust, .{
        .purpose = .server,
        .host = options.host,
        .now_sec = now_sec,
    }) catch |e| return common.abortVerify(c, alert_out, e);
    c.peer_fingerprint = common.fingerprint(chain.certs[0]);
    transcript.update(msg.raw);

    // CertificateVerify over the transcript through Certificate.
    const cv = try reader.next(c, alert_out);
    if (cv.kind != .certificate_verify) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
    var to_verify: [codec.certificate_verify_context.len + S.digest_length]u8 = undefined;
    @memcpy(to_verify[0..codec.certificate_verify_context.len], codec.certificate_verify_context);
    to_verify[codec.certificate_verify_context.len..].* = transcript.peek(S);
    const cv_parsed = common.CertificateVerifyMessage.parse(cv.body) catch |e| return common.abortParse(c, alert_out, e);
    verify.verifySignature(&leaf, cv_parsed.scheme, cv_parsed.signature, &to_verify) catch |e| return common.abortSignature(c, alert_out, e);
    transcript.update(cv.raw);

    // Server Finished.
    const fin = try reader.next(c, alert_out);
    if (fin.kind != .finished) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
    const expected = K.verifyData(K.finishedKey(server_hs), transcript.peek(S));
    if (fin.body.len != expected.len or !crypto.timing_safe.eql([expected.len]u8, expected, fin.body[0..expected.len].*)) {
        return common.abort(c, alert_out, .decrypt_error, error.TlsDecryptError);
    }
    if (reader.pendingBytes() != 0) return common.abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
    transcript.update(fin.raw);

    // Application secrets come from the transcript through the server Finished.
    var master = K.masterSecret(handshake_secret);
    defer crypto.secureZero(u8, &master);
    const finished_hash = transcript.peek(S);
    const client_ap = K.trafficSecret(master, "c ap traffic", finished_hash);
    const server_ap = K.trafficSecret(master, "s ap traffic", finished_hash);
    c.read_keys.wipe();
    c.read_keys = suites.DirectionKeys.init(suite, server_ap);

    // The client flight: compatibility change_cipher_spec, then the encrypted messages.
    if (!ccs_sent) c.writeChangeCipherSpec() catch return error.WriteFailed;
    c.write_keys = suites.DirectionKeys.init(suite, client_hs);
    if (cert_request) |req| {
        try sendClientCertificate(S, c, &transcript, options, req, identity, alert_out);
    }
    const client_verify = K.verifyData(K.finishedKey(client_hs), transcript.peek(S));
    const client_fin = codec.finished(&msg_buf, &client_verify);
    c.writeRecord(.handshake, client_fin) catch return error.WriteFailed;
    c.output.flush() catch return error.WriteFailed;
    transcript.update(client_fin);

    c.write_keys.wipe();
    c.write_keys = suites.DirectionKeys.init(suite, client_ap);
    c.handshake_complete = true;
    c.suite = suite;
    c.group = share.group().wire();
    return c.*;
}

/// The chain for a CertificateRequest with the name list `authorities`. The candidates are
/// `identity`, then `identities`.
fn chooseIdentity(options: Options, authorities: ?[]const u8) ?*const CertChain {
    const first: *const CertChain = options.identity orelse
        (if (options.identities.len > 0) options.identities[0] else return null);
    const list = authorities orelse return first;
    if (options.identity) |chain| if (ca_names.chainMatches(chain, list)) return chain;
    for (options.identities) |chain| if (ca_names.chainMatches(chain, list)) return chain;
    return switch (options.identity_fallback) {
        .first => first,
        .none => null,
    };
}

/// Send the Certificate and, with an identity, the CertificateVerify.
fn sendClientCertificate(comptime S: type, c: *Connection, transcript: *suites.Transcript, options: Options, req: CertificateRequest, identity: ?*const CertChain, alert_out: ?*tls.Alert) ConnectError!void {
    var cert_buf: [CertChain.max_chain_bytes + 512]u8 = undefined;
    var b: codec.Builder = .{ .buf = &cert_buf };
    b.byte(@intFromEnum(tls.HandshakeType.certificate));
    const msg = b.beginLen(u24);
    b.byte(req.context_len);
    b.bytes(req.context());
    if (identity) |chain| {
        // The chain message of the identity carries the list after its empty context.
        b.bytes(chain.handshake_message[5..]);
    } else {
        b.int(u24, 0);
    }
    b.endLen(u24, msg);
    const cert_msg = b.slice();
    c.writeRecord(.handshake, cert_msg) catch return error.WriteFailed;
    transcript.update(cert_msg);

    const chain = identity orelse return;
    const scheme = for (chain.key.schemes()) |s| {
        if (req.offersScheme(@intFromEnum(s))) break s;
    } else return common.abort(c, alert_out, .handshake_failure, error.TlsHandshakeFailure);
    var to_sign: [client_verify_context.len + S.digest_length]u8 = undefined;
    @memcpy(to_sign[0..client_verify_context.len], client_verify_context);
    to_sign[client_verify_context.len..].* = transcript.peek(S);
    var noise: [48]u8 = undefined;
    options.io.randomSecure(&noise) catch return common.abort(c, alert_out, .internal_error, error.EntropyUnavailable);
    var sig_buf: [PrivateKey.max_signature_len]u8 = undefined;
    const signature = chain.key.signScheme(scheme, &to_sign, noise, &sig_buf) catch return common.abort(c, alert_out, .internal_error, error.TlsInternalError);
    var cv_buf: [8 + PrivateKey.max_signature_len]u8 = undefined;
    const cv = codec.certificateVerify(&cv_buf, @intFromEnum(scheme), signature);
    c.writeRecord(.handshake, cv) catch return error.WriteFailed;
    transcript.update(cv);
}

// -- ClientHello -------------------------------------------------------------------------------

/// True when `host` can go into the server_name extension: a DNS name, not an address.
fn isServerName(host: []const u8) bool {
    if (host.len == 0 or host.len > 255) return false;
    if (std.Io.net.IpAddress.parse(host, 0)) |_| return false else |_| {}
    for (host) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '.')) return false;
    return true;
}

/// A ClientHello message, and whether it has the certificate_authorities extension.
const Hello = struct { bytes: []u8, names_sent: bool };

/// Build a ClientHello. With `send_names`, it has the names of the `trust` anchors when they
/// fit. In the first ClientHello they must also keep the message at 16 KiB or less.
fn clientHello(buf: []u8, random: [32]u8, session_id: *const [32]u8, options: Options, shares: []const key_share.KeyShare, cookie: ?[]const u8, send_names: bool) Hello {
    var b: codec.Builder = .{ .buf = buf };
    b.byte(@intFromEnum(tls.HandshakeType.client_hello));
    const msg = b.beginLen(u24);
    b.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2));
    b.bytes(&random);
    b.byte(32);
    b.bytes(session_id);
    const cs = b.beginLen(u16);
    for (options.cipher_suites) |s| b.int(u16, s.wire());
    b.endLen(u16, cs);
    b.byte(1);
    b.byte(0); // null compression
    const exts = b.beginLen(u16);
    if (isServerName(options.host)) {
        b.int(u16, @intFromEnum(tls.ExtensionType.server_name));
        const ext = b.beginLen(u16);
        const list = b.beginLen(u16);
        b.byte(0); // host_name
        b.int(u16, @intCast(options.host.len));
        b.bytes(options.host);
        b.endLen(u16, list);
        b.endLen(u16, ext);
    }
    {
        b.int(u16, @intFromEnum(tls.ExtensionType.supported_versions));
        const ext = b.beginLen(u16);
        b.byte(2);
        b.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_3));
        b.endLen(u16, ext);
    }
    {
        b.int(u16, @intFromEnum(tls.ExtensionType.supported_groups));
        const ext = b.beginLen(u16);
        const list = b.beginLen(u16);
        for (options.groups) |g| b.int(u16, g.wire());
        b.endLen(u16, list);
        b.endLen(u16, ext);
    }
    {
        b.int(u16, @intFromEnum(tls.ExtensionType.signature_algorithms));
        const ext = b.beginLen(u16);
        const list = b.beginLen(u16);
        for (offered_schemes) |s| b.int(u16, @intFromEnum(s));
        b.endLen(u16, list);
        b.endLen(u16, ext);
    }
    {
        b.int(u16, @intFromEnum(tls.ExtensionType.key_share));
        const ext = b.beginLen(u16);
        const list = b.beginLen(u16);
        var public_buf: [key_share.max_public_len]u8 = undefined;
        for (shares) |*share| {
            const public = share.publicBytes(&public_buf);
            b.int(u16, share.group().wire());
            b.int(u16, @intCast(public.len));
            b.bytes(public);
        }
        b.endLen(u16, list);
        b.endLen(u16, ext);
    }
    if (options.alpn.len > 0) {
        b.int(u16, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation));
        const ext = b.beginLen(u16);
        const list = b.beginLen(u16);
        for (options.alpn) |name| {
            b.byte(@intCast(name.len));
            b.bytes(name);
        }
        b.endLen(u16, list);
        b.endLen(u16, ext);
    }
    var names_sent = false;
    if (send_names) {
        // The message body of the first ClientHello stays at `codec.max_message_len` or less.
        // The extension header has 6 bytes.
        const room = (codec.max_message_len + 4) -| (b.len + 6);
        const limit = if (cookie == null) @min(ca_names.max_hello_list_len, room) else ca_names.max_hello_list_len;
        names_sent = ca_names.write(&b, options.trust, limit);
    }
    if (cookie) |value| {
        b.int(u16, @intFromEnum(tls.ExtensionType.cookie));
        const ext = b.beginLen(u16);
        b.int(u16, @intCast(value.len));
        b.bytes(value);
        b.endLen(u16, ext);
    }
    b.endLen(u16, exts);
    b.endLen(u24, msg);
    return .{ .bytes = b.slice(), .names_sent = names_sent };
}

fn offeredSuite(options: Options, wire: u16) ?Suite {
    for (options.cipher_suites) |s| if (s.wire() == wire) return s;
    return null;
}

fn offersGroup(options: Options, group: key_share.Group) bool {
    for (options.groups) |g| if (g == group) return true;
    return false;
}

fn offersAlpn(options: Options, name: []const u8) bool {
    for (options.alpn) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

// -- Server messages ---------------------------------------------------------------------------

/// A parsed ServerHello or HelloRetryRequest. Slices point into the message buffer.
pub const ServerHello = struct {
    random: [32]u8,
    session_id: []const u8,
    cipher_suite: u16,
    is_hrr: bool,
    key_share_group: ?u16 = null,
    /// Absent in a HelloRetryRequest.
    key_share_public: ?[]const u8 = null,
    cookie: ?[]const u8 = null,

    pub fn parse(body: []u8) codec.ParseError!ServerHello {
        var d: Decoder = .fromTheirSlice(body);
        d.ensure(2 + 32 + 1) catch return error.DecodeError;
        if (d.decode(u16) != @intFromEnum(tls.ProtocolVersion.tls_1_2)) return error.ProtocolVersion;
        var sh: ServerHello = .{ .random = d.array(32).*, .session_id = &.{}, .cipher_suite = 0, .is_hrr = false };
        sh.is_hrr = std.mem.eql(u8, &sh.random, &tls.hello_retry_request_sequence);
        const sid_len = d.decode(u8);
        if (sid_len > 32) return error.DecodeError;
        d.ensure(sid_len + 3) catch return error.DecodeError;
        sh.session_id = d.slice(sid_len);
        sh.cipher_suite = d.decode(u16);
        if (d.decode(u8) != 0) return error.IllegalParameter; // compression
        if (d.eof()) return error.MissingExtension;
        d.ensure(2) catch return error.DecodeError;
        const ext_len = d.decode(u16);
        var exts = d.sub(ext_len) catch return error.DecodeError;
        if (!d.eof()) return error.DecodeError;
        var version_ok = false;
        var seen_key_share = false;
        while (!exts.eof()) {
            exts.ensure(4) catch return error.DecodeError;
            const et = exts.decode(u16);
            const len = exts.decode(u16);
            var ext = exts.sub(len) catch return error.DecodeError;
            switch (@as(tls.ExtensionType, @enumFromInt(et))) {
                .supported_versions => {
                    if (version_ok) return error.IllegalParameter;
                    ext.ensure(2) catch return error.DecodeError;
                    if (ext.decode(u16) != @intFromEnum(tls.ProtocolVersion.tls_1_3)) return error.ProtocolVersion;
                    if (!ext.eof()) return error.DecodeError;
                    version_ok = true;
                },
                .key_share => {
                    if (seen_key_share) return error.IllegalParameter;
                    seen_key_share = true;
                    ext.ensure(2) catch return error.DecodeError;
                    sh.key_share_group = ext.decode(u16);
                    if (sh.is_hrr) {
                        if (!ext.eof()) return error.DecodeError;
                    } else {
                        ext.ensure(2) catch return error.DecodeError;
                        const klen = ext.decode(u16);
                        if (klen == 0) return error.DecodeError;
                        ext.ensure(klen) catch return error.DecodeError;
                        sh.key_share_public = ext.slice(klen);
                        if (!ext.eof()) return error.DecodeError;
                    }
                },
                .cookie => {
                    if (!sh.is_hrr or sh.cookie != null) return error.IllegalParameter;
                    ext.ensure(2) catch return error.DecodeError;
                    const clen = ext.decode(u16);
                    if (clen == 0) return error.DecodeError;
                    ext.ensure(clen) catch return error.DecodeError;
                    sh.cookie = ext.slice(clen);
                    if (!ext.eof()) return error.DecodeError;
                },
                // The client offered no pre-shared key, so the server must not select one.
                else => return error.IllegalParameter,
            }
        }
        if (!version_ok) return error.ProtocolVersion;
        return sh;
    }
};

pub const EncryptedExtensions = struct {
    alpn: ?[]const u8 = null,

    pub fn parse(body: []u8) codec.ParseError!EncryptedExtensions {
        var d: Decoder = .fromTheirSlice(body);
        d.ensure(2) catch return error.DecodeError;
        const ext_len = d.decode(u16);
        var exts = d.sub(ext_len) catch return error.DecodeError;
        if (!d.eof()) return error.DecodeError;
        var result: EncryptedExtensions = .{};
        var seen: codec.ExtensionSet = .initEmpty();
        while (!exts.eof()) {
            exts.ensure(4) catch return error.DecodeError;
            const et = exts.decode(u16);
            const len = exts.decode(u16);
            var ext = exts.sub(len) catch return error.DecodeError;
            if (seen.isSet(et)) return error.IllegalParameter;
            seen.set(et);
            switch (@as(tls.ExtensionType, @enumFromInt(et))) {
                .application_layer_protocol_negotiation => {
                    ext.ensure(3) catch return error.DecodeError;
                    const list_len = ext.decode(u16);
                    if (list_len == 0) return error.DecodeError;
                    var list = ext.sub(list_len) catch return error.DecodeError;
                    if (!ext.eof()) return error.DecodeError;
                    list.ensure(1) catch return error.DecodeError;
                    const plen = list.decode(u8);
                    if (plen == 0) return error.IllegalParameter;
                    list.ensure(plen) catch return error.DecodeError;
                    result.alpn = list.slice(plen);
                    if (!list.eof()) return error.IllegalParameter; // exactly one protocol
                },
                .server_name => {
                    if (len != 0) return error.DecodeError;
                },
                .supported_groups => {},
                // Anything the client did not offer is a protocol violation (section 4.2).
                else => return error.IllegalParameter,
            }
        }
        return result;
    }
};

/// A parsed CertificateRequest. The fields other than `authorities` are copies: the next
/// message overwrites the reader buffer.
pub const CertificateRequest = struct {
    context_buf: [255]u8 = undefined,
    context_len: u8 = 0,
    schemes: [64]u16 = undefined,
    scheme_count: u8 = 0,
    /// The checked name list of the certificate_authorities extension. It points into the
    /// message buffer and is valid until the next message.
    authorities: ?[]const u8 = null,

    pub fn parse(body: []u8) codec.ParseError!CertificateRequest {
        var d: Decoder = .fromTheirSlice(body);
        d.ensure(1) catch return error.DecodeError;
        const ctx_len = d.decode(u8);
        d.ensure(@as(usize, ctx_len) + 2) catch return error.DecodeError;
        var result: CertificateRequest = .{ .context_len = ctx_len };
        @memcpy(result.context_buf[0..ctx_len], d.slice(ctx_len));
        const ext_len = d.decode(u16);
        var exts = d.sub(ext_len) catch return error.DecodeError;
        if (!d.eof()) return error.DecodeError;
        var seen: codec.ExtensionSet = .initEmpty();
        while (!exts.eof()) {
            exts.ensure(4) catch return error.DecodeError;
            const et = exts.decode(u16);
            const len = exts.decode(u16);
            var ext = exts.sub(len) catch return error.DecodeError;
            if (seen.isSet(et)) return error.IllegalParameter;
            seen.set(et);
            if (et == ca_names.extension_type) result.authorities = try ca_names.parse(ext.buf);
            if (@as(tls.ExtensionType, @enumFromInt(et)) == .signature_algorithms) {
                ext.ensure(2) catch return error.DecodeError;
                const list_len = ext.decode(u16);
                if (list_len < 2 or list_len % 2 != 0) return error.DecodeError;
                var list = ext.sub(list_len) catch return error.DecodeError;
                if (!ext.eof()) return error.DecodeError;
                while (!list.eof()) {
                    list.ensure(2) catch return error.DecodeError;
                    const scheme = list.decode(u16);
                    if (result.scheme_count < result.schemes.len) {
                        result.schemes[result.scheme_count] = scheme;
                        result.scheme_count += 1;
                    }
                }
            }
        }
        if (!seen.isSet(@intFromEnum(tls.ExtensionType.signature_algorithms))) return error.MissingExtension;
        return result;
    }

    pub fn context(self: *const CertificateRequest) []const u8 {
        return self.context_buf[0..self.context_len];
    }

    pub fn offersScheme(self: *const CertificateRequest, id: u16) bool {
        for (self.schemes[0..self.scheme_count]) |s| if (s == id) return true;
        return false;
    }
};

test "server hello parsing" {
    var buf: [256]u8 = undefined;
    const sh = codec.serverHello(&buf, [_]u8{1} ** 32, "abc", 0x1301, 0x001d, &([_]u8{2} ** 32), false);
    const parsed = try ServerHello.parse(sh[4..]);
    try std.testing.expect(!parsed.is_hrr);
    try std.testing.expectEqual(0x1301, parsed.cipher_suite);
    try std.testing.expectEqual(0x001d, parsed.key_share_group.?);
    try std.testing.expectEqual(32, parsed.key_share_public.?.len);
    const hrr = codec.serverHello(&buf, tls.hello_retry_request_sequence, "abc", 0x1301, 0x0017, &.{}, true);
    const parsed_hrr = try ServerHello.parse(hrr[4..]);
    try std.testing.expect(parsed_hrr.is_hrr);
    try std.testing.expectEqual(0x0017, parsed_hrr.key_share_group.?);
    try std.testing.expect(parsed_hrr.key_share_public == null);
    try std.testing.expectError(error.DecodeError, ServerHello.parse(sh[4..20]));
}

test "certificate request with a long context is a decode error" {
    // The fuzz job found an integer overflow for a context length of 254 or 255.
    var body = [_]u8{ 0xff, 0x00, 0x00 };
    try std.testing.expectError(error.DecodeError, CertificateRequest.parse(&body));
    body[0] = 0xfe;
    try std.testing.expectError(error.DecodeError, CertificateRequest.parse(&body));
}

test "the default client hello offers no AEGIS suite" {
    const io = std.testing.io;
    var read_buf: [1]u8 = undefined;
    var write_buf: [1]u8 = undefined;
    var options: Options = .{ .io = io, .host = "localhost", .trust = .self_signed, .read_buffer = &read_buf, .write_buffer = &write_buf };
    var shares: Shares = .{};
    defer shares.wipe();
    try shares.generate(io, &.{.x25519});
    var buf: [client_hello_buffer_len]u8 = undefined;
    const session_id = [_]u8{0} ** 32;
    {
        const hello = try codec.ClientHello.parse(clientHello(&buf, [_]u8{1} ** 32, &session_id, options, shares.slice(), null, false).bytes[4..]);
        for (suites.default_suites) |s| try std.testing.expect(hello.offersSuite(s.wire()));
        try std.testing.expect(!hello.offersSuite(Suite.AEGIS_128L_SHA256.wire()));
        try std.testing.expect(!hello.offersSuite(Suite.AEGIS_256_SHA512.wire()));
    }
    // The option adds both AEGIS suites.
    options.cipher_suites = suites.default_suites_with_aegis;
    {
        const hello = try codec.ClientHello.parse(clientHello(&buf, [_]u8{1} ** 32, &session_id, options, shares.slice(), null, false).bytes[4..]);
        for (suites.default_suites) |s| try std.testing.expect(hello.offersSuite(s.wire()));
        try std.testing.expect(hello.offersSuite(Suite.AEGIS_128L_SHA256.wire()));
        try std.testing.expect(hello.offersSuite(Suite.AEGIS_256_SHA512.wire()));
    }
}

/// A ServerHello body with the `legacy_session_id` "abc", `TLS_AES_128_GCM_SHA256` and `exts`.
fn testServerHello(buf: []u8, random: [32]u8, exts: []const u8) []u8 {
    var b: codec.Builder = .{ .buf = buf };
    b.int(u16, 0x0303);
    b.bytes(&random);
    b.byte(3);
    b.bytes("abc");
    b.int(u16, 0x1301);
    b.byte(0);
    b.int(u16, @intCast(exts.len));
    b.bytes(exts);
    return b.slice();
}

test "trailing bytes and duplicates in server extensions are refused" {
    var buf: [256]u8 = undefined;
    const versions = "\x00\x2b\x00\x02\x03\x04";
    const versions_long = "\x00\x2b\x00\x03\x03\x04\x00";
    const share = "\x00\x33\x00\x24\x00\x1d\x00\x20" ++ "\x02" ** 32;
    _ = try ServerHello.parse(testServerHello(&buf, [_]u8{1} ** 32, versions ++ share));
    try std.testing.expectError(error.DecodeError, ServerHello.parse(testServerHello(&buf, [_]u8{1} ** 32, versions_long ++ share)));
    // A HelloRetryRequest cookie with a trailing byte.
    const hrr_share = "\x00\x33\x00\x02\x00\x1d";
    _ = try ServerHello.parse(testServerHello(&buf, tls.hello_retry_request_sequence, versions ++ "\x00\x2c\x00\x04\x00\x02\xaa\xbb" ++ hrr_share));
    try std.testing.expectError(error.DecodeError, ServerHello.parse(testServerHello(&buf, tls.hello_retry_request_sequence, versions ++ "\x00\x2c\x00\x05\x00\x02\xaa\xbb\x00" ++ hrr_share)));

    // EncryptedExtensions: an ALPN body with a trailing byte, and a second server_name.
    var ee_alpn = [_]u8{ 0, 10, 0, 16, 0, 6, 0, 3, 2, 'h', '2', 0 };
    try std.testing.expectError(error.DecodeError, EncryptedExtensions.parse(&ee_alpn));
    var ee_names = [_]u8{ 0, 8, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.IllegalParameter, EncryptedExtensions.parse(&ee_names));

    // CertificateRequest: signature_algorithms with a trailing byte, and a duplicate unknown
    // extension.
    var cr_ok = [_]u8{ 0, 0, 8, 0, 13, 0, 4, 0, 2, 0x04, 0x03 };
    const parsed = try CertificateRequest.parse(&cr_ok);
    try std.testing.expect(parsed.offersScheme(0x0403));
    var cr_trailing = [_]u8{ 0, 0, 9, 0, 13, 0, 5, 0, 2, 0x04, 0x03, 0 };
    try std.testing.expectError(error.DecodeError, CertificateRequest.parse(&cr_trailing));
    var cr_dup = [_]u8{ 0, 0, 16, 0x7a, 0x7a, 0, 0, 0, 13, 0, 4, 0, 2, 0x04, 0x03, 0x7a, 0x7a, 0, 0 };
    try std.testing.expectError(error.IllegalParameter, CertificateRequest.parse(&cr_dup));
}

test "the certificate_authorities extension of a certificate request" {
    const name = "\x30\x1a\x31\x18\x30\x16\x06\x03\x55\x04\x03\x0c\x0fzig-sdk test CA";
    var good = [_]u8{ 0, 0, 44, 0, 13, 0, 4, 0, 2, 0x04, 0x03, 0, 47, 0, 32, 0, 30, 0, 28 } ++ name.*;
    const req = try CertificateRequest.parse(&good);
    try std.testing.expect(ca_names.contains(req.authorities.?, name));
    // A wrong name length, and an extension without names.
    var bad = good;
    bad[18] = 27;
    try std.testing.expectError(error.DecodeError, CertificateRequest.parse(&bad));
    var empty = [_]u8{ 0, 0, 14, 0, 13, 0, 4, 0, 2, 0x04, 0x03, 0, 47, 0, 2, 0, 0 };
    try std.testing.expectError(error.DecodeError, CertificateRequest.parse(&empty));
}

test "server name eligibility" {
    try std.testing.expect(isServerName("localhost"));
    try std.testing.expect(isServerName("mcp.example.com"));
    try std.testing.expect(!isServerName("127.0.0.1"));
    try std.testing.expect(!isServerName("::1"));
    try std.testing.expect(!isServerName(""));
    try std.testing.expect(!isServerName("bad host"));
}
