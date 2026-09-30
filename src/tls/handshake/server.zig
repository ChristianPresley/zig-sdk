//! The TLS 1.3 server handshake (RFC 8446 section 4): ClientHello validation, cipher suite,
//! group and ALPN selection, HelloRetryRequest, key exchange, certificate presentation and
//! the Finished exchange.
const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const suites = @import("../suites.zig");
const Suite = suites.Suite;
const codec = @import("codec.zig");
const PrivateKey = @import("../PrivateKey.zig");
const key_share = @import("key_share.zig");
const Connection = @import("../Connection.zig");
const CertChain = @import("../CertChain.zig");

pub const Config = struct {
    /// Certificate chains, at least one. The first one is the default.
    chains: []const *const CertChain,
    /// Choose a chain for a server name. The default picks the first chain whose leaf
    /// names the host, else the first chain.
    select_chain: ?*const fn (server_name: ?[]const u8, chains: []const *const CertChain) ?*const CertChain = null,
    /// Application protocols in preference order. Empty disables ALPN.
    alpn: []const []const u8 = &.{},
    /// Reject clients that do not negotiate an application protocol.
    require_alpn: bool = false,
    cipher_suites: []const Suite = suites.default_suites,
    groups: []const key_share.Group = key_share.default_groups,
    /// What to do when the client asks for a server name no chain covers.
    server_name_mismatch: enum { ignore, alert } = .ignore,
};

pub const AcceptOptions = struct {
    io: std.Io,
    /// Plaintext buffer for the application. At least `Connection.min_read_buffer_len`.
    read_buffer: []u8,
    /// Plaintext buffer for the application.
    write_buffer: []u8,
    allow_truncation_attacks: bool = false,
    /// Receives the alert that ended a failed handshake, sent or received.
    alert: ?*tls.Alert = null,
};

pub const AcceptError = error{
    ReadFailed,
    WriteFailed,
    EntropyUnavailable,
    /// The client sent an alert.
    TlsAlert,
    TlsConnectionTruncated,
    TlsRecordOverflow,
    TlsDecodeError,
    TlsIllegalParameter,
    TlsUnexpectedMessage,
    TlsProtocolVersion,
    TlsMissingExtension,
    TlsHandshakeFailure,
    TlsNoApplicationProtocol,
    TlsUnrecognizedName,
    TlsDecryptError,
    TlsBadRecordMac,
    TlsSequenceOverflow,
    TlsInternalError,
};

pub const Server = struct {
    config: Config,

    pub fn init(config: Config) error{NoCertificateChain}!Server {
        if (config.chains.len == 0) return error.NoCertificateChain;
        return .{ .config = config };
    }

    /// Run the server side of a handshake on an accepted stream.
    pub fn accept(self: *const Server, input: *Reader, output: *Writer, options: AcceptOptions) AcceptError!Connection {
        var c: Connection = .init(input, output, .server, options.read_buffer, options.write_buffer, options.allow_truncation_attacks);
        errdefer c.deinit();
        var reader: MessageReader = .{};
        const first = try reader.next(&c, options);
        if (first.kind != .client_hello) return abort(&c, options, .unexpected_message, error.TlsUnexpectedMessage);
        const hello = codec.ClientHello.parse(first.body) catch |e| return abortParse(&c, options, e);
        const suite = selectSuite(self.config, &hello) orelse return abort(&c, options, .handshake_failure, error.TlsHandshakeFailure);
        switch (suite) {
            inline else => |s| return run(Suite.Type(s), s, self, &c, &reader, &hello, first.raw, options),
        }
    }
};

fn selectSuite(config: Config, hello: *const codec.ClientHello) ?Suite {
    for (config.cipher_suites) |s| if (hello.offersSuite(s.wire())) return s;
    return null;
}

const GroupChoice = struct {
    group: key_share.Group,
    /// The client's key share, or null when a HelloRetryRequest is needed.
    share: ?[]const u8,
};

fn selectGroup(config: Config, hello: *const codec.ClientHello) ?GroupChoice {
    for (config.groups) |g| {
        if (hello.keyShare(g.wire())) |share| return .{ .group = g, .share = share };
    }
    for (config.groups) |g| {
        if (hello.offersGroup(g.wire())) return .{ .group = g, .share = null };
    }
    return null;
}

fn selectChain(config: Config, server_name: ?[]const u8) ?*const CertChain {
    if (config.select_chain) |f| return f(server_name, config.chains);
    if (server_name) |name| {
        for (config.chains) |chain| if (chain.matchesHost(name)) return chain;
        if (config.server_name_mismatch == .alert) return null;
    }
    return config.chains[0];
}

fn selectAlpn(config: Config, hello: *const codec.ClientHello) error{NoApplicationProtocol}!?[]const u8 {
    if (config.alpn.len == 0) return null;
    if (hello.alpn.len == 0) {
        if (config.require_alpn) return error.NoApplicationProtocol;
        return null;
    }
    for (config.alpn) |name| if (hello.offersAlpn(name)) return name;
    return error.NoApplicationProtocol;
}

fn run(
    comptime S: type,
    comptime suite: Suite,
    self: *const Server,
    c: *Connection,
    reader: *MessageReader,
    hello1: *const codec.ClientHello,
    hello1_raw: []const u8,
    options: AcceptOptions,
) AcceptError!Connection {
    const K = suites.Schedule(S);
    const config = self.config;
    var transcript: suites.Transcript = .init(S);
    var session_id_buf: [32]u8 = undefined;
    @memcpy(session_id_buf[0..hello1.session_id.len], hello1.session_id);
    const session_id = session_id_buf[0..hello1.session_id.len];
    const compat_mode = session_id.len > 0;

    var hello = hello1.*;
    var choice = selectGroup(config, &hello) orelse return abort(c, options, .handshake_failure, error.TlsHandshakeFailure);
    var msg_buf: [1024]u8 = undefined;

    if (choice.share == null) {
        // HelloRetryRequest: replace ClientHello1 in the transcript with its hash.
        transcript.update(hello1_raw);
        const ch1_hash = transcript.peek(S);
        transcript = .init(S);
        transcript.update(codec.messageHash(&msg_buf, &ch1_hash));
        const hrr = codec.serverHello(&msg_buf, tls.hello_retry_request_sequence, session_id, suite.wire(), choice.group.wire(), &.{}, true);
        c.writeRecord(.handshake, hrr) catch return error.WriteFailed;
        transcript.update(hrr);
        if (compat_mode) c.writeChangeCipherSpec() catch return error.WriteFailed;
        c.output.flush() catch return error.WriteFailed;

        const second = try reader.next(c, options);
        if (second.kind != .client_hello) return abort(c, options, .unexpected_message, error.TlsUnexpectedMessage);
        hello = codec.ClientHello.parse(second.body) catch |e| return abortParse(c, options, e);
        if (selectSuite(config, &hello) != suite) return abort(c, options, .illegal_parameter, error.TlsIllegalParameter);
        if (!std.mem.eql(u8, hello.session_id, session_id)) return abort(c, options, .illegal_parameter, error.TlsIllegalParameter);
        const share = hello.keyShare(choice.group.wire()) orelse return abort(c, options, .illegal_parameter, error.TlsIllegalParameter);
        choice = .{ .group = choice.group, .share = share };
        transcript.update(second.raw);
    } else {
        transcript.update(hello1_raw);
    }

    // Decisions that depend on the final ClientHello.
    if (hello.server_name) |name| c.setServerName(name);
    const chain = selectChain(config, c.serverName()) orelse return abort(c, options, .unrecognized_name, error.TlsUnrecognizedName);
    const scheme = chain.key.scheme();
    if (!hello.offersScheme(@intFromEnum(scheme))) return abort(c, options, .handshake_failure, error.TlsHandshakeFailure);
    const alpn = selectAlpn(config, &hello) catch return abort(c, options, .no_application_protocol, error.TlsNoApplicationProtocol);
    if (alpn) |name| c.setAlpn(name);

    // Key exchange.
    var share = key_share.KeyShare.generate(options.io, choice.group) catch return abort(c, options, .internal_error, error.EntropyUnavailable);
    defer share.wipe();
    var shared_buf: [key_share.max_shared_len]u8 = undefined;
    defer crypto.secureZero(u8, &shared_buf);
    const shared = share.sharedSecret(choice.share.?, &shared_buf) catch |e| switch (e) {
        error.IllegalParameter => return abort(c, options, .illegal_parameter, error.TlsIllegalParameter),
        error.DecryptError => return abort(c, options, .decrypt_error, error.TlsDecryptError),
    };
    var public_buf: [key_share.max_public_len]u8 = undefined;
    const public = share.publicBytes(&public_buf);

    // ServerHello.
    var random: [32]u8 = undefined;
    options.io.randomSecure(&random) catch return abort(c, options, .internal_error, error.EntropyUnavailable);
    const server_hello = codec.serverHello(&msg_buf, random, session_id, suite.wire(), choice.group.wire(), public, false);
    c.writeRecord(.handshake, server_hello) catch return error.WriteFailed;
    transcript.update(server_hello);
    if (compat_mode and choice.share != null and !hrrSent(reader)) c.writeChangeCipherSpec() catch return error.WriteFailed;

    // Handshake keys.
    var handshake_secret = K.handshakeSecret(shared);
    defer crypto.secureZero(u8, &handshake_secret);
    const hello_hash = transcript.peek(S);
    var client_hs = K.trafficSecret(handshake_secret, "c hs traffic", hello_hash);
    defer crypto.secureZero(u8, &client_hs);
    const server_hs = K.trafficSecret(handshake_secret, "s hs traffic", hello_hash);
    c.write_keys = suites.DirectionKeys.init(suite, server_hs);

    // EncryptedExtensions, Certificate, CertificateVerify, Finished.
    const ee = codec.encryptedExtensions(&msg_buf, alpn, c.serverName() != null);
    c.writeRecord(.handshake, ee) catch return error.WriteFailed;
    transcript.update(ee);
    c.writeRecord(.handshake, chain.handshake_message) catch return error.WriteFailed;
    transcript.update(chain.handshake_message);

    var to_sign: [codec.certificate_verify_context.len + S.digest_length]u8 = undefined;
    @memcpy(to_sign[0..codec.certificate_verify_context.len], codec.certificate_verify_context);
    to_sign[codec.certificate_verify_context.len..].* = transcript.peek(S);
    var noise: [48]u8 = undefined;
    options.io.randomSecure(&noise) catch return abort(c, options, .internal_error, error.EntropyUnavailable);
    var sig_buf: [PrivateKey.max_signature_len]u8 = undefined;
    const signature = chain.key.sign(&to_sign, noise, &sig_buf) catch return abort(c, options, .internal_error, error.TlsInternalError);
    const cv = codec.certificateVerify(&msg_buf, @intFromEnum(scheme), signature);
    c.writeRecord(.handshake, cv) catch return error.WriteFailed;
    transcript.update(cv);

    const server_verify = K.verifyData(K.finishedKey(server_hs), transcript.peek(S));
    const fin = codec.finished(&msg_buf, &server_verify);
    c.writeRecord(.handshake, fin) catch return error.WriteFailed;
    transcript.update(fin);
    c.output.flush() catch return error.WriteFailed;

    // Application secrets are derived from the transcript through the server Finished.
    var master = K.masterSecret(handshake_secret);
    defer crypto.secureZero(u8, &master);
    const finished_hash = transcript.peek(S);
    const client_ap = K.trafficSecret(master, "c ap traffic", finished_hash);
    const server_ap = K.trafficSecret(master, "s ap traffic", finished_hash);

    // Client Finished under the client handshake keys.
    if (reader.pendingBytes() != 0) return abort(c, options, .unexpected_message, error.TlsUnexpectedMessage);
    c.read_keys = suites.DirectionKeys.init(suite, client_hs);
    const client_fin = try reader.next(c, options);
    if (client_fin.kind != .finished) return abort(c, options, .unexpected_message, error.TlsUnexpectedMessage);
    const expected = K.verifyData(K.finishedKey(client_hs), finished_hash);
    if (client_fin.body.len != expected.len or !crypto.timing_safe.eql([expected.len]u8, expected, client_fin.body[0..expected.len].*)) {
        return abort(c, options, .decrypt_error, error.TlsDecryptError);
    }
    if (reader.pendingBytes() != 0) return abort(c, options, .unexpected_message, error.TlsUnexpectedMessage);

    c.read_keys.wipe();
    c.write_keys.wipe();
    c.read_keys = suites.DirectionKeys.init(suite, client_ap);
    c.write_keys = suites.DirectionKeys.init(suite, server_ap);
    c.handshake_complete = true;
    c.suite = suite;
    c.group = choice.group.wire();
    return c.*;
}

fn hrrSent(reader: *const MessageReader) bool {
    return reader.messages_read > 1;
}

fn abort(c: *Connection, options: AcceptOptions, description: tls.Alert.Description, err: AcceptError) AcceptError {
    c.sendAlert(.fatal, description) catch {};
    if (options.alert) |a| a.* = .{ .level = .fatal, .description = description };
    return err;
}

fn abortParse(c: *Connection, options: AcceptOptions, err: codec.ParseError) AcceptError {
    return switch (err) {
        error.DecodeError => abort(c, options, .decode_error, error.TlsDecodeError),
        error.IllegalParameter => abort(c, options, .illegal_parameter, error.TlsIllegalParameter),
        error.ProtocolVersion => abort(c, options, .protocol_version, error.TlsProtocolVersion),
        error.MissingExtension => abort(c, options, .missing_extension, error.TlsMissingExtension),
    };
}

pub const Message = struct {
    kind: tls.HandshakeType,
    body: []u8,
    /// The message with its four-byte header, for the transcript.
    raw: []const u8,
};

/// Reassembles handshake messages from records, skipping compatibility change_cipher_spec
/// records and surfacing alerts.
const MessageReader = struct {
    buf: [codec.max_message_len + 4]u8 = undefined,
    len: usize = 0,
    /// Start of the message returned last, so its bytes stay valid until the next call.
    pending_consumed: usize = 0,
    messages_read: u32 = 0,

    /// Bytes of the next message that are already buffered. Must be zero when keys change.
    fn pendingBytes(self: *const MessageReader) usize {
        return self.len - self.pending_consumed;
    }

    fn next(self: *MessageReader, c: *Connection, options: AcceptOptions) AcceptError!Message {
        // Drop the message returned by the previous call.
        if (self.pending_consumed > 0) {
            const rest = self.buf[self.pending_consumed..self.len];
            @memmove(self.buf[0..rest.len], rest);
            self.len = rest.len;
            self.pending_consumed = 0;
        }
        while (true) {
            if (self.len >= 4) {
                const body_len = std.mem.readInt(u24, self.buf[1..4], .big);
                if (body_len > codec.max_message_len) return abort(c, options, .decode_error, error.TlsDecodeError);
                if (self.len >= 4 + body_len) {
                    self.pending_consumed = 4 + body_len;
                    self.messages_read += 1;
                    return .{
                        .kind = @enumFromInt(self.buf[0]),
                        .body = self.buf[4 .. 4 + body_len],
                        .raw = self.buf[0 .. 4 + body_len],
                    };
                }
            }
            const rec = c.readRecord() catch |e| switch (e) {
                error.ReadFailed => return error.ReadFailed,
                error.TlsConnectionTruncated => return error.TlsConnectionTruncated,
                error.TlsBadRecordMac => return abort(c, options, .bad_record_mac, error.TlsBadRecordMac),
                error.TlsRecordOverflow => return abort(c, options, .record_overflow, error.TlsRecordOverflow),
                error.TlsUnexpectedMessage => return abort(c, options, .unexpected_message, error.TlsUnexpectedMessage),
                error.TlsDecodeError => return abort(c, options, .decode_error, error.TlsDecodeError),
                error.TlsIllegalParameter => return abort(c, options, .illegal_parameter, error.TlsIllegalParameter),
                error.TlsSequenceOverflow => return abort(c, options, .internal_error, error.TlsSequenceOverflow),
                error.TlsAlert => unreachable,
            };
            switch (rec.content_type) {
                .handshake => {
                    if (rec.data.len == 0) return abort(c, options, .decode_error, error.TlsDecodeError);
                    if (self.len + rec.data.len > self.buf.len) return abort(c, options, .decode_error, error.TlsDecodeError);
                    @memcpy(self.buf[self.len..][0..rec.data.len], rec.data);
                    self.len += rec.data.len;
                },
                .change_cipher_spec => {
                    if (rec.data.len != 1 or rec.data[0] != 1) return abort(c, options, .unexpected_message, error.TlsUnexpectedMessage);
                },
                .alert => {
                    if (rec.data.len != 2) return abort(c, options, .decode_error, error.TlsDecodeError);
                    const alert: tls.Alert = .{ .level = @enumFromInt(rec.data[0]), .description = @enumFromInt(rec.data[1]) };
                    c.alert = alert;
                    if (options.alert) |a| a.* = alert;
                    return error.TlsAlert;
                },
                else => return abort(c, options, .unexpected_message, error.TlsUnexpectedMessage),
            }
        }
    }
};
