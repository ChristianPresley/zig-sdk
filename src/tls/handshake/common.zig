//! Handshake helpers shared by the server and the client: the error set, the message
//! reassembly over records, and the fatal alert helpers.
const std = @import("std");
const tls = std.crypto.tls;
const Decoder = tls.Decoder;
const codec = @import("codec.zig");
const Connection = @import("../Connection.zig");
const verify = @import("../verify.zig");

pub const Error = verify.Error || verify.SignatureError || error{
    ReadFailed,
    WriteFailed,
    EntropyUnavailable,
    /// The peer sent an alert.
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
    /// The server requires a client certificate and the client sent none.
    TlsCertificateRequired,
};

/// The signature schemes both sides accept in a CertificateVerify and, for the certificate
/// signatures, in a chain. The PKCS#1 v1.5 entries are for certificate signatures only.
pub const signature_schemes = [_]tls.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .ed25519,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .rsa_pss_pss_sha256,
    .rsa_pss_pss_sha384,
    .rsa_pss_pss_sha512,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
    .rsa_pkcs1_sha512,
};

pub fn acceptedScheme(wire: u16) ?tls.SignatureScheme {
    for (signature_schemes) |s| if (@intFromEnum(s) == wire) return s;
    return null;
}

/// A parsed Certificate message. Slices point into the message buffer.
pub const CertificateMessage = struct {
    context: []const u8,
    certs: [verify.max_certs][]const u8,
    count: usize,

    pub fn parse(body: []u8) codec.ParseError!CertificateMessage {
        var d: Decoder = .fromTheirSlice(body);
        d.ensure(1) catch return error.DecodeError;
        const ctx_len = d.decode(u8);
        d.ensure(@as(usize, ctx_len) + 3) catch return error.DecodeError;
        var result: CertificateMessage = .{ .context = d.slice(ctx_len), .certs = undefined, .count = 0 };
        const list_len = d.decode(u24);
        var list = d.sub(list_len) catch return error.DecodeError;
        if (!d.eof()) return error.DecodeError;
        while (!list.eof()) {
            list.ensure(3) catch return error.DecodeError;
            const cert_len = list.decode(u24);
            if (cert_len == 0) return error.DecodeError;
            list.ensure(@as(usize, cert_len) + 2) catch return error.DecodeError;
            const cert = list.slice(cert_len);
            const ext_len = list.decode(u16);
            list.ensure(ext_len) catch return error.DecodeError;
            _ = list.slice(ext_len);
            if (result.count == result.certs.len) return error.IllegalParameter;
            result.certs[result.count] = cert;
            result.count += 1;
        }
        return result;
    }
};

/// The scheme and signature of a CertificateVerify message.
pub const CertificateVerifyMessage = struct {
    scheme: tls.SignatureScheme,
    signature: []const u8,

    pub fn parse(body: []u8) codec.ParseError!CertificateVerifyMessage {
        var d: Decoder = .fromTheirSlice(body);
        d.ensure(4) catch return error.DecodeError;
        const scheme_wire = d.decode(u16);
        const sig_len = d.decode(u16);
        d.ensure(sig_len) catch return error.DecodeError;
        const signature = d.slice(sig_len);
        if (!d.eof()) return error.DecodeError;
        const scheme = acceptedScheme(scheme_wire) orelse return error.IllegalParameter;
        return .{ .scheme = scheme, .signature = signature };
    }
};

/// Map a chain validation error to its alert and return it.
pub fn abortVerify(c: *Connection, alert_out: ?*tls.Alert, err: verify.Error) verify.Error {
    return switch (err) {
        error.TlsCertificateInvalid,
        error.TlsCertificateHostMismatch,
        error.TlsCertificateNameNotPermitted,
        error.TlsCertificateUnsupportedConstraint,
        => abort(c, alert_out, .bad_certificate, err),
        error.TlsCertificateNotVerified, error.TlsCertificateIssuerNotFound, error.TlsCertificateNotCa => abort(c, alert_out, .unknown_ca, err),
        error.TlsCertificateExpired, error.TlsCertificateNotYetValid => abort(c, alert_out, .certificate_expired, err),
        error.TlsCertificateWrongPurpose => abort(c, alert_out, .unsupported_certificate, err),
    };
}

/// Map a CertificateVerify problem to its alert and return it.
pub fn abortSignature(c: *Connection, alert_out: ?*tls.Alert, err: verify.SignatureError) verify.SignatureError {
    return switch (err) {
        error.TlsBadSignatureScheme => abort(c, alert_out, .illegal_parameter, err),
        error.TlsDecryptError => abort(c, alert_out, .decrypt_error, err),
    };
}

/// The SHA-256 fingerprint of a DER certificate.
pub fn fingerprint(der: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &out, .{});
    return out;
}

pub const Message = struct {
    kind: tls.HandshakeType,
    body: []u8,
    /// The message with its four-byte header, for the transcript.
    raw: []const u8,
};

/// Reassembles handshake messages from records, skips compatibility change_cipher_spec
/// records and surfaces alerts. `buf` must hold the largest message plus its header.
pub const MessageReader = struct {
    buf: []u8,
    len: usize = 0,
    /// Start of the message returned last, so its bytes stay valid until the next call.
    pending_consumed: usize = 0,
    messages_read: u32 = 0,

    pub fn init(buf: []u8) MessageReader {
        return .{ .buf = buf };
    }

    /// Bytes of the next message that are already in the buffer. Must be zero when keys change.
    pub fn pendingBytes(self: *const MessageReader) usize {
        return self.len - self.pending_consumed;
    }

    pub fn next(self: *MessageReader, c: *Connection, alert_out: ?*tls.Alert) Error!Message {
        // Drop the message returned by the previous call.
        if (self.pending_consumed > 0) {
            const rest = self.buf[self.pending_consumed..self.len];
            @memmove(self.buf[0..rest.len], rest);
            self.len = rest.len;
            self.pending_consumed = 0;
        }
        const max_body = self.buf.len - 4;
        while (true) {
            if (self.len >= 4) {
                const body_len = std.mem.readInt(u24, self.buf[1..4], .big);
                if (body_len > max_body) return abort(c, alert_out, .decode_error, error.TlsDecodeError);
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
                error.TlsBadRecordMac => return abort(c, alert_out, .bad_record_mac, error.TlsBadRecordMac),
                error.TlsRecordOverflow => return abort(c, alert_out, .record_overflow, error.TlsRecordOverflow),
                error.TlsUnexpectedMessage => return abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage),
                error.TlsDecodeError => return abort(c, alert_out, .decode_error, error.TlsDecodeError),
                error.TlsIllegalParameter => return abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter),
                error.TlsSequenceOverflow => return abort(c, alert_out, .internal_error, error.TlsSequenceOverflow),
                error.TlsAlert => unreachable,
            };
            switch (rec.content_type) {
                .handshake => {
                    if (rec.data.len == 0) return abort(c, alert_out, .decode_error, error.TlsDecodeError);
                    if (self.len + rec.data.len > self.buf.len) return abort(c, alert_out, .decode_error, error.TlsDecodeError);
                    @memcpy(self.buf[self.len..][0..rec.data.len], rec.data);
                    self.len += rec.data.len;
                },
                .change_cipher_spec => {
                    if (rec.data.len != 1 or rec.data[0] != 1) return abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage);
                },
                .alert => {
                    if (rec.data.len != 2) return abort(c, alert_out, .decode_error, error.TlsDecodeError);
                    const alert: tls.Alert = .{ .level = @enumFromInt(rec.data[0]), .description = @enumFromInt(rec.data[1]) };
                    c.alert = alert;
                    if (alert_out) |a| a.* = alert;
                    return error.TlsAlert;
                },
                else => return abort(c, alert_out, .unexpected_message, error.TlsUnexpectedMessage),
            }
        }
    }
};

/// Send a fatal alert, record it, and return `err`.
pub fn abort(c: *Connection, alert_out: ?*tls.Alert, description: tls.Alert.Description, err: anytype) @TypeOf(err) {
    c.sendAlert(.fatal, description) catch {};
    if (alert_out) |a| a.* = .{ .level = .fatal, .description = description };
    return err;
}

pub fn abortParse(c: *Connection, alert_out: ?*tls.Alert, err: codec.ParseError) Error {
    return switch (err) {
        error.DecodeError => abort(c, alert_out, .decode_error, error.TlsDecodeError),
        error.IllegalParameter => abort(c, alert_out, .illegal_parameter, error.TlsIllegalParameter),
        error.ProtocolVersion => abort(c, alert_out, .protocol_version, error.TlsProtocolVersion),
        error.MissingExtension => abort(c, alert_out, .missing_extension, error.TlsMissingExtension),
    };
}

test "certificate message lengths near the maximum of their type are decode errors" {
    // The fuzz job found the same integer overflow as in the CertificateRequest.
    var long_context = [_]u8{ 0xfd, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.DecodeError, CertificateMessage.parse(&long_context));
    var long_cert = [_]u8{ 0x00, 0x00, 0x00, 0x05, 0xff, 0xff, 0xff, 0x00, 0x00 };
    try std.testing.expectError(error.DecodeError, CertificateMessage.parse(&long_cert));
}
