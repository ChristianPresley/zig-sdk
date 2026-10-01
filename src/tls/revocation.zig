//! Offline revocation checks of a verified certificate path. The SDK does not fetch
//! revocation data from the network. The application supplies CRLs (RFC 5280 section 5),
//! and a TLS server can staple OCSP responses (RFC 6960) to its certificates.
const std = @import("std");
const Certificate = std.crypto.Certificate;
const Crl = @import("Crl.zig");
const ocsp = @import("ocsp.zig");
const x509 = @import("x509.zig");

/// The tolerance for the clocks of the CA and of this host, in seconds: five minutes.
pub const clock_skew_sec: i64 = 300;

/// The revocation policy of a TLS client, or of a TLS server for client certificates.
/// The default makes no check. The checks apply to the `ca_set` and `bundle` trust
/// policies, and not to the trust anchor.
///
/// For each certificate of the path, the SDK finds a status:
///
/// - "revoked": a current CRL of the issuer lists the serial number of the certificate,
///   or a stapled OCSP response gives "revoked".
/// - "good": a current CRL of the issuer does not list the serial number, or a stapled
///   OCSP response gives "good".
/// - "unknown": else. A missing CRL, a stale CRL, a CRL with a bad signature and a CRL
///   of another issuer give this status. A missing staple and the OCSP status "unknown"
///   give it too.
///
/// The status "revoked" always ends the handshake. The status "unknown" ends the handshake
/// only with `hard_fail`, and only for a certificate in `scope`. With `hard_fail` and no
/// source of status, each certificate in `scope` has the status "unknown".
///
/// A stapled OCSP response that the client cannot accept always ends the handshake (RFC
/// 6066 section 8). Thus a stale staple, a staple for another certificate and a staple
/// without a valid signature end it, also with `soft_fail`.
pub const Policy = struct {
    /// The CRLs from the application. A CRL applies to a certificate when the CRL issuer
    /// has the name of the certificate issuer. The issuer in the path must sign the CRL.
    /// A current CRL has a `thisUpdate` and a `nextUpdate` around the verification time,
    /// with the tolerance `clock_skew_sec`.
    crls: []const *const Crl = &.{},
    /// OCSP stapling of the server certificates. Only the TLS client uses it. The server
    /// refuses a policy for client certificates with a value other than `off`.
    ocsp_stapling: OcspStapling = .off,
    /// The certificates that need a known status for `hard_fail`.
    scope: Scope = .leaf,
    /// What to do with a certificate in `scope` that has the status "unknown".
    unknown: Unknown = .soft_fail,

    pub const OcspStapling = enum {
        /// Do not ask for a staple. The client does not read a staple.
        off,
        /// Send `status_request` and check each staple that the server sends.
        request,
        /// As `request`, and refuse a leaf without a staple.
        require,
    };

    pub const Scope = enum {
        /// Only the leaf needs a known status.
        leaf,
        /// The leaf and each intermediate need a known status.
        chain,
    };

    pub const Unknown = enum {
        /// Accept the certificate.
        soft_fail,
        /// Refuse the certificate.
        hard_fail,
    };

    /// True when the policy makes a check.
    pub fn active(self: Policy) bool {
        return self.crls.len > 0 or self.ocsp_stapling != .off or self.unknown == .hard_fail;
    }
};

pub const Status = enum { good, revoked, unknown };

pub const Error = error{
    /// The issuer of a certificate in the path revoked it.
    Revoked,
    /// A certificate in scope has no known status, and the policy is `hard_fail`.
    StatusUnknown,
    /// The server stapled an OCSP response that the client does not accept.
    BadStaple,
    /// The policy is `require` and the server stapled no OCSP response to the leaf.
    StapleMissing,
    /// A certificate of the path does not parse.
    Malformed,
};

/// Check the status of each certificate of a verified path. `path` holds the leaf first
/// and then the intermediates. `anchor` is the trust anchor that signs the last one.
/// `staples` holds the stapled OCSP response of each certificate of `path`, by index.
pub fn checkPath(path: []const []const u8, anchor: []const u8, staples: []const ?[]const u8, policy: Policy, now_sec: i64) Error!void {
    if (!policy.active()) return;
    for (path, 0..) |cert, i| {
        const issuer = if (i + 1 < path.len) path[i + 1] else anchor;
        var status: Status = .unknown;
        if (policy.ocsp_stapling != .off) {
            const staple: ?[]const u8 = if (i < staples.len) staples[i] else null;
            if (staple) |response| {
                status = switch (ocsp.check(response, cert, issuer, now_sec, clock_skew_sec) catch return error.BadStaple) {
                    .good => .good,
                    .revoked => .revoked,
                    .unknown => .unknown,
                };
            } else if (i == 0 and policy.ocsp_stapling == .require) return error.StapleMissing;
        }
        if (status != .revoked) {
            switch (try crlStatus(cert, issuer, policy.crls, now_sec)) {
                .revoked => status = .revoked,
                .good => if (status == .unknown) {
                    status = .good;
                },
                .unknown => {},
            }
        }
        switch (status) {
            .good => {},
            .revoked => return error.Revoked,
            .unknown => {
                const in_scope = i == 0 or policy.scope == .chain;
                if (in_scope and policy.unknown == .hard_fail) return error.StatusUnknown;
            },
        }
    }
}

/// The status of `cert` from the CRLs that its issuer signs. `issuer` is the DER
/// certificate of the issuer.
pub fn crlStatus(cert: []const u8, issuer: []const u8, crls: []const *const Crl, now_sec: i64) Error!Status {
    if (crls.len == 0) return .unknown;
    const fields = x509.tbsFields(cert) catch return error.Malformed;
    const issuer_parsed = parseCertificate(issuer) catch return error.Malformed;
    var status: Status = .unknown;
    for (crls) |crl| {
        if (!std.mem.eql(u8, crl.issuer, fields.issuer.raw)) continue;
        if (!crl.isCurrent(now_sec, clock_skew_sec)) continue;
        if (!crl.signedBy(issuer_parsed, issuer)) continue;
        if (crl.find(fields.serial.content) != null) return .revoked;
        status = .good;
    }
    return status;
}

/// Parse a DER certificate with the std parser after the precheck of `x509`.
pub fn parseCertificate(bytes: []const u8) !Certificate.Parsed {
    // The std parser reads without bounds checks. The precheck refuses what would crash it.
    try x509.precheck(bytes);
    return (Certificate{ .buffer = bytes, .index = 0 }).parse();
}
