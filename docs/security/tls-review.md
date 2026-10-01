# Security review of the TLS code

This document records the internal security review of the TLS 1.3 code of the SDK, from September 2026. It also is the package for an external reviewer. No independent third party reviewed the code yet. The project cannot do that review itself.

## Scope

| Area | Files |
| --- | --- |
| Record layer | `src/tls/Connection.zig`, `src/tls/suites.zig` |
| Handshake | `src/tls/handshake/server.zig`, `client.zig`, `codec.zig`, `common.zig`, `key_share.zig`, `ca_names.zig` |
| Certificates and keys | `src/tls/verify.zig`, `x509.zig`, `der.zig`, `pem.zig`, `CaSet.zig`, `CertChain.zig`, `PrivateKey.zig`, `rsa.zig`, `pss.zig` |
| Revocation and name constraints | `src/tls/revocation.zig`, `Crl.zig`, `ocsp.zig`, `name_constraints.zig` |
| Users of TLS | `src/mcp/transport/http.zig`, `http1.zig`, `websocket.zig`, `src/mcp/auth/common.zig`, `src/grpc/transport/` |

The review does not include the cryptographic primitives of `std.crypto`. It includes the use of these primitives.

## Method

1. Read each file in the order of its exposure to data from the peer.
2. Compare each check with RFC 8446, RFC 5280, RFC 9525 and the specifications of the extensions.
3. Find each size from the peer that reaches an assertion, a slice or an integer operation.
4. Write a regression test for each finding before the fix.
5. Run the fuzz targets of the parsers and of the record layer.

## Findings

The severity tells the effect when a peer sends bad data. All findings have a fix and a regression test.

| ID | Severity | Area | Finding | Fix | Regression test |
| --- | --- | --- | --- | --- | --- |
| T1 | Critical | Record layer | The record layer decrypted a record into the free space of the plaintext buffer after the unread data. It only asserted that the record fits. A peer could stop the process in Debug and ReleaseSafe, and write out of the bounds of the buffer in ReleaseFast and ReleaseSmall. | Pull request 12: the record layer decrypts in place and keeps the rest of a record that does not fit. | `a record that does not fit after unread data arrives in order` |
| T2 | High | Chain validation | The SDK did not check the extended key usage. A client certificate could authenticate a server, and a server certificate could authenticate a client. | Pull request 13 | `the extended key usage of the leaf and the intermediates must permit the purpose` |
| T3 | High | Chain validation | The SDK accepted an intermediate without basic constraints when it had no key usage. | Pull request 13 | `an intermediate needs basic constraints with cA, an anchor can lack them` |
| T4 | Medium | Chain validation | The client compared the host with the common name of a certificate without a subject alternative name. This comparison does not obey the name constraints of a CA. | Pull request 13 | `the host name check ignores the common name` |
| T5 | Medium | ClientHello parser | The parser found duplicate extensions only among the first 32 types, and duplicate key shares only among the first 16 groups. | Pull request 13 | `a duplicate extension after many other extensions is refused` |
| T6 | Medium | Users of TLS | The HTTP/1.1 client, the WebSocket client and the authorization fetcher wrote the parts of a request head without a check. An access token or a URL with CR or LF could add headers. | Pull request 17 | `a request head with CR or LF in a part is refused`, `a token response with an access token that is not a token68 value is a failure` |
| T7 | Low | Extension parsers | The parsers accepted bytes after the structure of a known extension. | Pull request 13 | `trailing bytes in a known client hello extension are a decode error` |
| T8 | Low | Chain validation | A CA set tried only the first anchor with the name of the issuer. A root with a new key did not work. | Pull request 13 | `every anchor with the issuer name gets a try` |
| T9 | Low | Client handshake | The client refused a HelloRetryRequest with a cookie and without a key share. RFC 8446 permits it. | Pull request 17 | `a HelloRetryRequest with a cookie, with and without a key share` |
| T10 | Low | Client handshake | The client sent `illegal_parameter` for an extension that it did not request. RFC 8446 section 4.2 requires `unsupported_extension`. | Pull request 17 | `trailing bytes and duplicates in server extensions are refused` |
| T11 | Low | Client options | The client did not check the size of the ALPN names and of its lists against its fixed ClientHello buffer. A large option from the application stopped the process. | Pull request 17 | `options outside the limits of the client hello buffer give TlsInvalidOptions` |
| T12 | Information | Record layer | No fuzz target covered the record layer. | Pull request 17 | `fuzz: TLS record layer with padding, partial input and one changed byte` |

Earlier fuzz runs found two defects in TLS parsers and one in the HPACK decoder. Pull request 7 has the fixes.

## Checks without a finding

- The key schedule, the nonce of each record, the key update and the limit of the sequence number.
- The key shares: the point checks of the curves and the refusal of low-order X25519 points. Also the check of the ML-KEM encapsulation key and the order of the hybrid share.
- RSA: the constant-time arithmetic of `std.crypto.ff`, the check of each signature before it goes out, and the deterministic salt of RSA-PSS.
- CertificateVerify: the refusal of PKCS#1 v1.5 schemes, the match of the scheme and the key, and the match of the ECDSA curve.
- Finished: the constant-time comparison, and no handshake data after a key change.
- DER: a bounded reader, and the precheck of each certificate before the parser of the standard library.
- HelloRetryRequest: the echo of the legacy ID, the group checks, the cookie limit of 8 KiB, one HelloRetryRequest at most, and the same cipher suite.
- The server message buffer holds a CertificateRequest with the largest list of CA names.

## Accepted behavior

- The server does not accept early data and does not skip it (RFC 8446 section 4.2.10). A client that sends early data gets the alert `bad_record_mac`. The server issues no tickets, so a client has no pre-shared key of this server for early data.

## Package for an external reviewer

A reviewer can do these steps:

1. Read the scope above and the wiki pages `TLS-and-Certificates` and `Threat-Model`.
2. Build and run the tests: `zig build test`. The interoperability tests run when `openssl` 3.0 or later is installed. The tests of the hybrid group need OpenSSL 3.5.
3. Run the fuzz targets on Linux: `zig build test -Dfuzz --fuzz`.
4. Read the fixtures and the script that makes them in `test/fixtures/tls/`.
5. Report a vulnerability with the private form that `SECURITY.md` names.
