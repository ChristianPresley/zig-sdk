# TLS test fixtures

The TLS tests read the files in this directory. The project made all keys, certificates, CRLs and OCSP responses for the tests. Do not use them for other purposes.

| Path | Contents |
| --- | --- |
| `pem/` | Certificates, keys and CRLs in PEM. |
| `der/` | OCSP responses and one CRL in DER. |
| `generate.sh` | The script that makes the newer fixtures. |

## How to make the fixtures again

`generate.sh` makes the newer fixtures that the tables below list. It needs Bash and OpenSSL 3.4 or later.

1. Open a shell in the root of the repository.
2. Run `bash test/fixtures/tls/generate.sh`.
3. Run `zig build test`.

The script does not change the older fixtures: `ca.*`, `chain*`, `bad-chain-leaf.*` and the self-signed pairs, such as `p256.*`. It uses `ca.key` to sign some newer certificates. It makes new keys for each run. It keeps only the keys that the handshake tests load.

## Time

The tests verify the fixtures at a fixed time: 2027-01-15, 1800000000 seconds after the epoch. Thus the tests do not fail when the fixtures get old. Each newer certificate is valid from 2026-01-01 to 2036-01-01. Each CRL has a fixed `thisUpdate` and `nextUpdate`.

OpenSSL writes the time of the run into `thisUpdate` of an OCSP response, and it has no option to change it. `rev-leaf-stale.ocsp` gets a `nextUpdate` 30 days later. If you make the responses after 2026-12-01, move the fixed time of the tests.

## Host names and key usage

The older test CA (`ca.crt`) signs these certificates.

| File | What it has |
| --- | --- |
| `cn-only.crt` | The common name `localhost` and no subject alternative name. |
| `client-leaf.crt`, `client-leaf.key` | The extended key usage `clientAuth` only, and the names `localhost` and `127.0.0.1`. |
| `any-eku-leaf.crt` | The extended key usage `anyExtendedKeyUsage` only. |
| `eku-ca.crt` | An intermediate CA with the extended key usage `clientAuth` only. |
| `eku-leaf.crt` | A leaf of `eku-ca.crt` with `serverAuth` and `clientAuth`. |
| `no-bc-ca.crt` | An intermediate CA without basic constraints and without key usage. |
| `no-bc-leaf.crt` | A leaf of `no-bc-ca.crt`. |
| `ca-rekeyed.crt` | A root with the name of the older test CA and a different key. |

## Name constraints

`nc-root.crt` is the root. `nc-ca.crt` is an intermediate CA with critical name constraints. It permits these names:

- The DNS names `example.com` and its subdomains, and the subdomains of `example.org` (the constraint `.example.org`).
- The IP addresses in `10.0.0.0/8`, the address `127.0.0.1` and the addresses in `fd00::/8`.
- The directory names that start with `O=zig-sdk test`.
- The mailboxes at `example.com` and the URIs with a host below `example.com`.

It excludes the DNS name `bad.example.com` and the IP addresses in `10.1.0.0/16`. All leaves share the key `nc-leaf.key`.

| File | What it has |
| --- | --- |
| `nc-ok.crt` | Names of each form, all in the permitted subtrees. |
| `nc-excluded.crt` | The DNS name `bad.example.com`. |
| `nc-outside.crt` | The DNS name `www.example.net`. |
| `nc-apex.crt` | The DNS name `example.org`, which `.example.org` does not permit. |
| `nc-ip-excluded.crt` | The IP address `10.1.2.3`. |
| `nc-ip-outside.crt` | The IP address `192.168.1.1`. |
| `nc-dn-outside.crt` | The subject `O=other org`. |
| `nc-email-outside.crt` | The mailbox `dev@example.net`. |
| `nc-uri-outside.crt` | The URI `https://example.net/`. |
| `nc-sub-ca.crt` | A CA below `nc-ca.crt` that permits only `www.example.com`. |
| `nc-sub-ok.crt`, `nc-sub-outside.crt` | Leaves of `nc-sub-ca.crt` with `www.example.com` and `api.example.com`. |
| `nc-self-ca.crt` | A self-issued CA below `nc-ca.crt`. Its subject is the name of `nc-ca.crt`. |
| `nc-self-leaf.crt` | A leaf of `nc-self-ca.crt`. |
| `nc-rid-ca.crt` | A CA with a critical constraint on registered IDs. |
| `nc-rid-leaf.crt` | A leaf of `nc-rid-ca.crt` with a registered ID. |
| `nc-ok-chain.crt`, `nc-excluded-chain.crt` | A leaf and `nc-ca.crt`, for the handshake tests. |

## Revocation

`rev-root.crt` is the root. `rev-ca.crt` is an intermediate CA with an RSA key. It signs two leaves with the shared key `rev-leaf.key`. `rev-leaf.crt` has the serial number 0x3101 and is valid. The CA revokes `rev-revoked.crt` with the serial number 0x3102.

| File | What it has |
| --- | --- |
| `rev-chain.crt`, `rev-revoked-chain.crt` | A leaf and `rev-ca.crt`, for the handshake tests. |
| `rev-ca.crl`, `der/rev-ca.crl` | The CRL of `rev-ca.crt` in PEM and in DER. It lists 0x3102 with the reason code `keyCompromise`. |
| `rev-ca-stale.crl` | The same list with a `nextUpdate` of 2026-12-01. |
| `rev-ca-delta.crl` | The same list with a critical delta CRL indicator. |
| `rev-ca-critical.crl` | The same list with a critical extension that the SDK does not know. |
| `rev-root.crl` | The CRL of `rev-root.crt`. It is empty. |
| `der/rev-leaf-good.ocsp` | The status `good` for `rev-leaf.crt`. `rev-ca.crt` signs it, and the certificate ID has SHA-1 hashes. |
| `der/rev-leaf-good-delegated.ocsp` | The status `good`. A delegated responder signs it, and the certificate ID has SHA-256 hashes. |
| `der/rev-leaf-noeku.ocsp` | The status `good`. A delegated responder without the extended key usage `OCSPSigning` signs it. |
| `der/rev-leaf-stale.ocsp` | The status `good` with a `nextUpdate` 30 days after the run. |
| `der/rev-leaf-unknown.ocsp` | The status `unknown` for `rev-leaf.crt`. |
| `der/rev-revoked.ocsp` | The status `revoked` for `rev-revoked.crt`. |
