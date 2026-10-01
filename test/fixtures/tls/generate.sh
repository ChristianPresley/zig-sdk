#!/usr/bin/env bash
# Regenerate the TLS fixtures that this script names. Needs OpenSSL 3.4 or later.
# Run it from the repository root:
#
#   bash test/fixtures/tls/generate.sh
#
# The script does not touch the older fixtures (ca.*, chain*, bad-chain-leaf.*, the
# self-signed key pairs). It signs some certificates with the older test CA in ca.key.
# The tests verify at the fixed time 2027-01-15 (1800000000). Every certificate is valid
# from 2026-01-01 to 2036-01-01. The OCSP responses get the time of generation as
# thisUpdate, so regenerate them before 2026-12-01 or move the time of the tests.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: keep "/CN=..." as it is

pem=test/fixtures/tls/pem
der=test/fixtures/tls/der
mkdir -p "$pem" "$der"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# A native Windows openssl does not know the paths of Git Bash.
if command -v cygpath >/dev/null; then work=$(cygpath -m "$work"); fi

not_before=20260101000000Z
not_after=20360101000000Z

cat >"$work/ext.cnf" <<'EOF'
[root_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ca_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[leaf_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
authorityKeyIdentifier = keyid:always

[cn_only_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
authorityKeyIdentifier = keyid:always

[client_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
authorityKeyIdentifier = keyid:always

[any_eku_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = anyExtendedKeyUsage
subjectAltName = DNS:localhost
authorityKeyIdentifier = keyid:always

[eku_ca_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[no_bc_ext]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ocsp_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
noCheck = ignored
authorityKeyIdentifier = keyid:always

[ocsp_noeku_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
authorityKeyIdentifier = keyid:always

[nc_ca_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
nameConstraints = critical, @nc_ca_constraints

[nc_ca_constraints]
permitted;DNS.0 = example.com
permitted;DNS.1 = .example.org
permitted;IP.0 = 10.0.0.0/255.0.0.0
permitted;IP.1 = 127.0.0.1/255.255.255.255
permitted;IP.2 = fd00::/ffff:ff00::
permitted;dirName.0 = nc_permitted_dn
permitted;email.0 = example.com
permitted;URI.0 = .example.com
excluded;DNS.0 = bad.example.com
excluded;IP.0 = 10.1.0.0/255.255.0.0

[nc_permitted_dn]
O = zig-sdk test

[nc_sub_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
nameConstraints = critical, permitted;DNS:www.example.com

[nc_rid_ext]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
nameConstraints = critical, permitted;RID:1.2.3.4

[nc_leaf_ext]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = $ENV::SAN
authorityKeyIdentifier = keyid:always
EOF
export SAN=DNS:unused

# ec_key <path>
ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

# root <certificate> <key> <subject>
root() {
  openssl req -x509 -new -key "$2" -subj "$3" -sha256 -not_before $not_before -not_after $not_after \
    -config "$work/ext.cnf" -extensions root_ext -out "$1"
}

# issue <certificate> <subject> <key> <issuer certificate> <issuer key> <serial> <extensions>
issue() {
  openssl req -new -key "$3" -subj "$2" -out "$work/request.csr"
  openssl x509 -req -in "$work/request.csr" -CA "$4" -CAkey "$5" -set_serial "$6" -sha256 \
    -not_before $not_before -not_after $not_after -extfile "$work/ext.cnf" -extensions "$7" -out "$1"
}

# -- Certificates of the older test CA --------------------------------------------------------
old_ca="$pem/ca.crt"
old_key="$pem/ca.key"
ec_key "$work/cn-only.key"
issue "$pem/cn-only.crt" "/CN=localhost" "$work/cn-only.key" "$old_ca" "$old_key" 0x1001 cn_only_ext
ec_key "$pem/client-leaf.key"
issue "$pem/client-leaf.crt" "/CN=zig-sdk test client" "$pem/client-leaf.key" "$old_ca" "$old_key" 0x1002 client_ext
ec_key "$work/any-eku-leaf.key"
issue "$pem/any-eku-leaf.crt" "/CN=localhost" "$work/any-eku-leaf.key" "$old_ca" "$old_key" 0x1003 any_eku_ext
ec_key "$work/eku-ca.key"
issue "$pem/eku-ca.crt" "/CN=zig-sdk client-only CA" "$work/eku-ca.key" "$old_ca" "$old_key" 0x1004 eku_ca_ext
ec_key "$work/eku-leaf.key"
issue "$pem/eku-leaf.crt" "/CN=localhost" "$work/eku-leaf.key" "$pem/eku-ca.crt" "$work/eku-ca.key" 0x1005 leaf_ext
ec_key "$work/no-bc-ca.key"
issue "$pem/no-bc-ca.crt" "/CN=zig-sdk CA without basic constraints" "$work/no-bc-ca.key" "$old_ca" "$old_key" 0x1006 no_bc_ext
ec_key "$work/no-bc-leaf.key"
issue "$pem/no-bc-leaf.crt" "/CN=localhost" "$work/no-bc-leaf.key" "$pem/no-bc-ca.crt" "$work/no-bc-ca.key" 0x1007 leaf_ext
# A second root with the name of the older test CA and another key.
ec_key "$work/ca-rekeyed.key"
root "$pem/ca-rekeyed.crt" "$work/ca-rekeyed.key" "/CN=zig-sdk test CA"

# -- Name constraints -------------------------------------------------------------------------
for k in nc-root nc-ca nc-sub-ca nc-self-ca nc-rid-ca; do ec_key "$work/$k.key"; done
ec_key "$pem/nc-leaf.key"
root "$pem/nc-root.crt" "$work/nc-root.key" "/CN=zig-sdk name constraints root"
issue "$pem/nc-ca.crt" "/CN=zig-sdk constrained CA" "$work/nc-ca.key" "$pem/nc-root.crt" "$work/nc-root.key" 0x2001 nc_ca_ext
issue "$pem/nc-sub-ca.crt" "/O=zig-sdk test/CN=zig-sdk constrained sub CA" "$work/nc-sub-ca.key" "$pem/nc-ca.crt" "$work/nc-ca.key" 0x2002 nc_sub_ext
# Self-issued: the subject is the name of nc-ca, the key is new, and nc-ca signs it.
issue "$pem/nc-self-ca.crt" "/CN=zig-sdk constrained CA" "$work/nc-self-ca.key" "$pem/nc-ca.crt" "$work/nc-ca.key" 0x2003 ca_ext
issue "$pem/nc-rid-ca.crt" "/CN=zig-sdk registered ID CA" "$work/nc-rid-ca.key" "$pem/nc-root.crt" "$work/nc-root.key" 0x2004 nc_rid_ext

serial=$((0x2100))
# nc_leaf <name> <issuer name> <subject> <subjectAltName>
nc_leaf() {
  serial=$((serial + 1))
  SAN="$4" issue "$pem/$1.crt" "$3" "$pem/nc-leaf.key" "$pem/$2.crt" "$work/$2.key" "$serial" nc_leaf_ext
}
ok_dn="/O=zig-sdk test/CN=www.example.com"
nc_leaf nc-ok nc-ca "$ok_dn" "DNS:www.example.com, DNS:example.com, DNS:api.example.org, IP:10.2.3.4, IP:127.0.0.1, IP:fd00::1, email:dev@example.com, URI:https://api.example.com/mcp"
nc_leaf nc-excluded nc-ca "$ok_dn" "DNS:bad.example.com, IP:127.0.0.1"
nc_leaf nc-outside nc-ca "$ok_dn" "DNS:www.example.net"
nc_leaf nc-apex nc-ca "$ok_dn" "DNS:example.org"
nc_leaf nc-ip-excluded nc-ca "$ok_dn" "DNS:www.example.com, IP:10.1.2.3"
nc_leaf nc-ip-outside nc-ca "$ok_dn" "DNS:www.example.com, IP:192.168.1.1"
nc_leaf nc-dn-outside nc-ca "/O=other org/CN=www.example.com" "DNS:www.example.com"
nc_leaf nc-email-outside nc-ca "$ok_dn" "DNS:www.example.com, email:dev@example.net"
nc_leaf nc-uri-outside nc-ca "$ok_dn" "DNS:www.example.com, URI:https://example.net/"
nc_leaf nc-sub-ok nc-sub-ca "$ok_dn" "DNS:www.example.com"
nc_leaf nc-sub-outside nc-sub-ca "$ok_dn" "DNS:api.example.com"
nc_leaf nc-self-leaf nc-self-ca "$ok_dn" "DNS:www.example.com"
nc_leaf nc-rid-leaf nc-rid-ca "$ok_dn" "DNS:www.example.com, RID:1.2.3.4.5"
cat "$pem/nc-ok.crt" "$pem/nc-ca.crt" >"$pem/nc-ok-chain.crt"
cat "$pem/nc-excluded.crt" "$pem/nc-ca.crt" >"$pem/nc-excluded-chain.crt"

# -- Revocation -------------------------------------------------------------------------------
ec_key "$work/rev-root.key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/rev-ca.key"
for k in rev-ocsp rev-ocsp-noeku; do ec_key "$work/$k.key"; done
ec_key "$pem/rev-leaf.key"
root "$pem/rev-root.crt" "$work/rev-root.key" "/CN=zig-sdk revocation root"
issue "$pem/rev-ca.crt" "/CN=zig-sdk revocation CA" "$work/rev-ca.key" "$pem/rev-root.crt" "$work/rev-root.key" 0x3001 ca_ext
issue "$pem/rev-leaf.crt" "/CN=localhost" "$pem/rev-leaf.key" "$pem/rev-ca.crt" "$work/rev-ca.key" 0x3101 leaf_ext
issue "$pem/rev-revoked.crt" "/CN=localhost" "$pem/rev-leaf.key" "$pem/rev-ca.crt" "$work/rev-ca.key" 0x3102 leaf_ext
issue "$work/rev-ocsp.crt" "/CN=zig-sdk OCSP responder" "$work/rev-ocsp.key" "$pem/rev-ca.crt" "$work/rev-ca.key" 0x3103 ocsp_ext
issue "$work/rev-ocsp-noeku.crt" "/CN=zig-sdk OCSP responder without EKU" "$work/rev-ocsp-noeku.key" "$pem/rev-ca.crt" "$work/rev-ca.key" 0x3104 ocsp_noeku_ext
cat "$pem/rev-leaf.crt" "$pem/rev-ca.crt" >"$pem/rev-chain.crt"
cat "$pem/rev-revoked.crt" "$pem/rev-ca.crt" >"$pem/rev-revoked-chain.crt"

# The CA database of rev-ca: rev-leaf is valid, rev-revoked is revoked.
printf 'V\t360101000000Z\t\t3101\tunknown\t/CN=localhost\n' >"$work/index.txt"
printf 'R\t360101000000Z\t260901000000Z,keyCompromise\t3102\tunknown\t/CN=localhost\n' >>"$work/index.txt"
# A database without rev-leaf, for the status "unknown".
printf 'R\t360101000000Z\t260901000000Z,keyCompromise\t3102\tunknown\t/CN=localhost\n' >"$work/index-unknown.txt"
# The CA database of rev-root: nothing is revoked.
: >"$work/index-root.txt"

cat >"$work/ca.cnf" <<EOF
[ca]
default_ca = rev_ca
[rev_ca]
database = $work/index.txt
crlnumber = $work/crlnumber
default_md = sha256
[root_ca]
database = $work/index-root.txt
crlnumber = $work/crlnumber
default_md = sha256
[crl_ext]
authorityKeyIdentifier = keyid:always
[crl_delta_ext]
authorityKeyIdentifier = keyid:always
2.5.29.27 = critical, ASN1:INTEGER:999
[crl_critical_ext]
authorityKeyIdentifier = keyid:always
1.3.6.1.4.1.55555.1 = critical, ASN1:UTF8String:unknown critical extension
EOF
echo 1000 >"$work/crlnumber"

# crl <name> <database section> <issuer certificate> <issuer key> <last update> <next update> <extensions>
crl() {
  openssl ca -gencrl -config "$work/ca.cnf" -name "$2" -cert "$3" -keyfile "$4" \
    -crl_lastupdate "$5" -crl_nextupdate "$6" -crlexts "$7" -out "$pem/$1.crl"
}
crl rev-ca rev_ca "$pem/rev-ca.crt" "$work/rev-ca.key" 20260901000000Z 20360101000000Z crl_ext
crl rev-ca-stale rev_ca "$pem/rev-ca.crt" "$work/rev-ca.key" 20260901000000Z 20261201000000Z crl_ext
crl rev-ca-delta rev_ca "$pem/rev-ca.crt" "$work/rev-ca.key" 20260901000000Z 20360101000000Z crl_delta_ext
crl rev-ca-critical rev_ca "$pem/rev-ca.crt" "$work/rev-ca.key" 20260901000000Z 20360101000000Z crl_critical_ext
crl rev-root root_ca "$pem/rev-root.crt" "$work/rev-root.key" 20260901000000Z 20360101000000Z crl_ext
openssl crl -in "$pem/rev-ca.crl" -outform DER -out "$der/rev-ca.crl"

# -- OCSP responses ---------------------------------------------------------------------------
openssl ocsp -issuer "$pem/rev-ca.crt" -cert "$pem/rev-leaf.crt" -no_nonce -reqout "$work/leaf-sha1.req"
openssl ocsp -sha256 -issuer "$pem/rev-ca.crt" -cert "$pem/rev-leaf.crt" -no_nonce -reqout "$work/leaf-sha256.req"
openssl ocsp -issuer "$pem/rev-ca.crt" -cert "$pem/rev-revoked.crt" -no_nonce -reqout "$work/revoked.req"

# respond <name> <database> <request> <signer certificate> <signer key> <days> [options]
respond() {
  local name=$1 index=$2 req=$3 signer=$4 key=$5 days=$6
  shift 6
  openssl ocsp -index "$work/$index" -CA "$pem/rev-ca.crt" -rsigner "$signer" -rkey "$key" \
    -reqin "$work/$req" -ndays "$days" -respout "$der/$name.ocsp" "$@"
}
respond rev-leaf-good index.txt leaf-sha1.req "$pem/rev-ca.crt" "$work/rev-ca.key" 3650
respond rev-leaf-good-delegated index.txt leaf-sha256.req "$work/rev-ocsp.crt" "$work/rev-ocsp.key" 3650 -resp_key_id
respond rev-leaf-noeku index.txt leaf-sha1.req "$work/rev-ocsp-noeku.crt" "$work/rev-ocsp-noeku.key" 3650
respond rev-leaf-stale index.txt leaf-sha1.req "$pem/rev-ca.crt" "$work/rev-ca.key" 30
respond rev-leaf-unknown index-unknown.txt leaf-sha1.req "$pem/rev-ca.crt" "$work/rev-ca.key" 3650
respond rev-revoked index.txt revoked.req "$pem/rev-ca.crt" "$work/rev-ca.key" 3650
