#!/usr/bin/env bash
# Make the certificate chains tests/x509.rs reads, with OpenSSL 3 (any
# release with `x509 -not_before`), into this directory as DER. The keys are
# thrown away; the certificates are kept, so the test reads what a real CA
# tool writes. Run again only to change what the chains state.
#
#   root-rsa      RSA 2048 root (sha256WithRSAEncryption)
#   inter-p256    P-256 CA, pathlen 0, signed by root-rsa
#   leaf-p384     P-384 server key for host.test and *.wild.test, signed by
#                 inter-p256 with ecdsa-with-SHA384
#   root-ed25519  Ed25519 root, and leaf-ed25519 (an RSA 2048 server key for
#                 host.test) signed by it with Ed25519
#   leaf-client   like leaf-p384 but extKeyUsage clientAuth only
#   inter-notca   P-256, CA:FALSE, signed by root-rsa, and leaf-under-notca
#                 signed by it
#   inter-deep    a CA signed by inter-p256 (whose pathlen 0 forbids it), and
#                 leaf-deep signed by it
#   leaf-critical leaf-p384's shape with an unknown critical extension
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d "$PWD/.make.XXXXXX")
trap 'rm -rf "$work"' EXIT
dates=(-not_before 20000101000000Z -not_after 20991231235959Z)

key() { openssl genpkey "$@" -out "$work/$name.key" 2>/dev/null; }
rsa() { name=$1; key -algorithm RSA -pkeyopt rsa_keygen_bits:2048; }
ec() { name=$1; key -algorithm EC -pkeyopt "ec_paramgen_curve:$2"; }
ed() { name=$1; key -algorithm ED25519; }

# cert NAME SUBJECT ISSUER DIGEST EXTENSIONS: NAME's key, signed by ISSUER's.
cert() {
  local name=$1 subject=$2 issuer=$3 digest=$4 extensions=$5
  printf '%b\n' "$extensions" >"$work/$name.ext"
  openssl req -new -key "$work/$name.key" -subj "$subject" -out "$work/$name.csr"
  local signer=(-CA "$work/$issuer.pem" -CAkey "$work/$issuer.key")
  [ "$issuer" = "$name" ] && signer=(-key "$work/$name.key")
  openssl x509 -req -in "$work/$name.csr" "${signer[@]}" ${digest:+-"$digest"} "${dates[@]}" \
    -set_serial "0x$(openssl rand -hex 8)" -extfile "$work/$name.ext" -out "$work/$name.pem"
  openssl x509 -in "$work/$name.pem" -outform DER -out "$name.der"
}

ca='basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign'
server='basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:host.test,DNS:*.wild.test,IP:127.0.0.1'

rsa root-rsa;    cert root-rsa "/O=Skarbiec test/CN=RSA root" root-rsa sha256 "$ca"
ec inter-p256 P-256; cert inter-p256 "/O=Skarbiec test/CN=P-256 intermediate" root-rsa sha256 "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign"
ec leaf-p384 P-384;  cert leaf-p384 "/CN=host.test" inter-p256 sha384 "$server"
ed root-ed25519; cert root-ed25519 "/O=Skarbiec test/CN=Ed25519 root" root-ed25519 "" "$ca"
rsa leaf-ed25519; cert leaf-ed25519 "/CN=host.test" root-ed25519 "" "$server"
ec leaf-client P-256; cert leaf-client "/CN=host.test" inter-p256 sha256 "${server/serverAuth/clientAuth}"
ec inter-notca P-256; cert inter-notca "/O=Skarbiec test/CN=not a CA" root-rsa sha256 'basicConstraints=critical,CA:FALSE'
ec leaf-under-notca P-256; cert leaf-under-notca "/CN=host.test" inter-notca sha256 "$server"
ec inter-deep P-256; cert inter-deep "/O=Skarbiec test/CN=too deep" inter-p256 sha256 "$ca"
ec leaf-deep P-256; cert leaf-deep "/CN=host.test" inter-deep sha256 "$server"
ec leaf-critical P-256; cert leaf-critical "/CN=host.test" inter-p256 sha256 "$server\n1.3.6.1.4.1.99999.1=critical,ASN1:NULL"
rm -f ./*.srl
