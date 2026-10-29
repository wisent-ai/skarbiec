#!/usr/bin/env bash
# Real test of signing an SSH key with an authority the vault keeps,
# `skarbiec ssh sign <ca-id> <public-key-file>`, through the built binary and
# the real ssh-keygen, on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# ssh new makes the authority; a user key made by ssh-keygen in the test
# directory is signed. ssh-keygen -L reads the certificate back: signed by the
# authority's public key, for the identity and principals asked. No workspace
# is left beside the vault, the journal holds no key, and a missing
# --validity and a file that is not a public key are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/keygen/ssh_sign.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/keygen/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" </dev/null 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said" ;;
  esac
}

CA="sign-ca-$RUN"
WANT=ok run init "sign-owner-$RUN"
WANT=ok run ssh new "$CA"
CA_PUBLIC="$(printf '%s' "$out" | jq -r .public_key)"
ssh-keygen -q -t "$(printf '%s' "$out" | jq -r .type)" -N "" -C "user-$RUN" -f "$ROOT/user"

WANT=ok run ssh sign "$CA" "$ROOT/user.pub" --identity "alice-$RUN" --principals "deploy,ops" --validity "+1h"
printf '%s\n' "$(printf '%s' "$out" | jq -r .certificate)" >"$ROOT/user-cert.pub"
SHOWN="$(ssh-keygen -L -f "$ROOT/user-cert.pub")"
printf '%s\n' "$SHOWN" >>"$REPORT"
case "$SHOWN" in *"Key ID: \"alice-$RUN\""*) ;; *) fail "the certificate does not carry the identity asked" ;; esac
case "$SHOWN" in *deploy*ops*) ;; *) fail "the certificate does not carry both principals" ;; esac
CA_PRINT="$(printf '%s\n' "$CA_PUBLIC" | ssh-keygen -lf - | cut -d ' ' -f2)"
case "$SHOWN" in *"$CA_PRINT"*) ;; *) fail "the certificate is not signed by the authority's key $CA_PRINT" ;; esac
for left in "$ROOT"/.skarbiec-keygen-*; do
  if [ -e "$left" ]; then fail "a key workspace was left beside the vault: $left"; fi
done
if grep -q "PRIVATE KEY" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds a key"; fi
echo "ok: the certificate is signed by the authority for the identity and principals asked; nothing is left behind" >>"$REPORT"

# --host signs a host key: ssh-keygen -L names it a host certificate.
ssh-keygen -q -t "$(printf '%s' "$CA_PUBLIC" | cut -d ' ' -f1 | sed 's/^ssh-//')" -N "" -C "host-$RUN" -f "$ROOT/host"
WANT=ok run ssh sign "$CA" "$ROOT/host.pub" --identity "web-$RUN" --principals "web.example" --validity "+1h" --host
printf '%s\n' "$(printf '%s' "$out" | jq -r .certificate)" >"$ROOT/host-cert.pub"
case "$(ssh-keygen -L -f "$ROOT/host-cert.pub")" in *"host certificate"*) echo "ok: --host signs a host certificate" >>"$REPORT" ;; *) fail "--host did not make a host certificate" ;; esac

WANT=refused run ssh sign "$CA" "$ROOT/user.pub" --identity "alice-$RUN" --principals deploy
names "--validity is required"
printf 'not a key\n' >"$ROOT/not.pub"
WANT=refused run ssh sign "$CA" "$ROOT/not.pub" --identity "alice-$RUN" --principals deploy --validity "+1h"
names "ssh-keygen refused to sign"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
