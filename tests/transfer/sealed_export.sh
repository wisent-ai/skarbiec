#!/usr/bin/env bash
# Real test of moving items between vaults through a file that is never
# plaintext on disk: `skarbiec export <file> --canonical --encrypt-to <uid>`
# and `skarbiec import <file>`, through the built binary on two vaults of its
# own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vaults and keyring are never
# read or written.
#
# The first vault exports one login sealed to its owner; the file must be an
# armored OpenPGP message that does not hold the password. A second vault of
# the same owner imports it, and the login must read back with its password
# and tags. Sealing to a uid that is not a recipient is refused naming it.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/transfer/sealed_export.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/transfer/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  if [ "$got" = ok ]; then
    printf '$ skarbiec %s\nresult: ok\n\n' "$*" >>"$REPORT"
  else
    printf '$ skarbiec %s\nresult: refused\noutput: %s\nstderr: %s\n\n' "$*" "$out" "$said" >>"$REPORT"
  fi
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said; output: $out" ;;
  esac
}

OWNER="transfer-owner-$RUN"
ITEM="transfer-login-$RUN"
SECRET="transfer-secret-$RUN"
SEALED="$ROOT/sealed-export.asc"

: >"$ROOT/stdin"
export SKARBIEC_VAULT_FILE="$ROOT/first.json"
WANT=ok run init "$OWNER"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"transfer-user","password":"%s"},"context":{"domains":["transfer.test"]}}' \
  "$SECRET" >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type login --tags "moved-$RUN"
: >"$ROOT/stdin"

WANT=ok run export "$SEALED" --canonical --encrypt-to "$OWNER"
head -n1 "$SEALED" | grep -q -- '-----BEGIN PGP MESSAGE-----' || fail "the export is not an armored OpenPGP message"
if grep -q "$SECRET" "$SEALED"; then fail "the sealed export holds the password in plaintext"; fi
echo "ok: the export is sealed and holds no plaintext value" >>"$REPORT"

WANT=refused run export "$ROOT/other.asc" --canonical --encrypt-to "stranger-$RUN"
names "stranger-$RUN"

export SKARBIEC_VAULT_FILE="$ROOT/second.json"
WANT=ok run init "$OWNER"
WANT=ok run import "$SEALED"
WANT=ok run get "$ITEM" --field password
[ "$out" = "$SECRET" ] || fail "the imported login does not read back with its password"
WANT=ok run list
printf '%s' "$out" | jq -e --arg id "$ITEM" --arg tag "moved-$RUN" '.[] | select(.id == $id) | .tags | index($tag) != null' >/dev/null \
  || fail "the imported login lost its tag"
echo "ok: the second vault imported the sealed file with the value and tags intact" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
