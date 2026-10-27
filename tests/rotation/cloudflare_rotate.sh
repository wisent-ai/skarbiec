#!/usr/bin/env bash
# Real test of `skarbiec rotate --with cloudflare`, through the built binary on a
# vault of its own and Cloudflare's real API: SKARBIEC_TEST_CLOUDFLARE_TOKEN_FILE
# names an owner-only file holding a user API token kept for this test, with
# permission to edit API tokens. Rolling ends the value the file holds, so
# the test writes the new one back into the file before it ends, and the
# next run starts from it. SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# After rotate --with cloudflare the item holds a value Cloudflare verifies and the
# old one is refused; no token is printed. An --account that is not an
# account id and an item that is not a token are refused before Cloudflare
# is asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_CLOUDFLARE_TOKEN_FILE=<file> tests/rotation/cloudflare_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
TOKEN_FILE=${SKARBIEC_TEST_CLOUDFLARE_TOKEN_FILE:?set SKARBIEC_TEST_CLOUDFLARE_TOKEN_FILE to an owner-only file holding a Cloudflare user token kept for this test}
API="https://api.cloudflare.com/client/v4"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/rotation/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
# Whether Cloudflare verifies the token on standard input.
verifies() {
  printf 'Authorization: Bearer %s\n' "$*" | curl -sS --fail -H @- "$API/user/tokens/verify" | jq -e '.success' &>>"$REPORT"
}

: >"$ROOT/stdin"
WANT=ok run init "cloudflare-owner-$RUN"
ITEM="cloudflare-$RUN"
OLD="$(tr -d '\n' <"$TOKEN_FILE")"
jq -n --arg token "$OLD" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type token
: >"$ROOT/stdin"

WANT=refused run rotate "$ITEM" --with cloudflare --account "not/an/account"
names "is not a Cloudflare account id"
jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a token"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with cloudflare
names "rotate --with cloudflare rolls the token a token item keeps"

WANT=ok run rotate "$ITEM" --with cloudflare
case "$out" in *"$OLD"*) fail "rotate printed the old token" ;; esac
WANT=ok run get "$ITEM" --field token
NEW="$out"
# The next run starts from the value Cloudflare now verifies.
printf '%s\n' "$NEW" >"$TOKEN_FILE"
[ "$NEW" != "$OLD" ] || fail "the item still holds the old value"
verifies "$NEW" || fail "Cloudflare does not verify the new value"
if verifies "$OLD"; then fail "Cloudflare still verifies the old value"; fi
echo "ok: the item holds Cloudflare's new value and the old one is ended" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
