#!/usr/bin/env bash
# Real test of moving a second factor, `skarbiec totp uri <id>`, through the
# built binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE
# and GNUPGHOME point into this checkout's target directory, so the
# operator's vault and keyring are never read or written.
#
# A login gets a seed through totp set; totp uri prints an otpauth:// address
# carrying that seed, the login's name as issuer and its username as account.
# Storing the printed address on a second login through totp set gives it the
# same code `totp code` computes for the first — the round trip a phone makes. The
# journal names the read and never the seed; a login with no seed and a call
# without one id are refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/authenticator/totp_uri.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/authenticator/$RUN"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: output: $out stderr: $said" ;;
  esac
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"%s","password":"totp-uri-secret-%s"},"context":{"display_name":"%s","domains":["example.com"]}}' \
    "$2" "$RUN" "$3" >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "totp-uri-owner-$RUN"
FIRST="totp-uri-first-$RUN"
PHONE="totp-uri-phone-$RUN"
BARE="totp-uri-bare-$RUN"
SEED="JBSWY3DPEHPK3PXP"
login "$FIRST" "me@example.com" "Example Bank"
login "$PHONE" "me@example.com" "Example Bank"
login "$BARE" "me@example.com" "Example Bank"
printf '%s' "$SEED" >"$ROOT/stdin"
WANT=ok run totp set "$FIRST"
: >"$ROOT/stdin"

WANT=ok run totp uri "$FIRST"
ADDRESS="$(printf '%s' "$out" | jq -r .uri)"
case "$ADDRESS" in
  "otpauth://totp/Example%20Bank:me%40example%2Ecom?secret=$SEED&issuer=Example%20Bank&"*) ;;
  *) fail "totp uri did not print the address with issuer, account and seed: $ADDRESS" ;;
esac
echo "ok: totp uri prints the Key URI Format address with the item's name and username" >>"$REPORT"

printf '%s' "$ADDRESS" >"$ROOT/stdin"
WANT=ok run totp set "$PHONE"
: >"$ROOT/stdin"
WANT=ok run totp code "$FIRST"
FIRST_CODE="$(printf '%s' "$out" | jq -r .code)"
WANT=ok run totp code "$PHONE"
[ "$(printf '%s' "$out" | jq -r .code)" = "$FIRST_CODE" ] || fail "the address stored elsewhere did not answer the same code"
echo "ok: the printed address, stored again, answers the same code" >>"$REPORT"

jq -e --arg id "$FIRST" 'select(.op == "totp-uri-read") | .extra.item == $id' "$SKARBIEC_AUDIT_FILE" >/dev/null \
  || fail "the journal does not name the totp uri read"
if grep -q "$SEED" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds the seed"; fi

WANT=refused run totp uri "$BARE"
names "$BARE keeps no authenticator seed"
WANT=refused run totp uri
names "usage: totp uri <item-id>"
WANT=refused run totp "$FIRST"
names "usage: totp code"
WANT=refused run totp-uri "$FIRST"
names "unknown command: totp-uri"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
