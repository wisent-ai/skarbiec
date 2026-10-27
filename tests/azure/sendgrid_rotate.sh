#!/usr/bin/env bash
# Real test of `skarbiec rotate --with sendgrid`, through the built binary on a vault
# of its own and a real SendGrid account kept for this test:
# SKARBIEC_TEST_SENDGRID_KEY is a key of that account with API Keys access,
# made for this test alone. The test rotates it twice, so the account ends
# on a key the vault holds; the last report line names that item.
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# After rotate --with sendgrid the item holds a key that signs in, carrying the old
# key's name, and the old key no longer signs in; no key is printed. A note
# item and a token that is not a SendGrid key are refused before SendGrid is
# asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_SENDGRID_KEY=<SG....> tests/azure/sendgrid_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
FIRST=${SKARBIEC_TEST_SENDGRID_KEY:?set SKARBIEC_TEST_SENDGRID_KEY to a SendGrid key with API Keys access this test may replace}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/azure/$RUN"
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
# Whether SendGrid takes one key; the key reaches curl as a header on its
# standard input, and curl fails on SendGrid's refusal.
signs_in() {
  printf 'Authorization: Bearer %s\n' "$1" | curl -sf -o /dev/null -H @- "https://api.sendgrid.com/v3/scopes"
}

: >"$ROOT/stdin"
WANT=ok run init "sendgrid-owner-$RUN"
ITEM="sendgrid-$RUN"
jq -n --arg key "$FIRST" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$key},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type token
: >"$ROOT/stdin"

NAME=""
for round in first second; do
  WANT=ok run get "$ITEM" --field token
  OLD="$out"
  WANT=ok run rotate "$ITEM" --with sendgrid
  case "$out" in *"$OLD"*) fail "rotate printed the old key" ;; esac
  named="$(printf '%s' "$out" | jq -r .name)"
  [ -z "$NAME" ] || [ "$named" = "$NAME" ] || fail "the $round rotation changed the key's name from $NAME to $named"
  NAME="$named"
  WANT=ok run get "$ITEM" --field token
  NEW="$out"
  [ "$NEW" != "$OLD" ] || fail "the $round rotation left the item's key unchanged"
  signs_in "$NEW" || fail "the $round new key does not sign in"
  if signs_in "$OLD"; then fail "the $round old key still signs in"; fi
  echo "ok: the $round rotation stored a key named $NAME that signs in and deleted the old one" >>"$REPORT"
done
echo "the account's current test key is held by $ITEM in $SKARBIEC_VAULT_FILE" >>"$REPORT"

jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{value:"not a key"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
jq -n '{schema:"skarbiec.item.v2",kind:"token",fields:{token:"not-a-sendgrid-key"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "other-$RUN" --type token
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with sendgrid
case "$out" in *"rotate --with sendgrid replaces a token item"*) ;; *) fail "a note was not refused naming its kind: $out" ;; esac
WANT=refused run rotate "other-$RUN" --with sendgrid
case "$out" in *"not a SendGrid API key"*) ;; *) fail "a token that is not a SendGrid key was not refused: $out" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
