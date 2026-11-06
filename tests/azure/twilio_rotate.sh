#!/usr/bin/env bash
# Real test of `skarbiec rotate --with twilio`, through the built binary on a vault
# of its own and a real Twilio account kept for this test:
# SKARBIEC_TEST_TWILIO_SID names the account and SKARBIEC_TEST_TWILIO_TOKEN
# its current auth token. The test rotates the token twice, so the account
# ends on a token the vault holds; the last report line names that item.
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# After rotate --with twilio the item holds a token that signs in to the account and
# the old token no longer does; no token is printed. An item that is not an
# api-key and an api_user that is not an Account SID are refused before
# Twilio is asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_TWILIO_SID=<AC...> SKARBIEC_TEST_TWILIO_TOKEN=<token> tests/azure/twilio_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
SID=${SKARBIEC_TEST_TWILIO_SID:?set SKARBIEC_TEST_TWILIO_SID to an account this test may rotate the auth token of}
FIRST=${SKARBIEC_TEST_TWILIO_TOKEN:?set SKARBIEC_TEST_TWILIO_TOKEN to that account's current auth token}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/azure/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "account: $SID" >>"$REPORT"
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
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
# Whether Twilio takes one token for the account; the token reaches curl as
# a header on its standard input, and curl fails on Twilio's refusal.
signs_in() {
  printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "$SID" "$1" | base64 | tr -d '\n')" \
    | curl -sf -o /dev/null -H @- "https://api.twilio.com/2010-04-01/Accounts/$SID.json"
}

: >"$ROOT/stdin"
WANT=ok run init "twilio-owner-$RUN"
ITEM="twilio-$RUN"
jq -n --arg sid "$SID" --arg token "$FIRST" '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_user:$sid,api_key:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type api-key
: >"$ROOT/stdin"

for round in first second; do
  WANT=ok run get "$ITEM" --field api_key
  OLD="$out"
  WANT=ok run rotate "$ITEM" --with twilio
  # The old token must be in neither stream, so both are searched.
  case "$out$said" in *"$OLD"*) fail "rotate printed the old token" ;; esac
  WANT=ok run get "$ITEM" --field api_key
  NEW="$out"
  [ "$NEW" != "$OLD" ] || fail "the $round rotation left the item's token unchanged"
  signs_in "$NEW" || fail "the $round new token does not sign in"
  if signs_in "$OLD"; then fail "the $round old token still signs in"; fi
  echo "ok: the $round rotation stored a token that signs in and ended the old one" >>"$REPORT"
done
echo "the account's current token is held by $ITEM in $SKARBIEC_VAULT_FILE" >>"$REPORT"

jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{value:"not a token"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
jq -n '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_user:"someone",api_key:"x"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "other-$RUN" --type api-key
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with twilio
case "$said" in *"rotate --with twilio replaces an api-key item"*) ;; *) fail "a note was not refused naming its kind: output: $out stderr: $said" ;; esac
WANT=refused run rotate "other-$RUN" --with twilio
case "$said" in *"not a Twilio Account SID"*) ;; *) fail "an api_user that is not an Account SID was not refused: output: $out stderr: $said" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
