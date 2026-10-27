#!/usr/bin/env bash
# Real test of `skarbiec rotate --with vercel`, through the built binary on a vault
# of its own and a real Vercel account kept for this test:
# SKARBIEC_TEST_VERCEL_TOKEN is a token of that account made for this test
# alone. The test rotates it twice — the second time with --days, so the new
# token ends — and the account ends on a token the vault holds; the last
# report line names that item. SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# After rotate --with vercel the item holds a token that signs in, carrying the old
# token's name, and the old token no longer signs in; no token is printed. A
# note item and a --days that is not a number are refused before Vercel is
# asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_VERCEL_TOKEN=<token> SKARBIEC_TEST_VERCEL_DAYS=<N> tests/azure/vercel_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
FIRST=${SKARBIEC_TEST_VERCEL_TOKEN:?set SKARBIEC_TEST_VERCEL_TOKEN to a Vercel token this test may replace}
DAYS=${SKARBIEC_TEST_VERCEL_DAYS:?set SKARBIEC_TEST_VERCEL_DAYS to how many days the second new token lasts}
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
# Whether Vercel takes one token; the token reaches curl as a header on its
# standard input, and curl fails on Vercel's refusal.
signs_in() {
  printf 'Authorization: Bearer %s\n' "$1" | curl -sf -o /dev/null -H @- "https://api.vercel.com/v2/user"
}

: >"$ROOT/stdin"
WANT=ok run init "vercel-owner-$RUN"
ITEM="vercel-$RUN"
jq -n --arg token "$FIRST" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type token
: >"$ROOT/stdin"

NAME=""
for round in first second; do
  WANT=ok run get "$ITEM" --field token
  OLD="$out"
  case "$round" in
    first) WANT=ok run rotate "$ITEM" --with vercel ;;
    *)
      WANT=ok run rotate "$ITEM" --with vercel --days "$DAYS"
      [ "$(printf '%s' "$out" | jq -r '.expires_at != null')" = true ] || fail "the token made with --days does not end: $out"
      ;;
  esac
  case "$out" in *"$OLD"*) fail "rotate printed the old token" ;; esac
  named="$(printf '%s' "$out" | jq -r .name)"
  [ -z "$NAME" ] || [ "$named" = "$NAME" ] || fail "the $round rotation changed the token's name from $NAME to $named"
  NAME="$named"
  WANT=ok run get "$ITEM" --field token
  NEW="$out"
  [ "$NEW" != "$OLD" ] || fail "the $round rotation left the item's token unchanged"
  signs_in "$NEW" || fail "the $round new token does not sign in"
  if signs_in "$OLD"; then fail "the $round old token still signs in"; fi
  echo "ok: the $round rotation stored a token named $NAME that signs in and deleted the old one" >>"$REPORT"
done
echo "the account's current test token is held by $ITEM in $SKARBIEC_VAULT_FILE" >>"$REPORT"

jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{value:"not a token"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with vercel
case "$out" in *"rotate --with vercel replaces a token item"*) ;; *) fail "a note was not refused naming its kind: $out" ;; esac
WANT=refused run rotate "$ITEM" --with vercel --days "soon"
case "$out" in *"not a whole number of days"*) ;; *) fail "a --days that is not a number was not refused: $out" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
