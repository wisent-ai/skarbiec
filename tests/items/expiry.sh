#!/usr/bin/env bash
# Real test of recording when an item runs out, `skarbiec expiry set|clear|
# list`, through the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# It records a date already past on one item and a later one on another, then
# checks that list puts the past one first marked expired, that --before
# narrows the list, that rename carries the date to the new id, that clear
# removes it and a second clear says nothing was recorded, that set --tag
# records one day on every item a tag carries, and that a date of another
# shape, an unknown item and a tag no item carries are refused naming them.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/items/expiry.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/items/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "expiry-owner-$RUN"
PASSPORT="expiry-passport-$RUN"
CARD="expiry-card-$RUN"
note "$PASSPORT" "passport-$RUN"
note "$CARD" "card-$RUN"

PAST="2000-01-01T00:00:00Z"
LATER="2999-01-01T00:00:00Z"
BETWEEN="2500-01-01T00:00:00Z"
WANT=ok run expiry set "$PASSPORT" --on "$PAST"
WANT=ok run expiry set "$CARD" --on "$LATER"

WANT=ok run expiry list
[ "$(printf '%s' "$out" | jq -r '.[0].item')" = "$PASSPORT" ] || fail "list did not put the date already past first"
[ "$(printf '%s' "$out" | jq -r '.[0].expired')" = true ] || fail "list did not mark the past date expired"
WANT=ok run expiry list --before "$BETWEEN"
printf '%s' "$out" | jq -e --arg card "$CARD" 'map(.item) | index($card) == null' >/dev/null \
  || fail "--before listed a date after it"
echo "ok: list puts the lapsed item first, marked expired, and --before narrows it" >>"$REPORT"

RENAMED="expiry-passport-renamed-$RUN"
WANT=ok run rename "$PASSPORT" "$RENAMED"
WANT=ok run expiry list
printf '%s' "$out" | jq -e --arg id "$RENAMED" 'map(.item) | index($id) != null' >/dev/null \
  || fail "rename did not carry the recorded date to the new id"
echo "ok: rename carried the date" >>"$REPORT"

WANT=ok run expiry clear "$RENAMED"
WANT=ok run expiry clear "$RENAMED"
[ "$(printf '%s' "$out" | jq -r .cleared)" = false ] || fail "a second clear did not say nothing was recorded"
echo "ok: clear removes the date and a second clear writes nothing" >>"$REPORT"

SET="contractor-$RUN"
for member in "expiry-laptop-$RUN" "expiry-vpn-$RUN"; do
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$member" >"$ROOT/stdin"
  WANT=ok run set "$member" --type note --tags "$SET"
  : >"$ROOT/stdin"
done
WANT=ok run expiry set --tag "$SET" --on "$BETWEEN"
[ "$(printf '%s' "$out" | jq -c '.items | sort')" = "[\"expiry-laptop-$RUN\",\"expiry-vpn-$RUN\"]" ] \
  || fail "expiry set --tag did not name exactly the items carrying the tag"
WANT=ok run expiry list
printf '%s' "$out" | jq -e --arg on "$BETWEEN" --arg laptop "expiry-laptop-$RUN" --arg vpn "expiry-vpn-$RUN" \
  '[.[] | select((.item == $laptop or .item == $vpn) and .expires_at == $on)] | length == ([$laptop, $vpn] | length)' >/dev/null \
  || fail "expiry set --tag did not record the day on every tagged item"
echo "ok: expiry set --tag records one day on every live item the tag carries" >>"$REPORT"
WANT=ok run expiry clear --tag "$SET"
[ "$(printf '%s' "$out" | jq -c '.cleared | sort')" = "[\"expiry-laptop-$RUN\",\"expiry-vpn-$RUN\"]" ] \
  || fail "expiry clear --tag did not name the items whose date it forgot"
WANT=ok run expiry list
printf '%s' "$out" | jq -e --arg laptop "expiry-laptop-$RUN" --arg vpn "expiry-vpn-$RUN" \
  '[.[] | select(.item == $laptop or .item == $vpn)] | length == ([] | length)' >/dev/null \
  || fail "expiry clear --tag left a tagged item's date recorded"
WANT=ok run expiry clear --tag "$SET"
[ "$(printf '%s' "$out" | jq -c .cleared)" = "[]" ] || fail "a second clear --tag claimed to forget a date"
echo "ok: expiry clear --tag forgets the set's dates and a second one forgets nothing" >>"$REPORT"
WANT=refused run expiry set --tag "nobody-$RUN" --on "$LATER"
names "no live item carries the tag nobody-$RUN"

WANT=refused run expiry set "$CARD" --on tomorrow
names "--on tomorrow is not a UTC time"
WANT=refused run expiry set "missing-$RUN" --on "$LATER"
names "missing-$RUN"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
