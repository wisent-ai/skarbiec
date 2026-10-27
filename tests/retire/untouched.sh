#!/usr/bin/env bash
# Real test of `skarbiec delete --untouched-since <iso> [--yes]`, through the
# built binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE
# and GNUPGHOME point into this checkout's target directory, so the
# operator's vault and keyring are never read or written.
#
# Two notes are written, a moment is taken, then one of them is retagged, so
# the journal names it after the moment and not the other. Without --yes the
# untouched note is listed and nothing moves; with --yes it alone leaves the
# live list, a grant naming it is reported, and restore brings it back. A
# moment not of the stamp form, --tag beside --untouched-since, and a moment
# after which every item was named are refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/retire/untouched.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/retire/$RUN"
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
# One second, counted rather than typed, so a stamp falls after the writes.
SECOND="$(printf 's' | wc -c | tr -d ' ')"

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
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$1-value" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note --tags "$2"
  : >"$ROOT/stdin"
}
live() {
  WANT=ok run list
  printf '%s' "$out" | jq -e --arg id "$1" 'map(.id) | index($id) != null' >/dev/null
}

: >"$ROOT/stdin"
WANT=ok run init "retire-owner-$RUN"
USED="used-$RUN"
IDLE="idle-$RUN"
note "$USED" "retire-$RUN"
note "$IDLE" "retire-$RUN"
WANT=ok run grant issue "idle-consumer-$RUN" --capabilities "read:$IDLE#value" --until-revoked
sleep "$SECOND"
MOMENT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
WANT=ok run retag "$USED" --tags "retire-$RUN,touched-$RUN"

WANT=ok run delete --untouched-since "$MOMENT"
[ "$(printf '%s' "$out" | jq -r .confirmed)" = false ] || fail "delete --untouched-since without --yes trashed something"
printf '%s' "$out" | jq -e --arg idle "$IDLE" --arg used "$USED" '(.would_trash | index($idle) != null) and (.would_trash | index($used) == null)' >/dev/null \
  || fail "delete --untouched-since did not list exactly the untouched note: $out"
live "$IDLE" || fail "delete --untouched-since without --yes took the note out of the live list"
echo "ok: without --yes the untouched note is listed and nothing moves" >>"$REPORT"

WANT=ok run delete --untouched-since "$MOMENT" --yes
printf '%s' "$out" | jq -e --arg idle "$IDLE" --arg consumer "idle-consumer-$RUN" '.grants_naming_them[$idle] | index($consumer) != null' >/dev/null \
  || fail "delete --untouched-since --yes did not name the grant still naming the note: $out"
if live "$IDLE"; then fail "delete --untouched-since --yes left the untouched note live"; fi
live "$USED" || fail "delete --untouched-since --yes trashed the note the journal named since the moment"
grep -q '"items-trashed-untouched"' "$SKARBIEC_AUDIT_FILE" || fail "no items-trashed-untouched journal entry was appended"
WANT=ok run restore "$IDLE"
live "$IDLE" || fail "restore did not bring back the trashed note"
echo "ok: with --yes only the untouched note is trashed, its grant named, and restore undoes it" >>"$REPORT"

WANT=refused run delete --untouched-since "yesterday"
names "is not a UTC time of the form"
WANT=refused run delete --untouched-since "$MOMENT" --tag "retire-$RUN" --yes
names "not both"
WANT=ok run retag "$IDLE" --tags "retire-$RUN,touched-$RUN"
WANT=refused run delete --untouched-since "$MOMENT" --yes
names "so nothing was trashed"
live "$USED" || fail "a refused delete --untouched-since moved an item"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
