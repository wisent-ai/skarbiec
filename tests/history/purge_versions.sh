#!/usr/bin/env bash
# Real test of removing an item's old saved versions for good, `skarbiec
# purge <id> --versions-before <iso8601> [--yes]`, through the built binary
# on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# One note is written three times. Without --yes the saved version older
# than a moment between the first and second write is listed and history
# still holds it; with --yes only that version goes, history keeps the later
# one and the current value, and the current value still reads back. A
# second run forgets nothing; --all lists the item's remaining saved versions
# and with --yes removes them, keeping the current value; and a moment of
# another shape, a missing id, an id beside --all and an unknown item are
# refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/history/purge_versions.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/history/$RUN"
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
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out; stderr: $said" ;;
  esac
}
write_note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}
saved() {
  WANT=ok run history "$NOTE"
  printf '%s' "$out" | jq -c '[.versions[] | select(.current | not) | .at]'
}
current_at() {
  WANT=ok run history "$NOTE"
  printf '%s' "$out" | jq -r '.versions[] | select(.current) | .at'
}

: >"$ROOT/stdin"
WANT=ok run init "versions-owner-$RUN"
NOTE="versions-note-$RUN"
write_note "$NOTE" "first-$RUN"
# The stamps are the vault's own clock: BETWEEN falls after the first write
# and before the second, so the second saved version is younger than it.
FIRST="$(current_at)"
until [ "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \> "$FIRST" ]; do :; done
BETWEEN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
until [ "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \> "$BETWEEN" ]; do :; done
write_note "$NOTE" "second-$RUN"
write_note "$NOTE" "third-$RUN"

BEFORE="$(saved)"
OLDER="$(printf '%s' "$BEFORE" | jq -c '[.[] | select(. < "'"$BETWEEN"'")]')"
WANT=ok run purge "$NOTE" --versions-before "$BETWEEN"
[ "$(printf '%s' "$out" | jq -c .would_forget)" = "$OLDER" ] || fail "without --yes it did not list exactly the older saved versions"
[ "$(saved)" = "$BEFORE" ] || fail "without --yes a saved version went"
echo "ok: without --yes the older versions are listed and kept" >>"$REPORT"

WANT=ok run purge "$NOTE" --versions-before "$BETWEEN" --yes
[ "$(printf '%s' "$out" | jq -c .forgotten)" = "$OLDER" ] || fail "--yes did not name the versions it removed"
printf '%s' "$(saved)" | jq -e --arg cut "$BETWEEN" 'all(.[]; . >= $cut) and (length > ([] | length))' >/dev/null \
  || fail "--yes left an older version, or took the later one too"
WANT=ok run get "$NOTE" --field value
case "$out" in *"third-$RUN"*) ;; *) fail "the current value no longer reads back: $out; stderr: $said" ;; esac
echo "ok: --yes removes only the older versions and the current value stays" >>"$REPORT"

WANT=ok run purge "$NOTE" --versions-before "$BETWEEN" --yes
[ "$(printf '%s' "$out" | jq -c .forgotten)" = "[]" ] || fail "a second run claimed to remove a version"

LATEST="9999-01-01T00:00:00Z"
REMAINING="$(saved)"
WANT=ok run purge --all --versions-before "$LATEST"
[ "$(printf '%s' "$out" | jq -c --arg id "$NOTE" '.would_forget[$id]')" = "$REMAINING" ] \
  || fail "--all without --yes did not list the item's remaining saved versions"
[ "$(saved)" = "$REMAINING" ] || fail "--all without --yes removed a version"
WANT=ok run purge --all --versions-before "$LATEST" --yes
[ "$(saved)" = "[]" ] || fail "--all --yes left a saved version older than the moment"
WANT=ok run get "$NOTE" --field value
case "$out" in *"third-$RUN"*) ;; *) fail "--all took the current value: $out; stderr: $said" ;; esac
echo "ok: --all lists every item's older versions first and --yes removes them, keeping current values" >>"$REPORT"
WANT=refused run purge "$NOTE" --all --versions-before "$LATEST"
names "usage: purge <id> --versions-before"

WANT=refused run purge "$NOTE" --versions-before yesterday
names "--versions-before yesterday is not a UTC time"
WANT=refused run purge --versions-before "$BETWEEN"
names "usage: purge <id> --versions-before"
WANT=refused run purge "missing-$RUN" --versions-before "$BETWEEN"
names "missing-$RUN"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
