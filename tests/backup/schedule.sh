#!/usr/bin/env bash
# Real test of the rolling backup, `skarbiec backup schedule <directory>`,
# `backup unschedule` and the step `skarbiec maintain` runs for it, through the
# built binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE
# and GNUPGHOME point into this checkout's target directory, so the
# operator's vault and keyring are never read or written.
#
# schedule names the rolling copy; a maintain pass writes it byte for byte
# owner-only, a second pass with no change leaves it untouched, a write to the
# vault makes the next pass refresh it, and a directory that went away makes
# the pass fail naming it. unschedule stops it, and a second unschedule says
# nothing was scheduled. maintain's other steps may fail on a machine without
# the fleet's services; only the backup step's own outcome is judged, from
# its answer or its named failure.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/backup/schedule.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/backup/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
DISK="$ROOT/disk"
mkdir -p "$ROOT" "$KEYRING" "$DISK"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
maintain() {
  if out=$("$BIN" maintain </dev/null &>/dev/stdout); then got=ok; else got=failed; fi
  printf '$ skarbiec maintain\nresult: %s\noutput: %s\n\n' "$got" "$out" >>"$REPORT"
}
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "schedule-owner-$RUN"
note "schedule-first-$RUN" "first-$RUN"

WANT=ok run backup schedule "$DISK"
COPY="$(printf '%s' "$out" | jq -r .copy)"
WANT=ok run backup schedule
[ "$(printf '%s' "$out" | jq -r .copy)" = "$COPY" ] || fail "backup schedule alone did not name the rolling copy"
echo "ok: schedule names the rolling copy, and schedule alone reads it back" >>"$REPORT"

maintain
case "$out" in *"scheduled backup:"*) fail "the backup step failed: $out" ;; esac
cmp -s "$COPY" "$SKARBIEC_VAULT_FILE" || fail "maintain did not write the vault byte for byte to $COPY"
[ "$(stat -f '%Lp' "$COPY")" = "600" ] || fail "the rolling copy is not owner-only"
FIRST_INODE="$(stat -f '%i' "$COPY")"
maintain
[ "$(stat -f '%i' "$COPY")" = "$FIRST_INODE" ] || fail "a pass with no change replaced the rolling copy"
echo "ok: maintain writes the rolling copy and leaves it alone while nothing changed" >>"$REPORT"

note "schedule-second-$RUN" "second-$RUN"
maintain
cmp -s "$COPY" "$SKARBIEC_VAULT_FILE" || fail "maintain did not refresh the rolling copy after a write"
echo "ok: a write to the vault makes the next pass refresh the copy" >>"$REPORT"

mv "$DISK" "$ROOT/unplugged"
maintain
case "$out" in
  *"scheduled backup:"*"$DISK"*) echo "ok: a pass whose directory is gone fails naming it" >>"$REPORT" ;;
  *) fail "a pass whose directory is gone did not fail naming it: $out" ;;
esac
mv "$ROOT/unplugged" "$DISK"

WANT=ok run backup unschedule
[ "$(printf '%s' "$out" | jq -r .unscheduled)" = true ] || fail "unschedule did not say it stopped the schedule"
WANT=ok run backup unschedule
[ "$(printf '%s' "$out" | jq -r .unscheduled)" = false ] || fail "a second unschedule claimed to stop something"
WANT=refused run backup schedule "relative-$RUN"
case "$out" in *"absolute directory"*) ;; *) fail "a relative directory was not refused naming why: $out" ;; esac
echo "ok: unschedule stops it once, and a relative directory is refused" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
