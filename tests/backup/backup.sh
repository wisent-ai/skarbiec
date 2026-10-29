#!/usr/bin/env bash
# Real test of keeping, checking and restoring copies of the vault, `skarbiec
# backup <directory>`, `backup check <file> [--open]` and `backup restore
# <file> [--yes]`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# Two notes, one trashed. backup writes an owner-only copy holding one live
# and one trashed item; check --open opens the live one; the copy, used as
# SKARBIEC_VAULT_FILE, reads the note back. A file that is not a vault, a
# relative directory and a directory that does not exist are refused naming
# why, and no copy is written for them. After a later note, restore without
# --yes names that note as lost and changes nothing; with --yes the copy takes
# the vault's place and the note is gone, and restoring the vault kept aside
# brings it back.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/backup/backup.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/backup/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
COPIES="$ROOT/copies"
mkdir -p "$ROOT" "$KEYRING" "$COPIES"
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
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "backup-owner-$RUN"
KEPT="backup-kept-$RUN"
GONE="backup-gone-$RUN"
note "$KEPT" "kept-value-$RUN"
note "$GONE" "gone-value-$RUN"
WANT=ok run delete "$GONE"

WANT=ok run backup "$COPIES"
COPY="$(printf '%s' "$out" | jq -r .backup)"
[ -f "$COPY" ] || fail "backup named a copy that is not there: $COPY"
[ "$(stat -f '%Lp' "$COPY")" = "600" ] || fail "the copy is not owner-only: $(stat -f '%Lp' "$COPY")"
[ "$(printf '%s' "$out" | jq -c '[.holds.live_items, .holds.trashed_items]')" = "[1,1]" ] \
  || fail "backup did not count one live and one trashed item"
cmp -s "$COPY" "$SKARBIEC_VAULT_FILE" || fail "the copy is not the vault file byte for byte"
echo "ok: backup writes an owner-only, byte-identical copy and counts what it holds" >>"$REPORT"

WANT=ok run backup check "$COPY" --open
[ "$(printf '%s' "$out" | jq -c '[.ok, .holds.opened, (.holds.unreadable | length)]')" = "[true,true,0]" ] \
  || fail "check --open did not open every live item in the copy"
if out=$(SKARBIEC_VAULT_FILE="$COPY" "$BIN" get "$KEPT" --field value </dev/null 2>"$ROOT/said"); then
  said=$(cat "$ROOT/said")
  case "$out" in *"kept-value-$RUN"*) ;; *) fail "the copy did not read the note back: output: $out stderr: $said" ;; esac
else
  said=$(cat "$ROOT/said")
  fail "the copy did not open as a vault: output: $out stderr: $said"
fi
echo "ok: check --open opens the copy, and the copy restores the note" >>"$REPORT"

printf 'not a vault\n' >"$ROOT/not-a-vault.json"
WANT=refused run backup check "$ROOT/not-a-vault.json"
names "does not read as a Skarbiec vault"
WANT=refused run backup "relative-$RUN"
names "backup takes an absolute directory"
WANT=refused run backup "$ROOT/missing-$RUN"
names "is not a directory here; nothing was copied"
[ "$(find "$COPIES" -type f | wc -l | tr -d ' ')" = "$(printf '%s\n' "$COPY" | wc -l | tr -d ' ')" ] \
  || fail "a refused backup wrote a copy"

LATER="backup-later-$RUN"
note "$LATER" "later-value-$RUN"
WANT=ok run backup restore "$COPY"
[ "$(printf '%s' "$out" | jq -c .would_lose)" = "[\"$LATER\"]" ] || fail "restore without --yes did not name the item the copy lacks"
WANT=ok run get "$LATER" --field value
echo "ok: restore without --yes names what would be lost and changes nothing" >>"$REPORT"
WANT=ok run backup restore "$COPY" --yes
ASIDE="$(printf '%s' "$out" | jq -r .kept_aside)"
[ -f "$ASIDE" ] || fail "restore --yes did not keep the replaced vault aside"
cmp -s "$COPY" "$SKARBIEC_VAULT_FILE" || fail "restore --yes did not put the copy in place"
WANT=refused run get "$LATER" --field value
WANT=ok run backup restore "$ASIDE" --yes
WANT=ok run get "$LATER" --field value
case "$out" in *"later-value-$RUN"*) ;; *) fail "restoring the file kept aside did not bring the later item back: $out" ;; esac
echo "ok: restore --yes puts the copy in place, and restoring the file kept aside undoes it" >>"$REPORT"
WANT=refused run backup restore "$ROOT/not-a-vault.json" --yes
names "nothing was restored"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
