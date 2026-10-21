#!/usr/bin/env bash
# Real test of `skarbiec audit verify` fault lines through the built binary on
# a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# point into this checkout's target directory, so the operator's vault,
# journal and keyring are never read or written.
#
# It creates the vault and writes one item, so the journal holds entries,
# then appends a blank line, a line that is not JSON and a copy of the last
# entry whose hash is changed. audit verify must name, for the malformed line
# and for both the linkage and digest faults of the changed entry, the line
# each one has in the journal file, as grep -n counts it. Every command,
# whether it succeeded and its output go to the run's report.txt; no item
# value is written there.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run
# tests/audit/line_numbers.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/audit-line-numbers/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/stderr"); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  printf '$ skarbiec %s\nexit: %s\nresult: %s\nstdout: %s\nstderr: %s\n\n' "$*" "$status" "$got" "$out" "$(cat "$ROOT/stderr")" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT"
}
# The line a text has in the journal, as grep -n counts it.
line_of() {
  grep -n -F -x -- "$1" "$SKARBIEC_AUDIT_FILE" | cut -d: -f1
}
# The line audit verify names for one fault of one kind at one time.
fault_line() {
  printf '%s' "$out" | jq -r --arg fault "$1" --arg at "$2" \
    '[.faults[] | select(.fault == $fault and (.at // "") == $at) | .line] | first // "none"'
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

: >"$ROOT/stdin"
WANT=ok run init "audit-lines-owner-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"audit-lines-%s","password":"audit-lines-%s"},"context":{}}' "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set-json "audit-lines-item-$RUN" --type login
: >"$ROOT/stdin"
[ -s "$SKARBIEC_AUDIT_FILE" ] || fail "writing an item left no journal entry"

last=$(sed -n '$p' "$SKARBIEC_AUDIT_FILE")
changed=$(printf '%s' "$last" | jq -c --arg run "$RUN" '.hash = ("changed-" + $run)')
at=$(printf '%s' "$changed" | jq -r '.at')
malformed="not an entry $RUN"
printf '\n%s\n%s\n' "$malformed" "$changed" >>"$SKARBIEC_AUDIT_FILE"
malformed_line=$(line_of "$malformed")
changed_line=$(line_of "$changed")
echo "journal: malformed line $malformed_line, changed entry line $changed_line" >>"$REPORT"

WANT=ok run audit verify
printf '%s' "$out" | jq -e '.intact == false' >/dev/null || fail "a damaged journal was reported intact"
[ "$(printf '%s' "$out" | jq -r '[.faults[] | select(.fault == "malformed") | .line] | first')" = "$malformed_line" ] \
  || fail "the malformed fault does not name line $malformed_line"
[ "$(fault_line linkage "$at")" = "$changed_line" ] \
  || fail "the linkage fault does not name line $changed_line"
[ "$(fault_line digest "$at")" = "$changed_line" ] \
  || fail "the digest fault does not name line $changed_line"
echo "ok: every fault names the line it has in the journal file" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
