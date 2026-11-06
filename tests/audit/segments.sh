#!/usr/bin/env bash
# Real test of the audit journal's segments through the built binary, on a
# vault of its own under this checkout's target directory (HOME isolated, so
# the operator's vault, journal and keys are never read or written).
#
# The journal starts as one a release before segments wrote: three chained
# entries from the previous UTC day, in one file. The binary under test must:
#   - at its first append of the day close that file as
#     <journal>.d/000000.jsonl in place: the same inode and the same bytes,
#     made read-only, never copied or rewritten;
#   - open the new file with an audit-segment-closed line whose prev is the
#     closed segment's last hash and which names the segment, its bytes and
#     that hash, so audit verify walks both segments intact;
#   - close the open file on `audit rotate` as 000001.jsonl, and say there is
#     nothing to close when the open file holds no entry;
#   - answer audit list across segments (the newest N, and a filter), and
#     doctor's audit check through every closed segment;
#   - finish a close that stopped after its rename, at the next append;
#   - report a closed segment that was extended, or emptied, as a segment
#     fault naming it; refuse to read a journal with a numbered segment
#     missing, or with a file in the directory that is not a segment, naming
#     the file and the fix.
# Every command, its exit and its output go to the run's report.txt.
#
# Usage: SKARBIEC=<binary under test> tests/audit/segments.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test}
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/audit-segments/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT/home" "$ROOT/kept"
chmod go-rwx "$ROOT"
# A checkout states its revision; a delivered copy states it with
# SKARBIEC_TEST_SOURCE_REVISION.
echo "revision: ${SKARBIEC_TEST_SOURCE_REVISION:-$(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')}" >"$REPORT"
echo "binary: $BIN; sha256: $(openssl dgst -sha256 -r "$BIN" | cut -d' ' -f1)" >>"$REPORT"
export HOME="$ROOT/home"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
JOURNAL="$SKARBIEC_AUDIT_FILE"
SEGMENTS="$JOURNAL.d"

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nexit: %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$status" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"segments-%s","password":"segments-%s"},"context":{}}' "$1" "$RUN" >"$ROOT/stdin"
}
sha() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
inode() { ls -di "$1" | awk '{print $1}'; }
mode() { ls -ld "$1" | cut -c1-10; }
# One journal line chained onto $1, as a release before segments wrote it:
# the hash covers prev|at|op|extra, extra in its compact form.
entry() {
  local prev=$1 at=$2 op=$3 extra=$4 hash
  hash=$(printf '%s|%s|%s|%s' "$prev" "$at" "$op" "$extra" | openssl dgst -sha256 -r | cut -d' ' -f1)
  jq -cn --arg at "$at" --arg op "$op" --argjson extra "$extra" --arg prev "$prev" --arg hash "$hash" \
    '{at: $at, op: $op, extra: $extra, prev: $prev, hash: $hash}'
}
verify_field() { printf '%s' "$out" | jq -r "$1"; }

: >"$ROOT/stdin"
WANT=ok run init "segments-owner-$RUN"
login first
WANT=ok run set "segments-first-$RUN" --type login
: >"$ROOT/stdin"

# The journal a release before segments left: the previous UTC day, one file.
YESTERDAY=$(date -u -v-1d +%Y-%m-%d 2>/dev/null || date -u -d yesterday +%Y-%m-%d)
rm "$JOURNAL"
prev=""
for n in 1 2 3; do
  line=$(entry "$prev" "${YESTERDAY}T0${n}:00:00Z" "legacy-$n" "{\"n\":$n}")
  printf '%s\n' "$line" >>"$JOURNAL"
  prev=$(printf '%s' "$line" | jq -r .hash)
done
LEGACY_LAST=$prev
LEGACY_SHA=$(sha "$JOURNAL")
LEGACY_INODE=$(inode "$JOURNAL")
LEGACY_BYTES=$(awk '{ n += length($0) + 1 } END { print n }' "$JOURNAL")
echo "legacy journal: 3 entries of $YESTERDAY, $LEGACY_BYTES bytes, inode $LEGACY_INODE, sha256 $LEGACY_SHA" >>"$REPORT"
WANT=ok run audit verify
[ "$(verify_field .intact)/$(verify_field .segments)/$(verify_field .entries)" = "true/0/3" ] \
  || fail "the legacy journal did not verify as one intact segment of 3 entries"

# The first append of the day closes it in place.
login second
WANT=ok run set "segments-second-$RUN" --type login
: >"$ROOT/stdin"
[ -f "$SEGMENTS/000000.jsonl" ] || fail "the first append of a new day left no $SEGMENTS/000000.jsonl"
[ "$(inode "$SEGMENTS/000000.jsonl")" = "$LEGACY_INODE" ] || fail "000000.jsonl is a copy, not the legacy file moved in place"
[ "$(sha "$SEGMENTS/000000.jsonl")" = "$LEGACY_SHA" ] || fail "000000.jsonl's bytes differ from the legacy journal's"
[ "$(mode "$SEGMENTS/000000.jsonl")" = "-r--------" ] || fail "000000.jsonl is $(mode "$SEGMENTS/000000.jsonl"), not read-only for the owner"
[ "$(mode "$SEGMENTS")" = "drwx------" ] || fail "$SEGMENTS is $(mode "$SEGMENTS"), not owner-only"
first=$(sed -n 1p "$JOURNAL")
echo "open file's first line: $first" >>"$REPORT"
printf '%s' "$first" | jq -e --arg last "$LEGACY_LAST" --argjson bytes "$LEGACY_BYTES" \
  '.op == "audit-segment-closed" and .prev == $last and .extra.segment == "000000.jsonl"
   and .extra.bytes == $bytes and .extra.last_hash == $last' >/dev/null \
  || fail "the open file does not begin with the line closing 000000.jsonl onto its last hash"
WANT=ok run audit verify
[ "$(verify_field .intact)/$(verify_field .segments)" = "true/1" ] || fail "the journal did not verify intact through one closed segment"
echo "ok: the legacy journal became 000000.jsonl in place and the chain runs across it" >>"$REPORT"

# audit rotate closes now; an open file that holds only the line closing the
# segment before it has nothing to close.
WANT=ok run audit rotate
[ "$(verify_field .rotated)/$(verify_field .closed.segment)" = "true/000001.jsonl" ] || fail "audit rotate did not close 000001.jsonl"
[ "$(mode "$SEGMENTS/000001.jsonl")" = "-r--------" ] || fail "000001.jsonl is not read-only for the owner"
[ "$(awk 'END { print NR }' "$JOURNAL")" = "1" ] || fail "the open file after audit rotate holds more than the line closing 000001.jsonl"
WANT=ok run audit rotate
[ "$(verify_field .rotated)" = "false" ] || fail "audit rotate closed an open file holding only the line closing 000001.jsonl"
printf '%s' "$out" | jq -e '.reason | test("no entry beyond the line that closed 000001.jsonl")' >/dev/null \
  || fail "audit rotate did not say why there was nothing to close"
echo "ok: audit rotate closes the open file and says when there is nothing to close" >>"$REPORT"

# A close that stopped after its rename, before its line was written: the
# open file is gone and the newest closed segment holds the last entry. The
# next append writes the closing line first.
rm "$JOURNAL"
login third
WANT=ok run set "segments-third-$RUN" --type login
: >"$ROOT/stdin"
sed -n 1p "$JOURNAL" | jq -e '.op == "audit-segment-closed" and .extra.segment == "000001.jsonl" and (.extra.why | test("stopped"))' >/dev/null \
  || fail "the append after an interrupted close did not first write the line closing 000001.jsonl"
WANT=ok run audit verify
[ "$(verify_field .intact)/$(verify_field .segments)" = "true/2" ] || fail "the journal did not verify intact through two closed segments: $out"
TOTAL=$(verify_field .entries)
echo "ok: an interrupted close is finished by the next append" >>"$REPORT"

# Reading across segments.
WANT=ok run audit list --limit 6
[ "$(verify_field .matched)/$(verify_field .returned)" = "$TOTAL/6" ] || fail "audit list --limit 6 did not count all $TOTAL entries and return 6"
WANT=ok run audit list --op audit-segment-closed
[ "$(verify_field .matched)" = "2" ] || fail "audit list --op audit-segment-closed did not find both closing lines"
WANT=ok run audit list --op legacy-2
[ "$(verify_field '.entries[0].extra.n')" = "2" ] || fail "audit list did not read an entry of the closed segment 000000.jsonl"
WANT=ok run doctor
printf '%s' "$out" | jq -e '.checks[] | select(.check == "audit") | .status == "pass" and (.detail | test("through 2 closed segment"))' >/dev/null \
  || fail "doctor's audit check did not pass through both closed segments"
echo "ok: audit list and doctor read every segment" >>"$REPORT"

# A closed segment extended after it closed.
chmod u+w "$SEGMENTS/000000.jsonl"
printf '%s\n' "$(entry "$LEGACY_LAST" "${YESTERDAY}T09:00:00Z" "added-later" '{"n":9}')" >>"$SEGMENTS/000000.jsonl"
WANT=ok run audit verify
printf '%s' "$out" | jq -e '.intact == false and any(.faults[]; .fault == "segment" and .segment == "000001.jsonl" and (.detail | test("bytes")))' >/dev/null \
  || fail "an extended 000000.jsonl was not reported as a segment fault against the line closing it"
WANT=ok run doctor
printf '%s' "$out" | jq -e '.checks[] | select(.check == "audit") | .status == "fail" and (.detail | test("segment"))' >/dev/null \
  || fail "doctor's audit check did not fail naming the segment fault"
# Back to the bytes it closed with.
head -n 3 "$SEGMENTS/000000.jsonl" >"$ROOT/kept/000000.jsonl"
cat "$ROOT/kept/000000.jsonl" >"$SEGMENTS/000000.jsonl"
chmod 400 "$SEGMENTS/000000.jsonl"
WANT=ok run audit verify
[ "$(verify_field .intact)" = "true" ] || fail "000000.jsonl restored to its closed bytes does not verify intact: $out"

# A closed segment emptied.
chmod u+w "$SEGMENTS/000001.jsonl"
cp "$SEGMENTS/000001.jsonl" "$ROOT/kept/000001.jsonl"
: >"$SEGMENTS/000001.jsonl"
WANT=ok run audit verify
printf '%s' "$out" | jq -e 'any(.faults[]; .fault == "segment" and .segment == "000001.jsonl" and (.detail | test("holds no entry")))' >/dev/null \
  || fail "an emptied 000001.jsonl was not reported as a segment fault naming it"
cat "$ROOT/kept/000001.jsonl" >"$SEGMENTS/000001.jsonl"
chmod 400 "$SEGMENTS/000001.jsonl"
echo "ok: an extended or emptied closed segment is a segment fault naming it" >>"$REPORT"

# A numbered segment missing: refused naming it.
mv "$SEGMENTS/000000.jsonl" "$ROOT/kept/moved.jsonl"
WANT=refused run audit verify
printf '%s' "$said" | grep -q "000000.jsonl is missing" || fail "a missing 000000.jsonl was not named"
printf '%s' "$said" | grep -q "restore it" || fail "the missing-segment refusal does not say how to fix it"
# Appending reads no closed segment, so writes go on while one is away.
login away
WANT=ok run set "segments-away-$RUN" --type login
: >"$ROOT/stdin"
mv "$ROOT/kept/moved.jsonl" "$SEGMENTS/000000.jsonl"
# A file in the directory that is not a segment: refused naming it.
printf 'notes\n' >"$SEGMENTS/notes.txt"
WANT=refused run audit list --op legacy-1
printf '%s' "$said" | grep -q "notes.txt, which is not a closed audit segment" || fail "a stray file in $SEGMENTS was not named"
printf '%s' "$said" | grep -q "move that file out" || fail "the stray-file refusal does not say how to fix it"
rm "$SEGMENTS/notes.txt"
WANT=ok run audit verify
[ "$(verify_field .intact)/$(verify_field .segments)" = "true/2" ] || fail "the journal is not intact once every segment is back: $out"
echo "ok: a missing segment or a stray file is refused naming it and the fix" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
