#!/usr/bin/env bash
# Real test of `skarbiec bindings check <file> [--refuse]`, through the built
# binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# A bindings file names a live note's value, a note then trashed, an id no
# item has and a field the note does not hold. The check marks only the
# first as giving a value and names the problem of each other line, never a
# value; with --refuse it fails naming the failing variables; once every line
# names a live field it passes, also with --refuse.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/packages/bindings_check.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/packages/$RUN"
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
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$1-value" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}
row() {
  printf '%s' "$out" | jq -c --arg v "$1" '.bindings[] | select(.variable == $v)'
}

: >"$ROOT/stdin"
WANT=ok run init "bindings-owner-$RUN"
LIVE="live-$RUN"
GONE="gone-$RUN"
note "$LIVE"
note "$GONE"
WANT=ok run delete "$GONE"
BINDINGS="$ROOT/bindings"
cat >"$BINDINGS" <<EOF
# committed beside the project
GOOD=$LIVE:value
TRASHED=$GONE:value
MISSING=nobody-$RUN:value
WRONG=$LIVE:password
EOF

WANT=ok run bindings check "$BINDINGS"
[ "$(printf '%s' "$out" | jq -r .ok)" = false ] || fail "a file with failing lines was answered ok"
[ "$(row GOOD | jq -r .ok)" = true ] || fail "the live note's value was not marked as giving a value: $out"
row TRASHED | jq -e '.ok == false and (.problem | contains("in the trash"))' >/dev/null || fail "the trashed note was not named as in the trash: $out"
row MISSING | jq -e '.ok == false and (.problem | contains("no item"))' >/dev/null || fail "the missing id was not named: $out"
row WRONG | jq -e '.ok == false and (.problem | contains("no text field password"))' >/dev/null || fail "the missing field was not named: $out"
# A value must appear on neither stream.
case "$out$said" in *"$LIVE-value"*|*"$GONE-value"*) fail "the check printed a value" ;; esac
grep -q '"bindings-checked"' "$SKARBIEC_AUDIT_FILE" || fail "no bindings-checked journal entry was appended"
echo "ok: each line is marked, the failing ones with their problem, and no value is printed" >>"$REPORT"

WANT=refused run bindings check "$BINDINGS" --refuse
for variable in TRASHED MISSING WRONG; do
  case "$said" in *"$variable"*) ;; *) fail "--refuse did not name $variable: $said" ;; esac
done
echo "ok: --refuse fails naming every failing variable" >>"$REPORT"

printf 'GOOD=%s:value\n' "$LIVE" >"$BINDINGS"
WANT=ok run bindings check "$BINDINGS" --refuse
[ "$(printf '%s' "$out" | jq -r .ok)" = true ] || fail "a file whose every line gives a value was not answered ok: $out"
echo "ok: a file whose every line gives a value passes, also with --refuse" >>"$REPORT"

WANT=refused run bindings check
case "$said" in *"usage: bindings check"*) ;; *) fail "check without a file was not refused with the usage: $said" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
