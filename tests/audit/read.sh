#!/usr/bin/env bash
# Real test of `skarbiec audit`, the one journal read, through the built
# binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault, journal and keyring are never read or written.
#
# It creates the vault and writes one item, so the journal holds entries, then
# reads the whole journal, its newest entry alone (the tail path, which still
# counts every entry as matched), the entries of one operation (the filtered
# path), and refuses a zero limit; the retired audit-query is no command.
# Every command, whether it succeeded and its output go to the run's
# report.txt; no item value is written there.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/audit/read.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/audit/$RUN"
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
  if out=$(set -o pipefail; "$BIN" "$@" <"$ROOT/stdin" |& cat); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT"
}
field() {
  echo "$out" | jq -e -r "$@"
}

: >"$ROOT/stdin"
WANT=ok run init "audit-test-owner-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"audit-test-user-%s","password":"audit-test-%s"},"context":{}}' "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set-json "audit-test-login-$RUN" --type login
: >"$ROOT/stdin"

WANT=ok run audit
field '.entries | first | has("op")' >/dev/null || fail "the journal of a vault that was just written holds no entry"
total=$(field '.matched')
[ "$(field '.returned')" = "$total" ] || fail "an unlimited read returned fewer entries than it matched"
[ "$(field '.entries | length')" = "$total" ] || fail "entries and matched disagree"
echo "ok: the whole journal, $total entries" >>"$REPORT"

newest=$(printf 'x' | wc -c | tr -d ' ')
WANT=ok run audit --limit "$newest"
[ "$(field '.matched')" = "$total" ] || fail "the tail read did not count every entry as matched"
[ "$(field '.returned')" = "$newest" ] || fail "the tail read returned other than the newest entry"
echo "ok: --limit without a filter reads the tail and counts every entry" >>"$REPORT"

operation=$(field '.entries | last | .op')
WANT=ok run audit --op "$operation"
field --arg op "$operation" '.entries | all(.op == $op)' >/dev/null || fail "--op returned an entry of another operation"
echo "ok: --op $operation returns only that operation" >>"$REPORT"

zero=$(printf '' | wc -c | tr -d ' ')
WANT=refused run audit --limit "$zero"
case "$out" in
  *"--limit must be at least one"*) echo "ok: a zero limit is refused" >>"$REPORT" ;;
  *) fail "a zero limit was not refused by name" ;;
esac
WANT=refused run audit-query

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
