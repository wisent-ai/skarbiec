#!/usr/bin/env bash
# Real test of `skarbiec audit list|verify|epoch`, the journal group, through
# the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault, journal and keyring are never read or
# written.
#
# It creates the vault and writes one item, so the journal holds entries, then
# lists the whole journal, its newest entry alone (the tail path, which still
# counts every entry as matched), the entries of one operation (the filtered
# path), and refuses a zero limit; verifies the chain and finds it unbroken;
# refuses the group without a subcommand, an unknown subcommand, an epoch
# without --reason, and the retired spellings audit-query, verify-chain and
# audit-epoch-start. Every command, whether it succeeded and its output go to
# the run's report.txt; no item value is written there.
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
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

WANT=ok run audit list
field '.entries | first | has("op")' >/dev/null || fail "the journal of a vault that was just written holds no entry"
total=$(field '.matched')
[ "$(field '.returned')" = "$total" ] || fail "an unlimited read returned fewer entries than it matched"
[ "$(field '.entries | length')" = "$total" ] || fail "entries and matched disagree"
echo "ok: the whole journal, $total entries" >>"$REPORT"

newest=$(printf 'x' | wc -c | tr -d ' ')
WANT=ok run audit list --limit "$newest"
[ "$(field '.matched')" = "$total" ] || fail "the tail read did not count every entry as matched"
[ "$(field '.returned')" = "$newest" ] || fail "the tail read returned other than the newest entry"
echo "ok: --limit without a filter reads the tail and counts every entry" >>"$REPORT"

operation=$(field '.entries | last | .op')
WANT=ok run audit list --op "$operation"
field --arg op "$operation" '.entries | all(.op == $op)' >/dev/null || fail "--op returned an entry of another operation"
echo "ok: --op $operation returns only that operation" >>"$REPORT"

zero=$(printf '' | wc -c | tr -d ' ')
WANT=refused run audit list --limit "$zero"
case "$out" in
  *"--limit must be at least one"*) echo "ok: a zero limit is refused" >>"$REPORT" ;;
  *) fail "a zero limit was not refused by name" ;;
esac

WANT=ok run audit verify
[ "$(field '.intact')" = "true" ] || fail "a journal only this run wrote is reported broken"
echo "ok: audit verify finds the chain unbroken" >>"$REPORT"

WANT=refused run audit
case "$out" in
  *"audit needs a subcommand"*) echo "ok: the group without a subcommand is refused" >>"$REPORT" ;;
  *) fail "audit without a subcommand was not refused by name" ;;
esac
WANT=refused run audit sideways
case "$out" in
  *"unknown audit command: sideways"*) echo "ok: an unknown subcommand is refused" >>"$REPORT" ;;
  *) fail "an unknown audit subcommand was not refused by name" ;;
esac
WANT=refused run audit epoch
WANT=refused run audit epoch --reason "audit-test-$RUN"
case "$out" in
  *"audit journal is intact"*) echo "ok: an epoch over an intact chain is refused" >>"$REPORT" ;;
  *) fail "an epoch over an intact chain was not refused by name" ;;
esac
WANT=refused run audit-query
WANT=refused run verify-chain
WANT=refused run audit-epoch-start

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
