#!/usr/bin/env bash
# Real test of `skarbiec audit summary`, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault, journal and
# keyring are never read or written.
#
# Two items are written and one is read back, so the journal holds entries
# naming each. The summary over a span from long ago must count as many
# entries as audit list returns over that span, and give every operation and
# every item the count audit list's own entries give it; a span that starts
# ahead counts none. A missing --since and a time of another shape are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/audit/summary.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: output: $out stderr: $said" ;;
  esac
}
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s-value"},"context":{}}' "$1" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "summary-owner-$RUN"
FIRST="summary-first-$RUN"
SECOND="summary-second-$RUN"
note "$FIRST"
note "$SECOND"
WANT=ok run get "$FIRST" --field value

PAST="2000-01-01T00:00:00Z"
WANT=ok run audit list --since "$PAST"
printf '%s' "$out" >"$ROOT/list.json"
WANT=ok run audit summary --since "$PAST"
printf '%s' "$out" >"$ROOT/summary.json"

[ "$(jq .entries "$ROOT/summary.json")" = "$(jq '.entries | length' "$ROOT/list.json")" ] \
  || fail "the summary counts another number of entries than audit list returns"
for op in $(jq -r '.entries[].op' "$ROOT/list.json" | sort -u); do
  listed=$(jq --arg op "$op" '[.entries[] | select(.op == $op)] | length' "$ROOT/list.json")
  counted=$(jq --arg op "$op" '.operations[] | select(.op == $op) | .count' "$ROOT/summary.json")
  [ "$listed" = "$counted" ] || fail "operation $op: audit list has $listed entries, the summary counts $counted"
done
for item in "$FIRST" "$SECOND"; do
  listed=$(jq --arg id "$item" '[.entries[] | select(.extra.item == $id or ((.extra.items // []) | index($id) != null))] | length' "$ROOT/list.json")
  counted=$(jq --arg id "$item" '.items[] | select(.item == $id) | .count' "$ROOT/summary.json")
  [ "$listed" = "$counted" ] || fail "item $item: audit list names it $listed times, the summary counts $counted"
done
echo "ok: the summary's counts are the counts of audit list's own entries" >>"$REPORT"

WANT=ok run audit summary --since "2999-01-01T00:00:00Z"
[ "$(printf '%s' "$out" | jq .entries)" = "$(printf '%s' '[]' | jq length)" ] || fail "a span that starts ahead counted entries"
echo "ok: a span that starts ahead counts none" >>"$REPORT"

WANT=refused run audit summary
names "usage: audit summary"
WANT=refused run audit summary --since yesterday
names "--since yesterday is not a UTC time"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
