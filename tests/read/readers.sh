#!/usr/bin/env bash
# Real test of `skarbiec readers <id>`, which says who can open one item on
# this host without decrypting it, through the built binary on a vault of its
# own (SKARBIEC_VAULT_FILE and SKARBIEC_AUDIT_FILE under this checkout's target
# directory; the key file sits beside that vault, so the operator's vault and
# keys are never touched).
#
# It creates the vault, writes one login item and asks who can open it: the
# item names at least one key, every key named has its secret half here, and
# openable_here is true. It then removes the vault's key file, which is what a
# vault host that lost its keys looks like: readers still answers, now with
# no secret half here and openable_here false, and a read of the item is
# refused naming the key file. A missing item is refused naming its id. Every
# command and its result go to the run's report.txt.
#
# Usage: SKARBIEC=<built skarbiec binary> tests/read/readers.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?SKARBIEC must name the built skarbiec binary this journey runs}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/read/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT"
chmod go-rwx "$ROOT"
if git diff --quiet; then STATE=clean; else STATE=dirty; fi
echo "revision: $(git rev-parse HEAD) ($STATE)" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
KEYS="$ROOT/vault.keys.json"

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# Runs one command with $ROOT/stdin on its standard input, standard output in
# $out and standard error in $said; WANT says whether it had to succeed (ok) or
# be refused (refused).
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
field() {
  printf '%s' "$out" | jq -e "$1" >/dev/null || fail "readers answer does not satisfy $1: $out"
  echo "ok: $1" >>"$REPORT"
}

: >"$ROOT/stdin"
WANT=ok run init "readers-test-owner-$RUN"
ITEM="readers-test-login-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"readers-test-user-%s","password":"readers-test-secret-%s"},"context":{}}' \
  "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"

WANT=ok run readers "$ITEM"
field '.encrypted_to | length > 0'
field '[.encrypted_to[].secret_key_here] | all'
field '.openable_here == true'

[ -f "$KEYS" ] || fail "the vault's key file is not at $KEYS"
rm "$KEYS"
echo "removed the vault's key file $KEYS" >>"$REPORT"

WANT=ok run readers "$ITEM"
field '.encrypted_to | length > 0'
field '[.encrypted_to[].secret_key_here] | any | not'
field '.openable_here == false'
WANT=refused run get "$ITEM" --field password
case "$said" in
  *"$KEYS"*) echo "ok: the refused read names the key file" >>"$REPORT" ;;
  *) fail "the refused read does not name the key file $KEYS: $said" ;;
esac

WANT=refused run readers "missing-item-$RUN"
case "$said" in
  *"missing-item-$RUN"*) echo "ok: refused naming missing-item-$RUN" >>"$REPORT" ;;
  *) fail "expected a refusal naming missing-item-$RUN, got: $said" ;;
esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
