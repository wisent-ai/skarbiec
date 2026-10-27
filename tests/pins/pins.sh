#!/usr/bin/env bash
# Real test of keeping items at the front, `skarbiec pin add|remove|list`,
# through the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# It pins two notes and checks list names them in the order pinned, that a
# second pin of one writes nothing, that rename carries a pin to the new id,
# that a trashed item stays pinned but not live, that purge forgets its pin,
# that remove takes one off and a second remove writes nothing, and that an
# unknown item and another arrangement are refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/pins/pins.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/pins/$RUN"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$1-value" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}
pinned() {
  WANT=ok run pin list
  printf '%s' "$out" | jq -c '[.[] | .item]'
}

: >"$ROOT/stdin"
WANT=ok run init "pins-owner-$RUN"
BANK="pins-bank-$RUN"
ROUTER="pins-router-$RUN"
note "$BANK"
note "$ROUTER"

WANT=ok run pin add "$BANK"
WANT=ok run pin add "$ROUTER"
[ "$(pinned)" = "[\"$BANK\",\"$ROUTER\"]" ] || fail "pin list did not name the pins in the order they were made"
WANT=ok run pin add "$BANK"
[ "$(printf '%s' "$out" | jq -r .pinned)" = false ] || fail "a second pin of one item did not say nothing was written"
echo "ok: pins are listed in the order made and a second pin writes nothing" >>"$REPORT"
UNPINNED="pins-other-$RUN"
note "$UNPINNED"
WANT=ok run list --pinned
[ "$(printf '%s' "$out" | jq -c '[.[].id] | sort')" = "$(printf '["%s","%s"]' "$BANK" "$ROUTER" | jq -c sort)" ] \
  || fail "list --pinned did not keep exactly the pinned items"
echo "ok: list --pinned keeps the pinned items and no other" >>"$REPORT"

RENAMED="pins-bank-renamed-$RUN"
WANT=ok run rename "$BANK" "$RENAMED"
[ "$(pinned)" = "[\"$RENAMED\",\"$ROUTER\"]" ] || fail "rename did not carry the pin to the new id in place"
echo "ok: rename carried the pin" >>"$REPORT"

WANT=ok run delete "$ROUTER"
WANT=ok run pin list
[ "$(printf '%s' "$out" | jq -r --arg id "$ROUTER" '.[] | select(.item == $id) | .live')" = false ] \
  || fail "a trashed item's pin was not kept and marked not live"
WANT=ok run purge "$ROUTER" --yes
[ "$(pinned)" = "[\"$RENAMED\"]" ] || fail "purge did not forget the purged item's pin"
echo "ok: a trashed item stays pinned, not live, and purge forgets the pin" >>"$REPORT"

WANT=ok run pin remove "$RENAMED"
[ "$(pinned)" = "[]" ] || fail "pin remove did not take the pin off"
WANT=ok run pin remove "$RENAMED"
[ "$(printf '%s' "$out" | jq -r .unpinned)" = false ] || fail "a second remove did not say nothing was written"
echo "ok: remove takes a pin off and a second remove writes nothing" >>"$REPORT"

WANT=refused run pin add "missing-$RUN"
names "missing-$RUN is not a live item"
WANT=refused run pin "$RENAMED"
names "usage: pin add <id>"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
