#!/usr/bin/env bash
# Real test of `skarbiec exposure`, through the built binary on a vault of its
# own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# One item is granted to a consumer and another item to a second one. The
# exposure of the first names the owner's key, the first consumer's grant
# and not the second's, counts the journal entries naming it, and prints no
# value. --since a moment after everything names no journal entry. An id the
# vault does not hold and a --since that is not a moment are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/access/exposure.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/access/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
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
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: output: $out stderr: $said" ;;
  esac
}

: >"$ROOT/stdin"
WANT=ok run init "exposure-owner-$RUN"
SECRET="exposure-secret-$RUN"
ITEM="exposure-item-$RUN"
OTHER="exposure-other-$RUN"
for id in "$ITEM" "$OTHER"; do
  jq -n --arg key "$SECRET" '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_key:$key},context:{}}' >"$ROOT/stdin"
  WANT=ok run set "$id" --type api-key
done
: >"$ROOT/stdin"
READER="exposure-reader-$RUN"
STRANGER="exposure-stranger-$RUN"
WANT=ok run grant issue "$READER" --capabilities "read:$ITEM#api_key" --until-revoked
WANT=ok run grant issue "$STRANGER" --capabilities "read:$OTHER#api_key" --until-revoked

WANT=ok run exposure "$ITEM"
case "$out" in *"$SECRET"*) fail "exposure printed the value" ;; esac
printf '%s' "$out" >"$ROOT/exposure.json"
jq -e '.keys.encrypted_to | length > 0' "$ROOT/exposure.json" >/dev/null || fail "exposure names no key the item opens with"
jq -e --arg r "$READER" --arg s "$STRANGER" '[.grants[].consumer] | index($r) != null and index($s) == null' "$ROOT/exposure.json" >/dev/null \
  || fail "exposure does not name exactly the grant reaching the item"
jq -e '.journal_entries > 0' "$ROOT/exposure.json" >/dev/null || fail "exposure counts no journal entry naming the item"
echo "ok: exposure names the keys, the grant reaching the item and the journal entries, and no value" >>"$REPORT"

# Twice now since the epoch: a moment no entry of this run can reach.
LATER="$(jq -rn 'now + now | floor | todate')"
WANT=ok run exposure "$ITEM" --since "$LATER"
printf '%s' "$out" | jq -e '.journal_entries == 0 and (.acted | length == 0)' >/dev/null || fail "--since after everything still counts journal entries"
echo "ok: --since keeps only the entries from the moment" >>"$REPORT"

WANT=refused run exposure "no-such-item-$RUN"
names "no-such-item-$RUN"
WANT=refused run exposure "$ITEM" --since yesterday
names "--since yesterday is not a UTC time"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
