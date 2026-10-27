#!/usr/bin/env bash
# Real test of `skarbiec lockdown`, through the built binary on a vault of its
# own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# Three consumers hold grants. Without --yes every grant is still listed
# afterwards. --except naming a consumer with no grant is refused and
# withdraws nothing. With --yes --except one of them, the other two are gone
# from grant list and the kept one remains; the journal records the lockdown.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/access/lockdown.sh
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
consumers() {
  "$BIN" grant list </dev/null | jq -c '[.[].consumer] | sort'
}

: >"$ROOT/stdin"
WANT=ok run init "lockdown-owner-$RUN"
ITEM="lockdown-item-$RUN"
jq -n '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_key:"not-a-secret"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type api-key
: >"$ROOT/stdin"
FIRST="lockdown-a-$RUN"
SECOND="lockdown-b-$RUN"
KEPT="lockdown-kept-$RUN"
for consumer in "$FIRST" "$SECOND" "$KEPT"; do
  WANT=ok run grant issue "$consumer" --capabilities "read:$ITEM#api_key" --until-revoked
done
ALL="$(jq -cn --arg a "$FIRST" --arg b "$SECOND" --arg k "$KEPT" '[$a, $b, $k] | sort')"
[ "$(consumers)" = "$ALL" ] || fail "grant list does not hold the three grants issued"

WANT=ok run lockdown --except "$KEPT"
printf '%s' "$out" | jq -e --arg a "$FIRST" --arg b "$SECOND" '.applied == false and (.would_withdraw | sort) == ([$a, $b] | sort)' >/dev/null \
  || fail "the preview does not name the two grants it would withdraw"
[ "$(consumers)" = "$ALL" ] || fail "the preview withdrew a grant"
echo "ok: without --yes nothing is withdrawn" >>"$REPORT"

WANT=refused run lockdown --except "no-such-consumer-$RUN" --yes
names "no-such-consumer-$RUN"
[ "$(consumers)" = "$ALL" ] || fail "a refused lockdown withdrew a grant"
echo "ok: an unknown consumer to keep is refused before anything is withdrawn" >>"$REPORT"

WANT=ok run lockdown --except "$KEPT" --yes
printf '%s' "$out" | jq -e '.ok and .applied and (.revoked | length == 2)' >/dev/null || fail "the lockdown does not report two grants withdrawn"
[ "$(consumers)" = "$(jq -cn --arg k "$KEPT" '[$k]')" ] || fail "grant list holds more than the kept grant after the lockdown"
jq -e -s --arg k "$KEPT" 'map(select(.op == "lockdown")) | any(.extra.kept | index($k) != null)' "$SKARBIEC_AUDIT_FILE" >/dev/null \
  || fail "the journal holds no lockdown record naming the kept consumer"
echo "ok: --yes withdraws every grant but the kept one, and the journal records it" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
