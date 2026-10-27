#!/usr/bin/env bash
# Real test of `skarbiec health --saved-versions`, through the built binary on
# a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# point into this checkout's target directory, so the operator's vault and
# keyring are never read or written.
#
# One login changes its password away from P; another then takes P: the
# second is named under reused_retired with the first as retired_in. A third
# changes away from Q and back to Q: it is named with itself as retired_in.
# A fourth keeps its password while its username changes: it is not named.
# Without --saved-versions nothing is compared, and no answer carries a
# password.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/history/retired_reuse.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/history/$RUN"
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
# Store a login with one username and password, replacing what it held.
login() {
  jq -n --arg user "$2" --arg password "$3" \
    '{schema:"skarbiec.item.v2",kind:"login",fields:{username:$user,password:$password},context:{}}' >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "retired-owner-$RUN"

P="retired-p-$RUN"
Q="retired-q-$RUN"
GIVER="giver-$RUN"
TAKER="taker-$RUN"
BACK="back-$RUN"
KEEPER="keeper-$RUN"
login "$GIVER" me "$P"
login "$GIVER" me "giver-new-$RUN"
login "$TAKER" me "$P"
login "$BACK" me "$Q"
login "$BACK" me "back-between-$RUN"
login "$BACK" me "$Q"
login "$KEEPER" first "keeper-$RUN-password"
login "$KEEPER" second "keeper-$RUN-password"

WANT=ok run health
printf '%s' "$out" | jq -e '.saved_versions_checked == false and (.reused_retired | length == 0)' >/dev/null \
  || fail "health compared saved versions without --saved-versions"

WANT=ok run health --saved-versions
case "$out" in *"$P"*|*"$Q"*|*"keeper-$RUN-password"*) fail "health printed a password" ;; esac
printf '%s' "$out" >"$ROOT/health.json"
jq -e '.saved_versions_checked and .ok == false' "$ROOT/health.json" >/dev/null || fail "health --saved-versions was ok with a retired value in use"
jq -e --arg taker "$TAKER" --arg giver "$GIVER" '.reused_retired | any(.item == $taker and .retired_in == $giver and .field == "password")' "$ROOT/health.json" >/dev/null \
  || fail "the login taking another's retired password was not named"
echo "ok: a value another item gave up is named where it is used now" >>"$REPORT"
jq -e --arg back "$BACK" '.reused_retired | any(.item == $back and .retired_in == $back)' "$ROOT/health.json" >/dev/null \
  || fail "the login that brought its old password back was not named"
echo "ok: a value changed away from and brought back is named" >>"$REPORT"
jq -e --arg keeper "$KEEPER" '.reused_retired | all(.item != $keeper and .retired_in != $keeper)' "$ROOT/health.json" >/dev/null \
  || fail "a login that never changed its password was named"
jq -e --arg giver "$GIVER" '.reused_retired | all(.item != $giver)' "$ROOT/health.json" >/dev/null \
  || fail "the login that gave its password up was named as using it"
echo "ok: an unchanged password and the item that gave one up are not named" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
