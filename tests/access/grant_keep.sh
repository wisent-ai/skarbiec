#!/usr/bin/env bash
# Real test of `grant keep`, through the built binary on a vault of its own
# (SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written).
#
# A direct grant issued with a lifetime is kept: afterwards it records the
# same expiry a grant issued --until-revoked records, the bearer the consumer
# already held still verifies, and a second keep answers unchanged without
# writing. Refusals: a consumer with no grant, an acquire grant, and a keep
# without a consumer. Every command and verdict goes to the run's report.txt.
#
# Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION and the lifetime in whole
# seconds of the grants this test issues (SKARBIEC_TEST_GRANT_TTL), then run
# tests/access/grant_keep.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
TTL=${SKARBIEC_TEST_GRANT_TTL:?state the lifetime in whole seconds of the grants this test issues}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/grant-keep/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
cleanup() {
  if ! gpgconf --homedir "$GNUPGHOME" --kill all; then
    echo "cleanup: the gpg daemons of $GNUPGHOME did not stop" >>"$REPORT"
  fi
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
# Runs one skarbiec command; its standard output is in $out and its standard
# error in $said, which goes to the report. WANT says whether it had to
# succeed (ok) or be refused (refused).
run() {
  if out=$("$BIN" "$@" </dev/null 2>"$ROOT/stderr"); then status=ok; else status=refused; fi
  said=$(cat "$ROOT/stderr")
  printf '$ skarbiec %s\nresult: %s\n%s\n\n' "$*" "$status" "$said" >>"$REPORT"
  [ "$status" = "${WANT:?}" ] || fail "skarbiec $* was $status, expected $WANT: $said"
}
# What `grant list` records for consumer $1: field $2 of its row.
listed() {
  "$BIN" grant list </dev/null 2>>"$REPORT" \
    | jq -er --arg consumer "$1" --arg field "$2" '.[] | select(.consumer == $consumer) | .[$field] | tostring'
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

ITEM="keep-provider-$RUN"
KEPT="keep-consumer-$RUN"
FOREVER="keep-until-revoked-$RUN"
AGENT="keep-acquire-$RUN"
WANT=ok run init "keep-test-owner-$RUN"
jq -n '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_key:"not-a-secret"},context:{}}' \
  | "$BIN" set "$ITEM" --type api-key >>"$REPORT" 2>&1 || fail "set $ITEM was refused"

# The bearer the consumer holds is the one the issue generates and prints
# once; it goes to a file in this owner-only run directory and never into the
# report.
WANT=ok run grant issue "$KEPT" --capabilities "read:$ITEM#api_key" --ttl-seconds "$TTL"
TOKEN="$ROOT/consumer.token"
printf '%s' "$out" | jq -er .token >"$TOKEN" || fail "grant issue printed no bearer"
chmod go-rwx "$TOKEN"
WANT=ok run grant issue "$FOREVER" --capabilities "read:$ITEM#api_key" --until-revoked
BEFORE=$(listed "$KEPT" expires_at)
UNTIL_REVOKED=$(listed "$FOREVER" expires_at)
[ "$(listed "$FOREVER" until_revoked)" = true ] || fail "a grant issued --until-revoked is not listed until_revoked"
[ "$(listed "$KEPT" until_revoked)" = false ] || fail "a grant issued with --ttl-seconds is listed until_revoked"

WANT=ok run grant keep "$KEPT"
[ "$(printf '%s' "$out" | jq -r .status)" = kept ] || fail "the first keep did not answer kept: $out"
[ "$(printf '%s' "$out" | jq -r '.previous_expires_at | tostring')" = "$BEFORE" ] \
  || fail "the keep did not name the expiry it replaced: $out"
[ "$(listed "$KEPT" expires_at)" = "$UNTIL_REVOKED" ] || fail "the kept grant does not record the until-revoked expiry"
[ "$(listed "$KEPT" until_revoked)" = true ] || fail "the kept grant is not listed until_revoked"
echo "ok: the kept grant records and lists the expiry of a grant issued --until-revoked" >>"$REPORT"

WANT=ok run grant verify "$KEPT" "$ITEM" --action read --field api_key --token-file "$TOKEN"
[ "$(printf '%s' "$out" | jq -r .allowed)" = true ] || fail "the bearer the consumer held no longer verifies: $out"
echo "ok: the bearer held before the keep still verifies" >>"$REPORT"

cp "$SKARBIEC_VAULT_FILE" "$ROOT/vault.before-second-keep.json"
WANT=ok run grant keep "$KEPT"
[ "$(printf '%s' "$out" | jq -r .status)" = unchanged ] || fail "a second keep did not answer unchanged: $out"
cmp -s "$SKARBIEC_VAULT_FILE" "$ROOT/vault.before-second-keep.json" || fail "a second keep wrote the vault"
echo "ok: a second keep answers unchanged and writes nothing" >>"$REPORT"

WANT=refused run grant keep "absent-consumer-$RUN"
case "$said" in *"absent-consumer-$RUN has no grant"*) ;; *) fail "the refusal does not name the absent consumer: $said" ;; esac

openssl genpkey -algorithm ed25519 -out "$ROOT/workload.pem" 2>>"$REPORT"
openssl pkey -in "$ROOT/workload.pem" -pubout -out "$ROOT/workload.pub.pem"
chmod go-rwx "$ROOT/workload.pem" "$ROOT/workload.pub.pem"
WANT=ok run grant issue "$AGENT" --capabilities "acquire:$ITEM#api_key" \
  --workload-public-key-file "$ROOT/workload.pub.pem" --ttl-seconds "$TTL"
WANT=refused run grant keep "$AGENT"
case "$said" in *"acquire grant"*) ;; *) fail "the refusal does not say the grant is an acquire grant: $said" ;; esac

WANT=refused run grant keep
case "$said" in *"usage: grant keep <consumer>"*) ;; *) fail "a keep without a consumer is not refused with its usage: $said" ;; esac

echo "PASS" >>"$REPORT"
echo "grant keep: PASS ($REPORT)"
