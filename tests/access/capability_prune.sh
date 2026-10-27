#!/usr/bin/env bash
# Real test of the capability state a broker reads on every request: through
# the built binary on a vault of its own (SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, SKARBIEC_CAPABILITY_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written).
#
# The state holds what a long-running broker leaves behind: a capability whose
# single use is spent, one that was cancelled, one past its expiry, one still
# redeemable with the nonce it was redeemed with, and a nonce whose capability
# is gone. `grant capability` loads, prunes and rewrites that state, and the
# test checks what it keeps:
# - the redeemable capability, its nonce, and the one just issued;
# - nothing of the spent, cancelled or expired capabilities, and no orphan
#   nonce.
# Every command and verdict goes to the run's report.txt.
#
# Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION, the lifetime in whole
# seconds of the capabilities the test issues (SKARBIEC_TEST_CAPABILITY_TTL)
# and their use count (SKARBIEC_TEST_CAPABILITY_USES), then run
# tests/access/capability_prune.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
TTL=${SKARBIEC_TEST_CAPABILITY_TTL:?state the lifetime in whole seconds of the capabilities this test issues}
USES=${SKARBIEC_TEST_CAPABILITY_USES:?state how many uses the capabilities this test issues carry}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/capability-prune/$RUN"
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
export SKARBIEC_CAPABILITY_FILE="$ROOT/capabilities.json"
export SKARBIEC_CAPABILITY_ROUTES_FILE="$ROOT/capability-routes.json"
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
run() {
  if out=$("$BIN" "$@" 2>&1); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  printf '$ skarbiec %s\nexit: %s\nresult: %s\n\n' "$*" "$status" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
# The capability state the journal replays to: a snapshot replaces what was
# read before it, a capability entry sets one record, a nonce entry one nonce.
REPLAY='reduce .[] as $v ({capabilities: {}, nonces: {}};
  if ($v | has("capabilities")) then $v
  elif ($v | has("capability")) then .capabilities[$v.capability] = $v.record
  else .nonces[$v.nonce] = $v.seen_at end)'
# Whether the capability state holds the capability or nonce key $2 under $1.
holds() {
  jq -s -e --arg key "$2" "$REPLAY | .$1 | has(\$key)" "$SKARBIEC_CAPABILITY_FILE" >/dev/null
}
keeps() {
  if holds "$1" "$2"; then echo "ok: kept $3" >>"$REPORT"; else fail "dropped $3"; fi
}
drops() {
  if holds "$1" "$2"; then fail "kept $3"; else echo "ok: dropped $3" >>"$REPORT"; fi
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

ITEM="prune-provider-$RUN"
RESOURCE="provider:prune-$RUN"
WANT=ok run init "prune-test-owner-$RUN"
# The provider credential the capability route resolves to, written whole on
# stdin through set, the one write command.
jq -n '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_key:"not-a-secret"},context:{}}' \
  | WANT=ok run set "$ITEM" --type api-key "--tags=brama:provider:prune-$RUN"

# The state a broker leaves behind, one record of each kind. The state keys
# capabilities by id and nonces by `<id>:<nonce>`.
SPENT="spent-$RUN"
CANCELLED="cancelled-$RUN"
EXPIRED="expired-$RUN"
LIVE="live-$RUN"
GONE="gone-$RUN"
NOW=$(date +%s)
LATER=$((NOW + TTL))
jq -n \
  --arg spent "$SPENT" --arg cancelled "$CANCELLED" --arg expired "$EXPIRED" \
  --arg live "$LIVE" --arg gone "$GONE" --arg resource "$RESOURCE" \
  --argjson now "$NOW" --argjson later "$LATER" --argjson uses "$USES" '
  def record($state; $until; $left): {agent: "prune-agent", purpose: "prune", resource: $resource,
    target: "prune", authorization_id: "", issued_at: $now, expires_at: $until,
    remaining_uses: $left, state: $state};
  {capabilities: {
     ($spent): record("spent"; $later; $uses - $uses),
     ($cancelled): record("cancelled"; $later; $uses - $uses),
     ($expired): record("issued"; $now; $uses),
     ($live): record("issued"; $later; $uses)},
   nonces: {
     ($spent + ":spent-nonce"): $now,
     ($live + ":live-nonce"): $now,
     ($gone + ":orphan-nonce"): $now}}' >"$SKARBIEC_CAPABILITY_FILE"
chmod go-rwx "$SKARBIEC_CAPABILITY_FILE"

WANT=ok run grant capability --agent prune-agent --purpose prune --target prune \
  --resource "$RESOURCE" --ttl "$TTL" --max-uses "$USES"
ISSUED=$(printf '%s' "$out" | jq -r '.capability_id')
[ -n "$ISSUED" ] && [ "$ISSUED" != null ] || fail "grant capability answered no capability id: $out"
# The grant appends its one entry; the dead records the state still carried
# then outweigh the live ones, so the journal is replaced by a snapshot of
# what can still be redeemed.
keeps capabilities "$LIVE" "the redeemable capability"
keeps capabilities "$ISSUED" "the capability just issued"
keeps nonces "$LIVE:live-nonce" "the nonce of the redeemable capability"
drops capabilities "$SPENT" "the spent capability"
drops capabilities "$CANCELLED" "the cancelled capability"
drops capabilities "$EXPIRED" "the expired capability"
drops nonces "$SPENT:spent-nonce" "the nonce of the spent capability"
drops nonces "$GONE:orphan-nonce" "the nonce whose capability is gone"
echo "PASS" >>"$REPORT"
echo "capability prune: PASS ($REPORT)"
