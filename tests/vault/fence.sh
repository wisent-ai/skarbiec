#!/usr/bin/env bash
# Real test of the vault's write fence through the built binary on a vault
# of its own under this checkout's target directory (HOME isolated, so the
# operator's vault, journal and keys are never read or written).
#
# It arms a fence for one transaction and checks that every write is then
# refused naming the transaction and how to end it, that a write carrying
# --fence with that transaction passes and one with another does not, that
# a second arm of the same transaction answers already while another
# transaction's arm is refused, that /v1/items/read and /v1/items/revision
# carry the fence while it stands and nothing once it is lifted, that lift
# by another transaction is refused, and that every flag the fence does not
# take is refused naming it. Every command and answer goes to report.txt.
#
# Usage: SKARBIEC=<binary under test> tests/vault/fence.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test}
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/fence/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT/home"
chmod go-rwx "$ROOT"
echo "revision: ${SKARBIEC_TEST_SOURCE_REVISION:-$(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')}" >"$REPORT"
echo "binary: $BIN; sha256: $(openssl dgst -sha256 -r "$BIN" | cut -d' ' -f1)" >>"$REPORT"
export HOME="$ROOT/home"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
SERVE=
trap '[ -z "$SERVE" ] || kill "$SERVE" 2>/dev/null || true' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out $said"
}
says() {
  case "$said" in *"$1"*) echo "ok: $2" >>"$REPORT" ;; *) fail "$2: expected '$1' in: $said" ;; esac
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"u-%s","password":"p-%s"},"context":{}}' "$1" "$RUN" >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "fence-owner-$RUN"
login first
WANT=ok run set fenced --type login
: >"$ROOT/stdin"
WANT=ok run fence show
[ "$(printf '%s' "$out" | jq -c .fence)" = null ] || fail "fence show on a vault with none answered a fence: $out"

T="move-$RUN"
WANT=ok run fence arm --transaction "$T"
SINCE=$(printf '%s' "$out" | jq -r .fence.since)
[ -f "${SKARBIEC_VAULT_FILE%.json}.fence.json" ] || fail "fence arm wrote no fence beside the vault"
WANT=ok run fence arm --transaction "$T"
printf '%s' "$out" | jq -e '.already == true' >/dev/null || fail "a second arm of the same transaction did not answer already: $out"
WANT=refused run fence arm --transaction "other-$RUN"
says "already fenced for transaction $T" "arming another transaction is refused naming the one standing"

BEFORE=$(openssl dgst -sha256 -r "$SKARBIEC_VAULT_FILE" | cut -d' ' -f1)
login second
WANT=refused run set fenced --type login
says "the vault is moving (transaction $T, since $SINCE); retry after it" "a write while fenced is refused naming the transaction and time"
says "fence lift --transaction $T" "the refusal names how an abandoned move is ended"
login second
WANT=refused run set fenced --type login --fence "other-$RUN"
says "the vault is moving" "a write passing another transaction is refused"
: >"$ROOT/stdin"
WANT=refused run delete fenced
says "the vault is moving" "a delete while fenced is refused"
[ "$(openssl dgst -sha256 -r "$SKARBIEC_VAULT_FILE" | cut -d' ' -f1)" = "$BEFORE" ] || fail "a refused write changed the vault"
login third
WANT=ok run set fenced --type login --fence "$T"
: >"$ROOT/stdin"
echo "ok: the move's own write passes with --fence $T" >>"$REPORT"

# Reads over HTTP carry the fence while it stands.
WANT=ok run grant issue fence-reader --capabilities "read:fenced#password" --until-revoked --fence "$T"
TOKEN=$(printf '%s' "$out" | jq -r .token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || fail "grant issue answered no token: $out"
# Any free loopback port: serve prints the address it bound.
mkfifo "$ROOT/serve.log"
"$BIN" serve --port 0 &>"$ROOT/serve.log" &
SERVE=$!
ADDRESS=
while read -r line; do
  case "$line" in
    *"listening on http://"*) ADDRESS=${line#*http://}; ADDRESS=${ADDRESS%% *}; break ;;
  esac
done <"$ROOT/serve.log"
cat "$ROOT/serve.log" >/dev/null &
[ -n "$ADDRESS" ] || fail "serve ended before it listened"
ask() {
  curl -sS -X POST "http://$ADDRESS$1" -H 'content-type: application/json' -H 'x-consumer: fence-reader' \
    -H "authorization: Bearer $TOKEN" -d '{"id":"fenced","field":"password"}'
}
for route in /v1/items/read /v1/items/revision; do
  answer=$(ask "$route")
  printf 'POST %s while fenced: %s\n' "$route" "$(printf '%s' "$answer" | jq -c 'del(.value)')" >>"$REPORT"
  printf '%s' "$answer" | jq -e --arg t "$T" --arg s "$SINCE" '.fence.transaction == $t and .fence.since == $s' >/dev/null \
    || fail "$route did not carry the fence while it stands: $(printf '%s' "$answer" | jq -c 'del(.value)')"
done

WANT=refused run fence lift --transaction "other-$RUN"
says "the fence stands for transaction $T, not other-$RUN" "lift by another transaction is refused naming the standing one"
WANT=ok run fence lift --transaction "$T"
printf '%s' "$out" | jq -e '.lifted == true' >/dev/null || fail "fence lift did not lift: $out"
for route in /v1/items/read /v1/items/revision; do
  answer=$(ask "$route")
  printf '%s' "$answer" | jq -e 'has("fence") | not' >/dev/null || fail "$route still carried a fence after it was lifted"
done
login fourth
WANT=ok run set fenced --type login
: >"$ROOT/stdin"
echo "ok: once lifted, reads carry no fence and writes pass" >>"$REPORT"

WANT=refused run fence arm
says "need --transaction" "fence arm without a transaction is refused"
WANT=refused run fence show --transaction "$T"
says "does not take --transaction" "fence show refuses a flag it does not take"
WANT=refused run fence arm --transaction "$T" --force
says "does not take --force" "fence arm refuses a flag it does not take"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
