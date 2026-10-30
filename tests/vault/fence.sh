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

# A write in flight holds the vault's write lock; arm takes the same lock,
# so it never answers armed while that write can still land after it.
LOCK="${SKARBIEC_VAULT_FILE%.json}.write.lock"
echo "$$" >"$LOCK"
WANT=refused run fence arm --transaction "inflight-$RUN"
says "a write to the vault is in progress" "arm while a write holds the vault's lock is refused, not armed under it"
[ ! -e "${SKARBIEC_VAULT_FILE%.json}.fence.json" ] || fail "fence arm wrote a fence while a write held the lock"
rm -f "$LOCK"

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

# A fence file that cannot be read stops writes but not reads: the read
# answers, carrying why the fence could not be read.
FENCE="${SKARBIEC_VAULT_FILE%.json}.fence.json"
cp "$FENCE" "$ROOT/fence.kept"
printf 'not json' >"$FENCE"
for route in /v1/items/read /v1/items/revision; do
  answer=$(ask "$route")
  printf '%s' "$answer" | jq -e '.fence.unreadable | test("not JSON")' >/dev/null \
    || fail "$route did not answer with an unreadable fence named: $(printf '%s' "$answer" | jq -c 'del(.value)')"
done
login fifth
WANT=refused run set fenced --type login --fence "$T"
: >"$ROOT/stdin"
says "is not JSON" "a write with an unreadable fence is refused naming the fence"
cp "$ROOT/fence.kept" "$FENCE"
echo "ok: an unreadable fence stops writes, and reads still answer naming it" >>"$REPORT"

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

# A fence with a reason: the copy a move leaves behind, held for good. The
# reason is kept, answered by arm, show and every read, and said by the
# refusal.
R="the vault moved to destination-$RUN"
WANT=ok run fence arm --transaction "$T" --reason "$R"
printf '%s' "$out" | jq -e --arg r "$R" '.fence.reason == $r' >/dev/null || fail "fence arm did not keep the reason: $out"
WANT=ok run fence show
printf '%s' "$out" | jq -e --arg r "$R" '.fence.reason == $r' >/dev/null || fail "fence show did not answer the reason: $out"
answer=$(ask /v1/items/revision)
printf '%s' "$answer" | jq -e --arg r "$R" '.fence.reason == $r' >/dev/null || fail "a read did not carry the reason: $answer"
login sixth
WANT=refused run set fenced --type login
: >"$ROOT/stdin"
says "writes to this vault are held: $R (transaction $T" "a write is refused saying the fence's reason"
WANT=ok run fence lift --transaction "$T"
printf 'bad\nreason' >"$ROOT/reason"
WANT=refused run fence arm --transaction "$T" --reason "$(cat "$ROOT/reason")"
says "one line of text" "a reason holding a line break is refused"
echo "ok: a fence with a reason keeps it and every refusal and read says it" >>"$REPORT"

WANT=refused run fence arm
says "need --transaction" "fence arm without a transaction is refused"
WANT=refused run fence show --transaction "$T"
says "does not take --transaction" "fence show refuses a flag it does not take"
WANT=refused run fence arm --transaction "$T" --force
says "does not take --force" "fence arm refuses a flag it does not take"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
