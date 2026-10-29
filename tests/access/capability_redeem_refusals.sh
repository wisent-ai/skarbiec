#!/usr/bin/env bash
# Real test of why a capability redemption is refused, through the built
# binary's own capability broker (`serve --no-http --socket`) on a vault of its
# own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE, SKARBIEC_CAPABILITY_FILE,
# SKARBIEC_CAPABILITY_ROUTES_FILE and GNUPGHOME point into this checkout's
# target directory, so the operator's vault and keyring are never read or
# written. A workload key made for the run signs every request the way a
# gateway does, and the request goes over the broker's Unix socket.
#
# The wire answers every refusal with the same opaque `denied`; the reason is
# the broker's own log line, which is what the test reads:
# - a provider resource that stopped resolving to exactly one route after the
#   capability was issued (a second item now claims it) is refused with the
#   route table's own sentence, never as "no value" at a challenge item nobody
#   writes;
# - a capability whose stored record lost its agent is refused as damaged
#   state naming the capability and the field, never checked as agent "".
# Every command and verdict goes to the run's report.txt.
#
# Supply SKARBIEC, the lifetime in whole seconds of the grant and capabilities
# the test issues (SKARBIEC_TEST_CAPABILITY_TTL) and their use count
# (SKARBIEC_TEST_CAPABILITY_USES), then run tests/access/capability_redeem_refusals.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
TTL=${SKARBIEC_TEST_CAPABILITY_TTL:?state the lifetime in whole seconds of what this test issues}
USES=${SKARBIEC_TEST_CAPABILITY_USES:?state how many uses the capabilities this test issues carry}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/capability-redeem/$RUN"
REPORT="$ROOT/report.txt"
# gpg-agent's socket and the broker's socket live at short paths: a Unix
# socket path is limited in length.
KEYRING="$PWD/target/g$$"
SOCKET="$PWD/target/c$$.sock"
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
BROKER=""
cleanup() {
  if [ -n "$BROKER" ] && ! kill "$BROKER" 2>>"$REPORT"; then
    echo "cleanup: the broker had already exited" >>"$REPORT"
  fi
  if ! gpgconf --homedir "$GNUPGHOME" --kill all 2>>"$REPORT"; then
    echo "cleanup: gpgconf --kill all failed, its error is above" >>"$REPORT"
  fi
  rm -rf "$KEYRING" "$SOCKET"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >>"$REPORT"
  echo "FAIL: $* ($REPORT)" >&2
  false
}
# Runs one skarbiec command, standard output in $out and standard error in
# $said; WANT says whether it had to succeed (ok) or be refused (refused).
run() {
  if out=$("$BIN" "$@" </dev/null 2>"$ROOT/said"); then status=ok; else status=refused; fi
  said=$(cat "$ROOT/said")
  echo "$status: skarbiec $*" >>"$REPORT"
  [ "$status" = "${WANT:?}" ] || fail "skarbiec $* was $status, expected $WANT: output: $out stderr: $said"
}

AGENT="redeem-agent-$RUN"
ITEM="redeem-provider-$RUN"
RESOURCE="provider:redeem-$RUN"
WANT=ok run init "redeem-test-owner-$RUN"
# Writes item $1 claiming the resource, its value not-a-secret-$1 (the vault
# refuses two items holding exactly the same payload).
item() {
  jq -n --arg value "not-a-secret-$1" \
    '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_key:$value},context:{}}' \
    | "$BIN" set "$1" --type api-key "--tags=brama:$RESOURCE" >>"$REPORT" 2>&1 \
    || fail "set $1 was refused"
}
item "$ITEM"

# The workload key uses the signature algorithm the broker verifies.
openssl genpkey -algorithm ed25519 -out "$ROOT/workload.pem" 2>>"$REPORT"
openssl pkey -in "$ROOT/workload.pem" -pubout -out "$ROOT/workload.pub.pem"
chmod go-rwx "$ROOT/workload.pem" "$ROOT/workload.pub.pem"
WANT=ok run grant issue "$AGENT" --capabilities "acquire:$ITEM#api_key" \
  --workload-public-key-file "$ROOT/workload.pub.pem" --ttl-seconds "$TTL"
# Issues one capability for the resource and prints its id; the command's
# progress lines on standard error go to the report.
issue() {
  answer=$("$BIN" grant capability --agent "$AGENT" --purpose redeem-test --target redeem-test \
    --resource "$RESOURCE" --ttl "$TTL" --max-uses "$USES" </dev/null 2>>"$REPORT") \
    || fail "grant capability was refused: $answer"
  echo "ok: skarbiec grant capability --resource $RESOURCE" >>"$REPORT"
  printf '%s' "$answer" | jq -r '.capability_id'
}
ROUTE_LOST=$(issue)
DAMAGED=$(issue)

# The next broker log line containing $1, read from this function's standard
# input (the broker's log pipe); every line read is kept in the report.
logged() {
  while IFS= read -r line; do
    echo "broker: $line" >>"$REPORT"
    case "$line" in *"$1"*) said="$line"; return ;; esac
  done
  fail "the broker exited before logging '$1'"
}

# One signed redemption of capability $1 with nonce $2, as a workload sends it:
# the proof signs the domain, then id, nonce, workload and operation each
# followed by a zero byte, then the (empty) authorization id.
redeem() {
  printf 'SKARBIEC-WORKLOAD-PROOF\0v1\0%s\0%s\0%s\0%s\0' "$1" "$2" "$AGENT" redeem >"$ROOT/payload.bin"
  proof=$(openssl pkeyutl -sign -inkey "$ROOT/workload.pem" -rawin -in "$ROOT/payload.bin" \
    | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  request=$(jq -cn --arg id "$1" --arg nonce "$2" --arg workload "$AGENT" --arg proof "$proof" \
    '{version:"skarbiec.redeem.v1",operation:"redeem",capability_id:$id,nonce:$nonce,workload_id:$workload,proof:$proof}')
  answer=$(printf '%s\n' "$request" | nc -U "$SOCKET" | { IFS= read -r first; printf '%s' "$first"; })
  echo "redeem $1: $answer" >>"$REPORT"
}

# Everything that reads the broker's log runs with that log on its input.
against_broker() {
  logged "capability broker listening on"

  # A second item now claims the resource the first capability was issued for.
  item "$ITEM-second" </dev/null
  redeem "$ROUTE_LOST" "nonce-$RUN-route" </dev/null
  logged "redemption denied"
  case "$said" in
    *"resource $RESOURCE: "*) echo "ok: the route refusal names the resource and the route table's sentence" >>"$REPORT" ;;
    *) fail "the route refusal does not carry the route table's sentence: $said" ;;
  esac
  case "$said" in
    *capability-challenge-*) fail "a provider resource was read from a challenge item: $said" ;;
  esac

  # The second capability's stored record loses its agent: the journal gains
  # an entry setting the record it replays to, without the agent.
  jq -s -c --arg id "$DAMAGED" '
    reduce .[] as $v ({capabilities: {}, nonces: {}};
      if ($v | has("capabilities")) then $v
      elif ($v | has("capability")) then .capabilities[$v.capability] = $v.record
      else .nonces[$v.nonce] = $v.seen_at end)
    | {capability: $id, record: (.capabilities[$id] | del(.agent))}' \
    "$SKARBIEC_CAPABILITY_FILE" >"$ROOT/damaged.json"
  cat "$ROOT/damaged.json" >>"$SKARBIEC_CAPABILITY_FILE"
  redeem "$DAMAGED" "nonce-$RUN-damaged" </dev/null
  logged "redemption denied"
  case "$said" in
    *"capability $DAMAGED is damaged state: its record has no valid agent"*)
      echo "ok: the damaged record is refused naming the capability and the field" >>"$REPORT" ;;
    *) fail "the damaged record was not refused as damaged state: $said" ;;
  esac
}

# The broker, with its log on a pipe this test reads line by line.
mkfifo "$ROOT/broker.log"
"$BIN" serve --no-http --socket "$SOCKET" 2>"$ROOT/broker.log" &
BROKER=$!
against_broker <"$ROOT/broker.log"

echo "PASS" >>"$REPORT"
echo "capability redeem refusals: PASS ($REPORT)"
