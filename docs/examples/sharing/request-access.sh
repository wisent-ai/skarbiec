#!/bin/sh
# request-access.sh — an agent asks for a credential, a person decides, Skarbiec
# grants (docs/design/access-requests.md).
#
# Goal: watch one access request travel from the agent's MCP call to a
# redeemed value: the agent asks through `skarbiec mcp broker` (the surface Las
# federates) and is answered `pending`; the owner approves on the command line
# and states the lifetime and uses; the agent sees the capability id; the
# workload redeems it once with the request id signed into its proof. Then a
# denied request issues nothing, a dual-control item needs two different
# deciders, and a colleague's host files through POST /v1/access-requests.
# Requires: skarbiec on PATH (or SKARBIEC_BIN), openssl, nc with -U, and a
# free loopback port chosen by the system.
#
# Runs entirely inside its own demo directory and keyring — it never reads or
# writes your real vault. The demo values are not secrets.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}
DEMO_DIR=${SKARBIEC_EXAMPLE_DIR:-${TMPDIR:-/tmp}/skarbiec-request-example}

if [ -e "$DEMO_DIR" ]; then
  printf '%s\n' "refusing to overwrite $DEMO_DIR; remove it or set SKARBIEC_EXAMPLE_DIR"
  false
fi

umask u=rwx,go=
mkdir "$DEMO_DIR"
chmod u=rwx,go= "$DEMO_DIR"
export GNUPGHOME="$DEMO_DIR/gnupg"
export SKARBIEC_VAULT_FILE="$DEMO_DIR/demo.vault.json"
export SKARBIEC_AUDIT_FILE="$DEMO_DIR/demo.audit.jsonl"
export SKARBIEC_CAPABILITY_FILE="$DEMO_DIR/demo.capabilities.json"
export SKARBIEC_CAPABILITY_ROUTES_FILE="$DEMO_DIR/demo.capability-routes.json"
SOCKET="$DEMO_DIR/broker.sock"
mkdir "$GNUPGHOME"
chmod u=rwx,go= "$GNUPGHOME"

fail() {
  printf '%s\n' "$*"
  false
}

# What one JSON answer says for one key: the first "key": "value" or
# key":"value" pair, escaped or not, with its value.
field() {
  printf '%s\n' "$1" | sed -n "s/.*$2\\\\*\": *\\\\*\"\([^\"\\\\]*\).*/\1/p" | sed -n 1p
}

# One broker MCP session: initialize, then one tool call, as the agent the
# operator names in SKARBIEC_MCP_AGENT_ID. Prints the tool's JSON-RPC answer.
broker() {
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" \
    | SKARBIEC_MCP_AGENT_ID=demo-agent "$SB" mcp broker 2>/dev/null | sed -n 2p
}

# 1. A vault with an owner and an admin: both may decide. Each key is in this
#    demo keyring, which is what lets either of them decide on this host.
"$SB" init demo-owner
"$SB" recipient add demo-admin --role admin

# 2. Two credentials the agent may ask for. The second is marked dual-control
#    by its owner, so no single person can hand it out.
printf '{"schema":"skarbiec.item.v2","kind":"api-key","fields":{"api_key":"demo-key-not-a-secret"},"context":{}}' \
  | "$SB" set-json demo-provider --type api-key --tags brama:provider:demo
printf '{"schema":"skarbiec.item.v2","kind":"api-key","fields":{"api_key":"demo-root-not-a-secret"},"context":{}}' \
  | "$SB" set-json demo-root --type api-key --tags brama:provider:demo-root,dual-control

# 3. The workload behind the agent registers its Ed25519 key, as every
#    capability redemption requires. Registering lets it prove who it is; it
#    still has no capability to redeem.
openssl genpkey -algorithm ED25519 -out "$DEMO_DIR/workload-private.pem"
openssl pkey -in "$DEMO_DIR/workload-private.pem" -pubout -out "$DEMO_DIR/workload-public.pem"
"$SB" grant issue demo-agent --capabilities acquire:demo-provider#api_key \
  --workload-public-key-file "$DEMO_DIR/workload-public.pem" --ttl-seconds 3600

# 4. The one Skarbiec process: the capability socket and the loopback API on a
#    port the system chooses. Its log is read until both listeners are up.
mkfifo "$DEMO_DIR/serve.out"
"$SB" serve --port 0 --socket "$SOCKET" 2>"$DEMO_DIR/serve.out" &
SERVE_PID=$!
trap 'kill "$SERVE_PID" 2>/dev/null || true' EXIT
exec 3<"$DEMO_DIR/serve.out"
BASE=
while IFS= read -r line <&3; do
  case "$line" in
    *"API listening on"*) BASE=$(printf '%s\n' "$line" | sed -n 's/.*listening on \(http:[^ ]*\).*/\1/p') ;;
    *"capability broker listening on"*) break ;;
  esac
done
cat <&3 >"$DEMO_DIR/serve.log" &
[ -n "$BASE" ] || fail "serve did not start; see $DEMO_DIR/serve.log"

# 5. The agent asks through the broker surface. Nothing approved it yet, so
#    the answer is pending with the id a person decides.
ASK='{"purpose":"demo.read","resource":"provider:demo","target":"demo","ttl_seconds":600,"max_uses":1}'
broker health '{}'
ANSWER=$(broker capability_request "$ASK")
printf '%s\n' "$ANSWER"
REQUEST=$(field "$ANSWER" request_id)
[ -n "$REQUEST" ] || fail "capability_request filed no request"
[ "$(field "$ANSWER" status)" = pending ] || fail "expected a pending answer"
"$SB" request show "$REQUEST"

# 6. Approving needs the lifetime and the uses; there is no default.
if "$SB" request approve "$REQUEST" --by demo-owner --uses 1; then
  fail "approve without a lifetime was accepted"
fi
"$SB" request approve "$REQUEST" --by demo-owner --ttl-seconds 600 --uses 1

# 7. The agent learns the capability id through the same surface.
STATUS=$(broker access_request_status "{\"request_id\":\"$REQUEST\"}")
printf '%s\n' "$STATUS"
CAPABILITY=$(field "$STATUS" capability_id)
[ -n "$CAPABILITY" ] || fail "the approved request carries no capability"

# 8. The workload redeems it once, signing the request id into its proof.
redeem() {
  nonce=$(openssl rand -hex 16)
  payload="$DEMO_DIR/proof-payload.bin"
  printf 'SKARBIEC-WORKLOAD-PROOF\0v1\0%s\0%s\0%s\0redeem\0%s' \
    "$1" "$nonce" demo-workload "$2" >"$payload"
  proof=$(openssl pkeyutl -sign -inkey "$DEMO_DIR/workload-private.pem" -rawin -in "$payload" \
    | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  rm -f "$payload"
  printf '{"version":"skarbiec.redeem.v1","operation":"redeem","capability_id":"%s","nonce":"%s","workload_id":"demo-workload","proof":"%s","authorization_id":"%s"}\n' \
    "$1" "$nonce" "$proof" "$2" | nc -U "$SOCKET"
}
REDEEMED=$(redeem "$CAPABILITY" "$REQUEST")
printf '%s\n' "$REDEEMED"
printf '%s' "$REDEEMED" | grep -q 'demo-key-not-a-secret' || fail "redemption did not return the value"
if redeem "$CAPABILITY" "$REQUEST" | grep -q 'demo-key-not-a-secret'; then
  fail "a one-use capability was redeemed twice"
fi

# 9. A denied request issues nothing.
DENIED=$("$SB" request file --kind secret --resource provider:demo --action read \
  --purpose demo.read --target demo --ttl-seconds 600 --max-uses 1 \
  --agent demo-agent --harness example --reason "read the demo key again")
DENIED_ID=$(field "$DENIED" request_id)
"$SB" request deny "$DENIED_ID" --by demo-admin --reason "not needed"
[ "$(field "$("$SB" request show "$DENIED_ID")" state)" = denied ] || fail "deny did not close the request"
"$SB" request show "$DENIED_ID" | grep -q '"issued": null' || fail "a denied request issued a grant"
broker access_request_status "{\"request_id\":\"$DENIED_ID\"}"

# 10. Dual control: the owner's approval alone grants nothing, the same person
#     cannot approve twice, and a second decider issues the capability.
ROOT=$(broker capability_request \
  '{"purpose":"demo.read","resource":"provider:demo-root","target":"demo","ttl_seconds":600,"max_uses":1}')
ROOT_ID=$(field "$ROOT" request_id)
FIRST=$("$SB" request approve "$ROOT_ID" --by demo-owner --ttl-seconds 600 --uses 1)
printf '%s\n' "$FIRST"
[ "$(field "$FIRST" status)" = awaiting-second-decider ] || fail "one decider granted a dual-control item"
if "$SB" request approve "$ROOT_ID" --by demo-owner --ttl-seconds 600 --uses 1; then
  fail "the same decider approved twice"
fi
SECOND=$("$SB" request approve "$ROOT_ID" --by demo-admin --ttl-seconds 300 --uses 1)
printf '%s\n' "$SECOND"
[ "$(field "$SECOND" status)" = granted ] || fail "two deciders did not grant"

# 11. A colleague's host files through the loopback API, authorized by an
#     exact request:secret grant and by nothing else.
COLLEAGUE_TOKEN="$DEMO_DIR/colleague.token"
openssl rand -hex 32 >"$COLLEAGUE_TOKEN"
chmod u=rw,go= "$COLLEAGUE_TOKEN"
"$SB" grant issue colleague-host --capabilities request:secret --ttl-seconds 600 \
  --token-file "$COLLEAGUE_TOKEN"
COLLEAGUE=$("$SB" request file --to "$BASE" --consumer colleague-host --token-file "$COLLEAGUE_TOKEN" \
  --kind secret --resource demo-provider#api_key --action read --for-consumer colleague-reader \
  --agent colleague-agent --person colleague --reason "deploy the demo service")
printf '%s\n' "$COLLEAGUE"
COLLEAGUE_ID=$(field "$COLLEAGUE" request_id)
[ -n "$COLLEAGUE_ID" ] || fail "the colleague's request was not filed"
# The same grant does not let it ask for a device permission.
if "$SB" request file --to "$BASE" --consumer colleague-host --token-file "$COLLEAGUE_TOKEN" \
  --kind device --resource tama:hooks --action install --agent colleague-agent \
  --reason "install hooks" | grep -q request_id; then
  fail "a request:secret grant filed a device request"
fi
"$SB" request list --state pending

# 12. A standing grant: the owner approves until revoked, and the bearer is
#     written to an owner-only file the answer names, never printed.
APPROVED=$("$SB" request approve "$COLLEAGUE_ID" --by demo-owner --until-revoked)
printf '%s\n' "$APPROVED"
READER_TOKEN=$(field "$APPROVED" token_file)
"$SB" grant verify colleague-reader demo-provider --field api_key --token-file "$READER_TOKEN" \
  | grep -q '"allowed": true' || fail "the standing grant does not allow the read"

"$SB" audit list --op access-approved
printf '%s\n' "demo state: $DEMO_DIR"

# Verify: step 5 prints {"status":"pending","request_id":"<uuid>"} inside the
# MCP text item; step 7 {"request_id":"<uuid>","state":"approved",
# "capability_id":"<64 hex>"}; step 8 one control line with "status":"ok" and
# the demo value, and the second redemption is denied; step 9 the state
# "denied" with nothing issued; step 10 "awaiting-second-decider" and then
# "granted", the grant bounded by the narrower 300 seconds; step 11 a pending
# request filed by colleague-host.
#
# If it fails:
#
#   Error: demo-owner's secret key is not in this host's keyring
#     → a decider decides where their key is. The demo keeps both keys in
#       its own GNUPGHOME; on a real host run approve as the person.
#
#   Error: the broker surface is disabled: the operator must set
#   SKARBIEC_MCP_AGENT_ID
#     → the agent is the operator's statement, never a tool argument.
#
# Next: `skarbiec request watch --local --by <uid>` answers the same requests
# in a macOS dialog instead of on the command line.
