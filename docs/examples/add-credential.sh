#!/bin/sh
# add-credential.sh — add a credential manually, use it in code, lend it to an agent.
#
# The lifecycle this example demonstrates:
#   1. STORE   — the credential enters the vault via stdin (never inline,
#                never in shell history)
#   2. USE     — code never reads the value directly; it holds a
#                skarbiec:// reference and resolves it at call time
#   3. LEND    — an agent gets a grant for EXACTLY that one item and
#                nothing else
#
# Usage:  sh add-credential.sh <vault-path> <port>
#         (expects a vault from create-skarbiec.sh; creates a scratch one
#          when missing, so the example also runs standalone)
set -eu

VAULT=$1
PORT=$2
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
CONSUMER=local-operator
TOKEN_FILE="$HOME/.stado/$CONSUMER-skarbiec-token"
STADO_CONFIG="$HOME/.config/stado/$CONSUMER.json"
BASE_URL="http://127.0.0.1:$PORT"
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

# --- bootstrap: vault + serve must exist -----------------------------------
if [ ! -f "$VAULT" ]; then
  echo "== bootstrap: no vault at $VAULT — creating (same flow as create-skarbiec.sh)"
  SKARBIEC_VAULT_FILE="$VAULT" "$SB" init 'skarbiec-moj <moj@email.pl>' > /dev/null
fi
TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CONSUMER" --scopes 'read:*,write:*' | awk -F'"' '/"token"/ {print $4; exit}')
printf '%s' "$TOKEN" > "$TOKEN_FILE"; chmod u=rw,go= "$TOKEN_FILE"
mkdir -p "$HOME/.config/stado"
jq -n --arg c "$CONSUMER" --arg t "$TOKEN_FILE" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$STADO_CONFIG"
chmod u=rw,go= "$STADO_CONFIG"

SKARBIEC_VAULT_FILE="$VAULT" "$SB" serve --port "$PORT" > /dev/null &
SERVE_PID=$!
trap 'kill "$SERVE_PID" 2> /dev/null || true' EXIT
until curl -sf "$BASE_URL/health" > /dev/null; do :; done

# --- 1. STORE: manual add, value via stdin ---------------------------------
echo "== step: store the credential (value from EXAMPLE_VENDOR_KEY, demo default)"
printf '%s' "${EXAMPLE_VENDOR_KEY:-demo-key-not-real}" | \
  WC_SKARBIEC_URL="$BASE_URL" STADO_CONFIG="$STADO_CONFIG" \
  "$STADO" secrets put vendor-api

# --- 2. USE: code holds a reference, not the value --------------------------
echo "== step: code keeps only a reference and resolves at call time"
echo '    config:  {"vendor_key": "skarbiec://vendor-api/value"}'
echo "    resolution the consumer performs:"
WC_SKARBIEC_URL="$BASE_URL" STADO_CONFIG="$STADO_CONFIG" \
  "$STADO" secrets get vendor-api

# --- 3. LEND: a narrow grant for one agent ----------------------------------
echo "== step: lend exactly this item to an agent (scope: one read)"
AGENT=agent-demo
AGENT_TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$AGENT" --scopes 'read:vendor-api' | awk -F'"' '/"token"/ {print $4; exit}')
AGENT_TOKEN_FILE="$HOME/.stado/$AGENT-skarbiec-token"
AGENT_CONFIG="$HOME/.config/stado/$AGENT.json"
printf '%s' "$AGENT_TOKEN" > "$AGENT_TOKEN_FILE"; chmod u=rw,go= "$AGENT_TOKEN_FILE"
jq -n --arg c "$AGENT" --arg t "$AGENT_TOKEN_FILE" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$AGENT_CONFIG"
chmod u=rw,go= "$AGENT_CONFIG"

echo "    agent reads the lent item:"
WC_SKARBIEC_URL="$BASE_URL" STADO_CONFIG="$AGENT_CONFIG" \
  "$STADO" secrets get vendor-api

echo "    agent reads anything else (must fail):"
if WC_SKARBIEC_URL="$BASE_URL" STADO_CONFIG="$AGENT_CONFIG" \
     "$STADO" secrets get moja-usluga > /dev/null; then
  die "SCOPE BROKEN: agent read an item outside its grant"
else
  echo "    scope ok: agent is limited to vendor-api"
fi
