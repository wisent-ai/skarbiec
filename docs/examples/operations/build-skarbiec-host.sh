#!/bin/sh
# build-skarbiec-host.sh — build a complete skarbiec host from zero.
#
# A host = vault file + grants + serve. After this script the machine can
# act as a bond source: replicas can `skarbiec pull` from it, consumers
# can read items through stado secrets.
#
# Usage:  sh build-skarbiec-host.sh <vault-path> <port> [owner-uid]
set -eu

VAULT=$1
PORT=$2
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
if [ $# -gt 2 ]; then
  OWNER_UID=$3
else
  OWNER_UID='skarbiec-host <host@example.com>'
fi
CONSUMER=local-operator
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

echo "== step: init the vault at $VAULT"
[ -f "$VAULT" ] && die "already exists: $VAULT"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" init "$OWNER_UID" > /dev/null

echo "== step: grants — sync:pull for replicas, read/write for the operator"
SYNC_TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint replica-sync --scopes 'sync:pull' | awk -F'"' '/"token"/ {print $4; exit}')
[ -n "$SYNC_TOKEN" ] || die "sync:pull mint failed"
printf '%s' "$SYNC_TOKEN" > "$VAULT.replica-sync-token"; chmod u=rw,go= "$VAULT.replica-sync-token"

TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CONSUMER" --scopes 'read:*,write:*' | awk -F'"' '/"token"/ {print $4; exit}')
printf '%s' "$TOKEN" > "$HOME/.stado/$CONSUMER-skarbiec-token"; chmod u=rw,go= "$HOME/.stado/$CONSUMER-skarbiec-token"
mkdir -p "$HOME/.config/stado"
jq -n --arg c "$CONSUMER" --arg t "$HOME/.stado/$CONSUMER-skarbiec-token" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$HOME/.config/stado/$CONSUMER.json"
chmod u=rw,go= "$HOME/.config/stado/$CONSUMER.json"

echo "== step: serve on loopback port $PORT"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" serve --port "$PORT" > /dev/null &
SERVE_PID=$!
trap 'kill "$SERVE_PID" > /dev/null || true' EXIT
until curl -sf "http://localhost:$PORT/health" > /dev/null; do :; done

echo "== verify: host answers and serves its grant surface"
WC_SKARBIEC_URL="http://localhost:$PORT" STADO_CONFIG="$HOME/.config/stado/$CONSUMER.json" \
  "$STADO" secrets ls
echo "host built: vault=$VAULT serve=http://localhost:$PORT replica-token=$VAULT.replica-sync-token"
