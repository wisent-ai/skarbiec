#!/bin/sh
# change-skarbiec-host.sh — migrate a vault to a new host with the bond
# pull primitive (no manual file copy).
#
# The new host pulls the ciphertext from the old serve with a sync:pull
# token, serves it itself, and the SAME consumer grant keeps working —
# grants live inside the vault file, so they travel with the pull.
#
# Usage:  sh change-skarbiec-host.sh <old-base-url> <sync-token> <new-vault> <new-port> [sync-consumer]
set -eu

OLD_URL=$1
SYNC_TOKEN=$2
NEW_VAULT=$3
NEW_PORT=$4
if [ $# -gt 4 ]; then
  SYNC_CONSUMER=$5
else
  SYNC_CONSUMER=replica-sync
fi
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
CONSUMER=local-operator
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

echo "== step: pull the vault from $OLD_URL into $NEW_VAULT"
SKARBIEC_VAULT_FILE="$NEW_VAULT" "$SB" pull --from "$OLD_URL" --token "$SYNC_TOKEN" --consumer "$SYNC_CONSUMER"

echo "== step: serve the pulled vault on loopback port $NEW_PORT"
SKARBIEC_VAULT_FILE="$NEW_VAULT" "$SB" serve --port "$NEW_PORT" > /dev/null &
SERVE_PID=$!
trap 'kill "$SERVE_PID" > /dev/null || true' EXIT
until curl -sf "http://localhost:$NEW_PORT/health" > /dev/null; do :; done

echo "== verify: the operator grant (traveled with the file) reads via the new host"
WC_SKARBIEC_URL="http://localhost:$NEW_PORT" STADO_CONFIG="$HOME/.config/stado/$CONSUMER.json" \
  "$STADO" secrets ls
echo "host changed: now serving from $NEW_VAULT on port $NEW_PORT"
