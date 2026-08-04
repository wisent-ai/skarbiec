#!/bin/sh
# build-skarbiec-host.sh — host with one exact direct capability and serve.
# Usage: sh build-skarbiec-host.sh <vault-path> <port>
set -eu

export SKARBIEC_VAULT_FILE=$1
PORT=$2
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" init 'skarbiec-host <host@example.com>'
"$SB" set health-note --type note value=ready
"$SB" token-mint local-operator --capabilities 'read:health-note'
"$SB" serve --port "$PORT" &
until curl -sf "http://localhost:$PORT/health" > /dev/null; do :; done
echo "host up on port $PORT"
