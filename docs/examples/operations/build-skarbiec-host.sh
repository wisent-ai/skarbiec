#!/bin/sh
# build-skarbiec-host.sh — vault + grants + serve = a complete host.
# Usage: sh build-skarbiec-host.sh <vault-path> <port>
set -eu

export SKARBIEC_VAULT_FILE=$1
PORT=$2
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" init 'skarbiec-host <host@example.com>'
"$SB" token-mint replica-sync --scopes 'sync:pull'
"$SB" token-mint local-operator --scopes 'read:*,write:*'
"$SB" serve --port "$PORT" &
until curl -sf "http://localhost:$PORT/health" > /dev/null; do :; done
echo "host up on port $PORT"
