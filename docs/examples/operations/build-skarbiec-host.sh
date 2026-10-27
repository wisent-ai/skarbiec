#!/bin/sh
# build-skarbiec-host.sh — host with one exact direct capability and serve.
# Usage: SKARBIEC_BIN=<skarbiec binary> sh build-skarbiec-host.sh <vault-path> <port>
set -eu

export SKARBIEC_VAULT_FILE=$1
PORT=$2
SB=${SKARBIEC_BIN:?SKARBIEC_BIN must name the skarbiec binary this example runs}

"$SB" init 'skarbiec-host <host@example.com>'
printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"ready"},"context":{}}' \
  | "$SB" set health-note --type note
"$SB" grant issue local-operator --capabilities 'read:health-note' --until-revoked
"$SB" serve --port "$PORT" &
until curl -sf "http://localhost:$PORT/health" > /dev/null; do :; done
echo "host up on port $PORT"
