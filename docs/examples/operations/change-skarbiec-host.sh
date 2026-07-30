#!/bin/sh
# change-skarbiec-host.sh — move a vault to a new host with the pull
# primitive. Grants travel with the file, so consumers keep working.
# Usage: sh change-skarbiec-host.sh <old-base-url> <sync-token> <new-vault> <new-port>
set -eu

export SKARBIEC_VAULT_FILE=$3
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" pull --from "$1" --token "$2" --consumer replica-sync
"$SB" serve --port "$4" &
until curl -sf "http://localhost:$4/health" > /dev/null; do :; done
echo "host changed: serving $3 on port $4"
