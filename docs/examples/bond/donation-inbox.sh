#!/bin/sh
# donation-inbox.sh — donate an item, then review it in the remote inbox.
# Usage: sh donation-inbox.sh <donor-vault> <item> <remote-base-url> <donate-token>
set -eu

export SKARBIEC_VAULT_FILE=$1
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" donate "$2" --to "$3" --consumer donor --token "$4"

# owner side, on the remote vault:
SKARBIEC_VAULT_FILE="$SKARBIEC_REMOTE_VAULT" "$SB" donations
