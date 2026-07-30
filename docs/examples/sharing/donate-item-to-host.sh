#!/bin/sh
# donate-item-to-host.sh — the p2p donation path: write one item into a
# REMOTE vault without any file transfer.
#
# The donor reads an item from its own vault, encrypts it to the remote
# owner's public key (fetched from the remote serve), and POSTs it to the
# remote donations endpoint with a donate-scoped grant. The remote merges
# it (new ids only — a repeat is rejected with status "exists").
#
# Usage:  sh donate-item-to-host.sh <local-vault> <item-id> <remote-base-url> <donate-token>
set -eu

VAULT=$1
ITEM=$2
REMOTE=$3
DONATE_TOKEN=$4
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

[ -f "$VAULT" ] || die "no local vault: $VAULT"

echo "== step: donate $ITEM to $REMOTE"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" donate "$ITEM" \
  --to "$REMOTE" --consumer donor --token "$DONATE_TOKEN"

echo "== step: repeat the same donation (must be rejected as exists)"
STATUS=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" donate "$ITEM" \
  --to "$REMOTE" --consumer donor --token "$DONATE_TOKEN" | jq -r '.status // empty')
if [ "$STATUS" = "exists" ]; then
  echo "  repeat correctly rejected with status exists"
else
  die "repeat donation was not rejected (status: $STATUS)"
fi
