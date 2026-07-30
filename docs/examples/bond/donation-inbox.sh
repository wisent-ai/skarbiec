#!/bin/sh
# donation-inbox.sh — the bond v2 review flow: donations land in the
# remote inbox as pending; the owner accepts or rejects.
#
# Usage:  sh donation-inbox.sh <donor-vault> <item> <remote-base-url> <donate-token>
set -eu

VAULT=$1
ITEM=$2
REMOTE=$3
TOKEN=$4
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

echo "== step: donate $ITEM to $REMOTE (lands as pending, not merged)"
OUT=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" donate "$ITEM" \
  --to "$REMOTE" --consumer donor --token "$TOKEN")
echo "$OUT"
DONATION_ID=$(echo "$OUT" | jq -r '.donation_id // empty')
[ -n "$DONATION_ID" ] || die "no donation_id in response"

echo "== step: owner lists the pending inbox"
SKARBIEC_VAULT_FILE="$SKARBIEC_REMOTE_VAULT" "$SB" donations

echo "== step: owner accepts the donation"
SKARBIEC_VAULT_FILE="$SKARBIEC_REMOTE_VAULT" "$SB" donation-accept "$DONATION_ID"

echo "== verify: the item now exists in the remote vault"
SKARBIEC_VAULT_FILE="$SKARBIEC_REMOTE_VAULT" "$SB" get "$ITEM"
