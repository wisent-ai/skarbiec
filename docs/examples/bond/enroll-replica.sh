#!/bin/sh
# enroll-replica.sh — onboard a replica onto a source host with the bond
# enroll handshake (replaces manual add-user + share).
#
# The replica presents its public key to the source's enroll endpoint; the
# source adds it as a member recipient and re-seals the listed items to
# it. Then a plain pull gives the replica exactly those items.
#
# Usage:  sh enroll-replica.sh <source-base-url> <enroll-token> <replica-vault> <replica-uid> <items-csv>
set -eu

URL=$1
TOKEN=$2
VAULT=$3
UID_=$4
ITEMS=$5
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

[ -f "$VAULT" ] || die "no replica vault: $VAULT (run create-skarbiec.sh first)"

echo "== step: enroll $UID_ into $URL for items: $ITEMS"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" enroll --as "$UID_" --to "$URL" \
  --token "$TOKEN" --items "$ITEMS"
