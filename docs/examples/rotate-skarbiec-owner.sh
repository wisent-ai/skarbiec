#!/bin/sh
# rotate-skarbiec-owner.sh — safe owner rotation: backup first, then
# owner rotate, then verify the vault still opens.
# Usage: SKARBIEC_BIN=<skarbiec binary> sh rotate-skarbiec-owner.sh <vault> <old-owner-uid> <new-owner-uid>
set -eu

VAULT=$1
OLD_UID=$2
NEW_UID=$3
SB=${SKARBIEC_BIN:?SKARBIEC_BIN must name the skarbiec binary that rotates the owner}

# backup the ciphertext before touching anything
cp "$VAULT" "$VAULT.backup"

# successor key into the keyring (skarbiec makes the right key type)
SKARBIEC_VAULT_FILE="$VAULT" "$SB" recipient add "$NEW_UID"

# the atomic rotation
SKARBIEC_VAULT_FILE="$VAULT" "$SB" owner rotate "$NEW_UID"

# verify the vault still opens
SKARBIEC_VAULT_FILE="$VAULT" "$SB" list
SKARBIEC_VAULT_FILE="$VAULT" "$SB" recovery status
