#!/bin/sh
# donation-inbox.sh — donate an item, then review it in the remote inbox.
# Usage: sh donation-inbox.sh <donor-vault> <item> <remote-base-url> <donate-token-file> <remote-vault>
# The donate bearer is read from an owner-only file (mode 0600) at an absolute
# path; donate refuses a bearer on the command line.
set -eu

export SKARBIEC_VAULT_FILE=$1

skarbiec donate "$2" --to "$3" --consumer donor --token-file "$4"

# owner side, on the remote vault:
SKARBIEC_VAULT_FILE="$5" skarbiec donations
