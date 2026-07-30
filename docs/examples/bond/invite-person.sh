#!/bin/sh
# invite-person.sh — one redeemable package for a human, secret never in it.
# Usage: sh invite-person.sh <vault> <item> <for-consumer>
set -eu

export SKARBIEC_VAULT_FILE=$1
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" invite "$2" --for "$3"
