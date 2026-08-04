#!/bin/sh
# invite-person.sh — one workload-bound redemption contract, secret never in it.
# Usage: sh invite-person.sh <vault> <item> <field> <for-consumer> <workload-public-key-file>
set -eu

export SKARBIEC_VAULT_FILE=$1
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" invite "$2" --field "$3" --for "$4" --workload-public-key-file "$5"
