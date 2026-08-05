#!/bin/sh
# enroll-replica.sh — onboard a replica onto a source host in one handshake.
# Usage: sh enroll-replica.sh <source-base-url> <enroll:replica-uid-token> <replica-vault> <replica-uid> <items-csv>
set -eu

export SKARBIEC_VAULT_FILE=$3
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" enroll --as "$4" --to "$1" --token "$2" --items "$5"
