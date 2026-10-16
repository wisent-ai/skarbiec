#!/bin/sh
# change-skarbiec-host.sh — move a vault to a new host with the pull
# primitive. Grants travel with the file, so consumers keep working.
# Usage: sh change-skarbiec-host.sh <old-base-url> <sync-token-file> <new-vault> <new-port>
# The sync bearer is read from an owner-only file (mode 0600) at an absolute
# path; pull refuses a bearer on the command line.
set -eu

export SKARBIEC_VAULT_FILE=$3

skarbiec pull --from "$1" --token-file "$2" --consumer replica-sync
echo "pulled $3; serving it on port $4"
exec skarbiec serve --port "$4"
