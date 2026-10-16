#!/bin/sh
# enroll-replica.sh — onboard a replica onto a source host in one handshake.
# Usage: sh enroll-replica.sh <source-base-url> <enroll-token-file> <replica-vault> <replica-uid> <items-csv>
# The enroll bearer is read from an owner-only file (mode 0600) at an absolute
# path; enroll refuses a bearer on the command line.
set -eu

export SKARBIEC_VAULT_FILE=$3

skarbiec enroll --as "$4" --to "$1" --token-file "$2" --items "$5"
