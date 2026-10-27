#!/bin/sh
# create-skarbiec.sh — create a vault, put a secret in, read it back.
# Nothing but the commands themselves. Run: sh create-skarbiec.sh
set -eu

export SKARBIEC_VAULT_FILE=~/.skarbiec-moj.vault.json

skarbiec init 'skarbiec-moj <me@example.com>'
skarbiec set moja-usluga --type login username=me@example.com password="$EXAMPLE_SECRET"
skarbiec get moja-usluga
skarbiec status
