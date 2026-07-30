#!/bin/sh
# create-skarbiec.sh — create a vault, put a secret in, read it back.
# Nothing but the commands themselves. Run: sh create-skarbiec.sh

export SKARBIEC_VAULT_FILE=~/.skarbiec-moj.vault.json
SB=${SKARBIEC_BIN:-skarbiec}

"$SB" init 'skarbiec-moj <moj@email.pl>'
"$SB" set moja-usluga --type login login_email=moj@email.pl login_password="$EXAMPLE_SECRET"
"$SB" get moja-usluga
"$SB" status
