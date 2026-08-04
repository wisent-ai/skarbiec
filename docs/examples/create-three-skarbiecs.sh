#!/bin/sh
# create-three-skarbiecs.sh — three independent vaults, isolation proof.
# Nothing but the commands themselves. Run: sh create-three-skarbiecs.sh
set -eu

SB=${SKARBIEC_BIN:-skarbiec}

SKARBIEC_VAULT_FILE=~/.skarbiec-osobisty.vault.json "$SB" init 'skarbiec-osobisty <moj@email.pl>'
SKARBIEC_VAULT_FILE=~/.skarbiec-zespol.vault.json   "$SB" init 'skarbiec-zespol <moj@email.pl>'
SKARBIEC_VAULT_FILE=~/.skarbiec-maszynowy.vault.json "$SB" init 'skarbiec-maszynowy <moj@email.pl>'

SKARBIEC_VAULT_FILE=~/.skarbiec-osobisty.vault.json "$SB" set konto-bank --type login username=moj@email.pl password="$EXAMPLE_SECRET"

# isolation proof: the item exists in one vault, not in the others
SKARBIEC_VAULT_FILE=~/.skarbiec-osobisty.vault.json "$SB" get konto-bank --field username
SKARBIEC_VAULT_FILE=~/.skarbiec-zespol.vault.json   "$SB" get konto-bank || echo "ok: zespol cannot see konto-bank"
SKARBIEC_VAULT_FILE=~/.skarbiec-maszynowy.vault.json "$SB" get konto-bank || echo "ok: maszynowy cannot see konto-bank"
