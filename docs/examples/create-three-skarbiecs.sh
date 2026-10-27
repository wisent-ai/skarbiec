#!/bin/sh
# create-three-skarbiecs.sh — three independent vaults, isolation proof.
# Nothing but the commands themselves. Run: sh create-three-skarbiecs.sh
set -eu

SKARBIEC_VAULT_FILE=~/.skarbiec-osobisty.vault.json skarbiec init 'skarbiec-osobisty <me@example.com>'
SKARBIEC_VAULT_FILE=~/.skarbiec-zespol.vault.json skarbiec init 'skarbiec-zespol <me@example.com>'
SKARBIEC_VAULT_FILE=~/.skarbiec-maszynowy.vault.json skarbiec init 'skarbiec-maszynowy <me@example.com>'

SKARBIEC_VAULT_FILE=~/.skarbiec-osobisty.vault.json skarbiec set konto-bank --type login username=me@example.com password="$EXAMPLE_SECRET"

# isolation proof: the item exists in one vault, and reading it from the others is refused
SKARBIEC_VAULT_FILE=~/.skarbiec-osobisty.vault.json skarbiec get konto-bank --field username
if SKARBIEC_VAULT_FILE=~/.skarbiec-zespol.vault.json skarbiec get konto-bank; then
  echo "zespol can see konto-bank: the vaults are not isolated" >&2
  false
fi
if SKARBIEC_VAULT_FILE=~/.skarbiec-maszynowy.vault.json skarbiec get konto-bank; then
  echo "maszynowy can see konto-bank: the vaults are not isolated" >&2
  false
fi
echo "ok: only osobisty holds konto-bank"
