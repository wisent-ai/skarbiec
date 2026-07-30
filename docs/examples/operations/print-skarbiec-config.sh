#!/bin/sh
# print-skarbiec-config.sh — dump the complete skarbiec configuration,
# never a secret value.
#
# Prints: vault path + item count, owner + recipients, recovery status,
# consumer tokens with scopes (names and scopes only), SKARBIEC_* env,
# consumer configs, launchd services.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}
VAULT=${SKARBIEC_VAULT_FILE:-"$HOME/.stado/brama-runtime-config/local.vault.json"}

echo "== vault"
echo "  path: $VAULT"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" list | jq -r '"  items: \(length)"'

echo
echo "== recipients (who can open the vault)"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" users

echo
echo "== recovery"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" recovery-status

echo
echo "== consumer tokens (names + scopes, never values)"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" tokens

echo
echo "== environment"
env | awk -F= '$1 ~ /^SKARBIEC_/ {print "  " $1 "=" $2}'

echo
echo "== consumer configs"
for f in "$HOME"/.config/stado/*.json; do
  [ -f "$f" ] && jq -r '"  " + input_filename + " -> consumer " + .secrets.skarbiec.consumer' "$f"
done

echo
echo "== launchd services"
launchctl list | awk '$3 ~ /skarbiec/ {print "  " $1, $3}'
