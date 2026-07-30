#!/bin/sh
# give-credential-to-weles.sh — hand Weles a credential from the ONE vault,
# in the exact shape its consumers expect.
#
# One vault, many trust boundaries:
#   vault:    ~/.stado/brama-runtime-config/local.vault.json  (THE vault —
#             operator and Weles items live side by side; there is no
#             separate weles vault anymore)
#   contract: item weles-<vendor>-api  <->  consumer weles-<vendor>-client
#             (the scope, not the file, is the boundary)
#
# Flow: write the credential into the vault, grant the matching client a
# read scope for exactly that item, prove it reads only that one.
#
# Usage:  sh give-credential-to-weles.sh <skarbiec-port>
set -eu

VAULT="$HOME/.stado/brama-runtime-config/local.vault.json"
PORT=$1
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
ITEM=weles-demo-api
CLIENT=weles-demo-client
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

[ -f "$VAULT" ] || die "no vault: $VAULT"

echo "== step: write the credential into the vault (value via env, never inline)"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" set "$ITEM" --type api \
  "api_key=${EXAMPLE_VENDOR_KEY:-demo-key-not-real}" \
  "note=handed to weles by give-credential-to-weles.sh" >/dev/null

echo "== step: grant the weles client a read scope for exactly this item"
TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CLIENT" --scopes "read:$ITEM" | awk -F'"' '/"token"/ {print $4; exit}')
[ -n "$TOKEN" ] || die "token-mint returned no token"
TOKEN_FILE="$HOME/.stado/$CLIENT-skarbiec-token"
CONFIG="$HOME/.config/stado/$CLIENT.json"
printf '%s' "$TOKEN" > "$TOKEN_FILE"; chmod u=rw,go= "$TOKEN_FILE"
jq -n --arg c "$CLIENT" --arg t "$TOKEN_FILE" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$CONFIG"
chmod u=rw,go= "$CONFIG"

echo "== step: the weles client consumer reads the credential"
WC_SKARBIEC_URL="http://127.0.0.1:$PORT" STADO_CONFIG="$CONFIG" \
  "$STADO" secrets get "$ITEM"

echo "== step: the same client reads anything else (must fail)"
if WC_SKARBIEC_URL="http://127.0.0.1:$PORT" STADO_CONFIG="$CONFIG" \
     "$STADO" secrets get weles-database > /dev/null; then
  die "SCOPE BROKEN: weles client read an item outside its grant"
else
  echo "  scope ok: weles client is limited to $ITEM"
fi
