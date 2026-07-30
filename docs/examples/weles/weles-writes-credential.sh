#!/bin/sh
# weles-writes-credential.sh — a credential produced by Weles browser
# automation lands in the ONE vault (the acquire write-path).
#
# The production flow this mirrors:
#   Weles runs an acquire task (browser automation creates or refreshes a
#   credential), and stores the result into the vault
#   (storeSecretTarget: 'skarbiec'). The value flows from the automation's
#   private env into the vault item — no human and no agent ever sees it.
#   One vault holds operator and Weles items side by side; the scope is
#   the boundary, not the file.
#
# Usage:  sh weles-writes-credential.sh <skarbiec-port>
set -eu

VAULT="$HOME/.stado/brama-runtime-config/local.vault.json"
PORT=$1
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
ITEM=weles-newsite-login
CLIENT=weles-newsite-client
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

[ -f "$VAULT" ] || die "no vault: $VAULT"

echo "== step: automation-produced credential is written into the vault"
# In production these values come from the task's private env, not from
# literals — here they arrive through EXAMPLE_* env vars (demo defaults).
SKARBIEC_VAULT_FILE="$VAULT" "$SB" set "$ITEM" --type login \
  "login_email=${EXAMPLE_LOGIN_EMAIL:-newsite-auto@example.com}" \
  "login_password=${EXAMPLE_LOGIN_PASSWORD:-automation-generated}" \
  "created_via=weles-acquire" >/dev/null

echo "== step: grant the owning client a read scope for it"
TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CLIENT" --scopes "read:$ITEM" | awk -F'"' '/"token"/ {print $4; exit}')
[ -n "$TOKEN" ] || die "token-mint returned no token"
TOKEN_FILE="$HOME/.stado/$CLIENT-skarbiec-token"
CONFIG="$HOME/.config/stado/$CLIENT.json"
printf '%s' "$TOKEN" > "$TOKEN_FILE"; chmod u=rw,go= "$TOKEN_FILE"
jq -n --arg c "$CLIENT" --arg t "$TOKEN_FILE" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$CONFIG"
chmod u=rw,go= "$CONFIG"

echo "== step: the client reads the deposited credential back"
WC_SKARBIEC_URL="http://127.0.0.1:$PORT" STADO_CONFIG="$CONFIG" \
  "$STADO" secrets get "$ITEM"
