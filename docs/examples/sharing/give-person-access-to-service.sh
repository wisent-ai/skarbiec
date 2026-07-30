#!/bin/sh
# give-person-access-to-service.sh — lend a person access to ONE service
# (example: Supabase) from your vault, without ever copying the value.
#
# LEND vs GIVE:
#   - this script LENDS: the credential stays in YOUR vault, she borrows it
#     per call through a scoped grant, and you can switch her off any time
#     (token-revoke). Every read is auditable.
#   - for a durable offline copy in HER vault instead, use
#     sharing/share-credential-with-user.sh (the GIVE flow).
#
# Usage:  sh give-person-access-to-service.sh <skarbiec-port>
set -eu

VAULT="$HOME/.stado/brama-runtime-config/local.vault.json"
PORT=$1
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
CLIENT=zona
ITEMS="SUPABASE_URL SUPABASE_SERVICE_ROLE_KEY"
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

echo "== step: grant her a scope for exactly the Supabase items"
SCOPE_ARGS=""
for item in $ITEMS; do SCOPE_ARGS="$SCOPE_ARGS,read:$item"; done
TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CLIENT" --scopes "${SCOPE_ARGS#,}" | awk -F'"' '/"token"/ {print $4; exit}')
[ -n "$TOKEN" ] || die "token-mint returned no token"

TOKEN_FILE="$HOME/.stado/$CLIENT-skarbiec-token"
CONFIG="$HOME/.config/stado/$CLIENT.json"
printf '%s' "$TOKEN" > "$TOKEN_FILE"; chmod u=rw,go= "$TOKEN_FILE"
jq -n --arg c "$CLIENT" --arg t "$TOKEN_FILE" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$CONFIG"
chmod u=rw,go= "$CONFIG"

echo "== step: prove her grant reads Supabase…"
WC_SKARBIEC_URL="http://localhost:$PORT" STADO_CONFIG="$CONFIG" \
  "$STADO" secrets get SUPABASE_URL

echo "== step: …but nothing else (must fail)"
if WC_SKARBIEC_URL="http://localhost:$PORT" STADO_CONFIG="$CONFIG" \
     "$STADO" secrets get STRIPE_PRIVATE_KEY > /dev/null; then
  die "SCOPE BROKEN: grant reads outside Supabase"
else
  echo "  scope ok: her grant is Supabase-only"
fi

cat <<EOF

== handoff to her
  - copy to her machine: $TOKEN_FILE and $CONFIG
    (same-machine case: she just uses them against localhost:$PORT;
     remote case: tunnel per weles/remote-access-for-weles-host.sh)
  - her read:
    WC_SKARBIEC_URL=http://localhost:$PORT STADO_CONFIG=<path> stado secrets get SUPABASE_URL

== off-switch (when the access should end)
  SKARBIEC_VAULT_FILE="$VAULT" $SB token-revoke $CLIENT
EOF
