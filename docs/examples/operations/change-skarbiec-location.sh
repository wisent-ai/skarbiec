#!/bin/sh
# change-skarbiec-location.sh — migrate the served vault to a new host
# endpoint and prove consumers keep working.
# This preserves already-deployed direct grants during migration; it does not
# prescribe direct grants for a new workload.
#
# Why this works at all:
#   A vault is one ciphertext file, and the consumer grants (hashed tokens
#   + scopes) live INSIDE that file. Moving the file moves the grants.
#   The consumer's token file and config never change — only the URL the
#   consumer dials (WC_SKARBIEC_URL, or the launchd service's endpoint).
#   Key material (owner/recovery private keys) never travels in this flow;
#   the new host needs it separately (imported out of band, see
#   sharing/share-credential-with-user.sh for the transport pattern).
#
# Demo topology (one machine, two endpoints standing in for two hosts):
#   OLD host: skarbiec serve on port $2, serving vault $1
#   NEW host: skarbiec serve on port $3, serving a copy of the same file
#
# Usage:  sh change-skarbiec-location.sh <vault-path> <old-port> <new-port>
#         (expects a served vault with an item + consumer grant, e.g. from
#          add-credential.sh; bootstraps a scratch one when missing)
set -eu

VAULT=$1
OLD_PORT=$2
NEW_PORT=$3
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
CONSUMER=local-operator
TOKEN_FILE="$HOME/.stado/$CONSUMER-skarbiec-token"
STADO_CONFIG="$HOME/.config/stado/$CONSUMER.json"
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

# --- bootstrap: vault + item + grant if missing -----------------------------
if [ ! -f "$VAULT" ]; then
  echo "== bootstrap: scratch vault at $VAULT"
  SKARBIEC_VAULT_FILE="$VAULT" "$SB" init 'skarbiec-moj <moj@email.pl>' > /dev/null
  SKARBIEC_VAULT_FILE="$VAULT" "$SB" set moja-usluga --type secret \
    "value=${EXAMPLE_SECRET:-example-value}" >/dev/null
fi
TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CONSUMER" --scopes 'read:*,write:*' | awk -F'"' '/"token"/ {print $4; exit}')
printf '%s' "$TOKEN" > "$TOKEN_FILE"; chmod u=rw,go= "$TOKEN_FILE"
mkdir -p "$HOME/.config/stado"
jq -n --arg c "$CONSUMER" --arg t "$TOKEN_FILE" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$STADO_CONFIG"
chmod u=rw,go= "$STADO_CONFIG"

# --- OLD host comes up ------------------------------------------------------
echo "== step: OLD host serving on loopback port $OLD_PORT"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" serve --port "$OLD_PORT" > /dev/null &
OLD_PID=$!
trap 'kill "$OLD_PID" "$NEW_PID" > /dev/null || true' EXIT
until curl -sf "http://127.0.0.1:$OLD_PORT/health" > /dev/null; do :; done
echo "    consumer reads item via OLD host:"
WC_SKARBIEC_URL="http://127.0.0.1:$OLD_PORT" STADO_CONFIG="$STADO_CONFIG" \
  "$STADO" secrets get moja-usluga

# --- migration: file travels, serve flips -----------------------------------
echo "== step: copy the vault file to the NEW host location"
NEW_VAULT="$VAULT.migrated"
cp "$VAULT" "$NEW_VAULT"
kill "$OLD_PID" > /dev/null || true
echo "    OLD host stopped"

echo "== step: NEW host serving the copy on loopback port $NEW_PORT"
SKARBIEC_VAULT_FILE="$NEW_VAULT" "$SB" serve --port "$NEW_PORT" > /dev/null &
NEW_PID=$!
until curl -sf "http://127.0.0.1:$NEW_PORT/health" > /dev/null; do :; done

echo "    SAME consumer token reads item via NEW host (grant traveled with the file):"
WC_SKARBIEC_URL="http://127.0.0.1:$NEW_PORT" STADO_CONFIG="$STADO_CONFIG" \
  "$STADO" secrets get moja-usluga

echo "    OLD endpoint must be closed:"
if curl -sf "http://127.0.0.1:$OLD_PORT/health" > /dev/null; then
  die "OLD endpoint still answering — migration incomplete"
else
  echo "    old endpoint closed ok"
fi
