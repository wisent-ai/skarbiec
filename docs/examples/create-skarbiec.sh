#!/bin/sh
# create-skarbiec.sh — from zero to a stado-managed vault.
#
# WHERE A VAULT BELONGS (read before running):
#   A vault is meant to live BEHIND A SERVICE, not as a loose file. So the
#   location is a decision, not a detail:
#     - operator vault (the one stado/consumers use daily):
#         ~/.stado/skarbiec.vault.json
#       That is the path the launchd service `com.wisent.skarbiec` serves
#       (SKARBIEC_VAULT_FILE in its plist) and the path consumer configs
#       resolve to. Create there, then point the service at it.
#     - scratch/demo vault (this example's default):
#         a path of your choice + your own `skarbiec serve` on a port.
#   Never create "the real one" at a random path — a vault nobody serves
#   is a vault nobody uses.
#
# The flow:
#   1. create the vault file        (skarbiec init — vault creation has no
#                                    stado equivalent; stado manages items
#                                    INSIDE an existing vault)
#   2. mint a consumer grant        (so `stado secrets` is authorized)
#   3. serve THIS vault             (skarbiec serve on the port you pass —
#                                    stado talks to skarbiec over HTTP)
#   4. store + read items           (stado secrets put / get / ls)
#
# Usage:  sh create-skarbiec.sh <vault-path> <port>
#
# Where everything lands:
#   vault:           the path you pass as $1 (one JSON file — see above for
#                    which path to choose)
#   consumer token:  ~/.stado/local-operator-skarbiec-token
#   stado config:    ~/.config/stado/local-operator.json
#   skarbiec serve:  loopback, the port you pass as $2
set -eu

VAULT=$1
PORT=$2
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
CONSUMER=local-operator
TOKEN_FILE="$HOME/.stado/$CONSUMER-skarbiec-token"
STADO_CONFIG="$HOME/.config/stado/$CONSUMER.json"
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

echo "== step: create the vault at: $VAULT"
[ -f "$VAULT" ] && die "already exists: $VAULT"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" init 'skarbiec-moj <moj@email.pl>'

echo "== step: mint a read+write grant for the consumer"
TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CONSUMER" --scopes 'read:*,write:*' | awk -F'"' '/"token"/ {print $4; exit}')
[ -n "$TOKEN" ] || die "token-mint returned no token"
printf '%s' "$TOKEN" > "$TOKEN_FILE"
chmod u=rw,go= "$TOKEN_FILE"

echo "== step: write the stado consumer config"
mkdir -p "$HOME/.config/stado"
jq -n --arg c "$CONSUMER" --arg t "$TOKEN_FILE" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$STADO_CONFIG"
chmod u=rw,go= "$STADO_CONFIG"

echo "== step: serve this vault on loopback port $PORT"
echo "    (for the operator vault this is the launchd service's job —"
echo "     point com.wisent.skarbiec's SKARBIEC_VAULT_FILE at the same path)"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" serve --port "$PORT" > /dev/null &
SERVE_PID=$!
trap 'kill "$SERVE_PID" 2> /dev/null || true' EXIT
until curl -sf "http://127.0.0.1:$PORT/health" > /dev/null; do :; done

echo "== step: store the first item (value via stdin, never inline)"
printf '%s' "${EXAMPLE_SECRET:-example-value}" | \
  WC_SKARBIEC_URL="http://127.0.0.1:$PORT" STADO_CONFIG="$STADO_CONFIG" \
  "$STADO" secrets put moja-usluga

echo "== step: list + read-back"
WC_SKARBIEC_URL="http://127.0.0.1:$PORT" STADO_CONFIG="$STADO_CONFIG" "$STADO" secrets ls
WC_SKARBIEC_URL="http://127.0.0.1:$PORT" STADO_CONFIG="$STADO_CONFIG" "$STADO" secrets get moja-usluga
