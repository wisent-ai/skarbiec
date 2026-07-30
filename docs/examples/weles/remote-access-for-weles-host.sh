#!/bin/sh
# remote-access-for-weles-host.sh — give Weles on ANOTHER host (mac-mini)
# access to the skarbiec served HERE.
#
# Design fact: skarbiec serve binds loopback only — there is no port to
# open. Remote access always rides an encrypted tunnel; the vault file
# itself never leaves this machine. Two sanctioned paths:
#
#   A) secure tunnel host-to-host (private, simplest):
#        mac-mini forwards this host's loopback port to its own loopback
#        and dials it with its scoped consumer grant.
#   B) cloudflared edge (public TLS, the fleet pattern):
#        cloudflared here exposes the loopback serve as https://<name>;
#        Weles dials that URL with its grant.
#
# This script does the THIS-HOST side end to end and prints the exact
# mac-mini side.
#
# Usage:  sh remote-access-for-weles-host.sh <skarbiec-port> [scopes-csv]
# Example: sh remote-access-for-weles-host.sh 8786 'read:weles-*'
set -eu

VAULT="$HOME/.stado/brama-runtime-config/local.vault.json"
PORT=$1
if [ $# -gt 1 ]; then
  SCOPES=$2
else
  SCOPES='read:*'
fi
SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}
CLIENT=weles-mz
BUNDLE="$HOME/.stado/weles-mz-bundle"
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

echo "== step: mint a scoped grant for the remote weles consumer"
TOKEN=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" token-mint "$CLIENT" --scopes "$SCOPES" | awk -F'"' '/"token"/ {print $4; exit}')
[ -n "$TOKEN" ] || die "token-mint returned no token"

echo "== step: bundle token + stado config for transfer"
mkdir -p "$BUNDLE"
printf '%s' "$TOKEN" > "$BUNDLE/$CLIENT-skarbiec-token"
chmod u=rw,go= "$BUNDLE/$CLIENT-skarbiec-token"
jq -n --arg c "$CLIENT" --arg t "$HOME/.stado/$CLIENT-skarbiec-token" \
  '{secrets:{skarbiec:{consumer:$c, token_file:$t}}}' > "$BUNDLE/$CLIENT.json"
chmod u=rw,go= "$BUNDLE/$CLIENT.json"
echo "  bundle: $BUNDLE/ ($CLIENT-skarbiec-token, $CLIENT.json)"

echo "== step: prove the grant works on this host"
printf '%s' "$TOKEN" > "$HOME/.stado/$CLIENT-skarbiec-token"; chmod u=rw,go= "$HOME/.stado/$CLIENT-skarbiec-token"
cp "$BUNDLE/$CLIENT.json" "$HOME/.config/stado/$CLIENT.json"
WC_SKARBIEC_URL="http://localhost:$PORT" STADO_CONFIG="$HOME/.config/stado/$CLIENT.json" \
  "$STADO" secrets ls > /dev/null && echo "  grant ok: consumer reads through port $PORT"

cat <<EOF

== mac-mini side (run there)
# path A — secure tunnel host-to-host:
scp -i <key> $USER@$(hostname -s).local:$BUNDLE/\* ~/.stado/
#   then, persistently (e.g. autossh/launchd):
#   forward localhost:$PORT on mac-mini to localhost:$PORT here
export WC_SKARBIEC_URL=http://localhost:$PORT
export STADO_CONFIG=~/.config/stado/$CLIENT.json
stado secrets get <item>

# path B — cloudflared edge:
#   here: cloudflared tunnel --url http://localhost:$PORT (quick tunnel)
#   mac-mini: WC_SKARBIEC_URL=https://<trycloudflare-name> stado secrets get <item>
EOF
