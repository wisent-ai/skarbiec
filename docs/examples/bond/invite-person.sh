#!/bin/sh
# invite-person.sh — one redeemable package for a human: bootstrap token
# + redeem instructions, never the secret itself.
#
# Usage:  sh invite-person.sh <vault> <item> <for-consumer>
set -eu

VAULT=$1
ITEM=$2
FOR=$3
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

[ -f "$VAULT" ] || die "no vault: $VAULT"

echo "== step: build the invite package (contains NO secret value)"
PKG=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" invite "$ITEM" --for "$FOR")
echo "$PKG" | jq '{item, field, consumer, redeem}'
BOOT=$(echo "$PKG" | jq -r '.bootstrap_token // empty')
[ -n "$BOOT" ] || die "invite produced no bootstrap token"

echo "== step: the person redeems it (one-shot field access)"
ISSUED=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" acquisition-request "$FOR" "$ITEM" value --token "$BOOT" | jq -r '.token // empty')
[ -n "$ISSUED" ] || die "acquisition-request failed"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" acquisition-read "$FOR" "$ITEM" value --token "$ISSUED"

echo "== verify: a second read with the same token is refused"
SECOND=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" acquisition-read "$FOR" "$ITEM" value --token "$ISSUED" | jq -r '.ok')
if [ "$SECOND" = "false" ]; then
  echo "  single-use ok: token consumed"
else
  die "single-use token worked twice"
fi
