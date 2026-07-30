#!/bin/sh
# share-credential-with-user.sh — give a credential to ANOTHER USER,
# so it lands in THEIR vault, not just as a grant inside yours.
#
# The model:
#   - LEND (grant): the other party reads your vault item through a scoped
#     token (see add-credential.sh). The value stays in YOUR vault.
#   - GIVE (this example): the value MOVES to the recipient's own vault.
#     Transport is GPG encryption to the recipient's public key, so the
#     channel in between can be anything — mail, chat, a shared folder.
#
# Flow (two roles, one script for demo purposes):
#   recipient: exports ONLY their public key
#   donor:     encrypts one item value to that key, hands over the armor
#   recipient: decrypts and stores the item in their own vault
#
# Usage:  sh share-credential-with-user.sh <donor-vault> <item> <recipient-vault>
set -eu

DONOR_VAULT=$1
ITEM=$2
REC_VAULT=$3
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

[ -f "$DONOR_VAULT" ] || die "no donor vault: $DONOR_VAULT"
[ -f "$REC_VAULT" ] || die "no recipient vault: $REC_VAULT (run create-skarbiec.sh for the recipient first)"

# --- recipient side: export ONLY the public key ----------------------------
# skarbiec export-key prints the recipient's armored PUBLIC key — safe to
# publish, lets anyone encrypt TO the recipient, opens nothing itself.
echo "== step (recipient): export public key"
REC_UID=$(SKARBIEC_VAULT_FILE="$REC_VAULT" "$SB" users | jq -r 'to_entries | first(.[] | select(.value.role=="owner") | .key)')
[ -n "$REC_UID" ] || die "no owner recipient in $REC_VAULT"
PUB=$(SKARBIEC_VAULT_FILE="$REC_VAULT" "$SB" export-key "$REC_UID" | jq -r '.public_key')
[ -n "$PUB" ] || die "export-key returned nothing for $REC_UID"

# --- donor side: import that key, read the item, encrypt to it -------------
echo "== step (donor): import recipient public key + encrypt the item value"
printf '%s' "$PUB" | gpg --batch --quiet --import
REC_FPR=$(gpg --batch --list-keys --with-colons "$REC_UID" | awk -F: '/^fpr/ {print $10; exit}')
[ -n "$REC_FPR" ] || die "recipient key not in keyring after import"

VALUE=$(SKARBIEC_VAULT_FILE="$DONOR_VAULT" "$SB" get "$ITEM" | jq -r '.value') \
  || die "cannot read $ITEM from donor vault"
ARMOR_FILE="${TMPDIR:-$HOME}/share-$ITEM.asc"
printf '%s' "$VALUE" | gpg --batch --yes --encrypt --armor --recipient "$REC_FPR" > "$ARMOR_FILE"
unset VALUE
chmod u=rw,go= "$ARMOR_FILE"
echo "    armor written to: $ARMOR_FILE (ciphertext — any channel will do)"

# --- recipient side: decrypt + store in their own vault --------------------
echo "== step (recipient): decrypt + store in own vault"
SECRET=$(gpg --batch --quiet --decrypt "$ARMOR_FILE") \
  || die "recipient cannot decrypt $ARMOR_FILE"
SKARBIEC_VAULT_FILE="$REC_VAULT" "$SB" set "$ITEM" --type secret "value=$SECRET" >/dev/null
unset SECRET

echo "== verify: recipient opens the item in THEIR vault"
SKARBIEC_VAULT_FILE="$REC_VAULT" "$SB" get "$ITEM" --field value
echo "== verify: donor vault untouched (item still there)"
SKARBIEC_VAULT_FILE="$DONOR_VAULT" "$SB" get "$ITEM" --field value
