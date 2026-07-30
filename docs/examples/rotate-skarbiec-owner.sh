#!/bin/sh
# Example 03 — owner rotation without losing the vault (executable fire-drill).
# Usage:  sh 03-rotacja-wlasciciela-bez-utraty-vaulta.sh <vault-path> <old-owner-uid> <new-owner-uid>
# Example: sh 03-...sh ~/.skarbiec-moj.vault.json 'skarbiec-moj <moj@email.pl>' 'skarbiec-moj-year2 <moj@email.pl>'
set -eu

VAULT=$1
OLD_UID=$2
NEW_UID=$3
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

[ -f "$VAULT" ] || die "no vault: $VAULT (run example 01 first)"

BACKUP_DIR=$(dirname "$VAULT")
STAMP=$(date +%Y%m%d%H%M%S)

echo "== step: backup BEFORE any change"
cp "$VAULT" "$VAULT.backup-$STAMP"
gpg --batch --yes --pinentry-mode loopback --passphrase '' \
  --export-secret-keys --armor "$OLD_UID" > "$BACKUP_DIR/owner-backup-$STAMP.asc" \
  || die "cannot export the old key — STOP (this refusal is the safety guard)"
echo "backup ok: $VAULT.backup-$STAMP + owner-backup-$STAMP.asc"

echo "== step: successor key in the keyring (via skarbiec — correct SC+E key type)"
if ! gpg --list-secret-keys "$NEW_UID" > /dev/null; then
  SKARBIEC_VAULT_FILE="$VAULT" "$SB" add-user "$NEW_UID" > /dev/null
fi
gpg --list-secret-keys "$NEW_UID"

echo "== step: rotate-owner (atomic: a failure leaves the vault untouched)"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" rotate-owner "$NEW_UID"

echo "== step: verify every item still opens"
FIRST_ITEM=$(SKARBIEC_VAULT_FILE="$VAULT" "$SB" list | awk -F'"' '/"id"/ {print $4; exit}')
[ -n "$FIRST_ITEM" ] || die "vault empty after rotation?"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" get "$FIRST_ITEM" > /dev/null \
  || die "item $FIRST_ITEM does not open after rotation — delete nothing, restore the backup"
SKARBIEC_VAULT_FILE="$VAULT" "$SB" recovery-status
echo "ROTATION OK. Delete the old key only by hand, after this verification:"
echo "  gpg --delete-secret-and-public-key '<old-owner-fpr>'"
