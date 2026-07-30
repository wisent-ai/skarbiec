#!/bin/sh
# git-sync-two-hosts.sh — two vaults synced through a shared git remote
# (ciphertext only). Usage: sh git-sync-two-hosts.sh <workdir>
set -eu

DIR=$1
SB=${SKARBIEC_BIN:-skarbiec}

git init --bare -q "$DIR/remote.git"

SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" "$SB" init 'git-owner <o@x.pl>'
SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" "$SB" set shared-item --type secret value=shared-through-git

SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-owner" "$SB" sync-init "$DIR/remote.git"
SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-owner" "$SB" sync-push

SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" "$SB" init 'git-replica <r@x.pl>'
SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-replica" "$SB" sync-init "$DIR/remote.git"
SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-replica" "$SB" sync-pull

SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" "$SB" list
