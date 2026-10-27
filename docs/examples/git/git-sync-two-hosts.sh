#!/bin/sh
# git-sync-two-hosts.sh — two vaults synced through a shared git remote
# (ciphertext only). Usage: SKARBIEC_BIN=<skarbiec binary> sh git-sync-two-hosts.sh <workdir>
set -eu

DIR=$1
SB=${SKARBIEC_BIN:?SKARBIEC_BIN must name the skarbiec binary this example runs}

git init --bare -q "$DIR/remote.git"

SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" "$SB" init 'git-owner <owner@example.com>'
printf '{"schema":"skarbiec.item.v2","kind":"secret","fields":{"value":"shared-through-git"},"context":{}}' \
  | SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" "$SB" set shared-item --type secret

SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-owner" "$SB" mirror init "$DIR/remote.git"
SKARBIEC_VAULT_FILE="$DIR/owner.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-owner" "$SB" mirror push

SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" "$SB" init 'git-replica <replica@example.com>'
SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-replica" "$SB" mirror init "$DIR/remote.git"
SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" SKARBIEC_SYNC_DIR="$DIR/sync-replica" "$SB" mirror pull

SKARBIEC_VAULT_FILE="$DIR/replica.vault.json" "$SB" list
