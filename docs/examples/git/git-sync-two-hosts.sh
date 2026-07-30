#!/bin/sh
# git-sync-two-hosts.sh — the git bond mode: two vaults synchronized
# through a shared git remote (ciphertext only).
#
# The remote carries ONLY ciphertext — a bare repo anywhere reachable
# (self-hosted, e.g. over Tailscale). The owner pushes its vault; the
# replica pulls it. Per-item sealing decides what the replica can open.
#
# Usage:  sh git-sync-two-hosts.sh <workdir>
set -eu

DIR=$1
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }

mkdir -p "$DIR"
REMOTE="$DIR/remote.git"
OWNER_VAULT="$DIR/owner.vault.json"
REPLICA_VAULT="$DIR/replica.vault.json"

echo "== step: bare git remote (the shared ciphertext rendezvous)"
git init --bare -q "$REMOTE"

echo "== step: owner vault with a shared and a private item"
[ -f "$OWNER_VAULT" ] || SKARBIEC_VAULT_FILE="$OWNER_VAULT" "$SB" init 'git-owner <o@x.pl>' > /dev/null
SKARBIEC_VAULT_FILE="$OWNER_VAULT" "$SB" set shared-item --type secret "value=shared-through-git" >/dev/null
SKARBIEC_VAULT_FILE="$OWNER_VAULT" "$SB" set private-item --type secret "value=not-for-replica" >/dev/null

echo "== step: replica vault + its public key shared into the owner vault"
[ -f "$REPLICA_VAULT" ] || SKARBIEC_VAULT_FILE="$REPLICA_VAULT" "$SB" init 'git-replica <r@x.pl>' > /dev/null
SKARBIEC_VAULT_FILE="$REPLICA_VAULT" "$SB" export-key 'git-replica <r@x.pl>' | jq -r '.public_key' > "$DIR/replica-pub.asc"
SKARBIEC_VAULT_FILE="$OWNER_VAULT" "$SB" add-user 'git-replica <r@x.pl>' --import "$DIR/replica-pub.asc" > /dev/null
SKARBIEC_VAULT_FILE="$OWNER_VAULT" "$SB" share shared-item 'git-replica <r@x.pl>' > /dev/null

echo "== step: owner sync-push to the remote"
SKARBIEC_VAULT_FILE="$OWNER_VAULT" SKARBIEC_SYNC_DIR="$DIR/sync-owner" \
  "$SB" sync-init "$REMOTE" > /dev/null
SKARBIEC_VAULT_FILE="$OWNER_VAULT" SKARBIEC_SYNC_DIR="$DIR/sync-owner" \
  "$SB" sync-push > /dev/null

echo "== step: replica sync-pull from the remote"
SKARBIEC_VAULT_FILE="$REPLICA_VAULT" SKARBIEC_SYNC_DIR="$DIR/sync-replica" \
  "$SB" sync-init "$REMOTE" > /dev/null
SKARBIEC_VAULT_FILE="$REPLICA_VAULT" SKARBIEC_SYNC_DIR="$DIR/sync-replica" \
  "$SB" sync-pull > /dev/null

echo "== verify: replica opens the shared item"
SKARBIEC_VAULT_FILE="$REPLICA_VAULT" "$SB" get shared-item --field value
