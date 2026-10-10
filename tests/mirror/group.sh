#!/usr/bin/env bash
# Real test of `skarbiec mirror init|push|pull` and `skarbiec bond status`
# through the built binary. Two vaults, two sync directories and a bare Git
# repository standing in for the remote all live under this checkout's target
# directory, with GNUPGHOME there too, so the operator's vault, keyring and
# mirror are never read or written.
#
# The owner vault stores one item, sets up its mirror and pushes; the replica
# sets up its own mirror on the same remote and pulls, and then lists the
# owner's item. The mirror group without a subcommand and an unknown
# subcommand are refused; the withdrawn sync-push and sync-status are refused
# as unknown commands, and bond status answers. Every command and whether it
# succeeded go to the run's report.txt.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_SOURCE_REVISION=<full-sha> tests/mirror/group.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set SKARBIEC_TEST_SOURCE_REVISION to the full candidate source revision}
[ "$(git rev-parse HEAD)" = "$REVISION" ] || { echo "candidate source revision does not match HEAD"; false; }
git diff --quiet || { echo "candidate source has uncommitted changes"; false; }
git diff --cached --quiet || { echo "candidate source has staged changes"; false; }
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/mirror/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $REVISION" >"$REPORT"
echo "binary: $BIN; git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" &>/dev/stdout); then status=$?; got=ok; else status=$?; got=refused; fi
  printf '$ skarbiec %s\nexit: %s\nresult: %s\noutput: %s\n\n' "$*" "$status" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
says() {
  case "$out" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in the answer" ;;
  esac
}

REMOTE="$ROOT/remote.git"
git init --bare --initial-branch=main "$REMOTE" >>"$REPORT"
ITEM="mirror-item-$RUN"

export SKARBIEC_VAULT_FILE="$ROOT/owner.vault.json" SKARBIEC_SYNC_DIR="$ROOT/sync-owner"
WANT=ok run init "mirror-test-owner-$RUN"
jq -n --arg value "mirror-value-$RUN" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set-json "$ITEM" --type note
WANT=ok run mirror init "$REMOTE"
WANT=ok run mirror push
PUBLISHED=$(git --git-dir="$REMOTE" rev-parse refs/heads/main)
printf '%s\n' "$RUN" >"$SKARBIEC_SYNC_DIR/unrelated.txt"
git -C "$SKARBIEC_SYNC_DIR" add unrelated.txt
WANT=ok run mirror push
[ "$(git --git-dir="$REMOTE" rev-parse refs/heads/main)" = "$PUBLISHED" ] \
  || fail "pushing unchanged ciphertext must not create another commit"
jq -n --arg value "updated-mirror-value-$RUN" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set-json "$ITEM" --type note
mkdir "$SKARBIEC_SYNC_DIR/.git/index.lock"
WANT=refused run mirror push
says "git add" "a locked index reports the failed staging operation"
[ "$(git --git-dir="$REMOTE" rev-parse refs/heads/main)" = "$PUBLISHED" ] \
  || fail "failed staging must not publish an old commit as the new vault"
rmdir "$SKARBIEC_SYNC_DIR/.git/index.lock"
GIT_AUTHOR_NAME='' GIT_COMMITTER_NAME='' WANT=refused run mirror push
says "git commit" "an invalid Git identity reports the failed commit operation"
[ "$(git --git-dir="$REMOTE" rev-parse refs/heads/main)" = "$PUBLISHED" ] \
  || fail "failed commit must not report the old remote as synchronized"
WANT=ok run mirror push
[ "$(git --git-dir="$REMOTE" rev-parse refs/heads/main)" != "$PUBLISHED" ] \
  || fail "a repaired Git dependency must publish the changed vault"
git --git-dir="$REMOTE" show main:vault.enc.json >"$ROOT/published-vault.json"
cmp "$ROOT/published-vault.json" "$SKARBIEC_VAULT_FILE" \
  || fail "the published ciphertext must equal the current owner vault"
[ -z "$(git --git-dir="$REMOTE" ls-tree --name-only main -- unrelated.txt)" ] \
  || fail "publishing a vault must not publish unrelated staged files"
[ "$(git -C "$SKARBIEC_SYNC_DIR" diff --cached --name-only -- unrelated.txt)" = "unrelated.txt" ] \
  || fail "publishing a vault must preserve unrelated staged work"
WANT=refused run mirror
says "needs a subcommand" "the mirror group without a subcommand is refused"
WANT=refused run mirror frobnicate
says "unknown mirror command" "an unknown mirror subcommand is refused"
WANT=refused run sync-push
says "unknown command: sync-push" "the withdrawn sync-push is refused"
WANT=ok run bond status
WANT=refused run sync-status
says "unknown command: sync-status" "the withdrawn sync-status is refused"

export SKARBIEC_VAULT_FILE="$ROOT/replica.vault.json" SKARBIEC_SYNC_DIR="$ROOT/sync-replica"
WANT=ok run init "mirror-test-replica-$RUN"
WANT=ok run mirror init "$REMOTE"
WANT=ok run mirror pull
WANT=ok run list
says "$ITEM" "the replica lists the owner's item after mirror pull"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
