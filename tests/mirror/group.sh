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
# subcommand are refused; the old sync-push, which Stado runs on hosts against
# their installed Skarbiec, still pushes; bond status and the old sync-status
# both answer. Every command and whether it succeeded go to the run's
# report.txt.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/mirror/group.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/mirror/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
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
WANT=ok run set "$ITEM" --type note "value=mirror-value-$RUN"
WANT=ok run mirror init "$REMOTE"
WANT=ok run mirror push
WANT=refused run mirror
says "needs a subcommand" "the mirror group without a subcommand is refused"
WANT=refused run mirror frobnicate
says "unknown mirror command" "an unknown mirror subcommand is refused"
WANT=ok run sync-push
echo "ok: the old sync-push still pushes" >>"$REPORT"
WANT=ok run bond status
WANT=ok run sync-status
echo "ok: bond status and the old sync-status both answer" >>"$REPORT"

export SKARBIEC_VAULT_FILE="$ROOT/replica.vault.json" SKARBIEC_SYNC_DIR="$ROOT/sync-replica"
WANT=ok run init "mirror-test-replica-$RUN"
WANT=ok run mirror init "$REMOTE"
WANT=ok run mirror pull
WANT=ok run list
says "$ITEM" "the replica lists the owner's item after mirror pull"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
