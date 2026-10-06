#!/bin/sh
# Real test of `skarbiec bond-add` and `bond-edit` through the built binary,
# on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written. The keyring sits at a short
# path because gpg-agent's socket lives in it and a Unix socket path is
# limited in length.
#
# It creates the vault with `init`, adds a bond, checks that adding the same
# name again is refused naming its mode and role, edits the bond's channel
# and interval and reads it back with `bond-list` (the mode and role it was
# not given stay), checks that an edit is held to bond-add's checks (an
# unknown mode) and that editing a bond nobody configured is refused, then
# removes it. Every command, its exit status and output go to the run's
# report.txt.
#
# Usage: tests/bonds/bond_edit.sh   (SKARBIEC selects the binary, default
#   target/debug/skarbiec)
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:-$PWD/target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/bonds/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod 700 "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all 2>/dev/null || true; rm -rf "$KEYRING"' EXIT

run() {
  expected=$1
  shift
  set +e
  out=$("$BIN" "$@" 2>"$ROOT/stderr" </dev/null)
  status=$?
  set -e
  err=$(cat "$ROOT/stderr")
  printf '$ skarbiec %s\nexit: %s\nstdout: %s\nstderr: %s\n\n' "$*" "$status" "$out" "$err" >>"$REPORT"
  if [ "$status" -ne "$expected" ]; then
    echo "FAIL: skarbiec $* exited $status, expected $expected: $err" | tee -a "$REPORT" >&2
    exit 1
  fi
}
check() {
  if [ "$2" != "$3" ]; then
    echo "FAIL: $1: got '$2', expected '$3'" | tee -a "$REPORT" >&2
    exit 1
  fi
  echo "ok: $1 = $2" >>"$REPORT"
}
refused() {
  case "$err$out" in
    *"$1"*) echo "ok: refused with: $1" >>"$REPORT" ;;
    *) echo "FAIL: expected a refusal containing '$1', got: $err $out" | tee -a "$REPORT" >&2; exit 1 ;;
  esac
}

run 0 init "bond-test-owner-$RUN"
BOND="test-bond-$RUN"
run 0 bond-add "$BOND" --mode replica --role replica --channel "file:$ROOT/source.json"
run 1 bond-add "$BOND" --mode hub --role source --channel "file:$ROOT/other.json"
refused "bond $BOND is already configured (mode replica, role replica); \`skarbiec bond-edit $BOND\` changes it"

run 0 bond-edit "$BOND" --channel "file:$ROOT/moved.json" --interval 600
run 0 bond-list
check "the channel is edited" "$(echo "$out" | jq -r --arg b "$BOND" '.[$b].channel.address')" "$ROOT/moved.json"
check "the interval is edited" "$(echo "$out" | jq -r --arg b "$BOND" '.[$b].channel.interval_seconds')" "600"
check "the mode is kept" "$(echo "$out" | jq -r --arg b "$BOND" '.[$b].mode')" "replica"
check "the role is kept" "$(echo "$out" | jq -r --arg b "$BOND" '.[$b].role')" "replica"

run 1 bond-edit "$BOND" --mode sideways
refused "mode must be one of: replica, hub, p2p, git"
run 1 bond-edit "missing-$RUN" --interval 60
refused "missing-$RUN"

run 0 bond-remove "$BOND"
run 0 bond-list
check "the bond is gone" "$(echo "$out" | jq --arg b "$BOND" 'has($b)')" "false"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
