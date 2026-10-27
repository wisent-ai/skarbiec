#!/usr/bin/env bash
# Real test of `/readyz` while another process holds the keyring lock, through
# the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# It creates the vault and one note, starts `skarbiec serve`, reads `/readyz`
# once while nothing holds the keyring, then holds the keyring lock the way
# GnuPG does (its lock file naming a live pid and this host), fires one
# `/readyz` whose canary decrypt queues behind that lock, and asks `/readyz`
# again: the second must answer 503 naming the holder instead of accepting
# the connection and never answering. The lock is then released and the first
# request must complete with 200. held_lock.mjs drives the listener.
#
# Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION and SKARBIEC_TEST_HTTP_PORT,
# then run this file.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
: "${SKARBIEC_TEST_HTTP_PORT:?set the isolated listener bind port for real HTTP qualification}"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/health/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export SKARBIEC_TEST_REPORT_DIR="$ROOT"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

run() {
  if out=$("$BIN" "$@" &>/dev/stdout); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  printf '$ skarbiec %s\nexit: %s\nresult: %s\n\n' "$*" "$status" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
BIN_REVISION=$("$BIN" --version | jq -er '.commit') || fail "binary has no release commit identity"
[ "$BIN_REVISION" = "$SOURCE_REVISION" ] || fail "binary revision $BIN_REVISION differs from $SOURCE_REVISION"

WANT=ok run init "held-lock-owner-$RUN"
jq -n --arg value "held-lock-value-$RUN" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set "held-lock-note-$RUN" --type note

node tests/health/held_lock.mjs
echo "passed" >>"$REPORT"
