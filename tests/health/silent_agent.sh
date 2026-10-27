#!/usr/bin/env bash
# Real test of `/readyz` while gpg-agent accepts and never answers, through
# the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# It creates the vault and one note, starts `skarbiec serve`, reads `/readyz`
# once with the real agent answering, then ends the agent and puts a socket in
# its place that accepts every connection and never greets, fires one `/readyz`
# whose canary decrypt asks that silent agent for its key, and asks `/readyz`
# again: the second must answer 503 naming the waiting gpg child, the status
# it stopped at and the repair, instead of accepting the connection and never
# answering, and publish the child under crypto.gpg_waiting_on_agent. The
# silent socket is then ended, the vault recovers its daemons, and the first
# request must complete with 200. silent_agent.mjs drives the listener.
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

WANT=ok run init "silent-agent-owner-$RUN"
jq -n --arg value "silent-agent-value-$RUN" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set "silent-agent-note-$RUN" --type note

node tests/health/silent_agent.mjs
echo "passed" >>"$REPORT"
