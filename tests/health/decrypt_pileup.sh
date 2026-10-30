#!/usr/bin/env bash
# Real test of many concurrent item reads against one `skarbiec serve`, with
# a real gpg, gpg-agent and keyboxd, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE and SKARBIEC_AUDIT_FILE point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# GNUPGHOME is ~/.skarbiec/test-runs/<id>, the short root the product owns,
# removed on exit: gpg-agent and keyboxd listen on unix sockets inside it, a
# unix socket path cannot exceed 104 bytes (sun_path), and a home under this
# checkout's target directory is longer than that.
#
# It writes one note, grants a consumer `read` of it, and checks:
# - SKARBIEC_GPG_DEADLINE_SECONDS that is not a whole number of seconds above
#   zero is refused naming the setting, its value and how to fix it;
# - decrypt_pileup.mjs: reads past the gpg capacity queue instead of each
#   spawning gpg; `/health` answers at once throughout, reporting the queue's
#   depth and its oldest wait; a caller that closes its connection leaves no
#   gpg child and no queued run behind; with gpg-agent silent, every read
#   answers 503 within the deadline naming the wait, the cause and the fix;
#   with the agent back, every read answers its value.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run this file.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/health/pileup-$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$HOME/.skarbiec/test-runs/p$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING" "$HOME/.skarbiec" "$HOME/.skarbiec/test-runs"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
# The key database is served by keyboxd, as on a vault host, so the journey
# counts the keyboxd daemons serving the home as well as its gpg-agents.
echo use-keyboxd >"$KEYRING/common.conf"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export SKARBIEC_TEST_REPORT_DIR="$ROOT"
cleanup() {
  if ! gpgconf --homedir "$GNUPGHOME" --kill all 2>>"$REPORT"; then
    echo "cleanup: gpgconf --kill all did not complete" >>"$REPORT"
  fi
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" 2>"$ROOT/said"); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nexit: %s\nresult: %s\n\n' "$*" "$status" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
says() {
  case "$said" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in: $said" ;;
  esac
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"

ITEM="pileup-note-$RUN"
export SKARBIEC_TEST_ITEM="$ITEM"
export SKARBIEC_TEST_CONSUMER="pileup-reader-$RUN"
export SKARBIEC_TEST_VALUE="pileup-value-$RUN"

WANT=ok run init "pileup-owner-$RUN"
jq -n --arg value "$SKARBIEC_TEST_VALUE" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set "$ITEM" --type note
WANT=ok run grant issue "$SKARBIEC_TEST_CONSUMER" --capabilities "read:$ITEM#value" --until-revoked
SKARBIEC_TEST_TOKEN=$(printf '%s' "$out" | jq -r .token)
[ -n "$SKARBIEC_TEST_TOKEN" ] && [ "$SKARBIEC_TEST_TOKEN" != null ] || fail "grant issue answered no token"
export SKARBIEC_TEST_TOKEN

for malformed in zero 0 -5 1.5; do
  SKARBIEC_GPG_DEADLINE_SECONDS=$malformed WANT=refused run get "$ITEM" --field value
  says "SKARBIEC_GPG_DEADLINE_SECONDS is \"$malformed\", which is not a whole number of seconds above zero" \
    "a deadline of $malformed is refused naming the setting and its value"
  says "or unset it to bound each run by its caller's connection alone" \
    "the refusal of $malformed says how to fix it"
done
WANT=ok run get "$ITEM" --field value
[ "$out" = "$SKARBIEC_TEST_VALUE" ] || fail "an unset deadline did not read the value"
echo "ok: with the deadline unset, a command reads its value" >>"$REPORT"

node tests/health/decrypt_pileup.mjs
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
