#!/usr/bin/env bash
# Real test of `skarbiec mirror publish|unpublish`, the mirror push every
# `skarbiec maintain` pass makes on a publishing host, and doctor's `mirror`
# check, through the built binary. One vault, its sync directory and a bare
# Git repository standing in for the remote live under this checkout's target
# directory, with GNUPGHOME there too, so the operator's vault, keyring and
# mirror are never read or written.
#
# Publishing without a mirror is refused and names the directory it looked
# in; doctor reports the mirror not configured. Once the mirror is set up and
# published, a changed vault makes doctor fail the mirror check, and one
# maintain pass pushes it: the remote then holds the live ciphertext and
# doctor passes. After unpublish a maintain pass reports no mirror push and
# the remote keeps the last published commit; a mirror whose Git config
# cannot be read fails the pass with Git's error. Every command and whether
# it succeeded go to the run's report.txt.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_SOURCE_REVISION=<full-sha> tests/mirror/publish.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set SKARBIEC_TEST_SOURCE_REVISION to the full candidate source revision}
[ "$(git rev-parse HEAD)" = "$REVISION" ] || { echo "candidate source revision does not match HEAD"; false; }
git diff --quiet || { echo "candidate source has uncommitted changes"; false; }
git diff --cached --quiet || { echo "candidate source has staged changes"; false; }
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/mirror-publish/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $REVISION" >"$REPORT"
echo "binary: $BIN; git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

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
# Doctor's verdict on the mirror alone: the other checks of an isolated vault
# (daemons, endpoint) are not this test's subject, so doctor's own exit is
# recorded and the mirror check is read from its report.
mirror_verdict() {
  if report=$("$BIN" doctor 2>>"$REPORT"); then status=$?; else status=$?; fi
  printf '$ skarbiec doctor\nexit: %s\noutput: %s\n\n' "$status" "$report" >>"$REPORT"
  verdict=$(printf '%s' "$report" | jq -r '.checks[] | select(.check == "mirror") | .status')
  [ "$verdict" = "$1" ] || fail "$2: doctor's mirror check is '$verdict', expected '$1'"
  echo "ok: $2" >>"$REPORT"
}
note() {
  jq -n --arg value "$1" \
    '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
    | WANT=ok run set "$ITEM" --type note
}

REMOTE="$ROOT/remote.git"
git init --bare --initial-branch=main "$REMOTE" >>"$REPORT"
ITEM="publish-item-$RUN"
export SKARBIEC_VAULT_FILE="$ROOT/owner.vault.json" SKARBIEC_SYNC_DIR="$ROOT/sync-owner"
WANT=ok run init "publish-test-owner-$RUN"
note "first-$RUN"

WANT=refused run mirror publish
says "no mirror in $SKARBIEC_SYNC_DIR" "publishing without a mirror is refused, naming the directory"
mirror_verdict not_configured "a host without a mirror reports the mirror not configured"

WANT=ok run mirror init "$REMOTE"
WANT=ok run mirror push
PUSHED=$(git --git-dir="$REMOTE" rev-parse refs/heads/main)
mirror_verdict pass "the vault just pushed passes the mirror check"

WANT=ok run mirror publish
says '"publish": true' "mirror publish records publishing"
note "second-$RUN"
mirror_verdict fail "a vault changed after the last push fails the mirror check"
WANT=ok run maintain
says '"mirror": {' "a maintain pass on a publishing host reports its mirror push"
[ "$(git --git-dir="$REMOTE" rev-parse refs/heads/main)" != "$PUSHED" ] \
  || fail "a maintain pass on a publishing host must push the changed vault"
git --git-dir="$REMOTE" show main:vault.enc.json >"$ROOT/published-vault.json"
cmp "$ROOT/published-vault.json" "$SKARBIEC_VAULT_FILE" \
  || fail "the remote must hold the live ciphertext after the maintain pass"
mirror_verdict pass "the vault a maintain pass pushed passes the mirror check"

WANT=ok run mirror unpublish
says '"publish": false' "mirror unpublish records not publishing"
PUBLISHED=$(git --git-dir="$REMOTE" rev-parse refs/heads/main)
note "third-$RUN"
WANT=ok run maintain
says '"mirror": null' "a maintain pass on a host that stopped publishing pushes nothing"
[ "$(git --git-dir="$REMOTE" rev-parse refs/heads/main)" = "$PUBLISHED" ] \
  || fail "a host that stopped publishing must leave the remote as it was"
mirror_verdict fail "the unpublished change is reported by the mirror check"

grep -q '"sync-publish"' "$SKARBIEC_AUDIT_FILE" \
  || fail "publishing changes are written to the audit journal"
echo "ok: publishing changes are in the audit journal" >>"$REPORT"

printf '[skarbiec\n' >>"$SKARBIEC_SYNC_DIR/.git/config"
WANT=refused run maintain
says "git config --bool skarbiec.publish" \
  "an unreadable mirror config fails the pass instead of reading as a host that does not publish"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
