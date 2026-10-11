#!/usr/bin/env bash
# Real test of the credential lifecycle's pending-request guard through the
# built binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE
# and GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# A credential operation reads the credential's pending request before it is
# submitted, and enforces the retry barrier and the pending-request refusals on
# it. A pending request that is live but is not a credential operation record
# used to read as no request at all, and the operation ran on past it. Here
# the pending request of a generic provider's credential is a login item, which
# carries no operation record; `credential acquire --local` must refuse naming
# that item, contact no Weles, and leave the item exactly as it was.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run
# tests/credential/unreadable_request.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/credential/$RUN"
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
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# Runs one command, its standard output and standard error together in $out;
# WANT says whether it had to succeed (ok) or be refused (refused). The
# command, observed exit status and verdict are reported.
run() {
  if out=$("$BIN" "$@" &>/dev/stdout); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  printf '$ skarbiec %s\nexit: %s\nresult: %s\noutput:\n%s\n\n' "$*" "$status" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
says() {
  case "$out" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in the answer" ;;
  esac
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"

PROVIDER="unreadable-request-$RUN"
PROVIDER=$(printf '%s' "$PROVIDER" | tr 'A-Z' 'a-z')
REQUEST="operation:credential/$PROVIDER"

WANT=ok run init "unreadable-request-owner-$RUN"
jq -n --arg user "request-user-$RUN" --arg password "request-password-$RUN" \
  '{schema:"skarbiec.item.v2",kind:"login",fields:{username:$user,password:$password},context:{}}' \
  | WANT=ok run set-json "$REQUEST" --type login
BEFORE=$(jq -cS --arg id "$REQUEST" '.items[$id]' "$SKARBIEC_VAULT_FILE")
[ "$BEFORE" != "null" ] || fail "the pending request item was not written"

WANT=refused run get "$REQUEST" --field value
FIELD_FAILURE=$out

WANT=refused run credential acquire --local --provider "$PROVIDER" --consumer "unreadable-request-consumer"
says "$REQUEST" "the refusal names the retained request"
says "$PROVIDER" "the refusal names the credential"
case "$FIELD_FAILURE" in
  *": "*) FIELD_CAUSE=${FIELD_FAILURE##*: } ;;
  *) FIELD_CAUSE=$FIELD_FAILURE ;;
esac
says "$FIELD_CAUSE" "the lifecycle refusal retains the actual field-read cause"

AFTER=$(jq -cS --arg id "$REQUEST" '.items[$id]' "$SKARBIEC_VAULT_FILE")
[ "$BEFORE" = "$AFTER" ] || fail "the refused operation changed the pending request item"
echo "ok: the refused operation left the pending request item unchanged" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
