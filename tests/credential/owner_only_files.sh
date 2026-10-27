#!/usr/bin/env bash
# Real test of the owner-only checks the credential client makes before it
# reaches the canonical Skarbiec, through the built binary with a PATH that
# holds no program at all. The checks compare a file's owner with the uid the
# kernel reports for the process, so they answer without any helper program;
# the forwards directory and token files live in this checkout's target
# directory, so the operator's forwards and vault are never read.
#
#   * an owner-only token file passes the check, and the call goes on to the
#     forward lookup, which refuses with SKARBIEC_ENDPOINT_UNRESOLVED because
#     the fresh forwards directory declares no canonical Skarbiec;
#   * a token file group or other may read is refused by name;
#   * a declared forward that group or other may write is refused by name;
#   * `rotation set` refuses an interval that is not a whole number of days
#     with the value it was given.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run
# tests/credential/owner_only_files.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
case "$BIN" in
  /*) ;;
  *) BIN="$PWD/$BIN" ;;
esac
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/credential/$RUN"
REPORT="$ROOT/report.txt"
EMPTY_PATH="$ROOT/no-programs"
mkdir -p "$ROOT" "$EMPTY_PATH" "$ROOT/forwards"
chmod go-rwx "$ROOT" "$ROOT/forwards"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export STADO_FORWARDS_DIR="$ROOT/forwards"

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# Runs one command with a PATH that holds no program, its standard output
# and standard error together in $out; WANT says whether it had to succeed
# (ok) or be refused (refused). The command, observed exit status and verdict
# are reported.
run() {
  if out=$(PATH="$EMPTY_PATH" "$BIN" "$@" 2>&1); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  printf '$ PATH=%s skarbiec %s\nexit: %s\nresult: %s\noutput:\n%s\n\n' "$EMPTY_PATH" "$*" "$status" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
says() {
  case "$out" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in the answer" ;;
  esac
}
lacks() {
  case "$out" in
    *"$1"*) fail "$2: '$1' is in the answer" ;;
    *) echo "ok: $2" >>"$REPORT" ;;
  esac
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"

ITEM="owner-only-$RUN"
CALLER="owner-only-caller"

OWNED="$ROOT/owned-token"
printf '%s\n' "token-$RUN" >"$OWNED"
chmod u=rw,go= "$OWNED"
WANT=refused run credential status "$ITEM" --as "$CALLER" --token-file "$OWNED"
says "SKARBIEC_ENDPOINT_UNRESOLVED" "an owner-only token file passes the ownership check and the call reaches the forward lookup"
lacks "effective uid" "the ownership check needs no helper program"

SHARED="$ROOT/shared-token"
printf '%s\n' "token-$RUN" >"$SHARED"
chmod u=rw,go=r "$SHARED"
WANT=refused run credential status "$ITEM" --as "$CALLER" --token-file "$SHARED"
says "credential token file must be an owner-only regular file" "a token file others may read is refused by name"

FORWARD="$STADO_FORWARDS_DIR/skarbiec.local"
printf '%s\n' "http://localhost:$RUN" >"$FORWARD"
chmod u=rw,go=rw "$FORWARD"
WANT=refused run credential status "$ITEM" --as "$CALLER" --token-file "$OWNED"
says "without group or world write" "a forward others may write is refused by name"
rm -f "$FORWARD"

WANT=refused run rotation set "$ITEM" --every-days weekly --provider owner-only-provider --consumer owner-only-consumer
says "--every-days must be a whole number of days above zero, not weekly" "a non-numeric interval is refused with the value given"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
