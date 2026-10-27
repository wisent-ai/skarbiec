#!/usr/bin/env bash
# Real test of `skarbiec rotate --with aws`, through the built binary on a vault of
# its own and a real AWS account: SKARBIEC_TEST_AWS_USER names an IAM user
# kept for this test, and the aws CLI's own configuration signs in as someone
# who may create, update, list and delete that user's access keys. The test
# makes the user a key, rotates it twice, and deletes every key it made.
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# After rotate --with aws the item holds a key AWS lists as active and the old key
# is inactive; with --delete-old the old key is gone from AWS. No secret is
# printed. An item that is not an access key, and a temporary key with a
# session token, are refused before AWS is asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_AWS_USER=skarbiec-rotation-test tests/rotation/aws_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
USER_NAME=${SKARBIEC_TEST_AWS_USER:?set SKARBIEC_TEST_AWS_USER to an IAM user this test may make and delete access keys for}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/rotation/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "iam user: $USER_NAME" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
MADE="$ROOT/made-keys"
: >"$MADE"
keys() {
  aws iam list-access-keys --user-name "$USER_NAME" --output json
}
cleanup() {
  # Every key this run made or rotated to, and no other.
  while read -r key; do
    if keys | jq -e --arg key "$key" '.AccessKeyMetadata[] | select(.AccessKeyId == $key)' &>/dev/null; then
      aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$key" &>>"$REPORT" || echo "cleanup: could not delete $key" >>"$REPORT"
    fi
  done <"$MADE"
  gpgconf --homedir "$GNUPGHOME" --kill all
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
status_of() {
  keys | jq -r --arg key "$*" '.AccessKeyMetadata[] | select(.AccessKeyId == $key) | .Status'
}

: >"$ROOT/stdin"
WANT=ok run init "aws-owner-$RUN"
ITEM="aws-$RUN"
FIRST="$(aws iam create-access-key --user-name "$USER_NAME" --output json)"
FIRST_ID="$(printf '%s' "$FIRST" | jq -r .AccessKey.AccessKeyId)"
echo "$FIRST_ID" >>"$MADE"
printf '%s' "$FIRST" | jq '{schema:"skarbiec.item.v2",kind:"access-key",fields:{access_key_id:.AccessKey.AccessKeyId,secret_access_key:.AccessKey.SecretAccessKey},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type access-key
: >"$ROOT/stdin"
FIRST_SECRET="$(printf '%s' "$FIRST" | jq -r .AccessKey.SecretAccessKey)"

WANT=ok run rotate "$ITEM" --with aws
case "$out" in *"$FIRST_SECRET"*) fail "rotate printed the old secret" ;; esac
SECOND_ID="$(printf '%s' "$out" | jq -r .key)"
echo "$SECOND_ID" >>"$MADE"
WANT=ok run get "$ITEM" --field access_key_id
[ "$out" = "$SECOND_ID" ] || fail "the item does not hold the key rotate named"
[ "$(status_of "$SECOND_ID")" = "Active" ] || fail "AWS does not list the new key as active"
[ "$(status_of "$FIRST_ID")" = "Inactive" ] || fail "the old key is not inactive"
echo "ok: the item holds the new active key and the old one is inactive" >>"$REPORT"

# The inactive key still counts against the user's keys: make room first.
aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$FIRST_ID" &>>"$REPORT"
WANT=ok run rotate "$ITEM" --with aws --delete-old
THIRD_ID="$(printf '%s' "$out" | jq -r .key)"
echo "$THIRD_ID" >>"$MADE"
[ "$(printf '%s' "$out" | jq -r .retired_as)" = "deleted" ] || fail "--delete-old did not answer deleted"
[ -z "$(status_of "$SECOND_ID")" ] || fail "--delete-old left the old key in AWS"
[ "$(status_of "$THIRD_ID")" = "Active" ] || fail "AWS does not list the newest key as active"
echo "ok: --delete-old removes the old key from AWS" >>"$REPORT"

jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a key"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with aws
case "$out" in *"rotate --with aws replaces an access-key item"*) ;; *) fail "a note was not refused naming its kind: $out" ;; esac
jq -n '{schema:"skarbiec.item.v2",kind:"access-key",fields:{access_key_id:"ASIATEMPORARY",secret_access_key:"temporary",session_token:"token"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "temporary-$RUN" --type access-key
: >"$ROOT/stdin"
WANT=refused run rotate "temporary-$RUN" --with aws
case "$out" in *"temporary key"*) ;; *) fail "a key with a session token was not refused: $out" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
