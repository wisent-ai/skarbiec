#!/usr/bin/env bash
# Real test of `skarbiec rotate --with gcp`, through the built binary on a vault of
# its own and a real Google Cloud project: SKARBIEC_TEST_GCP_ACCOUNT names a
# service account kept for this test, holding the Service Account Key Admin
# role on itself, and gcloud's own configuration signs in as someone who may
# make, list and delete its keys. The test makes the account a key, rotates
# it twice, and deletes every key it made. SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# After rotate --with gcp the item holds a key Google lists as enabled and the old
# key is disabled; with --delete-old the old key is gone from Google. No key
# is printed, and gcloud's own configuration is left as it was. An item that
# is not a service account, and a credential that is not a service account
# key file, are refused before Google is asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_GCP_ACCOUNT=<service account email> tests/cloud/gcp_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
ACCOUNT=${SKARBIEC_TEST_GCP_ACCOUNT:?set SKARBIEC_TEST_GCP_ACCOUNT to a service account this test may make and delete keys for}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/cloud/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "service account: $ACCOUNT" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
MADE="$ROOT/made-keys"
: >"$MADE"
keys() {
  gcloud iam service-accounts keys list --iam-account="$ACCOUNT" --managed-by=user --format=json
}
cleanup() {
  # Every key this run made or rotated to, and no other.
  while read -r key; do
    if keys | jq -e --arg key "$key" '.[] | select(.name | endswith("/" + $key))' &>/dev/null; then
      gcloud iam service-accounts keys delete "$key" --iam-account="$ACCOUNT" --quiet &>>"$REPORT" || echo "cleanup: could not delete $key" >>"$REPORT"
    fi
  done <"$MADE"
  rm -f "$ROOT/first.json"
  gpgconf --homedir "$GNUPGHOME" --kill all
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
# enabled, disabled, or nothing when Google no longer lists the key.
state_of() {
  keys | jq -r --arg key "$*" '.[] | select(.name | endswith("/" + $key)) | if .disabled then "disabled" else "enabled" end'
}

CONFIG_BEFORE="$(gcloud config list --format=json)"
: >"$ROOT/stdin"
WANT=ok run init "gcp-owner-$RUN"
ITEM="gcp-$RUN"
gcloud iam service-accounts keys create "$ROOT/first.json" --iam-account="$ACCOUNT" &>>"$REPORT"
FIRST_ID="$(jq -r .private_key_id "$ROOT/first.json")"
echo "$FIRST_ID" >>"$MADE"
FIRST_KEY="$(jq -r .private_key "$ROOT/first.json")"
jq --rawfile file "$ROOT/first.json" -n '{schema:"skarbiec.item.v2",kind:"service-account",fields:{credential_json:$file},context:{}}' >"$ROOT/stdin"
rm -f "$ROOT/first.json"
WANT=ok run set "$ITEM" --type service-account
: >"$ROOT/stdin"

WANT=ok run rotate "$ITEM" --with gcp
# The old key must be in neither stream, so both are searched.
case "$out$said" in *"$FIRST_KEY"*) fail "rotate printed the old key" ;; esac
SECOND_ID="$(printf '%s' "$out" | jq -r .key)"
echo "$SECOND_ID" >>"$MADE"
WANT=ok run get "$ITEM" --field credential_json
[ "$(printf '%s' "$out" | jq -r .private_key_id)" = "$SECOND_ID" ] || fail "the item does not hold the key rotate named"
[ "$(state_of "$SECOND_ID")" = "enabled" ] || fail "Google does not list the new key as enabled"
[ "$(state_of "$FIRST_ID")" = "disabled" ] || fail "the old key is not disabled"
echo "ok: the item holds the new enabled key and the old one is disabled" >>"$REPORT"

WANT=ok run rotate "$ITEM" --with gcp --delete-old
THIRD_ID="$(printf '%s' "$out" | jq -r .key)"
echo "$THIRD_ID" >>"$MADE"
[ "$(printf '%s' "$out" | jq -r .retired_as)" = "deleted" ] || fail "--delete-old did not answer deleted"
[ -z "$(state_of "$SECOND_ID")" ] || fail "--delete-old left the old key in Google"
[ "$(state_of "$THIRD_ID")" = "enabled" ] || fail "Google does not list the newest key as enabled"
echo "ok: --delete-old removes the old key from Google" >>"$REPORT"
[ "$(gcloud config list --format=json)" = "$CONFIG_BEFORE" ] || fail "rotate changed gcloud's own configuration"
echo "ok: gcloud's own configuration is unchanged" >>"$REPORT"
for leftover in "$(dirname "$SKARBIEC_VAULT_FILE")"/.skarbiec-keygen-*; do
  [ -e "$leftover" ] && fail "a key workspace was left beside the vault: $leftover"
done
echo "ok: no key file is left beside the vault" >>"$REPORT"

jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a key"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with gcp
case "$said" in *"rotate --with gcp replaces a service-account item"*) ;; *) fail "a note was not refused naming its kind: output: $out stderr: $said" ;; esac
jq -n '{schema:"skarbiec.item.v2",kind:"service-account",fields:{credential_json:"{\"type\":\"authorized_user\"}"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "user-$RUN" --type service-account
: >"$ROOT/stdin"
WANT=refused run rotate "user-$RUN" --with gcp
case "$said" in *"not a service_account key file"*) ;; *) fail "an authorized-user credential was not refused: output: $out stderr: $said" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
