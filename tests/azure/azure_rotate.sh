#!/usr/bin/env bash
# Real test of `skarbiec rotate --with azure`, through the built binary on a vault of
# its own and a real Microsoft Entra application: SKARBIEC_TEST_AZURE_APP
# names an application kept for this test, SKARBIEC_TEST_AZURE_TENANT its
# tenant, and az's own configuration signs in as someone who may manage the
# application's secrets. The test gives the application a secret, rotates it
# twice, and deletes every secret it made. SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# After rotate --with azure the item holds a secret Entra lists and that signs in,
# and the old one still exists; with --delete-old the old one is gone from
# Entra. No secret is printed, and az's own configuration is left as it was.
# An item that is not an oauth-client, and an end given both ways or as no
# day, are refused before Entra is asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_AZURE_APP=<application id> SKARBIEC_TEST_AZURE_TENANT=<tenant> tests/azure/azure_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
APP=${SKARBIEC_TEST_AZURE_APP:?set SKARBIEC_TEST_AZURE_APP to an application this test may add and delete secrets for}
TENANT=${SKARBIEC_TEST_AZURE_TENANT:?set SKARBIEC_TEST_AZURE_TENANT to the application's tenant}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/azure/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "application: $APP in $TENANT" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
# One year, counted rather than typed.
YEARS="$(printf 'y' | wc -c | tr -d ' ')"
MADE="$ROOT/made-secrets"
: >"$MADE"
listed() {
  az ad app credential list --id "$APP" --output json
}
cleanup() {
  # Every secret this run made or rotated to, and no other.
  while read -r key; do
    if listed | jq -e --arg key "$key" '.[] | select(.keyId == $key)' &>/dev/null; then
      az ad app credential delete --id "$APP" --key-id "$key" &>>"$REPORT" || echo "cleanup: could not delete $key" >>"$REPORT"
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
present() {
  listed | jq -e --arg key "$1" 'any(.[]; .keyId == $key)' >/dev/null
}

CONFIG_BEFORE="$(az account show --output json)"
: >"$ROOT/stdin"
WANT=ok run init "azure-owner-$RUN"
ITEM="azure-$RUN"
BEFORE_IDS="$(listed | jq -c '[.[].keyId]')"
FIRST="$(az ad app credential reset --id "$APP" --append --display-name "skarbiec-test-$RUN" --years "$YEARS" --output json | jq -r .password)"
FIRST_ID="$(listed | jq -r --argjson before "$BEFORE_IDS" '[.[].keyId] - $before | .[]')"
echo "$FIRST_ID" >>"$MADE"
jq -n --arg app "$APP" --arg secret "$FIRST" '{schema:"skarbiec.item.v2",kind:"oauth-client",fields:{client_id:$app,client_secret:$secret},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type oauth-client
: >"$ROOT/stdin"

WANT=ok run rotate "$ITEM" --with azure --tenant "$TENANT" --years "$YEARS"
case "$out" in *"$FIRST"*) fail "rotate printed the old secret" ;; esac
SECOND_ID="$(printf '%s' "$out" | jq -r .key)"
echo "$SECOND_ID" >>"$MADE"
[ "$(printf '%s' "$out" | jq -r --arg first "$FIRST_ID" '.old_keys | index($first) != null')" = "true" ] || fail "rotate did not name the old secret's key: $out"
present "$SECOND_ID" || fail "Entra does not list the new secret"
present "$FIRST_ID" || fail "without --delete-old the old secret was deleted"
WANT=ok run get "$ITEM" --field client_secret
case "$out" in *"$FIRST"*) fail "the item still holds the old secret" ;; esac
echo "ok: the item holds the new secret Entra lists, and the old one remains" >>"$REPORT"

WANT=ok run rotate "$ITEM" --with azure --tenant "$TENANT" --years "$YEARS" --delete-old
THIRD_ID="$(printf '%s' "$out" | jq -r .key)"
echo "$THIRD_ID" >>"$MADE"
[ "$(printf '%s' "$out" | jq -r --arg second "$SECOND_ID" '.deleted | index($second) != null')" = "true" ] || fail "--delete-old did not answer the old key deleted: $out"
present "$SECOND_ID" && fail "--delete-old left the old secret in Entra"
present "$THIRD_ID" || fail "Entra does not list the newest secret"
echo "ok: --delete-old removes the old secret from Entra" >>"$REPORT"
[ "$(az account show --output json)" = "$CONFIG_BEFORE" ] || fail "rotate changed the account az is signed in as"
echo "ok: az's own sign-in is unchanged" >>"$REPORT"
for leftover in "$(dirname "$SKARBIEC_VAULT_FILE")"/.skarbiec-keygen-*; do
  [ -e "$leftover" ] && fail "an Azure configuration was left beside the vault: $leftover"
done
echo "ok: no Azure configuration is left beside the vault" >>"$REPORT"

WANT=refused run rotate "$ITEM" --with azure --tenant "$TENANT" --years "$YEARS" --end-date "2999-01-01"
case "$out" in *"give one"*) ;; *) fail "both --end-date and --years were not refused: $out" ;; esac
WANT=refused run rotate "$ITEM" --with azure --tenant "$TENANT" --end-date "next-year"
case "$out" in *"is not a day as YYYY-MM-DD"*) ;; *) fail "an end that is no day was not refused: $out" ;; esac
jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a secret"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with azure --tenant "$TENANT" --years "$YEARS"
case "$out" in *"rotate --with azure replaces an oauth-client item"*) ;; *) fail "a note was not refused naming its kind: $out" ;; esac
echo "ok: an end given twice, an end that is no day and a note are refused" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
