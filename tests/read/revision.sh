#!/usr/bin/env bash
# Real test of an item's revision, the version of its value a reader compares
# against the value it holds: `skarbiec get <id> --revision` on the CLI and
# `POST /v1/items/revision` on the API of a real `skarbiec serve`, through the
# built binary on a vault of its own (SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE
# and GNUPGHOME point into this checkout's target directory, so the
# operator's vault and keyring are never read or written).
#
# It writes one item, grants a consumer `read` of one field, and checks:
# - the CLI and the API name the same item_uid and revision, and the API's
#   revision answer carries no value;
# - `/v1/items/read` returns the same revision beside the value;
# - writing a new value changes the revision, and the read then returns the
#   new value under it;
# - retagging (no new value) leaves the revision as it was;
# - a wrong bearer and an ungranted field are refused 403, a missing id 400,
#   a trashed item 410, and `get --revision --field` is refused naming both;
# - a request with no x-consumer, or with no bearer, is refused 401 naming
#   the header it lacks.
# - a second real broker with an empty keyring can return the revision but
#   refuses the encrypted value with the actual missing-secret-key cause;
#   the original broker still reads the unchanged value afterward.
# Every command, curl request and verdict goes to the run's report.txt;
# values and bearers are never written there.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run tests/read/revision.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/revision/$RUN"
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
SERVE_PID=
EMPTY_KEYRING="$PWD/target/e$$"
EMPTY_SERVE_PID=
# Cleanup runs on every exit; a step that cannot be done is written to the
# report with the command's own error rather than passed over.
cleanup_step() {
  if ! "$@" 2>>"$REPORT"; then echo "cleanup: $* did not complete" >>"$REPORT"; fi
}
cleanup() {
  if [ -n "$SERVE_PID" ]; then cleanup_step kill "$SERVE_PID"; fi
  if [ -n "$EMPTY_SERVE_PID" ]; then cleanup_step kill "$EMPTY_SERVE_PID"; fi
  if [ -d "$EMPTY_KEYRING" ]; then
    cleanup_step gpgconf --homedir "$EMPTY_KEYRING" --kill all
    rm -rf "$EMPTY_KEYRING"
  fi
  cleanup_step gpgconf --homedir "$GNUPGHOME" --kill all
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
# One JSON string or number member of $out.
member() {
  printf '%s' "$out" | tr -d '\n' | sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p"
}
# POST $2 as JSON to the API route $1 as $CONSUMER with bearer $3; $out holds
# the body and $status the HTTP status.
api() {
  status=$(curl -sS -o "$ROOT/body" -w '%{http_code}' -X POST "http://$ADDRESS$1" \
    -H 'content-type: application/json' -H "x-consumer: $CONSUMER" \
    -H "authorization: Bearer $3" -d "$2")
  out=$(cat "$ROOT/body")
  printf 'POST %s %s\nstatus: %s\n\n' "$1" "$2" "$status" >>"$REPORT"
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

ITEM="revision-note-$RUN"
FIELD=value
CONSUMER="revision-test-$RUN"

WANT=ok run init "revision-test-owner-$RUN"
jq -n --arg value "first-$RUN" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set "$ITEM" --type note
WANT=ok run grant issue "$CONSUMER" --capabilities "read:$ITEM#$FIELD" --until-revoked
TOKEN=$(member token)
[ -n "$TOKEN" ] || fail "grant issue answered no token"

WANT=ok run get "$ITEM" --revision
CLI_UID=$(member item_uid)
CLI_REVISION=$(member revision)
[ -n "$CLI_UID" ] && [ -n "$CLI_REVISION" ] || fail "get --revision named no item_uid or revision: $out"
case "$out$said" in *"first-$RUN"*) fail "get --revision printed the value" ;; esac
echo "ok: get --revision names the item_uid and revision and no value" >>"$REPORT"

# Any free loopback port: serve prints the address it bound.
mkfifo "$ROOT/serve.log"
"$BIN" serve --port "0" &>"$ROOT/serve.log" &
SERVE_PID=$!
while read -r line; do
  case "$line" in
    *"listening on http://"*) ADDRESS=${line#*http://}; ADDRESS=${ADDRESS%% *}; break ;;
  esac
done <"$ROOT/serve.log"
cat "$ROOT/serve.log" >/dev/null &
echo "serve: $ADDRESS" >>"$REPORT"

cp "$SKARBIEC_AUDIT_FILE" "$ROOT/audit-before-revision.jsonl"
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "200" ] || fail "revision answered $status: $out"
[ "$(member item_uid)" = "$CLI_UID" ] && [ "$(member revision)" = "$CLI_REVISION" ] \
  || fail "the API's version differs from the CLI's: $out"
case "$out" in *"first-$RUN"*|*'"value"'*) fail "the revision answer carries the value" ;; esac
echo "ok: /v1/items/revision names the CLI's item_uid and revision and no value" >>"$REPORT"
cmp "$SKARBIEC_AUDIT_FILE" "$ROOT/audit-before-revision.jsonl" \
  || fail "revision-only API read changed the audit journal"
echo "ok: revision-only API read leaves the exact audit bytes unchanged" >>"$REPORT"

api /v1/items/read "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "200" ] && [ "$(member value)" = "first-$RUN" ] && [ "$(member revision)" = "$CLI_REVISION" ] \
  || fail "the read did not return the value under the same revision: status $status"
echo "ok: /v1/items/read returns the value under the same revision" >>"$REPORT"

jq -n --arg value "second-$RUN" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set "$ITEM" --type note
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
SECOND=$(member revision)
[ "$status" = "200" ] && [ -n "$SECOND" ] && [ "$SECOND" != "$CLI_REVISION" ] \
  || fail "a new value did not change the revision: $out"
api /v1/items/read "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$(member value)" = "second-$RUN" ] && [ "$(member revision)" = "$SECOND" ] \
  || fail "the read after the write did not return the new value under the new revision"
echo "ok: a new value changes the revision and the read returns it under the new one" >>"$REPORT"

WANT=ok run retag "$ITEM" --tags "revision-test"
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$(member revision)" = "$SECOND" ] || fail "retagging changed the revision: $out"
echo "ok: retagging leaves the revision as it was" >>"$REPORT"

# The consumer grant lives in the vault envelope, not in the owner's
# secret keyring. Exercise that distinction with an actual second broker.
OWNER_ADDRESS=$ADDRESS
mkdir "$EMPTY_KEYRING"
chmod go-rwx "$EMPTY_KEYRING"
mkfifo "$ROOT/empty-keyring-serve.log"
GNUPGHOME="$EMPTY_KEYRING" LC_ALL=C "$BIN" serve --port "0" &>"$ROOT/empty-keyring-serve.log" &
EMPTY_SERVE_PID=$!
ADDRESS=
while read -r line; do
  case "$line" in
    *"listening on http://"*) ADDRESS=${line#*http://}; ADDRESS=${ADDRESS%% *}; break ;;
  esac
done <"$ROOT/empty-keyring-serve.log"
[ -n "$ADDRESS" ] || fail "the empty-keyring broker exited without a listening address"
cat "$ROOT/empty-keyring-serve.log" >"$ROOT/empty-keyring-server-output" &
echo "empty-keyring serve: $ADDRESS; keyring: $EMPTY_KEYRING" >>"$REPORT"
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "200" ] && [ "$(member item_uid)" = "$CLI_UID" ] && [ "$(member revision)" = "$SECOND" ] \
  || fail "the empty-keyring broker could not return the actual item revision: status $status"
api /v1/items/read "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "503" ] || fail "missing decryption authority answered $status instead of an infrastructure refusal"
printf '%s' "$out" | jq -e '.error_code == "infra_down" and (.detail | contains("No secret key")) and (has("value") | not)' >/dev/null \
  || fail "the decryption refusal omitted the actual GnuPG cause or returned a value"
case "$out" in *"second-$RUN"*) fail "the failed decryption response disclosed the secret" ;; esac
printf '%s\n' "$out" >"$ROOT/decryption-refusal.json"
ADDRESS=$OWNER_ADDRESS
api /v1/items/read "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "200" ] && [ "$(member value)" = "second-$RUN" ] && [ "$(member revision)" = "$SECOND" ] \
  || fail "the refused decryption changed the original broker's stored value or revision"
echo "ok: missing secret key is an explicit decryption failure; original value and revision remain readable" >>"$REPORT"

api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "not-the-bearer-$RUN"
[ "$status" = "403" ] || fail "a wrong bearer answered $status"
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"other\"}" "$TOKEN"
[ "$status" = "403" ] || fail "an ungranted field answered $status"
api /v1/items/revision "{\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "400" ] || fail "a request with no id answered $status"
echo "ok: a wrong bearer and an ungranted field are refused 403, a missing id 400" >>"$REPORT"

# A request that presents no consumer, or a consumer with no bearer, is
# refused 401 naming the header it lacks, before the vault is read; it is
# never answered as a grant the consumer does not hold.
unidentified() {
  status=$(curl -sS -o "$ROOT/body" -w '%{http_code}' -X POST "http://$ADDRESS/v1/items/read" \
    -H 'content-type: application/json' "$@" -d "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}")
  out=$(cat "$ROOT/body")
  printf 'POST /v1/items/read (headers: %s)\nstatus: %s\nbody: %s\n\n' "$*" "$status" "$out" >>"$REPORT"
}
unidentified -H "authorization: Bearer $TOKEN"
[ "$status" = "401" ] && printf '%s' "$out" | jq -e '.error | contains("x-consumer")' >/dev/null \
  || fail "a request with no x-consumer answered $status: $out"
unidentified -H "x-consumer: $CONSUMER"
[ "$status" = "401" ] && printf '%s' "$out" | jq -e --arg consumer "$CONSUMER" '.error | contains("carries no bearer") and contains($consumer)' >/dev/null \
  || fail "a request with no bearer answered $status: $out"
echo "ok: a missing x-consumer or bearer is refused 401 naming the header it lacks" >>"$REPORT"

WANT=refused run get "$ITEM" --revision --field "$FIELD"
says "--field or --revision" "get refuses --revision with --field, naming both"

WANT=ok run delete "$ITEM"
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "410" ] || fail "a trashed item answered $status"
echo "ok: a trashed item is refused 410" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
