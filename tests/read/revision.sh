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
#   a trashed item 410, and `get --revision --field` is refused naming both.
# Every command, curl request and verdict goes to the run's report.txt;
# values and bearers are never written there.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/read/revision.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/revision/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
SERVE_PID=
cleanup() {
  if [ -n "$SERVE_PID" ]; then kill "$SERVE_PID" || true; fi
  gpgconf --homedir "$GNUPGHOME" --kill all || true
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
says() {
  case "$out" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in: $out" ;;
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

ITEM="revision-note-$RUN"
FIELD=value
CONSUMER="revision-test-$RUN"

WANT=ok run init "revision-test-owner-$RUN"
WANT=ok run set "$ITEM" --type note "$FIELD=first-$RUN"
WANT=ok run grant issue "$CONSUMER" --capabilities "read:$ITEM#$FIELD"
TOKEN=$(member token)
[ -n "$TOKEN" ] || fail "grant issue answered no token"

WANT=ok run get "$ITEM" --revision
CLI_UID=$(member item_uid)
CLI_REVISION=$(member revision)
[ -n "$CLI_UID" ] && [ -n "$CLI_REVISION" ] || fail "get --revision named no item_uid or revision: $out"
case "$out" in *"first-$RUN"*) fail "get --revision printed the value" ;; esac
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

api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "200" ] || fail "revision answered $status: $out"
[ "$(member item_uid)" = "$CLI_UID" ] && [ "$(member revision)" = "$CLI_REVISION" ] \
  || fail "the API's version differs from the CLI's: $out"
case "$out" in *"first-$RUN"*|*'"value"'*) fail "the revision answer carries the value" ;; esac
echo "ok: /v1/items/revision names the CLI's item_uid and revision and no value" >>"$REPORT"

api /v1/items/read "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "200" ] && [ "$(member value)" = "first-$RUN" ] && [ "$(member revision)" = "$CLI_REVISION" ] \
  || fail "the read did not return the value under the same revision: status $status"
echo "ok: /v1/items/read returns the value under the same revision" >>"$REPORT"

WANT=ok run set "$ITEM" --type note "$FIELD=second-$RUN"
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

api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "not-the-bearer-$RUN"
[ "$status" = "403" ] || fail "a wrong bearer answered $status"
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"other\"}" "$TOKEN"
[ "$status" = "403" ] || fail "an ungranted field answered $status"
api /v1/items/revision "{\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "400" ] || fail "a request with no id answered $status"
echo "ok: a wrong bearer and an ungranted field are refused 403, a missing id 400" >>"$REPORT"

WANT=refused run get "$ITEM" --revision --field "$FIELD"
says "--field or --revision" "get refuses --revision with --field, naming both"

WANT=ok run delete "$ITEM"
api /v1/items/revision "{\"id\":\"$ITEM\",\"field\":\"$FIELD\"}" "$TOKEN"
[ "$status" = "410" ] || fail "a trashed item answered $status"
echo "ok: a trashed item is refused 410" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
