#!/usr/bin/env bash
# Real test that `skarbiec serve` is one process: through the built binary,
# on a vault of its own under this checkout's target directory (its key file
# beside it, HOME isolated so no Stado declaration routes it elsewhere), with
# a PATH that holds no program at all.
#
# It starts `serve` and, while a sampler records the children of the serve
# process every few milliseconds, drives every path a request takes to the
# vault: /health, /readyz (which opens its canary items), operator writes of
# new items and of a new version, operator reads of a field and of an
# earlier version, `readers`, the key report, `keys check` and `recovery
# status`. Every answer must be the one the request asked for, and the
# sampler, which must have taken samples the whole time, must never have seen
# a child of the serve process. A PATH with no program means a child it tried
# to start would also fail the request it served.
#
# Usage: SKARBIEC=<binary under test> tests/serve/one_process.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test}
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/serve/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT/home" "$ROOT/empty-path"
chmod go-rwx "$ROOT"
# A checkout states its revision; a delivered copy states it with
# SKARBIEC_TEST_SOURCE_REVISION.
echo "revision: ${SKARBIEC_TEST_SOURCE_REVISION:-$(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')}" >"$REPORT"
echo "binary: $BIN; sha256: $(openssl dgst -sha256 -r "$BIN" | cut -d' ' -f1)" >>"$REPORT"
export HOME="$ROOT/home"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
SERVE=
SAMPLER=
cleanup() {
  [ -z "$SAMPLER" ] || kill "$SAMPLER" 2>/dev/null || true
  [ -z "$SERVE" ] || kill "$SERVE" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

OWNER="one-process-owner-$RUN"
PATH="$ROOT/empty-path" "$BIN" init "$OWNER" >>"$REPORT" 2>&1 || fail "init was refused with an empty PATH"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"canary","password":"canary-%s"},"context":{}}' "$RUN" \
  | PATH="$ROOT/empty-path" "$BIN" set canary --type login >>"$REPORT" 2>&1 || fail "the canary item was not written"

PATH="$ROOT/empty-path" "$BIN" serve --port 0 >"$ROOT/serve.log" 2>&1 &
SERVE=$!
ADDRESS=
for _ in $(seq 1 200); do
  ADDRESS=$(sed -n 's/.*listening on \(http:[^ ]*\).*/\1/p' "$ROOT/serve.log")
  [ -z "$ADDRESS" ] || break
  sleep 0.05
done
[ -n "$ADDRESS" ] || fail "serve did not listen: $(cat "$ROOT/serve.log")"
echo "serve pid $SERVE at $ADDRESS" >>"$REPORT"

# Every sample is one line: the moment, and each child pid of the serve
# process, or none. Linux names a process's children in
# /proc/<pid>/task/<tid>/children, read without starting a program; macOS
# has no /proc, and pgrep -P answers there (1 when there is no child).
children_of() {
  if [ -d "/proc/$1/task" ]; then
    cat /proc/"$1"/task/*/children 2>/dev/null | tr -s ' \n' ' ' | sed 's/^ *//; s/ *$//'
  else
    pgrep -lP "$1" || true
  fi
}
(
  while kill -0 "$SERVE" 2>/dev/null; do
    children=$(children_of "$SERVE")
    printf '%s %s\n' "$(date +%s)" "${children:-none}"
    sleep 0.005
  done
) >"$ROOT/children.log" &
SAMPLER=$!
# The first sample lands before any request, so the sampler watches them all.
for _ in $(seq 1 200); do
  [ ! -s "$ROOT/children.log" ] || break
  sleep 0.01
done
[ -s "$ROOT/children.log" ] || fail "the child sampler wrote no sample before the requests began"

request() {
  local method=$1 route=$2 body=${3:-}
  if [ "$method" = GET ]; then
    status=$(curl -sS -o "$ROOT/answer" -w '%{http_code}' "$ADDRESS$route")
  else
    status=$(curl -sS -o "$ROOT/answer" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      --data-binary "$body" "$ADDRESS$route")
  fi
  answer=$(cat "$ROOT/answer")
  printf '%s %s %s\nstatus: %s\nanswer: %s\n\n' "$method" "$route" "$body" "$status" "$answer" >>"$REPORT"
  [ "$status" = 200 ] || fail "$method $route answered $status: $answer"
}
is() {
  printf '%s' "$answer" | jq -e "$1" >/dev/null || fail "the answer does not satisfy $1: $answer"
  echo "ok: $1" >>"$REPORT"
}
payload() {
  jq -n --arg u "$1" --arg p "$2" \
    '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":$u,"password":$p},"context":{}} | tostring'
}

for round in 1 2 3; do
  request GET /health
  is '.ok == true'
  request GET /readyz
  is '.ok == true and (.canaries | length) > 0'
  for n in 1 2 3; do
    id="item-$round-$n"
    request POST /v1/operator/items/set-json \
      "$(jq -n --arg id "$id" --argjson p "$(payload "user-$n" "first-$round-$n")" \
        '{"positionals":[$id],"flags":{"type":"login"},"payload":$p}')"
    request POST /v1/operator/items/set-json \
      "$(jq -n --arg id "$id" --argjson p "$(payload "user-$n" "second-$round-$n")" \
        '{"positionals":[$id],"flags":{"type":"login"},"payload":$p}')"
    request POST /v1/operator/items/get \
      "$(jq -n --arg id "$id" '{"positionals":[$id],"flags":{"field":"password"}}')"
    [ "$answer" = "\"second-$round-$n\"" ] || [ "$answer" = "second-$round-$n" ] \
      || fail "$id read back as $answer"
    stamp=$(jq -r --arg id "$id" '.items[$id].history[0].created_at' "$SKARBIEC_VAULT_FILE")
    request POST /v1/operator/items/get \
      "$(jq -n --arg id "$id" --arg at "$stamp" '{"positionals":[$id],"flags":{"field":"password","at":$at}}')"
    case "$answer" in *"first-$round-$n"*) ;; *) fail "$id at $stamp read back as $answer" ;; esac
    request POST /v1/operator/items/readers "$(jq -n --arg id "$id" '{"id":$id}')"
    is '.openable_here == true and .format == "sealed"'
  done
  request POST /v1/operator/keys '{}'
  is '.ok == true'
  request POST /v1/operator/key-doctor '{}'
  is '.status == "readable"'
  request POST /v1/operator/recovery '{}'
  is 'has("recovery_fpr")'
done

kill "$SAMPLER"
wait "$SAMPLER" 2>/dev/null || true
SAMPLER=
samples=$(grep -c '' "$ROOT/children.log" || true)
seen=$(grep -vc ' none$' "$ROOT/children.log" || true)
echo "children samples: $samples; samples with a child: $seen" >>"$REPORT"
[ "$samples" -ge 50 ] || fail "the sampler took only $samples samples, too few to have watched the requests"
[ "$seen" = 0 ] || fail "serve started a child process: $(grep -v ' none$' "$ROOT/children.log" | head -5)"
echo "ok: serve had no child in $samples samples across every request" >>"$REPORT"
kill "$SERVE"
SERVE=

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
