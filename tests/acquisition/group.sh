#!/usr/bin/env bash
# Real test of `skarbiec acquisition request|read` through the built binary on a
# vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE, the acquisition
# state and GNUPGHOME point into this checkout's target directory, so the
# operator's vault and keyring are never read or written.
#
# It creates the vault and one note, registers a workload key with an acquire
# grant for that field, signs a proof, asks `acquisition request` for a one-use
# token, reads the field once with `acquisition read --token-file`, and checks
# that the spent token is refused. The group without a subcommand and an
# unknown subcommand are refused, and the withdrawn hyphenated
# `acquisition-request` is refused as an unknown command, issuing nothing.
# Every command and whether it succeeded go to the run's report.txt; no token
# or field value is written there.
#
# Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION, SKARBIEC_OPENSSL,
# SKARBIEC_TEST_GRANT_TTL_SECONDS and SKARBIEC_TEST_HTTP_PORT, then run this file.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
GRANT_TTL=${SKARBIEC_TEST_GRANT_TTL_SECONDS:?set the acquire grant lifetime in seconds for this real journey}
OPENSSL=${SKARBIEC_OPENSSL:?set SKARBIEC_OPENSSL to an Ed25519-capable OpenSSL binary}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
HTTP_PORT=${SKARBIEC_TEST_HTTP_PORT:?set the isolated broker bind port for real HTTP qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/acquisition/$RUN"
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
export SKARBIEC_ACQUISITION_FILE="$ROOT/acquisitions.json"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# Runs one command, its standard output and standard error together in $out;
# WANT says whether it had to succeed (ok) or be refused (refused). The
# command, observed exit status and verdict are reported, never token output.
run() {
  if out=$("$BIN" "$@" &>/dev/stdout); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  printf '$ skarbiec %s\nexit: %s\nresult: %s\n\n' "$*" "$status" "$got" >>"$REPORT"
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

CONSUMER="acquisition-test-$RUN"
ITEM="acquisition-note-$RUN"
FIELD=value
VALUE="acquisition-value-$RUN"
WORKLOAD_ID="acquisition-workload-$RUN"
PRIVATE_KEY="$ROOT/workload-private.pem"
PUBLIC_KEY="$ROOT/workload-public.pem"

WANT=ok run init "acquisition-test-owner-$RUN"
jq -n --arg value "$VALUE" \
  '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' \
  | WANT=ok run set-json "$ITEM" --type note
"$OPENSSL" genpkey -algorithm ED25519 -out "$PRIVATE_KEY"
"$OPENSSL" pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
WANT=ok run grant issue "$CONSUMER" --capabilities "acquire:$ITEM#$FIELD" \
  --workload-public-key-file "$PUBLIC_KEY" --ttl-seconds "$GRANT_TTL"

# One signed proof per request: the timestamp is now and the nonce is fresh.
NONCE_BYTES=$(printf '%s' '................................' | wc -c | tr -d ' ')
proof() {
  TIMESTAMP=$(date +%s)
  NONCE=$("$OPENSSL" rand -base64 "$NONCE_BYTES" | tr '+/' '-_' | tr -d '=\n')
  printf 'SKARBIEC-WORKLOAD-ACQUISITION\0v1\0%s\0%s\0%s\0%s\0%s\0%s' \
    "$CONSUMER" "$ITEM" "$FIELD" "$WORKLOAD_ID" "$TIMESTAMP" "$NONCE" >"$ROOT/payload"
  SIGNATURE=$("$OPENSSL" pkeyutl -sign -inkey "$PRIVATE_KEY" -rawin -in "$ROOT/payload" \
    | od -An -tx1 | tr -d ' \n')
  rm -f "$ROOT/payload"
}
token_from() {
  printf '%s\n' "$out" | sed -n 's/.*"token": "\([^"]*\)".*/\1/p'
}

proof
WANT=ok run acquisition request "$CONSUMER" "$ITEM" "$FIELD" --workload-id "$WORKLOAD_ID" \
  --workload-timestamp "$TIMESTAMP" --workload-nonce "$NONCE" --workload-signature "$SIGNATURE"
TOKEN=$(token_from)
[ -n "$TOKEN" ] || fail "acquisition request answered no token"
printf '%s' "$TOKEN" >"$ROOT/token"
chmod u=rw,go= "$ROOT/token"
GRANT_EXPIRY=$(jq -er --arg consumer "$CONSUMER" '.tokens[$consumer].expires_at' "$SKARBIEC_VAULT_FILE")
jq -e --arg consumer "$CONSUMER" --argjson expiry "$GRANT_EXPIRY" \
  '.tokens | any(.consumer == $consumer and .expires_at == $expiry)' \
  "$SKARBIEC_ACQUISITION_FILE" >/dev/null \
  || fail "the issued bearer did not inherit the persisted lending grant expiry"
echo "ok: acquisition bearer inherits the persisted grant expiry" >>"$REPORT"

WANT=ok run acquisition read "$CONSUMER" "$ITEM" "$FIELD" --token-file "$ROOT/token"
says "$VALUE" "acquisition read returns the bound field"
WANT=refused run acquisition read "$CONSUMER" "$ITEM" "$FIELD" --token-file "$ROOT/token"
says "acquisition read: unauthorized" "a spent token is refused"
WANT=refused run acquisition request "$CONSUMER" "$ITEM" "$FIELD" --workload-id "$WORKLOAD_ID" \
  --workload-timestamp "$TIMESTAMP" --workload-nonce "$NONCE" --workload-signature "$SIGNATURE"
says "acquisition request: unauthorized" "the proof nonce remains spent after bearer consumption"

WANT=refused run acquisition
says "needs a subcommand" "the acquisition group without a subcommand is refused"
WANT=refused run acquisition frobnicate
says "unknown acquisition command" "an unknown acquisition subcommand is refused"

proof
WANT=refused run acquisition-request "$CONSUMER" "$ITEM" "$FIELD" --workload-id "$WORKLOAD_ID" \
  --workload-timestamp "$TIMESTAMP" --workload-nonce "$NONCE" --workload-signature "$SIGNATURE"
[ -z "$(token_from)" ] || fail "the withdrawn acquisition-request still issued a token"
echo "ok: the withdrawn acquisition-request is refused and issues no token" >>"$REPORT"

proof
WANT=ok run acquisition request "$CONSUMER" "$ITEM" "$FIELD" --workload-id "$WORKLOAD_ID" \
  --workload-timestamp "$TIMESTAMP" --workload-nonce "$NONCE" --workload-signature "$SIGNATURE"
TOKEN=$(token_from)
[ -n "$TOKEN" ] || fail "HTTP qualification requires a genuinely issued bearer"
printf '%s' "$TOKEN" >"$ROOT/token"
chmod u=rw,go= "$ROOT/token"
SKARBIEC="$BIN" SKARBIEC_TEST_SOURCE_REVISION="$SOURCE_REVISION" \
  SKARBIEC_TEST_HTTP_PORT="$HTTP_PORT" SKARBIEC_TEST_CONSUMER="$CONSUMER" \
  SKARBIEC_TEST_ITEM="$ITEM" SKARBIEC_TEST_FIELD="$FIELD" SKARBIEC_TEST_VALUE="$VALUE" \
  SKARBIEC_TEST_TOKEN_FILE="$ROOT/token" node tests/acquisition/http.mjs
echo "ok: real HTTP storage refusal, unchanged bearer, recovery and replay; $ROOT/http-report.json" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
