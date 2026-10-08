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
# unknown subcommand are refused, and the hyphenated `acquisition-request`,
# which workloads written before the group still run, issues a token too.
# Every command and whether it succeeded go to the run's report.txt; no token
# or field value is written there.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/acquisition/group.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/acquisition/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
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
# WANT says whether it had to succeed (ok) or be refused (refused). Only the
# command line and the verdict are reported: an answer may carry a token.
run() {
  if out=$(set -o pipefail; "$BIN" "$@" |& cat); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
says() {
  case "$out" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in the answer" ;;
  esac
}

CONSUMER="acquisition-test-$RUN"
ITEM="acquisition-note-$RUN"
FIELD=value
VALUE="acquisition-value-$RUN"
WORKLOAD_ID="acquisition-workload-$RUN"
PRIVATE_KEY="$ROOT/workload-private.pem"
PUBLIC_KEY="$ROOT/workload-public.pem"

WANT=ok run init "acquisition-test-owner-$RUN"
WANT=ok run set "$ITEM" --type note "$FIELD=$VALUE"
openssl genpkey -algorithm ED25519 -out "$PRIVATE_KEY"
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
WANT=ok run grant issue "$CONSUMER" --capabilities "acquire:$ITEM#$FIELD" \
  --workload-public-key-file "$PUBLIC_KEY"

# One signed proof per request: the timestamp is now and the nonce is fresh.
NONCE_BYTES=$(printf '%s' '................................' | wc -c | tr -d ' ')
proof() {
  TIMESTAMP=$(date +%s)
  NONCE=$(openssl rand -base64 "$NONCE_BYTES" | tr '+/' '-_' | tr -d '=\n')
  printf 'SKARBIEC-WORKLOAD-ACQUISITION\0v1\0%s\0%s\0%s\0%s\0%s\0%s' \
    "$CONSUMER" "$ITEM" "$FIELD" "$WORKLOAD_ID" "$TIMESTAMP" "$NONCE" >"$ROOT/payload"
  SIGNATURE=$(openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -rawin -in "$ROOT/payload" \
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

WANT=ok run acquisition read "$CONSUMER" "$ITEM" "$FIELD" --token-file "$ROOT/token"
says "$VALUE" "acquisition read returns the bound field"
WANT=refused run acquisition read "$CONSUMER" "$ITEM" "$FIELD" --token-file "$ROOT/token"
says "acquisition read: unauthorized" "a spent token is refused"

WANT=refused run acquisition
says "needs a subcommand" "the acquisition group without a subcommand is refused"
WANT=refused run acquisition frobnicate
says "unknown acquisition command" "an unknown acquisition subcommand is refused"

proof
WANT=ok run acquisition-request "$CONSUMER" "$ITEM" "$FIELD" --workload-id "$WORKLOAD_ID" \
  --workload-timestamp "$TIMESTAMP" --workload-nonce "$NONCE" --workload-signature "$SIGNATURE"
[ -n "$(token_from)" ] || fail "the hyphenated acquisition-request answered no token"
echo "ok: the hyphenated acquisition-request still issues a token" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
