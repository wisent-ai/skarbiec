#!/usr/bin/env bash
# Real test of `skarbiec expiry tokens`, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written.
#
# One item holds a token that ran out at the epoch, another one that runs
# out long after now, and a host name of three dotted parts. expiry tokens
# lists the first as expired and first, the second as valid with its issuer,
# leaves the host name alone, names a value shaped as a token whose header is
# not JSON under malformed, and with --before now lists only the expired one.
# No token is printed, and a --before that is not a moment is refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/tokens/token_expiry.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/tokens/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
b64url() {
  printf '%s' "$1" | base64 | tr -d '\n=' | tr '+/' '-_'
}
token() {
  printf '%s.%s.signature-%s' "$(b64url '{"alg":"HS256","typ":"JWT"}')" "$(b64url "$1")" "$RUN"
}
store() {
  jq -n --arg token "$2" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
  WANT=ok run set "$1" --type token
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "tokens-owner-$RUN"
NOW="$(date -u +%s)"
EPOCH=$((NOW - NOW))
EPOCH_ISO="$(jq -rn --argjson moment "$EPOCH" '$moment | todate')"
LATER=$((NOW + NOW))
OLD="old-$RUN"
FRESH="fresh-$RUN"
HOST="host-$RUN"
BROKEN="broken-$RUN"
store "$OLD" "$(token "{\"exp\":$EPOCH,\"sub\":\"secret-subject-$RUN\"}")"
store "$FRESH" "$(token "{\"exp\":$LATER,\"iss\":\"issuer-$RUN\"}")"
store "$HOST" "db.example.com"
store "$BROKEN" "$(b64url '{"alg').$(b64url '{"exp":true}').signature-$RUN"

WANT=ok run expiry tokens
case "$out" in *"signature-$RUN"*|*"secret-subject-$RUN"*) fail "expiry tokens printed a token or its subject" ;; esac
printf '%s' "$out" >"$ROOT/tokens.json"
jq -e --arg old "$OLD" --arg epoch "$EPOCH_ISO" '.tokens[0].item == $old and .tokens[0].expired and .tokens[0].expires_at == $epoch' "$ROOT/tokens.json" >/dev/null \
  || fail "the token that ran out at the epoch is not first and expired"
jq -e --arg fresh "$FRESH" --arg issuer "issuer-$RUN" '.tokens | any(.item == $fresh and (.expired | not) and .issuer == $issuer)' "$ROOT/tokens.json" >/dev/null \
  || fail "the token running out later is not listed valid with its issuer"
jq -e --arg host "$HOST" '[.tokens[].item, .malformed[].item] | index($host) == null' "$ROOT/tokens.json" >/dev/null \
  || fail "a host name was taken for a token"
jq -e --arg broken "$BROKEN" '.malformed | any(.item == $broken and (.error | contains("header is not JSON")))' "$ROOT/tokens.json" >/dev/null \
  || fail "the value shaped as a token with a header that is not JSON is not named malformed"
echo "ok: tokens are listed soonest end first, a host name is left alone and a broken one is named" >>"$REPORT"

WANT=ok run expiry tokens --before "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -e --arg old "$OLD" '[.tokens[].item] == [$old]' <<<"$out" >/dev/null || fail "--before now did not keep only the expired token"
echo "ok: --before keeps only the tokens ending before it" >>"$REPORT"

WANT=refused run expiry tokens --before tomorrow
names "--before tomorrow is not a UTC time"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
