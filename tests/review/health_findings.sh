#!/usr/bin/env bash
# Real test of three of `skarbiec health`'s findings — one secret kept in
# several items, a sign-in address without TLS, and one account kept twice —
# through the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# Three logins: the first signs in at an http:// address; the second names the
# same site and the same username in other letter case; the third is for
# another site but holds the first one's password. health must name the
# first under insecure_addresses with that address, the first two under
# same_account for the site, and the first and third as one reused group, and
# its answer must hold no username and no password.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/review/health_findings.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/review/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"%s","password":"%s"},"context":%s}' \
    "$2" "$3" "$4" >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "health-owner-$RUN"
PLAIN="health-plain-$RUN"
TWICE="health-twice-$RUN"
REUSED="health-reused-$RUN"
SHARED_SECRET="health-shared-secret-$RUN"
USERNAME="Health-User-$RUN"
login "$PLAIN" "$USERNAME" "$SHARED_SECRET" '{"domains":["account.test"],"url":"http://account.test/login"}'
login "$TWICE" "$(printf '%s' "$USERNAME" | tr '[:upper:]' '[:lower:]')" "health-other-secret-$RUN" '{"domains":["account.test"]}'
login "$REUSED" "someone-else-$RUN" "$SHARED_SECRET" '{"domains":["elsewhere.test"]}'

WANT=ok run health
printf '%s' "$out" >"$ROOT/health.json"
jq -e --arg id "$PLAIN" '.insecure_addresses | any(.item == $id and (.addresses | index("http://account.test/login") != null))' "$ROOT/health.json" >/dev/null \
  || fail "insecure_addresses does not name the login that signs in over http"
jq -e --arg one "$PLAIN" --arg two "$TWICE" '.same_account | any(.site == "account.test" and (.items | index($one) != null) and (.items | index($two) != null))' "$ROOT/health.json" >/dev/null \
  || fail "same_account does not group the two logins of one site and username"
jq -e --arg one "$PLAIN" --arg two "$REUSED" '.reused | any((index($one) != null) and (index($two) != null))' "$ROOT/health.json" >/dev/null \
  || fail "reused does not group the two items holding one password"
echo "ok: health names the http address, the account kept twice and the reused password" >>"$REPORT"

if grep -qi "$USERNAME" "$ROOT/health.json"; then fail "health printed a username"; fi
if grep -q "$SHARED_SECRET" "$ROOT/health.json"; then fail "health printed a password"; fi
echo "ok: the answer holds no username and no password" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
