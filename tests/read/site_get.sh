#!/usr/bin/env bash
# Real test of reading a login by its site, `skarbiec login get <site> --field
# <field> [--username <name>]`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# It creates the vault, writes one login for example.test with set, and
# reads its password by the site and by an address on a subdomain of it; then
# writes a second login for the same site and checks that a read without
# --username is refused naming both, that --username picks the right one, and
# that a site no login names, a one-time code of a login with no seed and a
# missing --field are refused with their causes. The audit journal must name
# the read and never the value.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/read/site_get.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/read/$RUN"
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
  if [ "$got" = ok ]; then
    printf '$ skarbiec %s\nresult: ok\n\n' "$*" >>"$REPORT"
  else
    printf '$ skarbiec %s\nresult: refused\noutput: %s\n\n' "$*" "$out" >>"$REPORT"
  fi
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
value() {
  printf '%s' "$out" | jq -r .value
}

: >"$ROOT/stdin"
WANT=ok run init "site-get-owner-$RUN"

FIRST="site-get-first-$RUN"
SECOND="site-get-second-$RUN"
SECRET_ONE="site-get-secret-one-$RUN"
SECRET_TWO="site-get-secret-two-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"first-%s","password":"%s"},"context":{"domains":["example.test"]}}' \
  "$RUN" "$SECRET_ONE" >"$ROOT/stdin"
WANT=ok run set "$FIRST" --type login
: >"$ROOT/stdin"

WANT=ok run login get example.test --field password
[ "$(value)" = "$SECRET_ONE" ] || fail "login get did not read the password of the one login offered on the site"
WANT=ok run login get https://login.example.test/path --field password
[ "$(value)" = "$SECRET_ONE" ] || fail "login get did not read the login of the parent domain from an address on a subdomain"
echo "ok: login get read the one login by its site and by an address on a subdomain" >>"$REPORT"

printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"second-%s","password":"%s"},"context":{"domains":["example.test"]}}' \
  "$RUN" "$SECRET_TWO" >"$ROOT/stdin"
WANT=ok run set "$SECOND" --type login
: >"$ROOT/stdin"

WANT=refused run login get example.test --field password
names "$FIRST"
names "$SECOND"
names "--username"
WANT=ok run login get example.test --field password --username "second-$RUN"
[ "$(value)" = "$SECRET_TWO" ] || fail "--username did not pick the second login"
echo "ok: --username picked the login it names" >>"$REPORT"

WANT=refused run login get nothing-here.test --field password
names "no login is offered on nothing-here.test"
WANT=refused run login get example.test --field one-time-code --username "first-$RUN"
names "$FIRST gives no one-time code"
WANT=refused run login get example.test
names "usage: login get"
WANT=refused run site-get example.test --field password
names "unknown command: site-get"

grep -q '"site-get"' "$SKARBIEC_AUDIT_FILE" || fail "the audit journal records no site-get entry for login get"
if grep -q "$SECRET_ONE" "$SKARBIEC_AUDIT_FILE"; then fail "the audit journal holds a value login get read"; fi
echo "ok: the journal records login get as site-get and no value" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
