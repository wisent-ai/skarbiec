#!/usr/bin/env bash
# Real test of changing the sites one login is offered on, `skarbiec sites
# <id> --add|--remove|--set`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# It writes one login for one site, adds a second site and checks both are
# kept and login list offers the login on the new one; removes the first and
# checks only the second is left, with its well-known change-password address;
# then checks the refusals: removing a site the login is not offered on, two
# of --set, --add and --remove at once, and a domain that is not a bare host.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/autofill/sites.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/autofill/$RUN"
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
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
domains() {
  printf '%s' "$out" | jq -c .domains
}

: >"$ROOT/stdin"
WANT=ok run init "sites-owner-$RUN"
ITEM="sites-login-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"sites-user","password":"sites-secret-%s"},"context":{"domains":["first.test"]}}' \
  "$RUN" >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"

WANT=ok run sites "$ITEM" --add second.test
[ "$(domains)" = '["first.test","second.test"]' ] || fail "--add did not keep the first site and append the second: $(domains)"
WANT=ok run login list second.test
printf '%s' "$out" | jq -e --arg id "$ITEM" '.logins | any(.item == $id)' >/dev/null \
  || fail "login list does not offer the login on the site just added"
echo "ok: --add kept the first site, appended the second, and login list offers it there" >>"$REPORT"

WANT=ok run sites "$ITEM" --remove first.test
[ "$(domains)" = '["second.test"]' ] || fail "--remove did not leave only the second site: $(domains)"
WANT=ok run sites "$ITEM"
[ "$(printf '%s' "$out" | jq -r '.change_password[]')" = "https://second.test/.well-known/change-password" ] \
  || fail "sites did not name the well-known change-password address of the site left"
echo "ok: --remove left the second site, and sites names its change-password address" >>"$REPORT"

WANT=refused run sites "$ITEM" --remove first.test
names "is not offered on first.test"
WANT=refused run sites "$ITEM" --add third.test --remove second.test
names "name one of --set, --add or --remove"
WANT=refused run sites "$ITEM" --add https://third.test/login
names "is not a bare host"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
