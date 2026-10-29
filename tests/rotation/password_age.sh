#!/usr/bin/env bash
# Real test of `skarbiec password age`, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written.
#
# It writes one login, rewrites it with only its username changed and checks
# that its password still dates from the first save; then changes the password
# and checks that it now dates from that save. The dates are compared with the
# stamps `history` lists, so no clock has to move between writes. It also
# checks the refusals: an id together with --set-before, and a --set-before
# that is not a UTC time.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/rotation/password_age.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/rotation/$RUN"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  if [ "$got" = ok ]; then
    printf '$ skarbiec %s\nresult: ok\noutput: %s\nstderr: %s\n\n' "$*" "$out" "$said" >>"$REPORT"
  else
    printf '$ skarbiec %s\nresult: refused\noutput: %s\nstderr: %s\n\n' "$*" "$out" "$said" >>"$REPORT"
  fi
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said; output: $out" ;;
  esac
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"%s","password":"%s"},"context":{"domains":["example.test"]}}' \
    "$1" "$2" >"$ROOT/stdin"
  WANT=ok run set "$ITEM" --type login
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "password-age-owner-$RUN"
ITEM="password-age-login-$RUN"

login "first-user" "first-secret-$RUN"
login "second-user" "first-secret-$RUN"
WANT=ok run history "$ITEM"
FIRST_SAVE=$(printf '%s' "$out" | jq -r '.versions | first | .at')
WANT=ok run password age "$ITEM"
[ "$(printf '%s' "$out" | jq -r .set_at)" = "$FIRST_SAVE" ] \
  || fail "a save that changed only the username moved the password's date"
echo "ok: a username change left the password dated from the first save" >>"$REPORT"

login "second-user" "second-secret-$RUN"
WANT=ok run history "$ITEM"
LAST_SAVE=$(printf '%s' "$out" | jq -r '.versions | last | .at')
WANT=ok run password age "$ITEM"
[ "$(printf '%s' "$out" | jq -r .set_at)" = "$LAST_SAVE" ] \
  || fail "the save that changed the password did not date it"
WANT=ok run password age
printf '%s' "$out" | jq -e --arg id "$ITEM" '.logins | any(.id == $id)' >/dev/null \
  || fail "password age without an id did not list the login"
echo "ok: the password is dated from the save that changed it, and the list carries it" >>"$REPORT"
if grep -q "second-secret-$RUN" "$REPORT"; then fail "password age printed a password"; fi

WANT=refused run password age "$ITEM" --set-before "$LAST_SAVE"
names "usage: password age"
WANT=refused run password-age "$ITEM"
names "unknown command: password-age"
WANT=refused run password age --set-before yesterday
names "--set-before yesterday is not a UTC time"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
