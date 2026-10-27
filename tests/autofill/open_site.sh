#!/usr/bin/env bash
# Real test of opening a login's site, `skarbiec open <id>`, through the built
# binary and the desktop's real opener, on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written. Run it on a host with a desktop session: the default
# browser opens a tab on a reserved .invalid host, which no server answers.
#
# A login on one site opens it; --change-password opens its well-known
# change-password page. A login on two sites without --site, a --site it is
# not offered on and a login with no site are refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/autofill/open_site.sh
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
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"me","password":"open-secret-%s"},"context":{"domains":%s}}' "$RUN" "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}

ONE="open-$RUN.invalid"
TWO="open-two-$RUN.invalid"
: >"$ROOT/stdin"
WANT=ok run init "open-owner-$RUN"
login "single-$RUN" "[\"$ONE\"]"
login "double-$RUN" "[\"$ONE\",\"$TWO\"]"
login "nowhere-$RUN" "[]"

WANT=ok run open "single-$RUN"
[ "$(printf '%s' "$out" | jq -r .opened)" = "https://$ONE/" ] || fail "open did not open the login's site: $out"
WANT=ok run open "single-$RUN" --change-password
[ "$(printf '%s' "$out" | jq -r .opened)" = "https://$ONE/.well-known/change-password" ] || fail "--change-password did not open the change-password page: $out"
WANT=ok run open "double-$RUN" --site "$TWO"
[ "$(printf '%s' "$out" | jq -r .opened)" = "https://$TWO/" ] || fail "--site did not choose the site named: $out"
echo "ok: open hands the site, or its change-password page, to the default browser" >>"$REPORT"

WANT=refused run open "double-$RUN"
names "name one with --site"
WANT=refused run open "single-$RUN" --site "$TWO"
names "is not offered on $TWO"
WANT=refused run open "nowhere-$RUN"
names "names no site to open"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
