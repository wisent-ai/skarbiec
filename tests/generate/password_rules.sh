#!/usr/bin/env bash
# Real test of generating from a site's password rules, `skarbiec generate
# --rules '<rules>'`, `skarbiec password rules <id> --set|--clear` and
# `generate --rules-of <id> --into <id> --field password`, through the built
# binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# The rules allow lower, upper, digits and only the symbols in the set, and
# cap the length. The printed password has exactly that length, holds every
# class, and every symbol in it is from the set. Rules kept on a login give
# the same: the password written into it obeys them and is never printed.
# Rules with no length, a class the language does not name, both --rules and
# --rules-of, and --rules-of a login keeping none are refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/generate/password_rules.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/generate/$RUN"
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
# Fails naming the first rule the value breaks: its length, one of every
# class, and no character outside lower, upper, digits and the allowed set.
obey() {
  [ "${#1}" = "$CAP" ] || fail "$2 is ${#1} characters, not $CAP"
  case "$1" in *[[:lower:]]*) ;; *) fail "$2 holds no lower-case letter" ;; esac
  case "$1" in *[[:upper:]]*) ;; *) fail "$2 holds no upper-case letter" ;; esac
  case "$1" in *[[:digit:]]*) ;; *) fail "$2 holds no digit" ;; esac
  case "$1" in *[![:alnum:]_!-]*) fail "$2 holds a character the rules do not allow" ;; esac
}

CAP="$(printf '%s' "$RUN" | wc -c | tr -d ' ')"
RULES="minlength: $CAP; maxlength: $CAP; required: lower; required: upper; required: digit; allowed: [-_!]"

: >"$ROOT/stdin"
WANT=ok run init "rules-owner-$RUN"

WANT=ok run generate --rules "$RULES"
obey "$(printf '%s' "$out" | jq -r .password)" "the printed password"
echo "ok: generate --rules prints a password of the capped length from the allowed characters" >>"$REPORT"

LOGIN="rules-login-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"me","password":"old-%s"},"context":{}}' "$RUN" >"$ROOT/stdin"
WANT=ok run set "$LOGIN" --type login
: >"$ROOT/stdin"
WANT=refused run generate --rules-of "$LOGIN"
names "$LOGIN keeps no password rules"
WANT=ok run password rules "$LOGIN" --set "$RULES"
WANT=ok run password rules "$LOGIN"
[ "$(printf '%s' "$out" | jq -r .password_rules)" = "$RULES" ] || fail "password rules did not read back the rules set"
WANT=ok run generate --rules-of "$LOGIN" --into "$LOGIN" --field password
case "$out" in *'"password"'*) fail "generate --into printed a value: $out" ;; esac
WANT=ok run get "$LOGIN" --field password
obey "$out" "the password written into the login"
echo "ok: rules kept on a login shape the password generate --into writes, which is never printed" >>"$REPORT"

WANT=ok run password rules "$LOGIN" --clear
WANT=ok run password rules "$LOGIN"
[ "$(printf '%s' "$out" | jq -r .password_rules)" = null ] || fail "--clear left the rules in place"

SIGNUP="rules-signup-$RUN"
WANT=ok run login new "$SIGNUP" --username me --rules "$RULES"
WANT=ok run password rules "$SIGNUP"
[ "$(printf '%s' "$out" | jq -r .password_rules)" = "$RULES" ] || fail "login new --rules did not keep the rules on the login"
WANT=ok run get "$SIGNUP" --field password
obey "$out" "the password login new made"
echo "ok: login new --rules makes a password the rules accept and keeps them on the login" >>"$REPORT"

# --lookup against the real Password Manager Resources list: the site is the
# first one listed whose rules state a length, so the generator can follow
# them; a login on that site gets exactly the listed rules, and a login on a
# reserved .invalid host is refused naming that the list holds none.
LISTED="$ROOT/password-rules.json"
curl -sS --fail https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/password-rules.json -o "$LISTED"
SITE="$(jq -r '[to_entries[] | select(.value["password-rules"] | test("maxlength|minlength"))][0].key' "$LISTED")"
SITE_RULES="$(jq -r --arg site "$SITE" '.[$site]["password-rules"]' "$LISTED")"
echo "site from the list: $SITE ($SITE_RULES)" >>"$REPORT"
LISTED_LOGIN="rules-listed-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"me","password":"old-%s"},"context":{"domains":["%s"]}}' "$RUN" "$SITE" >"$ROOT/stdin"
WANT=ok run set "$LISTED_LOGIN" --type login
: >"$ROOT/stdin"
WANT=ok run password rules "$LISTED_LOGIN" --lookup
[ "$(printf '%s' "$out" | jq -r .found_for)" = "$SITE" ] || fail "--lookup did not name $SITE as where the rules were found"
WANT=ok run password rules "$LISTED_LOGIN"
[ "$(printf '%s' "$out" | jq -r .password_rules)" = "$(printf '%s' "$SITE_RULES" | sed -e 's/^ *//' -e 's/ *$//')" ] \
  || fail "--lookup did not record the rules the list holds for $SITE"
echo "ok: --lookup records the rules Password Manager Resources lists for the login's site" >>"$REPORT"
UNLISTED="rules-unlisted-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"me","password":"old-%s"},"context":{"domains":["rules-%s.invalid"]}}' "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set "$UNLISTED" --type login
: >"$ROOT/stdin"
WANT=refused run password rules "$UNLISTED" --lookup
names "Password Manager Resources lists no password rules for rules-$RUN.invalid"
WANT=refused run password rules "$LOGIN" --lookup --clear
names "give one"

WANT=refused run generate --rules "required: lower"
names "state neither minlength nor maxlength"
WANT=refused run generate --rules "maxlength: $CAP; required: emoji"
names "password rule class emoji"
WANT=refused run password rules "$LOGIN" --set "maxlength: $CAP; required: emoji"
names "password rule class emoji"
WANT=refused run generate --rules "$RULES" --rules-of "$LOGIN"
names "--rules and --rules-of"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
