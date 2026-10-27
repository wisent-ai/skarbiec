#!/usr/bin/env bash
# Real test of `skarbiec health` naming logins whose password breaks the
# password rules they keep for their site, through the built binary on a
# vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# point into this checkout's target directory, so the operator's vault and
# keyring are never read or written.
#
# A login holds a lower-case password with a hyphen and digits, longer than
# its rules allow; its rules require an upper-case letter and allow only
# lower-case letters and digits. health lists it under breaks_site_rules with
# the maxlength rule, the required upper rule and the hyphen outside the
# allowed classes, and ok is false. After `generate --rules-of <id> --into
# <id> --field password` it is no longer listed. A login whose recorded rules
# name a class the language does not is reported in unreadable naming that
# class, never counted as following them. No password reaches the answer.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/generate/site_rules_health.sh
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

: >"$ROOT/stdin"
WANT=ok run init "site-rules-owner-$RUN"

# The pid's digits: the cap is their count, and the password is longer.
DIGITS="$$"
CAP="$(printf '%s' "$DIGITS" | wc -c | tr -d ' ')"
PASSWORD="old-password-$DIGITS"
RULES="maxlength: $CAP; required: upper; allowed: lower, digit"
LOGIN="site-rules-$RUN"
jq -n --arg password "$PASSWORD" --arg rules "$RULES" \
  '{schema:"skarbiec.item.v2",kind:"login",fields:{username:"me",password:$password},context:{password_rules:$rules}}' >"$ROOT/stdin"
WANT=ok run set "$LOGIN" --type login
: >"$ROOT/stdin"

WANT=ok run health
case "$out" in *"$PASSWORD"*) fail "health printed the password" ;; esac
printf '%s' "$out" >"$ROOT/health.json"
jq -e '.ok == false' "$ROOT/health.json" >/dev/null || fail "health was ok with a login breaking its site's rules"
jq -e --arg id "$LOGIN" --arg cap "maxlength: $CAP" \
  '.breaks_site_rules | any(.item == $id and (.broken | index($cap) != null) and (.broken | index("required: upper") != null) and (.broken | any(startswith("a character outside"))))' \
  "$ROOT/health.json" >/dev/null || fail "breaks_site_rules does not name $LOGIN with maxlength, required upper and the character outside"
echo "ok: health names the login breaking its site's rules with every rule broken" >>"$REPORT"

WANT=ok run generate --rules-of "$LOGIN" --length "$CAP" --into "$LOGIN" --field password
WANT=ok run health
jq -e --arg id "$LOGIN" '.breaks_site_rules | all(.item != $id)' <<<"$out" >/dev/null \
  || fail "the login is still listed after a password generated from its rules"
echo "ok: a password generated from the rules is no longer listed" >>"$REPORT"

ODD="site-rules-odd-$RUN"
jq -n --arg password "$PASSWORD" \
  '{schema:"skarbiec.item.v2",kind:"login",fields:{username:"me",password:$password},context:{password_rules:"required: emoji"}}' >"$ROOT/stdin"
WANT=ok run set "$ODD" --type login
: >"$ROOT/stdin"
WANT=ok run health
jq -e --arg id "$ODD" '.unreadable | any(.item == $id and (.error | contains("password rule class emoji")))' <<<"$out" >/dev/null \
  || fail "rules the language does not name were not reported in unreadable"
echo "ok: rules not in the language are reported, not counted as followed" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
