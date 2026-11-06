#!/usr/bin/env bash
# Real test of two of `skarbiec review`'s sections, passwords_set_before and
# logins_offered_nowhere, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# One login names a site and one names none. Held to a moment far ahead,
# passwords_set_before lists both and logins_offered_nowhere lists only the one
# without a site; held to a moment long past, passwords_set_before lists none.
# Neither section may fail, and the answer holds no password.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/review/review_sections.sh
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"%s-user","password":"%s"},"context":%s}' \
    "$1" "$2" "$3" >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}
section_failed() {
  printf '%s' "$out" | jq -e --arg name "$1" '.failed_sections | index($name) != null' >/dev/null
}

: >"$ROOT/stdin"
WANT=ok run init "review-owner-$RUN"
SITED="review-sited-$RUN"
NOWHERE="review-nowhere-$RUN"
login "$SITED" "review-secret-one-$RUN" '{"domains":["review.test"]}'
login "$NOWHERE" "review-secret-two-$RUN" '{}'

WANT=ok run review --before "2999-01-01T00:00:00Z"
printf '%s' "$out" >"$ROOT/review-ahead.json"
for name in passwords_set_before logins_offered_nowhere; do
  if section_failed "$name"; then fail "the $name section failed: $(printf '%s' "$out" | jq -c --arg name "$name" '.sections[$name]')"; fi
done
printf '%s' "$out" | jq -e --arg a "$SITED" --arg b "$NOWHERE" \
  '.sections.passwords_set_before.logins | map(.id) | (index($a) != null) and (index($b) != null)' >/dev/null \
  || fail "passwords_set_before held to a moment ahead does not list both logins"
printf '%s' "$out" | jq -e --arg a "$SITED" --arg b "$NOWHERE" \
  '.sections.logins_offered_nowhere.logins | (index($b) != null) and (index($a) == null)' >/dev/null \
  || fail "logins_offered_nowhere does not list exactly the login without a site"
echo "ok: held to a moment ahead, both logins are dated and only the siteless one is offered nowhere" >>"$REPORT"

WANT=ok run review --before "2000-01-01T00:00:00Z"
printf '%s' "$out" | jq -e '.sections.passwords_set_before.logins | length == 0' >/dev/null \
  || fail "passwords_set_before held to a moment long past lists a login"
echo "ok: held to a moment long past, no password was set before it" >>"$REPORT"

[ "$(printf '%s' "$out" | jq -r .sections.secret_health.breach_checked)" = false ] \
  || fail "a review without --breached asked Have I Been Pwned"
printf '%s' "$out" | jq -e '.sections | has("breached_sites") | not' >/dev/null \
  || fail "a review without --breached read the list of breached sites"
# The real Have I Been Pwned range API answers this run; secret_health holds
# its refusal when it cannot be reached, and the other sections still run.
WANT=ok run review --before "2000-01-01T00:00:00Z" --breached
if section_failed secret_health; then
  fail "secret_health failed with --breached: $(printf '%s' "$out" | jq -c .sections.secret_health)"
fi
[ "$(printf '%s' "$out" | jq -r .sections.secret_health.breach_checked)" = true ] \
  || fail "review --breached did not ask Have I Been Pwned"
if section_failed breached_sites; then
  fail "breached_sites failed with --breached: $(printf '%s' "$out" | jq -c .sections.breached_sites)"
fi
printf '%s' "$out" | jq -e '.sections.breached_sites.exposed | type == "array"' >/dev/null \
  || fail "review --breached did not hold the breached sites"
echo "ok: review asks Have I Been Pwned, and reads its breached sites, only with --breached" >>"$REPORT"

if grep -q "review-secret-" "$ROOT/review-ahead.json"; then fail "review printed a password"; fi

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
