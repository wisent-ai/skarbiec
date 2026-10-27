#!/usr/bin/env bash
# Real test of naming the logins whose site was breached, `skarbiec
# breach sites`, through the built binary against Have I Been Pwned's real
# list of breaches, on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# The site is taken from the list itself: the first breach that names a
# domain. A login on that site, made now, holds a password set after the
# breach, so it is listed under changed_since with the breach's name and day
# and not under exposed; a login on a reserved .invalid host is listed
# nowhere. The answer carries the list's address and attribution, and the
# password never appears in it. An argument is refused with the usage.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/review/site_breaches.sh
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
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"%s-user","password":"%s"},"context":{"domains":["%s"]}}' \
    "$1" "breach-secret-$RUN" "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}

LIST="$ROOT/breaches.json"
curl -sS --fail -A skarbiec-tests https://haveibeenpwned.com/api/v3/breaches -o "$LIST"
SITE="$(jq -r '[.[] | select(.Domain != "")][0].Domain' "$LIST")"
NAME="$(jq -r --arg site "$SITE" '[.[] | select(.Domain == $site)][0].Name' "$LIST")"
echo "site from the list: $SITE ($NAME)" >>"$REPORT"

: >"$ROOT/stdin"
WANT=ok run init "breach-owner-$RUN"
BREACHED="breach-site-$RUN"
ELSEWHERE="breach-elsewhere-$RUN"
login "$BREACHED" "$SITE"
login "$ELSEWHERE" "breach-$RUN.invalid"

WANT=ok run breach sites
printf '%s' "$out" | jq -e --arg item "$BREACHED" --arg name "$NAME" \
  '[.changed_since[] | select(.item == $item) | .breach] | index($name) != null' >/dev/null \
  || fail "the login on $SITE was not listed as changed since the $NAME breach"
printf '%s' "$out" | jq -e --arg item "$BREACHED" --arg other "$ELSEWHERE" \
  '([.exposed[].item] | index($item) == null) and ([.exposed[].item, .changed_since[].item] | index($other) == null)' >/dev/null \
  || fail "a login made after the breach was exposed, or the .invalid login was listed"
printf '%s' "$out" | jq -e '(.source | startswith("https://haveibeenpwned.com/")) and (.attribution | contains("CC BY"))' >/dev/null \
  || fail "the answer does not name the list and its attribution"
case "$out" in *"breach-secret-$RUN"*) fail "breach sites printed a password" ;; esac
echo "ok: a login made after its site's breach is listed as changed since, with the list's attribution" >>"$REPORT"

WANT=refused run breach sites "$SITE"
case "$out" in *"usage: breach sites"*) echo "ok: an argument is refused with the usage" >>"$REPORT" ;; *) fail "an argument was not refused with the usage: $out" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
