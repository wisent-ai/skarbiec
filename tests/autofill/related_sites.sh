#!/usr/bin/env bash
# Real test of adding the sites that share one sign-in, `skarbiec sites <id>
# --add-related`, through the built binary against Password Manager
# Resources' real shared-credentials list, on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# The group is taken from the list itself: the first "shared" group. A login
# on its first site gains every other site of the group, named under
# related_added and stored as its domains, keeping the first. A login on a
# reserved .invalid host is refused naming that the list holds no related
# site, and --add-related with --add is refused naming the choice.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/autofill/related_sites.sh
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: output: $out stderr: $said" ;;
  esac
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"me","password":"related-secret-%s"},"context":{"domains":["%s"]}}' \
    "$RUN" "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}

LIST="$ROOT/shared-credentials.json"
curl -sS --fail https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/shared-credentials.json -o "$LIST"
GROUP="$(jq -c '[.[] | select(has("shared"))][0].shared' "$LIST")"
FIRST="$(printf '%s' "$GROUP" | jq -r 'first')"
OTHERS="$(printf '%s' "$GROUP" | jq -c --arg first "$FIRST" '. - [$first]')"
echo "group from the list: $GROUP" >>"$REPORT"

: >"$ROOT/stdin"
WANT=ok run init "related-owner-$RUN"
SHARED="related-login-$RUN"
ALONE="related-alone-$RUN"
login "$SHARED" "$FIRST"
login "$ALONE" "related-$RUN.invalid"

# The first site may sit in other groups too, so the group is checked as
# contained in what was added and stored, and the first site is not added
# again: a site the login already names stays once.
WANT=ok run sites "$SHARED" --add-related
printf '%s' "$out" | jq -e --argjson want "$OTHERS" --arg first "$FIRST" \
  '($want - .related_added) == [] and (.related_added | index($first)) == null' >/dev/null \
  || fail "--add-related did not name every other site of the group $GROUP, or named $FIRST again"
WANT=ok run sites "$SHARED"
printf '%s' "$out" | jq -e --argjson want "$GROUP" --arg first "$FIRST" \
  '($want - .domains) == [] and ([.domains[] | select(. == $first)] | length) == ([$first] | length)' >/dev/null \
  || fail "the login's sites do not hold the whole group $GROUP once"
case "$out" in *"related-secret-$RUN"*) fail "sites printed the password" ;; esac
echo "ok: --add-related stores every site of the shared group, keeping the first" >>"$REPORT"

WANT=refused run sites "$ALONE" --add-related
names "Password Manager Resources lists no site sharing a sign-in with related-$RUN.invalid"
WANT=refused run sites "$SHARED" --add-related --add "related-$RUN.invalid"
names "name one of --set, --add, --remove, --add-related or --change-pages"

# --change-pages against the real change-password list: the first site it
# lists gets that page; a reserved .invalid host gets its well-known address.
PAGES="$ROOT/change-password-URLs.json"
curl -sS --fail https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/change-password-URLs.json -o "$PAGES"
LISTED="$(jq -r 'keys[0]' "$PAGES")"
PAGE="$(jq -r --arg site "$LISTED" '.[$site]' "$PAGES")"
login "pages-$RUN" "$LISTED"
WANT=ok run sites "pages-$RUN" --change-pages
printf '%s' "$out" | jq -e --arg page "$PAGE" '.pages[0].change_password == $page' >/dev/null \
  || fail "--change-pages did not name the page the list holds for $LISTED: $out"
WANT=ok run sites "$ALONE" --change-pages
printf '%s' "$out" | jq -e --arg page "https://related-$RUN.invalid/.well-known/change-password" \
  '.pages[0].change_password == $page and .pages[0].source == "well-known"' >/dev/null \
  || fail "--change-pages did not fall to the well-known address for an unlisted site: $out"
echo "ok: --change-pages names the listed page, else the well-known address" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
