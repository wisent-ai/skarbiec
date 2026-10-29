#!/usr/bin/env bash
# Real test of `skarbiec rotate --with gitlab`, through the built binary on a vault
# of its own and a real GitLab: SKARBIEC_TEST_GITLAB_URL names the instance
# and SKARBIEC_TEST_GITLAB_TOKEN_FILE an owner-only file holding a token kept
# for this test, with the api or self_rotate scope. Rotation revokes the
# token the file holds, so the test writes the new one back into the file
# before it ends, and the next run starts from it. SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# After rotate --with gitlab the item holds a token GitLab answers for and the old
# one is refused; no token is printed. An address that is not https://, and
# an item that is not a token, are refused before GitLab is asked.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_GITLAB_URL=https://gitlab.example.com SKARBIEC_TEST_GITLAB_TOKEN_FILE=<file> tests/rotation/gitlab_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
URL=${SKARBIEC_TEST_GITLAB_URL:?set SKARBIEC_TEST_GITLAB_URL to the GitLab instance this test rotates a token on}
TOKEN_FILE=${SKARBIEC_TEST_GITLAB_TOKEN_FILE:?set SKARBIEC_TEST_GITLAB_TOKEN_FILE to an owner-only file holding a token kept for this test}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/rotation/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "gitlab: $URL" >>"$REPORT"
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
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said; output: $out" ;;
  esac
}
# Whether GitLab answers for the token on standard input.
answers() {
  printf 'PRIVATE-TOKEN: %s\n' "$*" | curl -sS --fail -H @- "$URL/api/v4/personal_access_tokens/self" &>>"$REPORT"
}

: >"$ROOT/stdin"
WANT=ok run init "gitlab-owner-$RUN"
ITEM="gitlab-$RUN"
OLD="$(tr -d '\n' <"$TOKEN_FILE")"
jq -n --arg token "$OLD" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type token
: >"$ROOT/stdin"

WANT=refused run rotate "$ITEM" --with gitlab --url "http://gitlab.example.com"
names "is not an https:// GitLab address"
jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a token"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run rotate "note-$RUN" --with gitlab --url "$URL"
names "rotate --with gitlab replaces the token a token item keeps"

WANT=ok run rotate "$ITEM" --with gitlab --url "$URL"
# Neither stream may carry the old token.
case "$out$said" in *"$OLD"*) fail "rotate printed the old token" ;; esac
WANT=ok run get "$ITEM" --field token
NEW="$out"
# The next run starts from the token GitLab now answers for.
printf '%s\n' "$NEW" >"$TOKEN_FILE"
[ "$NEW" != "$OLD" ] || fail "the item still holds the old token"
answers "$NEW" || fail "GitLab does not answer for the new token"
if answers "$OLD"; then fail "GitLab still answers for the old token"; fi
echo "ok: the item holds GitLab's new token and the old one is revoked" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
