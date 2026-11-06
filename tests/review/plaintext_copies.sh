#!/usr/bin/env bash
# Real test of `skarbiec scan`, through the built binary on a vault of its
# own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written, and the files scanned are made here.
#
# A login's password sits on the first line of one file and a token on the
# third line of a .env in a subdirectory; a third file holds neither, a
# symbolic link points at a file outside the scanned directory holding the
# password, and one file cannot be read. scan names both copies with their
# file, line, item and field, does not follow the link, names the unreadable
# file, and never prints a value. With --min-length above the token's length
# the token is listed as not compared and its copy is not reported. No
# --fields and a --min-length that is not a number are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/review/plaintext_copies.sh
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
trap 'chmod u+r "$ROOT/tree/locked.txt"; gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

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
    *) fail "expected a refusal naming '$*', got: $said" ;;
  esac
}

: >"$ROOT/stdin"
WANT=ok run init "scan-owner-$RUN"

PASSWORD="secret-$RUN-password-long-enough"
TOKEN="tok-$$"
LOGIN="scan-login-$RUN"
TOKEN_ITEM="scan-token-$RUN"
jq -n --arg password "$PASSWORD" '{schema:"skarbiec.item.v2",kind:"login",fields:{username:"me",password:$password},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$LOGIN" --type login
jq -n --arg token "$TOKEN" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$TOKEN_ITEM" --type token
: >"$ROOT/stdin"

TREE="$ROOT/tree"
mkdir -p "$TREE/app"
printf '%s is the password\n' "$PASSWORD" >"$TREE/notes.txt"
printf '# settings\nDEBUG=true\nAPI_TOKEN=%s\n' "$TOKEN" >"$TREE/app/.env"
printf 'nothing here\n' >"$TREE/clean.txt"
printf '%s\n' "$PASSWORD" >"$ROOT/outside.txt"
ln -s "$ROOT/outside.txt" "$TREE/link.txt"
printf '%s\n' "$PASSWORD" >"$TREE/locked.txt"
chmod a-r "$TREE/locked.txt"

WANT=ok run scan "$TREE" --fields password,token
# A value must appear on neither stream.
case "$out$said" in *"$PASSWORD"*|*"$TOKEN"*) fail "scan printed a value" ;; esac
printf '%s' "$out" >"$ROOT/scan.json"
jq -e '.ok == false' "$ROOT/scan.json" >/dev/null || fail "scan was ok with copies on disk"
jq -e --arg file "$TREE/notes.txt" --arg id "$LOGIN" '.found | any(.file == $file and .line == 1 and .item == $id and .field == "password")' "$ROOT/scan.json" >/dev/null \
  || fail "the password's copy in notes.txt line 1 was not named"
jq -e --arg file "$TREE/app/.env" --arg id "$TOKEN_ITEM" '.found | any(.file == $file and .line == 3 and .item == $id and .field == "token")' "$ROOT/scan.json" >/dev/null \
  || fail "the token's copy in app/.env line 3 was not named"
jq -e --arg file "$TREE/link.txt" '.found | all(.file != $file)' "$ROOT/scan.json" >/dev/null || fail "scan followed a symbolic link"
jq -e --arg file "$TREE/clean.txt" '.found | all(.file != $file)' "$ROOT/scan.json" >/dev/null || fail "a file holding no value was reported"
echo "ok: scan names each copy by file, line, item and field and does not follow links" >>"$REPORT"
if [ "$(id -u)" != "0" ]; then
  jq -e --arg file "$TREE/locked.txt" '.unreadable_files | any(.path == $file)' "$ROOT/scan.json" >/dev/null \
    || fail "the unreadable file was not named"
  echo "ok: an unreadable file is named with its error" >>"$REPORT"
fi

LONGER="$(printf '%s-' "$TOKEN" | wc -c | tr -d ' ')"
WANT=ok run scan "$TREE/app" --fields token --min-length "$LONGER"
jq -e --arg id "$TOKEN_ITEM" '(.below_min_length | any(.item == $id and .field == "token")) and (.found | length == 0)' <<<"$out" >/dev/null \
  || fail "--min-length did not leave the shorter token uncompared and named"
echo "ok: --min-length leaves shorter values uncompared and names them" >>"$REPORT"

WANT=refused run scan "$TREE"
names "usage: scan"
WANT=refused run scan "$TREE" --fields token --min-length long
names "--min-length long is not a whole number"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
