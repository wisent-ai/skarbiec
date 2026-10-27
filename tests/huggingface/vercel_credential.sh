#!/usr/bin/env bash
# Real test of `skarbiec tool` with the vercel adapter, through the built binary on a
# vault and a home of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE,
# GNUPGHOME, HOME and XDG_DATA_HOME point into this checkout's target
# directory, so the operator's vault, keyring and Vercel sign-in are never
# read or written.
#
# An auth.json holding a token beside another key, in the older ~/.vercel
# the CLI still reads: status names it as plain text, never the token; import
# moves it into a token item, binds VERCEL_TOKEN, remembers the bindings file
# and writes auth.json back keeping the other key; exec --env-from gives a
# program VERCEL_TOKEN. A file keeping no token and an auth.json that is not
# a JSON object are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/huggingface/vercel_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/huggingface/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home/.vercel" "$ROOT/data" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
export XDG_DATA_HOME="$ROOT/data"
AUTH="$HOME/.vercel/auth.json"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}

: >"$ROOT/stdin"
WANT=ok run init "vercel-owner-$RUN"
TOKEN="vercel_token_$RUN"
jq -n --arg token "$TOKEN" '{"// Note":"This is your Vercel credentials file.",token:$token}' >"$AUTH"
BINDINGS="$ROOT/bindings"

WANT=ok run tool status vercel
[ "$(printf '%s' "$out" | jq -r .file)" = "$AUTH" ] || fail "status does not name the auth.json the CLI reads: $out"
printf '%s' "$out" | jq -e '.entries | any(.kept == "plain text")' >/dev/null || fail "status did not name the token as plain text: $out"
case "$out" in *"$TOKEN"*) fail "status printed the token" ;; esac
echo "ok: status names the file and its plain-text token, never the token" >>"$REPORT"

ITEM="vercel-cli-$RUN"
WANT=ok run tool import vercel "$ITEM" --bindings "$BINDINGS"
case "$out" in *"$TOKEN"*) fail "import printed the token" ;; esac
jq -e 'has("token") | not' "$AUTH" >/dev/null || fail "auth.json still holds the token"
jq -e 'has("// Note")' "$AUTH" >/dev/null || fail "import dropped the other key"
grep -qxF "VERCEL_TOKEN=$ITEM:token" "$BINDINGS" || fail "the bindings file does not bind VERCEL_TOKEN"
WANT=ok run get "$ITEM" --field token
[ "$out" = "$TOKEN" ] || fail "the item does not hold the moved token"
WANT=ok run bindings list
printf '%s' "$out" | jq -e --arg file "$BINDINGS" '[.files[].file] | index($file) != null' >/dev/null || fail "import did not remember the bindings file: $out"
seen="$("$BIN" exec --env-from "$BINDINGS" -- sh -c 'printf "%s" "$VERCEL_TOKEN"' </dev/null)"
[ "$seen" = "$TOKEN" ] || fail "exec --env-from did not give the program VERCEL_TOKEN"
echo "ok: import moves the token, keeps the other key, remembers the bindings file and exec gives it" >>"$REPORT"

WANT=refused run tool import vercel "again-$RUN" --bindings "$BINDINGS"
case "$out" in *"keeps no token"*) ;; *) fail "a file keeping no token was not refused: $out" ;; esac
printf 'not json' >"$AUTH"
WANT=refused run tool status vercel
case "$out" in *"is not the JSON object the Vercel CLI writes"*) ;; *) fail "an auth.json that is not JSON was not refused naming it: $out" ;; esac
echo "ok: no token and an unreadable auth.json are refused" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
