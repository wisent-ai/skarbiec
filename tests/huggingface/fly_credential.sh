#!/usr/bin/env bash
# Real test of `skarbiec tool` with the fly adapter, through the built binary on a vault
# and a home of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE, GNUPGHOME,
# HOME and FLY_CONFIG_DIR point into this checkout's target directory, so the
# operator's vault, keyring and flyctl sign-in are never read or written.
#
# A config.yml holding an access token among other settings: status names it
# as plain text, never the token; import moves it into a token item, binds
# FLY_ACCESS_TOKEN, remembers the bindings file and removes only the
# access_token line; exec --env-from gives a program FLY_ACCESS_TOKEN; doctor's
# developer_tokens check no longer names flyctl. A file keeping no token and a
# variable the bindings file binds elsewhere are refused with the file
# unchanged.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/huggingface/fly_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/huggingface/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$ROOT/fly" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
export FLY_CONFIG_DIR="$ROOT/fly"
CONFIG="$FLY_CONFIG_DIR/config.yml"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

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
tokens_check() {
  if doctor=$("$BIN" doctor </dev/null); then echo "doctor: ok" >>"$REPORT"; else echo "doctor: a check failed" >>"$REPORT"; fi
  printf '%s' "$doctor" | jq -r '.checks[] | select(.check == "developer_tokens") | "\(.status) \(.detail)"'
}

: >"$ROOT/stdin"
WANT=ok run init "fly-owner-$RUN"
TOKEN="fo1_token_$RUN"
cat >"$CONFIG" <<EOF
access_token: $TOKEN
auto_update: true
send_metrics: false
EOF
BINDINGS="$ROOT/bindings"

WANT=ok run tool status fly
printf '%s' "$out" | jq -e '.entries | any(.entry == "access_token" and .kept == "plain text")' >/dev/null || fail "status did not name the token as plain text: $out"
# The token must appear on neither stream.
case "$out$said" in *"$TOKEN"*) fail "status printed the token" ;; esac
case "$(tokens_check)" in
  fail*"tool import fly"*) ;;
  *) fail "doctor's developer_tokens check does not name flyctl's token: $(tokens_check)" ;;
esac
echo "ok: status and doctor name the plain-text token, never the token" >>"$REPORT"

ITEM="fly-$RUN"
WANT=ok run tool import fly "$ITEM" --bindings "$BINDINGS"
case "$out$said" in *"$TOKEN"*) fail "import printed the token" ;; esac
if grep -q "$TOKEN" "$CONFIG"; then fail "config.yml still holds the token"; fi
grep -qxF "auto_update: true" "$CONFIG" || fail "import dropped another setting"
grep -qxF "FLY_ACCESS_TOKEN=$ITEM:token" "$BINDINGS" || fail "the bindings file does not bind FLY_ACCESS_TOKEN"
WANT=ok run get "$ITEM" --field token
[ "$out" = "$TOKEN" ] || fail "the item does not hold the moved token"
WANT=ok run bindings list
printf '%s' "$out" | jq -e --arg file "$BINDINGS" '[.files[].file] | index($file) != null' >/dev/null || fail "import did not remember the bindings file: $out"
seen="$("$BIN" exec --env-from "$BINDINGS" -- sh -c 'printf "%s" "$FLY_ACCESS_TOKEN"' </dev/null)"
[ "$seen" = "$TOKEN" ] || fail "exec --env-from did not give the program FLY_ACCESS_TOKEN"
case "$(tokens_check)" in
  *"tool import fly"*) fail "doctor still names flyctl's token: $(tokens_check)" ;;
  *) echo "ok: import moves the token, remembers the bindings file, and doctor no longer names it" >>"$REPORT" ;;
esac

cp "$CONFIG" "$ROOT/config-before-refusals"
WANT=refused run tool import fly "again-$RUN" --bindings "$BINDINGS"
case "$said" in *"keeps no access_token"*) ;; *) fail "a file keeping no token was not refused: $said" ;; esac
printf 'access_token: other_%s\n' "$RUN" >>"$CONFIG"
cp "$CONFIG" "$ROOT/config-before-refusals"
WANT=refused run tool import fly "clash-$RUN" --bindings "$BINDINGS"
case "$said" in *"already binds FLY_ACCESS_TOKEN"*) ;; *) fail "a variable bound elsewhere was not refused: $said" ;; esac
cmp -s "$CONFIG" "$ROOT/config-before-refusals" || fail "a refused import changed config.yml"
echo "ok: no token and a clashing binding are refused, config.yml unchanged" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
