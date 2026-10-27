#!/usr/bin/env bash
# Real test of `skarbiec tool` with the npm adapter, through the built binary on a vault
# and an npm user configuration of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, GNUPGHOME, HOME and NPM_CONFIG_USERCONFIG point into
# this checkout's target directory, so the operator's vault, keyring and
# ~/.npmrc are never read or written.
#
# An .npmrc holding two registry tokens in plain text: status names both as
# plain text, never a token; import moves one into a token item, binds it in
# a bindings file and writes ${NAME} in its place, keeping the other line;
# exec --env-from gives a program that variable holding the token; doctor's
# helpers check names the token left in plain text beside it. A registry
# .npmrc does not name, one already read from a variable and a variable the
# bindings file binds elsewhere are refused with .npmrc unchanged.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/packages/npm_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/packages/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
export NPM_CONFIG_USERCONFIG="$ROOT/home/npmrc"
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
# The variable import binds a registry's token to, worked out as the CLI
# page describes it: NPM_TOKEN_ and the registry's letters and digits in
# upper case, every other run of characters one underscore.
variable_for() {
  printf 'NPM_TOKEN_%s' "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr -c '[:upper:][:digit:]' '_' | tr -s '_' | sed 's/^_*//; s/_*$//')"
}

: >"$ROOT/stdin"
WANT=ok run init "npm-owner-$RUN"
PUBLISH="npm-publish-$RUN"
OTHER="npm-other-$RUN"
REGISTRY="//npm-$RUN.example.invalid/"
LEFT="//left-$RUN.example.invalid/"
printf 'save-exact=true\n%s:_authToken=%s\n%s:_authToken=%s\n' "$REGISTRY" "$PUBLISH" "$LEFT" "$OTHER" >"$NPM_CONFIG_USERCONFIG"
BINDINGS="$ROOT/bindings"

WANT=ok run tool status npm
printf '%s' "$out" | jq -e --arg r "$REGISTRY" --arg l "$LEFT" \
  '[.entries[] | select(.kept == "plain text") | .entry] | (index($r) != null) and (index($l) != null)' >/dev/null \
  || fail "status did not name both registries as plain text: $out"
case "$out" in *"$PUBLISH"*|*"$OTHER"*) fail "status printed a token" ;; esac
echo "ok: status names both plain-text registries, never a token" >>"$REPORT"

ITEM="npm-$RUN"
WANT=ok run tool import npm "$ITEM" --select "$REGISTRY" --bindings "$BINDINGS"
NAME="$(printf '%s' "$out" | jq -r '.variables[]')"
[ "$NAME" = "$(variable_for "$REGISTRY")" ] || fail "import bound $NAME, not the variable its page describes"
case "$out" in *"$PUBLISH"*) fail "import printed the token" ;; esac
grep -qxF "$REGISTRY:_authToken=\${$NAME}" "$NPM_CONFIG_USERCONFIG" || fail ".npmrc does not read $REGISTRY's token from \${$NAME}: $(cat "$NPM_CONFIG_USERCONFIG")"
grep -qxF "$LEFT:_authToken=$OTHER" "$NPM_CONFIG_USERCONFIG" || fail "import changed the other registry's line"
grep -qxF "save-exact=true" "$NPM_CONFIG_USERCONFIG" || fail "import dropped an unrelated line"
if grep -q "$PUBLISH" "$NPM_CONFIG_USERCONFIG"; then fail ".npmrc still holds the moved token"; fi
grep -qxF "$NAME=$ITEM:token" "$BINDINGS" || fail "the bindings file does not bind $NAME: $(cat "$BINDINGS")"
WANT=ok run get "$ITEM" --field token
[ "$out" = "$PUBLISH" ] || fail "the item does not hold the moved token"
echo "ok: import moves the token into the item, binds it and leaves \${$NAME} in .npmrc" >>"$REPORT"

# The program exec starts sees the variable npm expands holding the token.
seen="$("$BIN" exec --env-from "$BINDINGS" -- sh -c "printf '%s' \"\$$NAME\"" </dev/null)"
[ "$seen" = "$PUBLISH" ] || fail "exec --env-from did not give the program $NAME holding the token"
echo "ok: exec --env-from gives npm the token through $NAME" >>"$REPORT"

WANT=ok run doctor
printf '%s' "$out" | jq -e --arg l "$LEFT" '.checks[] | select(.check == "helpers") | (.status == "fail") and (.detail | contains($l))' >/dev/null \
  || fail "doctor's helpers check did not name the token left in plain text: $out"
echo "ok: doctor names the registry still kept in plain text" >>"$REPORT"

cp "$NPM_CONFIG_USERCONFIG" "$ROOT/npmrc-before-refusals"
WANT=refused run tool import npm "again-$RUN" --select "$REGISTRY" --bindings "$BINDINGS"
case "$out" in *"already reads"*) ;; *) fail "a registry read from a variable was not refused: $out" ;; esac
WANT=refused run tool import npm "none-$RUN" --select "//nowhere-$RUN.example.invalid/" --bindings "$BINDINGS"
case "$out" in *"keeps no _authToken"*) ;; *) fail "a registry .npmrc does not name was not refused: $out" ;; esac
printf '%s=someone-else:token\n' "$(variable_for "$LEFT")" >>"$BINDINGS"
WANT=refused run tool import npm "clash-$RUN" --select "$LEFT" --bindings "$BINDINGS"
case "$out" in *"already binds"*) ;; *) fail "a variable bound elsewhere was not refused: $out" ;; esac
cmp -s "$NPM_CONFIG_USERCONFIG" "$ROOT/npmrc-before-refusals" || fail "a refused import changed .npmrc"
echo "ok: a variable-read registry, an unknown registry and a clashing binding are refused, .npmrc unchanged" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
