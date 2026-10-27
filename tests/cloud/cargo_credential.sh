#!/usr/bin/env bash
# Real test of `skarbiec helper ... cargo`, through the built binary on a
# vault of its own and the provider exactly as Cargo runs it: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, GNUPGHOME and CARGO_HOME all point into this checkout's
# target directory, so the operator's vault, keyring and ~/.cargo are never
# read or written.
#
# setup adds the provider line under [registry], keeping the other lines,
# and names the registries credentials.toml still holds; helper answer cargo, run with the
# index in CARGO_REGISTRY_INDEX_URL as Cargo's token-from-stdout provider
# runs it, prints the token of the login offered on the index host — the one
# changed in the vault included. import moves crates-io's token out of
# credentials.toml into a new login and leaves the other registry's line.
# unset removes the provider line. A provider list someone else set, and an
# import of a registry the file holds no token for, are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/cloud/cargo_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/cloud/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/cargo" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export CARGO_HOME="$ROOT/cargo"
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
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
login() {
  jq -n --arg host "$1" --arg token "$2" '{schema:"skarbiec.item.v2",kind:"login",fields:{username:"cargo",password:$token},context:{domains:[$host]}}' >"$ROOT/stdin"
  WANT=ok run set "$3" --type login
  : >"$ROOT/stdin"
}
# The provider as Cargo runs it: the index in the environment, the token on stdout.
provider() {
  CARGO_REGISTRY_INDEX_URL="$1" "$BIN" helper answer cargo 2>>"$REPORT"
}

: >"$ROOT/stdin"
WANT=ok run init "cargo-owner-$RUN"
INDEX="index-$RUN.example.com"
login "$INDEX" "first-$RUN" "registry-$RUN"

printf '[net]\ngit-fetch-with-cli = true\n' >"$CARGO_HOME/config.toml"
printf '[registry]\ntoken = "crates-%s"\n\n[registries.internal]\ntoken = "internal-%s"\n' "$RUN" "$RUN" >"$CARGO_HOME/credentials.toml"
WANT=ok run helper setup cargo
[ "$(printf '%s' "$out" | jq -r '.plain_tokens.registries | join(",")')" = "crates-io,internal" ] || fail "setup did not name the registries credentials.toml holds: $out"
grep -q '^git-fetch-with-cli' "$CARGO_HOME/config.toml" || fail "setup did not keep config.toml's other lines"
grep -q "cargo:token-from-stdout $BIN helper answer cargo\"" "$CARGO_HOME/config.toml" || fail "setup wrote no provider line"
WANT=ok run helper setup cargo
[ "$(printf '%s' "$out" | jq -r .written)" = "false" ] || fail "setup run again wrote again"
echo "ok: setup writes one provider line and keeps the rest" >>"$REPORT"

[ "$(provider "sparse+https://$INDEX/")" = "first-$RUN" ] || fail "get did not print the login's token"
login "$INDEX" "second-$RUN" "registry-$RUN"
[ "$(provider "sparse+https://$INDEX/")" = "second-$RUN" ] || fail "get did not follow the token changed in the vault"
if provider "sparse+https://nothing-$RUN.example.com/"; then fail "an index no login is offered on was answered"; fi
grep -q '"cargo-credential"' "$SKARBIEC_AUDIT_FILE" || fail "the read was not journalled"
echo "ok: get prints the vault's current token and fails for an index with none" >>"$REPORT"

WANT=refused run helper import cargo "absent-$RUN" --registry nowhere --host "$INDEX"
names "keeps no token for registry nowhere"
WANT=ok run helper import cargo "crates-$RUN" --registry crates-io --host "crates-$RUN.example.com"
if grep -q "crates-$RUN" "$CARGO_HOME/credentials.toml"; then fail "import left crates-io's token in credentials.toml"; fi
grep -q "internal-$RUN" "$CARGO_HOME/credentials.toml" || fail "import removed another registry's token"
[ "$(provider "sparse+https://crates-$RUN.example.com/")" = "crates-$RUN" ] || fail "the imported token is not answered from the vault"
echo "ok: import moves one registry's token into the vault" >>"$REPORT"

WANT=ok run helper unset cargo
if grep -q "helper answer cargo" "$CARGO_HOME/config.toml"; then fail "unset left the provider line"; fi
WANT=refused run helper unset cargo
names "names no skarbiec credential provider"
printf 'global-credential-providers = ["cargo:token"]\n' >>"$CARGO_HOME/config.toml"
WANT=refused run helper setup cargo
names "already sets"
echo "ok: unset removes the line; another provider list is refused" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
