#!/usr/bin/env bash
# Real test of `skarbiec helper ... terraform`, through the built binary on a
# vault of its own and the helper program exactly as Terraform runs it:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE, GNUPGHOME and HOME all point into
# this checkout's target directory, so the operator's vault, keyring,
# ~/.terraformrc and ~/.terraform.d are never read or written.
#
# setup links terraform-credentials-skarbiec in the plugin directory and
# writes the credentials_helper block, keeping what the configuration held,
# and names the hosts credentials.tfrc.json still holds; that program run as
# `get <host>` answers the token of the login offered on the host — the one
# changed in the vault included — and {} for a host with none. import moves a
# host's token out of credentials.tfrc.json into a new login. unset removes
# the block and the link. Another helper, store, and an import of a host the
# file holds no token for are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/cloud/terraform_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/cloud/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home/.terraform.d" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
unset TF_CLI_CONFIG_FILE TF_CLI_CONFIG_DIR
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
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: output: $out stderr: $said" ;;
  esac
}
login() {
  jq -n --arg host "$1" --arg token "$2" '{schema:"skarbiec.item.v2",kind:"login",fields:{username:$host,password:$token},context:{domains:[$host]}}' >"$ROOT/stdin"
  WANT=ok run set "$3" --type login
  : >"$ROOT/stdin"
}
PLUGIN="$HOME/.terraform.d/plugins/terraform-credentials-skarbiec"
# The helper as Terraform runs it: by its program name, with the action and host.
helper() {
  "$PLUGIN" "$@" 2>>"$REPORT"
}

: >"$ROOT/stdin"
WANT=ok run init "terraform-owner-$RUN"
HOST="app.example.com"
FIRST="token-one-$RUN"
SECOND="token-two-$RUN"
login "$HOST" "$FIRST" "terraform-$RUN"

printf 'plugin_cache_dir = "%s/cache"\n' "$HOME" >"$HOME/.terraformrc"
jq -n --arg token "plain-$RUN" '{credentials:{"registry.example.com":{token:$token}}}' >"$HOME/.terraform.d/credentials.tfrc.json"
WANT=ok run helper setup terraform
[ "$(printf '%s' "$out" | jq -r '.no_longer_read.hosts[0]')" = "registry.example.com" ] || fail "setup did not name the host credentials.tfrc.json holds: $out"
grep -q '^plugin_cache_dir' "$HOME/.terraformrc" || fail "setup did not keep the configuration's other settings"
grep -q '^credentials_helper "skarbiec" {$' "$HOME/.terraformrc" || fail "setup wrote no credentials_helper block"
[ "$(readlink "$PLUGIN")" = "$BIN" ] || fail "the plugin does not link to the binary under test"
WANT=ok run helper setup terraform
[ "$(grep -c '^credentials_helper' "$HOME/.terraformrc")" = "$(printf 'x' | wc -c | tr -d ' ')" ] || fail "setup run again wrote a second block"
WANT=ok run helper status terraform
printf '%s' "$out" | jq -e '.tools[0] | .tool == "terraform" and .state.configured and .state.program_present' &>/dev/null || fail "helper status does not say Terraform asks this vault: $out"
echo "ok: setup links the plugin, writes one block and keeps the rest, and status says so" >>"$REPORT"

[ "$(helper get "$HOST" | jq -r .token)" = "$FIRST" ] || fail "get did not answer the login's token"
login "$HOST" "$SECOND" "terraform-$RUN"
[ "$(helper get "$HOST" | jq -r .token)" = "$SECOND" ] || fail "get did not follow the token changed in the vault"
[ "$(helper get "nothing.example.com")" = "{}" ] || fail "a host no login is offered on was not answered {}"
grep -q '"terraform-credential"' "$SKARBIEC_AUDIT_FILE" || fail "the read was not journalled"
if helper store "$HOST" </dev/null; then fail "store was not refused"; fi
echo "ok: get answers the vault's current token, {} for a host with none, and store is refused" >>"$REPORT"

WANT=refused run helper import terraform "moved-$RUN" --host "$HOST"
names "holds no token for $HOST"
WANT=ok run helper import terraform "moved-$RUN" --host registry.example.com
[ "$(jq -r '.credentials | has("registry.example.com")' "$HOME/.terraform.d/credentials.tfrc.json")" = "false" ] || fail "import left the token in credentials.tfrc.json"
[ "$(helper get registry.example.com | jq -r .token)" = "plain-$RUN" ] || fail "the imported token is not answered from the vault"
echo "ok: import moves a token out of credentials.tfrc.json into the vault" >>"$REPORT"

WANT=ok run helper unset terraform
if grep -q '^credentials_helper' "$HOME/.terraformrc"; then fail "unset left the block"; fi
grep -q '^plugin_cache_dir' "$HOME/.terraformrc" || fail "unset removed the configuration's other settings"
[ ! -e "$PLUGIN" ] || fail "unset left the plugin link"
WANT=refused run helper unset terraform
names "names no skarbiec credentials helper"
printf 'credentials_helper "other" {\n  args = []\n}\n' >>"$HOME/.terraformrc"
WANT=refused run helper setup terraform
names "already names a credentials helper"
echo "ok: unset removes the block and the link; another helper is refused" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
