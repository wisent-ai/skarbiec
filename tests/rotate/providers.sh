#!/usr/bin/env bash
# Real test of `skarbiec rotate <id> --with <provider>` and `skarbiec rotation
# providers`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written. The ssh provider is the one rotated through, because it
# needs nothing outside this machine.
#
# rotation providers lists every provider with the flags its usage line
# declares — the names and flags rotate and rotation set accept. rotate
# without --with, with a provider that does not exist and with
# a flag the provider does not take is refused before the item changes; the
# old per-provider command name is no command at all. rotate --with ssh
# replaces the key and the answer names the provider.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/rotate/providers.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/rotate/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
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
  if out=$("$BIN" "$@" </dev/null &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}

WANT=ok run init "rotate-test-owner-$RUN"

WANT=ok run rotation providers
PROVIDERS="$out"
printf '%s' "$PROVIDERS" | jq -e '.providers | all(.flags | type == "array") and all(.usage | test("--with " + .provider))' &>/dev/null \
  || fail "a provider's usage line does not name it after --with: $PROVIDERS"
printf '%s' "$PROVIDERS" | jq -e '.providers[] | select(.provider == "ssh") | .flags | index("hosts") and index("github")' &>/dev/null \
  || fail "the ssh provider does not list --hosts and --github: $PROVIDERS"
printf '%s' "$PROVIDERS" | jq -e '.providers[] | select(.provider == "database") | .flags | index("url") and index("length")' &>/dev/null \
  || fail "the database provider does not list --url and --length: $PROVIDERS"
echo "ok: rotation providers lists each provider with the flags its usage line declares" >>"$REPORT"
WANT=refused run rotation providers extra
names "rotation providers takes no argument or flag"

KEY="rotated-$RUN"
WANT=ok run ssh new "$KEY"
BEFORE="$(printf '%s' "$out" | jq -r .public_key)"

WANT=refused run rotate "$KEY"
names "--with <provider>"
WANT=refused run rotate "$KEY" --with nowhere
names "--with nowhere is not a provider this vault rotates through"
for provider in $(printf '%s' "$PROVIDERS" | jq -r '.providers[].provider'); do
  case "$out" in *"$provider"*) ;; *) fail "the refusal does not name the provider $provider: $out" ;; esac
done
WANT=refused run rotate "$KEY" --with ssh --url postgresql://db.example.com/app
names "--with ssh takes no --url"
WANT=refused run ssh-rotate "$KEY"
WANT=ok run get "$KEY" --field public_key
[ "$out" = "$BEFORE" ] || fail "a refused rotate changed the key"
echo "ok: no provider, an unknown provider, a stray flag and the old command name are refused and the key is unchanged" >>"$REPORT"

WANT=ok run rotate "$KEY" --with ssh
[ "$(printf '%s' "$out" | jq -r .provider)" = "ssh" ] || fail "the answer does not name the ssh provider: $out"
case "$out" in *"PRIVATE KEY"*) fail "rotate printed a private key" ;; esac
NEW="$(printf '%s' "$out" | jq -r .public_key)"
WANT=ok run get "$KEY" --field public_key
[ "$out" = "$NEW" ] && [ "$out" != "$BEFORE" ] || fail "the item does not hold the new key rotate named: $out"
echo "ok: rotate --with ssh replaces the key and names the provider" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
