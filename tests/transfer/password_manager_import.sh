#!/usr/bin/env bash
# Real test of `skarbiec import` reading a password manager's export field by
# field, through the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vaults and keyring are never read or written.
#
# A Bitwarden export whose login password is a number is refused naming the
# item, the field and the kind of value, never the value, and the vault gains
# nothing. A login whose authenticator is an otpauth address with another
# digit count is imported with the address kept aside and a warning naming
# the digit count; one with a usable seed is imported with its seed active.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/transfer/password_manager_import.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/transfer-import/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" </dev/null 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
# Either stream: a refused import says why on stderr, an accepted one names
# each item's warning in the JSON report on stdout.
names() {
  case "$out$said" in
    *"$*"*) echo "ok: names: $*" >>"$REPORT" ;;
    *) fail "expected the answer to name '$*', got: $out; stderr: $said" ;;
  esac
}
# The `type` Bitwarden gives a login, read from the importer's own
# declaration so the export this journey writes is the one it reads.
LOGIN_TYPE=$(sed -n 's/^const LOGIN_TYPE: u64 = \([[:digit:]]*\);$/\1/p' src/core/importer/providers/bitwarden.rs)
[ -n "$LOGIN_TYPE" ] || fail "src/core/importer/providers/bitwarden.rs declares no LOGIN_TYPE"
# One Bitwarden login item: its id and name, then the login object as JSON.
item() {
  jq -n --arg id "$1" --arg name "$2" --argjson type "$LOGIN_TYPE" --argjson login "$3" \
    '{id: $id, name: $name, type: $type, login: $login}'
}
export_of() {
  jq -s '{encrypted: false, items: .}'
}

WANT=ok run init "import-owner-$RUN"

NUMERIC_PASSWORD="40417$$"
item "numeric-$RUN" "numeric $RUN" "{\"username\": \"numeric-user\", \"password\": $NUMERIC_PASSWORD}" \
  | export_of >"$ROOT/numeric-password.json"
WANT=refused run import "$ROOT/numeric-password.json" --format bitwarden
names "Bitwarden items["
names "password holds a number"
# Neither stream may carry the refused password.
case "$out$said" in *"$NUMERIC_PASSWORD"*) fail "the refusal printed the password it refused" ;; esac
WANT=ok run list
printf '%s' "$out" | jq -e 'length == 0' >/dev/null || fail "a refused import left items in the vault: $out"
echo "ok: a numeric password refuses the import by field and kind, and the vault holds nothing" >>"$REPORT"

{
  item "eight-$RUN" "eight digits $RUN" \
    "{\"username\": \"eight-user\", \"password\": \"eight-$RUN\", \"totp\": \"otpauth://totp/eight?secret=JBSWY3DPEHPK3PXP&digits=8\"}"
  item "usable-$RUN" "usable seed $RUN" \
    "{\"username\": \"usable-user\", \"password\": \"usable-$RUN\", \"totp\": \"otpauth://totp/usable?secret=JBSWY3DPEHPK3PXP\"}"
} | export_of >"$ROOT/authenticators.json"
WANT=ok run import "$ROOT/authenticators.json" --format bitwarden
names "was not activated"
names "asks for 8 digits"
WANT=ok run list
USABLE=$(printf '%s' "$out" | jq -r --arg title "usable seed $RUN" '.[] | select(.title == $title) | .id')
[ -n "$USABLE" ] || fail "the login with a usable seed was not imported: $out"
WANT=ok run totp code "$USABLE"
echo "ok: an eight-digit address is kept aside with the digit count named; a usable seed computes a code" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
