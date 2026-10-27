#!/usr/bin/env bash
# Real test of making an SSH key in the vault, `skarbiec ssh new <id>`,
# through the built binary and the real ssh-keygen, on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# It makes a key and checks that the answer carries a public key of the type
# it names, with the comment asked for and no private key; that the item
# holds a private key whose public half, as ssh-keygen -y derives it, is the
# one printed; that no workspace is left beside the vault; and that a second
# key under the same id and a call without one id are refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/keygen/new_ssh_key.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/keygen/$RUN"
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
  if out=$("$BIN" "$@" </dev/null 2>&1); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}

WANT=ok run init "keygen-owner-$RUN"
KEY="keygen-key-$RUN"
COMMENT="me@keygen-$RUN"
WANT=ok run ssh new "$KEY" --comment "$COMMENT"
PUBLIC="$(printf '%s' "$out" | jq -r .public_key)"
TYPE="$(printf '%s' "$out" | jq -r .type)"
case "$PUBLIC" in
  "ssh-$TYPE "*" $COMMENT") ;;
  *) fail "the answer is not an ssh-$TYPE public key with the comment: $PUBLIC" ;;
esac
case "$out" in *"PRIVATE KEY"*) fail "the answer carried the private key" ;; esac
echo "ok: ssh new prints only the public key, with the comment" >>"$REPORT"

WANT=ok run get "$KEY" --field private_key
printf '%s\n' "$out" >"$ROOT/derive.key"
chmod go-rwx "$ROOT/derive.key"
DERIVED="$(ssh-keygen -y -f "$ROOT/derive.key")"
rm -f "$ROOT/derive.key"
[ "${PUBLIC% *}" = "${DERIVED% *}" ] || fail "the stored private key does not derive the printed public key"
echo "ok: the stored private key derives the printed public key" >>"$REPORT"

for left in "$ROOT"/.skarbiec-keygen-*; do
  if [ -e "$left" ]; then fail "a key workspace was left beside the vault: $left"; fi
done
echo "ok: no key workspace is left beside the vault" >>"$REPORT"

WANT=refused run ssh new "$KEY"
names "$KEY already exists"
WANT=refused run ssh new
names "usage: ssh new <id>"
WANT=refused run new-ssh-key "other-$KEY"
names "unknown command: new-ssh-key"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
