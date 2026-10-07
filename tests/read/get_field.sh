#!/usr/bin/env bash
# Real test of reading from Skarbiec with one CLI command, `skarbiec get <id>
# --field <field>`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written. The keyring sits at a short path because gpg-agent's socket
# lives in it and a Unix socket path is limited in length.
#
# It creates the vault with `init`, writes one login item with `set-json` (the
# payload on stdin, so no value is in argv), reads one field back and checks
# that the command printed exactly that field's plaintext and nothing else,
# then checks the refusals: a field the item does not hold and an item the
# vault does not hold are each refused, naming what is missing. Every command
# and whether it succeeded go to the run's report.txt, with its output for the
# refusals; a read value is never written there.
#
# Usage: tests/read/get_field.sh   (SKARBIEC selects the binary, default
#   target/debug/skarbiec)
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:-$PWD/target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/read/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# Runs one command with $ROOT/stdin on its standard input, standard output and
# standard error together in $out; WANT says whether it had to succeed (ok) or
# be refused (refused).
run() {
  if out=$(set -o pipefail; "$BIN" "$@" <"$ROOT/stdin" |& cat); then got=ok; else got=refused; fi
  if [ "$got" = ok ]; then
    printf '$ skarbiec %s\nresult: ok\n\n' "$*" >>"$REPORT"
  else
    printf '$ skarbiec %s\nresult: refused\noutput: %s\n\n' "$*" "$out" >>"$REPORT"
  fi
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}

: >"$ROOT/stdin"
WANT=ok run init "read-test-owner-$RUN"

ITEM="read-test-login-$RUN"
SECRET="read-test-secret-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"read-test-user-%s","password":"%s"},"context":{}}' \
  "$RUN" "$SECRET" >"$ROOT/stdin"
WANT=ok run set-json "$ITEM" --type login
: >"$ROOT/stdin"

WANT=ok run get "$ITEM" --field password
[ "$out" = "$SECRET" ] || fail "get --field password did not print exactly the stored value and nothing else"
echo "ok: get --field password printed exactly the stored value and nothing else" >>"$REPORT"

WANT=refused run get "$ITEM" --field "missing_field_$RUN"
names "missing_field_$RUN"
WANT=refused run get "missing-item-$RUN" --field password
names "missing-item-$RUN"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
