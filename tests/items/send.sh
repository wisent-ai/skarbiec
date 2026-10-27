#!/usr/bin/env bash
# Real test of handing one value to someone outside the vault, `skarbiec send
# <id> --field <field>`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# The armored message it prints must open with plain `gpg --decrypt` and the
# passphrase it prints, in a second keyring that holds no key at all — as the
# recipient would open it — and give back exactly the field's value. The
# journal must record the send and never the value or the passphrase. A field
# the item does not hold is refused naming it.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/items/send.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/items/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
STRANGER="$PWD/target/s$$"
mkdir -p "$ROOT" "$KEYRING" "$STRANGER"
chmod go-rwx "$KEYRING" "$STRANGER"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$KEYRING" --kill all || true; gpgconf --homedir "$STRANGER" --kill all || true; rm -rf "$KEYRING" "$STRANGER"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
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
WANT=ok run init "send-owner-$RUN"
ITEM="send-login-$RUN"
SECRET="send-secret-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"send-user","password":"%s"},"context":{}}' \
  "$SECRET" >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"

WANT=ok run send "$ITEM" --field password
printf '%s' "$out" | jq -r .message >"$ROOT/message.asc"
PASSPHRASE=$(printf '%s' "$out" | jq -r .passphrase)
[ -n "$PASSPHRASE" ] || fail "send printed no passphrase"
opened=$(gpg --homedir "$STRANGER" --batch --pinentry-mode loopback --passphrase "$PASSPHRASE" --decrypt "$ROOT/message.asc" 2>>"$REPORT") \
  || fail "the message did not open with gpg --decrypt and its passphrase in an empty keyring"
[ "$opened" = "$SECRET" ] || fail "the message opened to something other than the field's value"
echo "ok: the message opens with plain gpg and the passphrase, to exactly the value" >>"$REPORT"

grep -q '"item-sent"' "$SKARBIEC_AUDIT_FILE" || fail "the journal records no item-sent"
if grep -q "$SECRET" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds the value sent"; fi
if grep -q "$PASSPHRASE" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds the passphrase"; fi
echo "ok: the journal records the send and neither the value nor the passphrase" >>"$REPORT"

WANT=refused run send "$ITEM" --field "missing_$RUN"
names "missing_$RUN"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
