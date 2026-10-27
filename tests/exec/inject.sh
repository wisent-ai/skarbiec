#!/usr/bin/env bash
# Real test of filling a configuration template, `skarbiec inject <template>
# <out-file> [--replace]`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# The template names two fields of one login and holds a {{ other }} that is
# not ours. The filled file holds both values where the references were, the
# other braces as written, and is owner-only; skarbiec's output and the
# journal hold no value. An existing file is refused without --replace and
# replaced with it. A missing field, a malformed reference and a template
# with no reference are refused, and then no file is written.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/exec/inject.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/exec/$RUN"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}

SECRET="inject-secret-$RUN"
ITEM="inject-db-$RUN"
TEMPLATE="$ROOT/env.template"
FILLED="$ROOT/env"
: >"$ROOT/stdin"
WANT=ok run init "inject-owner-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"app-%s","password":"%s"},"context":{}}' "$RUN" "$SECRET" >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"

printf 'USER={{ skarbiec:%s:username }}\nPASSWORD={{skarbiec:%s:password}}\nKEPT={{ other }}\n' "$ITEM" "$ITEM" >"$TEMPLATE"
WANT=ok run inject "$TEMPLATE" "$FILLED"
printf 'USER=app-%s\nPASSWORD=%s\nKEPT={{ other }}\n' "$RUN" "$SECRET" >"$ROOT/expected"
cmp -s "$ROOT/expected" "$FILLED" || fail "the filled file is not the template with both values: $(cat "$FILLED")"
[ "$(stat -f %Lp "$FILLED")" = "$(stat -f %Lp "$SKARBIEC_VAULT_FILE")" ] || fail "the filled file is not owner-only as the vault is"
case "$out" in *"$SECRET"*) fail "inject printed a value" ;; esac
if grep -q "$SECRET" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds a value"; fi
printf '%s' "$out" | jq -e '.references | map(.field) | index("password") != null' >/dev/null || fail "the answer does not name the references"
echo "ok: both references filled, other braces kept, owner-only, no value printed or journalled" >>"$REPORT"

WANT=refused run inject "$TEMPLATE" "$FILLED"
names "exists; --replace overwrites it"
WANT=ok run inject "$TEMPLATE" "$FILLED" --replace

rm -f "$ROOT/none"
printf 'PIN={{ skarbiec:%s:pin }}\n' "$ITEM" >"$ROOT/missing.template"
WANT=refused run inject "$ROOT/missing.template" "$ROOT/none"
names "line"
names "$ITEM has no text field pin"
printf 'BAD={{ skarbiec:%s }}\n' "$ITEM" >"$ROOT/bad.template"
WANT=refused run inject "$ROOT/bad.template" "$ROOT/none"
names "is not {{ skarbiec:<id>:<field> }}"
printf 'NOTHING=here\n' >"$ROOT/plain.template"
WANT=refused run inject "$ROOT/plain.template" "$ROOT/none"
names "so there is nothing to fill"
[ ! -e "$ROOT/none" ] || fail "a refused inject wrote a file"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
