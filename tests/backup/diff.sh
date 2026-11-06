#!/usr/bin/env bash
# Real test of comparing a copy with the vault, `skarbiec backup diff <file>`,
# through the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# Three notes are copied. Then one is changed, one is trashed and a fourth is
# made. The diff names the changed note under changed with the copy's older
# revision, the trashed one under only_in_copy, the new one under
# only_in_vault, and counts the untouched one as alike; the vault is not
# changed by asking. A file that is not a vault is refused naming it.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/backup/diff.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/backup/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
COPIES="$ROOT/copies"
mkdir -p "$ROOT" "$KEYRING" "$COPIES"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}

KEPT="diff-kept-$RUN"
CHANGED="diff-changed-$RUN"
GONE="diff-gone-$RUN"
NEW="diff-new-$RUN"
: >"$ROOT/stdin"
WANT=ok run init "diff-owner-$RUN"
note "$KEPT" "kept"
note "$CHANGED" "before"
note "$GONE" "gone"
WANT=ok run backup "$COPIES"
COPY="$(printf '%s' "$out" | jq -r .backup)"

note "$CHANGED" "after"
WANT=ok run delete "$GONE"
note "$NEW" "new"
BEFORE="$(shasum "$SKARBIEC_VAULT_FILE")"

WANT=ok run backup diff "$COPY"
printf '%s' "$out" | jq -e --arg c "$CHANGED" '[.changed[] | select(.item == $c and .copy.revision < .vault.revision)] | length > ([] | length)' >/dev/null \
  || fail "the changed note is not under changed with the copy's older revision: $out"
printf '%s' "$out" | jq -e --arg g "$GONE" --arg n "$NEW" '([.only_in_copy[].item] | index($g) != null) and ([.only_in_vault[].item] | index($n) != null)' >/dev/null \
  || fail "the trashed note is not only in the copy, or the new one not only in the vault: $out"
printf '%s' "$out" | jq -e --arg k "$KEPT" '[.changed[].item, .only_in_copy[].item, .only_in_vault[].item] | index($k) == null' >/dev/null \
  || fail "the untouched note was reported as different: $out"
[ "$(shasum "$SKARBIEC_VAULT_FILE")" = "$BEFORE" ] || fail "backup diff changed the vault"
echo "ok: diff names changed, only-in-copy and only-in-vault items without changing the vault" >>"$REPORT"

printf 'not a vault' >"$ROOT/plain.txt"
WANT=refused run backup diff "$ROOT/plain.txt"
case "$said" in *"does not read as a Skarbiec vault"*) echo "ok: a file that is not a vault is refused" >>"$REPORT" ;; *) fail "a file that is not a vault was not refused naming it: output: $out stderr: $said" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
