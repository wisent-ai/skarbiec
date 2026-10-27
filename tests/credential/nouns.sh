#!/usr/bin/env bash
# Real test of the credential commands named noun then verb, through the built
# binary. The forwards directory, vault and journal live in this checkout's
# target directory (STADO_FORWARDS_DIR, SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE), so the operator's forwards and vault are never read or
# written.
#
#   * `credential endpoint declare <url>` writes the canonical forward: the
#     marker holds the declared address and the answer names the file;
#   * `credential endpoint declare` without an address is refused with its
#     usage, and writes nothing;
#   * a noun alone (`credential directory`) is refused naming the missing verb;
#   * `credential directory seal` and `credential quarantine resolve` without
#     --local are refused naming the command and the flag;
#   * the retired spellings `declare-endpoint`, `seal-directory`, `reseal` and
#     `resolve-quarantine` are unknown credential commands.
#
# Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION and the canonical address the
# test declares (SKARBIEC_TEST_CANONICAL_URL, an http address in a
# documentation range: the declaration writes the marker and reports whether
# anything answers there, which nothing does), then run tests/credential/nouns.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
CANONICAL_URL=${SKARBIEC_TEST_CANONICAL_URL:?name the canonical address this test declares}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/credential-nouns/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT" "$ROOT/forwards"
chmod go-rwx "$ROOT" "$ROOT/forwards"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export STADO_FORWARDS_DIR="$ROOT/forwards"

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
# Runs one skarbiec command, its standard output and standard error together
# in $out; WANT says whether it had to succeed (ok) or be refused (refused).
run() {
  if out=$("$BIN" "$@" </dev/null 2>&1); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput:\n%s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "${WANT:?}" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
says() {
  case "$out" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in the answer" ;;
  esac
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"

WANT=refused run credential endpoint declare
says "usage: credential endpoint declare <url>" "a declaration without an address is refused with its usage"
[ -z "$(ls -A "$ROOT/forwards")" ] || fail "a refused declaration wrote into the forwards directory"

WANT=ok run credential endpoint declare "$CANONICAL_URL"
grep -rqF "$CANONICAL_URL" "$ROOT/forwards" || fail "the forwards directory does not hold the declared address"
says "$ROOT/forwards" "the answer names the forward file it wrote"

WANT=refused run credential directory
says "credential directory needs a verb" "a noun alone is refused naming the missing verb"

WANT=refused run credential directory seal "nouns-item-$RUN" --provider microsoft_entra
says "credential directory seal runs against the vault file it owns; rerun it with --local" "directory seal outside --local is refused naming the command"
WANT=refused run credential quarantine resolve "nouns-item-$RUN"
says "credential quarantine resolve runs against the vault file it owns; rerun it with --local" "quarantine resolve outside --local is refused naming the command"

for retired in declare-endpoint seal-directory reseal resolve-quarantine; do
  WANT=refused run credential "$retired" "nouns-item-$RUN"
  says "unknown credential command: $retired" "the retired spelling $retired is an unknown credential command"
done

echo "PASS" >>"$REPORT"
echo "credential nouns: PASS ($REPORT)"
