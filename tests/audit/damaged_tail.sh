#!/usr/bin/env bash
# Real test of the audit journal's chain tail through the built binary on a
# vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# point into this checkout's target directory, so the operator's vault,
# journal and keyring are never read or written.
#
# It creates the vault and writes one item, so the journal holds entries,
# then appends a line that is not an entry to the journal and writes a second
# item. The write must be refused naming the damaged last line, and the
# journal must still end with that line: no entry may be chained onto the
# older hash behind it. Then it replaces the damaged line with an entry that
# carries no hash and expects the refusal that names the missing hash.
# Every command, whether it succeeded and its output go to the run's
# report.txt; no item value is written there.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run
# tests/audit/damaged_tail.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/audit-damaged-tail/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  printf '$ skarbiec %s\nexit: %s\nresult: %s\noutput: %s\n\n' "$*" "$status" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT"
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"audit-tail-user-%s","password":"audit-tail-%s"},"context":{}}' "$1" "$RUN" >"$ROOT/stdin"
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

: >"$ROOT/stdin"
WANT=ok run init "audit-tail-owner-$RUN"
login first
WANT=ok run set-json "audit-tail-first-$RUN" --type login
[ -s "$SKARBIEC_AUDIT_FILE" ] || fail "writing an item left no journal entry"

damaged="{\"at\": \"audit-tail-$RUN\", \"op\": "
printf '%s\n' "$damaged" >>"$SKARBIEC_AUDIT_FILE"
login second
WANT=refused run set-json "audit-tail-second-$RUN" --type login
case "$out" in
  *"ends with a line that is not an entry"*) ;;
  *) fail "the refusal does not name the damaged last journal line" ;;
esac
[ "$(sed -n '$p' "$SKARBIEC_AUDIT_FILE")" = "$damaged" ] \
  || fail "an entry was chained past the damaged line"
echo "ok: a damaged last line refuses the next entry and stays last" >>"$REPORT"

kept=$(grep -v -F -x -- "$damaged" "$SKARBIEC_AUDIT_FILE")
printf '%s\n{"at":"audit-tail-%s","op":"audit-tail-unhashed"}\n' "$kept" "$RUN" >"$SKARBIEC_AUDIT_FILE"
login third
WANT=refused run set-json "audit-tail-third-$RUN" --type login
case "$out" in
  *"last entry carries no hash"*) ;;
  *) fail "the refusal does not name the last entry's missing hash" ;;
esac
echo "ok: a last entry without a hash refuses the next entry" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
