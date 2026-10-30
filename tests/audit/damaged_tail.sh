#!/usr/bin/env bash
# Real test of the audit journal's chain tail through the built binary on a
# vault of its own: SKARBIEC_VAULT_FILE and SKARBIEC_AUDIT_FILE point into
# this checkout's target directory, the key file beside that vault, so the
# operator's vault, journal and keys are never read or written.
#
# It creates the vault and writes one item, so the journal holds entries,
# then appends a line that is not an entry to the journal and writes a second
# item. An item write the vault has saved stands, so the write succeeds; its
# audit entry must be refused on stderr naming the damaged last line, and the
# journal must still end with that line: no entry may be chained onto the
# older hash behind it. Then it replaces the damaged line with an entry that
# carries no hash and expects the refusal that names the missing hash, with
# that line still last. Every command, whether it succeeded and its output go
# to the run's report.txt; no item value is written there.
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nexit: %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$status" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
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
WANT=ok run set "audit-tail-first-$RUN" --type login
[ -s "$SKARBIEC_AUDIT_FILE" ] || fail "writing an item left no journal entry"

damaged="{\"at\": \"audit-tail-$RUN\", \"op\": "
printf '%s\n' "$damaged" >>"$SKARBIEC_AUDIT_FILE"
login second
WANT=ok run set "audit-tail-second-$RUN" --type login
case "$said" in
  *"audit entry was not recorded"*"ends with a line that is not an entry"*) ;;
  *) fail "the write did not say its audit entry was refused for the damaged last journal line" ;;
esac
[ "$(sed -n '$p' "$SKARBIEC_AUDIT_FILE")" = "$damaged" ] \
  || fail "an entry was chained past the damaged line"
echo "ok: a damaged last line refuses the next entry, says so, and stays last" >>"$REPORT"

kept=$(grep -v -F -x -- "$damaged" "$SKARBIEC_AUDIT_FILE")
unhashed="{\"at\":\"audit-tail-$RUN\",\"op\":\"audit-tail-unhashed\"}"
printf '%s\n%s\n' "$kept" "$unhashed" >"$SKARBIEC_AUDIT_FILE"
login third
WANT=ok run set "audit-tail-third-$RUN" --type login
case "$said" in
  *"audit entry was not recorded"*"last entry carries no hash"*) ;;
  *) fail "the write did not say its audit entry was refused for the last entry's missing hash" ;;
esac
[ "$(sed -n '$p' "$SKARBIEC_AUDIT_FILE")" = "$unhashed" ] \
  || fail "an entry was chained past the entry without a hash"
echo "ok: a last entry without a hash refuses the next entry, says so, and stays last" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
