#!/usr/bin/env bash
# Real test of `skarbiec readers <id>`, which says who can open one item on
# this host without decrypting it, through the built binary on a vault and
# keyring of its own (SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# under this checkout's target directory, so the operator's vault and keyring
# are never touched).
#
# It creates the vault, writes one login item and asks who can open it: the
# item names at least one key, every key named has its secret half here, and
# openable_here is true. It then deletes every secret key from the test
# keyring, which is what a vault host that lost its key looks like: readers
# still answers, now with no secret half here and openable_here false, and a
# read of the item is refused. A missing item is refused naming its id.
# Every command and its result go to the run's report.txt.
#
# Usage: SKARBIEC=<built skarbiec binary> tests/read/readers.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?SKARBIEC must name the built skarbiec binary this journey runs}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/read/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
if git diff --quiet; then STATE=clean; else STATE=dirty; fi
echo "revision: $(git rev-parse HEAD) ($STATE)" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# Runs one command with $ROOT/stdin on its standard input, standard output and
# standard error together in $out; WANT says whether it had to succeed (ok) or
# be refused (refused).
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
field() {
  printf '%s' "$out" | jq -e "$1" >/dev/null || fail "readers answer does not satisfy $1: $out"
  echo "ok: $1" >>"$REPORT"
}

: >"$ROOT/stdin"
WANT=ok run init "readers-test-owner-$RUN"
ITEM="readers-test-login-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"readers-test-user-%s","password":"readers-test-secret-%s"},"context":{}}' \
  "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"

WANT=ok run readers "$ITEM"
field '.encrypted_to | length > 0'
field '[.encrypted_to[].secret_key_here] | all'
field '.openable_here == true'

gpg --batch --list-secret-keys --with-colons |
  while IFS=: read -r kind _ _ _ _ _ _ _ _ fingerprint _; do
    [ "$kind" != fpr ] || gpg --batch --yes --delete-secret-keys "$fingerprint"
  done
echo "deleted every secret key from the test keyring" >>"$REPORT"

WANT=ok run readers "$ITEM"
field '.encrypted_to | length > 0'
field '[.encrypted_to[].secret_key_here] | any | not'
field '.openable_here == false'
WANT=refused run get "$ITEM" --field password

WANT=refused run readers "missing-item-$RUN"
case "$out" in
  *"missing-item-$RUN"*) echo "ok: refused naming missing-item-$RUN" >>"$REPORT" ;;
  *) fail "expected a refusal naming missing-item-$RUN, got: $out" ;;
esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
