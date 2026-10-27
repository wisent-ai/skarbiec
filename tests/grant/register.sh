#!/usr/bin/env bash
# Real test of `grant register`, through the built binary on a vault of its
# own (SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written).
#
# An acquisition catalog of two rows registers two workload-bound acquire
# grants, each listed with the capability its row names; the journal records
# the registration. Registering the same catalog with the same key again needs
# no --replace-capabilities; another key is refused without it and taken with
# it. Refusals: no catalog, a relative catalog path, a missing lifetime, a flag
# the command does not take, and the retired spelling
# `token-register-acquisitions`. Every command and verdict goes to the run's
# report.txt.
#
# Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION and the lifetime in whole
# seconds of the grants this test registers (SKARBIEC_TEST_GRANT_TTL), then run
# tests/grant/register.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
TTL=${SKARBIEC_TEST_GRANT_TTL:?state the lifetime in whole seconds of the grants this test registers}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/grant-register/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/r$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
cleanup() {
  if ! gpgconf --homedir "$GNUPGHOME" --kill all; then
    echo "cleanup: the gpg daemons of $GNUPGHOME did not stop" >>"$REPORT"
  fi
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
# Runs one skarbiec command; its standard output is in $out and its standard
# error in $said, which goes to the report. WANT says whether it had to
# succeed (ok) or be refused (refused).
run() {
  if out=$("$BIN" "$@" </dev/null 2>"$ROOT/stderr"); then status=ok; else status=refused; fi
  said=$(cat "$ROOT/stderr")
  printf '$ skarbiec %s\nresult: %s\n%s\n\n' "$*" "$status" "$said" >>"$REPORT"
  [ "$status" = "${WANT:?}" ] || fail "skarbiec $* was $status, expected $WANT: $said"
}
# The capabilities `grant list` records for consumer $1, as JSON.
capabilities_of() {
  "$BIN" grant list </dev/null 2>>"$REPORT" \
    | jq -ec --arg consumer "$1" '.[] | select(.consumer == $consumer) | .capabilities'
}
refused_saying() {
  case "$said" in *"$1"*) ;; *) fail "the refusal does not say '$1': $said" ;; esac
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

ITEM="register-provider-$RUN"
FIRST="register-first-$RUN"
SECOND="register-second-$RUN"
WANT=ok run init "register-test-owner-$RUN"
jq -n '{schema:"skarbiec.item.v2",kind:"api-key",fields:{api_key:"not-a-secret"},context:{}}' \
  | "$BIN" set "$ITEM" --type api-key >>"$REPORT" 2>&1 || fail "set $ITEM was refused"

openssl genpkey -algorithm ed25519 -out "$ROOT/workload.pem" 2>>"$REPORT"
openssl pkey -in "$ROOT/workload.pem" -pubout -out "$ROOT/workload.pub.pem"
openssl genpkey -algorithm ed25519 -out "$ROOT/other.pem" 2>>"$REPORT"
openssl pkey -in "$ROOT/other.pem" -pubout -out "$ROOT/other.pub.pem"
chmod go-rwx "$ROOT"/*.pem
CATALOG="$ROOT/catalog.conf"
printf '# consumer|item|field\n%s|%s|api_key\n%s|%s|api_key\n' "$FIRST" "$ITEM" "$SECOND" "$ITEM" >"$CATALOG"
chmod go-rwx "$CATALOG"

WANT=ok run grant register "$CATALOG" --workload-public-key-file "$ROOT/workload.pub.pem" --ttl-seconds "$TTL"
[ "$(printf '%s' "$out" | jq -r '.registered | tostring')" = "$(grep -cv '^#' "$CATALOG")" ] \
  || fail "grant register did not register one grant per catalog row: $out"
for consumer in "$FIRST" "$SECOND"; do
  [ "$(capabilities_of "$consumer")" = "[\"acquire:$ITEM#api_key\"]" ] \
    || fail "$consumer does not hold exactly the capability its row names"
done
jq -e --arg first "$FIRST" 'select(.op == "token-register-acquisitions") | .extra.consumers | index($first) != null' \
  "$SKARBIEC_AUDIT_FILE" >/dev/null || fail "the journal does not record the registration naming $FIRST"
echo "ok: every catalog row is an acquire grant, and the journal records the registration" >>"$REPORT"

WANT=ok run grant register "$CATALOG" --workload-public-key-file "$ROOT/workload.pub.pem" --ttl-seconds "$TTL"
echo "ok: registering the same catalog with the same key needs no --replace-capabilities" >>"$REPORT"

WANT=refused run grant register "$CATALOG" --workload-public-key-file "$ROOT/other.pub.pem" --ttl-seconds "$TTL"
refused_saying "differs from the acquisition catalog; pass --replace-capabilities"
WANT=ok run grant register "$CATALOG" --workload-public-key-file "$ROOT/other.pub.pem" --ttl-seconds "$TTL" --replace-capabilities
echo "ok: another key is refused without --replace-capabilities and taken with it" >>"$REPORT"

WANT=refused run grant register
refused_saying "usage: grant register <absolute-catalog>"
WANT=refused run grant register catalog.conf --workload-public-key-file "$ROOT/workload.pub.pem" --ttl-seconds "$TTL"
refused_saying "acquisition catalog path must be absolute"
WANT=refused run grant register "$CATALOG" --workload-public-key-file "$ROOT/workload.pub.pem"
refused_saying "grant register requires --ttl-seconds"
WANT=refused run grant register "$CATALOG" --workload-public-key-file "$ROOT/workload.pub.pem" --ttl-seconds "$TTL" --audience other
refused_saying "unsupported grant register flag"
WANT=refused run token-register-acquisitions "$CATALOG" --workload-public-key-file "$ROOT/workload.pub.pem" --ttl-seconds "$TTL"
refused_saying "unknown command: token-register-acquisitions"

echo "PASS" >>"$REPORT"
echo "grant register: PASS ($REPORT)"
