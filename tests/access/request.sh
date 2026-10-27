#!/usr/bin/env bash
# Real test of the access request register (docs/design/access-requests.md),
# through the real binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, the capability files and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written. The keyring sits at a short path because gpg-agent's socket
# lives in it and a Unix socket path is limited in length.
#
# It checks what the runnable example (docs/examples/sharing/request-access.sh)
# does not: who may not decide (a member, a stranger, the decider a request did
# not name), what an approval must not leave out or mix (no lifetime, no uses
# for a capability, uses on a standing grant, until-revoked on a capability),
# that a closed request takes no further decision, that the requesting agent
# may withdraw its own request, that the register is owner-only and holds no
# bearer, that a dual-control grant takes the narrower bounds, and that the
# journal records every step. Every command and whether it succeeded go to the
# run's report.txt.
#
# Usage:
#   SKARBIEC=<binary> \
#   REQUEST_TEST_WIDE_SECONDS=<N> REQUEST_TEST_WIDE_USES=<N> \
#   REQUEST_TEST_NARROW_SECONDS=<N> REQUEST_TEST_NARROW_USES=<N> \
#   tests/access/request.sh
#   SKARBIEC names the binary under test: a build (target/debug/skarbiec) or
#   the installed release; the report records which one and its version.
#   The wide bounds are what the agent asks and the first decider grants; the
#   narrow ones, each smaller, are what the second decider grants and what
#   a dual-control grant must then carry.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?SKARBIEC must name the skarbiec binary under test (a build such as target/debug/skarbiec, or the installed release)}
WIDE_SECONDS=${REQUEST_TEST_WIDE_SECONDS:?REQUEST_TEST_WIDE_SECONDS must state the lifetime the agent asks and the first decider grants}
WIDE_USES=${REQUEST_TEST_WIDE_USES:?REQUEST_TEST_WIDE_USES must state the uses the agent asks and the first decider grants}
NARROW_SECONDS=${REQUEST_TEST_NARROW_SECONDS:?REQUEST_TEST_NARROW_SECONDS must state the shorter lifetime the second decider grants}
NARROW_USES=${REQUEST_TEST_NARROW_USES:?REQUEST_TEST_NARROW_USES must state the fewer uses the second decider grants}
[ "$NARROW_SECONDS" -lt "$WIDE_SECONDS" ] \
  || { echo "REQUEST_TEST_NARROW_SECONDS ($NARROW_SECONDS) must be less than REQUEST_TEST_WIDE_SECONDS ($WIDE_SECONDS)" >&2; false; }
[ "$NARROW_USES" -lt "$WIDE_USES" ] \
  || { echo "REQUEST_TEST_NARROW_USES ($NARROW_USES) must be less than REQUEST_TEST_WIDE_USES ($WIDE_USES)" >&2; false; }
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/access-request/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "version: $("$BIN" --version &>/dev/stdout)" >>"$REPORT"
echo "bounds: wide $WIDE_SECONDS s / $WIDE_USES uses, narrow $NARROW_SECONDS s / $NARROW_USES uses" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export SKARBIEC_CAPABILITY_FILE="$ROOT/capabilities.json"
export SKARBIEC_CAPABILITY_ROUTES_FILE="$ROOT/capability-routes.json"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# One command, standard output and standard error together in $out; WANT says
# whether it had to succeed (ok) or be refused (refused).
run() {
  if out=$("$BIN" "$@" </dev/null &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
has() {
  case "$out" in
    *"$*"*) echo "ok: output names: $*" >>"$REPORT" ;;
    *) fail "expected output naming '$*', got: $out" ;;
  esac
}
# The first request id the last answer names; an answer naming none fails.
id_of() {
  local first
  IFS= read -r first < <(printf '%s\n' "$out" | sed -n 's/.*"request_id": "\([^"]*\)".*/\1/p') \
    || fail "the answer names no request_id: $out"
  printf '%s\n' "$first"
}
# The permission string `ls -l` prints for one file.
mode_of() {
  local mode rest
  read -r mode rest < <(ls -l "$1")
  printf '%s\n' "$mode"
}

OWNER="request-test-owner-$RUN"
WANT=ok run init "$OWNER"
WANT=ok run recipient add "request-test-admin-$RUN" --role admin
WANT=ok run recipient add "request-test-member-$RUN" --role member
printf '{"schema":"skarbiec.item.v2","kind":"api-key","fields":{"api_key":"request-test-%s"},"context":{}}' "$RUN" \
  | "$BIN" set request-test-item --type api-key --tags "brama:provider:request-test,dual-control" >/dev/null
printf '{"schema":"skarbiec.item.v2","kind":"api-key","fields":{"api_key":"request-test-plain-%s"},"context":{}}' "$RUN" \
  | "$BIN" set request-test-plain --type api-key >/dev/null

# A capability request, asked bounds included.
WANT=ok run request file --kind secret --resource provider:request-test --action read \
  --purpose test.read --target test --ttl-seconds "$WIDE_SECONDS" --max-uses "$WIDE_USES" \
  --agent request-test-agent --reason "test the register"
has '"dual_control": true'
CAPABILITY=$(id_of)
[ -n "$CAPABILITY" ] || fail "request file named no request id"

# The register is owner-only and names the request.
mode=$(mode_of "$ROOT/vault.requests.json")
[ "$mode" = "-rw-------" ] || fail "the register is $mode, not owner-only"
echo "ok: the register is owner-only" >>"$REPORT"

# Who may not decide.
WANT=refused run request approve "$CAPABILITY" --by "request-test-member-$RUN" \
  --ttl-seconds "$NARROW_SECONDS" --uses "$NARROW_USES"
has "only a recipient with role owner or admin may decide"
WANT=refused run request approve "$CAPABILITY" --by request-test-stranger \
  --ttl-seconds "$NARROW_SECONDS" --uses "$NARROW_USES"
has "is not a recipient of this vault"

# What an approval must state, and what it must not mix.
WANT=refused run request approve "$CAPABILITY" --by "$OWNER" --uses "$NARROW_USES"
has "--ttl-seconds <N> or --until-revoked"
WANT=refused run request approve "$CAPABILITY" --by "$OWNER" --ttl-seconds "$NARROW_SECONDS"
has "--uses <N> is required"
WANT=refused run request approve "$CAPABILITY" --by "$OWNER" --until-revoked --uses "$NARROW_USES"
has "a capability always expires"
WANT=refused run request approve "$CAPABILITY" --by "$OWNER" --ttl-seconds "$NARROW_SECONDS" \
  --until-revoked --uses "$NARROW_USES"
has "exclusive"

# Dual control: the narrower of the two deciders' bounds is what is issued.
WANT=ok run request approve "$CAPABILITY" --by "$OWNER" --ttl-seconds "$WIDE_SECONDS" --uses "$WIDE_USES"
has '"status": "awaiting-second-decider"'
WANT=ok run request approve "$CAPABILITY" --by "request-test-admin-$RUN" \
  --ttl-seconds "$NARROW_SECONDS" --uses "$NARROW_USES"
has '"status": "granted"'
remaining=$(sed -n 's/.*"remaining_uses": *\([[:digit:]]*\).*/\1/p' "$ROOT/capabilities.json")
[ "$remaining" = "$NARROW_USES" ] || fail "the issued capability has $remaining uses, not the narrower $NARROW_USES"
grep -q "\"authorization_id\": *\"$CAPABILITY\"" "$ROOT/capabilities.json" \
  || fail "the capability is not bound to the request id"
echo "ok: the grant took the narrower bounds and the request id" >>"$REPORT"

# A closed request takes no further decision.
WANT=refused run request deny "$CAPABILITY" --by "$OWNER"
has "not pending"

# A standing grant names no uses, and its bearer never reaches the answer or
# the register.
WANT=ok run request file --kind secret --resource request-test-plain#api_key --action read \
  --for-consumer request-test-reader --agent request-test-agent --reason "standing read"
STANDING=$(id_of)
WANT=refused run request approve "$STANDING" --by "$OWNER" --until-revoked --uses "$NARROW_USES"
has "drop --uses"
WANT=ok run request approve "$STANDING" --by "$OWNER" --until-revoked
TOKEN_FILE=$(printf '%s\n' "$out" | sed -n 's/.*"token_file": "\([^"]*\)".*/\1/p')
BEARER=$(cat "$TOKEN_FILE")
case "$out" in *"$BEARER"*) fail "approve printed the bearer" ;; esac
grep -q "$BEARER" "$ROOT/vault.requests.json" && fail "the register holds the bearer"
mode=$(mode_of "$TOKEN_FILE")
[ "$mode" = "-rw-------" ] || fail "the bearer file is $mode, not owner-only"
echo "ok: the bearer is only in its owner-only file" >>"$REPORT"

# A request names its decider: an admin may not decide what is the owner's.
WANT=ok run request file --kind membership --resource org:wisent-ai --action join \
  --agent request-test-agent --person request-test-colleague --decider owner --reason "join"
OWNERS=$(id_of)
WANT=refused run request approve "$OWNERS" --by "request-test-admin-$RUN" --until-revoked
has "is for owner to decide"
WANT=ok run request deny "$OWNERS" --by "$OWNER" --reason "not now"
has '"state": "denied"'

# The requesting agent withdraws its own request; nobody else who is not a
# decider can.
WANT=ok run request file --kind device --resource tama:hooks --action install \
  --agent request-test-agent --reason "install hooks"
DEVICE=$(id_of)
WANT=refused run request withdraw "$DEVICE" --by request-test-other-agent
WANT=ok run request withdraw "$DEVICE" --by request-test-agent
has '"state": "withdrawn"'

# A device request names no vault grant.
WANT=refused run request file --kind device --resource tama:hooks --action install \
  --agent request-test-agent --reason "x" --for-consumer request-test-reader
has "names no vault grant"

# Every step is journaled.
for op in access-requested access-approved access-denied access-withdrawn; do
  WANT=ok run audit list --op "$op"
  has "\"op\": \"$op\""
done
WANT=ok run audit verify
has '"intact": true'

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
