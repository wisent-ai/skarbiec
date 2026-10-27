#!/bin/bash
# Real test of the `skarbiec recovery`, `emergency`, `donation` and
# `recipient` groups
# through the built binary, on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
# The keyring sits at a short path because gpg-agent's socket lives in it and
# a Unix socket path is limited in length.
#
# It creates the vault with `init`, then for each group checks that a call
# with no subcommand, an unknown subcommand and the retired hyphenated
# spelling fail with the usage refusal that names them.
# It reads `recovery status`; refuses an emergency grant for an
# unknown recipient and one whose moment is not a UTC stamp, records one for
# the owner whose moment has passed, lists it pending, refuses to revoke it
# while pending, activates it, refuses to cancel it once activated, revokes
# it and lists it gone; refuses to cancel a grant nobody holds; lists the empty
# donation inbox and checks that accepting and rejecting a donation nobody
# sent are refused; lists the owner as a recipient, exports its public key,
# adds a member, refuses to remove it without --yes, removes it with --yes
# and lists it gone. Every command, whether it succeeded, and its output go to
# the run's report.txt.
#
# Usage: SKARBIEC=<path to the built binary> tests/vault/groups.sh
set -eu -o pipefail
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?SKARBIEC names the built skarbiec binary this test runs, for example target/debug/skarbiec after cargo build}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/vault-groups/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all &>/dev/null; rm -rf "$KEYRING"' EXIT

# One call: stdout lands in $out, stderr in $err, and whether it succeeded in
# $outcome (succeeded or failed). stderr reaches the substitution through
# &>/dev/stdout before stdout moves to the file, so the binary's own exit
# status decides the outcome; `|&` is not used because macOS ships bash 3.2,
# which does not have it.
call() {
  outcome=succeeded
  err=$("$BIN" "$@" </dev/null &>/dev/stdout >"$ROOT/stdout") || outcome=failed
  out=$(cat "$ROOT/stdout")
  printf '$ skarbiec %s\noutcome: %s\nstdout: %s\nstderr: %s\n\n' "$*" "$outcome" "$out" "$err" >>"$REPORT"
}
fail() {
  echo "FAIL: $1" | tee -a "$REPORT" >/dev/stderr
  false
}
ok() {
  call "$@"
  [ "$outcome" = succeeded ] || fail "skarbiec $* failed: $err"
}
fails() {
  call "$@"
  [ "$outcome" = failed ] || fail "skarbiec $* succeeded, a refusal was expected: $out"
}
check() {
  [ "$2" = "$3" ] || fail "$1: got '$2', expected '$3'"
  echo "ok: $1 = $2" >>"$REPORT"
}
refused() {
  case "$err$out" in
    *"$1"*) echo "ok: refused with: $1" >>"$REPORT" ;;
    *) fail "expected a refusal containing '$1', got: $err $out" ;;
  esac
}

OWNER="groups-test-owner-$RUN"
ok init "$OWNER"

fails recovery
refused "recovery needs a subcommand"
fails recovery sideways
refused "unknown recovery command: sideways"
fails recovery-status
refused "unknown command: recovery-status"
ok recovery status
check "recovery status counts items" "$(echo "$out" | jq -r 'has("item_count")')" "true"

fails emergency
refused "emergency needs a subcommand"
fails emergency sideways
refused "unknown emergency command: sideways"
fails emergency-list
refused "unknown command: emergency-list"
PASSED_MOMENT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ok emergency grant "nobody-$RUN" --activate-after "$PASSED_MOMENT"
check "an unknown grantee is blocked" "$(echo "$out" | jq -r '.reason')" "unknown_recipient"
fails emergency grant "$OWNER" --activate-after tomorrow
refused "--activate-after tomorrow is not a UTC time of the form"
ok emergency grant "$OWNER" --activate-after "$PASSED_MOMENT"
ok emergency list
check "the grant is pending" "$(echo "$out" | jq -r --arg g "$OWNER" '.[$g].status')" "pending"
fails emergency revoke "$OWNER"
refused "is pending, so it has shared nothing to revoke"
ok emergency activate "$OWNER"
check "a due grant is activated" "$(echo "$out" | jq -r '.ok')" "true"
fails emergency cancel "$OWNER"
refused "is already activated, and cancel withdraws only a grant that is still waiting"
ok emergency revoke "$OWNER"
check "the revocation names the grantee" "$(echo "$out" | jq -r '.grantee')" "$OWNER"
ok emergency list
check "the revoked grant is gone" "$(echo "$out" | jq --arg g "$OWNER" 'has($g)')" "false"
fails emergency cancel "$OWNER"
refused "no emergency grant for $OWNER"

fails donation
refused "donation needs list, accept or reject"
fails donation sideways
refused "unknown donation command: sideways"
fails donations
refused "unknown command: donations"
ok donation list
check "the inbox is empty" "$(echo "$out" | jq -r '. == []')" "true"
fails donation accept "missing-$RUN"
refused "no pending donation: missing-$RUN"
fails donation reject "missing-$RUN"
refused "no pending donation: missing-$RUN"

fails recipient
refused "recipient needs a subcommand"
fails recipient sideways
refused "unknown recipient command: sideways"
fails users
refused "unknown command: users"
ok recipient list
check "the owner is a recipient" "$(echo "$out" | jq -r --arg u "$OWNER" '.[$u].role')" "owner"
ok recipient export "$OWNER"
check "the exported key is a public key" "$(echo "$out" | jq -r '.public_key | startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")')" "true"
fails recipient export "nobody-$RUN"
refused "unknown recipient: nobody-$RUN"
MEMBER="groups-test-member-$RUN"
ok recipient add "$MEMBER"
check "the member is registered as a member" "$(echo "$out" | jq -r '.role')" "member"
fails recipient remove "$MEMBER"
refused "nothing was changed"
ok recipient list
check "a refused removal keeps the member" "$(echo "$out" | jq --arg u "$MEMBER" 'has($u)')" "true"
ok recipient remove "$MEMBER" --yes
ok recipient list
check "the removed member is gone" "$(echo "$out" | jq --arg u "$MEMBER" 'has($u)')" "false"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
