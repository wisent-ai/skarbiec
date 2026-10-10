#!/usr/bin/env bash
# Real test of `skarbiec policy check|set|get|unset` through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written.
#
# It creates the vault, checks a candidate while no rule is set (passes, the
# rule reported unconfigured), sets min_generated_length to the length of one
# candidate, then checks a shorter candidate (fails) and that candidate itself
# (passes) — each read from standard input. The refusals: a candidate given as
# an argument and an empty standard input are refused naming standard input,
# the retired policy-check-length is no command, and the policy group refuses a
# missing or unknown subcommand. The withdrawn hyphenated policy-get is
# refused as an unknown command.
# Every command and whether
# it succeeded go to the run's report.txt; a candidate is never written there.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run tests/policy/check.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/policy/$RUN"
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

# Runs one command with $ROOT/stdin on its standard input, standard output and
# standard error together in $out; WANT says whether it had to succeed (ok) or
# be refused (refused). Outputs of refusals go to the report; a refusal never
# repeats the candidate, which never reaches argv.
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then status=$?; got=ok; else status=$?; got=refused; fi
  if [ "$got" = ok ]; then
    printf '$ skarbiec %s\nresult: ok\n\n' "$*" >>"$REPORT"
  else
    printf '$ skarbiec %s\nresult: refused\noutput: %s\n\n' "$*" "$out" >>"$REPORT"
  fi
  printf 'exit: %s\n' "$status" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT"
}
says() {
  case "$out" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in the answer" ;;
  esac
}
verdict() {
  printf '%s' "$out" | jq -e --argjson expected "$1" '.ok == $expected' >/dev/null \
    || fail "$2: the top-level verdict was not ok=$1"
  echo "ok: $2" >>"$REPORT"
}
actual_length() {
  printf '%s' "$out" | jq -e --argjson expected "$1" \
    'any(.rules[]; .key == "min_generated_length" and .actual == $expected)' >/dev/null \
    || fail "policy check did not report the exact candidate length"
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

: >"$ROOT/stdin"
WANT=ok run init "policy-test-owner-$RUN"

LONG="policy-test-candidate-$RUN"
SHORT="${LONG%-*}"
printf '%s' "$LONG" >"$ROOT/stdin"
WANT=ok run policy check
says '"configured": false' "with no rule set the rule is reported unconfigured"
verdict true "with no rule set a candidate passes"

: >"$ROOT/stdin"
WANT=ok run policy set min_generated_length "${#LONG}"
WANT=ok run policy get
says "\"min_generated_length\": ${#LONG}" "policy get reads the rule policy set wrote"
WANT=refused run policy-get
says "unknown command: policy-get" "the withdrawn policy-get is refused"
WANT=refused run policy
says "needs a subcommand" "the policy group without a subcommand is refused"
WANT=refused run policy frobnicate
says "unknown policy command" "an unknown policy subcommand is refused"

printf '%s\n' "$SHORT" >"$ROOT/stdin"
WANT=ok run policy check
verdict false "a candidate shorter than min_generated_length fails"
case "$out" in *"$SHORT"*) fail "policy check repeated the candidate" ;; esac

printf '%s\n' "$LONG" >"$ROOT/stdin"
WANT=ok run policy check
verdict true "a candidate of exactly min_generated_length passes, its trailing newline not counted"
actual_length "${#LONG}"
printf '%s\r\n' "$LONG" >"$ROOT/stdin"
WANT=ok run policy check
actual_length "${#LONG}"
candidate="$LONG"$'\n'
printf '%s\n' "$candidate" >"$ROOT/stdin"
WANT=ok run policy check
actual_length "${#candidate}"
candidate="$LONG "
printf '%s\r\n' "$candidate" >"$ROOT/stdin"
WANT=ok run policy check
actual_length "${#candidate}"
case "$out" in *"$LONG"*) fail "policy check repeated the candidate" ;; esac

: >"$ROOT/stdin"
WANT=refused run policy check "argument-candidate-$RUN"
says "standard input" "a candidate given as an argument is refused naming standard input"
ARGUMENT_STATUS=$status
WANT=refused run policy check
says "the one it read was empty" "an empty standard input is refused"
[ "$status" != "$ARGUMENT_STATUS" ] \
  || fail "a malformed invocation must not share the empty-input refusal exit status"
WANT=refused run policy-check-length "argument-candidate-$RUN"

: >"$ROOT/stdin"
WANT=ok run policy unset min_generated_length
says '"removed": true' "withdrawing a configured rule reports its removal"
WANT=ok run policy get
case "$out" in
  *'"min_generated_length"'*) fail "the withdrawn policy rule remained persisted" ;;
esac
printf '%s\n' "$SHORT" >"$ROOT/stdin"
WANT=ok run policy check
says '"configured": false' "the withdrawn rule is reported unconfigured"
verdict true "the previously rejected candidate passes after withdrawal"

cp "$SKARBIEC_VAULT_FILE" "$ROOT/vault-before-repeat.json"
cp "$SKARBIEC_AUDIT_FILE" "$ROOT/audit-before-repeat.jsonl"
: >"$ROOT/stdin"
WANT=ok run policy unset min_generated_length
says '"removed": false' "repeated withdrawal reports an already absent rule"
cmp "$SKARBIEC_VAULT_FILE" "$ROOT/vault-before-repeat.json" \
  || fail "repeated withdrawal rewrote the vault"
cmp "$SKARBIEC_AUDIT_FILE" "$ROOT/audit-before-repeat.jsonl" \
  || fail "repeated withdrawal appended an audit mutation"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
