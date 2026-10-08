#!/usr/bin/env bash
# Real test of `skarbiec agent-enrol <agent>`, through the real binary on a
# vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point
# into this checkout's target directory, so the operator's vault and keyring are
# never read or written. The keyring sits at a short path because gpg-agent's
# socket lives in it and a Unix socket path is limited in length.
#
# It creates the vault with `init`, enrols one agent and checks the persisted
# state: the answer names the item <agent>-agent-signing and the resource
# agent:<agent>, `route resolve agent:<agent>` answers from that item, and the
# item holds a generated agent_auth_secret that never appeared in the
# command's output. Then it checks the refusals: enrolling the same agent
# again, an agent name that is not one path component, and an agent whose
# item id is already taken by an unrelated item; after the refusals the vault
# lists exactly the items it listed before them. Every command and whether it
# succeeded go to the run's report.txt, with the output of the refusals; the
# generated secret is never written there.
#
# Usage: SKARBIEC=<binary> tests/access/agent_enrol.sh
#   SKARBIEC names the binary under test: a build (target/debug/skarbiec) or
#   the installed release; the report records which one and its version.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?SKARBIEC must name the skarbiec binary under test (a build such as target/debug/skarbiec, or the installed release)}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/access/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "version: $("$BIN" --version &>/dev/stdout)" >>"$REPORT"
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
# be refused (refused). Successful output is kept out of the report because a
# resolve or get answer may carry the secret. `&>/dev/stdout` joins both
# streams into the substitution's pipe and keeps the binary's own exit status;
# `|&` is not used because macOS ships bash 3.2, which does not have it.
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  if [ "$got" = ok ]; then
    printf '$ skarbiec %s\nresult: ok\n\n' "$*" >>"$REPORT"
  else
    printf '$ skarbiec %s\nresult: refused\noutput: %s\n\n' "$*" "$out" >>"$REPORT"
  fi
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
has() {
  case "$out" in
    *"$*"*) echo "ok: output names: $*" >>"$REPORT" ;;
    *) fail "expected output naming '$*', got: $out" ;;
  esac
}

: >"$ROOT/stdin"
WANT=ok run init "enrol-test-owner-$RUN"

AGENT="enrol-test-agent-$RUN"
WANT=ok run agent-enrol "$AGENT"
has "\"item\": \"$AGENT-agent-signing\""
has "\"resource\": \"agent:$AGENT\""
has '"created": true'
ENROL_OUTPUT="$out"

WANT=ok run get "$AGENT-agent-signing" --field agent_auth_secret
SECRET="$out"
[ -n "$SECRET" ] || fail "the enrolled item holds an empty agent_auth_secret"
case "$ENROL_OUTPUT" in
  *"$SECRET"*) fail "agent-enrol printed the generated secret" ;;
esac
echo "ok: agent_auth_secret is generated, stored and absent from agent-enrol's output" >>"$REPORT"

WANT=ok run get "$AGENT-agent-signing" --field id
[ "$out" = "$AGENT" ] || fail "the enrolled item's id field is '$out', not '$AGENT'"
echo "ok: the item's id field names the agent" >>"$REPORT"

WANT=ok run route resolve "agent:$AGENT"
has "$AGENT-agent-signing"

TAKEN="enrol-test-taken-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"enrol-test-user-%s","password":"enrol-test-password-%s"},"context":{}}' \
  "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set-json "$TAKEN-agent-signing" --type login
: >"$ROOT/stdin"

WANT=ok run list
BEFORE="$out"
has "$AGENT-agent-signing"

WANT=refused run agent-enrol "$AGENT"
has "already has a signing identity in item $AGENT-agent-signing"

WANT=refused run agent-enrol "enrol/test/$RUN"
has "agent name of letters, digits"

WANT=refused run agent-enrol "$TAKEN"
has "item $TAKEN-agent-signing already exists and is not $TAKEN's signing identity"

WANT=ok run list
[ "$out" = "$BEFORE" ] || fail "a refused agent-enrol changed the vault's items"
echo "ok: the refusals left the vault's items unchanged" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
