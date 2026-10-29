#!/usr/bin/env bash
# Real test of loading every key a tag carries into an agent, `skarbiec
# ssh-add --tag <tag> --agent <socket>`, through the built binary, the real
# ssh-keygen and a real ssh-agent of its own, on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault, keyring and agent are
# never read or written.
#
# Two keys made with the tag and a note carrying it too: both keys are named
# under added and the agent lists both, by the fingerprints of the public
# keys ssh new printed; the note is named under refused with why, and the
# answer is then not ok. A tag no item carries, and neither an id nor --tag,
# are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/keygen/tagged_agent.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/keygen/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
# A socket path has a short limit, so the agent's lives beside the keyring.
AGENT="$PWD/target/a$$.sock"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
eval "$(ssh-agent -a "$AGENT")" >/dev/null
trap 'ssh-agent -k >/dev/null; gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING" "$AGENT"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" </dev/null 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said" ;;
  esac
}
fingerprint() {
  printf '%s\n' "$1" | ssh-keygen -lf - | cut -d ' ' -f2
}

TAG="deploy-$RUN"
WANT=ok run init "agent-owner-$RUN"
WANT=ok run ssh new "agent-one-$RUN" --tags "$TAG"
ONE="$(fingerprint "$(printf '%s' "$out" | jq -r .public_key)")"
WANT=ok run ssh new "agent-two-$RUN" --tags "$TAG"
TWO="$(fingerprint "$(printf '%s' "$out" | jq -r .public_key)")"
printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"no key"},"context":{}}' >"$ROOT/note.json"
"$BIN" set "agent-note-$RUN" --type note --tags "$TAG" <"$ROOT/note.json" >>"$REPORT"

# One item holds no key, so the answer is not ok; it is read either way.
if out=$("$BIN" ssh add --tag "$TAG" --agent "$AGENT" </dev/null 2>"$ROOT/said"); then got=ok; else got=refused; fi
said=$(cat "$ROOT/said")
printf '$ skarbiec ssh add --tag %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$TAG" "$got" "$out" "$said" >>"$REPORT"
printf '%s' "$out" | jq -e --arg one "agent-one-$RUN" --arg two "agent-two-$RUN" \
  '([.added[].item] | index($one) != null and index($two) != null) and .ok == false' >/dev/null \
  || fail "both tagged keys were not named as added, or the answer was ok with a refusal"
printf '%s' "$out" | jq -e --arg note "agent-note-$RUN" '.refused[] | select(.item == $note) | .error | contains("holds no private_key")' >/dev/null \
  || fail "the tagged note was not refused naming its missing key"
LOADED="$(SSH_AUTH_SOCK="$AGENT" ssh-add -l)"
case "$LOADED" in *"$ONE"*) ;; *) fail "the agent does not hold the first key: $LOADED" ;; esac
case "$LOADED" in *"$TWO"*) ;; *) fail "the agent does not hold the second key: $LOADED" ;; esac
# The private key must appear on neither stream.
case "$out$said" in *"PRIVATE KEY"*) fail "the answer carried a private key" ;; esac
echo "ok: both tagged keys are in the agent; the note is refused with why" >>"$REPORT"

WANT=refused run ssh add --tag "none-$RUN" --agent "$AGENT"
names "no live item carries the tag none-$RUN"
WANT=refused run ssh add --agent "$AGENT"
names "usage: ssh add"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
