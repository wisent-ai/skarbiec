#!/usr/bin/env bash
# Real test of `skarbiec rotate --with ssh --hosts`, through the built binary on a
# vault of its own and a real SSH server: SKARBIEC_TEST_SSH_HOST names
# user@host, an account the tester can already reach with plain `ssh` and
# whose ~/.ssh/authorized_keys this test may change; it must be in the
# tester's known_hosts. SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written. Every line the test adds to
# authorized_keys carries this run's id and is removed at the end.
#
# A key made by ssh new is put on the host with the tester's own access.
# rotate --with ssh --hosts then leaves the host trusting the new key and not the
# old one, and the vault holds the new pair. Rotating again against the host
# and a second name no ssh can reach fails, leaves the vault's key as it was,
# and takes the never-stored key back off the host that took it.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_SSH_HOST=me@test-box tests/keygen/ssh_rotate_hosts.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
HOST=${SKARBIEC_TEST_SSH_HOST:?set SKARBIEC_TEST_SSH_HOST to user@host of an account you reach with ssh and whose authorized_keys this test may change}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/keygen/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "host: $HOST" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
COMMENT="skarbiec-test-$RUN"
cleanup() {
  ssh -o BatchMode=yes "$HOST" "f=~/.ssh/authorized_keys; grep -v -- '$COMMENT' \"\$f\" > \"\$f.clean\"; mv \"\$f.clean\" \"\$f\"" &>>"$REPORT" \
    || echo "cleanup: could not remove this run's lines from $HOST" >>"$REPORT"
  gpgconf --homedir "$GNUPGHOME" --kill all
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
# Whether the host's authorized_keys holds exactly this line.
trusted() {
  ssh -o BatchMode=yes "$HOST" "grep -qxF -- '$1' ~/.ssh/authorized_keys"
}

: >"$ROOT/stdin"
WANT=ok run init "hosts-owner-$RUN"
ITEM="hosts-key-$RUN"
WANT=ok run ssh new "$ITEM" --comment "$COMMENT"
FIRST="$(printf '%s' "$out" | jq -r .public_key)"
ssh -o BatchMode=yes "$HOST" "umask 077; mkdir -p ~/.ssh; printf '%s\n' '$FIRST' >> ~/.ssh/authorized_keys" || fail "could not put the first key on $HOST"

WANT=ok run rotate "$ITEM" --with ssh --hosts "$HOST"
# The private key must appear on neither stream.
case "$out$said" in *"PRIVATE KEY"*) fail "rotate printed a private key" ;; esac
SECOND="$(printf '%s' "$out" | jq -r .public_key)"
printf '%s' "$out" | jq -e --arg h "$HOST" '.ok and (.hosts | any(.host == $h and .retired_removed))' >/dev/null || fail "the answer does not say $HOST lost the retired line"
trusted "$SECOND" || fail "$HOST does not trust the new key"
if trusted "$FIRST"; then fail "$HOST still trusts the retired key"; fi
WANT=ok run get "$ITEM" --field public_key
[ "$out" = "$SECOND" ] || fail "the vault does not hold the key the host trusts"
echo "ok: the host trusts only the new key and the vault holds it" >>"$REPORT"

UNREACHABLE="nobody@unreachable-$$.invalid"
WANT=refused run rotate "$ITEM" --with ssh --hosts "$HOST,$UNREACHABLE"
case "$said" in *"$UNREACHABLE"*"taken back off every host"*) ;; *) fail "the refusal does not name the unreachable host and the rollback: $said" ;; esac
WANT=ok run get "$ITEM" --field public_key
[ "$out" = "$SECOND" ] || fail "a failed rotation changed the vault's key"
trusted "$SECOND" || fail "a failed rotation took the vault's key off $HOST"
LINES="$(ssh -o BatchMode=yes "$HOST" "grep -c -- '$COMMENT' ~/.ssh/authorized_keys")"
[ "$LINES" = "$(printf '%s\n' "$SECOND" | grep -c -- "$COMMENT")" ] || fail "$HOST kept a key the vault never took"
echo "ok: a host that fails leaves the vault and the other host as they were" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
