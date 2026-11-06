#!/usr/bin/env bash
# Real test of `skarbiec rotate --with ssh`, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written.
#
# A key made by ssh new, tagged and granted to a consumer, is rotated:
# the item's public key is the new one rotate printed, the private key
# derives that public key, the comment is kept, the retired public key is the
# old one, the old private key is still read at its saved version, and the
# tag and the grant are unchanged. A login item and an unknown id are refused.
# No private key is printed.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/keygen/ssh_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/keygen/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

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
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said" ;;
  esac
}
# A public key line without its comment: its type and its key.
bare() {
  read -r kind key _comment <<<"$1"
  printf '%s %s' "$kind" "$key"
}
# The public key a private key derives, as ssh-keygen -y prints it.
derived() {
  printf '%s\n' "$1" >"$ROOT/key"
  chmod go-rwx "$ROOT/key"
  bare "$(ssh-keygen -y -f "$ROOT/key")"
  rm -f "$ROOT/key"
}

: >"$ROOT/stdin"
WANT=ok run init "rotate-test-owner-$RUN"
ITEM="rotate-key-$RUN"
COMMENT="deploy@rotate-$RUN"
WANT=ok run ssh new "$ITEM" --comment "$COMMENT" --tags "$ITEM"
OLD_PUBLIC="$(printf '%s' "$out" | jq -r .public_key)"
CONSUMER="rotate-consumer-$RUN"
WANT=ok run grant issue "$CONSUMER" --capabilities "read:$ITEM#public_key" --until-revoked
WANT=ok run get "$ITEM" --field private_key
OLD_PRIVATE="$out"

WANT=ok run rotate "$ITEM" --with ssh
# The private key must appear on neither stream.
case "$out$said" in *"PRIVATE KEY"*) fail "rotate printed a private key" ;; esac
NEW_PUBLIC="$(printf '%s' "$out" | jq -r .public_key)"
[ "$(printf '%s' "$out" | jq -r .retired_public_key)" = "$OLD_PUBLIC" ] || fail "retired_public_key is not the old public key"
[ "$NEW_PUBLIC" != "$OLD_PUBLIC" ] || fail "the public key did not change"
case "$NEW_PUBLIC" in *" $COMMENT") ;; *) fail "the new key did not keep the comment: $NEW_PUBLIC" ;; esac
WANT=ok run get "$ITEM" --field public_key
[ "$out" = "$NEW_PUBLIC" ] || fail "the item does not hold the printed public key"
WANT=ok run get "$ITEM" --field private_key
[ "$(derived "$out")" = "$(bare "$NEW_PUBLIC")" ] || fail "the stored private key does not derive the new public key"
echo "ok: the item holds a fresh pair whose private key derives the printed public key, comment kept" >>"$REPORT"

STAMP="$("$BIN" history "$ITEM" </dev/null | jq -r '[.versions[] | select(.current | not)] | last | .at')"
WANT=ok run get "$ITEM" --at "$STAMP" --field private_key
[ "$out" = "$OLD_PRIVATE" ] || fail "the old private key is not kept at its saved version"
WANT=ok run tags
printf '%s' "$out" | jq -e --arg id "$ITEM" 'tostring | contains($id)' >/dev/null || fail "the item lost its tag"
"$BIN" grant list --item "$ITEM" </dev/null | jq -e --arg c "$CONSUMER" 'any(.consumer == $c)' >/dev/null || fail "the grant no longer reaches the item"
echo "ok: the old key stays in saved versions and the tag and grant are kept" >>"$REPORT"

jq -n '{schema:"skarbiec.item.v2",kind:"login",fields:{username:"me",password:"rotate-not-a-key"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "rotate-login-$RUN" --type login
: >"$ROOT/stdin"
WANT=refused run rotate "rotate-login-$RUN" --with ssh
names "not a key-pair"
WANT=refused run rotate "no-such-key-$RUN" --with ssh
names "no-such-key-$RUN"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
