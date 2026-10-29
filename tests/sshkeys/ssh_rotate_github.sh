#!/usr/bin/env bash
# Real test of `skarbiec rotate --with ssh --github`, through the built binary on a
# vault of its own and real GitHub: SKARBIEC_TEST_GITHUB_REPO names a
# repository, owner/name, kept for this test, which the gh CLI on PATH is
# signed in to administer. The test adds the item's key as a deploy key,
# rotates, and deletes every deploy key it made. SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# After rotate --with ssh the repository holds the new key as a read-only deploy
# key with the old title and no longer the old one, and the item holds the
# new pair. A repository without the old key refuses the rotation and the
# vault keeps the old pair; --github naming no owner/name is refused.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_GITHUB_REPO=owner/name tests/sshkeys/ssh_rotate_github.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
REPO=${SKARBIEC_TEST_GITHUB_REPO:?set SKARBIEC_TEST_GITHUB_REPO to an owner/name repository this test may add and delete deploy keys on}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/sshkeys/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "repository: $REPO" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
TITLE="skarbiec-test-$RUN"
cleanup() {
  for id in $(gh api "repos/$REPO/keys" --jq ".[] | select(.title == \"$TITLE\") | .id"); do
    gh api -X DELETE "repos/$REPO/keys/$id" &>>"$REPORT" || echo "cleanup: could not delete deploy key $id" >>"$REPORT"
  done
  gpgconf --homedir "$GNUPGHOME" --kill all
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" </dev/null 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said; output: $out" ;;
  esac
}
deploy_keys() {
  gh api "repos/$REPO/keys" --jq ".[] | select(.title == \"$TITLE\") | \"\(.read_only) \(.key)\""
}

WANT=ok run init "github-owner-$RUN"
KEY="deploy-$RUN"
WANT=ok run ssh new "$KEY"
OLD="$(printf '%s' "$out" | jq -r .public_key)"

WANT=refused run rotate "$KEY" --with ssh --github "not-a-repository"
names "is not a GitHub repository as owner/name"
WANT=refused run rotate "$KEY" --with ssh --github "$REPO"
names "has no deploy key matching the item's public key"
WANT=ok run get "$KEY" --field public_key
[ "$out" = "$OLD" ] || fail "a refused rotation changed the item's key"

gh api -X POST "repos/$REPO/keys" -f title="$TITLE" -f key="$OLD" -F read_only=true &>>"$REPORT"
WANT=ok run rotate "$KEY" --with ssh --github "$REPO"
NEW="$(printf '%s' "$out" | jq -r .public_key)"
[ "$(printf '%s' "$out" | jq -r '.deploy_keys[0].retired_removed')" = "true" ] || fail "the old deploy key was not deleted: $out"
[ "$(printf '%s' "$out" | jq -r '.deploy_keys[0].forge')" = "github" ] || fail "the deploy key row does not name its forge: $out"
KEYS="$(deploy_keys)"
printf '%s' "$KEYS" | grep -q "^true $(printf '%s' "$NEW" | cut -d' ' -f1-2)" || fail "the repository does not hold the new key read-only: $KEYS"
if printf '%s' "$KEYS" | grep -q "$(printf '%s' "$OLD" | cut -d' ' -f2)"; then fail "the repository still holds the old key: $KEYS"; fi
echo "ok: the repository holds the new key read-only, with the old title, and no longer the old one" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
