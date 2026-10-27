#!/usr/bin/env bash
# Real test of `skarbiec ci set github`, through the built binary on a
# vault of its own and a real GitHub repository the tester owns, named by
# SKARBIEC_TEST_GITHUB_REPO (owner/repo) with gh signed in on this machine.
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written; the secrets it sets carry this run's id and are deleted
# at the end.
#
# Without --yes nothing is set and gh secret list does not show the names.
# With --yes both secrets are set and gh secret list shows them; no answer
# carries a value. A repository that is not owner/repo, a binding to a
# missing item and another forge are refused, the missing item before any
# secret is set.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_GITHUB_REPO=me/sandbox tests/ci/actions_secrets.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
REPO=${SKARBIEC_TEST_GITHUB_REPO:?set SKARBIEC_TEST_GITHUB_REPO to owner/repo of a repository you own, where gh may set and delete secrets}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/ci/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "repository: $REPO" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
FIRST="SKARBIEC_TEST_A_$$"
SECOND="SKARBIEC_TEST_B_$$"
cleanup() {
  for name in "$FIRST" "$SECOND"; do
    gh secret delete "$name" --repo "$REPO" &>>"$REPORT" || echo "cleanup: $name was not set" >>"$REPORT"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
listed() {
  gh secret list --repo "$REPO" | cut -f1
}

: >"$ROOT/stdin"
WANT=ok run init "ci-owner-$RUN"
VALUE="ci-secret-$RUN"
jq -n --arg token "$VALUE" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "ci-token-$RUN" --type token
jq -n '{schema:"skarbiec.item.v2",kind:"login",fields:{username:"deploy",password:"ci-password"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "ci-login-$RUN" --type login
: >"$ROOT/stdin"
printf '%s=ci-token-%s:token\n%s=ci-login-%s:password\n' "$FIRST" "$RUN" "$SECOND" "$RUN" >"$ROOT/bindings"

WANT=ok run ci set github "$REPO" --env-from "$ROOT/bindings"
printf '%s' "$out" | jq -e '.applied == false and (.secrets | length == 2)' >/dev/null || fail "the preview did not name two secrets unapplied"
if listed | grep -qx "$FIRST"; then fail "the preview set $FIRST"; fi
echo "ok: without --yes nothing is set" >>"$REPORT"

WANT=ok run ci set github "$REPO" --env-from "$ROOT/bindings" --yes
case "$out" in *"$VALUE"*|*ci-password*) fail "the answer carried a value" ;; esac
printf '%s' "$out" | jq -e --arg first "$FIRST" --arg second "$SECOND" '.ok and (.set | index($first) != null and index($second) != null)' >/dev/null \
  || fail "the answer does not name both secrets set"
listed | grep -qx "$FIRST" || fail "gh secret list does not show $FIRST"
listed | grep -qx "$SECOND" || fail "gh secret list does not show $SECOND"
echo "ok: --yes sets every secret the bindings name, as GitHub lists them" >>"$REPORT"

WANT=refused run ci set github not-a-repo --env-from "$ROOT/bindings"
names "is not owner/repo"
WANT=refused run ci set gitlab "$REPO" --env-from "$ROOT/bindings"
names "gitlab is neither"
printf 'SKARBIEC_TEST_MISSING_%s=no-such-item-%s:token\n' "$$" "$RUN" >"$ROOT/missing"
WANT=refused run ci set github "$REPO" --env-from "$ROOT/missing" --yes
names "no-such-item-$RUN"
if listed | grep -qx "SKARBIEC_TEST_MISSING_$$"; then fail "a secret was set for a missing item"; fi
WANT=refused run ci github "$REPO" --env-from "$ROOT/bindings"
names "usage: ci set|keep"
WANT=refused run ci-secrets github "$REPO" --env-from "$ROOT/bindings"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
