#!/usr/bin/env bash
# Real test of `skarbiec hook` and `scan --refuse`, through the built
# binary on a vault of its own and a git repository made here:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# With the hook installed, git refuses a commit adding a file that holds a
# token the vault keeps, naming the file and the item, and the commit is not
# made; a commit of a clean file goes through. status says the hook is
# Skarbiec's; a second install without --replace is refused; uninstall
# removes it, after which the same commit goes through, and scan --history
# then names that commit and file as holding the token. A hook another
# program wrote is reported as present but not installed, and uninstall
# leaves it as it is.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/githook/commit_guard.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/githook/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
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
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out; stderr: $said" ;;
  esac
}
commit() {
  if out=$(git -C "$REPO" -c user.name=skarbiec-test -c user.email=test@example.com commit -m "$1" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ git commit -m %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$1" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "git commit $1 was $got, expected $WANT: $out; stderr: $said"
}

: >"$ROOT/stdin"
WANT=ok run init "githook-owner-$RUN"
TOKEN="githook-secret-$RUN"
ITEM="githook-token-$RUN"
jq -n --arg token "$TOKEN" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type token
: >"$ROOT/stdin"

REPO="$ROOT/repo"
git init -q "$REPO"
WANT=ok run hook status "$REPO"
printf '%s' "$out" | jq -e '.present == false and .installed == false' >/dev/null || fail "a fresh repository was reported with a hook"
WANT=ok run hook install "$REPO" --fields token
HOOK="$(printf '%s' "$out" | jq -r .hook)"
[ -x "$HOOK" ] || fail "the hook $HOOK is not executable"
WANT=ok run hook status "$REPO"
printf '%s' "$out" | jq -e '.present and .installed' >/dev/null || fail "status does not report the installed hook"

printf 'API_TOKEN=%s\n' "$TOKEN" >"$REPO/app.env"
git -C "$REPO" add app.env
WANT=refused commit "leak"
# git hands everything a pre-commit hook prints to its own standard error.
case "$said" in *app.env*"$ITEM"*) ;; *) fail "the refused commit does not name app.env and $ITEM: $out; stderr: $said" ;; esac
case "$out$said" in *"$TOKEN"*) fail "the refusal printed the token" ;; esac
if git -C "$REPO" rev-parse -q --verify HEAD >/dev/null; then fail "the refused commit was made"; fi
echo "ok: the hook refuses a commit holding a vault value, naming the file and item" >>"$REPORT"

git -C "$REPO" rm -q --cached app.env
printf 'nothing secret\n' >"$REPO/README"
git -C "$REPO" add README
WANT=ok commit "clean"
echo "ok: a clean commit goes through" >>"$REPORT"

WANT=refused run hook install "$REPO" --fields token
names "add --replace"
WANT=ok run hook uninstall "$REPO"
[ ! -e "$HOOK" ] || fail "uninstall left the hook"
git -C "$REPO" add app.env
WANT=ok commit "after uninstall"
echo "ok: after uninstall the hook no longer stops commits" >>"$REPORT"

# The token is now in history: scan --history names that commit and file, the
# clean commit before it holds none, and no value is printed.
LEAKED="$(git -C "$REPO" rev-parse HEAD)"
CLEAN="$(git -C "$REPO" rev-parse HEAD~)"
WANT=ok run scan "$REPO" --history --fields token
case "$out$said" in *"$TOKEN"*) fail "scan --history printed the token" ;; esac
printf '%s' "$out" | jq -e --arg commit "$LEAKED" --arg id "$ITEM" \
  '.ok == false and (.found | any(.commit == $commit and .file == "app.env" and .item == $id and .field == "token"))' >/dev/null \
  || fail "scan --history did not name the commit that added the token"
printf '%s' "$out" | jq -e --arg commit "$CLEAN" '.found | all(.commit != $commit)' >/dev/null || fail "scan --history named the clean commit"
echo "ok: scan --history names the commit and file that put a vault value in history" >>"$REPORT"
WANT=refused run scan "$ROOT/not-a-repo" --history --fields token
names "git log could not read"

printf '#!/bin/sh\n# another program\n' >"$HOOK"
WANT=ok run hook status "$REPO"
printf '%s' "$out" | jq -e '.present and (.installed | not)' >/dev/null || fail "another program's hook was reported as Skarbiec's"
WANT=refused run hook uninstall "$REPO"
names "was not written by skarbiec hook install"
[ -e "$HOOK" ] || fail "uninstall removed another program's hook"
WANT=refused run hook status "$ROOT/not-a-repo"
names "is not a git repository"
WANT=refused run hook install "$REPO"
names "usage: hook"
WANT=refused run git-hook status "$REPO"
names "unknown command: git-hook"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
