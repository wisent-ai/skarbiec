#!/usr/bin/env bash
# Real test of `skarbiec signing`, through the built binary on a vault of its
# own and real git and ssh-agent: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE,
# GNUPGHOME and GIT_CONFIG_GLOBAL point into this checkout's target
# directory, and the test starts an ssh-agent of its own and stops it, so the
# operator's vault, keyring, git configuration and agent are never touched.
#
# After setup and ssh-add a commit in a fresh repository is signed by the
# vault key, as git verifies it against an allowed-signers file naming that
# key; status names the item and that the agent holds the key; rotate --with ssh
# moves the signing key; unset removes it. A note is refused as a signing key.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/sshkeys/git_sign.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/sshkeys/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export GIT_CONFIG_GLOBAL="$ROOT/gitconfig"
eval "$(ssh-agent -s -a "$ROOT/agent.sock")" >/dev/null
trap 'ssh-agent -k >/dev/null; gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

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
signed_commit() {
  git -C "$ROOT/repo" -c user.name=test -c user.email="git-sign-$$@example.com" commit -q --allow-empty -m "$*" &>>"$REPORT"
}

WANT=ok run init "git-sign-owner-$RUN"
KEY="signing-$RUN"
WANT=ok run ssh new "$KEY"
PUBLIC="$(printf '%s' "$out" | jq -r .public_key)"

WANT=ok run signing setup "$KEY"
[ "$(printf '%s' "$out" | jq -r .agent_holds_it)" = "false" ] || fail "the agent held the key before ssh add: $out"
WANT=ok run ssh add "$KEY"
WANT=ok run signing status
[ "$(printf '%s' "$out" | jq -r .item)" = "$KEY" ] || fail "status does not name the item keeping the key: $out"
[ "$(printf '%s' "$out" | jq -r .agent_holds_it)" = "true" ] || fail "status does not see the key in the agent: $out"

git init -q "$ROOT/repo"
signed_commit "first"
printf 'git-sign-%s@example.com %s\n' "$$" "$PUBLIC" >"$ROOT/allowed"
git -C "$ROOT/repo" -c gpg.ssh.allowedSignersFile="$ROOT/allowed" verify-commit HEAD &>>"$REPORT" || fail "git does not verify the commit as signed by the vault key"
echo "ok: a commit is signed by the vault key through the agent" >>"$REPORT"

WANT=ok run rotate "$KEY" --with ssh
NEW="$(printf '%s' "$out" | jq -r .public_key)"
[ "$(printf '%s' "$out" | jq -r .git_signing.moved)" = "true" ] || fail "rotate did not move the signing key: $out"
grep -q "$(printf '%s' "$NEW" | cut -d' ' -f2)" "$GIT_CONFIG_GLOBAL" || fail "git's signing key is not the rotated one"
echo "ok: rotate --with ssh moves git's signing key" >>"$REPORT"

jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a key"},context:{}}' >"$ROOT/note.json"
"$BIN" set "note-$RUN" --type note <"$ROOT/note.json" &>>"$REPORT"
WANT=refused run signing setup "note-$RUN"
names "signing signs with the SSH key a key-pair item keeps"

WANT=ok run signing unset
if git config --global user.signingkey &>/dev/null; then fail "unset left user.signingkey"; fi
WANT=refused run signing unset
names "signs with no key set by signing setup"
WANT=refused run git-sign status
echo "ok: unset removes the settings and a second unset is refused" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
