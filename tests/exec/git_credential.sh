#!/usr/bin/env bash
# Real test of git signing in with the vault, `skarbiec helper ... git`,
# through the built binary and the real git, on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, and GIT_CONFIG_GLOBAL names a git
# configuration file there, so the operator's vault, keyring and git
# configuration are never read or written.
#
# setup <host> writes git's per-site helper naming this binary; then `git
# credential fill`, as git itself does before a push, answers the login's
# username and password from the vault, and the journal names the item but
# not the value. A request over plain http is refused, and unset removes the
# setting. A host that is not one is refused. import moves a sign-in git's
# store helper left in ~/.git-credentials into a new login, sets the host up
# and takes only that line out; several sign-ins for a host without
# --username are refused naming each.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/exec/git_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/exec/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export GIT_CONFIG_GLOBAL="$ROOT/gitconfig"
export GIT_TERMINAL_PROMPT=false
: >"$GIT_CONFIG_GLOBAL"
export HOME="$ROOT/home"
export XDG_CONFIG_HOME="$ROOT/home/.config"
mkdir -p "$HOME"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

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

HOST="forge-$RUN.example"
TOKEN="git-token-$RUN"
: >"$ROOT/stdin"
WANT=ok run init "git-owner-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"octo-%s","password":"%s"},"context":{"domains":["%s"]}}' "$RUN" "$TOKEN" "$HOST" >"$ROOT/stdin"
WANT=ok run set "forge-$RUN" --type login
: >"$ROOT/stdin"

WANT=ok run helper setup git "$HOST"
[ "$(git config --global --get "credential.https://$HOST.helper")" = "!$BIN helper answer git" ] \
  || fail "setup did not name this binary as git's helper for $HOST"

printf 'protocol=https\nhost=%s\n\n' "$HOST" | git credential fill >"$ROOT/filled"
grep -qx "username=octo-$RUN" "$ROOT/filled" || fail "git was not given the login's username"
grep -qx "password=$TOKEN" "$ROOT/filled" || fail "git was not given the login's token"
grep -q '"git-credential"' "$SKARBIEC_AUDIT_FILE" || fail "no git-credential journal record"
if grep -q "$TOKEN" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds the token"; fi
echo "ok: git credential fill answers the login from the vault; the journal holds no value" >>"$REPORT"

printf 'protocol=http\nhost=%s\n\n' "$HOST" >"$ROOT/stdin"
WANT=refused run helper answer git get
names "skarbiec answers only https"
: >"$ROOT/stdin"

WANT=ok run helper unset git "$HOST"
if git config --global --get "credential.https://$HOST.helper"; then fail "unset left git's helper for $HOST"; fi
WANT=refused run helper setup git "not a host"
names "is not a host as git names one"

STORED="stored-$RUN.example.com"
printf 'https://ci-%s:first%%40%s@%s\nhttps://bot-%s:second-%s@%s\nhttps://other:kept-%s@other-%s.example.com\n' \
  "$RUN" "$RUN" "$STORED" "$RUN" "$RUN" "$STORED" "$RUN" "$RUN" >"$HOME/.git-credentials"
WANT=refused run helper import git "stored-$RUN" "$STORED"
names "name one with --username"
WANT=ok run helper import git "stored-$RUN" "$STORED" --username "ci-$RUN"
case "$out" in *"first@$RUN"*) fail "import printed the password" ;; esac
if grep -q "ci-$RUN" "$HOME/.git-credentials"; then fail "import left the imported line in the store"; fi
grep -q "bot-$RUN" "$HOME/.git-credentials" || fail "import removed another user's line"
grep -q "other-$RUN.example.com" "$HOME/.git-credentials" || fail "import removed another host's line"
printf 'protocol=https\nhost=%s\nusername=ci-%s\n\n' "$STORED" "$RUN" | git credential fill >"$ROOT/stored"
grep -qx "password=first@$RUN" "$ROOT/stored" || fail "git was not given the imported, decoded password from the vault"
echo "ok: import moves one stored sign-in into the vault, decoded, and git reads it from there" >>"$REPORT"

WANT=ok run helper list
printf '%s' "$out" | jq -e '.tools | any(.tool == "git" and (.usage | contains("helper import git <id> <host>")))' >/dev/null \
  || fail "helper list does not name git with its usage line: $out"
WANT=refused run helper status nowhere
names "nowhere is not a tool skarbiec answers for"
echo "ok: helper list names git with its forms, and status of an unknown tool is refused naming the tools" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
