#!/usr/bin/env bash
# Real test of which vault a bare `skarbiec` opens on a machine Stado routes
# to the vault owner. With secrets.skarbiec.url declared and no
# secrets.skarbiec.vault_file, the default file
# ~/.local/share/skarbiec/skarbiec.vault.json is a leftover copy the owner
# never reads: `init` must not create it, and a command that opens the vault
# here rather than asking the owner (`duplicates`, `delete`) must neither read
# nor write it. A vault named with SKARBIEC_VAULT_FILE is still opened, a vault
# Stado declares here is still opened, a machine Stado says nothing about
# still falls back to the default file, and a Stado config that is not JSON is
# refused naming it instead of choosing a vault.
#
# Everything runs through the built binary in an isolated HOME, keyring,
# vault and audit journal under this checkout's target directory, so the
# operator's vault, keyring and Stado config are never read or written. The
# keyring sits at a short path because gpg-agent's socket lives in it and a
# Unix socket path is limited in length. Every command, its exit status and
# whether it succeeded go to the run's report.txt, with its output for the
# refusals; a stored value is never written there.
#
# Supply SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION, then run
# tests/selection/unchosen_copy.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
SOURCE_REVISION=${SKARBIEC_TEST_SOURCE_REVISION:?set the exact committed source revision under qualification}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/selection/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home/.config/stado" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
export HOME="$ROOT/home"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
unset STADO_CONFIG SKARBIEC_VAULT_FILE
CONFIG="$HOME/.config/stado/config.json"
COPY="$HOME/.local/share/skarbiec/skarbiec.vault.json"
OWN="$ROOT/own.vault.json"
DECLARED="$ROOT/declared.vault.json"
ROUTE="stado://service/skarbiec?consumer=vault-test-$RUN"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

# Runs one command with $ROOT/stdin on its standard input, standard output and
# standard error together in $out; WANT says whether it had to succeed (ok) or
# be refused (refused). VAULT, when nonempty, is passed as SKARBIEC_VAULT_FILE.
run() {
  if env ${VAULT:+SKARBIEC_VAULT_FILE="$VAULT"} "$BIN" "$@" <"$ROOT/stdin" &>"$ROOT/out"; then
    status=$?; got=ok
  else
    status=$?; got=refused
  fi
  out=$(cat "$ROOT/out")
  printf '$ %sskarbiec %s\nexit: %s\nresult: %s\n' "${VAULT:+SKARBIEC_VAULT_FILE=$VAULT }" "$*" "$status" "$got" >>"$REPORT"
  if [ "$got" = refused ]; then printf 'output: %s\n' "$out" >>"$REPORT"; fi
  printf '\n' >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
config() {
  printf '%s\n' "$1" >"$CONFIG"
  printf 'stado config: %s\n\n' "$1" >>"$REPORT"
}

[ "$(git rev-parse HEAD)" = "$SOURCE_REVISION" ] || fail "source revision differs from the candidate declaration"
git diff --quiet || fail "source has uncommitted tracked changes"
git diff --cached --quiet || fail "source has staged uncommitted changes"

ITEM="vault-test-login-$RUN"
SECRET="vault-test-secret-$RUN"
item_json() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"vault-test-user-%s","password":"%s"},"context":{}}' \
    "$RUN" "$SECRET" >"$ROOT/stdin"
}

# A client machine: Stado routes it to the owner and declares no vault here.
config "{\"secrets\":{\"skarbiec\":{\"url\":\"$ROUTE\"}}}"
: >"$ROOT/stdin"
VAULT= WANT=refused run init "vault-test-owner-$RUN"
names "this machine holds no Skarbiec vault"
names "$ROUTE"
names "$COPY"
[ ! -e "$COPY" ] || fail "a refused init still created $COPY"
echo "ok: the refused init created no file at $COPY" >>"$REPORT"

# A vault named explicitly is the caller's own and is opened.
VAULT="$OWN" WANT=ok run init "vault-test-owner-$RUN"
item_json
VAULT="$OWN" WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"
VAULT="$OWN" WANT=ok run get "$ITEM" --field password
[ "$out" = "$SECRET" ] || fail "an explicitly named vault did not return the stored value"
echo "ok: an explicitly named vault was written and read back" >>"$REPORT"

# A leftover copy at the fallback path is neither read nor written by a
# command that opens the vault here instead of asking the owner.
mkdir -p "$(dirname "$COPY")"
cp "$OWN" "$COPY"
cp "$COPY" "$ROOT/copy.before"
VAULT= WANT=refused run duplicates
names "this machine holds no Skarbiec vault"
names "is neither read nor written"
VAULT= WANT=refused run delete "$ITEM"
names "is neither read nor written"
cmp -s "$COPY" "$ROOT/copy.before" || fail "a refused command changed $COPY"
echo "ok: the refused read and write left $COPY byte-for-byte unchanged" >>"$REPORT"

# The copy is still readable when named, so its items can be moved out.
VAULT="$COPY" WANT=ok run get "$ITEM" --field password
[ "$out" = "$SECRET" ] || fail "the copy named explicitly did not return the stored value"
echo "ok: the copy named explicitly is readable, for moving its items out" >>"$REPORT"

# A Stado config that is not JSON cannot say whether this machine holds a
# vault: the default file is refused naming the config.
config '{'
VAULT= WANT=refused run duplicates
names "$CONFIG"
names "is the default vault"
cmp -s "$COPY" "$ROOT/copy.before" || fail "a refused command changed $COPY"
echo "ok: an unreadable Stado config refuses the default vault naming the config" >>"$REPORT"

# The vault owner: Stado declares the vault file here, so a bare skarbiec opens it.
config "{\"secrets\":{\"skarbiec\":{\"url\":\"$ROUTE\",\"vault_file\":\"$DECLARED\"}}}"
cp "$OWN" "$DECLARED"
item_json
VAULT= WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"
VAULT= WANT=ok run get "$ITEM" --field password
[ "$out" = "$SECRET" ] || fail "the declared vault did not return the stored value"
echo "ok: the vault Stado declares on this machine was written and read" >>"$REPORT"

# A machine Stado says nothing about keeps the fallback file.
config '{}'
VAULT= WANT=ok run get "$ITEM" --field password
[ "$out" = "$SECRET" ] || fail "the fallback vault did not return the stored value"
echo "ok: with no Stado route the fallback vault is opened" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
