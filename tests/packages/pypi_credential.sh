#!/usr/bin/env bash
# Real test of `skarbiec tool` with the twine adapter, through the built binary on a
# vault and a ~/.pypirc of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE,
# GNUPGHOME and HOME point into this checkout's target directory, so the
# operator's vault, keyring and ~/.pypirc are never read or written.
#
# A .pypirc with two repository sections keeping passwords: status names both
# as plain text, never a value; import moves one section's username and
# password into a login, binds TWINE_USERNAME and TWINE_PASSWORD, and removes
# only that password line; exec --env-from gives a program both variables. A
# section .pypirc does not hold, one keeping no password, and a variable the
# bindings file binds elsewhere are refused with .pypirc unchanged.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/packages/pypi_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/packages/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
PYPIRC="$HOME/.pypirc"
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

: >"$ROOT/stdin"
WANT=ok run init "pypi-owner-$RUN"
MAIN="pypi-main-$RUN"
TEST="pypi-test-$RUN"
cat >"$PYPIRC" <<EOF
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = $MAIN

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = $TEST
EOF
BINDINGS="$ROOT/bindings"

WANT=ok run tool status twine
printf '%s' "$out" | jq -e '[.entries[] | select(.kept == "plain text") | .entry] | (index("pypi") != null) and (index("testpypi") != null)' >/dev/null \
  || fail "status did not name both sections as plain text: $out"
# A password must appear on neither stream.
case "$out$said" in *"$MAIN"*|*"$TEST"*) fail "status printed a password" ;; esac
echo "ok: status names both sections keeping a password, never a value" >>"$REPORT"

ITEM="pypi-$RUN"
WANT=ok run tool import twine "$ITEM" --select pypi --bindings "$BINDINGS"
case "$out$said" in *"$MAIN"*) fail "import printed the password" ;; esac
if grep -q "$MAIN" "$PYPIRC"; then fail ".pypirc still holds the moved password"; fi
grep -qF "password = $TEST" "$PYPIRC" || fail "import removed the other section's password"
grep -qF "repository = https://test.pypi.org/legacy/" "$PYPIRC" || fail "import dropped an unrelated line"
grep -qxF "TWINE_USERNAME=$ITEM:username" "$BINDINGS" || fail "the bindings file does not bind TWINE_USERNAME"
grep -qxF "TWINE_PASSWORD=$ITEM:password" "$BINDINGS" || fail "the bindings file does not bind TWINE_PASSWORD"
WANT=ok run get "$ITEM" --field password
[ "$out" = "$MAIN" ] || fail "the login does not hold the moved password"
echo "ok: import moves the password into a login, binds both variables and removes only that line" >>"$REPORT"

seen="$("$BIN" exec --env-from "$BINDINGS" -- sh -c 'printf "%s %s" "$TWINE_USERNAME" "$TWINE_PASSWORD"' </dev/null)"
[ "$seen" = "__token__ $MAIN" ] || fail "exec --env-from did not give the program the twine sign-in"
echo "ok: exec --env-from gives twine its username and password" >>"$REPORT"

cp "$PYPIRC" "$ROOT/pypirc-before-refusals"
WANT=refused run tool import twine "none-$RUN" --select "nowhere-$RUN" --bindings "$BINDINGS"
case "$said" in *"has no [nowhere-$RUN] section"*) ;; *) fail "a section .pypirc does not hold was not refused: $said" ;; esac
WANT=refused run tool import twine "again-$RUN" --select pypi --bindings "$BINDINGS"
case "$said" in *"keeps no password"*) ;; *) fail "a section keeping no password was not refused: $said" ;; esac
WANT=refused run tool import twine "clash-$RUN" --select testpypi --bindings "$BINDINGS"
case "$said" in *"already binds TWINE_USERNAME"*) ;; *) fail "a variable bound to another item was not refused: $said" ;; esac
cmp -s "$PYPIRC" "$ROOT/pypirc-before-refusals" || fail "a refused import changed .pypirc"
echo "ok: an unknown section, one without a password and a clashing binding are refused, .pypirc unchanged" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
