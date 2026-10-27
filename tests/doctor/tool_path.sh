#!/usr/bin/env bash
# Real test that Skarbiec runs gpg only from the PATH it was started with:
# through the built binary, with SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME inside this checkout's target directory, so the operator's vaults
# and keyring are never read or written.
#
# With a PATH that holds no gpg, `skarbiec init` is refused naming gpg and the
# PATH it searched, and writes no vault: no install directory is guessed.
# With the caller's PATH restored, the same init succeeds, proving the refusal
# came from the PATH and not from the keyring.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/doctor/tool_path.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/tool-path/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/empty-path" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
CALLER_PATH=$PATH
trap 'PATH=$CALLER_PATH gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >>/dev/stderr
  false
}

OWNER="tool-path-owner-$RUN"
if out=$(PATH="$ROOT/empty-path" "$BIN" init "$OWNER" </dev/null &>/dev/stdout); then
  fail "init ran with a PATH that holds no gpg: $out"
fi
printf '$ PATH=%s skarbiec init %s\nrefused: %s\n\n' "$ROOT/empty-path" "$OWNER" "$out" >>"$REPORT"
case "$out" in
  *"gpg"*"is in no directory of PATH"*"$ROOT/empty-path"*) echo "ok: refused naming gpg and the PATH searched" >>"$REPORT" ;;
  *) fail "the refusal does not name gpg and the PATH it searched: $out" ;;
esac
[ -e "$SKARBIEC_VAULT_FILE" ] && fail "the refused init wrote $SKARBIEC_VAULT_FILE"
echo "ok: the refused init wrote no vault" >>"$REPORT"

out=$("$BIN" init "$OWNER" </dev/null &>/dev/stdout) || fail "init with the caller's PATH was refused: $out"
printf '$ skarbiec init %s\nresult: ok\n\n' "$OWNER" >>"$REPORT"
[ -e "$SKARBIEC_VAULT_FILE" ] || fail "init with the caller's PATH wrote no vault"
echo "ok: with gpg on PATH the same init succeeds" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
