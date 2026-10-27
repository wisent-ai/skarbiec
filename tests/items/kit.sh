#!/usr/bin/env bash
# Real test of the emergency kit, `skarbiec kit`, through the built binary on a
# vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# point into this checkout's target directory, so the operator's vault and
# keyring are never read or written.
#
# A vault fresh from init records its owner, the owner's key and a recovery
# key, so the kit is complete: ok is true and nothing is missing. Its page
# names the vault file and both fingerprints the answer carries, lists the
# restore steps, and holds no secret: no private key block.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/items/kit.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/items/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

"$BIN" init "kit-owner-$RUN" >>"$REPORT" 2>&1 || fail "init was refused"
kit=$("$BIN" kit 2>&1) || fail "kit was refused: $kit"
printf '$ skarbiec kit\n%s\n\n' "$kit" >>"$REPORT"

[ "$(printf '%s' "$kit" | jq -r .ok)" = true ] || fail "a fresh vault's kit is not complete: $(printf '%s' "$kit" | jq -c .missing)"
[ "$(printf '%s' "$kit" | jq -r '.missing | length')" = "$(printf '%s' '[]' | jq length)" ] || fail "a fresh vault's kit names something missing"
page=$(printf '%s' "$kit" | jq -r .page)
for piece in "$SKARBIEC_VAULT_FILE" "$(printf '%s' "$kit" | jq -r .owner_key_fingerprint)" "$(printf '%s' "$kit" | jq -r .recovery_key_fingerprint)" "To restore, in this order:"; do
  case "$page" in
    *"$piece"*) ;;
    *) fail "the page does not carry $piece" ;;
  esac
done
case "$page" in
  *"PRIVATE KEY"*) fail "the page holds a private key block" ;;
esac
echo "ok: a fresh vault's kit is complete and its page carries the file, both fingerprints and the steps, and no secret" >>"$REPORT"

[ "$(printf '%s' "$kit" | jq -r .latest_backup)" = null ] || fail "a vault never backed up names a latest backup"
case "$page" in *"Latest backup: not recorded"*) ;; *) fail "the page does not say no backup was made" ;; esac
mkdir -p "$ROOT/copies"
copy=$("$BIN" backup "$ROOT/copies" 2>&1) || fail "backup was refused: $copy"
made=$(printf '%s' "$copy" | jq -r .backup)
kit=$("$BIN" kit 2>&1) || fail "kit was refused after a backup: $kit"
printf '$ skarbiec kit (after backup)\n%s\n\n' "$kit" >>"$REPORT"
[ "$(printf '%s' "$kit" | jq -r .latest_backup.backup)" = "$made" ] || fail "the kit does not name the backup just made"
case "$(printf '%s' "$kit" | jq -r .page)" in *"Latest backup: $made"*) ;; *) fail "the page does not name the backup just made" ;; esac
echo "ok: the kit names the newest backup, or says none was made" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
