#!/usr/bin/env bash
# Real test of three of `skarbiec doctor`'s checks, keys, autofill and
# backup, through the built binary on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, GNUPGHOME and HOME point into this checkout's target
# directory, so the operator's vault, keyring and browser setup are never read
# or written.
#
# On a fresh vault the owner's new key is in the keyring and unexpired, so the
# keys check passes; with no browser autofill connected under this HOME the
# autofill check is not_configured, and with no backup made the backup check
# is too. A backup makes it pass naming the copy, and removing the copy makes
# it fail naming it. Then the owner's secret and public key are deleted from
# the keyring and the keys check must fail naming the owner, because every
# write would encrypt to that key. doctor's own exit status is recorded beside
# its answer, since other checks decide it.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/doctor/checks.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/doctor/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export HOME="$ROOT/home"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
# Runs doctor and keeps its answer in $doctor with its exit status in the report.
diagnose() {
  if doctor=$("$BIN" doctor 2>&1); then status=ok; else status=failed; fi
  printf '$ skarbiec doctor\nexit: %s\n%s\n\n' "$status" "$doctor" >>"$REPORT"
  printf '%s' "$doctor" | jq -e .checks >/dev/null || fail "doctor answered no checks: $doctor"
}
# The status and detail one check reported in the last doctor run.
check() {
  printf '%s' "$doctor" | jq -r --arg name "$1" '.checks[] | select(.check == $name) | "\(.status) \(.detail)"'
}

OWNER="doctor-owner-$RUN"
"$BIN" init "$OWNER" >>"$REPORT" 2>&1 || fail "init was refused"
diagnose
case "$(check keys)" in
  pass*) echo "ok: the keys check passes on a fresh vault" >>"$REPORT" ;;
  *) fail "the keys check did not pass on a fresh vault: $(check keys)" ;;
esac
case "$(check autofill)" in
  not_configured*) echo "ok: the autofill check is not_configured with no autofill connected" >>"$REPORT" ;;
  *) fail "the autofill check was not not_configured with no autofill connected: $(check autofill)" ;;
esac
case "$(check backup)" in
  not_configured*) echo "ok: the backup check is not_configured before any backup" >>"$REPORT" ;;
  *) fail "the backup check was not not_configured before any backup: $(check backup)" ;;
esac
mkdir -p "$ROOT/copies"
copy=$("$BIN" backup "$ROOT/copies" 2>&1) || fail "backup was refused: $copy"
made=$(printf '%s' "$copy" | jq -r .backup)
diagnose
case "$(check backup)" in
  pass*"$made"*) echo "ok: the backup check passes naming the copy just made" >>"$REPORT" ;;
  *) fail "the backup check did not pass naming the copy: $(check backup)" ;;
esac
rm -f "$made"
diagnose
case "$(check backup)" in
  fail*"$made"*) echo "ok: the backup check fails naming a copy that is gone" >>"$REPORT" ;;
  *) fail "the backup check did not fail naming the vanished copy: $(check backup)" ;;
esac

FINGERPRINT=$(gpg --batch --with-colons --list-secret-keys "$OWNER" | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$FINGERPRINT" ] || fail "the owner's key is not in the test keyring"
gpg --batch --yes --delete-secret-and-public-key "$FINGERPRINT" >>"$REPORT" 2>&1 || fail "the owner's key could not be deleted from the test keyring"
diagnose
case "$(check keys)" in
  fail*"$OWNER"*) echo "ok: the keys check fails naming the owner once its key is gone" >>"$REPORT" ;;
  *) fail "the keys check did not fail naming the owner: $(check keys)" ;;
esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
