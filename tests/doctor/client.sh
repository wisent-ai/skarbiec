#!/usr/bin/env bash
# Real test of `skarbiec doctor`'s vault check on a machine Stado makes a
# client of the vault owner: secrets.skarbiec.url is declared and no
# secrets.skarbiec.vault_file, so this machine holds no vault and reads the
# fleet vault from the owner. The check must not say the vault is missing or
# uninitialized: it passes naming the route and what declares it. A leftover
# copy at the default path is named as a copy that is not used and left
# unchanged. A Stado config that is not JSON makes the check fail naming the
# file instead of guessing which vault this machine has.
#
# Everything runs through the built binary in an isolated HOME, keyring and
# audit journal under this checkout's target directory, so the operator's
# vault, keyring and Stado config are never read or written. doctor's own
# exit status is recorded beside its answer, since other checks decide it.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/doctor/client.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/doctor/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home/.config/stado" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export HOME="$ROOT/home"
export GNUPGHOME="$KEYRING"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
unset STADO_CONFIG SKARBIEC_VAULT_FILE
CONFIG="$HOME/.config/stado/config.json"
COPY="$HOME/.local/share/skarbiec/skarbiec.vault.json"
# A plain address, so the isolated HOME needs no Stado to resolve a service
# route; nothing connects to it, since doctor's vault check asks no owner.
ROUTE="https://owner-$RUN.example.invalid"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
# Runs doctor and keeps its answer in $doctor and its standard error in $said,
# with its exit status in the report.
diagnose() {
  if doctor=$("$BIN" doctor 2>"$ROOT/said"); then status=ok; else status=failed; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec doctor\nexit: %s\noutput: %s\nstderr: %s\n\n' "$status" "$doctor" "$said" >>"$REPORT"
  printf '%s' "$doctor" | jq -e .checks >/dev/null || fail "doctor answered no checks: $doctor; stderr: $said"
}
vault() {
  printf '%s' "$doctor" | jq -r '.checks[] | select(.check == "vault") | "\(.status) \(.detail)"'
}

printf '{"secrets":{"skarbiec":{"url":"%s"}}}\n' "$ROUTE" >"$CONFIG"
diagnose
case "$(vault)" in
  "pass this host holds no vault: Stado reads the fleet vault through secrets.skarbiec.url ($ROUTE)"*"is not used")
    echo "ok: the vault check passes naming the route and its declaration" >>"$REPORT" ;;
  *) fail "the vault check did not pass naming the route: $(vault)" ;;
esac

mkdir -p "$(dirname "$COPY")"
printf '{}\n' >"$COPY"
diagnose
case "$(vault)" in
  pass*"$ROUTE"*"$COPY is a leftover copy and is not used") echo "ok: the vault check names the leftover copy" >>"$REPORT" ;;
  *) fail "the vault check did not name the leftover copy: $(vault)" ;;
esac
[ "$(cat "$COPY")" = "{}" ] || fail "the leftover copy was changed"

printf 'not json\n' >"$CONFIG"
diagnose
case "$(vault)" in
  fail*"$CONFIG"*) echo "ok: the vault check fails naming the unreadable config" >>"$REPORT" ;;
  *) fail "the vault check did not fail naming the unreadable config: $(vault)" ;;
esac
echo "passed" >>"$REPORT"
