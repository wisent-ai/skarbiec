#!/usr/bin/env bash
# Real test of naming the logins that could have authenticator codes, `skarbiec
# totp missing`, through the built binary against the real 2FA Directory, on
# a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# point into this checkout's target directory, so the operator's vault and
# keyring are never read or written.
#
# Three logins: one for github.com with no seed, one for github.com with a
# seed, and one for a reserved .invalid host no directory lists. Only the
# first is named, under github.com; the answer carries the directory's
# address and attribution, and neither password nor seed appears in it.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/review/codes_missing.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/review/$RUN"
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
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"%s-user","password":"%s"%s},"context":{"domains":["%s"]}}' \
    "$1" "codes-secret-$RUN" "$3" "$2" >"$ROOT/stdin"
  WANT=ok run set "$1" --type login
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "codes-owner-$RUN"
BARE="codes-bare-$RUN"
SEEDED="codes-seeded-$RUN"
ELSEWHERE="codes-elsewhere-$RUN"
SEED="JBSWY3DPEHPK3PXP"
login "$BARE" "github.com" ""
login "$SEEDED" "github.com" ",\"totp_secret\":\"$SEED\""
login "$ELSEWHERE" "codes-$RUN.invalid" ""

# A login that names no code is a finding, so the command reports ok false
# and still exits as an answer.
if out=$("$BIN" totp missing </dev/null 2>"$ROOT/said"); then got=ok; else got=refused; fi
said=$(cat "$ROOT/said")
printf '$ skarbiec totp missing\nresult: %s\noutput: %s\nstderr: %s\n\n' "$got" "$out" "$said" >>"$REPORT"
printf '%s' "$out" | jq -e . >/dev/null || fail "totp missing did not answer JSON ($got): output: $out stderr: $said"
printf '%s' "$out" | jq -e --arg bare "$BARE" \
  '[.logins[] | select(.item == $bare) | .sites[].site] | index("github.com") != null' >/dev/null \
  || fail "the login on github.com without a seed was not named under github.com"
printf '%s' "$out" | jq -e --arg seeded "$SEEDED" --arg elsewhere "$ELSEWHERE" \
  '[.logins[].item] | (index($seeded) == null) and (index($elsewhere) == null)' >/dev/null \
  || fail "a login with a seed, or on a site no directory lists, was named"
printf '%s' "$out" | jq -e '(.source | startswith("https://api.2fa.directory/")) and (.attribution | contains("2FA Directory"))' >/dev/null \
  || fail "the answer does not name the directory and its attribution"
# A password or seed must appear on neither stream.
case "$out$said" in
  *"codes-secret-$RUN"* | *"$SEED"*) fail "totp missing printed a password or a seed" ;;
esac
echo "ok: only the github.com login without a seed is named, with the directory's attribution" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
