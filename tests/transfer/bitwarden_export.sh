#!/usr/bin/env bash
# Real test of exporting for Bitwarden, `skarbiec export <file>
# --bitwarden-csv`, through the built binary on a vault of its own:
# SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# A login with two sites, a seed and notes, and a note, export to Bitwarden's
# header and one row each: the login's sites both in login_uri, its seed in
# login_totp, the note's text in notes. The file is owner-only. An item of
# another kind is refused naming it, and two shapes together are refused;
# neither writes a file.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/transfer/bitwarden_export.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/transfer/$RUN"
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
    *) fail "expected a refusal naming '$*', got: $said; output: $out" ;;
  esac
}

SEED="JBSWY3DPEHPK3PXP"
LOGIN="bw-login-$RUN"
NOTE="bw-note-$RUN"
: >"$ROOT/stdin"
WANT=ok run init "bw-owner-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"me-%s","password":"bw-secret-%s","totp_secret":"%s"},"context":{"domains":["one-%s.example","two-%s.example"],"notes":"bw-notes-%s"}}' \
  "$RUN" "$RUN" "$SEED" "$RUN" "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set "$LOGIN" --type login
printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"bw-note-text-%s"},"context":{}}' "$RUN" >"$ROOT/stdin"
WANT=ok run set "$NOTE" --type note
# The token's id lies outside the --match the export below narrows to.
printf '{"schema":"skarbiec.item.v2","kind":"token","fields":{"token":"other-token-%s"},"context":{}}' "$RUN" >"$ROOT/stdin"
WANT=ok run set "other-token-$RUN" --type token
: >"$ROOT/stdin"

WANT=refused run export "$ROOT/all.csv" --bitwarden-csv
names "other-token-$RUN"
[ ! -e "$ROOT/all.csv" ] || fail "a refused export wrote a file"

CSV="$ROOT/bitwarden.csv"
WANT=ok run export "$CSV" --bitwarden-csv --match "bw-"
grep -qx 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp' "$CSV" \
  || fail "the file does not start with Bitwarden's header"
grep -q "\"login\",\"$LOGIN\",\"bw-notes-$RUN\",\"\",\"\",\"https://one-$RUN.example/,https://two-$RUN.example/\",\"me-$RUN\",\"bw-secret-$RUN\",\"$SEED\"" "$CSV" \
  || fail "the login's row does not carry its notes, both sites, username, password and seed: $(cat "$CSV")"
grep -q "\"note\",\"$NOTE\",\"bw-note-text-$RUN\"" "$CSV" || fail "the note's row does not carry its text"
[ "$(stat -f %Lp "$CSV")" = "$(stat -f %Lp "$SKARBIEC_VAULT_FILE")" ] || fail "the file is not owner-only as the vault is"
echo "ok: logins and notes export in Bitwarden's CSV with sites, seeds and notes" >>"$REPORT"

WANT=refused run export "$ROOT/two.csv" --bitwarden-csv --canonical
names "name one"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
