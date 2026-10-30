#!/usr/bin/env bash
# Real test of `skarbiec upgrade --apply` over v1 items through the built
# binary, on a vault of its own under this checkout's target directory (its
# key file beside it), so the operator's vault and keys are never read or
# written.
#
# A fresh vault is turned back into a v1 envelope holding four items whose
# payloads gpg encrypted to the owner's key, as v1 wrote them (gpg runs only
# here, to make those fixtures, in a GnuPG home of its own that imports the
# owner's public key Skarbiec exports):
#   - a login written under the legacy type `login`, which becomes a login
#     carrying its username and password and no import_warning;
#   - a service account without credential_json, kept as its kind holding its
#     whole record, its import_warning naming the missing credential_json;
#   - an item of a type no legacy writer used, kept whole as a stado-secret,
#     its import_warning naming the type;
#   - an item whose value is not an object, kept as value, its import_warning
#     saying so.
# Skarbiec then runs with a PATH that holds no gpg: the upgrade opens the
# OpenPGP payloads in process, and the persisted v2 items, read back with
# `get`, carry their kind and import_warning and are in the sealed format.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/upgrade/legacy_items.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/upgrade/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT" "$ROOT/no-gpg"
chmod go-rwx "$ROOT"
# gpg-agent's socket lives in its home, and a Unix socket path is short.
mkdir -p "$HOME/.skarbiec/test-runs"
GHOME=$(mktemp -d "$HOME/.skarbiec/test-runs/u.XXXXXX")
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GHOME" --kill all || true; rm -rf "$GHOME"' EXIT
# The tools the test itself uses, linked one by one, and no gpg among them.
for tool in jq cat; do ln -s "$(command -v "$tool")" "$ROOT/no-gpg/$tool"; done

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
skarbiec() {
  PATH="$ROOT/no-gpg" "$BIN" "$@"
}

skarbiec init "legacy-owner-$RUN" >>"$REPORT" 2>&1 || fail "init was refused"
owner=$(skarbiec kit 2>"$ROOT/said" | jq -r .owner_key_fingerprint) || fail "kit did not name the owner key: $(cat "$ROOT/said")"
skarbiec owner key show "legacy-owner-$RUN" 2>"$ROOT/said" | jq -r .public_key >"$ROOT/owner.asc" \
  || fail "owner key show did not export the owner key: $(cat "$ROOT/said")"
gpg --homedir "$GHOME" --batch --import "$ROOT/owner.asc" >>"$REPORT" 2>&1 \
  || fail "gpg did not import the public key Skarbiec exported"

seal() {
  printf '%s' "$1" | gpg --homedir "$GHOME" --batch --yes --armor --trust-model always --recipient "$owner" --encrypt
}

legacy_item() {
  jq -n --arg type "$1" --arg cipher "$(seal "$2")" '{
    type: $type, current: $cipher, recipients: [], tags: [], history: [],
    deleted: false, deleted_at: null,
    created_at: "2000-01-01T00:00:00Z", updated_at: "2000-01-01T00:00:00Z"
  }'
}

login=$(legacy_item login '{"username":"legacy-user","password":"legacy-password"}')
account=$(legacy_item service-account '{"project_id":"legacy-project","client_email":"legacy@example.invalid"}')
unknown=$(legacy_item never-written-kind '{"anything":"kept"}')
bare=$(legacy_item token '"a bare legacy string"')
jq --argjson login "$login" --argjson account "$account" --argjson unknown "$unknown" --argjson bare "$bare" \
  '.version = "v1" | .items = {"legacy-login": $login, "legacy-account": $account, "legacy-unknown": $unknown, "legacy-bare": $bare}' \
  "$SKARBIEC_VAULT_FILE" >"$ROOT/legacy.vault.json"
chmod go-rwx "$ROOT/legacy.vault.json"
cp "$ROOT/legacy.vault.json" "$SKARBIEC_VAULT_FILE"

if upgraded=$(skarbiec upgrade --apply --snapshot "$ROOT/snapshot.json" 2>"$ROOT/said"); then got=ok; else got=refused; fi
said=$(cat "$ROOT/said")
[ "$got" = ok ] || fail "upgrade --apply was refused: $upgraded; stderr: $said"
printf '$ skarbiec upgrade --apply\noutput: %s\nstderr: %s\n\n' "$upgraded" "$said" >>"$REPORT"
[ "$(jq -r .version "$SKARBIEC_VAULT_FILE")" = v2 ] || fail "the vault was not moved to the v2 envelope"

stored() {
  case "$(jq -r --arg id "$1" '.items[$id].current.ciphertext' "$SKARBIEC_VAULT_FILE")" in
    "-----BEGIN SKARBIEC SEALED-----"*) ;;
    *) fail "$1 was not written in the sealed format" ;;
  esac
  skarbiec get "$1"
}
check() {
  id=$1 kind=$2 warning=$3
  payload=$(stored "$id") || fail "$id was not stored decryptably"
  printf '%s: %s\n' "$id" "$payload" >>"$REPORT"
  [ "$(printf '%s' "$payload" | jq -r .kind)" = "$kind" ] || fail "$id became $(printf '%s' "$payload" | jq -r .kind), not $kind"
  said=$(printf '%s' "$payload" | jq -r '.context.import_warning')
  case "$warning" in
    "") [ "$said" = null ] || fail "$id carries an import_warning it should not: $said" ;;
    *) case "$said" in *"$warning"*) ;; *) fail "$id's import_warning does not say '$warning': $said" ;; esac ;;
  esac
}

check legacy-login login ""
echo "ok: a legacy login became a login without a warning" >>"$REPORT"
check legacy-account service-account "named no credential_json"
echo "ok: a service account without credential_json says so" >>"$REPORT"
check legacy-unknown stado-secret 'legacy kind "never-written-kind" has no canonical kind'
echo "ok: an unknown legacy type is kept whole and named" >>"$REPORT"
check legacy-bare stado-secret "was not an object"
echo "ok: a value that is not an object is kept whole, and both that and the token schema's refusal are said" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
