#!/bin/sh
# Store one login account's authenticator seed, so a sign-in can answer Google's
# second factor without a person.
#
# A claude sign-in for claude-wisent-google-sso ran unattended as far as Google's
# second-factor prompt and stopped there: the fleet holds that account's address
# and password but no seed, and nothing else in either vault carries one. Weles
# computes the code itself when the login item has a `totp_secret` field, so this
# is the one value a person still has to hand over, once.
#
# The seed arrives on standard input, never in an argument, and is never printed
# or logged. Both authorities are updated, because Weles reads its own scoped
# vault while the fleet vault stays the source of truth:
#
#   printf '%s' 'THESEEDFROMTHEAUTHENTICATOR' | store-login-totp-seed
#
# Run it with ACCOUNT set to store a seed for a different login item.
set -eu

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PATH
umask 077

SKARBIEC=${SKARBIEC_BIN:-"$HOME/.stado/services/brama/current/darwin-arm/bin/skarbiec-entitlements-router"}
[ -x "$SKARBIEC" ] || SKARBIEC="$HOME/.stado/bin/skarbiec"
[ -x "$SKARBIEC" ] || SKARBIEC=$(command -v skarbiec || true)
[ -n "$SKARBIEC" ] && [ -x "$SKARBIEC" ] || {
  printf 'no skarbiec binary on this host\n' >&2
  exit 1
}

ACCOUNT=${ACCOUNT:-claude-wisent-google-sso}
CONSUMER_PREFIX=${CONSUMER_PREFIX:-weles-claude-wisent-google-sso-client}
FIELD=${FIELD:-totp_secret}
FLEET_VAULT=${FLEET_VAULT:-"$HOME/.stado/skarbiec.vault.json"}
WELES_VAULT=${WELES_VAULT:-"$HOME/.stado/weles-skarbiec.vault.json"}
WORKLOAD_KEY=${WELES_WORKLOAD_PUBLIC_KEY_FILE:-"$HOME/.stado/weles-credential-workload-public.pem"}

for path in "$FLEET_VAULT" "$WELES_VAULT" "$WORKLOAD_KEY"; do
  [ -r "$path" ] || {
    printf 'not readable: %s\n' "$path" >&2
    exit 1
  }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/store-login-totp.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

# The seed is read once here and handed to the vault through a file only this
# user can open, because an authenticator secret on a command line is a secret in
# every process table on the host.
/bin/cat > "$work/seed.txt"
SEED_FILE="$work/seed.txt" /usr/bin/python3 - <<'PY'
import os
import pathlib
import re

seed = pathlib.Path(os.environ["SEED_FILE"]).read_text().strip().replace(" ", "").upper()
if not seed:
    raise SystemExit("no seed arrived on standard input")
if not re.fullmatch(r"[A-Z2-7]{16,128}", seed):
    raise SystemExit(
        "that does not look like an authenticator seed: expected 16 to 128 base32 "
        "characters (A-Z and 2-7), which is what Google shows behind 'can't scan it'"
    )
pathlib.Path(os.environ["SEED_FILE"]).write_text(seed)
print(f"    seed accepted: {len(seed)} base32 characters")
PY

store_into() {
  vault=$1
  label=$2
  printf -- '--- %s\n' "$label"
  if ! SKARBIEC_VAULT_FILE="$vault" "$SKARBIEC" get "$ACCOUNT" > "$work/item.json" 2>/dev/null; then
    printf '    %s does not hold %s; provision the account there first\n' "$label" "$ACCOUNT" >&2
    return 1
  fi
  ITEM_FILE="$work/item.json" SEED_FILE="$work/seed.txt" FIELD="$FIELD" \
    /usr/bin/python3 - > "$work/next.json" <<'PY'
import json
import os
import pathlib

document = json.loads(pathlib.Path(os.environ["ITEM_FILE"]).read_text())
fields = document.get("fields")
if not isinstance(fields, dict):
    raise SystemExit("the item carries no fields object")
fields[os.environ["FIELD"]] = pathlib.Path(os.environ["SEED_FILE"]).read_text().strip()
document["fields"] = fields
print(json.dumps(document))
PY
  SKARBIEC_VAULT_FILE="$vault" "$SKARBIEC" set-json "$ACCOUNT" --type login < "$work/next.json" >/dev/null
  SKARBIEC_VAULT_FILE="$vault" "$SKARBIEC" token-mint "$CONSUMER_PREFIX-$FIELD" \
    --capabilities "acquire:$ACCOUNT#$FIELD" \
    --workload-public-key-file "$WORKLOAD_KEY" >/dev/null
  printf '    stored the field and granted acquire:%s#%s to %s\n' "$ACCOUNT" "$FIELD" "$CONSUMER_PREFIX-$FIELD"
}

store_into "$FLEET_VAULT" "fleet vault"
store_into "$WELES_VAULT" "Weles authority"

printf -- '--- fields each authority now records for %s\n' "$ACCOUNT"
for vault in "$FLEET_VAULT" "$WELES_VAULT"; do
  printf '    %s: ' "$(basename "$vault")"
  SKARBIEC_VAULT_FILE="$vault" "$SKARBIEC" get "$ACCOUNT" 2>/dev/null | /usr/bin/python3 -c '
import json, sys
print(sorted((json.load(sys.stdin).get("fields") or {})))
'
done
printf 'restart com.wisent.always-on.skarbiec-weles so the authority reloads, then the renewal loop signs this account in by itself\n'
