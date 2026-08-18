#!/bin/sh
# Provision one login account into Weles's own Skarbiec authority.
#
# Weles reads a login account through a scoped authority of its own, not through
# the fleet vault: on this fleet that authority serves ~/.stado/weles-skarbiec.
# vault.json, and it holds exactly the accounts someone provisioned into it. The
# account claude_controlyourai is there with its two `acquire` grants and signs in
# every time; claude-wisent-google-sso — the account that minted three live claude
# subscriptions — was never provisioned, so every sign-in for it failed. The
# refusal read "unauthorized", which is why it looked like a missing grant for a
# day: the grant was fine, the item did not exist in the authority being asked.
#
# The value crosses between the two vaults inside this process only. Nothing is
# printed but field names, and nothing is written to a command line.
set -eu

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PATH

SKARBIEC=${SKARBIEC_BIN:-"$HOME/.stado/services/brama/current/darwin-arm/bin/skarbiec-entitlements-router"}
[ -x "$SKARBIEC" ] || SKARBIEC="$HOME/.stado/bin/skarbiec"
[ -x "$SKARBIEC" ] || SKARBIEC=$(command -v skarbiec || true)
[ -n "$SKARBIEC" ] && [ -x "$SKARBIEC" ] || {
  printf 'no skarbiec binary on this host\n' >&2
  exit 1
}

SOURCE_VAULT=${SOURCE_VAULT:-"$HOME/.stado/skarbiec.vault.json"}
TARGET_VAULT=${TARGET_VAULT:-"$HOME/.stado/weles-skarbiec.vault.json"}
WORKLOAD_KEY=${WELES_WORKLOAD_PUBLIC_KEY_FILE:-"$HOME/.stado/weles-credential-workload-public.pem"}
ACCOUNT=${ACCOUNT:-claude-wisent-google-sso}
CONSUMER_PREFIX=${CONSUMER_PREFIX:-weles-claude-wisent-google-sso-client}

for path in "$SOURCE_VAULT" "$TARGET_VAULT" "$WORKLOAD_KEY"; do
  [ -r "$path" ] || {
    printf 'not readable: %s\n' "$path" >&2
    exit 1
  }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/provision-weles-login.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

printf -- '--- reading %s from the fleet vault\n' "$ACCOUNT"
SKARBIEC_VAULT_FILE="$SOURCE_VAULT" "$SKARBIEC" get "$ACCOUNT" > "$work/item.json"
/usr/bin/python3 - "$work/item.json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[len(["self"])], "r", encoding="utf-8"))
fields = document.get("fields")
if not isinstance(fields, dict) or not fields:
    raise SystemExit("the source item carries no fields")
missing = [name for name in ("username", "password") if not fields.get(name)]
if missing:
    raise SystemExit(f"the source item is missing {', '.join(missing)}")
print("    kind:", document.get("kind"), "fields:", sorted(fields))
PY

printf -- '--- writing it into the Weles authority\n'
SKARBIEC_VAULT_FILE="$TARGET_VAULT" "$SKARBIEC" set-json "$ACCOUNT" --type login < "$work/item.json" >/dev/null
printf '    written\n'

printf -- '--- granting the two acquisitions in that authority\n'
for field in username password; do
  consumer="$CONSUMER_PREFIX-$field"
  SKARBIEC_VAULT_FILE="$TARGET_VAULT" "$SKARBIEC" token-mint "$consumer" \
    --capabilities "acquire:$ACCOUNT#$field" \
    --workload-public-key-file "$WORKLOAD_KEY" >/dev/null
  printf '    %s -> acquire:%s#%s\n' "$consumer" "$ACCOUNT" "$field"
done

printf -- '--- what the authority now holds for this account\n'
TARGET_VAULT="$TARGET_VAULT" ACCOUNT="$ACCOUNT" /usr/bin/python3 - <<'PY'
import json
import os
import pathlib

document = json.loads(pathlib.Path(os.environ["TARGET_VAULT"]).read_text())
account = os.environ["ACCOUNT"]
item = (document.get("items") or {}).get(account) or {}
print("    item:", account, "kind:", item.get("kind"), "state:", item.get("state"))
for entry in (document.get("tokens") or {}).values():
    if not isinstance(entry, dict):
        continue
    for capability in entry.get("capabilities") or []:
        if isinstance(capability, dict) and capability.get("item") == account:
            print(
                f"    grant: {entry.get('audience')} {capability.get('action')}"
                f" {capability.get('item')}#{capability.get('field')}"
            )
PY
