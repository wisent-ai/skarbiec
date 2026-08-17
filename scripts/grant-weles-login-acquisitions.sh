#!/bin/sh
# Grant Weles the acquisitions its login trajectories declare.
#
# Weles reads a login account's username and password through one workload-bound
# acquisition per field, with a consumer named after the account. The client side
# of that contract is scripts/worker/deploy/skarbiec-acquisition-scopes.conf in
# the Weles release; the vault side is a minted consumer token carrying `acquire`
# on that exact item and field. When only the client side exists, the trajectory
# dies with "workload-bound Skarbiec acquisition failed for <account>", which is
# how three claude subscriptions stayed unrenewable while the account that mints
# them sat in the vault the whole time.
#
# Minting an existing consumer again is harmless: the token is replaced with one
# carrying the same capabilities, and no secret value is read, written or printed
# here.
set -eu

SKARBIEC=${SKARBIEC_BIN:-"$HOME/.stado/services/brama/current/darwin-arm/bin/skarbiec-entitlements-router"}

# A helper session arrives without a PATH worth having, and minting a token signs
# with gpg: without this the run fails with "spawn gpg: No such file or
# directory" on a host where gpg is installed and fine.
PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PATH
[ -x "$SKARBIEC" ] || SKARBIEC="$HOME/.stado/bin/skarbiec"
[ -x "$SKARBIEC" ] || SKARBIEC=$(command -v skarbiec || true)
[ -n "$SKARBIEC" ] && [ -x "$SKARBIEC" ] || {
  printf 'no skarbiec binary on this host\n' >&2
  exit 1
}

SKARBIEC_VAULT_FILE=${SKARBIEC_VAULT_FILE:-"$HOME/.stado/skarbiec.vault.json"}
[ -f "$SKARBIEC_VAULT_FILE" ] || {
  printf 'no fleet vault at %s\n' "$SKARBIEC_VAULT_FILE" >&2
  exit 1
}
export SKARBIEC_VAULT_FILE

# An `acquire` capability is bound to the workload that may redeem it, so the new
# grants must name the same key the working account's grants already name.
# Measured on this fleet: ~/.stado/weles-credential-workload-public.pem holds
# exactly the key recorded in weles-claude-controlyourai-client-username, so
# binding to it grants the same workload and nothing else.
WORKLOAD_KEY=${WELES_WORKLOAD_PUBLIC_KEY_FILE:-"$HOME/.stado/weles-credential-workload-public.pem"}
[ -r "$WORKLOAD_KEY" ] || {
  printf 'no readable Weles workload public key at %s; an acquire grant cannot be bound without it\n' "$WORKLOAD_KEY" >&2
  exit 1
}

# The account Weles could not read, and the two fields a Google sign-in needs.
# Kept as an explicit table rather than derived from the account name, so adding
# an account is a reviewed line here and never a pattern that grants more than
# was intended.
grants='weles-claude-wisent-google-sso-client-username|claude-wisent-google-sso|username
weles-claude-wisent-google-sso-client-password|claude-wisent-google-sso|password'

printf '%s\n' "$grants" | while IFS='|' read -r consumer item field; do
  [ -n "$consumer" ] || continue
  printf -- '--- %s -> acquire:%s#%s\n' "$consumer" "$item" "$field"
  "$SKARBIEC" token-mint "$consumer" \
    --capabilities "acquire:$item#$field" \
    --workload-public-key-file "$WORKLOAD_KEY" >/dev/null
  printf '    minted\n'
done
printf -- '--- resulting grants for this account\n'
/usr/bin/python3 - <<'PY'
import json, os, pathlib

document = json.loads((pathlib.Path(os.environ["SKARBIEC_VAULT_FILE"])).read_text())
for name, entry in (document.get("tokens") or {}).items():
    if not isinstance(entry, dict):
        continue
    consumer = entry.get("consumer") or name
    if "claude-wisent-google-sso" not in json.dumps(entry.get("capabilities") or []):
        continue
    for capability in entry.get("capabilities") or []:
        if not isinstance(capability, dict):
            continue
        print(
            f"    {consumer}: {capability.get('action')} {capability.get('item')}"
            f"#{capability.get('field')}"
        )
PY
