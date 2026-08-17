#!/bin/sh
# Restore the enumeration tags on Brama's subscription bundles.
#
# Brama's gateway and its desktop console both decide what an item is by tag:
# `brama:subscription` plus `brama:agent:<agent>`, with `brama:provider:` and
# `brama:id:` carrying the provider and the subscription id. Two bundles on this
# vault carry an empty tag list, so every reader that enumerates by tag skips
# them — while the routing catalog, which is built from a different projection,
# keeps using them. The result is a subscription that serves traffic and reports
# a plan window in the usage ledger yet appears nowhere in the console.
#
# Tags are metadata beside the envelope, so this uses `retag` and never touches
# a payload. Running it twice is the same as running it once.
set -eu
# The binary that carries `retag` reaches the always-on host inside Brama's
# release, where it is installed as the entitlements router; that is the same
# Skarbiec executable under another name, so no separate deployment is needed.
SKARBIEC=${SKARBIEC_BIN:-"$HOME/.stado/services/brama/current/darwin-arm/bin/skarbiec-entitlements-router"}
[ -x "$SKARBIEC" ] || SKARBIEC="$HOME/.stado/bin/skarbiec"
[ -x "$SKARBIEC" ] || SKARBIEC=$(command -v skarbiec || true)
[ -n "$SKARBIEC" ] && [ -x "$SKARBIEC" ] || {
  printf 'no skarbiec binary carrying `retag` is available\n' >&2
  exit 1
}
"$SKARBIEC" help 2>/dev/null | /usr/bin/grep -q '"retag"' || {
  printf '%s does not advertise `retag`; ship the release that carries it first\n' "$SKARBIEC" >&2
  exit 1
}

# The fleet's vault, not this user's personal default under
# ~/.local/share/skarbiec. Brama's launcher names the same file, and pointing at
# the default would silently retag items in an empty vault and report success.
SKARBIEC_VAULT_FILE=${SKARBIEC_VAULT_FILE:-"$HOME/.stado/skarbiec.vault.json"}
[ -f "$SKARBIEC_VAULT_FILE" ] || {
  printf 'no fleet vault at %s\n' "$SKARBIEC_VAULT_FILE" >&2
  exit 1
}
export SKARBIEC_VAULT_FILE

retag() {
  id=$1
  tags=$2
  printf -- '--- %s\n' "$id"
  "$SKARBIEC" retag "$id" --tags "$tags"
}

retag "provider:codex:brama-sub-wisent-app-codex-primary" \
  "brama:subscription,brama:agent:wisent-app,brama:provider:codex,brama:id:brama-sub-wisent-app-codex-primary"
retag "provider:kimi:brama-sub-wisent-app-kimi-primary" \
  "brama:subscription,brama:agent:wisent-app,brama:provider:kimi,brama:id:brama-sub-wisent-app-kimi-primary"

printf -- '--- resulting tags\n'
/usr/bin/python3 - <<'PY'
import json, os, pathlib

vault = pathlib.Path(os.environ["HOME"]) / ".stado/skarbiec.vault.json"
items = (json.loads(vault.read_text()).get("items") or {})
for name in sorted(items):
    if not name.startswith("provider:") or "brama-sub-" not in name:
        continue
    entry = items[name] or {}
    tags = entry.get("tags") or []
    print(name, "->", ",".join(sorted(tags)) if tags else "<none>")
PY
