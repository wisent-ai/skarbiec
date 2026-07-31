#!/bin/zsh
# install-browser-host.sh — register the Skarbiec native messaging host and
# mint its narrowly scoped grant.
#
# What this does, in order:
#   1. builds the skarbiec binary (native-host subcommand included) and
#      installs it to ~/.stado/bin/skarbiec (rm + cp — never overwrite in
#      place; macOS kills exec of a replaced-in-place signed binary);
#   2. mints the `skarbiec-browser-host` consumer grant scoped to
#      `read:login-*` only, written to ~/.stado/browser-host-skarbiec-token;
#   3. writes the native messaging manifests for Chrome and Firefox pointing
#      at that binary;
#   4. prints how to load the unpacked extension in each browser.
#
# Chrome needs the extension id (assigned on first load) in allowed_origins;
# pass it back via the first argument once known. Firefox pins its own id
# from the manifest's browser_specific_settings, so it works immediately.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SKARBIEC_BIN="$HOME/.stado/bin/skarbiec"
TOKEN_FILE="$HOME/.stado/browser-host-skarbiec-token"
CONSUMER="skarbiec-browser-host"
EXT_DIR="$REPO/browser"
CHROME_HOSTS="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
FIREFOX_HOSTS="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
HOST_NAME="ai.wisent.skarbiec"
EXTENSION_ID="${1:-}"

print "→ building skarbiec (native-host)"
cargo build --release --manifest-path "$REPO/Cargo.toml" >/dev/null
rm -f "$SKARBIEC_BIN"
cp "$REPO/target/release/skarbiec" "$SKARBIEC_BIN"
chmod +x "$SKARBIEC_BIN"

print "→ minting $CONSUMER grant (scope: read:login-*)"
TOKEN=$(SKARBIEC_VAULT_FILE="${SKARBIEC_VAULT_FILE:-$HOME/.stado/skarbiec.vault.json}" \
  "$SKARBIEC_BIN" token-mint "$CONSUMER" --scopes "read:login-*" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
umask u=rwx,go=
printf '%s' "$TOKEN" > "$TOKEN_FILE"

write_chrome_manifest() {
  mkdir -p "$CHROME_HOSTS"
  local origins
  if [[ -n "$EXTENSION_ID" ]]; then
    origins="\"chrome-extension://$EXTENSION_ID/\""
  else
    origins=""
  fi
  cat > "$CHROME_HOSTS/$HOST_NAME.json" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Skarbiec vault bridge for the autofill extension",
  "path": "$SKARBIEC_BIN",
  "type": "stdio",
  "allowed_origins": [$origins]
}
JSON
  print "✓ Chrome manifest: $CHROME_HOSTS/$HOST_NAME.json"
}

write_firefox_manifest() {
  mkdir -p "$FIREFOX_HOSTS"
  cat > "$FIREFOX_HOSTS/$HOST_NAME.json" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Skarbiec vault bridge for the autofill extension",
  "path": "$SKARBIEC_BIN",
  "type": "stdio",
  "allowed_extensions": ["skarbiec-autofill@wisent.ai"]
}
JSON
  print "✓ Firefox manifest: $FIREFOX_HOSTS/$HOST_NAME.json"
}

write_chrome_manifest
write_firefox_manifest

cat <<NEXT

Load the extension:
  Chrome:  chrome://extensions → Developer mode → Load unpacked → $EXT_DIR
           then copy the assigned extension id and re-run:
             $0 <extension-id>
  Firefox: about:debugging → This Firefox → Load Temporary Add-on →
           $EXT_DIR/manifest.json (id is pinned, works immediately)

Verify the host:
  $SKARBIEC_BIN native-host   # speaks length-prefixed JSON on stdio
NEXT
