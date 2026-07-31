#!/bin/zsh
# install-browser-extension.sh — load the Skarbiec autofill extension into
# every installed desktop browser. Run it yourself:
#
#     zsh ~/Documents/CodingProjects/Wisent/skarbiec/scripts/install-browser-extension.sh
#
# Chromium-family browsers (Chrome, Arc, Brave, Edge) get the extension
# through the vendor's documented --load-extension launch flag: starting the
# browser once with that flag registers the unpacked extension in the
# profile permanently. This is the only side-load path left on macOS —
# external-extension JSON side-loading is disabled on this platform, and an
# enterprise force-install policy requires a hosted update service.
#
# Firefox has no launch-flag equivalent; the script opens the temporary
# add-on page and prints the manifest path (a permanent Firefox install
# would need a Mozilla-signed XPI).
set -euo pipefail

EXT_DIR="$(cd "$(dirname "$0")/../browser" && pwd)"
LOAD_ARG="--load-extension=$EXT_DIR"

if [[ ! -f "$EXT_DIR/manifest.json" ]]; then
  print -u2 "extension not found at $EXT_DIR"
  false
  exit "$?"
fi

print "→ extension: $EXT_DIR"

load_into() {
  local app_name="$1"
  if [[ -d "/Applications/$app_name.app" ]]; then
    open -na "$app_name" --args "$LOAD_ARG"
    print "✓ $app_name: extension loaded (check the toolbar for the Skarbiec icon)"
  else
    print "· $app_name: not installed, skipping"
  fi
}

load_into "Google Chrome"
load_into "Arc"
load_into "Brave Browser"
load_into "Microsoft Edge"

if [[ -d "/Applications/Firefox.app" ]]; then
  open -na Firefox "about:debugging#/runtime/this-firefox"
  print "· Firefox: opened the add-on page — click 'Load Temporary Add-on' and pick:"
  print "    $EXT_DIR/manifest.json"
else
  print "· Firefox: not installed, skipping"
fi

cat <<'NOTE'

Verify after the browser starts:
  - the Skarbiec icon appears in the toolbar;
  - a password field on a site with a vault login shows the blue "S" badge;
  - native messaging is already registered (id ghhjjmbnfljfokflholofpjapfhadbnb
    is pinned in both the extension and the host manifest).

If a browser was already running, quit and start it once via this script —
the flag only applies to a fresh process.
NOTE
