#!/bin/sh
# browser-autofill.sh — fill logins in Chrome/Firefox straight from the vault.
#
# The moving parts: a WebExtension (browser/) that never sees a vault token,
# and a native messaging host (`skarbiec native-host`) that answers the
# extension through the loopback API with a grant scoped to read:login-* only.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"

# 1. install: build the binary, mint the skarbiec-browser-host grant
#    (read:login-* only), write Chrome + Firefox native messaging manifests
"$REPO/scripts/install-browser-host.sh"

# 2. store a login the extension can offer. Item id must start with login-;
#    `domains` controls which hosts the fill is offered on (subdomains match)
printf '%s' '{"name":"Example","username":"you@example.com","password":"correct-horse-battery","domains":["example.com"]}' \
  | "$SB" set-json login-example-com --type login

# 3. load the extension once per browser:
#    Chrome   chrome://extensions → Developer mode → Load unpacked → browser/
#             then re-run the installer with the assigned id:
#               scripts/install-browser-host.sh <extension-id>
#    Firefox  about:debugging → This Firefox → Load Temporary Add-on →
#             browser/manifest.json (id pinned, works immediately)

# 4. verify the host without a browser: frames are a u32 LE length + JSON.
#    ping (17 bytes) should answer {"ok":true,...,"service":"skarbiec-native-host"}
printf '\x11\x00\x00\x00{"action":"ping"}' | "$SB" native-host

# 5. from then on: a password field on a matching site gets an "S" badge;
#    clicking it (or the toolbar popup) fills username/password/TOTP.
#    Revoke browser access at any time without touching other consumers:
#      skarbiec token-revoke skarbiec-browser-host
