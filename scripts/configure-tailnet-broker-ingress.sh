#!/bin/sh
set -eu

for candidate in \
  /Applications/Tailscale.app/Contents/MacOS/Tailscale \
  /usr/local/bin/tailscale \
  /opt/homebrew/bin/tailscale \
  /usr/bin/tailscale
do
  if [ -x "$candidate" ]; then
    tailscale="$candidate"
    break
  fi
done

[ -n "${tailscale:-}" ] || {
  printf '%s\n' "tailscale executable not found" >&2
  exit 1
}

"$tailscale" serve --bg --https=9443 --yes http://127.0.0.1:8787
"$tailscale" serve status --json
