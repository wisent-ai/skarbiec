#!/bin/sh
set -eu

[ "$(uname -s)" = Darwin ] || {
  printf '%s\n' "Skarbiec host broker restart requires launchd" >&2
  exit 1
}

label=com.wisent.always-on.skarbiec
/bin/launchctl kickstart -k "system/$label"
/bin/sleep 1
/bin/launchctl print "system/$label" >/dev/null
printf '%s\n' active
