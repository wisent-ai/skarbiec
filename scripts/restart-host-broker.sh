#!/bin/sh
set -eu

[ "$(uname -s)" = Darwin ] || {
  printf '%s\n' "Skarbiec host broker restart requires launchd" >&2
  exit 1
}

label=com.wisent.always-on.skarbiec
exec_as_root="/usr/bin/sudo"
$exec_as_root /bin/launchctl kickstart -k "system/$label"
/bin/sleep 1
$exec_as_root /bin/launchctl print "system/$label" >/dev/null
printf '%s\n' active
