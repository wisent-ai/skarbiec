#!/bin/sh
set -eu

[ "$(uname -s)" = Darwin ] || {
  printf '%s\n' "Skarbiec host broker restart requires launchd" >&2
  exit 1
}

label=com.wisent.always-on.skarbiec
plist="/Library/LaunchDaemons/$label.plist"
binary="$HOME/.stado/bin/skarbiec"
exec_as_root="/usr/bin/sudo"

$exec_as_root /bin/launchctl bootout system "$plist" 2>/dev/null || true
for pid in $(/usr/bin/pgrep -f "^${binary}([[:space:]]|$)" || true)
do
  command=$(/bin/ps -p "$pid" -o comm= | /usr/bin/xargs)
  [ "$command" = "$binary" ] || continue
  $exec_as_root /bin/kill -TERM "$pid"
done
/bin/sleep 2
$exec_as_root /bin/launchctl bootstrap system "$plist"
$exec_as_root /bin/launchctl kickstart -k "system/$label"
/bin/sleep 1
$exec_as_root /bin/launchctl print "system/$label" >/dev/null
printf '%s\n' active
