#!/bin/sh
set -eu

[ "$(uname -s)" = Darwin ] || {
  printf '%s\n' "Skarbiec host broker restart requires launchd" >&2
  exit 1
}

label=com.wisent.always-on.skarbiec
plist="/Library/LaunchDaemons/$label.plist"
binary="$HOME/.stado/bin/skarbiec"
logs="$HOME/.stado/logs"
user=$(/usr/bin/id -un)
exec_as_root="/usr/bin/sudo"
temporary="/tmp/$label.plist.$$"
trap '/bin/rm -f "$temporary"' EXIT

/bin/mkdir -p "$logs"
cat >"$temporary" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$label</string>
  <key>UserName</key>
  <string>$user</string>
  <key>ProgramArguments</key>
  <array>
    <string>$binary</string>
    <string>serve</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>$HOME</string>
    <key>GNUPGHOME</key>
    <string>$HOME/.gnupg</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>SKARBIEC_AUDIT_FILE</key>
    <string>$HOME/.stado/skarbiec.audit.jsonl</string>
    <key>SKARBIEC_VAULT_FILE</key>
    <string>$HOME/.stado/skarbiec.vault.json</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$logs/skarbiec.out</string>
  <key>StandardErrorPath</key>
  <string>$logs/skarbiec.err</string>
</dict>
</plist>
EOF

$exec_as_root /usr/bin/install -o root -g wheel -m 0644 "$temporary" "$plist"
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
