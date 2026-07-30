#!/bin/sh
# check-skarbiec-host.sh — where is my skarbiec host right now?
#
# Answers in one shot:
#   - which skarbiec serve processes run here (port + vault each serves),
#   - is the launchd operator service up and healthy,
#   - the one-line answer: host, vault, how consumers reach it.
set -eu

echo "== skarbiec serve processes on this host"
pgrep -fl 'skarbiec serve' || echo "  (none running)"

echo
echo "== vault each serve is using"
for pid in $(pgrep -f 'skarbiec serve'); do
  vault=$(ps eww -p "$pid" | tr ' ' '\n' | awk -F= '$1=="SKARBIEC_VAULT_FILE" {print $2; exit}')
  port=$(ps -o command= -p "$pid" | awk '{for(i=1;i<=NF;i++) if($i=="--port") print $(i+1)}')
  echo "  pid $pid  port ${port:-default}  vault ${vault:-?}"
done

echo
echo "== launchd services"
launchctl list | awk '$3 ~ /skarbiec/ {print "  " $1, $3}'

echo
echo "== operator service health (default loopback)"
STADO_CONFIG=${STADO_CONFIG:-$HOME/.config/stado/local-operator.json}
export STADO_CONFIG
if ${STADO_BIN:-stado} secrets ls > /dev/null; then
  echo "  healthy: stado secrets reaches the served vault"
else
  echo "  UNHEALTHY: stado secrets cannot reach the served vault"
fi
