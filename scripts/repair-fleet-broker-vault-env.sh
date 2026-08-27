#!/bin/sh
# Point the fleet broker unit at the operator vault it is meant to serve.
#
# On 2026-08-27 the always-on host served every Skarbiec request with
# "vault not initialized at ~/.local/share/skarbiec/skarbiec.vault.json":
# the launchd unit `com.wisent.compute.service.skarbiec` runs the bare
# binary with no SKARBIEC_VAULT_FILE, so a fresh process falls back to the
# product default path while the operator vault lives at
# ~/.stado/skarbiec.vault.json. The long-lived process that used to hold
# the port had inherited the right environment from whatever started it
# years of uptime ago; the unit itself never carried it, which is why the
# first honest restart exposed the gap. This writes the variable into the
# unit's own definition, so every future start is correct by construction.
#
# Idempotent: a plist already carrying the right value is left alone and
# the unit is not cycled. A changed plist needs a bootout+bootstrap pair,
# because launchd holds the definition it bootstrapped and kickstart never
# re-reads the file; the window without a listener is accepted here only
# because a broker answering "vault not initialized" to everything is
# already not serving. Ends by proving the outcome: the broker's own
# answer must stop naming the uninitialized default vault.
set -eu

PLIST="$HOME/Library/LaunchAgents/com.wisent.compute.service.skarbiec.plist"
LABEL="com.wisent.compute.service.skarbiec"
VAULT="$HOME/.stado/skarbiec.vault.json"
PORT="8895"

[ -f "$PLIST" ] || { echo "no unit plist at $PLIST" >&2; exit 69; }
[ -f "$VAULT" ] || { echo "no operator vault at $VAULT" >&2; exit 69; }

current=$(/usr/bin/plutil -extract EnvironmentVariables.SKARBIEC_VAULT_FILE raw -o - "$PLIST" 2>/dev/null || true)
if [ "$current" = "$VAULT" ]; then
  echo "unit already names $VAULT; nothing to change"
else
  if ! /usr/bin/plutil -extract EnvironmentVariables raw -o - "$PLIST" >/dev/null 2>&1; then
    /usr/bin/plutil -insert EnvironmentVariables -json '{}' "$PLIST"
  fi
  /usr/bin/plutil -replace EnvironmentVariables.SKARBIEC_VAULT_FILE -string "$VAULT" "$PLIST" 2>/dev/null \
    || /usr/bin/plutil -insert EnvironmentVariables.SKARBIEC_VAULT_FILE -string "$VAULT" "$PLIST"
  uid=$(id -u)
  /bin/launchctl bootout "gui/$uid/$LABEL" 2>/dev/null || true
  /bin/launchctl bootstrap "gui/$uid" "$PLIST"
fi

# The proof: the broker must answer something other than the uninitialized
# default-vault refusal. /v1/owner-pubkey needs no consumer credential.
attempt=0
while [ $attempt -lt 30 ]; do
  answer=$(/usr/bin/curl -s -m 3 "http://127.0.0.1:$PORT/v1/owner-pubkey" || true)
  case "$answer" in
    "") ;;
    *"vault not initialized"*) echo "broker still answers: $answer" >&2; exit 1 ;;
    *) echo "broker serves $VAULT: $answer" | /usr/bin/head -c 300; echo; exit 0 ;;
  esac
  sleep 2
  attempt=$((attempt + 1))
done
echo "broker did not answer on 127.0.0.1:$PORT after the reload" >&2
exit 1
