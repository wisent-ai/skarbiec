#!/bin/sh
# Report whether a named Skarbiec vault is actually reachable by the workloads
# that read from it, and say which link in the chain is broken when it is not.
#
# A vault file on disk proves nothing. A consumer reaches it through a launchd
# service that binds a local port named in ~/.stado/forwards/<service>.local,
# which Stado's resolver then fronts on a stable port that the consumer's env
# file points at, under a workload identity the resolver must authorize. Five
# things can disagree, and when they do the failure arrives at the consumer as a
# generic "credential unavailable" that names none of them.
#
# That is not hypothetical. On 2026-08-06 a Weles credential rotation could not
# start because com.wisent.compute.service.com.wisent.skarbiec-weles was disabled
# in launchd, while a different Skarbiec instance served a different vault on
# another port. The consumer's env file pointed at a stable port with no backend,
# and the only symptom was ADOPT_CANDIDATE_UNAVAILABLE.
#
# Read-only: starts nothing, writes nothing, prints no secret material.
#
# Usage: scripts/check-serving-path.sh [service-name] [consumer-env-file]
#   service-name      forwards entry to check, default skarbiec-weles
#   consumer-env-file env file naming the stable port and workload identity,
#                     default $HOME/.config/weles/worker.env
set -eu

SERVICE="${1:-skarbiec-weles}"
ENV_FILE="${2:-$HOME/.config/weles/worker.env}"
LABEL="com.wisent.compute.service.com.wisent.$SERVICE"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
FORWARD_FILE="$HOME/.stado/forwards/$SERVICE.local"
PROBE_TIMEOUT='5'
UNREACHABLE='000'
# Shell truth as named values, so the numeric-literal rule is satisfied without
# hiding what a bare return status means.
TRUE='0'
FALSE='1'

# Broken links are counted by appending to a string, so the tally needs no
# arithmetic and the script stays free of numeric literals.
BROKEN=''

note() {
    printf '%-26s %s\n' "$1" "$2"
}

fail() {
    note "$1" "$2"
    BROKEN="$BROKEN."
}

# curl already writes 000 through -w when it cannot connect, so a fallback that
# appends its own would produce 000000 and compare unequal to every unreachable
# marker -- which is how an earlier version of this script reported a dead port
# as answering. Swallow the exit status only, never add to the output.
probe() {
    curl -sS -o /dev/null -m "$PROBE_TIMEOUT" -w '%{http_code}' "$1" || true
}

reachable() {
    case "${1:-}" in
        '' | "$UNREACHABLE" | "$UNREACHABLE"*) return "$FALSE" ;;
        *) return "$TRUE" ;;
    esac
}

# 1. launchd enablement. A disabled service is an operator decision, not drift,
#    so the remedy is named rather than performed.
DISABLED_STATE=$(launchctl print-disabled "gui/$(id -u)" |
    awk -v label="\"$LABEL\"" '$1 == label { print $3 }')
if [ "${DISABLED_STATE:-absent}" = 'enabled' ]; then
    note 'launchd enablement' 'enabled'
elif [ "${DISABLED_STATE:-absent}" = 'disabled' ]; then
    fail 'launchd enablement' "disabled by an operator; undo with: launchctl enable gui/$(id -u)/$LABEL"
else
    fail 'launchd enablement' "no launchd record for $LABEL"
fi

# 2. Is it actually running? Enabled and loaded are different questions.
SERVICE_PID=$(launchctl list | awk -v label="$LABEL" '$3 == label { print $1 }')
if [ -z "$SERVICE_PID" ]; then
    fail 'launchd process' "not loaded; bootstrap with: launchctl bootstrap gui/$(id -u) $PLIST"
elif [ "$SERVICE_PID" = '-' ]; then
    fail 'launchd process' 'loaded but not running; read the service log for its exit reason'
else
    note 'launchd process' "running, pid $SERVICE_PID"
fi

# 3. Which vault it was told to serve, read from the plist and then the launcher
#    it names, never guessed. Two instances serving two vaults is the case that
#    makes a healthy-looking process useless to this consumer.
#
#    The plist is read as XML rather than through PlistBuddy, because PlistBuddy
#    writes "Does Not Exist" to stderr for an absent key, which reads like a
#    failure in the middle of a check that is about to succeed by other means.
VAULT=''
VAULT_SOURCE=''
if [ -f "$PLIST" ]; then
    VAULT=$(awk '
        /<key>SKARBIEC_VAULT_FILE<\/key>/ { want = "yes"; next }
        want == "yes" && /<string>/ {
            line = $0
            sub(/^[^>]*<string>/, "", line)
            sub(/<\/string>.*$/, "", line)
            print line
            exit
        }
    ' "$PLIST")
    if [ -n "$VAULT" ]; then
        VAULT_SOURCE='plist'
    else
        LAUNCHER=$(awk '
            /<key>ProgramArguments<\/key>/ { want = "yes"; next }
            want == "yes" && /<string>/ {
                line = $0
                sub(/^[^>]*<string>/, "", line)
                sub(/<\/string>.*$/, "", line)
                print line
                exit
            }
        ' "$PLIST")
        if [ -n "$LAUNCHER" ] && [ -f "$LAUNCHER" ]; then
            RAW=$(awk -F'=' '/^export SKARBIEC_VAULT_FILE=/ { gsub(/"/, "", $2); print $2; exit }' "$LAUNCHER")
            VAULT=$(printf '%s' "$RAW" | sed "s|^\$HOME|$HOME|")
            VAULT_SOURCE="launcher $LAUNCHER"
        fi
    fi
fi
if [ -z "$VAULT" ]; then
    fail 'vault served' 'neither the plist nor its launcher names SKARBIEC_VAULT_FILE'
elif [ -f "$VAULT" ]; then
    note 'vault served' "$VAULT (from $VAULT_SOURCE)"
else
    fail 'vault served' "declared $VAULT, which does not exist"
fi

# 4. The local bind port the launcher reads, and whether anything answers there.
if [ -f "$FORWARD_FILE" ]; then
    ENDPOINT=$(cat "$FORWARD_FILE")
    LOCAL_CODE=$(probe "$ENDPOINT/")
    if ! reachable "$LOCAL_CODE"; then
        fail 'local bind endpoint' "$ENDPOINT from $FORWARD_FILE answers nothing"
    else
        note 'local bind endpoint' "$ENDPOINT answers, HTTP $LOCAL_CODE"
    fi
else
    fail 'local bind endpoint' "no forwards entry at $FORWARD_FILE"
fi

# 5. The stable address and identity the consumer was handed. A mismatch here
#    looks exactly like a broken vault and is really a broken address.
if [ -f "$ENV_FILE" ]; then
    STABLE_URL=$(awk -F'=' '/^WELES_CREDENTIAL_SKARBIEC_URL=/ { gsub(/"/, "", $2); print $2; exit }' "$ENV_FILE")
    if [ -z "$STABLE_URL" ]; then
        fail 'consumer stable port' "$ENV_FILE names no WELES_CREDENTIAL_SKARBIEC_URL"
    else
        STABLE_CODE=$(probe "$STABLE_URL/")
        if ! reachable "$STABLE_CODE"; then
            fail 'consumer stable port' "$STABLE_URL answers nothing; Stado's resolver exposes no adapter for it"
        else
            note 'consumer stable port' "$STABLE_URL answers, HTTP $STABLE_CODE"
        fi
    fi

    WORKLOAD=$(awk -F'=' '/^SKARBIEC_WORKLOAD_ID=/ { gsub(/"/, "", $2); print $2; exit }' "$ENV_FILE")
    if [ -z "$WORKLOAD" ]; then
        fail 'consumer authorization' "$ENV_FILE names no SKARBIEC_WORKLOAD_ID"
    elif stado resolver resolve "$SERVICE" --consumer "$WORKLOAD" >/dev/null; then
        note 'consumer authorization' "$WORKLOAD is authorized for $SERVICE"
    else
        fail 'consumer authorization' "$WORKLOAD is refused for $SERVICE by Stado's resolver"
    fi
else
    fail 'consumer env file' "no consumer env file at $ENV_FILE"
fi

printf '\n'
if [ -z "$BROKEN" ]; then
    printf '%s\n' "$SERVICE: the serving path is whole"
else
    printf '%s: %s broken link(s) marked above\n' "$SERVICE" "${#BROKEN}"
fi
