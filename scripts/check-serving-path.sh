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
REGISTRY="$HOME/.stado/local-storage/registry.json"
PROBE_TIMEOUT='5'

# Stado places a logical service on exactly one host. Checking the wrong machine
# is the failure this script exists to prevent and once caused itself: run on a
# laptop, it reported a disabled launchd service and a dead stable port as broken
# links, when both were correct there because the service lives on the always-on
# host. Read the placement first and say so before reporting anything else.
ACTIVE_HOST=$(awk -v service="\"$SERVICE\":" '
    index($0, service) { inside = "yes"; next }
    inside == "yes" && /"active_host"/ {
        line = $0
        sub(/^[^:]*:[[:space:]]*"/, "", line)
        sub(/".*$/, "", line)
        print line
        exit
    }
    inside == "yes" && /^      }/ { exit }
' "$REGISTRY")
# hostname -s answers with the shell's own capitalisation, which is not the
# registry's: charless-mac-mini and Charless-Mac-mini are one machine, and
# comparing them literally made this script announce it was on the wrong host
# while standing on the right one.
THIS_HOST=$(hostname -s | tr '[:upper:]' '[:lower:]')
ACTIVE_HOST_KEY=$(printf '%s' "$ACTIVE_HOST" | tr '[:upper:]' '[:lower:]')

if [ -z "$ACTIVE_HOST" ]; then
    printf '%-26s %s\n' 'placement' "$REGISTRY declares no active_host for $SERVICE"
elif [ "$ACTIVE_HOST_KEY" = "$THIS_HOST" ]; then
    printf '%-26s %s\n' 'placement' "$SERVICE belongs here ($ACTIVE_HOST)"
else
    printf '%-26s %s\n' 'placement' "$SERVICE belongs on $ACTIVE_HOST, and this is $THIS_HOST"
    printf '%s\n' "Every check below describes $THIS_HOST, where this service is not"
    printf '%s\n' "supposed to run, so a disabled unit and a dead port are correct here."
    printf '%s\n' "Install this script on $ACTIVE_HOST and run it there:"
    printf '%s\n' "  stado host install-helper $ACTIVE_HOST $0 check-serving-path"
    printf '%s\n' "  stado host run-helper $ACTIVE_HOST check-serving-path"
    printf '\n'
fi

# The unit label comes from the registry, never from the service name. An
# always-on host runs /Library/LaunchDaemons/com.wisent.always-on.<service> and a
# workstation runs a user agent named com.wisent.compute.service.com.wisent.<service>,
# so guessing one shape reported a healthy system daemon as an absent agent.
MANAGED=$(awk -v service="\"$SERVICE\":" '
    index($0, service) { inside = "yes"; next }
    inside == "yes" && /"managed_service"/ {
        line = $0
        sub(/^[^:]*:[[:space:]]*"/, "", line)
        sub(/".*$/, "", line)
        print line
        exit
    }
    inside == "yes" && /^      }/ { exit }
' "$REGISTRY")
LABEL="${MANAGED:-com.wisent.compute.service.com.wisent.$SERVICE}"
if [ -f "/Library/LaunchDaemons/$LABEL.plist" ]; then
    PLIST="/Library/LaunchDaemons/$LABEL.plist"
else
    PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
fi
FORWARD_FILE="$HOME/.stado/forwards/$SERVICE.local"
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

# 1 and 2. Whether launchd has the unit enabled, and whether it runs.
#
#    Only a user agent can be answered here. A unit under /Library/LaunchDaemons
#    lives in launchd's system domain, which a user session may not query --
#    `launchctl print-disabled gui/501` simply omits it and `launchctl list` never
#    shows it, which this script first reported as "no launchd record" and "not
#    loaded" for a daemon that was serving requests the whole time. A daemon whose
#    endpoint answers is running, and that is checked below on evidence rather than
#    on a query this process cannot make.
case "$PLIST" in
    /Library/LaunchDaemons/*)
        note 'launchd domain' "system daemon; user sessions cannot read its state"
        note 'launchd state' "ask the owner: stado service status $LABEL --host $ACTIVE_HOST"
        ;;
    *)
        DISABLED_STATE=$(launchctl print-disabled "gui/$(id -u)" |
            awk -v label="\"$LABEL\"" '$1 == label { print $3 }')
        if [ "${DISABLED_STATE:-absent}" = 'enabled' ]; then
            note 'launchd enablement' 'enabled'
        elif [ "${DISABLED_STATE:-absent}" = 'disabled' ]; then
            fail 'launchd enablement' "disabled by an operator; undo with: launchctl enable gui/$(id -u)/$LABEL"
        else
            fail 'launchd enablement' "no launchd record for $LABEL"
        fi

        SERVICE_PID=$(launchctl list | awk -v label="$LABEL" '$3 == label { print $1 }')
        if [ -z "$SERVICE_PID" ]; then
            fail 'launchd process' "not loaded; bootstrap with: launchctl bootstrap gui/$(id -u) $PLIST"
        elif [ "$SERVICE_PID" = '-' ]; then
            fail 'launchd process' 'loaded but not running; read the service log for its exit reason'
        else
            note 'launchd process' "running, pid $SERVICE_PID"
        fi
        ;;
esac

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

# 4. Where the service actually binds. A workstation keeps that in a forwards
#    entry the launcher reads; an always-on host has none, and the registry's own
#    endpoint for this host is the declaration. Treating a missing forwards file
#    as a broken link reported the always-on host as broken when it was serving.
ENDPOINT=''
ENDPOINT_SOURCE=''
if [ -f "$FORWARD_FILE" ]; then
    ENDPOINT=$(cat "$FORWARD_FILE")
    ENDPOINT_SOURCE="$FORWARD_FILE"
else
    ENDPOINT=$(awk -v service="\"$SERVICE\":" -v host="\"$ACTIVE_HOST\":" '
        index($0, service) { inside = "yes"; next }
        inside == "yes" && index($0, host) { athost = "yes"; next }
        athost == "yes" && /"url"/ {
            line = $0
            sub(/^[^:]*:[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }
        inside == "yes" && /^      }/ { exit }
    ' "$REGISTRY")
    ENDPOINT_SOURCE="registry endpoint for $ACTIVE_HOST"
fi
if [ -z "$ENDPOINT" ]; then
    fail 'service endpoint' "neither $FORWARD_FILE nor the registry names an endpoint"
else
    LOCAL_CODE=$(probe "$ENDPOINT/")
    if ! reachable "$LOCAL_CODE"; then
        fail 'service endpoint' "$ENDPOINT from $ENDPOINT_SOURCE answers nothing"
    else
        note 'service endpoint' "$ENDPOINT answers, HTTP $LOCAL_CODE ($ENDPOINT_SOURCE)"
    fi
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

    # The worker never calls the resolver directly: it connects to the stable port,
    # and the adapter behind that port performs the resolution under the consumer
    # the registry declares for it. So a direct resolve with the worker's own
    # workload id proves nothing about the worker, and reporting it as a broken
    # link is how this script first accused a healthy path. Report the identity and
    # the adapter's declared consumer side by side instead.
    WORKLOAD=$(awk -F'=' '/^SKARBIEC_WORKLOAD_ID=/ { gsub(/"/, "", $2); print $2; exit }' "$ENV_FILE")
    ADAPTER_CONSUMER=$(awk -v service="\"service\": \"$SERVICE\"" '
        index($0, service) { inside = "yes"; next }
        inside == "yes" && /"consumer"/ {
            line = $0
            sub(/^[^:]*:[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }
    ' "$REGISTRY")
    if [ -z "$WORKLOAD" ]; then
        fail 'workload identity' "$ENV_FILE names no SKARBIEC_WORKLOAD_ID"
    else
        note 'workload identity' "$WORKLOAD writes as itself, reads through the adapter"
    fi
    if [ -z "$ADAPTER_CONSUMER" ]; then
        fail 'adapter consumer' "$REGISTRY declares no adapter consumer for $SERVICE"
    else
        note 'adapter consumer' "$ADAPTER_CONSUMER, as declared for the stable port"
    fi

    # Reaching the vault is not the same as being allowed to do the work: a worker
    # whose allowlist omits the credential actions claims none of them, and a
    # queued operation simply never runs.
    #
    # The launcher is the authority, not the env file. launch-mac.sh and launch.sh
    # both `unset WELES_ACTION_ALLOWLIST` and rebuild it from
    # weles/scripts/worker/deploy/weles-action-allowlist.txt in the deployed
    # checkout, so the copy sitting in the env file is discarded at startup.
    # Reading the env file reported an allowlist the worker never uses.
    ALLOWLIST_FILE="$HOME/weles/scripts/worker/deploy/weles-action-allowlist.txt"
    if [ -f "$ALLOWLIST_FILE" ]; then
        ALLOWLIST=$(awk 'NF { printf "%s,", $0 }' "$ALLOWLIST_FILE")
        ALLOWLIST_SOURCE="$ALLOWLIST_FILE, which the launcher rebuilds from"
    else
        ALLOWLIST=$(awk -F'=' '/^WELES_ACTION_ALLOWLIST=/ { gsub(/"/, "", $2); print $2; exit }' "$ENV_FILE")
        ALLOWLIST_SOURCE="$ENV_FILE, with no deployed checkout to override it"
    fi
    CREDENTIAL_ACTIONS=$(printf '%s' "$ALLOWLIST" | tr ',' '\n' | awk '/password/ { printf "%s ", $0 }')
    if [ -z "$ALLOWLIST" ]; then
        fail 'credential actions' "no allowlist in $ALLOWLIST_SOURCE, so the worker claims nothing"
    elif [ -z "$CREDENTIAL_ACTIONS" ]; then
        fail 'credential actions' "no password action in $ALLOWLIST_SOURCE"
    else
        note 'credential actions' "$CREDENTIAL_ACTIONS"
        note 'allowlist source' "$ALLOWLIST_SOURCE"
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
