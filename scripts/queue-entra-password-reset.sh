#!/bin/sh
# Attempt the one Entra lifecycle operation that does not require knowing the
# current password, and report exactly what Skarbiec says.
#
# Why attempt rather than conclude: a comment in state.rs says rotate, reset and
# verify "stage against a live managed item", and from that I concluded for many
# turns that reset is impossible while the item is unmanaged. That was inference,
# not evidence, and this session has shown repeatedly that my inferences about what
# is impossible are wrong. The refusal, if it comes, is the fact worth having, and
# it will name its own reason.
#
# Why reset and not rotate: rotate demands the known managed password so a
# compensating rollback exists. reset is the operation written for an unknown
# current password, and the trajectory behind it hands every interactive identity
# verification to a human instead of pretending to satisfy it, so it cannot
# complete silently.
#
# What it found, on charless-mac-mini, exit status 1:
#
#   Error: weles-microsoft-jakub-wisent-ai-password is not an active
#   Weles-managed credential; refusing external reset
#
# So the inference was right and is now evidence: reset needs an item already
# active and managed, managed state is entered only through adopt, and adopt reads
# the current password from operator stdin. Every Entra lifecycle path leads back
# to a value only the account holder has, and this script exists so nobody has to
# take that on trust again -- it is idempotent and changes nothing when it runs.
set -eu

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"

CREDENTIAL='weles-microsoft-jakub-wisent-ai-password'
PROVIDER='microsoft_entra'
CONSUMER='weles-microsoft-jakub-wisent-ai-password-reader-password'
PURPOSE='entra-admin-password-rotation'

BIN="$HOME/.stado/bin/skarbiec"
VAULT="$HOME/.stado/weles-skarbiec.vault.json"
UNLOCK="$HOME/.stado/weles-skarbiec-unlock"
RECOVERY_PUB="$HOME/.stado/bin/skarbiec-recovery-pub.asc"

note() {
    printf '%-20s %s\n' "$1" "$2"
}

if [ ! -x "$BIN" ]; then
    note 'skarbiec binary' "not executable at $BIN"
    exit
fi
if [ ! -f "$VAULT" ]; then
    note 'vault' "absent at $VAULT"
    exit
fi
note 'vault' "$VAULT"

export SKARBIEC_VAULT_FILE="$VAULT"
if [ -f "$UNLOCK" ]; then
    export SKARBIEC_UNLOCK_FILE="$UNLOCK"
fi
if [ -f "$RECOVERY_PUB" ]; then
    gpg --batch --quiet --import "$RECOVERY_PUB" || true
fi

note 'attempting' "credential reset $CREDENTIAL"
printf '\n'
# The exit status is captured alongside the message. Skarbiec was never silent here:
# the refusal went to stderr and a narrow window over the output hid it, which is
# worth stating because the missing line was mine and not the tool's.
RESET_STATUS='0'
"$BIN" credential reset "$CREDENTIAL" \
    --provider "$PROVIDER" \
    --consumer "$CONSUMER" \
    --purpose "$PURPOSE" \
    --local || RESET_STATUS="$?"
note 'reset exit status' "$RESET_STATUS"
printf '\n'
"$BIN" credential status "$CREDENTIAL" --local
