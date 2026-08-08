#!/bin/sh
# Bring the consumer Microsoft credential under Skarbiec management using the value
# the vault on this host already holds, without the value ever being printed.
#
# Why this is needed: the item stores its password under the field `value`, while
# every Microsoft lifecycle reads the canonical field `password`
# (wire.rs contract_field). So the scopes resolve, the grant exists, and the read
# still finds nothing. `credential adopt` is the one operation that writes the
# canonical field, and by design it takes the current password on stdin: mod.rs
# records that adopt is absent from the remote endpoint on purpose, because the
# current password is read from operator stdin and never travels.
#
# Why it is safe: adopt has provider effect none. It records and proves; it never
# writes to Microsoft. Nothing about the account changes here. The value moves from
# one field of one item to the canonical field of the same item, on the same host,
# through a pipe -- it is not read into any transcript, not echoed, and not written
# to any file.
#
# Idempotent: an item already in the managed state is reported and left alone.
#
# What running it establishes, and why it stops short. Skarbiec refuses with
# CREDENTIAL_FIELD_CONTRACT_MISMATCH: the item "carries value and no password, but
# the microsoft credential contract writes password. Skarbiec adds no alias and
# writes no second field beside value: migrate the item to password as an explicit
# operator decision before any lifecycle operation". So the field migration is a
# decision the tool reserves to a person, not a step an agent may infer, and this
# script deliberately does not force it: anything still reading `value` would be
# reading a field that no longer holds the live password.
#
# A second, separate obstacle surfaces in the same run: the item carries a
# credential operation record from an older wire version, and `credential status`
# reports "unsupported wire version; expected skarbiec.credential-operation.v3".
# That stale record predates this work and blocks status on the item.
set -eu

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"

CREDENTIAL='weles-microsoft-primary-password'
LEGACY_FIELD='value'
PROVIDER='microsoft'
ACCOUNT='lukasz.bartoszcze@gmail.com'
WRITER_CONSUMER='weles-microsoft-primary-password-writer'

BIN="$HOME/.stado/bin/skarbiec"
VAULT="$HOME/.stado/weles-skarbiec.vault.json"
UNLOCK="$HOME/.stado/weles-skarbiec-unlock"
RECOVERY_PUB="$HOME/.stado/bin/skarbiec-recovery-pub.asc"

note() {
    printf '%-22s %s\n' "$1" "$2"
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

STATE=$("$BIN" credential status "$CREDENTIAL" --local || true)
case "$STATE" in
    *'"lifecycle_state": "managed"'*)
        note 'lifecycle state' 'already managed; left alone'
        printf '%s\n' "$STATE"
        exit
        ;;
    *)
        note 'lifecycle state' 'not managed; adopting from the stored value'
        ;;
esac

# One pipeline, so the value has no name and touches no file. A failure on either
# side leaves the item exactly as it was, because adopt stages nothing it could not
# read.
if "$BIN" get "$CREDENTIAL" "$LEGACY_FIELD" | "$BIN" credential adopt "$CREDENTIAL" \
    --provider "$PROVIDER" \
    --account "$ACCOUNT" \
    --consumer "$WRITER_CONSUMER" \
    --password-stdin \
    --local; then
    note 'adopt' 'staged the canonical field from the stored value'
else
    note 'adopt' 'refused; the error above names the cause'
fi

printf '\n'
"$BIN" credential status "$CREDENTIAL" --local
