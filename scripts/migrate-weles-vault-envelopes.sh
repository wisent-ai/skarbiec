#!/bin/sh
# Finish the v1 to v2 envelope migration on the Weles vault this host serves.
#
# Why it is needed: token-mint refuses an item still in the v1 envelope with
# "item uses the legacy envelope (run migrate-v2)". On the always-on host that
# refusal blocks minting the acquisition reader the shipped scopes declare for
# weles-microsoft-primary-password, and the message names the remedy without
# naming which vault, which is why the blockage read as a missing item.
#
# Why it is safe to run here rather than deferred: `migrate-v2` writes a snapshot
# of the vault before touching it, to <vault>.pre-v2.<epoch> with owner-only mode,
# and refuses outright if that snapshot path already exists. Restoring is a copy
# back. The same migration was already performed elsewhere in this fleet, which is
# why an operator workstation carries skarbiec.vault.pre-v2-20260804.json, so this
# completes a migration rather than starting one.
#
# Reports the item, revision and grant counts it rewrote, and the snapshot path.
set -eu

# run-helper hands over a minimal environment, and the vault is PGP-encrypted, so
# gpg has to be reachable or the migration fails as "spawn gpg".
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"

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
    note 'vault' "absent at $VAULT; this host serves no Weles vault"
    exit
fi
note 'vault' "$VAULT"

export SKARBIEC_VAULT_FILE="$VAULT"
if [ -f "$UNLOCK" ]; then
    export SKARBIEC_UNLOCK_FILE="$UNLOCK"
fi

# A rewrite re-encrypts to every recipient the vault lists, so each recipient's
# public key has to be present or gpg fails with "No public key".
if [ -f "$RECOVERY_PUB" ]; then
    gpg --batch --quiet --import "$RECOVERY_PUB" || true
    note 'recovery recipient' 'public key imported'
fi

note 'before' "$("$BIN" status || true)"

# The migration refuses while a legacy grant names a field its item does not have:
#   legacy capability names weles-microsoft-primary-password#login_password;
#   canonical fields: value
# That grant can authorize nothing -- there is no such field to acquire -- so it is
# not a capability being taken away, it is a dangling reference being cleared. The
# same broken name is why the shipped scopes, which declare a reader for the field
# password, point at a consumer the vault does not carry. Revoking is reversible by
# minting again once the intended field is settled.
STALE_GRANT='weles-microsoft-primary-password-reader-login_password'
REVOKED=$("$BIN" token-revoke "$STALE_GRANT" || true)
case "$REVOKED" in
    '')
        note 'stale grant' "token-revoke $STALE_GRANT produced no output; read the error above"
        ;;
    *)
        note 'stale grant' "revoked $STALE_GRANT"
        ;;
esac

printf '\n'
"$BIN" migrate-v2
printf '\n'
note 'after' "$("$BIN" status || true)"
