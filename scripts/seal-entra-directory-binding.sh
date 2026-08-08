#!/bin/sh
# Seal one Entra directory binding into the Skarbiec vault this host serves, and
# mint the reader grant the shipped acquisition scopes name for it.
#
# Why a script and not two commands: the vault that matters lives on the always-on
# host, and `stado host install-helper` plus `run-helper` is the documented way to
# reach it. Sealing on an operator workstation writes the binding into that
# machine's vault instead, which is the mistake this repository's
# check-serving-path already reports as "this vault holds none".
#
# What a binding is: tenant id, principal object id and UPN for a directory
# identity. No password, no token, no secret material of any kind. The value the
# lifecycle later reads is staged separately, by whoever knows it.
#
# Correctness does not rest on these three values being right. The Entra
# trajectory asserts tid, oid and preferred_username against the claims of a live
# authenticated session before any password write, and refuses with
# ENTRA_IDENTITY_MISMATCH and providerEffect none when they disagree. A wrong
# binding stops the operation; it cannot rotate the wrong account.
#
# Idempotent: an existing identical binding, or an existing grant, is reported and
# left alone. Stderr is deliberately not silenced, so a refusal is visible rather
# than swallowed.
set -eu

# run-helper hands the script a minimal environment. The vault is PGP-encrypted,
# so skarbiec spawns gpg, and without homebrew on PATH that fails as
# "spawn gpg: No such file or directory" -- an error that reads like a missing
# vault rather than a missing binary. Mirror what the Skarbiec launcher exports.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"

CREDENTIAL='weles-microsoft-jakub-wisent-ai-password'
PROVIDER='microsoft_entra'
TENANT='23572277-0021-42ac-b2b9-10bd86c7d2af'
OBJECT_ID='4c888895-03cf-4ab1-a11e-46942c568217'
ACCOUNT_UPN='jakub@wisent.ai'
READER_CONSUMER='weles-microsoft-jakub-wisent-ai-password-reader-password'
FIELD='password'

BIN="$HOME/.stado/bin/skarbiec"
VAULT="$HOME/.stado/weles-skarbiec.vault.json"
UNLOCK="$HOME/.stado/weles-skarbiec-unlock"
TOKEN_OUT="$HOME/.stado/$READER_CONSUMER-skarbiec-token"

note() {
    printf '%-22s %s\n' "$1" "$2"
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
    note 'unlock' 'from the host unlock file'
else
    note 'unlock' "no unlock file at $UNLOCK; relying on the ambient environment"
fi

# A vault is re-encrypted to every recipient it lists, so a write needs each
# recipient's public key present here. The fleet vault names a recovery recipient
# whose public key this host does not carry, which makes the vault effectively
# read-only on its own machine and fails as "No public key" rather than as
# anything about recovery. The key is public material; importing it restores the
# ability to write a vault this host already serves.
RECOVERY_PUB="$HOME/.stado/bin/skarbiec-recovery-pub.asc"
if [ -f "$RECOVERY_PUB" ]; then
    gpg --batch --quiet --import "$RECOVERY_PUB" || true
    note 'recovery recipient' 'public key imported'
else
    note 'recovery recipient' "no key file at $RECOVERY_PUB; a write may fail as No public key"
fi

# 1. The directory binding.
BEFORE=$("$BIN" credential status "$CREDENTIAL" --local || true)
case "$BEFORE" in
    *"$OBJECT_ID"*)
        note 'directory binding' 'already sealed with this object id; left alone'
        ;;
    *)
        "$BIN" credential seal-directory "$CREDENTIAL" \
            --provider "$PROVIDER" \
            --tenant "$TENANT" \
            --object-id "$OBJECT_ID" \
            --account-upn "$ACCOUNT_UPN" \
            --local
        note 'directory binding' 'sealed'
        ;;
esac

# 2. The reader grant the deployed scopes name. Without it the scope line points
#    at a consumer that does not exist here and every read throws.
#
#    An acquisition reader is not a bearer-token grant: `acquire` capabilities
#    mint no token at all, because the workload proves itself by signing each
#    request with its own key. So the grant records the workload's public key and
#    the exact item#field, and nothing secret is written out.
WORKLOAD_PUB="$HOME/.stado/weles-credential-workload-public.pem"
WORKLOAD_KEY="$HOME/.stado/weles-credential-workload-private.pem"

# The grant records the workload's public half. A host that holds only the signing
# key still has everything needed, because the public key is derivable from it --
# and deriving is safer than shipping one, since a mismatched public key would mint
# a grant no signature can ever satisfy.
if [ ! -f "$WORKLOAD_PUB" ] && [ -f "$WORKLOAD_KEY" ]; then
    openssl pkey -in "$WORKLOAD_KEY" -pubout -out "$WORKLOAD_PUB"
    note 'workload public key' "derived from $WORKLOAD_KEY"
fi
# Skarbiec refuses a key file the rest of the machine can touch, and reports it as
# "must be an owner-controlled regular file" -- which reads like the wrong path
# rather than the wrong mode. openssl writes with the ambient umask, so narrow it.
if [ -f "$WORKLOAD_PUB" ]; then
    chmod go-rwx "$WORKLOAD_PUB"
fi

# Minting is the same work for every credential the shipped scopes declare with
# the password field, so it is written once and applied to each. The consumer
# Microsoft account needs it as much as the directory identity: the fleet vault
# carries a grant minted for the field login_password, while the scopes shipped
# inside the release name a consumer for the field password. Those are two
# different consumer names, so the scope line points at a grant that is not there,
# and the read throws before any password is involved.
mint_reader() {
    item="$1"
    consumer="$item-reader-$FIELD"
    if [ ! -f "$WORKLOAD_PUB" ]; then
        note 'reader grant' "no workload key material at $WORKLOAD_KEY or $WORKLOAD_PUB"
        return
    fi
    minted=$("$BIN" token-mint "$consumer" \
        --capabilities "acquire:$item#$FIELD" \
        --workload-public-key-file "$WORKLOAD_PUB" \
        --local || true)
    case "$minted" in
        '')
            # Two causes seen in practice, and the message names neither on its
            # own: an item still in the v1 envelope, which token-mint refuses with
            # "run migrate-v2", and a capability whose field the item does not
            # allow. A whole-vault envelope migration on an always-on host is not
            # something this helper performs.
            note "grant $item" 'refused; the error above names the cause, often a legacy v1 envelope'
            ;;
        *)
            note "grant $item" 'minted or already current'
            ;;
    esac
}

mint_reader "$CREDENTIAL"
mint_reader 'weles-microsoft-primary-password'

printf '\n'
"$BIN" credential status "$CREDENTIAL" --local
