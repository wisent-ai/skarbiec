#!/bin/sh
set -eu

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export SKARBIEC_VAULT_FILE="${SKARBIEC_VAULT_FILE:-$HOME/.stado/skarbiec.vault.json}"

exec "$HOME/.stado/bin/skarbiec" sync-pull
