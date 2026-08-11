#!/bin/sh
set -eu

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export SKARBIEC_VAULT_FILE="${SKARBIEC_VAULT_FILE:-$HOME/.stado/skarbiec.vault.json}"

action="${1:-pull}"
case "$action" in
  pull|push) ;;
  *) printf 'usage: %s [pull|push] [--force]\n' "$0" >&2; exit 2 ;;
esac

shift || true
exec "$HOME/.stado/bin/skarbiec" "sync-$action" "$@"
