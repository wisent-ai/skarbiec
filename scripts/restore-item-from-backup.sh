#!/bin/sh
# Restore one item into the live vault from a vault backup file on the same host.
#
#   restore-item-from-backup.sh <backup-vault.json> <item-id>
#
# Measured on charless-mac-mini on 2026-09-02: weles-figma-personal-access-token
# was acquired on 2026-08-12, served 24 acquisitions that day, and was present in
# skarbiec.vault.before-stado-local-agent-bearer-rotation.json (2026-08-17, 548
# items) — and absent from the live vault (603 items) with no delete, trash or
# purge entry for it in the audit journal. The live document was replaced by a
# sync that did not carry the host-local item, and the consumer grant
# (weles-figma-design-assets-exporter) survived, so every acquisition failed as
# `503 infra_down` (an existing grant whose item is gone) instead of `401`.
#
# The backup is ciphertext for the same owner key, so the value is readable only
# here, by the owner. It moves from `get` to `set-json` through a pipe and is
# never printed, never placed in an argument, and never written to a file. The
# original tags and recipients are carried over from the backup's envelope.
# Writing an item that already exists in the live vault is refused: this
# restores an absence, it does not roll a live credential back.
set -eu

backup=${1:?usage: restore-item-from-backup.sh <backup-vault.json> <item-id>}
item=${2:?usage: restore-item-from-backup.sh <backup-vault.json> <item-id>}

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PATH
SKARBIEC=${SKARBIEC_BIN:-"$HOME/.stado/bin/skarbiec"}
[ -x "$SKARBIEC" ] || SKARBIEC=$(command -v skarbiec || true)
[ -n "$SKARBIEC" ] && [ -x "$SKARBIEC" ] || {
  printf 'no skarbiec binary on this host\n' >&2
  exit 1
}
live=${SKARBIEC_VAULT_FILE:-"$HOME/.stado/skarbiec.vault.json"}
[ -f "$live" ] || { printf 'no live vault at %s\n' "$live" >&2; exit 1; }
[ -f "$backup" ] || { printf 'no backup vault at %s\n' "$backup" >&2; exit 1; }
case "$item" in
  *[!A-Za-z0-9._-]*|'') printf 'item id must be an exact name: %s\n' "$item" >&2; exit 1 ;;
esac

envelope() {
  SKARBIEC_VAULT_FILE="$1" "$SKARBIEC" list | /usr/bin/python3 -c '
import json, sys
wanted = sys.argv[1]
for entry in json.load(sys.stdin):
    if entry.get("id") == wanted:
        print(json.dumps({
            "present": True,
            "deleted": bool(entry.get("deleted")),
            "kind": entry.get("kind"),
            "tags": ",".join(entry.get("tags") or []),
            "recipients": ",".join(entry.get("recipients") or []),
        }))
        break
else:
    print(json.dumps({"present": False}))
' "$2"
}

live_state=$(envelope "$live" "$item")
case "$live_state" in
  *'"present": true'*)
    printf '%s already exists in %s; restore-item-from-backup restores an absence and never overwrites a live item (skarbiec restore-version rolls a live item back)\n' "$item" "$live" >&2
    exit 2 ;;
esac

backup_state=$(envelope "$backup" "$item")
case "$backup_state" in
  *'"present": true'*) ;;
  *) printf '%s is not in %s\n' "$item" "$backup" >&2; exit 1 ;;
esac
case "$backup_state" in
  *'"deleted": true'*) printf '%s is in the trash of %s; restore it there first\n' "$item" "$backup" >&2; exit 1 ;;
esac
kind=$(printf '%s' "$backup_state" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["kind"])')
tags=$(printf '%s' "$backup_state" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["tags"])')
recipients=$(printf '%s' "$backup_state" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["recipients"])')

# `get` emits the canonical payload (schema, kind, fields, context, extensions),
# which is exactly what `set-json` reads. The pipe is the only place the value is.
SKARBIEC_VAULT_FILE="$backup" "$SKARBIEC" get "$item" \
  | SKARBIEC_VAULT_FILE="$live" "$SKARBIEC" set-json "$item" --type "$kind" --tags="$tags" --recipients="$recipients" >/dev/null

restored=$(envelope "$live" "$item")
case "$restored" in
  *'"present": true'*) printf 'restored %s (%s) into %s from %s\n' "$item" "$kind" "$live" "$backup" ;;
  *) printf 'restore of %s did not land in %s\n' "$item" "$live" >&2; exit 1 ;;
esac
