#!/usr/bin/env python3
"""Migrate this host's vault to the v2 envelope and report what changed.

`get_item` refuses a pre-v2 item outright, so every credential still in that
shape is invisible to the services that read the store. The command that fixes
it writes a `pre-v2` snapshot beside the vault before touching anything, so the
step reverses by putting that file back.

Reports the legacy items before and after, and the migration's own summary.
Prints item ids and counts, never a value.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

HOME = Path(os.environ.get("HOME", "."))
SKARBIEC = Path(os.environ.get("SKARBIEC_BIN", str(HOME / ".stado" / "bin" / "skarbiec")))
VAULT = Path(
    os.environ.get("SKARBIEC_VAULT_FILE", str(HOME / ".stado" / "skarbiec.vault.json"))
)


def legacy_ids() -> list[str]:
    items = (json.loads(VAULT.read_text()).get("items") or {})
    return sorted(
        item_id
        for item_id, entry in items.items()
        if isinstance(entry, dict)
        and (entry.get("format") is None or not isinstance(entry.get("current"), dict))
    )


before = legacy_ids()
print("vault:", VAULT)
print("legacy before:", before or "none")
if not before:
    raise SystemExit("already migrated")

environment = {
    **os.environ,
    "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "SKARBIEC_VAULT_FILE": str(VAULT),
}
done = subprocess.run(
    [str(SKARBIEC), "migrate-v2"],
    capture_output=True,
    text=True,
    env=environment,
)
print("migrate exit:", done.returncode)
detail = " ".join((done.stdout or "").split())
if detail:
    print("  summary:", detail)
for line in (done.stderr or "").splitlines():
    print("  note:", line)

after = legacy_ids()
print("legacy after:", after or "none")
for item_id in before:
    opened = subprocess.run(
        [str(SKARBIEC), "get", item_id], capture_output=True, text=True, env=environment
    )
    if opened.returncode:
        print(f"  {item_id}: unreadable:", " ".join((opened.stderr or "").split()))
    else:
        print(f"  {item_id}: reads, fields=", sorted((json.loads(opened.stdout).get("fields") or {})))
