#!/usr/bin/env python3
"""Put the vault back the way the grant restore found it.

`restore-dropped-grants.py` writes a timestamped copy before it changes
anything. Merging a pre-migration snapshot's capability lists back can
reintroduce grants the migration superseded rather than dropped, which shows up
as duplicated subscription entries and redemptions denied for a mismatched
authorization. When that happens the answer is the copy, not another merge.

Read-only about everything except the vault it restores, and it refuses when no
backup from that tool is present.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import time

HOME = pathlib.Path(os.environ.get("HOME", "."))
VAULT = pathlib.Path(os.environ.get("SKARBIEC_VAULT_FILE", HOME / ".stado" / "skarbiec.vault.json"))

backups = sorted(
    VAULT.parent.glob(f"{VAULT.name}.before-grant-restore-*"),
    key=lambda path: path.stat().st_mtime,
)
if not backups:
    raise SystemExit(f"no grant-restore backup beside {VAULT}")

newest = backups[-len(["newest"])]
aside = VAULT.with_name(f"{VAULT.name}.before-revert-{int(time.time())}")
shutil.copy2(VAULT, aside)
shutil.copy2(newest, VAULT)
print("reverted from:", newest.name)
print("previous state kept at:", aside.name)
