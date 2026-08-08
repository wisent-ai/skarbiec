#!/usr/bin/env python3
"""Rehearse `migrate-v2` on a throwaway copy and report what it would change.

The live store is gated: a write needs the owner's recorded words. The guard
names the way to test the change anyway -- run it against a store under a
temporary directory -- so the claim "migrating this item restores the provider"
can be a measurement instead of a prediction.

Copies the vault to a temporary directory, migrates the copy, reports each
formerly legacy item's envelope and whether it reads afterwards, then deletes
the copy. The real store is opened read-only and never written.

Prints item ids, envelope shape and field names, never a value.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

HOME = Path(os.environ.get("HOME", "."))
SKARBIEC = Path(os.environ.get("SKARBIEC_BIN", str(HOME / ".stado" / "bin" / "skarbiec")))
SOURCE = Path(
    os.environ.get("SKARBIEC_VAULT_FILE", str(HOME / ".stado" / "skarbiec.vault.json"))
)


def legacy_ids(document: dict) -> list[str]:
    items = document.get("items") or {}
    return sorted(
        item_id
        for item_id, entry in items.items()
        if isinstance(entry, dict)
        and (entry.get("format") is None or not isinstance(entry.get("current"), dict))
    )


document = json.loads(SOURCE.read_text())
before = legacy_ids(document)
print("source:", SOURCE)
print("legacy before:", before or "none")
if not before:
    raise SystemExit("nothing to rehearse")

workspace = Path(tempfile.mkdtemp(prefix="skarbiec-rehearsal-"))
try:
    copy = workspace / "skarbiec.vault.json"
    shutil.copy2(SOURCE, copy)
    environment = {
        **os.environ,
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "SKARBIEC_VAULT_FILE": str(copy),
    }
    migrated = subprocess.run(
        [str(SKARBIEC), "migrate-v2"],
        capture_output=True,
        text=True,
        env=environment,
    )
    print("migrate exit:", migrated.returncode)
    detail = " ".join((migrated.stdout or migrated.stderr or "").split())
    if detail:
        print("  said:", detail)
    after = legacy_ids(json.loads(copy.read_text()))
    print("legacy after:", after or "none")
    for item_id in before:
        opened = subprocess.run(
            [str(SKARBIEC), "get", item_id],
            capture_output=True,
            text=True,
            env=environment,
        )
        if opened.returncode:
            print(f"  {item_id}: still unreadable:", " ".join((opened.stderr or "").split()))
            continue
        fields = sorted((json.loads(opened.stdout).get("fields") or {}))
        print(f"  {item_id}: reads, fields={fields}")
finally:
    shutil.rmtree(workspace, ignore_errors=True)
    print("rehearsal copy removed:", workspace)
