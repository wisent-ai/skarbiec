#!/usr/bin/env python3
"""Compare a vault's capabilities against its pre-migration snapshot.

The envelope migration drops a grant whose canonical target it cannot resolve.
That keeps the migration from stopping halfway, and it silently reduces what
every consumer may read. This prints the before and after counts so the loss is
visible instead of being discovered by a service that suddenly cannot read its
own credential.

Read-only.
"""
from __future__ import annotations

import json
import os
import pathlib

HOME = pathlib.Path(os.environ.get("HOME", "."))
VAULT = pathlib.Path(os.environ.get("SKARBIEC_VAULT_FILE", HOME / ".stado" / "skarbiec.vault.json"))


def capabilities(document: dict) -> list:
    return [
        item
        for token in document.get("tokens", {}).values()
        for item in token.get("capabilities", [])
    ]


snapshots = sorted(VAULT.parent.glob(f"{VAULT.name}.pre-v*"), key=lambda p: p.stat().st_mtime)
print("vault:", VAULT)
if not VAULT.exists():
    raise SystemExit("vault not found")

live = json.loads(VAULT.read_text())
print("consumers:", len(live.get("tokens", {})))
print("capabilities now:", len(capabilities(live)))

if not snapshots:
    print("no pre-migration snapshot beside it")
else:
    newest = snapshots[-len(["newest"])]
    before = json.loads(newest.read_text())
    print("snapshot:", newest.name)
    print("capabilities then:", len(capabilities(before)))
    live_pairs = {
        (audience, item.get("item"), item.get("field"), item.get("action"))
        for audience, token in live.get("tokens", {}).items()
        for item in token.get("capabilities", [])
    }
    lost = [
        (audience, item.get("item"), item.get("field"))
        for audience, token in before.get("tokens", {}).items()
        for item in token.get("capabilities", [])
        if (audience, item.get("item"), item.get("field"), item.get("action")) not in live_pairs
    ]
    print("capabilities lost:", len(lost))
    for audience, item, field in lost[: len("abcdefghijkl")]:
        print(f"  {audience} -> {item}#{field}")
