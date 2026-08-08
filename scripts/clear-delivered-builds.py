#!/usr/bin/env python3
"""Remove delivered build copies once the operator binary carries the fix.

A build parked under `files/` is useful exactly until it is promoted, and
harmful afterwards: tooling that prefers a delivered copy keeps testing that
copy instead of the binary the operator actually runs, so the verification and
the reality drift apart while both look green.

Removes only the copies this session delivered, and only when the promoted
binary exists. Prints what it removed.
"""
from __future__ import annotations

import os
from pathlib import Path

HOME = Path(os.environ.get("HOME", "."))
FILES = HOME / ".stado" / "files"
PROMOTED = HOME / ".stado" / "bin" / "skarbiec"
DELIVERED = ("skarbiec-migrate-fix", "skarbiec-with-migration-fix")

print("promoted binary:", PROMOTED, "exists:", PROMOTED.exists())
if not PROMOTED.exists():
    raise SystemExit("nothing promoted; keeping the delivered copies")

for name in DELIVERED:
    candidate = FILES / name
    if candidate.exists():
        candidate.unlink()
        print("removed:", candidate)
    else:
        print("absent:", candidate)
