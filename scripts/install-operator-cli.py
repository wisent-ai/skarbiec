#!/usr/bin/env python3
"""Put a delivered Skarbiec build in the operator bin, re-signed where it lands.

A repair that exists only in a file under `files/` is a trap: the operator runs
the command by its usual name, gets the old binary, and meets the old failure.
This promotes a delivered build to `$HOME/.stado/bin/skarbiec`, keeping the
previous one beside it under a `before-` name so the swap reverses with a copy.

Copying a linker-signed Mach-O invalidates its signature and macOS then kills
the process on exec without a message, so the binary is signed at its
destination rather than at its source.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

HOME = Path(os.environ.get("HOME", "."))
DELIVERED = HOME / ".stado" / "files" / os.environ.get(
    "OPERATOR_CLI_FILE", "skarbiec-with-migration-fix"
)
TARGET = HOME / ".stado" / "bin" / "skarbiec"
OWNER_EXECUTABLE = stat.S_IRWXU

if not DELIVERED.exists():
    raise SystemExit(f"delivered build is absent: {DELIVERED}")

if TARGET.exists():
    kept = TARGET.with_name(TARGET.name + ".before-migration-fix")
    shutil.copy2(TARGET, kept)
    print("kept:", kept)

shutil.copy(DELIVERED, TARGET)
os.chmod(TARGET, OWNER_EXECUTABLE)
signed = subprocess.run(
    ["/usr/bin/codesign", "--force", "--sign", "-", str(TARGET)],
    capture_output=True,
    text=True,
)
if signed.returncode:
    raise SystemExit(f"codesign failed: {(signed.stderr or signed.stdout).strip()}")

version = subprocess.run(
    [str(TARGET), "--version"], capture_output=True, text=True
)
print("installed:", TARGET)
print("version:", " ".join((version.stdout or version.stderr).split()))
