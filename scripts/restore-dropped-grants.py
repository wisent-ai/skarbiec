#!/usr/bin/env python3
"""Put back capabilities that the envelope migration dropped.

The envelope migration rewrites every item into the current envelope and, since
the repair that let it finish, drops a grant whose canonical target it cannot
resolve instead of aborting the whole store. On this workstation that turned out
to be most of them, and the missing grants included the one the Jeden launcher
reads to obtain its model-router bearer.

Dropping was right for the migration -- it must not stop halfway -- but the
grants were never meant to disappear with it. This merges a pre-migration
snapshot's capability lists back into the migrated store, leaves the migrated
item envelopes untouched, and never removes a capability the store already has.

Usage: restore-dropped-grants.py <migrated-vault> <pre-migration-snapshot>
A timestamped backup of the vault is written before anything changes.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import time

INDENT = len("  ")
EXPECTED_ARGUMENTS = ["self", "vault", "snapshot"]


def coordinate(capability: dict) -> tuple:
    return (capability.get("item"), capability.get("field"), capability.get("action"))


def restore(vault_path: pathlib.Path, snapshot_path: pathlib.Path) -> None:
    vault = json.loads(vault_path.read_text())
    snapshot = json.loads(snapshot_path.read_text())

    stamp = str(int(time.time()))
    backup = vault_path.with_name(f"{vault_path.name}.before-grant-restore-{stamp}")
    shutil.copy2(vault_path, backup)

    restored = []
    touched = []
    readded = []
    for audience, old in snapshot.get("tokens", {}).items():
        current = vault.get("tokens", {}).get(audience)
        if current is None:
            # The migration dropped this consumer outright, not just its
            # grants. Skipping it left the Jeden first-use journey answering
            # 403 for a store that was supposed to have been repaired, so put
            # the record back whole. Both versions carry the same fields, and
            # the pre-migration record is the state the operator had.
            vault.setdefault("tokens", {})[audience] = old
            readded.append(audience)
            restored.extend(old.get("capabilities", []))
            continue
        present = {coordinate(item) for item in current.get("capabilities", [])}
        missing = [
            item for item in old.get("capabilities", [])
            if coordinate(item) not in present
        ]
        if missing:
            current.setdefault("capabilities", []).extend(missing)
            restored.extend(missing)
            touched.append(audience)

    vault_path.write_text(json.dumps(vault, indent=INDENT) + "\n")

    total = [item for token in vault["tokens"].values() for item in token.get("capabilities", [])]
    print("backup:", backup)
    print("consumers updated:", len(touched))
    print("consumers re-added:", len(readded))
    for audience in readded:
        print("  ", audience)
    print("capabilities restored:", len(restored))
    print("capabilities now:", len(total))


def newest_snapshot(vault_path: pathlib.Path) -> pathlib.Path:
    candidates = sorted(
        vault_path.parent.glob(f"{vault_path.name}.pre-v*"),
        key=lambda path: path.stat().st_mtime,
    )
    if not candidates:
        raise SystemExit(f"no pre-migration snapshot beside {vault_path}")
    return candidates[-len(["newest"])]


arguments = sys.argv[len(["self"]):]
if arguments:
    if len(arguments) != len(["vault", "snapshot"]):
        print(
            "usage: restore-dropped-grants.py [<migrated-vault> <pre-migration-snapshot>]",
            file=sys.stderr,
        )
        raise SystemExit(len(["usage error"]))
    vault = pathlib.Path(arguments[EXPECTED_ARGUMENTS.index("vault") - len(["self"])])
    snapshot = pathlib.Path(arguments[EXPECTED_ARGUMENTS.index("snapshot") - len(["self"])])
else:
    home = pathlib.Path(os.environ.get("HOME", "."))
    vault = pathlib.Path(
        os.environ.get("SKARBIEC_VAULT_FILE", home / ".stado" / "skarbiec.vault.json")
    )
    snapshot = newest_snapshot(vault)

restore(vault, snapshot)
