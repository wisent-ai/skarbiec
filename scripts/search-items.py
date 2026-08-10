#!/usr/bin/env python3
"""Search this vault by item id, tags, and decrypted context - never by value.

`list` sees only the plaintext envelope: id, kind, tags, recipients. The context
that says which account or service a credential belongs to lives inside the
ciphertext, so no grant holder can search it and no listing can index it. An
owner holding the key can, and that is what this does: it opens each item
locally, matches the query against the id, tags, field names and context, and
reports the coordinates.

Field values are read to prove decryptability and are never printed.

    python3 scripts/search-items.py gmail
    python3 scripts/search-items.py --fast google      # envelope only, no keys
    python3 scripts/search-items.py --json workspace
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HOME = Path(os.environ.get("HOME", "."))
SKARBIEC = Path(os.environ.get("SKARBIEC_BIN", HOME / ".stado" / "bin" / "skarbiec"))
VAULT = Path(
    os.environ.get("SKARBIEC_VAULT_FILE", HOME / ".stado" / "skarbiec.vault.json")
)
ENVIRONMENT = {
    **os.environ,
    "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "SKARBIEC_VAULT_FILE": str(VAULT),
}


def envelope_rows() -> list[dict[str, object]]:
    listed = subprocess.run(
        [str(SKARBIEC), "list"], capture_output=True, text=True, env=ENVIRONMENT, check=False
    )
    if listed.returncode:
        raise SystemExit(f"cannot list the vault: {listed.stderr.strip()[:200]}")
    return [row for row in json.loads(listed.stdout) if not row.get("deleted")]


def open_item(identifier: str) -> dict[str, object] | None:
    got = subprocess.run(
        [str(SKARBIEC), "get", identifier],
        capture_output=True,
        text=True,
        env=ENVIRONMENT,
        check=False,
    )
    if got.returncode:
        return None
    try:
        return json.loads(got.stdout)
    except json.JSONDecodeError:
        return None


def context_matches(context: dict[str, object], pattern: re.Pattern[str]) -> dict[str, str]:
    matched: dict[str, str] = {}
    for key, value in context.items():
        rendered = value if isinstance(value, str) else json.dumps(value)
        if pattern.search(key) or pattern.search(rendered):
            matched[key] = rendered
    return matched


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("query", help="case-insensitive regular expression")
    parser.add_argument("--fast", action="store_true", help="match the envelope only; open no item")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit machine-readable results")
    arguments = parser.parse_args()

    pattern = re.compile(arguments.query, re.IGNORECASE)
    results: list[dict[str, object]] = []
    undecryptable: list[str] = []

    for row in envelope_rows():
        identifier = str(row.get("id") or "")
        tags = [str(tag) for tag in (row.get("tags") or [])]
        envelope_hit = bool(pattern.search(identifier)) or any(pattern.search(tag) for tag in tags)

        context_hit: dict[str, str] = {}
        field_names: list[str] = []
        if not arguments.fast:
            document = open_item(identifier)
            if document is None:
                if envelope_hit:
                    undecryptable.append(identifier)
                continue
            field_names = sorted((document.get("fields") or {}).keys())
            context = document.get("context")
            if isinstance(context, dict):
                context_hit = context_matches(context, pattern)

        if not envelope_hit and not context_hit:
            continue
        results.append(
            {
                "id": identifier,
                "kind": row.get("kind"),
                "tags": tags,
                "fields": field_names,
                "matched_context": context_hit,
                "matched_on": "envelope" if envelope_hit else "context",
            }
        )

    results.sort(key=lambda entry: str(entry["id"]))
    if arguments.as_json:
        print(json.dumps({"query": arguments.query, "results": results, "undecryptable": undecryptable}, indent=2))
        return 0

    print(f"{len(results)} item(s) match {arguments.query!r}")
    for entry in results:
        print(f"\n  {entry['id']}")
        print(f"    kind: {entry['kind']}  tags: {','.join(entry['tags']) or '-'}")
        if entry["fields"]:
            print(f"    fields: {','.join(entry['fields'])}")
        for key, value in (entry["matched_context"] or {}).items():
            print(f"    context.{key}: {value}")
    if undecryptable:
        print(f"\n{len(undecryptable)} matching item(s) could not be opened with the local key:")
        for identifier in undecryptable:
            print(f"  {identifier}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
