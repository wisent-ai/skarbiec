#!/usr/bin/env python3
"""Print the command names advertised by `skarbiec help` without executing code."""

import json
import pathlib
import re

source = pathlib.Path(__file__).resolve().parents[1] / "src" / "main.rs"
text = source.read_text(encoding="utf-8")
matches = re.findall(r'json!\(\{"commands":\s*(\[[^]]+\])\}\)', text)
if len(matches) != 1:
    raise SystemExit(f"expected exactly one advertised command array in {source}, found {len(matches)}")
commands = json.loads(matches[0])
if not commands or any(not isinstance(command, str) or not command for command in commands):
    raise SystemExit("advertised command surface must contain non-empty strings")
if len(commands) != len(set(commands)):
    raise SystemExit("advertised command surface contains duplicates")
print(json.dumps({"surface": sorted(commands)}, separators=(",", ":")))
