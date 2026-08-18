#!/usr/bin/env python3
"""Run one Skarbiec credential operation named entirely by a delivered request.

The operator delivers `$HOME/.stado/credential-operation-request.json` with
`operation`, `credential_id`, `provider` and `consumer`. Skarbiec owns the
operation: it submits the credential-operation wire to the configured Weles
bridge and then settles it with `credential status`. Nothing about a specific
account lives in this file, so one helper serves every account and every
operation the vault supports.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess

HOME = pathlib.Path.home()
REQUEST = HOME / ".stado/credential-operation-request.json"
BINARY = HOME / ".stado/bin/skarbiec"
VAULT = pathlib.Path(os.environ.get("SKARBIEC_VAULT_FILE", HOME / ".stado/skarbiec.vault.json"))
BRIDGE = pathlib.Path(
    os.environ.get(
        "SKARBIEC_WELES_CREDENTIAL_COMMAND",
        HOME / "weles/scripts/worker/deploy/weles-skarbiec-local.mjs",
    )
).resolve()
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
OPERATIONS = ("acquire", "rotate", "reset", "verify", "remove", "reauth")


def run(arguments: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(BINARY), *arguments],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={
            **os.environ,
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "SKARBIEC_VAULT_FILE": str(VAULT),
            "SKARBIEC_WELES_CREDENTIAL_COMMAND": str(BRIDGE),
        },
    )


def emit(label: str, result: subprocess.CompletedProcess) -> dict:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {"stdout": " ".join(result.stdout.split())[:400]}
    detail = " ".join(result.stderr.split())[:400]
    print(f"{label}: exit={result.returncode} {json.dumps(payload, ensure_ascii=False)[:600]}")
    if detail:
        print(f"{label} stderr: {detail}")
    return payload


def main() -> None:
    if not BINARY.is_file():
        raise SystemExit(f"no Skarbiec binary at {BINARY}")
    if not BRIDGE.is_file():
        raise SystemExit(f"no Weles credential bridge at {BRIDGE}")
    if not REQUEST.is_file():
        raise SystemExit(f"no delivered request at {REQUEST}")
    try:
        request = json.loads(REQUEST.read_text(encoding="utf-8"))
        if not isinstance(request, dict) or set(request) != {
            "operation",
            "credential_id",
            "provider",
            "consumer",
        }:
            raise SystemExit(
                "request must contain exactly operation, credential_id, provider and consumer"
            )
        operation = request["operation"]
        if operation not in OPERATIONS:
            raise SystemExit(f"operation must be one of {', '.join(OPERATIONS)}")
        for key in ("credential_id", "provider", "consumer"):
            if not isinstance(request[key], str) or not NAME.fullmatch(request[key]):
                raise SystemExit(f"{key} is not an exact name")
        submitted = emit(
            "submit",
            run(
                [
                    "credential",
                    operation,
                    request["credential_id"],
                    "--provider",
                    request["provider"],
                    "--consumer",
                    request["consumer"],
                    "--local",
                ],
                timeout=1500,
            ),
        )
        settled = emit(
            "status",
            run(["credential", "status", request["credential_id"], "--local"], timeout=300),
        )
        confirmed = settled.get("confirmed") is True or settled.get("status") == "completed"
        print(
            "verdict:",
            json.dumps(
                {
                    "operation": operation,
                    "credential": request["credential_id"],
                    "submitted": submitted.get("status"),
                    "settled": settled.get("status"),
                    "confirmed": confirmed,
                },
                ensure_ascii=False,
            ),
        )
        if not confirmed:
            raise SystemExit(1)
    finally:
        REQUEST.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
