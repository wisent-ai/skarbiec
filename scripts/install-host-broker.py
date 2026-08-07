#!/usr/bin/env python3
"""Put a transferred Skarbiec release into the host's operator bin directory.

A broker binary older than the launchers that drive it fails as
`unknown command: capability-issue`, which reads like a policy refusal and is
actually a version skew — the shape that took the always-on gateway down. This
installs an already-transferred release archive over `~/.stado/bin/skarbiec`,
keeps the replaced binary beside it, and proves the new one answers the verb.

Set SKARBIEC_RELEASE_VERSION to the version passed to `stado host
install-release`.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

HOME = Path(os.environ.get("HOME", "."))
VERSION = os.environ.get("SKARBIEC_RELEASE_VERSION", "")
PLATFORM = os.environ.get("SKARBIEC_RELEASE_PLATFORM", "darwin-arm64")
FAMILY = "skarbiec"
BIN_DIR = HOME / ".stado" / "bin"
TARGET = BIN_DIR / "skarbiec"
VERB = "capability-issue"
OWNER_EXECUTABLE = (
    stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
)

# `stado host run-helper` does not carry the caller's environment to the host,
# so a helper that demands a version variable can never be run through the
# sanctioned channel. Take the newest transferred archive unless the host's own
# environment names an exact one.
RELEASES = HOME / ".stado" / "releases" / FAMILY
if VERSION:
    archive = RELEASES / VERSION / PLATFORM / f"{FAMILY}.tar.gz"
else:
    candidates = sorted(
        RELEASES.glob(f"*/{PLATFORM}/{FAMILY}.tar.gz"),
        key=lambda path: path.stat().st_mtime,
    )
    if not candidates:
        raise SystemExit(f"no transferred {FAMILY} release under {RELEASES}")
    archive = candidates.pop()
    VERSION = archive.parent.parent.name
if not archive.exists():
    raise SystemExit(f"release archive is absent: {archive}")


def answers_verb(binary: Path) -> tuple[bool, str]:
    done = subprocess.run([str(binary), VERB], capture_output=True, text=True, check=False)
    combined = (done.stdout + done.stderr).strip()
    return ("unknown command" not in combined), combined


with tempfile.TemporaryDirectory() as work:
    with tarfile.open(archive) as bundle:
        bundle.extractall(work)
    staged = Path(work) / FAMILY
    if not staged.exists():
        raise SystemExit(f"archive does not contain {FAMILY}")
    staged_ok, _ = answers_verb(staged)
    if not staged_ok:
        raise SystemExit(f"staged binary still lacks {VERB}; refusing to install")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    kept = TARGET.with_name(f"skarbiec.before-{VERSION}")
    if TARGET.exists():
        shutil.copy2(TARGET, kept)
    shutil.copy(staged, TARGET)
    os.chmod(TARGET, OWNER_EXECUTABLE)
    # Copying a linker-signed Mach-O to a new path invalidates its signature and
    # macOS answers by killing it on exec — SIGKILL with no message, which reads
    # like anything except a signature problem. Re-sign ad-hoc at the final
    # path, then prove the binary still runs before anything depends on it.
    signed = subprocess.run(
        ["/usr/bin/codesign", "--force", "--sign", "-", str(TARGET)],
        capture_output=True,
        text=True,
        check=False,
    )
    if signed.returncode:
        raise SystemExit(f"codesign failed: {(signed.stderr or signed.stdout).strip()}")

installed_ok, response = answers_verb(TARGET)
print("installed:", TARGET)
print("kept:", kept)
print("verb answered:", installed_ok)
for line in response.splitlines():
    print("response:", line)
    break
