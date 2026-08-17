#!/usr/bin/env python3
"""Record which vault login a Brama subscription bundle signs in with.

A subscription bundle holds the credential a provider accepts; the login item
holds the account that credential was minted from. Nothing on the vault said
which was which, so a renewal loop that wants to refresh a refused subscription
had no way to know whose sign-in to drive. This writes that fact down as one
more tag on the bundle, `brama:login:<login-item-id>`, beside the tags the
gateway and its console already enumerate by (`brama:subscription`,
`brama:agent:<agent>`, `brama:provider:<provider>`, `brama:id:<id>`).

Only the mappings the fleet's own naming settles are written. Four logins serve
seven subscriptions, and three claude subscriptions share the one remaining
login: which of `claude-1`, `claude-2` and `claude-primary` was minted from
`claude-wisent-google-sso` is not recorded anywhere on this vault, and the two
that were not would be renewed by signing into an account they do not belong
to. Those are printed as unresolved and left untagged, because an untagged
subscription is reported as unmapped by the renewal loop and never attempted,
while a wrong tag is a login into the wrong account.

Tags are metadata beside the envelope: this uses `retag`, which never touches a
payload, never re-encrypts to a narrowed recipient list and never advances the
item's revision. Every tag already on an item is carried over in the order it
was written, so running this twice is the same as running it once.

Usage: map-subscription-logins.py [--dry-run]
       SKARBIEC_BIN=<path> SKARBIEC_VAULT_FILE=<path> map-subscription-logins.py

Runs where the vault is. On the always-on host that means through Stado:
  stado host install-helper <host> scripts/map-subscription-logins.py map-subscription-logins
  stado host run-helper <host> map-subscription-logins
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

NONE = len([])
FIRST = len(["argv0"])
DETAIL = int("400")
LOGIN_TAG_PREFIX = "brama:login:"
# Tags Skarbiec refuses on a `retag`, because only an authenticated writer of
# that lifecycle may set them.
RESERVED_TAGS = ("managed:weles",)

# The binary that carries `retag` reaches the always-on host inside Brama's
# release, where the same Skarbiec executable is installed as the entitlements
# router. Prefer it, then a Stado-managed binary, then whatever is on PATH.
BINARY_CANDIDATES = (
    "$HOME/.stado/services/brama/current/darwin-arm/bin/skarbiec-entitlements-router",
    "$HOME/.stado/bin/skarbiec",
)

# The fleet's vault, not this user's personal default under
# ~/.local/share/skarbiec. Pointing at the default would retag items in an empty
# vault and report success, which is the exact failure this script exists to
# make impossible.
DEFAULT_VAULT = "$HOME/.stado/skarbiec.vault.json"

# The mappings the vault's own names settle. `claude_controlyourai` names its
# account in both the bundle id and the login id; codex has exactly one login,
# so both codex subscriptions can only have come from it; kimi likewise.
SUBSCRIPTION_LOGINS = {
    "provider:claude-code:brama-sub-wisent-app-claude-controlyourai": "claude_controlyourai",
    "provider:codex:brama-sub-wisent-app-codex-primary": "codex-wisent-google-sso",
    "provider:codex:brama-sub-wisent-app-codex-secondary": "codex-wisent-google-sso",
    "provider:kimi:brama-sub-wisent-app-kimi-primary": "kimi-lukasz-google-sso",
}

# Three subscriptions, one remaining login, and no record of which one it minted.
# Named here so the report says which subscriptions are deliberately untagged
# and what would settle them, rather than leaving their absence to be noticed.
AMBIGUOUS_SUBSCRIPTIONS = (
    "provider:claude-code:brama-sub-wisent-app-claude-1",
    "provider:claude-code:brama-sub-wisent-app-claude-2",
    "provider:claude-code:brama-sub-wisent-app-claude-primary",
)
AMBIGUOUS_REASON = (
    "three claude subscriptions share the single remaining login "
    "claude-wisent-google-sso, and this vault records nothing that says which "
    "one it minted; tagging any of them would point a renewal loop at an "
    "account the subscription does not belong to"
)


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(len(["failed"]))


def resolved_binary() -> str:
    configured = os.environ.get("SKARBIEC_BIN", "").strip()
    candidates = [configured] if configured else [
        os.path.expandvars(candidate) for candidate in BINARY_CANDIDATES
    ]
    for candidate in candidates:
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    if configured:
        fail(f"SKARBIEC_BIN={configured} is not an executable file")
    found = subprocess.run(
        ["/usr/bin/env", "which", "skarbiec"], capture_output=True, text=True, check=False
    ).stdout.strip()
    if found and os.access(found, os.X_OK):
        return found
    fail(
        "no skarbiec binary found; looked at "
        + ", ".join(os.path.expandvars(candidate) for candidate in BINARY_CANDIDATES)
        + " and PATH"
    )
    raise AssertionError("unreachable")


def run(binary: str, arguments: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [binary, *arguments],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )


def require_retag(binary: str, environment: dict[str, str]) -> None:
    """Refuse to run against a binary that predates `retag`.

    An older binary has no way to write a tag without rewriting the payload, and
    a caller who reached for `set-json` instead would re-encrypt a live
    credential to whatever recipients the entry carries now.
    """
    answer = run(binary, ["help"], environment)
    try:
        commands = json.loads(answer.stdout).get("commands") or []
    except ValueError:
        fail(f"{binary} does not answer `help` with JSON; it is not a Skarbiec binary")
        raise AssertionError("unreachable")
    if "retag" not in commands:
        fail(
            f"{binary} does not advertise `retag`; ship the release that carries "
            "tag preservation before mapping logins"
        )


def vault_items(binary: str, environment: dict[str, str]) -> dict[str, list[str]]:
    answer = run(binary, ["list"], environment)
    if answer.returncode != NONE:
        fail(
            f"{binary} list failed against {environment['SKARBIEC_VAULT_FILE']}: "
            f"{answer.stderr.strip()[:DETAIL]}"
        )
    try:
        rows = json.loads(answer.stdout)
    except ValueError:
        fail(f"{binary} list did not answer with JSON: {answer.stdout.strip()[:DETAIL]}")
        raise AssertionError("unreachable")
    return {
        row.get("id"): list(row.get("tags") or [])
        for row in rows
        if isinstance(row, dict) and not row.get("deleted")
    }


def planned_tags(existing: list[str], login: str) -> list[str] | None:
    """The tag list to write, or None when the item already says this.

    Every tag already present is kept, in the order the vault holds it, because
    `retag` replaces the whole list and a tag dropped here is an item that
    disappears from every reader that enumerates by tag.
    """
    wanted = f"{LOGIN_TAG_PREFIX}{login}"
    if wanted in existing:
        return None
    return [*existing, wanted]


def conflicting_login(existing: list[str], login: str) -> str | None:
    for tag in existing:
        if tag.startswith(LOGIN_TAG_PREFIX) and tag != f"{LOGIN_TAG_PREFIX}{login}":
            return tag
    return None


def reserved_tag(existing: list[str]) -> str | None:
    """The tag `retag` will not write back, if the item carries one.

    `retag` replaces the whole list and refuses `managed:weles`, which is
    reserved for authenticated Weles writes. An item carrying it therefore
    cannot be retagged at all: writing the list without it would take a live
    credential out of Weles management, and writing it with it is refused. Say
    so by name instead of letting the refusal surface as an unexplained error.
    """
    for tag in existing:
        if tag in RESERVED_TAGS:
            return tag
    return None


def main() -> int:
    arguments = sys.argv[FIRST:]
    dry_run = arguments == ["--dry-run"]
    if arguments and not dry_run:
        fail("usage: map-subscription-logins.py [--dry-run]")

    binary = resolved_binary()
    vault = pathlib.Path(
        os.environ.get("SKARBIEC_VAULT_FILE") or os.path.expandvars(DEFAULT_VAULT)
    )
    if not vault.is_file():
        fail(
            f"no fleet vault at {vault}; set SKARBIEC_VAULT_FILE to the vault this "
            "fleet's gateway reads rather than retagging an empty default"
        )
    environment = {**os.environ, "SKARBIEC_VAULT_FILE": str(vault)}
    require_retag(binary, environment)

    print(f"binary: {binary}")
    print(f"vault:  {vault}")
    items = vault_items(binary, environment)

    missing = {
        name
        for name in (*SUBSCRIPTION_LOGINS, *SUBSCRIPTION_LOGINS.values(), *AMBIGUOUS_SUBSCRIPTIONS)
        if name not in items
    }
    if missing:
        fail(
            "this vault does not hold "
            + ", ".join(sorted(missing))
            + "; it is not the fleet vault these mappings were established against"
        )

    conflicts: list[str] = []
    written: list[str] = []
    for bundle in sorted(SUBSCRIPTION_LOGINS):
        login = SUBSCRIPTION_LOGINS[bundle]
        existing = items[bundle]
        clash = conflicting_login(existing, login)
        if clash:
            conflicts.append(
                f"{bundle} already carries {clash} but is mapped to {login}; "
                "resolve which account minted it before retagging"
            )
            continue
        reserved = reserved_tag(existing)
        if reserved:
            conflicts.append(
                f"{bundle} carries the reserved tag {reserved}, which `retag` will "
                "not write back; record its login through the lifecycle that "
                "manages the item rather than dropping that tag"
            )
            continue
        wanted = planned_tags(existing, login)
        if wanted is None:
            print(f"--- {bundle}\n    already records {LOGIN_TAG_PREFIX}{login}")
            continue
        print(f"--- {bundle}\n    add {LOGIN_TAG_PREFIX}{login} to {','.join(existing) or '<none>'}")
        if dry_run:
            continue
        answer = run(binary, ["retag", bundle, "--tags", ",".join(wanted)], environment)
        if answer.returncode != NONE:
            conflicts.append(f"{bundle} retag failed: {answer.stderr.strip()[:DETAIL]}")
            continue
        written.append(bundle)

    print("--- unresolved")
    for bundle in AMBIGUOUS_SUBSCRIPTIONS:
        print(f"    {bundle}: no brama:login: tag written")
    print(f"    reason: {AMBIGUOUS_REASON}")

    print("--- resulting tags")
    after = vault_items(binary, environment) if written else items
    for bundle in sorted((*SUBSCRIPTION_LOGINS, *AMBIGUOUS_SUBSCRIPTIONS)):
        print(f"    {bundle} -> {','.join(after.get(bundle) or []) or '<none>'}")

    if conflicts:
        for conflict in conflicts:
            print(conflict, file=sys.stderr)
        return len(["conflicts"])
    return NONE


if __name__ == "__main__":
    raise SystemExit(main())
