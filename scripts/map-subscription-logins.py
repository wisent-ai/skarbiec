#!/usr/bin/env python3
"""Record which vault login a Brama subscription bundle signs in with.

A subscription bundle holds the credential a provider accepts; the login item
holds the account that credential was minted from. Nothing on the vault said
which was which, so a renewal loop that wants to refresh a refused subscription
had no way to know whose sign-in to drive. This writes that fact down as one
more tag on the bundle, `brama:login:<login-item-id>`, beside the tags the
gateway and its console already enumerate by (`brama:subscription`,
`brama:agent:<agent>`, `brama:provider:<provider>`, `brama:id:<id>`).

Two sources of truth are written, and neither is a guess. The first is the
mappings the fleet's own naming settles: `claude_controlyourai` names its account
in both ids, and codex and kimi have exactly one login each. The second is a
mapping an observed sign-in proved: three claude subscriptions share the one
remaining login `claude-wisent-google-sso`, and nothing on this vault says which
of them it mints - but a sign-in does. Whichever bundle's revision advances after
a login for that account is a bundle that account mints, and the renewal loop
hands those pairs here to be written. Anything still unproven is printed as
unresolved and left untagged, because an untagged subscription is reported as
unmapped by the renewal loop and never attempted, while a wrong tag is a login
into the wrong account.

Tags are metadata beside the envelope: this uses `retag`, which never touches a
payload, never re-encrypts to a narrowed recipient list and never advances the
item's revision. Every tag already on an item is carried over in the order it
was written, so running this twice is the same as running it once.

Usage: map-subscription-logins.py [--dry-run]
       SKARBIEC_BIN=<path> SKARBIEC_VAULT_FILE=<path> map-subscription-logins.py

Proven pairs arrive as `bundle=login[,bundle=login...]`, either in
BRAMA_PROVEN_LOGINS or pinned into the `@PROVEN@` placeholder below when this
file is installed as a helper - `stado host run-helper` carries no arguments and
no caller environment, so a caller that has something to say has to say it in the
file it installs. An unrendered placeholder means "nothing was proven", which is
the honest default: the settled mappings are still written.

The last line of output is one JSON object, so a caller reads an answer rather
than scraping the report above it.

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

# Every login this fleet holds. A proven pair naming anything else is refused:
# whatever wrote it was not reading this vault.
KNOWN_LOGINS = (
    "claude-wisent-google-sso",
    "claude_controlyourai",
    "codex-wisent-google-sso",
    "kimi-lukasz-google-sso",
)

# Pairs an observed sign-in proved, pinned here when this file is installed as a
# helper by replacing every `@PROVEN@` in it. An installer replaces the token
# everywhere it appears, so "was this rendered" is answered by the value's shape
# rather than by comparing it to a literal that would have been replaced too: a
# real pair names a bundle, and no bundle id begins with an at sign.
PROVEN_TOKEN_MARK = "@"
PROVEN_LOGINS = os.environ.get("BRAMA_PROVEN_LOGINS") or "@PROVEN@"


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


def proven_pairs() -> dict[str, str]:
    """The pairs a sign-in proved, parsed strictly or refused.

    A pair that names a bundle this script does not recognise as a subscription,
    a login this vault does not hold, or a mapping the settled table already
    contradicts is refused rather than written: a proven pair is evidence, and
    evidence that disagrees with the vault is a caller bug, not a new fact.
    """
    if PROVEN_LOGINS.startswith(PROVEN_TOKEN_MARK):
        return {}
    pairs: dict[str, str] = {}
    for entry in PROVEN_LOGINS.split(","):
        entry = entry.strip()
        if not entry:
            continue
        bundle, separator, login = entry.partition("=")
        bundle, login = bundle.strip(), login.strip()
        if not separator or not bundle.startswith("provider:") or login not in KNOWN_LOGINS:
            fail(
                f"proven mapping {entry!r} is not <provider:...bundle>=<login this "
                f"vault holds>; known logins are {', '.join(KNOWN_LOGINS)}"
            )
        settled = SUBSCRIPTION_LOGINS.get(bundle)
        if settled and settled != login:
            fail(
                f"proven mapping {bundle}={login} contradicts the settled mapping "
                f"{bundle}={settled}; one of the two is wrong and neither is a guess "
                "this script may make"
            )
        pairs[bundle] = login
    return pairs


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

    # A trashed bundle is still in the vault and still needs no login: it mints
    # nothing. `skarbiec list` omits it, so demanding every name be visible read
    # a retired subscription as "wrong vault" and refused to map the six live
    # ones. Recognise the vault by the logins plus at least one live bundle, and
    # treat an unlisted bundle as nothing to map.
    missing_logins = {name for name in SUBSCRIPTION_LOGINS.values() if name not in items}
    if missing_logins:
        fail(
            "this vault does not hold "
            + ", ".join(sorted(missing_logins))
            + "; it is not the fleet vault these mappings were established against"
        )
    if not any(name in items for name in SUBSCRIPTION_LOGINS):
        fail(
            "this vault holds none of the subscription bundles these mappings "
            "name; it is not the fleet vault they were established against"
        )
    proven = proven_pairs()
    mappings = {**SUBSCRIPTION_LOGINS, **proven}
    for bundle, login in sorted(proven.items()):
        print(f"  {bundle}: proven by an observed sign-in for {login}")
    retired = sorted(
        name for name in (*mappings, *AMBIGUOUS_SUBSCRIPTIONS) if name not in items
    )
    for name in retired:
        print(f"  {name}: not listed by this vault (retired or purged); nothing to map")

    conflicts: list[str] = []
    written: list[str] = []
    already: list[str] = []
    for bundle in sorted(mappings):
        login = mappings[bundle]
        existing = items.get(bundle)
        if existing is None:
            continue
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
            already.append(bundle)
            continue
        print(f"--- {bundle}\n    add {LOGIN_TAG_PREFIX}{login} to {','.join(existing) or '<none>'}")
        if dry_run:
            continue
        answer = run(binary, ["retag", bundle, "--tags", ",".join(wanted)], environment)
        if answer.returncode != NONE:
            conflicts.append(f"{bundle} retag failed: {answer.stderr.strip()[:DETAIL]}")
            continue
        written.append(bundle)

    unresolved = [bundle for bundle in AMBIGUOUS_SUBSCRIPTIONS if bundle not in mappings]
    print("--- unresolved")
    for bundle in unresolved:
        print(f"    {bundle}: no brama:login: tag written")
    if unresolved:
        print(f"    reason: {AMBIGUOUS_REASON}")

    print("--- resulting tags")
    after = vault_items(binary, environment) if written else items
    for bundle in sorted((*mappings, *AMBIGUOUS_SUBSCRIPTIONS)):
        print(f"    {bundle} -> {','.join(after.get(bundle) or []) or '<none>'}")

    for conflict in conflicts:
        print(conflict, file=sys.stderr)
    # One JSON object as the last line, so a caller reads an answer rather than
    # the report above it.
    print(
        json.dumps(
            {
                "vault": str(vault),
                "dry_run": dry_run,
                "written": written,
                "already": already,
                "proven": proven,
                "retired": retired,
                "unresolved": unresolved,
                "conflicts": conflicts,
            }
        )
    )
    return len(["conflicts"]) if conflicts else NONE


if __name__ == "__main__":
    raise SystemExit(main())
