"""App Store Connect from this vault: one bearer, one HTTP call, one openssl, one write.

Shared by `apple-developer-id.py` (the macOS Developer ID certificate) and
`apple-ios-signing.py` (iOS distribution certificate, bundle ids, App Store
profiles), so the JWT, the API error rendering, the openssl wrapper and the way
an item is written through stdin exist once.

The App Store Connect key is read from this vault, never from a file on disk;
secrets reach `skarbiec set-json` through stdin and never appear in argv.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import jwt

API = "https://api.appstoreconnect.apple.com/v1"
DEFAULT_KEY_ITEM = "api-appstoreconnect-weles"


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def vault_get(item: str, field: str) -> str:
    result = subprocess.run(
        ["skarbiec", "get", item, "--field", field], text=True, capture_output=True,
    )
    if result.returncode:
        fail(f"skarbiec get {item}#{field}: {' '.join((result.stderr or '').split())[:200]}")
    return result.stdout.strip()


def vault_item(item: str) -> dict:
    result = subprocess.run(["skarbiec", "get", item], text=True, capture_output=True)
    if result.returncode:
        fail(f"skarbiec get {item}: {' '.join((result.stderr or '').split())[:200]}")
    return json.loads(result.stdout)


def vault_has(item: str) -> bool:
    result = subprocess.run(["skarbiec", "get", item], text=True, capture_output=True)
    return result.returncode == 0


def vault_set_bundle(item: str, fields: dict[str, str], context: dict[str, str]) -> None:
    """Write the item as one canonical `bundle` payload, through stdin.

    `skarbiec set` takes `k=v` pairs in argv, which publishes a secret to `ps`
    for as long as the command runs — the one thing a vault exists to prevent.
    `set-json` reads a canonical payload from stdin instead, so nothing sensitive
    is ever an argument.

    The kind is `bundle` because the schema says so, not by preference:
    `certificate` allows exactly certificate, private_key, chain and passphrase
    (src/core/schema.rs), while the release manifests declare
    certificate_p12_base64, certificate_password, sign_identity and
    provisioning_profile_base64. `bundle` is the kind with no field allowlist,
    which is what a set of related release values is.
    """
    payload = {
        "schema": "skarbiec.item.v2",
        "kind": "bundle",
        "fields": fields,
        "context": context,
    }
    result = subprocess.run(
        ["skarbiec", "set-json", item, "--type", "bundle"],
        input=json.dumps(payload), text=True, capture_output=True,
    )
    if result.returncode:
        fail(f"skarbiec set-json {item}: {' '.join((result.stderr or '').split())[:300]}")


def api_key_from(item: str) -> tuple[str, str, str] | None:
    """Read an App Store Connect key from whichever shape the vault holds it in.

    Two shapes exist here, both legitimate. `api-appstoreconnect-weles` is a
    `key-pair` with issuer_id, key_id and private_key as fields.
    `platform-admin-appstore-apikey` is a `stado-secret` whose single `value` is
    an object carrying issuer_id, key_id and p8 — the shape the asc CLI keychain
    export produces, recorded in its context as `asc-cli-keychain`.
    """
    payload = vault_item(item)
    fields = payload.get("fields", {})
    if {"issuer_id", "key_id"} <= set(fields):
        return fields["key_id"], fields["issuer_id"], fields.get("private_key", "")
    value = fields.get("value")
    if isinstance(value, dict) and {"issuer_id", "key_id"} <= set(value):
        return value["key_id"], value["issuer_id"], value.get("p8", "")
    return None


def add_credential_arguments(parser: argparse.ArgumentParser, environ: dict[str, str]) -> None:
    parser.add_argument("--vault-item", default=DEFAULT_KEY_ITEM,
                        help="vault item carrying issuer_id, key_id and private_key")
    parser.add_argument("--key-id", default=environ.get("APPLE_API_KEY_ID"))
    parser.add_argument("--issuer", default=environ.get("APPLE_API_ISSUER_ID"))
    parser.add_argument("--key-file", default=environ.get("APPLE_API_KEY_FILE"))


def credentials(args: argparse.Namespace) -> tuple[str, str, str]:
    """Where the App Store Connect key comes from.

    The vault, because that is where it belongs and where the fleet already keeps
    it; reading it here means the key never lands on disk. The copy this work
    started from was an `AuthKey_*.p8` sitting in ~/Downloads, which is exactly
    the situation a vault exists to end.

    Explicit arguments still win, for the bootstrap case where the vault does not
    hold the key yet.
    """
    if args.key_id and args.issuer and args.key_file:
        if not Path(args.key_file).is_file():
            fail(f"App Store Connect key file is absent: {args.key_file}")
        return args.key_id, args.issuer, Path(args.key_file).read_text()
    found = api_key_from(args.vault_item)
    if found is None:
        fail(f"{args.vault_item} carries no App Store Connect key: expected issuer_id and key_id")
    key_id, issuer, private_key = found
    if not private_key:
        fail(f"{args.vault_item} names a key but holds no private key material")
    return args.key_id or key_id, args.issuer or issuer, private_key


def token(key_id: str, issuer: str, private_key: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": issuer, "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"},
        private_key,
        algorithm="ES256",
        headers={"kid": key_id, "typ": "JWT"},
    )


def call(path: str, bearer: str, method: str = "GET", body: dict | None = None,
         user_agent: str = "skarbiec-apple-asc") -> dict:
    request = urllib.request.Request(
        f"{API}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "User-Agent": user_agent,
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        try:
            errors = json.loads(detail)["errors"]
            detail = "; ".join(
                f"{item.get('title', '')}: {item.get('detail', '')}".strip(": ") for item in errors
            )
        except Exception:
            detail = " ".join(detail.split())[:400]
        fail(f"App Store Connect {method} {path} -> {error.code}: {detail}")
        raise


def openssl(*argv: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["openssl", *argv], input=stdin, capture_output=True,
    )
    if result.returncode:
        fail(f"openssl {' '.join(argv[:2])}: {result.stderr.decode(errors='replace').strip()[:300]}")
    return result.stdout


def describe(certificate: dict) -> str:
    attributes = certificate.get("attributes", {})
    return (
        f"{certificate.get('id', '?'):<12} {attributes.get('certificateType', '?'):<26} "
        f"{attributes.get('displayName', '?'):<34} expires {attributes.get('expirationDate', '?')[:10]}"
    )


def list_certificates(bearer: str) -> list[dict]:
    return call("/certificates?limit=200", bearer).get("data", [])
