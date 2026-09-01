#!/usr/bin/env python3
"""Obtain and store the Developer ID Application certificate the fleet signs with.

Every `*-desktop` release manifest, and oko's command-line release, declares the
same three coordinates:

    MACOS_CERT_P12       wisent-apple-developer-id#certificate_p12_base64
    MACOS_CERT_PASSWORD  wisent-apple-developer-id#certificate_password
    MACOS_SIGN_IDENTITY  wisent-apple-developer-id#sign_identity

Nothing had ever created that item, so every signing build refused and the
update feeds served 404 for want of a signed artifact. The certificate was
treated as something a human fetches from the portal in a browser; it is not.
App Store Connect creates DEVELOPER_ID_APPLICATION certificates over its REST
API, which needs no browser, no consent dialog and no trusted-device code.

    apple-developer-id.py list                 what the account already has
    apple-developer-id.py mint                 create one and store it
    apple-developer-id.py mint --dry-run       everything except create and store

The private key never leaves this process except into the vault: the CSR is
generated here, the p12 is assembled here, and both are handed to `skarbiec set`
through stdin rather than argv, so they never appear in `ps` or a shell history.

Credentials it needs, and where it looks:

    APPLE_API_KEY_ID / --key-id        the App Store Connect key identifier
    APPLE_API_ISSUER_ID / --issuer     the issuer UUID from that key's page
    APPLE_API_KEY_FILE / --key-file    the AuthKey_<id>.p8 file

An Account Holder key is required to create a Developer ID certificate; a key
with a lesser role gets a clear 403 from Apple, which this reports as such.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import jwt

API = "https://api.appstoreconnect.apple.com/v1"
ITEM = "wisent-apple-developer-id"
CERTIFICATE_TYPE = "DEVELOPER_ID_APPLICATION"


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

def call(path: str, bearer: str, method: str = "GET", body: dict | None = None) -> dict:
    request = urllib.request.Request(
        f"{API}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "User-Agent": "skarbiec-apple-developer-id",
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


def vault_store(fields: dict[str, str], identity: str, certificate_id: str) -> None:
    """Write the item as one canonical payload, through stdin.

    `skarbiec set` takes `k=v` pairs in argv, which publishes a secret to `ps`
    for as long as the command runs — the one thing a vault exists to prevent.
    `set-json` reads a canonical payload from stdin instead, so nothing sensitive
    is ever an argument.

    The kind is `bundle` because the schema says so, not by preference:
    `certificate` allows exactly certificate, private_key, chain and passphrase
    (src/core/schema.rs:25), while the fifty-two release manifests declare
    certificate_p12_base64, certificate_password and sign_identity. `bundle` is
    the kind with no field allowlist (schema.rs:239), which is what a set of
    related release values is.
    """
    payload = {
        "schema": "skarbiec.item.v2",
        "kind": "bundle",
        "fields": fields,
        "context": {
            "purpose": "macos-developer-id-signing",
            "certificate_id": certificate_id,
            "sign_identity": identity,
            "created_by": "skarbiec/scripts/apple-developer-id.py",
        },
    }
    result = subprocess.run(
        ["skarbiec", "set-json", ITEM, "--type", "bundle"],
        input=json.dumps(payload), text=True, capture_output=True,
    )
    if result.returncode:
        fail(f"skarbiec set-json {ITEM}: {' '.join((result.stderr or '').split())[:300]}")


def describe(certificate: dict) -> str:
    attributes = certificate.get("attributes", {})
    return (
        f"{certificate.get('id', '?'):<12} {attributes.get('certificateType', '?'):<26} "
        f"{attributes.get('displayName', '?'):<34} expires {attributes.get('expirationDate', '?')[:10]}"
    )


def list_certificates(bearer: str) -> list[dict]:
    return call("/certificates?limit=200", bearer).get("data", [])


def mint(bearer: str, dry_run: bool) -> None:
    existing = [
        item for item in list_certificates(bearer)
        if item.get("attributes", {}).get("certificateType") == CERTIFICATE_TYPE
    ]
    for item in existing:
        print(f"already present  {describe(item)}")
    if existing and not dry_run:
        fail(
            f"{len(existing)} {CERTIFICATE_TYPE} certificate(s) already exist and Apple caps how many "
            f"an account may hold. Download one from the portal, or revoke it there first; this tool "
            f"will not revoke a certificate other builds may be signing with."
        )

    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        key = work / "key.pem"
        csr = work / "request.csr"
        openssl("genrsa", "-out", str(key), "2048")
        openssl(
            "req", "-new", "-key", str(key), "-out", str(csr),
            "-subj", "/CN=Wisent-AI Developer ID Application/O=Wisent-AI, Inc/C=US",
        )
        if dry_run:
            print(f"dry run: a {CERTIFICATE_TYPE} certificate would be requested with this CSR")
            print(csr.read_text().strip().splitlines()[0] + " ... (generated, not sent)")
            return

        created = call(
            "/certificates", bearer, "POST",
            {
                "data": {
                    "type": "certificates",
                    "attributes": {
                        "certificateType": CERTIFICATE_TYPE,
                        "csrContent": csr.read_text(),
                    },
                }
            },
        )
        attributes = created["data"]["attributes"]
        print(f"created          {describe(created['data'])}")

        der = work / "certificate.cer"
        der.write_bytes(base64.b64decode(attributes["certificateContent"]))
        pem = work / "certificate.pem"
        pem.write_bytes(openssl("x509", "-inform", "DER", "-in", str(der), "-outform", "PEM"))

        password = secrets.token_urlsafe(24)
        p12 = work / "identity.p12"
        openssl(
            "pkcs12", "-export", "-legacy",
            "-inkey", str(key), "-in", str(pem),
            "-name", attributes["name"],
            "-out", str(p12), "-passout", "stdin",
            stdin=password.encode(),
        )
        identity = attributes["name"]
        vault_store(
            {
                "certificate_p12_base64": base64.b64encode(p12.read_bytes()).decode(),
                "certificate_password": password,
                "sign_identity": identity,
            },
            identity,
            created["data"]["id"],
        )

    print(f"stored           {ITEM}#certificate_p12_base64, #certificate_password, #sign_identity")
    print(f"identity         {identity}")
    print("next             a signing build now resolves its three coordinates from the vault")


def main() -> int:
    root = argparse.ArgumentParser(prog="apple-developer-id.py", description=__doc__)
    root.add_argument("--vault-item", default="api-appstoreconnect-weles",
                      help="vault item carrying issuer_id, key_id and private_key")
    root.add_argument("--key-id", default=os.environ.get("APPLE_API_KEY_ID"))
    root.add_argument("--issuer", default=os.environ.get("APPLE_API_ISSUER_ID"))
    root.add_argument("--key-file", default=os.environ.get("APPLE_API_KEY_FILE"))
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list every certificate the account holds")
    commands.add_parser("roles", help="who holds which App Store Connect role, and who the Account Holder is")
    creator = commands.add_parser("mint", help="create a Developer ID Application certificate and store it")
    creator.add_argument("--dry-run", action="store_true")
    args = root.parse_args()

    key_id, issuer, private_key = credentials(args)
    bearer = token(key_id, issuer, private_key)
    if args.command == "list":
        rows = list_certificates(bearer)
        if not rows:
            print("the account holds no certificates")
        for row in sorted(rows, key=lambda item: item.get("attributes", {}).get("certificateType", "")):
            print(describe(row))
        return 0
    if args.command == "roles":
        # Creating a DEVELOPER_ID_APPLICATION certificate is refused for every
        # role but Account Holder, so the only question that matters about a key
        # is whose rights it carries. Both keys in this vault are `key_type:
        # team`, and Apple answered the create with 403 "This operation can only
        # be performed by the Account Holder" for each.
        for user in call("/users?limit=200", bearer).get("data", []):
            attributes = user.get("attributes", {})
            roles = ", ".join(attributes.get("roles", []))
            print(
                f"{attributes.get('username', '?'):<34} "
                f"{(attributes.get('firstName', '') + ' ' + attributes.get('lastName', '')).strip():<26} {roles}"
            )
        return 0
    mint(bearer, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
