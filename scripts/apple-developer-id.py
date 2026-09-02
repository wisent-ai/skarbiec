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

The App Store Connect plumbing — bearer, calls, openssl, the stdin write — is
`apple_asc.py`, shared with `apple-ios-signing.py`.
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import tempfile
from pathlib import Path

from apple_asc import (
    add_credential_arguments,
    call,
    credentials,
    describe,
    fail,
    list_certificates,
    openssl,
    token,
    vault_set_bundle,
)

# The item Stado actually reads when it signs: host_precheck_runner.rs sets
# DEVELOPER_ID_ITEM = "desktop-release-developer-id". The release manifests
# declare wisent-apple-developer-id in their secret_env, and Stado reads that
# coordinate nowhere — it resolves signing material by its own constants.
ITEM = "desktop-release-developer-id"
CERTIFICATE_TYPE = "DEVELOPER_ID_APPLICATION"


def vault_store(fields: dict[str, str], identity: str, certificate_id: str) -> None:
    vault_set_bundle(
        ITEM,
        fields,
        {
            "purpose": "macos-developer-id-signing",
            "certificate_id": certificate_id,
            "sign_identity": identity,
            "created_by": "skarbiec/scripts/apple-developer-id.py",
        },
    )


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
            user_agent="skarbiec-apple-developer-id",
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
    add_credential_arguments(root, os.environ)
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
