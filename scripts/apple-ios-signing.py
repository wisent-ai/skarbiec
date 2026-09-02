#!/usr/bin/env python3
"""Mint and store what an iOS release needs to sign, and hand it to the repository that builds it.

Every `*-ios` release manifest declares the same coordinates:

    IOS_DIST_P12_B64        wisent-ios-distribution#certificate_p12_base64
    IOS_DIST_P12_PASSWORD   wisent-ios-distribution#certificate_password
    IOS_SIGN_IDENTITY       wisent-ios-distribution#sign_identity
    IOS_PROFILE_B64         <repository>-signing#provisioning_profile_base64

and each repository's TestFlight workflow reads the same six GitHub secrets
(those four plus AC_API_KEY_ID / AC_API_ISSUER_ID / AC_API_KEY_P8). Nothing had
ever created the vault items, so every iOS release path stopped at its first
secret. All of it is issued by App Store Connect over its REST API — no browser,
no consent dialog: the certificate from a CSR generated here, the bundle id and
app record by name, the App Store provisioning profile from the two.

    apple-ios-signing.py list
    apple-ios-signing.py mint-certificate [--dry-run]
    apple-ios-signing.py profile --repository jeden-ios --bundle-id ai.wisent.jeden \\
        --app-name Jeden [--profile-name "Jeden CI AppStore"] [--dry-run]
    apple-ios-signing.py publish --repository jeden-ios

The private key never leaves this process except into the vault: the CSR is
generated here, the p12 is assembled here, and the item is written through
stdin. `publish` pipes each value into `gh secret set` the same way.

Credentials come from the vault item `api-appstoreconnect-weles` (issuer_id,
key_id, private_key), or from APPLE_API_KEY_ID / APPLE_API_ISSUER_ID /
APPLE_API_KEY_FILE when bootstrapping. The App Store Connect plumbing is
`apple_asc.py`, shared with `apple-developer-id.py`.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

from apple_asc import (
    add_credential_arguments,
    call,
    credentials,
    describe,
    fail,
    list_certificates,
    openssl,
    token,
    vault_get,
    vault_has,
    vault_item,
    vault_set_bundle,
)

CERTIFICATE_ITEM = "wisent-ios-distribution"
CERTIFICATE_TYPE = "IOS_DISTRIBUTION"
PROFILE_TYPE = "IOS_APP_STORE"
ORGANIZATION = "wisent-ai"
CREATED_BY = "skarbiec/scripts/apple-ios-signing.py"
# The vault item Stado's publisher bootstrap reads as the GitHub credential
# (host_precheck_runner.rs: GITHUB_CREDENTIAL_ITEM), a token with `repo` scope.
PACKAGES_TOKEN_ITEM = "GITHUB_TOKEN"
USER_AGENT = "skarbiec-apple-ios-signing"


def signing_item(repository: str) -> str:
    return f"{repository}-signing"


def subject_fields(pem: Path) -> dict[str, str]:
    """CN and OU of a certificate, as Xcode names the identity and the team."""
    text = openssl(
        "x509", "-in", str(pem), "-noout", "-subject", "-nameopt", "sep_multiline",
    ).decode()
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*(CN|OU|O)=(.*)$", line)
        if match:
            fields[match.group(1)] = match.group(2).strip()
    if "CN" not in fields:
        fail(f"certificate subject carries no CN: {' '.join(text.split())[:200]}")
    return fields


def serial_number(pem: Path) -> str:
    text = openssl("x509", "-in", str(pem), "-noout", "-serial").decode().strip()
    return text.split("=", 1)[-1]


# --- certificate ------------------------------------------------------------


def mint_certificate(bearer: str, key_id: str, dry_run: bool, replace: bool) -> None:
    if vault_has(CERTIFICATE_ITEM) and not replace and not dry_run:
        context = vault_item(CERTIFICATE_ITEM).get("context", {})
        fail(
            f"{CERTIFICATE_ITEM} already holds certificate {context.get('certificate_id', '?')} "
            f"({context.get('sign_identity', '?')}, expires {context.get('expires_at', '?')[:10]}). "
            f"Builds sign with it; pass --replace to mint another and overwrite the item."
        )
    existing = [
        item for item in list_certificates(bearer)
        if item.get("attributes", {}).get("certificateType") == CERTIFICATE_TYPE
    ]
    for item in existing:
        # An API-issued certificate whose private key this vault does not hold is
        # unusable from here; it is listed, not treated as ours.
        print(f"account holds    {describe(item)}")

    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        key = work / "key.pem"
        csr = work / "request.csr"
        openssl("genrsa", "-out", str(key), "2048")
        openssl(
            "req", "-new", "-key", str(key), "-out", str(csr),
            "-subj", "/CN=Wisent-AI iOS Distribution/O=Wisent-AI, Inc/C=US",
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
            user_agent=USER_AGENT,
        )
        attributes = created["data"]["attributes"]
        certificate_id = created["data"]["id"]
        print(f"created          {describe(created['data'])}")

        der = work / "certificate.cer"
        der.write_bytes(base64.b64decode(attributes["certificateContent"]))
        pem = work / "certificate.pem"
        pem.write_bytes(openssl("x509", "-inform", "DER", "-in", str(der), "-outform", "PEM"))
        subject = subject_fields(pem)
        identity = subject["CN"]

        password = secrets.token_urlsafe(24)
        p12 = work / "identity.p12"
        openssl(
            "pkcs12", "-export", "-legacy",
            "-inkey", str(key), "-in", str(pem),
            "-name", identity,
            "-out", str(p12), "-passout", "stdin",
            stdin=password.encode(),
        )
        vault_set_bundle(
            CERTIFICATE_ITEM,
            {
                "certificate_p12_base64": base64.b64encode(p12.read_bytes()).decode(),
                "certificate_password": password,
                "sign_identity": identity,
            },
            {
                "purpose": "ios-app-store-distribution-signing",
                "source_kind": "app-store-connect-api",
                "certificate_id": certificate_id,
                "certificate_type": CERTIFICATE_TYPE,
                "serial_number": serial_number(pem),
                "expires_at": attributes.get("expirationDate", ""),
                "sign_identity": identity,
                "team_id": subject.get("OU", ""),
                "key_id": key_id,
                "created_by": CREATED_BY,
            },
        )

    print(f"stored           {CERTIFICATE_ITEM}#certificate_p12_base64, #certificate_password, #sign_identity")
    print(f"identity         {identity}")
    print(f"undo             node weles/scripts/trajectories/apple/asc/certs/asc_certs.mjs with REVOKE={certificate_id}")


# --- bundle id, app record, profile -----------------------------------------


def ensure_bundle_id(bearer: str, identifier: str, name: str, dry_run: bool) -> str | None:
    listed = call(
        f"/bundleIds?filter[identifier]={quote(identifier, safe='')}&limit=200", bearer, user_agent=USER_AGENT,
    ).get("data", [])
    for item in listed:
        if item.get("attributes", {}).get("identifier") == identifier:
            print(f"bundle id        {item['id']}  {identifier} (registered)")
            return item["id"]
    if dry_run:
        print(f"dry run: bundle id {identifier} would be registered as {name!r} on IOS")
        return None
    created = call(
        "/bundleIds", bearer, "POST",
        {"data": {"type": "bundleIds", "attributes": {"identifier": identifier, "name": name, "platform": "IOS"}}},
        user_agent=USER_AGENT,
    )
    print(f"bundle id        {created['data']['id']}  {identifier} (registered now)")
    return created["data"]["id"]


def existing_app(bearer: str, bundle_id: str) -> str | None:
    listed = call(f"/apps?filter[bundleId]={quote(bundle_id, safe='')}&limit=10", bearer, user_agent=USER_AGENT).get("data", [])
    for item in listed:
        if item.get("attributes", {}).get("bundleId") == bundle_id:
            print(f"app record       {item['id']}  {item['attributes'].get('name', '?')} (exists)")
            return item["id"]
    return None


def create_app(bearer: str, bundle_id: str, bundle_record: str, name: str, sku: str) -> str:
    """The App Store Connect app record: `altool --upload-app` refuses a build for a
    bundle id with no app behind it. Apple requires the name to be unused store-wide,
    so its refusal is the operator's cue to choose another and rerun."""
    created = call(
        "/apps", bearer, "POST",
        {
            "data": {
                "type": "apps",
                "attributes": {"name": name, "primaryLocale": "en-US", "sku": sku, "bundleId": bundle_id},
                "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": bundle_record}}},
            }
        },
        user_agent=USER_AGENT,
    )
    print(f"app record       {created['data']['id']}  {name} (created now)")
    return created["data"]["id"]


def vault_certificate_id() -> str:
    if not vault_has(CERTIFICATE_ITEM):
        fail(f"{CERTIFICATE_ITEM} is absent: run `apple-ios-signing.py mint-certificate` first")
    certificate_id = vault_item(CERTIFICATE_ITEM).get("context", {}).get("certificate_id", "")
    if not certificate_id:
        fail(f"{CERTIFICATE_ITEM} records no certificate_id in its context")
    return certificate_id


def ensure_profile(bearer: str, name: str, bundle_record: str | None, certificate_id: str, dry_run: bool) -> dict | None:
    """One App Store profile by name, signed with the vault's certificate.

    Profiles are immutable at Apple: one that exists under this name but names
    another certificate or bundle id is deleted and recreated, and that is said
    out loud, because a CI build that pinned its UUID stops until it re-reads it.
    """
    listed = call(
        f"/profiles?filter[name]={quote(name, safe='')}&include=certificates,bundleId&limit=200", bearer, user_agent=USER_AGENT,
    )
    for item in listed.get("data", []):
        attributes = item.get("attributes", {})
        if attributes.get("name") != name:
            continue
        relationships = item.get("relationships", {})
        certificates = {row.get("id") for row in relationships.get("certificates", {}).get("data", [])}
        bundle = relationships.get("bundleId", {}).get("data", {}).get("id")
        current = (
            attributes.get("profileState") == "ACTIVE"
            and certificate_id in certificates
            and (bundle_record is None or bundle == bundle_record)
        )
        if current:
            print(f"profile          {item['id']}  {name} (current, expires {attributes.get('expirationDate', '?')[:10]})")
            return item
        print(
            f"profile          {item['id']}  {name} is stale: state {attributes.get('profileState')}, "
            f"certificates {sorted(certificates)}, bundle {bundle}"
        )
        if dry_run:
            print("dry run: it would be deleted and recreated")
            return None
        call(f"/profiles/{item['id']}", bearer, "DELETE", user_agent=USER_AGENT)
        print(f"profile          {item['id']}  deleted")
    if dry_run or bundle_record is None:
        print(f"dry run: profile {name!r} ({PROFILE_TYPE}) would be created with certificate {certificate_id}")
        return None
    created = call(
        "/profiles", bearer, "POST",
        {
            "data": {
                "type": "profiles",
                "attributes": {"name": name, "profileType": PROFILE_TYPE},
                "relationships": {
                    "bundleId": {"data": {"type": "bundleIds", "id": bundle_record}},
                    "certificates": {"data": [{"type": "certificates", "id": certificate_id}]},
                },
            }
        },
        user_agent=USER_AGENT,
    )
    item = created["data"]
    print(f"profile          {item['id']}  {name} (created now, expires {item['attributes'].get('expirationDate', '?')[:10]})")
    return item


def profile(bearer: str, args: argparse.Namespace) -> None:
    certificate_id = vault_certificate_id()
    profile_name = args.profile_name or f"{args.app_name} CI AppStore"
    bundle_record = ensure_bundle_id(bearer, args.bundle_id, args.app_name, args.dry_run)
    app_id = existing_app(bearer, args.bundle_id)
    item = ensure_profile(bearer, profile_name, bundle_record, certificate_id, args.dry_run)
    if item is None:
        if app_id is None:
            print(f"dry run: an app record {args.app_name!r} (sku {args.sku or args.repository}) would be created for {args.bundle_id}")
        return
    attributes = item["attributes"]
    content = attributes.get("profileContent")
    if not content:
        # A listed profile carries its content only when asked for directly.
        content = call(f"/profiles/{item['id']}", bearer, user_agent=USER_AGENT)["data"]["attributes"].get("profileContent", "")
    if not content:
        fail(f"profile {item['id']} returned no profileContent")
    target = signing_item(args.repository)
    vault_set_bundle(
        target,
        {"provisioning_profile_base64": content},
        {
            "purpose": "ios-app-store-signing",
            "source_kind": "app-store-connect-api",
            "repository": f"{ORGANIZATION}/{args.repository}",
            "bundle_id": args.bundle_id,
            "profile_id": item["id"],
            "profile_uuid": attributes.get("uuid", ""),
            "profile_name": profile_name,
            "profile_type": PROFILE_TYPE,
            "expires_at": attributes.get("expirationDate", ""),
            "certificate_id": certificate_id,
            "created_by": CREATED_BY,
        },
    )
    print(f"stored           {target}#provisioning_profile_base64")
    # Last, because it is the one step Apple may refuse on a name, and the profile
    # above is already usable for signing whatever the app ends up being called.
    if app_id is None and bundle_record is not None:
        create_app(bearer, args.bundle_id, bundle_record, args.app_name, args.sku or args.repository)
    print(f"next             apple-ios-signing.py publish --repository {args.repository}")


# --- GitHub secrets ---------------------------------------------------------


def set_secret(repository: str, name: str, value: str) -> None:
    result = subprocess.run(
        ["gh", "secret", "set", name, "--repo", f"{ORGANIZATION}/{repository}"],
        input=value, text=True, capture_output=True,
    )
    if result.returncode:
        fail(f"gh secret set {name} --repo {ORGANIZATION}/{repository}: {' '.join((result.stderr or '').split())[:300]}")
    print(f"secret           {ORGANIZATION}/{repository}  {name}")


def publish(args: argparse.Namespace, key_id: str, issuer: str, private_key: str) -> None:
    target = signing_item(args.repository)
    if not vault_has(target):
        fail(f"{target} is absent: run `apple-ios-signing.py profile --repository {args.repository} …` first")
    values = {
        "AC_API_KEY_ID": key_id,
        "AC_API_ISSUER_ID": issuer,
        # The workflows `base64 --decode` this into AuthKey_<id>.p8.
        "AC_API_KEY_P8": base64.b64encode(private_key.strip().encode() + b"\n").decode(),
        "IOS_DIST_P12_B64": vault_get(CERTIFICATE_ITEM, "certificate_p12_base64"),
        "IOS_DIST_P12_PASSWORD": vault_get(CERTIFICATE_ITEM, "certificate_password"),
        "IOS_PROFILE_B64": vault_get(target, "provisioning_profile_base64"),
        # Package.swift pins private wisent-ai packages by URL; a GitHub-hosted
        # runner clones them with this, the same token Stado hands desktop
        # repositories as RELEASE_BOOTSTRAP_TOKEN.
        "WISENT_PACKAGES_TOKEN": vault_get(PACKAGES_TOKEN_ITEM, "value"),
    }
    for name, value in values.items():
        if not value:
            fail(f"{name} resolved to an empty value; nothing was published")
    for name, value in values.items():
        set_secret(args.repository, name, value)
    print(f"published        {len(values)} secrets; the TestFlight workflow of {ORGANIZATION}/{args.repository} can now resolve, sign and upload")


# --- listing ----------------------------------------------------------------


def show(bearer: str) -> None:
    rows = list_certificates(bearer)
    print(f"certificates     {len(rows)}")
    for row in sorted(rows, key=lambda item: item.get("attributes", {}).get("certificateType", "")):
        print(f"  {describe(row)}")
    bundles = call("/bundleIds?limit=200", bearer, user_agent=USER_AGENT).get("data", [])
    print(f"bundle ids       {len(bundles)}")
    for row in sorted(bundles, key=lambda item: item.get("attributes", {}).get("identifier", "")):
        attributes = row.get("attributes", {})
        print(f"  {row['id']:<12} {attributes.get('platform', '?'):<10} {attributes.get('identifier', '?'):<32} {attributes.get('name', '')}")
    apps = call("/apps?limit=200", bearer, user_agent=USER_AGENT).get("data", [])
    print(f"apps             {len(apps)}")
    for row in sorted(apps, key=lambda item: item.get("attributes", {}).get("bundleId", "")):
        attributes = row.get("attributes", {})
        print(f"  {row['id']:<12} {attributes.get('bundleId', '?'):<32} {attributes.get('name', '')}  sku {attributes.get('sku', '')}")
    profiles = call("/profiles?limit=200", bearer, user_agent=USER_AGENT).get("data", [])
    print(f"profiles         {len(profiles)}")
    for row in sorted(profiles, key=lambda item: item.get("attributes", {}).get("name", "")):
        attributes = row.get("attributes", {})
        print(
            f"  {row['id']:<12} {attributes.get('profileType', '?'):<20} {attributes.get('profileState', '?'):<8} "
            f"expires {attributes.get('expirationDate', '?')[:10]}  {attributes.get('name', '')}"
        )
    if vault_has(CERTIFICATE_ITEM):
        context = vault_item(CERTIFICATE_ITEM).get("context", {})
        print(f"vault            {CERTIFICATE_ITEM}: certificate {context.get('certificate_id', '?')}, {context.get('sign_identity', '?')}")
    else:
        print(f"vault            {CERTIFICATE_ITEM}: absent")


def main() -> int:
    root = argparse.ArgumentParser(prog="apple-ios-signing.py", description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    add_credential_arguments(root, os.environ)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="certificates, bundle ids, apps and profiles the account holds")
    minter = commands.add_parser("mint-certificate", help=f"create an {CERTIFICATE_TYPE} certificate and store it as {CERTIFICATE_ITEM}")
    minter.add_argument("--dry-run", action="store_true")
    minter.add_argument("--replace", action="store_true", help=f"mint even though {CERTIFICATE_ITEM} exists, overwriting it")
    prof = commands.add_parser("profile", help="register the bundle id and app record, create the App Store profile, store <repository>-signing")
    prof.add_argument("--repository", required=True, help="repository name inside wisent-ai, e.g. jeden-ios")
    prof.add_argument("--bundle-id", required=True, help="e.g. ai.wisent.jeden")
    prof.add_argument("--app-name", required=True, help="the App Store Connect app name; Apple requires it to be unused store-wide")
    prof.add_argument("--profile-name", help='defaults to "<app-name> CI AppStore", the name project.yml pins')
    prof.add_argument("--sku", help="defaults to the repository name")
    prof.add_argument("--dry-run", action="store_true")
    pub = commands.add_parser("publish", help="set the six GitHub Actions secrets of one repository from the vault")
    pub.add_argument("--repository", required=True)
    args = root.parse_args()

    key_id, issuer, private_key = credentials(args)
    bearer = token(key_id, issuer, private_key)
    if args.command == "list":
        show(bearer)
    elif args.command == "mint-certificate":
        mint_certificate(bearer, key_id, args.dry_run, args.replace)
    elif args.command == "profile":
        profile(bearer, args)
    elif args.command == "publish":
        publish(args, key_id, issuer, private_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
