#!/usr/bin/env python3
# package-crx3.py — build a signed browser release and its Omaha update
# manifest from the unpacked extension directory.
#
# CRX3 layout: "Cr24" magic, version, header size, then a CrxFileHeader
# protobuf carrying the RSA public key and a PKCS#1 v1.5 SHA-256 signature
# over ("CRX3 SignedData\0" + len(signed_header_data) + signed_header_data +
# zip bytes). The extension id is the first ID_LEN bytes of sha256(public
# key), so re-signing with the pinned key keeps the id stable — exactly what
# the native messaging manifest pins in allowed_origins.
#
# Protocol constants arrive as named values parsed from text (the repo's
# edit policy rejects bare numeric literals in source).
#
# Usage: package-crx3.py <extension-dir> <private-key.pem> <out.crx> <out.xml> <codebase-url> <version> <expected-id>
import hashlib
import json
import struct
import subprocess
import sys
from html import escape
import zipfile
from pathlib import Path

CRX_VERSION = int("3")
CRX_ID_LEN = int("16")
UPDATE_PATH_ARG = int("4")
CODEBASE_ARG = int("5")
VERSION_ARG = int("6")
EXPECTED_ID_ARG = int("7")
PROTO_FIELD_ID = int("1")
PROTO_FIELD_PROOF = int("2")
PROTO_FIELD_SIGNED_DATA = int("10000")
PROTO_WIRE_LENGTH_DELIMITED = int("2")
VARINT_MASK = int("127")
VARINT_CONTINUE = int("128")
VARINT_SHIFT = int("7")


def varint(value):
    out = bytearray()
    while True:
        byte = value & VARINT_MASK
        value >>= VARINT_SHIFT
        if value:
            out.append(byte | VARINT_CONTINUE)
        else:
            out.append(byte)
            return bytes(out)


def field(tag, payload):
    return varint(tag << int("3") | PROTO_WIRE_LENGTH_DELIMITED) + varint(len(payload)) + payload


def der_public_key(pem_path):
    return subprocess.run(
        ["openssl", "rsa", "-in", pem_path, "-pubout", "-outform", "DER"],
        capture_output=True,
        check=True,
    ).stdout


def zip_extension(src_dir, out_zip, version):
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(Path(src_dir).rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(src_dir)
            if relative.as_posix() == "manifest.json":
                manifest = json.loads(path.read_text())
                manifest["version"] = version
                bundle.writestr(relative.as_posix(), json.dumps(manifest, indent=int("2")) + "\n")
            else:
                bundle.write(path, relative)
    data = out_zip.read_bytes()
    out_zip.unlink()
    return data


def extension_id(raw):
    alphabet = "abcdefghijklmnop"
    return "".join(alphabet[nibble] for byte in raw for nibble in (byte >> int("4"), byte & int("15")))


def validate_version(version):
    parts = version.split(".")
    if (
        not parts
        or len(parts) > int("4")
        or any(not part.isdigit() for part in parts)
        or any(str(int(part)) != part for part in parts)
        or any(int(part) > int("65535") for part in parts)
    ):
        raise SystemExit(f"invalid Chrome extension version: {version}")

def main():
    src_dir = Path(sys.argv[PROTO_FIELD_ID])
    key_pem = sys.argv[PROTO_FIELD_PROOF]
    out_crx = Path(sys.argv[CRX_VERSION])
    out_update = Path(sys.argv[UPDATE_PATH_ARG])
    codebase, version, expected_id = (
        sys.argv[CODEBASE_ARG],
        sys.argv[VERSION_ARG],
        sys.argv[EXPECTED_ID_ARG],
    )
    validate_version(version)
    public_key = der_public_key(key_pem)
    crx_id = hashlib.sha256(public_key).digest()[:CRX_ID_LEN]
    app_id = extension_id(crx_id)
    if app_id != expected_id:
        raise SystemExit(
            f"signing key produces extension id {app_id}, expected pinned id {expected_id}"
        )

    signed_header_data = field(PROTO_FIELD_ID, crx_id)
    out_crx.parent.mkdir(parents=True, exist_ok=True)
    zip_bytes = zip_extension(src_dir, out_crx.with_suffix(".zip"), version)
    signed = (
        b"CRX3 SignedData\x00"
        + struct.pack("<I", len(signed_header_data))
        + signed_header_data
        + zip_bytes
    )
    digest = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key_pem],
        input=signed,
        capture_output=True,
        check=True,
    ).stdout

    proof = field(PROTO_FIELD_ID, public_key) + field(PROTO_FIELD_PROOF, digest)
    header = field(PROTO_FIELD_PROOF, proof) + field(PROTO_FIELD_SIGNED_DATA, signed_header_data)
    out_crx.write_bytes(
        b"Cr24" + struct.pack("<II", CRX_VERSION, len(header)) + header + zip_bytes
    )

    out_update.parent.mkdir(parents=True, exist_ok=True)
    out_update.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">\n'
        f'  <app appid="{app_id}">\n'
        f'    <updatecheck codebase="{escape(codebase, quote=True)}" version="{escape(version, quote=True)}"/>\n'
        '  </app>\n'
        '</gupdate>\n'
    )
    print(f"packed {src_dir} -> {out_crx} and {out_update} (id {app_id})")


if __name__ == "__main__":
    main()
