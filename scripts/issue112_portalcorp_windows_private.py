#!/usr/bin/env python3
"""Issue #112 portalcorp PG16: private original ZIP inspection and vetted staging.

Only read verified original provider bytes and stage explicitly allowlisted files
inside disposable Windows CI. Reuse the common ZIP safety auditor. This script
does not authorize a download, signature, Release, mirror or redistribution.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import zipfile

ASSET_SHA256 = "a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571"
ASSET_BYTES = 163732
PE_MACHINE_AMD64 = 0x8664
FILE = re.compile(
    r"(?:(?P<root>[A-Za-z0-9_.-]+)/)?(?P<member>"
    r"lib/vector[.]dll|share/extension/vector[.]control|"
    r"share/extension/vector--[A-Za-z0-9._-]+[.]sql)\Z"
)


def require(ok, message):
    if not ok:
        raise ValueError("Portalcorp PG16 original ZIP DENY: " + message)


def audit_existing_zip(payload):
    path = Path(__file__).with_name("issue112-external-zip-pilot.py")
    spec = importlib.util.spec_from_file_location("_issue112_original_zip", path)
    require(spec is not None and spec.loader is not None, "shared ZIP auditor absent")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.audit_zip(payload)


def inspect_and_stage(payload, lib, share, *, expected_sha=None):
    require(type(payload) is bytes and 0 < len(payload) <= 2_000_000,
            "unbounded original bytes")
    if expected_sha is not None:
        require(len(payload) == ASSET_BYTES and
                hashlib.sha256(payload).hexdigest() == expected_sha,
                "original size or exact SHA256 mismatch")
    audit = audit_existing_zip(payload)  # Paths, ZIP CRC, bombs, symlinks, duplicates.
    selected = []
    with zipfile.ZipFile(__import__("io").BytesIO(payload)) as archive:
        for record in archive.infolist():
            match = FILE.fullmatch(record.filename)
            if match:
                selected.append((match.group("root") or "", match.group("member"),
                                 archive.read(record)))
    require(len(selected) >= 3 and len(selected) <= 100,
            "unexpected vetted archive member count")
    roots = {p for p, _, _ in selected}
    require(len(roots) == 1, "mixed archive roots")
    members = [name for _, name, _ in selected]
    require(members.count("lib/vector.dll") == 1 and
            members.count("share/extension/vector.control") == 1 and
            any(m.startswith("share/extension/vector--") and m.endswith(".sql")
                for m in members), "missing unique DLL/control/SQL")
    control = next(blob for _, path, blob in selected
                   if path == "share/extension/vector.control")
    require(len(control) < 4096 and
            re.search(rb"(?m)^\s*default_version\s*=\s*['\"]0[.]8[.]0['\"]", control),
            "upstream pgvector v0.8.0 control not verified")
    dll = next(blob for _, path, blob in selected if path == "lib/vector.dll")
    require(128 <= len(dll) <= 2_000_000 and dll.startswith(b"MZ"), "invalid PE image")
    offset = struct.unpack_from("<I", dll, 0x3c)[0]
    require(offset + 6 <= len(dll) and dll[offset:offset+4] == b"PE\0\0" and
            struct.unpack_from("<H", dll, offset + 4)[0] == PE_MACHINE_AMD64,
            "Windows DLL is not PE AMD64")
    require(sum(len(b) for _, _, b in selected) <= 5_000_000,
            "vetted files exceed staging budget")

    lib = Path(lib)
    ext = Path(share) / "extension"
    require(lib.is_dir() and ext.is_dir(), "disposable PostgreSQL target missing")
    plan = []
    for _, member, blob in selected:
        dst = lib / "vector.dll" if member == "lib/vector.dll" else ext / member.rsplit("/", 1)[1]
        require(not dst.exists() and not dst.is_symlink(), "refuse to overwrite installed file")
        plan.append((dst, blob))
    for dst, blob in plan:
        with dst.open("xb") as file:
            file.write(blob)
    return {"originalSha256": hashlib.sha256(payload).hexdigest(),
            "originalBytes": len(payload), "zipMembers": audit["zipMembers"],
            "vettedFiles": len(plan), "peMachine": "AMD64", "pgMajor": 16,
            "extensionVersion": "0.8.0", "signedAdmission": False,
            "getAuthorized": False, "mirrorAuthorized": False}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--original", required=True, type=Path)
    p.add_argument("--pkglibdir", required=True, type=Path)
    p.add_argument("--sharedir", required=True, type=Path)
    a = p.parse_args()
    original = a.original
    require(original.is_file() and not original.is_symlink(), "original ZIP unavailable")
    result = inspect_and_stage(original.read_bytes(), a.pkglibdir, a.sharedir,
                               expected_sha=ASSET_SHA256)
    print("PORTALCORP_ORIGINAL_PG16_VETTED_STAGE=PASS " +
          json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
