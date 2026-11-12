#!/usr/bin/env python3
"""Exact original TimescaleDB Windows DLL PE/byte receipts, NONPUBLISHING.

This is a new component-level intake, not a retry of the successful original
ZIP rehash workflow. A member hash or matching PE header does not prove its
license, source revision, dependencies, signed producer, or GET authorization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import urllib.request
import zipfile

from issue112_pgroonga_independent_rehash import copy_checked_bytes
from issue112_timescaledb_original_rehash import (
    MAJORS, OnlyOfficialRedirects, checked_url, inspect_zip, original_pin,
)

MAX_DLL_BYTES = 64 * 1024 * 1024
EXPECTED_DLLS = 3  # Existing successful Run 43116446694, all three PG majors.


def pe_amd64_header(lead):
    if len(lead) < 0x40 or lead[:2] != b"MZ":
        raise ValueError("DLL does not start with a DOS MZ header")
    offset = struct.unpack_from("<I", lead, 0x3C)[0]
    if offset < 0x40 or offset > len(lead) - 26:
        raise ValueError("Invalid bounded PE header offset")
    if lead[offset:offset + 4] != b"PE\0\0":
        raise ValueError("DLL lacks PE signature")
    machine, = struct.unpack_from("<H", lead, offset + 4)
    optional_size, = struct.unpack_from("<H", lead, offset + 20)
    if machine != 0x8664 or optional_size < 2 or offset + 24 + optional_size > len(lead):
        raise ValueError("DLL is not a bounded AMD64 PE image")
    magic, = struct.unpack_from("<H", lead, offset + 24)
    if magic != 0x20B:
        raise ValueError("DLL is not PE32+ AMD64")
    return "AMD64_PE32_PLUS_HEADER_ONLY"


def dll_receipts(zip_path):
    """Read exact DLL bytes; reject unsafe ZIP via the shared validated guard."""
    inventory = inspect_zip(zip_path)
    if inventory["dllMembers"] != EXPECTED_DLLS:
        raise ValueError("Unexpected TimescaleDB DLL count")
    result = []
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            if member.is_dir() or not member.filename.casefold().endswith(".dll"):
                continue
            if member.file_size < 256 or member.file_size > MAX_DLL_BYTES:
                raise ValueError("Unbounded or empty PE DLL")
            digest = hashlib.sha256()
            count = 0
            header = b""
            with archive.open(member) as stream:
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    count += len(block)
                    if count > member.file_size or count > MAX_DLL_BYTES:
                        raise ValueError("DLL exceeded declared size")
                    if len(header) < 4096:
                        header += block[:4096 - len(header)]
                    digest.update(block)
            if count != member.file_size:
                raise ValueError("Incomplete DLL member")
            result.append({
                "path": member.filename,
                "bytes": count,
                "sha256": digest.hexdigest(),
                "peObservation": pe_amd64_header(header),
                "actualSourceComponent": "UNVERIFIED",
                "componentLicenseAndNotice": "UNVERIFIED",
                "runtimeDependencies": "UNVERIFIED",
                "producerSourceToBinaryProvenance": "UNVERIFIED",
            })
    if len(result) != EXPECTED_DLLS:
        raise ValueError("Incomplete TimescaleDB DLL inventory")
    return {"dllMembers": result, "zipInventory": inventory}


def audit(pg, opener=None):
    pin = original_pin(pg)
    opener = opener or urllib.request.build_opener(OnlyOfficialRedirects())
    req = urllib.request.Request(pin["url"], headers={
        "User-Agent": "pgextwin-issue112-timescaledb-dll-intake/1",
    })
    with tempfile.TemporaryDirectory(prefix="issue112-timescale-dll-") as folder:
        path = Path(folder) / pin["name"]
        with opener.open(req, timeout=90) as response:
            checked_url(response.geturl())
            size, digest = copy_checked_bytes(
                response, path, pin["size"], pin["sha256"])
        components = dll_receipts(path)
    return {
        "schemaVersion": "pgextwin-issue112-timescaledb-dll-intake/v1",
        "state": "CANDIDATE_ONLY_NONPUBLISHING",
        "pgMajor": pg, "assetId": pin["assetId"],
        "originalBytes": size, "originalSha256": digest,
        **components,
        "allBinaryComponentLicensesVerified": False,
        "completeNoticesVerified": False,
        "dynamicDependenciesVerified": False,
        "producerBuildToAssetSignatureVerified": False,
        "newSourceSpecificSignedAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=MAJORS, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.pg), sort_keys=True))
    print("TIMESCALEDB_DLL_RECEIPTS=OBSERVED PG=" + args.pg +
          " RIGHTS=UNVERIFIED PROVENANCE=UNVERIFIED PUBLIC_GET=DENY "
          "MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
