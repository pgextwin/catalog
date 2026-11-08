#!/usr/bin/env python3
"""Private, nonpublishing original HypoPG 1.4.1 Windows ZIP qualifier (PG14-16).

Even a PASS means original-byte/ZIP/PE/SQL inspection ONLY. This script
cannot issue a signed admission, establish complete licenses/NOTICE/provenance,
or make a user CLI download authorized. The ZIP is never uploaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import zipfile

PINS = {
    "14": {"assetId": 164673161, "bytes": 23115},
    "15": {"assetId": 164673166, "bytes": 23123},
    "16": {"assetId": 164673171, "bytes": 22997},
}
REPO = "HypoPG/hypopg"
RELEASE_ID = 153113229
REPO_ID = 37308208
VERSION = "1.4.1"
SAFE_NAME = re.compile(r"[A-Za-z0-9_+.-]+\Z")


def demand(ok, message):
    if not ok:
        raise ValueError("HYPoPG original review DENY: " + message)


def pe_amd64(data):
    demand(len(data) >= 128 and data[:2] == b"MZ", "missing DLL MZ")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    demand(offset + 24 <= len(data) and data[offset:offset + 4] == b"PE\0\0"
           and struct.unpack_from("<H", data, offset + 4)[0] == 0x8664,
           "DLL is not Windows PE AMD64")


def review(original, pg, pgroot=None):
    demand(pg in PINS, "unsupported PG major")
    file = Path(original)
    demand(file.is_file() and not file.is_symlink() and
           file.stat().st_size == PINS[pg]["bytes"], "unexpected original ZIP size")
    raw = file.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    payload = {}
    notices = []
    seen = set()
    expanded = 0
    with zipfile.ZipFile(file) as z:
        members = z.infolist()
        demand(3 <= len(members) <= 200, "unexpected ZIP member count")
        for member in members:
            name = member.filename
            leaf = name.rstrip("/").rsplit("/", 1)[-1]
            demand(bool(name) and not name.startswith("/") and "\\" not in name
                   and ":" not in name and "\x00" not in name
                   and all(part not in (".", "..", "") for part in name.rstrip("/").split("/"))
                   and name.casefold() not in seen,
                   "unsafe/duplicate ZIP path")
            seen.add(name.casefold())
            demand(stat.S_IFMT(member.external_attr >> 16) != stat.S_IFLNK,
                   "symlink in ZIP")
            demand(member.file_size <= 8_000_000 and
                   member.file_size <= 300 * max(1, member.compress_size),
                   "unsafe ZIP expansion")
            expanded += member.file_size
            demand(expanded <= 20_000_000, "ZIP cumulative expansion exceeded")
            if member.is_dir():
                continue
            demand(SAFE_NAME.fullmatch(leaf) is not None, "unsafe source filename")
            if leaf.casefold().startswith(("license", "notice", "copying")):
                notices.append(name)
            if (leaf.casefold() == "hypopg.dll" or
                leaf.casefold() == "hypopg.control" or
                re.fullmatch(r"hypopg--[A-Za-z0-9_.+-]+\.sql", leaf, re.IGNORECASE)):
                demand(leaf.casefold() not in payload, "duplicate install leaf")
                demand(member.file_size <= 5_000_000, "oversized install member")
                payload[leaf.casefold()] = z.read(member)
        demand(z.testzip() is None, "ZIP CRC failure")
    demand("hypopg.dll" in payload and "hypopg.control" in payload
           and any(x.startswith("hypopg--") and x.endswith(".sql") for x in payload),
           "missing original DLL/control/SQL")
    pe_amd64(payload["hypopg.dll"])
    if pgroot is not None:
        root = Path(pgroot)
        locations = []
        for leaf, value in sorted(payload.items()):
            folder = root / ("lib" if leaf == "hypopg.dll" else "share/extension")
            dest = folder / leaf
            demand(folder.is_dir() and not folder.is_symlink() and
                   not dest.exists() and not dest.is_symlink(),
                   "unsafe/missing/destination collision in disposable PostgreSQL")
            locations.append((dest, value))
        # No archive extraction; create-only *allowlisted* extension files to
        # the disposable Windows CI installation only, never output original ZIP.
        created = []
        try:
            for dest, value in locations:
                with dest.open("xb") as out:
                    out.write(value)
                created.append(dest)
        except Exception:
            for path in created:
                path.unlink(missing_ok=True)
            raise
    return {
        "schemaVersion": "pgextwin-issue112-private-original-byte-review/v1",
        "provider": REPO, "repositoryId": REPO_ID, "releaseId": RELEASE_ID,
        "assetId": PINS[pg]["assetId"], "postgresqlMajor": pg,
        "originalBytes": len(raw), "independentlyHashedSha256": digest,
        "zipMembers": len(members), "zipCrc": "PASS",
        "peMachine": "AMD64", "installFiles": sorted(payload),
        "packagedNoticePaths": sorted(notices),
        "noticeProvenanceAccepted": False,
        "publisherAuthorized": False,
        "downloadAuthorized": False, "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "state": "CANDIDATE_ONLY_ORIGINAL_BYTE_REVIEW",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--pg", choices=sorted(PINS), required=True)
    parser.add_argument("--pgroot", type=Path, required=True)
    args = parser.parse_args()
    result = review(args.zip, args.pg, args.pgroot)
    print("HYPoPG_ORIGINAL_PRIVATE_REVIEW=" +
          json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
