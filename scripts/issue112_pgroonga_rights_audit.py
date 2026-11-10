#!/usr/bin/env python3
"""Strictly nonpublishing exact-original PGroonga 4.1.0 Windows rights receipts."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.request
import zipfile

PINS = {
    14: (53806600, "39d2685f234c8b45563f57f113bd8c84cc1ae4e8c0c22e6826bf168ba1c0ab39"),
    15: (53863529, "fbc73734028b0b2372a6ee6538863999c2f9f06ec9f1be633ac460c7d8a0d4f1"),
    16: (53751780, "40c71f7890e6ceb46f79fdc10e596da21bfb622f7c9d1f8be7784175d96df7e8"),
    17: (53836587, "dcbd356ab8a7c8fc3a3cc7082b4f99a1884b5a68674e25ef4bbe56583c38147b"),
    18: (53826667, "3ccbfaf771ec7a0edf61dabe0eb60188dcc22feff8449a7e96afdb87641630ab"),
}
VERSION = "4.1.0"
DOC_PATTERN = re.compile(r"(?:^|[._-])(?:licen[cs]e|notice|copying|copyright)(?:$|[._-])", re.I)
MAX_LICENSE = 512 * 1024
MAX_BIN = 64 * 1024 * 1024

def original_name(major):
    if major not in PINS:
        raise ValueError("Unsupported PostgreSQL major")
    return f"pgroonga-{VERSION}-postgresql-{major}-x64.zip"

def original_url(major):
    return f"https://github.com/pgroonga/pgroonga/releases/download/{VERSION}/{original_name(major)}"

def verify_file(path, major):
    size, sha = PINS[major]
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > size:
                raise ValueError("Original exceeds pinned size")
            digest.update(chunk)
    if count != size or digest.hexdigest() != sha:
        raise ValueError("Original ZIP size/SHA256 mismatch")

def audit_members(path, major, *, require_pin=True):
    if require_pin:
        verify_file(path, major)
    records, docs, by_basename, seen = [], [], {}, set()
    expanded = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > 20000:
            raise ValueError("ZIP member count out of bounds")
        for entry in entries:
            name = entry.filename.replace(chr(92), "/")
            pieces = name.rstrip("/").split("/")
            if (not name or name.startswith("/") or ":" in name
                    or any(p in ("", ".", "..") for p in pieces)
                    or any(ord(c) < 32 for c in name)
                    or ((entry.external_attr >> 16) & 0o170000) == 0o120000):
                raise ValueError("Unsafe ZIP member path")
            folded = name.casefold()
            if folded in seen:
                raise ValueError("Duplicate or case-colliding ZIP entry")
            seen.add(folded)
            if entry.is_dir():
                continue
            expanded += entry.file_size
            if expanded > 1024 ** 3:
                raise ValueError("ZIP expanded size cap exceeded")
            p = PurePosixPath(name)
            doc = bool(DOC_PATTERN.search(p.name))
            binary = p.suffix.lower() in (".dll", ".exe")
            if not doc and not binary:
                continue
            limit = MAX_LICENSE if doc else MAX_BIN
            if entry.file_size <= 0 or entry.file_size > limit:
                raise ValueError("Invalid notice/binary member size")
            digest = hashlib.sha256()
            preview = bytearray()
            count = 0
            with archive.open(entry) as stream:
                while chunk := stream.read(1024 * 1024):
                    count += len(chunk)
                    if count > entry.file_size:
                        raise ValueError("Member length overflow")
                    digest.update(chunk)
                    if doc and len(preview) < 300:
                        preview.extend(chunk[:300 - len(preview)])
            if count != entry.file_size:
                raise ValueError("Truncated member")
            row = {"path": name, "bytes": count, "sha256": digest.hexdigest()}
            if doc:
                row["openingText"] = " ".join(preview.decode("utf-8", errors="replace").split())[:180]
                docs.append(row)
            if binary:
                row.update(componentIdentityVerified=False,
                           componentLicenseNoticeVerified=False,
                           exactProducerProvenanceVerified=False,
                           targetWindowsDynamicDependenciesVerified=False)
                records.append(row)
                by_basename.setdefault(p.name.lower(), []).append(name)
        if archive.testzip() is not None:
            raise ValueError("ZIP CRC mismatch")
    if not any(r["path"].lower().endswith("/pgroonga.dll") for r in records):
        raise ValueError("Missing PGroonga DLL")
    if not any(n.lower().endswith("/pgroonga.control") for n in seen):
        raise ValueError("Missing PGroonga control")
    return {
        "schemaVersion": "pgextwin-pgroonga-rights-receipt-nonpublishing/v1",
        "pgMajor": major, "version": VERSION, "origin": original_url(major),
        "expectedZipBytes": PINS[major][0], "expectedZipSha256": PINS[major][1],
        "zipMemberCount": len(entries),
        "licenseNoticeFiles": sorted(docs, key=lambda r: r["path"]),
        "binaryMemberReceipts": sorted(records, key=lambda r: r["path"]),
        "duplicateBinaryBasenames": {k: v for k, v in sorted(by_basename.items()) if len(v) > 1},
        "licenseNoticeCandidatesCount": len(docs),
        "binaryMemberCount": len(records),
        "sourceTagWindowsBuildWorkflow": "https://github.com/pgroonga/pgroonga/blob/4.1.0/.github/workflows/windows.yml",
        "officialLicenseExplanation": "https://pgroonga.github.io/#license",
        "licenseNoticeClosureVerified": False,
        "thirdPartyComponentVersionsVerified": False,
        "exactSourceToReleaseBinaryAttestationVerified": False,
        "targetWindowsDynamicDependenciesVerified": False,
        "redistributionAuthorized": False,
        "independentSigstoreAdmissionVerified": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "publisherAuthorized": False,
    }

def download_original(major, target):
    size, _ = PINS[major]
    req = urllib.request.Request(original_url(major), headers={"User-Agent": "pgextwin-rights-probe/1"})
    with urllib.request.urlopen(req, timeout=90) as response, target.open("xb") as stream:
        count = 0
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > size:
                raise ValueError("Original download exceeds pinned size")
            stream.write(chunk)
    verify_file(target, major)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", type=int, choices=tuple(PINS), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pgroonga-rights-") as folder:
        target = Path(folder) / original_name(args.pg)
        download_original(args.pg, target)
        result = audit_members(target, args.pg)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    print("PGROONGA_RIGHTS=OBSERVED NOTICE_CLOSURE=UNVERIFIED "
          "PRODUCER_ATTESTATION=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")

if __name__ == "__main__":
    main()
