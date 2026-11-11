#!/usr/bin/env python3
"""Independent official TimescaleDB 2.31.0 Windows ZIP bytes audit, DENY-only.

This private CI audit fetches official public originals at immutable release
names, rehashes *actual response bytes* against the already reviewed API-only
baseline, and checks ZIP safety. A matching API digest is not a producer
signature, source-to-binary provenance, rights clearance or public admission.
No ZIP is retained, installed, mirrored, published or signed.
"""
import argparse
import json
from pathlib import Path
import re
import stat
import tempfile
import urllib.parse
import urllib.request
import zipfile

from issue112_latest_external_review import ROOT, timescaledb_observed_baseline
from issue112_pgroonga_independent_rehash import copy_checked_bytes

RELEASE_URL = "https://github.com/timescale/timescaledb/releases/download/2.31.0"
ALLOWED_HOSTS = frozenset((
    "github.com", "release-assets.githubusercontent.com",
    "objects.githubusercontent.com", "github-releases.githubusercontent.com",
))
MAJORS = ("16", "17", "18")
MAX_ZIP_MEMBERS = 4096
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


def checked_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or
            parsed.username is not None or parsed.password is not None or
            parsed.port not in (None, 443)):
        raise ValueError("Unapproved original Release HTTP redirect")
    return url


class OnlyOfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def original_pin(pg, root=ROOT):
    if pg not in MAJORS:
        raise ValueError("No observed TimescaleDB original for this PG major")
    source = timescaledb_observed_baseline(root)
    matching = [x for x in source["records"] if x["pgMajor"] == pg]
    if len(matching) != 1:
        raise ValueError("Missing or duplicated original identity")
    row = matching[0]
    if (source["releaseId"] != 418582851 or
            row["assetName"] != f"timescaledb-postgresql-{pg}-windows-amd64.zip" or
            not re.fullmatch(r"[a-f0-9]{64}", row["apiSha256"])):
        raise ValueError("Unreviewed original release identity")
    return {
        "pg": pg, "name": row["assetName"], "assetId": row["assetId"],
        "releaseId": source["releaseId"], "size": row["apiBytes"],
        "sha256": row["apiSha256"],
        "url": checked_url(f"{RELEASE_URL}/{row['assetName']}"),
    }


def inspect_zip(path):
    """Bounded ZIP metadata/CRC/paths audit. No extraction or DLL execution."""
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not 0 < len(entries) <= MAX_ZIP_MEMBERS:
            raise ValueError("Unsafe or empty original ZIP member count")
        seen = set()
        total = 0
        dll_count = 0
        notices = []
        for entry in entries:
            name = entry.filename
            parts = name.rstrip("/").split("/")
            if (not name or name.startswith(("/", "\\")) or "\\" in name or
                    ":" in name or any(part in ("", ".", "..") for part in parts) or
                    name.casefold() in seen or (entry.flag_bits & 1) or
                    stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError("Unsafe original ZIP member")
            seen.add(name.casefold())
            total += entry.file_size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Original ZIP decompression budget exceeded")
            if not entry.is_dir() and name.casefold().endswith(".dll"):
                dll_count += 1
            if re.search(r"(?:^|/)(?:licen[cs]e|notice|copying|third.party)(?:[./_-]|$)",
                         name, re.IGNORECASE):
                notices.append(name)
        if dll_count < 1:
            raise ValueError("No Windows DLL in observed TimescaleDB ZIP")
        if archive.testzip() is not None:
            raise ValueError("Original ZIP CRC verification failed")
        return {"members": len(entries), "dllMembers": dll_count,
                "declaredUncompressedBytes": total,
                "potentialNoticePaths": sorted(notices)}


def audit(pg, root=ROOT, opener=None):
    pin = original_pin(pg, root)
    opener = opener or urllib.request.build_opener(OnlyOfficialRedirects())
    request = urllib.request.Request(
        pin["url"], headers={"User-Agent": "pgextwin-issue112-timescaledb-byte-audit/1"})
    with tempfile.TemporaryDirectory(prefix="issue112-timescale-") as tmp:
        dest = Path(tmp) / pin["name"]
        with opener.open(request, timeout=90) as response:
            checked_url(response.geturl())
            actual_size, actual_sha = copy_checked_bytes(
                response, dest, pin["size"], pin["sha256"])
        inventory = inspect_zip(dest)
    return {
        "schemaVersion": "pgextwin-issue112-timescaledb-original-rehash-deny-only/v1",
        "sourceRepo": "timescale/timescaledb", "releaseTag": "2.31.0",
        "releaseId": pin["releaseId"], "assetId": pin["assetId"],
        "assetName": pin["name"], "pgMajor": pg,
        "independentOriginalBytes": actual_size, "independentSha256": actual_sha,
        "zipSafetyChecked": True, "zipInventory": inventory,
        "producerSourceToBinaryAttestationVerified": False,
        "rightsAndNoticesClosureVerified": False,
        "windowsRuntimeVerified": False, "independentSignedAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "redistributionAuthorized": False, "releaseAuthorized": False,
        "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=MAJORS, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.pg), sort_keys=True))
    print(f"TIMESCALEDB_ORIGINAL_REHASH=PASS PG={args.pg} "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
