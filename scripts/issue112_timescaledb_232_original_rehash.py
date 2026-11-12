#!/usr/bin/env python3
"""Independent 2.32.0 TimescaleDB official original-byte verification; DENY-only.

Only reuses the strict new-stable offline review metadata, shared bounded
ZIP/redirect/sha256 verifier and disposable CI staging. It does not confer
producer provenance, rights, Windows runtime acceptance or public GET.
"""
import argparse
import json
from pathlib import Path
import tempfile
import urllib.request

from issue112_latest_external_review import ROOT, DENY, make_plan
from issue112_timescaledb_original_rehash import (
    OnlyOfficialRedirects, checked_url, inspect_zip,
)
from issue112_pgroonga_independent_rehash import copy_checked_bytes

VERSION = "2.32.0"
RELEASE_ID = 442824242
RELEASE_URL = "https://github.com/timescale/timescaledb/releases/download/2.32.0"
MAJORS = ("16", "17", "18")


def original_pin(pg, root=ROOT):
    if pg not in MAJORS:
        raise ValueError("No new stable TimescaleDB ZIP for this major")
    review = make_plan(root, pg=pg, extension="timescaledb",
                       version=VERSION, source="timescaledb")
    rows = review["selected"]
    if (len(rows) != 1 or review["admittedAssets"] != 0 or
            any(review.get(flag) is not False for flag in DENY)):
        raise ValueError("Non-denying or ambiguous official 2.32.0 candidate")
    row = rows[0]
    name = f"timescaledb-postgresql-{pg}-windows-amd64.zip"
    prefix = f"github-metadata:timescale/timescaledb:{RELEASE_ID}:"
    ident = row["packageIdentity"]
    if (row["source"] != "TIMESCALEDB_REHASHED_ORIGINAL_ONLY_2_32" or
            row["version"] != VERSION or row["pgMajor"] != pg or
            row["provider"] != "timescale/timescaledb" or
            row["assetName"] != name or row["format"] != "zip" or
            row["originalBytes"] != row["apiObservedBytes"] or
            row["originalSha256"] != row["apiObservedSha256"] or
            row["originalRehashEvidenceRunId"] != 43242594902 or
            not isinstance(row.get("originalRehashEvidenceJobId"), int) or
            not isinstance(ident, str) or not ident.startswith(prefix) or
            not ident[len(prefix):].isdigit() or
            "INDEPENDENT_ORIGINAL_BYTES_NOT_REHASHED" in row["blockers"] or
            any(row.get(flag) is not False for flag in DENY)):
        raise ValueError("Candidate was silently promoted or source changed")
    return {
        "pg": pg, "name": name,
        "releaseId": RELEASE_ID, "assetId": int(ident[len(prefix):]),
        "size": row["apiObservedBytes"], "sha256": row["apiObservedSha256"],
        "url": checked_url(f"{RELEASE_URL}/{name}"),
    }


def audit(pg, root=ROOT, opener=None):
    pin = original_pin(pg, root)
    opener = opener or urllib.request.build_opener(OnlyOfficialRedirects())
    request = urllib.request.Request(
        pin["url"], headers={"User-Agent": "pgextwin-timescale-232-deny-only/1"})
    with tempfile.TemporaryDirectory(prefix="timescale-232-private-") as tmp:
        dest = Path(tmp) / pin["name"]
        with opener.open(request, timeout=90) as response:
            checked_url(response.geturl())
            actual_size, actual_sha = copy_checked_bytes(
                response, dest, pin["size"], pin["sha256"])
        inventory = inspect_zip(dest)
    return {
        "schemaVersion": "pgextwin-issue112-timescaledb-232-original-rehash-deny-only/v1",
        "sourceRepo": "timescale/timescaledb", "releaseTag": VERSION,
        "releaseId": RELEASE_ID, "assetId": pin["assetId"],
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
    print(f"TIMESCALEDB_232_ORIGINAL_REHASH=PASS PG={args.pg} "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
