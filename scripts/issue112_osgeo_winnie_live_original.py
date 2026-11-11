#!/usr/bin/env python3
"""Exact-origin, SHA-pinned, temporary Winnie receipt; NONPUBLISHING.

This is a unique source-byte inspection, not a rerun of any successful SQL job.
Never mirrors, uploads, signs, releases, or changes admission policies.
"""
import argparse
import json
from pathlib import Path
import tempfile
import urllib.request

from discover_osgeo_windows_bundles import NoRedirect
from issue112_osgeo_original_byte_pilot import read_original
from issue112_osgeo_winnie_version_receipt import ORIGINALS, audit

ORIGIN = "https://download-cache.osgeo.org/postgis/windows/"
DENIALS = (
    "producerSourceRevisionVerified", "sourceToExactDllBytesAttested",
    "componentLicenseNoticeClosureVerified", "runtimeDependencyClosureVerified",
    "independentSignedAdmission", "publicGetAuthorized", "mirrorAuthorized",
    "publisherAuthorized", "releaseAuthorized",
)


def review_original(pg, opener=None):
    """Read a pinned exact original from its canonical origin, then delete it."""
    if pg not in ORIGINALS:
        raise ValueError("Unsupported pinned PostgreSQL major")
    version, expected_size, expected_sha = ORIGINALS[pg]
    filename = f"postgis-bundle-pg{pg}-{version}x64.zip"
    url = f"{ORIGIN}pg{pg}/{filename}"
    # No fallback to alternate host, archive path, mirror, or redirected asset.
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    with tempfile.TemporaryDirectory(prefix="pgextwin-osgeo-version-") as directory:
        target = Path(directory) / filename
        observed_size, observed_sha = read_original(url, target, opener=opener)
        if observed_size != expected_size or observed_sha != expected_sha:
            raise ValueError("Exact original SHA256/size mismatch; fail closed")
        result = audit(target, pg)
    if (result.get("status") != "CANDIDATE_ONLY" or
            result.get("originalZipBytes") != expected_size or
            result.get("originalZipSha256") != expected_sha or
            any(result.get(field) is not False for field in DENIALS)):
        raise ValueError("Offline inspector did not preserve every deny gate")
    return {"sourceOriginalUrl": url, "originRedirectAllowed": False,
            "binaryOrigin": "EXACT_CANONICAL_OSGEO_ONLY", **result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", required=True, choices=sorted(ORIGINALS))
    args = parser.parse_args()
    print(json.dumps(review_original(args.pg), sort_keys=True))
    print("ORIGINAL_VERSION_RECEIPT=OBSERVATION_ONLY SOURCE=UNVERIFIED "
          "COMPONENT_RIGHTS=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
