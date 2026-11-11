#!/usr/bin/env python3
"""Exact-origin, SHA-pinned, temporary Winnie receipt; NONPUBLISHING."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.request
import zipfile

from discover_osgeo_windows_bundles import NoRedirect
from issue112_osgeo_original_byte_pilot import read_original
from issue112_osgeo_winnie_version_receipt import (
    ORIGINALS, MAX_MANIFEST_BYTES, MAX_TEXT_LINES, audit, denied_report,
)

ORIGIN = "https://download-cache.osgeo.org/postgis/windows/"
DENIALS = (
    "producerSourceRevisionVerified", "sourceToExactDllBytesAttested",
    "componentLicenseNoticeClosureVerified", "runtimeDependencyClosureVerified",
    "independentSignedAdmission", "publicGetAuthorized", "mirrorAuthorized",
    "publisherAuthorized", "releaseAuthorized",
)


def metadata_lines(target, pg):
    """Bounded, JSON-escaped exact metadata lines, never inferred version claims."""
    version, _, _ = ORIGINALS[pg]
    member = f"postgis-bundle-pg{pg}-{version}x64/version.txt"
    with zipfile.ZipFile(target) as archive:
        if member not in archive.namelist():
            return [], None, None
        info = archive.getinfo(member)
        if info.is_dir() or not 0 < info.file_size <= MAX_MANIFEST_BYTES:
            raise ValueError("Unsafe version.txt metadata size")
        with archive.open(info) as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) != info.file_size:
        raise ValueError("Truncated version.txt metadata")
    decoded = raw.decode("utf-8")
    if "\x00" in decoded:
        raise ValueError("NUL in version.txt metadata")
    lines = decoded.splitlines()
    if len(lines) > MAX_TEXT_LINES or any(len(line) > 2048 for line in lines):
        raise ValueError("Unbounded version.txt lines")
    # The original may contain conflicting/duplicate declarations; disclose raw
    # lines only, never coerce them into a unique trusted component version.
    return lines, len(raw), hashlib.sha256(raw).hexdigest()


def review_original(pg, opener=None):
    """Read a pinned exact original from its canonical origin, then delete it."""
    if pg not in ORIGINALS:
        raise ValueError("Unsupported pinned PostgreSQL major")
    version, expected_size, expected_sha = ORIGINALS[pg]
    filename = f"postgis-bundle-pg{pg}-{version}x64.zip"
    url = f"{ORIGIN}pg{pg}/{filename}"
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    with tempfile.TemporaryDirectory(prefix="pgextwin-osgeo-version-") as directory:
        target = Path(directory) / filename
        observed_size, observed_sha = read_original(url, target, opener=opener)
        if observed_size != expected_size or observed_sha != expected_sha:
            raise ValueError("Exact original SHA256/size mismatch; fail closed")
        try:
            result = audit(target, pg)
            parsed = result.get("versionTxtFound") is True
        except ValueError as exc:
            # Only the exact duplicate-label condition can become a documented
            # *rejected metadata observation*. Never relax the strict parser.
            if str(exc) != "Conflicting or duplicate Winnie component version":
                raise
            result = denied_report(pg, version, expected_size, expected_sha, {
                "versionTxtFound": True,
                "versionTxtMember": f"postgis-bundle-pg{pg}-{version}x64/version.txt",
                "versionTxtSha256": None, "versionTxtBytes": None,
                "packagingComponentVersionClaims": {},
                "manifestObservation": "DUPLICATE_COMPONENT_LABELS_UNPARSED",
            })
            parsed = False
        raw_lines, version_bytes, version_sha = metadata_lines(target, pg)
        if result.get("versionTxtFound"):
            if result.get("versionTxtSha256") not in (None, version_sha) or \
                    result.get("versionTxtBytes") not in (None, version_bytes):
                raise ValueError("Version metadata digest disagreement")
            result["versionTxtSha256"] = version_sha
            result["versionTxtBytes"] = version_bytes
        elif raw_lines or version_sha is not None:
            raise ValueError("Unexpected version metadata presence")
    if (result.get("status") != "CANDIDATE_ONLY" or
            result.get("originalZipBytes") != expected_size or
            result.get("originalZipSha256") != expected_sha or
            any(result.get(field) is not False for field in DENIALS)):
        raise ValueError("Offline inspector did not preserve every deny gate")
    return {"sourceOriginalUrl": url, "originRedirectAllowed": False,
            "binaryOrigin": "EXACT_CANONICAL_OSGEO_ONLY", **result,
            "componentClaimsParsed": parsed,
            "rawVersionTxtLinesUntrusted": raw_lines}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", required=True, choices=sorted(ORIGINALS))
    args = parser.parse_args()
    print(json.dumps(review_original(args.pg), sort_keys=True))
    print("ORIGINAL_VERSION_RECEIPT=OBSERVATION_ONLY SOURCE=UNVERIFIED "
          "COMPONENT_RIGHTS=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
