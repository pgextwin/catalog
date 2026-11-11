#!/usr/bin/env python3
"""Independently rehash official *public* PGroonga/Groonga release bytes.

Read-only, nonpublishing. Neither a producer attestation nor permission to
download through pgextwin. No private tokens, artifacts, signatures or writes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.request
from urllib.parse import urlsplit
import zipfile

import issue112_pgroonga_rights_audit as rights

SOURCE_NAME = "groonga-16.1.3.tar.gz"
SOURCE_URL = (
    "https://github.com/groonga/groonga/releases/download/v16.1.3/"
    + SOURCE_NAME
)
SOURCE_BYTES = 110532722
SOURCE_SHA256 = "61e1c8f1671e22d7bf4cd8c35002b9674d29ba82ae2cbe6835d73d3a45af202b"
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com", "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}
TARGETS = ("source", "14", "15", "16", "17", "18")


def original_pin(target):
    if target == "source":
        return SOURCE_NAME, SOURCE_URL, SOURCE_BYTES, SOURCE_SHA256
    pg = int(target)
    if pg not in rights.PINS:
        raise ValueError("Unsupported PostgreSQL major")
    size, digest = rights.PINS[pg]
    return rights.original_name(pg), rights.original_url(pg), size, digest


def copy_checked_bytes(stream, dest: Path, size: int, sha256: str):
    """Verify newly streamed bytes, not just remote API metadata."""
    if size <= 0 or len(sha256) != 64:
        raise ValueError("Invalid expected pin")
    actual = hashlib.sha256()
    count = 0
    with dest.open("xb") as output:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > size:
                raise ValueError("Downloaded bytes exceed fixed size")
            actual.update(chunk)
            output.write(chunk)
    if count != size or actual.hexdigest() != sha256:
        raise ValueError("Independent download size/SHA256 mismatch")
    return count, actual.hexdigest()


def rehash(target):
    name, url, size, sha256 = original_pin(target)
    request = urllib.request.Request(
        url, headers={"User-Agent": "pgextwin-issue112-public-byte-rehash/1"}
    )
    with tempfile.TemporaryDirectory(prefix="issue112-public-rehash-") as tmp:
        dest = Path(tmp) / name
        with urllib.request.urlopen(request, timeout=90) as response:
            final_url = response.geturl()
            parts = urlsplit(final_url)
            if parts.scheme != "https" or parts.hostname not in ALLOWED_DOWNLOAD_HOSTS:
                raise ValueError("Release redirect outside approved HTTPS hosts")
            count, digest = copy_checked_bytes(response, dest, size, sha256)
        evidence = {
            "schemaVersion": "issue112-pgroonga-public-byte-rehash-nonpublishing/v1",
            "target": target,
            "officialPublicReleaseUrl": url,
            "bytesIndependentlyRead": count,
            "independentSha256": digest,
            "matchesRecordedOfficialReleaseDigest": True,
            "actualWindowsProducerGroongaSourceMatched": False,
            "sourceToBinaryProvenanceVerified": False,
            "componentLicenseNoticeVerified": False,
            "independentSignedGetAdmission": False,
            "publicGetAuthorized": False,
            "mirrorAuthorized": False,
            "publisherAuthorized": False,
        }
        if target != "source":
            pg = int(target)
            inventory = rights.audit_members(dest, pg)
            with zipfile.ZipFile(dest) as archive:
                xxhash_named = any(
                    "xxhash" in item["path"].lower()
                    or b"xxhash" in archive.read(item["path"]).lower()
                    or b"yann collet" in archive.read(item["path"]).lower()
                    for item in inventory["licenseNoticeFiles"]
                )
            evidence.update(
                pgMajor=pg,
                zipMemberCount=inventory["zipMemberCount"],
                binaryMemberCount=inventory["binaryMemberCount"],
                namedRightsDocumentCount=inventory["licenseNoticeCandidatesCount"],
                xxHashLicenseOrAttributionFoundInOriginalNamedRightsDocuments=xxhash_named,
                xxHashBSD2ClauseNoticeClosureVerified=False,
            )
    return evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset", required=True, choices=TARGETS)
    args = parser.parse_args()
    print(json.dumps(rehash(args.asset), sort_keys=True))
    print("INDEPENDENT_PUBLIC_BYTES=PASS PRODUCER_INPUT_MATCH=UNVERIFIED "
          "NOTICE_CLOSURE=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
