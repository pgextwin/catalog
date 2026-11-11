#!/usr/bin/env python3
"""Read-only Cybertec pg_track_settings original-byte pilot; NEVER an admission."""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import stat
import urllib.request
import zipfile

BASE = "https://repository.cybertec.at/windows/public/"
MAJORS = ("14", "15", "16", "17", "18")
VERSION = "2.1.2"
SOURCE_SHA = "36a23f3c6d684c40140da1a24b1c3ee0e707b77a"
MAX_ZIP = 2_000_000
MAX_FILES = 128
MAX_EXPANDED = 4_000_000
SQL = re.compile(r"pg_track_settings--[0-9A-Za-z._-]+\\.sql\\Z")
DENIALS = dict(publicGetAuthorized=False, mirrorAuthorized=False,
               publisherAuthorized=False, releaseAuthorized=False,
               independentlySignedAdmission=False,
               producerProvenanceVerified=False,
               rightsNoticeClosureVerified=False,
               communityWindowsRuntimeVerified=False)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("Redirected Cybertec original refused")


def original_url(pg):
    if pg not in MAJORS:
        raise ValueError("Unsupported PG major")
    return f"{BASE}{pg}/extension/pg_track_settings-{pg}-public-{VERSION}.zip"


def review_zip(raw, pg, source=None):
    if pg not in MAJORS or type(raw) is not bytes or not 0 < len(raw) <= MAX_ZIP:
        raise ValueError("Original ZIP missing, too large or unsupported major")
    payload = {}
    notices = []
    members = []
    seen = set()
    expanded = 0
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        if not 2 <= len(entries) <= MAX_FILES:
            raise ValueError("ZIP entry count out of bounds")
        for entry in entries:
            name = entry.filename
            if (not name or name.startswith("/") or "\\" in name or ":" in name or
                    "\x00" in name or name.casefold() in seen or
                    any(part in ("", ".", "..") for part in name.rstrip("/").split("/")) or
                    stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK):
                raise ValueError("Unsafe or duplicate ZIP member")
            seen.add(name.casefold())
            if entry.file_size > MAX_EXPANDED or entry.file_size > 300 * max(1, entry.compress_size):
                raise ValueError("ZIP expansion limit")
            expanded += entry.file_size
            if expanded > MAX_EXPANDED:
                raise ValueError("ZIP cumulative expansion limit")
            if entry.is_dir():
                continue
            members.append(name)
            leaf = name.rsplit("/", 1)[-1]
            if leaf.casefold() in ("license", "license.txt", "license.md", "copying", "notice", "notice.txt"):
                notices.append(name)
            if leaf == "pg_track_settings.control" or SQL.fullmatch(leaf):
                if leaf in payload:
                    raise ValueError("Duplicate installable source basename")
                payload[leaf] = archive.read(entry)
        if archive.testzip() is not None:
            raise ValueError("ZIP CRC invalid")
    if "pg_track_settings.control" not in payload or "pg_track_settings--2.1.2.sql" not in payload:
        raise ValueError("Expected upstream control or versioned SQL absent")
    if b"default_version = '2.1.2'" not in payload["pg_track_settings.control"]:
        raise ValueError("Unrecognized installed default version")
    matched, modified, missing = [], [], []
    if source is not None:
        root = Path(source)
        if not root.is_dir() or root.is_symlink():
            raise ValueError("Missing or linked pinned source checkout")
        for name, data in sorted(payload.items()):
            path = root / name
            if path.is_symlink():
                raise ValueError("Linked upstream source file")
            if not path.is_file():
                missing.append(name)
            elif path.read_bytes() == data:
                matched.append(name)
            else:
                modified.append(name)
    return {
        "schemaVersion": "pgextwin-issue112-cybertec-track-original/v1",
        "status": "CANDIDATE_ONLY",
        "provider": "CYBERTEC_PGEE_PUBLIC_COMMUNITY_ABI_UNVERIFIED",
        "postgresqlMajor": pg, "packageVersionLabelUntrusted": VERSION,
        "upstreamTagCommitPinned": SOURCE_SHA,
        "originalUrl": original_url(pg),
        "originalSizeBytes": len(raw),
        "originalSha256": hashlib.sha256(raw).hexdigest(),
        "zipCrc": "PASS", "zipMemberCount": len(entries),
        "unpackedBytes": expanded,
        "installableSqlAndControl": sorted(payload),
        "installableMemberSha256": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(payload.items())},
        "packagedLicenseNoticeMembers": sorted(notices),
        "upstreamExactByteMatches": matched,
        "upstreamByteDiffers": modified,
        "upstreamNotPresent": missing,
        "upstreamCompleteSqlControlMatch": source is not None and not modified and not missing,
        **DENIALS,
    }


def review_original(pg, source=None, opener=None):
    url = original_url(pg)
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    req = urllib.request.Request(url, headers={
        "Accept": "application/zip, application/octet-stream",
        "User-Agent": "pgextwin-private-original-audit/1"
    })
    with opener.open(req, timeout=45) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("Original origin status or redirect mismatch")
        content_type = response.headers.get("Content-Type", "").split(";")[0].lower().strip()
        if content_type not in ("application/zip", "application/octet-stream", "application/x-zip-compressed"):
            raise ValueError("Unexpected original media type")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdecimal() or not 0 < int(length) <= MAX_ZIP):
            raise ValueError("Original declared length out of bounds")
        raw = response.read(MAX_ZIP + 1)
    if length is not None and len(raw) != int(length):
        raise ValueError("Truncated original response")
    return review_zip(raw, pg, source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=MAJORS, required=True)
    parser.add_argument("--source", type=Path, required=True,
                        help="Exact upstream checkout at the pinned tag commit")
    args = parser.parse_args()
    result = review_original(args.pg, args.source)
    print(json.dumps(result, sort_keys=True))
    print("CYBERTEC_ORIGINAL_BYTES=OBSERVED UPSTREAM_SOURCE_EQUIVALENCE=OBSERVATION_ONLY "
          "WINDOWS_RUNTIME=UNVERIFIED NOTICE=UNVERIFIED SOURCE_PROVENANCE=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
