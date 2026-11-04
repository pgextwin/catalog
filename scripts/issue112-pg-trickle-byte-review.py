#!/usr/bin/env python3
"""Issue #112: strictly private read-only original pg_trickle PG18 Windows ZIP audit.

No extraction to filesystem, execution, upload, signed-feed mutation, Release,
user download authorization or mirror. Results are evidence, not admission.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "issue112_external_zip_pilot", ROOT / "scripts/issue112-external-zip-pilot.py")
pilot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pilot)

REPO = "trickle-labs/pg-trickle"
TAG = "v0.108.3"
RELEASE_ID = 404988260
ASSET_ID = 616203967
ASSET = "pg_trickle-0.108.3-pg18-windows-amd64.zip"
SIZE = 7029107
DIGEST = "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b"
TAG_SHA = "ce709f06327b4801f79fc48934bc96107b450907"
MAX_ZIP_BYTES = 16_000_000
MAX_EXPANDED_BYTES = 180_000_000
MAX_MEMBERS = 2500
API_BASE = "https://api.github.com/repos/" + REPO
URL = "https://github.com/" + REPO + "/releases/download/" + TAG + "/" + ASSET


def pe_machine(blob):
    """Minimal structural PE machine check; not PostgreSQL ABI verification."""
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise ValueError("Invalid Windows DLL DOS header")
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe_offset > len(blob) - 26 or blob[pe_offset:pe_offset + 4] != b"PE\\x00\\x00":
        raise ValueError("Invalid Windows DLL PE header")
    machine = struct.unpack_from("<H", blob, pe_offset + 4)[0]
    magic = struct.unpack_from("<H", blob, pe_offset + 24)[0]
    if machine != 0x8664 or magic != 0x20B:
        raise ValueError("Not an AMD64 PE32+ DLL")
    return "AMD64_PE32_PLUS_HEADER_ONLY"


def examine_package(data):
    """Reuse the existing ZIP member/CRC/path/symlink/bomb auditor; no extraction."""
    info = pilot.audit_zip(data, max_members=MAX_MEMBERS,
                           max_expanded_bytes=MAX_EXPANDED_BYTES)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        dlls = [e for e in entries if e.filename.lower().endswith("lib/pg_trickle.dll")]
        controls = [e for e in entries
                    if e.filename.lower().endswith("extension/pg_trickle.control")]
        if len(dlls) != 1 or len(controls) != 1:
            raise ValueError("Exact pg_trickle DLL/control layout absent or duplicated")
        if dlls[0].file_size > 90_000_000:
            raise ValueError("Excessive DLL size")
        pe = pe_machine(archive.read(dlls[0]))
        notices = sorted(e.filename for e in entries
                         if re.fullmatch(r"(LICENSE|LICENCE|NOTICE)(?:[.][A-Za-z0-9._-]+)?",
                                         e.filename.rsplit("/", 1)[-1], re.IGNORECASE))
        sql_files = sum(e.filename.lower().endswith(".sql") for e in entries)
        if sql_files < 1:
            raise ValueError("Extension SQL files missing")
        return {**info, "dllMember": dlls[0].filename,
                "controlMember": controls[0].filename,
                "sqlFiles": sql_files, "packageNoticeMembers": notices,
                "peCheck": pe}


def read_limited(url, max_bytes):
    pilot.safe_url(url)
    opener = urllib.request.build_opener(pilot.PinnedRedirects())
    request = urllib.request.Request(
        url, headers={"User-Agent": "pgextwin-issue112-private-byte-audit/1",
                      "Accept": "application/vnd.github+json"})
    with opener.open(request, timeout=50) as response:
        pilot.safe_url(response.url)
        if response.status != 200:
            raise ValueError("Unexpected upstream HTTP status")
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Upstream response exceeds audit limit")
    return data


def assert_release_identity(release, tag_ref):
    if (release.get("tag_name") != TAG or release.get("id") != RELEASE_ID
            or release.get("draft") is not False or release.get("prerelease") is not False
            or tag_ref.get("object", {}).get("type") != "commit"
            or tag_ref["object"].get("sha") != TAG_SHA):
        raise ValueError("Upstream tag/release/source identity changed")
    matches = [a for a in release.get("assets", []) if a.get("id") == ASSET_ID]
    if len(matches) != 1:
        raise ValueError("Pinned original asset ID missing or duplicated")
    asset = matches[0]
    if (asset.get("name") != ASSET or asset.get("size") != SIZE
            or asset.get("digest") != "sha256:" + DIGEST
            or asset.get("state") != "uploaded"
            or asset.get("browser_download_url") != URL):
        raise ValueError("Pinned original ZIP metadata drift")


def run():
    release = json.loads(read_limited(API_BASE + "/releases/tags/" + TAG, 2_000_000))
    tag_ref = json.loads(read_limited(API_BASE + "/git/ref/tags/" + TAG, 100_000))
    assert_release_identity(release, tag_ref)
    data = read_limited(URL, MAX_ZIP_BYTES)
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError("Independently fetched original ZIP bytes differ from pinned SHA256/size")
    inspection = examine_package(data)
    print(json.dumps({
        "scope": "PRIVATE_ORIGINAL_BYTE_EVIDENCE_ONLY",
        "provider": REPO, "releaseId": RELEASE_ID, "tag": TAG,
        "tagSourceCommit": TAG_SHA, "assetId": ASSET_ID, "asset": ASSET,
        "size": len(data), "sha256": DIGEST, **inspection,
        "result": "ORIGINAL_ZIP_SHA256_CRC_AND_PE_HEADER_PASS",
        "sourceBuildProvenanceVerified": False, "pg18RuntimeAbiVerified": False,
        "dependencyClosureVerified": False, "licenseAndNoticeAccepted": False,
        "signedCatalogPin": False, "formalSourceSpecificAuthorization": False,
        "downloadAuthorized": False, "mirrorAuthorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    run()
