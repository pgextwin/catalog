#!/usr/bin/env python3
"""Issue #112: offline, nonpublishing Winnie version.txt receipt from pinned OSGeo ZIPs.

The manifest contains self-reported packaging metadata, never a signed producer
attestation, independent component NOTICE clearance or download authorization.
No HTTP request, ZIP extraction, GitHub write, or workflow dispatch is made.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

from issue112_osgeo_original_byte_pilot import inspect

# Independently rehashed originals from Issue #112 comments 6791571591 (PG14-17)
# and the existing PG18 source-byte audit. Never derive a trusted pin from HTML.
ORIGINALS = {
    "14": ("3.6.1", 124000548, "d95f1e0ed333c3b0729210fb6573d4d7e07bc7eba61868d51fb1eebd338b1a97"),
    "15": ("3.6.2", 123986945, "520c3fd7ebf95050d8d89dc1b626f4f43111a3d726f60b73bbbbbd95784688eb"),
    "16": ("3.6.2", 123957610, "9f4e8a30d69ed7cc0088dd3d218ac65bd4e26aa5b7bffcb2ebd7dcb74a4ff2a6"),
    "17": ("3.6.2", 123959035, "7ba180ee2a352987b9a2f194673652c59483b55852295ccf401dceccd8765425"),
    "18": ("3.7.0", 83320975, "fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40"),
}
MAX_MANIFEST_BYTES = 64 * 1024
MAX_TEXT_LINES = 512
COMPONENT_LABELS = frozenset(("GEOS", "GDAL", "PROJ", "LIBICONV", "CGAL",
                              "BOOST", "SFCGAL"))
VERSION_LINE = re.compile(
    r"^([A-Z]+) VERSION: ([0-9][0-9A-Za-z._+~-]{0,63})(?:[ \t]+[^\r\n]*)?$"
)


def verified_local_zip(path, pg):
    if pg not in ORIGINALS:
        raise ValueError("Unsupported pinned PG major")
    version, expected_size, expected_sha = ORIGINALS[pg]
    path = Path(path)
    if not path.is_file() or path.stat().st_size != expected_size:
        raise ValueError("Local ZIP size does not match independently observed pin")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            count += len(block)
            if count > expected_size:
                raise ValueError("Original ZIP size cap exceeded")
            digest.update(block)
    if count != expected_size or digest.hexdigest() != expected_sha:
        raise ValueError("Local ZIP SHA256 differs from exact original")
    inspect(path)  # existing archive path/symlink/bomb/AMD64/CRC checks
    return version, expected_size, expected_sha


def parse_manifest(content):
    """Strictly extract *claims* without treating text as provenance or NOTICE."""
    if type(content) is not bytes or not 0 < len(content) <= MAX_MANIFEST_BYTES:
        raise ValueError("Missing or oversized Winnie version metadata")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Manifest is not UTF-8") from exc
    if "\x00" in text:
        raise ValueError("NUL in Winnie manifest")
    lines = text.splitlines()
    if len(lines) > MAX_TEXT_LINES or any(len(line) > 2048 for line in lines):
        raise ValueError("Unbounded Winnie manifest lines")
    claims = {}
    for line in lines:
        if line.startswith(tuple(label + " VERSION:" for label in COMPONENT_LABELS)):
            match = VERSION_LINE.fullmatch(line)
            if match is None or match.group(1) not in COMPONENT_LABELS:
                raise ValueError("Invalid Winnie component version line")
            key, value = match.groups()
            if key in claims:
                raise ValueError("Conflicting or duplicate Winnie component version")
            claims[key] = value
    return {key: claims[key] for key in sorted(claims)}


def receipt(archive, pg, version):
    """Read only the expected in-bundle version.txt; never extract to disk."""
    if pg not in ORIGINALS or version != ORIGINALS[pg][0]:
        raise ValueError("PG and PostGIS version not pinned")
    root = "postgis-bundle-pg" + pg + "-" + version + "x64/"
    member = root + "version.txt"
    members = archive.namelist()
    if len(members) != len(set(x.casefold() for x in members)):
        raise ValueError("Case-insensitive duplicate ZIP entry")
    if member not in members:
        return {"versionTxtFound": False, "versionTxtMember": member,
                "versionTxtSha256": None, "versionTxtBytes": None,
                "packagingComponentVersionClaims": {},
                "manifestObservation": "EXPECTED_VERSION_TXT_ABSENT"}
    info = archive.getinfo(member)
    if info.is_dir() or not 0 < info.file_size <= MAX_MANIFEST_BYTES:
        raise ValueError("Invalid Winnie version.txt member size")
    with archive.open(info, "r") as src:
        content = src.read(MAX_MANIFEST_BYTES + 1)
    if len(content) != info.file_size:
        raise ValueError("Truncated Winnie version.txt")
    return {"versionTxtFound": True, "versionTxtMember": member,
            "versionTxtSha256": hashlib.sha256(content).hexdigest(),
            "versionTxtBytes": len(content),
            "packagingComponentVersionClaims": parse_manifest(content),
            "manifestObservation": "SELF_REPORTED_PACKAGING_METADATA_ONLY"}


def denied_report(pg, version, size, sha, observation):
    """No report field can elevate original ZIP metadata into authority."""
    return {
        "schemaVersion": "pgextwin-issue112-osgeo-winnie-version-receipt/v1",
        "status": "CANDIDATE_ONLY",
        "pgMajor": pg, "postgisVersion": version,
        "originalZipBytes": size, "originalZipSha256": sha,
        **observation,
        "producerSourceRevisionVerified": False,
        "sourceToExactDllBytesAttested": False,
        "componentLicenseNoticeClosureVerified": False,
        "runtimeDependencyClosureVerified": False,
        "independentSignedAdmission": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "publisherAuthorized": False,
        "releaseAuthorized": False,
    }


def audit(path, pg):
    version, size, sha = verified_local_zip(path, pg)
    with zipfile.ZipFile(path) as archive:
        observation = receipt(archive, pg, version)
    return denied_report(pg, version, size, sha, observation)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", choices=sorted(ORIGINALS), required=True)
    parser.add_argument("--zip", type=Path, required=True,
                        help="Existing locally held original ZIP; NO network fetch")
    args = parser.parse_args()
    print(json.dumps(audit(args.zip, args.pg), sort_keys=True))
    print("WINNIE_VERSION=OBSERVED_ONLY PRODUCER=UNVERIFIED RIGHTS=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
