#!/usr/bin/env python3
"""Issue #112: independently inspect one pglogical 2.4.8 provider original.

Read-only external metadata and private disposable Windows staging ONLY.
Not a Sigstore verification, publisher action, authorization or ZIP mirror.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import urllib.request
import zipfile

REPO = "semihkiroglu/pglogical-windows"
REPO_ID = 1324318750
RELEASE_ID = 381578857
TAG = "2.4.8-w1"
TAG_COMMIT = "98f8f67e5c3b963cbd93ef452ecf456d880bbfc4"
UPSTREAM_COMMIT = "9a0e182745885ad0152ea387988c95a483396a81"
PINS = {
    14: (541766447, 176778, "e722ca3eb5caad4da06620c32632d8b6ee7129b840d4e7da253721594c5024d3"),
    15: (541766450, 176749, "ff60107d6adef9a5b61dc2b78214f8ac9831a8df8f230a9cd9c90e7f7d3ebef2"),
    16: (541766449, 176275, "be599b6d3171cbb4d12d26bab51f909cb179af3ad7b4b6768c5fb89f4dec1157"),
    17: (541766446, 176170, "3cba8b233db52835ca62586d337132c816c42237151716e57dfa28a860633d7b"),
    18: (541766448, 176460, "1f69a4528b506a1bda01b8171f83d44268bbefe08b0adab49e00788c26d52eb3"),
}
ALLOWED = re.compile(
    r"(?:BUILD-INFO\.json|share/pglogical/COPYRIGHT|"
    r"lib/(?:pglogical|pglogical_output)\.dll|"
    r"bin/pglogical_create_subscriber\.exe|"
    r"share/extension/(?:pglogical|pglogical_origin)\.control|"
    r"share/extension/pglogical(?:_origin)?--[A-Za-z0-9_.-]+\.sql)\Z"
)
FILE_BOUND = 3_000_000
TOTAL_BOUND = 12_000_000
ZIP_BOUND = 1_000_000


def require(condition, message):
    if not condition:
        raise ValueError("PGLOGICAL_INDEPENDENT_PILOT_DENY: " + message)


def api_json(path):
    url = "https://api.github.com/repos/" + REPO + ("/" + path if path else "")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "pgextwin-candidate-audit"}
    token = os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        require(response.geturl() == url, "metadata redirected")
        return json.load(io.TextIOWrapper(io.BytesIO(response.read(500_001)), encoding="utf-8"))


def validate_source_registry(major, asset_id, length, sha):
    path = Path(__file__).resolve().parents[1] / "external/windows-candidates-pglogical-v1.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    require(catalog.get("trust") == "UNVERIFIED_METADATA_ONLY" and
            catalog.get("publicationAuthorized") is False and
            catalog.get("redistributionAuthorized") is False, "registry authority")
    rows = catalog.get("candidates")
    require(isinstance(rows, list) and len(rows) == 5 and
            {str(row.get("pgMajor")) for row in rows} == {str(m) for m in PINS},
            "five-source inventory changed")
    for row in rows:
        pg = int(row["pgMajor"])
        pin_id, pin_size, pin_sha = PINS[pg]
        name = f"pglogical-2.4.8-pg{pg}-w1-x64.zip"
        url = f"https://github.com/{REPO}/releases/download/{TAG}/{name}"
        require(row.get("extension") == "pglogical" and
                row.get("upstreamVersion") == "2.4.8" and
                row.get("sourceRepo") == REPO and
                row.get("releaseTag") == TAG and
                row.get("releaseId") == RELEASE_ID and
                row.get("assetId") == pin_id and
                row.get("assetName") == name and
                row.get("assetUrl") == url and
                row.get("apiDigest") == "sha256:" + pin_sha and
                row.get("originalSha256") is None and
                row.get("originalBytes") is None and
                row.get("downloadAuthorized") is False and
                row.get("rightsReviewed") is False and
                row.get("provenanceVerified") is False and
                row.get("compatibilityVerified") is False and
                row.get("dependenciesVerified") is False,
                f"PG{pg} registry was altered or promoted")
    require((asset_id, length, sha) == PINS[major], "internal pin mismatch")


def verify_metadata(major, asset_id, length, sha):
    provider = api_json("")
    require(provider.get("id") == REPO_ID and provider.get("full_name") == REPO,
            "provider repository identity")
    ref = api_json("git/ref/tags/" + TAG)
    require(ref.get("object", {}).get("type") == "commit" and
            ref["object"]["sha"] == TAG_COMMIT, "provider tag moved")
    release = api_json("releases/" + str(RELEASE_ID))
    name = f"pglogical-2.4.8-pg{major}-w1-x64.zip"
    url = f"https://github.com/{REPO}/releases/download/{TAG}/{name}"
    matches = [a for a in release.get("assets", []) if a.get("name") == name]
    require(release.get("id") == RELEASE_ID and release.get("tag_name") == TAG and
            release.get("draft") is False and release.get("prerelease") is False and
            len(matches) == 1 and matches[0].get("id") == asset_id and
            matches[0].get("size") == length and matches[0].get("state") == "uploaded" and
            matches[0].get("digest") == "sha256:" + sha and
            matches[0].get("browser_download_url") == url,
            "provider release metadata changed")
    return url


def fetch_original(url, length, sha):
    req = urllib.request.Request(url, headers={"User-Agent": "pgextwin-candidate-audit"})
    with urllib.request.urlopen(req, timeout=90) as response:
        from urllib.parse import urlsplit
        final = urlsplit(response.geturl())
        require(final.scheme == "https" and final.hostname in
                {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"},
                "unexpected asset download host")
        data = response.read(ZIP_BOUND + 1)
    require(len(data) == length and len(data) <= ZIP_BOUND, "original asset byte size mismatch")
    require(hashlib.sha256(data).hexdigest() == sha, "independent original SHA256 mismatch")
    return data


def pe_x64(data):
    if len(data) < 256 or data[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    return (offset + 26 <= len(data) and data[offset:offset + 4] == b"PE\0\0" and
            struct.unpack_from("<H", data, offset + 4)[0] == 0x8664 and
            struct.unpack_from("<H", data, offset + 24)[0] == 0x20b)


def inspect_zip(data, major):
    payload = {}
    required = {
        "BUILD-INFO.json", "share/pglogical/COPYRIGHT",
        "lib/pglogical.dll", "lib/pglogical_output.dll",
        "bin/pglogical_create_subscriber.exe", "share/extension/pglogical.control",
        "share/extension/pglogical_origin.control",
        "share/extension/pglogical_origin--1.0.0.sql",
    }
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(8 <= len(entries) <= 120, "ZIP member count")
        names = set()
        total = 0
        for member in entries:
            name = member.filename
            require(name and "\\" not in name and ":" not in name and
                    not name.startswith("/") and
                    all(segment not in (".", "..", "") for segment in name.rstrip("/").split("/")),
                    "unsafe ZIP member path")
            require(name.casefold() not in names, "duplicate ZIP member path")
            names.add(name.casefold())
            require(((member.external_attr >> 16) & 0xF000) != 0xA000,
                    "ZIP symlink is not permitted")
            if member.is_dir():
                continue
            require(ALLOWED.fullmatch(name) is not None, "unknown ZIP member: " + name)
            require(member.file_size <= FILE_BOUND and
                    member.file_size <= 200 * max(member.compress_size, 1), "ZIP bomb")
            total += member.file_size
            require(total <= TOTAL_BOUND, "ZIP total expanded size")
            payload[name] = archive.read(member)
        require(archive.testzip() is None, "ZIP CRC failure")
    require(required <= set(payload), "required core file missing")
    require(any(re.fullmatch(r"share/extension/pglogical--[A-Za-z0-9_.-]+\.sql", x)
                for x in payload), "pglogical SQL missing")
    info = json.loads(payload["BUILD-INFO.json"].decode("utf-8-sig"))
    require(str(info.get("pglogicalVersion")) == "2.4.8" and
            str(info.get("postgresqlCompatibilityMajor")) == str(major) and
            info.get("upstreamTag") == "REL2_4_8" and
            info.get("upstreamCommitSha") == UPSTREAM_COMMIT and
            int(info.get("windowsPackagingRevision", -1)) == 1 and
            re.fullmatch(r"[0-9a-f]{64}", str(info.get("edbArtifactCalculatedSha256", ""))),
            "untrusted embedded BUILD-INFO.json identity mismatch")
    for binary in ("lib/pglogical.dll", "lib/pglogical_output.dll",
                   "bin/pglogical_create_subscriber.exe"):
        require(pe_x64(payload[binary]), "invalid Windows AMD64 PE: " + binary)
    require(len(payload["share/pglogical/COPYRIGHT"]) > 100, "copyright absent")
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", type=int, choices=sorted(PINS), required=True)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "win32" and os.getenv("GITHUB_ACTIONS") == "true" and
            os.getenv("GITHUB_REPOSITORY") == "pgextwin/catalog" and
            os.getenv("RUNNER_TEMP"), "ephemeral Windows CI only")
    stage = args.stage.resolve()
    require(stage.parent == Path(os.environ["RUNNER_TEMP"]).resolve() and not stage.exists(),
            "private stage must be unique, absent, and runner-local")
    asset_id, length, sha = PINS[args.pg]
    validate_source_registry(args.pg, asset_id, length, sha)
    url = verify_metadata(args.pg, asset_id, length, sha)
    data = fetch_original(url, length, sha)
    payload = inspect_zip(data, args.pg)
    stage.mkdir(mode=0o700)
    for name, content in payload.items():
        if not (name.startswith("lib/") or name.startswith("bin/") or
                name.startswith("share/extension/")):
            continue
        destination = stage.joinpath(*name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as out:
            out.write(content)
    print(f"ORIGINAL_BYTES=PASS PG={args.pg} ASSET={asset_id} LENGTH={length} SHA256={sha}")
    print("ZIP_SAFE_LAYOUT=PASS AMD64_PE=PASS SOURCE_METADATA=REPORTED_NOT_ATTESTED")
    print("CANDIDATE_ONLY=YES SIGSTORE_UNVERIFIED=YES PUBLISH=DENY GET=DENY MIRROR=DENY")


if __name__ == "__main__":
    main()
