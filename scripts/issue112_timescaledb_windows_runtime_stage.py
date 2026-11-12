#!/usr/bin/env python3
"""Stage exact official TimescaleDB 2.31.0 or 2.32.0 Windows bytes on CI only.

An integrity/runtime experiment, NOT a source-to-binary attestation, rights
clearance, external download admission, artifact mirror or publication path.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import urllib.request
import zipfile

from issue112_timescaledb_original_rehash import (
    OnlyOfficialRedirects, checked_url, inspect_zip,
    original_pin as original_pin_231,
)
from issue112_timescaledb_232_original_rehash import original_pin as original_pin_232
from issue112_pgroonga_independent_rehash import copy_checked_bytes


def extract_reviewed_zip(zip_path: Path, stage: Path):
    """Reject unsafe archives before extraction; never overwrite a preexisting tree."""
    inspection = inspect_zip(zip_path)  # bounds, CRC, symlinks, path and case aliases
    with zipfile.ZipFile(zip_path) as archive:
        if "timescaledb/setup.exe" not in archive.namelist():
            raise ValueError("Official Windows setup.exe missing from expected package root")
        if stage.exists() or stage.is_symlink():
            raise ValueError("Staging directory must be new (create-only)")
        stage.mkdir(parents=False, exist_ok=False)
        try:
            for member in archive.infolist():
                name = member.filename
                dest = stage.joinpath(*name.rstrip("/").split("/"))
                if member.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, dest.open("xb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            setup = stage / "timescaledb" / "setup.exe"
            if not setup.is_file() or setup.stat().st_size <= 0:
                raise ValueError("Windows setup.exe missing or empty after staging")
        except BaseException:
            shutil.rmtree(stage)
            raise
    return {"members": inspection["members"], "dllMembers": inspection["dllMembers"],
            "setupPath": str(stage / "timescaledb" / "setup.exe")}


def original_pin(pg: str, version: str = "2.31.0"):
    if version == "2.31.0":
        return original_pin_231(pg)
    if version == "2.32.0":
        return original_pin_232(pg)
    raise ValueError("Unreviewed TimescaleDB Windows version")


def original_stage(pg: str, stage: Path, opener=None, version: str = "2.31.0"):
    pin = original_pin(pg, version)
    opener = opener or urllib.request.build_opener(OnlyOfficialRedirects())
    request = urllib.request.Request(
        pin["url"], headers={"User-Agent": "pgextwin-issue112-timescaledb-windows-sql/1"})
    with tempfile.TemporaryDirectory(prefix="timescale-checked-") as tmp:
        zip_path = Path(tmp) / pin["name"]
        with opener.open(request, timeout=90) as response:
            checked_url(response.geturl())
            size, sha = copy_checked_bytes(response, zip_path, pin["size"], pin["sha256"])
        inspection = extract_reviewed_zip(zip_path, stage)
    return {"pgMajor": pg, "version": version, "sourceRepo": "timescale/timescaledb",
            "releaseId": pin["releaseId"], "assetId": pin["assetId"],
            "size": size, "sha256": sha, "inspection": inspection,
            "publicGetAuthorized": False, "redistributionAuthorized": False,
            "rightsAccepted": False, "producerAttestationVerified": False,
            "signedAdmission": False, "publisherAuthorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=("16", "17", "18"), required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--version", choices=("2.31.0", "2.32.0"),
                        default="2.31.0")
    args = parser.parse_args()
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("GITHUB_REPOSITORY") != "pgextwin/catalog" or
            os.environ.get("RUNNER_OS") != "Windows" or
            not os.environ.get("RUNNER_TEMP")):
        raise SystemExit("DENY: only ephemeral pgextwin/catalog Windows CI")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    stage = args.stage.absolute()
    if stage.parent.resolve() != runner or stage.is_symlink():
        raise SystemExit("DENY: stage must be a direct child of RUNNER_TEMP")
    report = original_stage(args.pg, stage, version=args.version)
    print(json.dumps(report, sort_keys=True))
    print(f"TIMESCALEDB_STAGED_ORIGINAL=PASS PG={args.pg} "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
