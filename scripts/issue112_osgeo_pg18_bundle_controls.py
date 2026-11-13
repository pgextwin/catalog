#!/usr/bin/env python3
"""Issue #112: exact PG18 OSGeo bundle .control inventory, DENY-only.

Presence in an immutable original ZIP is not Windows runtime support, source
provenance, component rights or an independently signed GET admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import urllib.request
import zipfile

from discover_osgeo_windows_bundles import NoRedirect
from issue112_latest_external_review import BUNDLE_COMPONENTS
from issue112_osgeo_original_byte_pilot import read_original
from issue112_osgeo_winnie_version_receipt import ORIGINALS, verified_local_zip

PG = "18"
VERSION, EXPECTED_SIZE, EXPECTED_SHA = ORIGINALS[PG]
ROOT = f"postgis-bundle-pg{PG}-{VERSION}x64/"
ORIGIN = f"https://download-cache.osgeo.org/postgis/windows/pg{PG}/{ROOT[:-1]}.zip"
MAX_CONTROL_BYTES = 64 * 1024
CONTROL_VERSION = re.compile(
    r"^[ \t]*default_version[ \t]*=[ \t]*'([0-9]+(?:\.[0-9]+){1,3})'[ \t]*(?:#.*)?$",
    re.MULTILINE,
)
DENIALS = (
    "allBundleComponentsInstallable", "allComponentRuntimeVerified",
    "producerSourceToZipSigned", "allComponentRightsNoticesVerified",
    "transitiveDependenciesVerified", "ownerSignedAdmission",
    "publicGetAuthorized", "mirrorAuthorized", "redistributionAuthorized",
    "releaseAuthorized", "publisherAuthorized",
)


def inventory(archive: zipfile.ZipFile) -> dict:
    """Observe only exact .control names inside the expected physical original."""
    names = archive.namelist()
    if len(names) != len({n.casefold() for n in names}):
        raise ValueError("Duplicate casefolded ZIP member")
    selected = {name: [] for name in BUNDLE_COMPONENTS}
    for component in BUNDLE_COMPONENTS:
        suffix = f"/share/extension/{component}.control"
        for name in names:
            if not name.startswith(ROOT) or not name.endswith(suffix):
                continue
            info = archive.getinfo(name)
            if info.is_dir() or not 0 < info.file_size <= MAX_CONTROL_BYTES:
                raise ValueError("Missing or oversized control content")
            with archive.open(info) as stream:
                raw = stream.read(MAX_CONTROL_BYTES + 1)
            if len(raw) != info.file_size:
                raise ValueError("Truncated control file")
            try:
                control_text = raw.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError("Non-UTF8 control file") from exc
            if "\x00" in control_text:
                raise ValueError("NUL in control file")
            versions = CONTROL_VERSION.findall(control_text.replace("\r\n", "\n"))
            if len(versions) > 1:
                raise ValueError("Ambiguous default_version in control")
            selected[component].append({
                "originalMember": name,
                "originalMemberSha256": hashlib.sha256(raw).hexdigest(),
                "originalMemberBytes": len(raw),
                "location": "DIRECT_SHARE_EXTENSION"
                            if name == ROOT + f"share/extension/{component}.control"
                            else "NESTED_BUNDLE_CANDIDATE_ONLY",
                "declaredDefaultVersion": versions[0] if versions else None,
                "declaredVersionIsNotRuntimeEvidence": True,
            })
    if not selected["postgis"] or not selected["pgrouting"]:
        raise ValueError("Missing core PostGIS or pgRouting control candidates")
    return {
        "schemaVersion": "pgextwin-issue112-osgeo-exact-bundle-controls-deny-only/v1",
        "status": "CANDIDATE_ONLY",
        "pgMajor": PG,
        "bundleVersion": VERSION,
        "originalSourceUrl": ORIGIN,
        "originalZipBytes": EXPECTED_SIZE,
        "originalZipSha256": EXPECTED_SHA,
        "componentObservations": [
            {"extension": name, "observedControlMembers": selected[name],
             "directInstallableControlObserved": any(
                 row["location"] == "DIRECT_SHARE_EXTENSION" for row in selected[name]
             )}
            for name in BUNDLE_COMPONENTS
        ],
        "observedComponentControlNames": sum(bool(rows) for rows in selected.values()),
        "missingComponentControlNames": sorted(
            name for name, rows in selected.items() if not rows
        ),
        "memberPresenceIsNotCurrentSupportOrLicense": True,
        **{flag: False for flag in DENIALS},
    }


def review_original(opener=None) -> dict:
    """Single canonical no-redirect original; rehash & delete ephemeral bytes."""
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    with tempfile.TemporaryDirectory(prefix="pgextwin-osgeo-controls-") as directory:
        target = Path(directory) / (ROOT[:-1] + ".zip")
        size, sha = read_original(ORIGIN, target, opener=opener)
        if size != EXPECTED_SIZE or sha != EXPECTED_SHA:
            raise ValueError("Original ZIP SHA256/size mismatch")
        verified_local_zip(target, PG)
        with zipfile.ZipFile(target) as archive:
            receipt = inventory(archive)
    if any(receipt.get(flag) is not False for flag in DENIALS):
        raise ValueError("Unauthorized positive or missing admission flag")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(review_original(), sort_keys=True))
    print("OSGEO_EXACT_CONTROL_INVENTORY=OBSERVED_ONLY "
          "RUNTIME=UNVERIFIED RIGHTS=UNVERIFIED PROVENANCE=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY REDISTRIBUTION=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
