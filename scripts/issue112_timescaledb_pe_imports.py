#!/usr/bin/env python3
"""Original TimescaleDB 2.31.0 PE static/delay-import evidence, deny-only.

Reuses reviewed original ZIP pins, ZIP safety and exact per-DLL byte receipts.
PE import names are not effective Windows loader resolution, dynamic loads,
component rights, producer provenance or public download authorization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.request
import zipfile

from issue112_osgeo_dependency_inventory import (
    WINDOWS_SYSTEM_NAME_HINTS, static_imports,
)
from issue112_pgroonga_independent_rehash import copy_checked_bytes
from issue112_timescaledb_dll_receipts import dll_receipts, MAX_DLL_BYTES
from issue112_timescaledb_original_rehash import (
    MAJORS, OnlyOfficialRedirects, checked_url, original_pin,
)

EXPECTED_DLL_NAMES = frozenset({
    "timescaledb.dll",
    "timescaledb-2.31.0.dll",
    "timescaledb-tsl-2.31.0.dll",
})


def inspect_imports(zip_path):
    """Bind static import observations to exact verified DLL member receipts."""
    original = dll_receipts(zip_path)  # ZIP path/CRC/sizes and PE headers checked.
    receipts = original["dllMembers"]
    by_basename = {}
    for row in receipts:
        basename = row["path"].rsplit("/", 1)[-1].casefold()
        if basename in by_basename:
            raise ValueError("Ambiguous TimescaleDB DLL basename")
        by_basename[basename] = row
    if frozenset(by_basename) != EXPECTED_DLL_NAMES:
        raise ValueError("Unexpected TimescaleDB original DLL identity")

    rows = []
    referenced_by = {}
    with zipfile.ZipFile(zip_path) as archive:
        for row in receipts:
            member = archive.getinfo(row["path"])
            if not 0 < member.file_size <= MAX_DLL_BYTES:
                raise ValueError("Invalid bounded TimescaleDB DLL size")
            with archive.open(member) as stream:
                data = stream.read(MAX_DLL_BYTES + 1)
            if (len(data) != row["bytes"] or
                    hashlib.sha256(data).hexdigest() != row["sha256"]):
                raise ValueError("Import scan bytes differ from original DLL receipt")
            try:
                ordinary, delayed = static_imports(data)
                analysis = "AMD64_PE32_PLUS_IMPORT_TABLES_PARSED"
                error = None
            except ValueError as exc:
                # A valid AMD64 PE header is not proof that the import tables
                # are parseable. Preserve this gap; do not silently pass it.
                ordinary, delayed = [], []
                analysis = "NOT_PARSED"
                error = str(exc)
            names = sorted(set(ordinary + delayed))
            external = sorted(n for n in names if n not in by_basename)
            for name in external:
                referenced_by.setdefault(name, set()).add(row["path"])
            rows.append({
                "path": row["path"], "bytes": row["bytes"],
                "sha256": row["sha256"], "analysis": analysis,
                "parseError": error, "staticImports": ordinary,
                "delayImports": delayed,
                "bundledNameImports": sorted(n for n in names if n in by_basename),
                "nonbundledNameImports": external,
                "actualWindowsLoaderResolutionVerified": False,
                "dynamicLoadLibraryCoverageVerified": False,
                "componentLicenseNoticeVerified": False,
                "producerSourceToBinaryProvenanceVerified": False,
            })

    unresolved = []
    for name, consumers in sorted(referenced_by.items()):
        if name in WINDOWS_SYSTEM_NAME_HINTS:
            category = "WINDOWS_OS_NAME_HINT_ONLY"
        elif name == "postgres.exe":
            category = "POSTGRES_HOST_NAME_HINT_ONLY"
        else:
            category = "NONBUNDLED_IMPORT_PROVIDER_UNVERIFIED"
        unresolved.append({
            "name": name, "category": category,
            "referencedBy": sorted(consumers),
            "resolvedOnExactTargetWindows": False,
        })
    return {
        "dllImportReceipts": rows,
        "unbundledImportTriage": unresolved,
        "allImportTablesParsed": all(
            x["analysis"] == "AMD64_PE32_PLUS_IMPORT_TABLES_PARSED"
            for x in rows),
        "zipInventory": original["zipInventory"],
    }


def audit(pg, opener=None):
    pin = original_pin(pg)
    opener = opener or urllib.request.build_opener(OnlyOfficialRedirects())
    request = urllib.request.Request(pin["url"], headers={
        "User-Agent": "pgextwin-issue112-timescale-pe-import-intake/1",
    })
    with tempfile.TemporaryDirectory(prefix="issue112-timescale-imports-") as tmp:
        dest = Path(tmp) / pin["name"]
        with opener.open(request, timeout=90) as response:
            checked_url(response.geturl())
            size, sha = copy_checked_bytes(
                response, dest, pin["size"], pin["sha256"])
        imports = inspect_imports(dest)
    return {
        "schemaVersion": "pgextwin-issue112-timescaledb-pe-imports-deny-only/v1",
        "state": "CANDIDATE_ONLY_NONPUBLISHING",
        "pgMajor": pg, "assetId": pin["assetId"],
        "originalBytes": size, "originalSha256": sha,
        **imports,
        "effectiveWindowsLoaderResolutionVerified": False,
        "dynamicDependenciesVerified": False,
        "exactComponentLicenseAndNoticesVerified": False,
        "producerRunBoundToAssetDigestVerified": False,
        "newSourceSpecificSignedAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=MAJORS, required=True)
    args = parser.parse_args()
    result = audit(args.pg)
    print(json.dumps(result, sort_keys=True))
    print("TIMESCALEDB_PE_IMPORTS=OBSERVED_NOT_AUTHORIZED PG=" + args.pg +
          " PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
