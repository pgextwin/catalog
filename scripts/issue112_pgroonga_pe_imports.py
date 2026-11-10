#!/usr/bin/env python3
"""PGroonga exact-original PE import observations (static only, nonpublishing)."""
import argparse
import json
from pathlib import Path
import tempfile
import zipfile

from issue112_pgroonga_rights_audit import (
    MAX_BIN, PINS, audit_members, download_original, original_name,
)
from issue112_osgeo_dependency_inventory import static_imports

def import_triage(records, names):
    """Attribute missing imports to consumers; names do NOT verify loader paths."""
    all_external = {}
    for record in records:
        if record["analysis"] != "AMD64_PE32_PLUS":
            continue
        for dep in record["staticImports"] + record["delayImports"]:
            if dep not in names:
                all_external.setdefault(dep, set()).add(record["path"])
    return [{"name": dep, "requesters": sorted(requesters),
             "targetWindowsDllResolutionVerified": False}
            for dep, requesters in sorted(all_external.items())]

def inspect_archive(path, pg, *, verify_pin=True):
    receipts = audit_members(path, pg, require_pin=verify_pin)
    records = []
    by_basename = {}
    for item in receipts["binaryMemberReceipts"]:
        base = item["path"].rsplit("/", 1)[-1].lower()
        by_basename.setdefault(base, []).append(item["path"])
    with zipfile.ZipFile(path) as archive:
        for item in receipts["binaryMemberReceipts"]:
            name = item["path"]
            info = archive.getinfo(name)
            if not 0 < info.file_size <= MAX_BIN:
                raise ValueError("Invalid PE member size")
            data = archive.read(info)
            if len(data) != info.file_size:
                raise ValueError("Truncated PE member")
            try:
                regular, delayed = static_imports(data)
            except ValueError as e:
                records.append({"path": name, "analysis": "NOT_PARSED",
                                "reason": str(e)[:160]})
                continue
            records.append({"path": name, "analysis": "AMD64_PE32_PLUS",
                            "staticImports": regular, "delayImports": delayed})
    names = set(by_basename)
    missing = import_triage(records, names)
    return {
        "schemaVersion": "pgextwin-pgroonga-static-pe-imports-nonpublishing/v1",
        "pgMajor": pg, "version": receipts["version"],
        "expectedZipBytes": PINS[pg][0],
        "expectedZipSha256": PINS[pg][1],
        "memberCount": receipts["zipMemberCount"],
        "binaryMemberCount": len(records),
        "parsedPeCount": sum(x["analysis"] == "AMD64_PE32_PLUS" for x in records),
        "nonparsedBinaryMembers": [x for x in records if x["analysis"] == "NOT_PARSED"],
        "ambiguousBundledBasenames": {k: v for k, v in sorted(by_basename.items()) if len(v) > 1},
        "staticImportsAbsentFromBundle": missing,
        "perBinaryImports": records,
        "licenseNoticeCandidatesCount": receipts["licenseNoticeCandidatesCount"],
        "completeRuntimeDependenciesVerified": False,
        "actualTargetWindowsDllResolutionVerified": False,
        "dynamicLoadLibraryDependenciesVerified": False,
        "componentLicenseAndNoticeClosureVerified": False,
        "exactProducerProvenanceVerified": False,
        "independentSignedGetAdmission": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "publisherAuthorized": False,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", type=int, choices=tuple(PINS), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pgroonga-imports-") as folder:
        original = Path(folder) / original_name(args.pg)
        download_original(args.pg, original)
        result = inspect_archive(original, args.pg)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    print("PGROONGA_PE_STATIC_IMPORTS=OBSERVED DYNAMIC_LOADER=UNVERIFIED "
          "NOTICE=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")

if __name__ == "__main__":
    main()
