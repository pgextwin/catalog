#!/usr/bin/env python3
"""Read-only original-PGroonga static dependency-to-rights graph; never GET admission.

All path/rights candidates remain unverified. PE import names do not establish
Windows DLL resolution, optional LoadLibrary edges, or redistribution rights.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import tempfile

from issue112_osgeo_dependency_inventory import NAME_PATTERN
from issue112_pgroonga_pe_imports import inspect_archive
from issue112_pgroonga_rights_audit import (
    PINS, audit_members, download_original, original_name,
)
from issue112_pgroonga_rights_join import PATH_TO_GROUP, join_receipts


def graph(rights, imports, *, strict=False):
    """Join two independently computed observations of the SAME original ZIP."""
    pg = rights.get("pgMajor")
    if (pg not in PINS or imports.get("pgMajor") != pg
            or rights.get("version") != "4.1.0"
            or imports.get("version") != rights["version"]
            or rights.get("expectedZipSha256") != imports.get("expectedZipSha256")):
        raise ValueError("Mismatched original PG major, version or ZIP receipt")
    if strict and (rights.get("expectedZipSha256") != PINS[pg][1]
                   or rights.get("expectedZipBytes") != PINS[pg][0]
                   or imports.get("expectedZipBytes") != PINS[pg][0]):
        raise ValueError("Original ZIP pinned identity changed")
    joined = join_receipts(rights, strict=strict)
    rows = joined["binaryRightsReviewRows"]
    observed = imports.get("perBinaryImports")
    if not isinstance(observed, list) or len(observed) != len(rows):
        raise ValueError("Missing original PE inspection rows")
    by_path = {}
    for item in observed:
        path = item.get("path")
        if not isinstance(path, str) or path in by_path:
            raise ValueError("Duplicated or invalid PE member path")
        by_path[path] = item
    ledger = {r["path"]: r for r in rows}
    if set(by_path) != set(ledger):
        raise ValueError("PE and rights original member inventories differ")
    if strict and (set(ledger) != set(PATH_TO_GROUP) or len(rows) != 43):
        raise ValueError("Missing exact 4.1.0 binary members")
    basenames = defaultdict(list)
    for path in ledger:
        basenames[path.rsplit("/", 1)[-1].casefold()].append(path)
    links, externals, ambiguous, not_parsed = {}, {}, {}, []
    for path in sorted(ledger):
        item = by_path[path]
        if item.get("analysis") == "NOT_PARSED":
            if not isinstance(item.get("reason"), str) or not item["reason"]:
                raise ValueError("Unexplained non-PE binary")
            links[path] = []
            not_parsed.append(path)
            continue
        if item.get("analysis") != "AMD64_PE32_PLUS":
            raise ValueError("Unknown or missing PE analysis status")
        for field in ("staticImports", "delayImports"):
            names = item.get(field)
            if (not isinstance(names, list) or len(names) != len(set(names))
                    or any(not isinstance(x, str) or x != x.lower()
                           or not NAME_PATTERN.fullmatch(x) for x in names)):
                raise ValueError("Unsafe or duplicate PE import names")
        direct = []
        for imported in sorted(set(item["staticImports"] + item["delayImports"])):
            targets = sorted(basenames.get(imported, []))
            if len(targets) == 1:
                direct.append(targets[0])
            elif len(targets) > 1:
                ambiguous.setdefault(imported, set()).add(path)
            else:
                externals.setdefault(imported, set()).add(path)
        links[path] = direct
    output, missing = [], []
    for path in sorted(ledger):
        seen, pending = set(), [path]
        while pending:
            next_path = pending.pop()
            if next_path in seen:
                continue
            seen.add(next_path)
            pending.extend(links[next_path])
        lacking = sorted(p for p in seen if not ledger[p]["candidateDocuments"])
        if lacking:
            missing.append(path)
        output.append({
            "path": path, "sha256": ledger[path]["sha256"],
            "candidateComponentGroup": ledger[path]["candidateComponentGroup"],
            "directBundledImportPathCandidates": links[path],
            "staticReachableBundledBinaryPaths": sorted(seen - {path}),
            "staticReachableComponentGroupCandidates": sorted({
                ledger[p]["candidateComponentGroup"] for p in seen
                if ledger[p]["candidateComponentGroup"]
            }),
            "staticReachableMissingNamedNoticeCandidates": lacking,
            "peImportParsed": path not in not_parsed,
            "actualWindowsLoaderPathsVerified": False,
            "transitiveComponentRightsVerified": False,
            "binarySourceProvenanceVerified": False,
        })
    return {
        "schemaVersion": "pgextwin-pgroonga-static-dependency-rights-graph-deny-only/v1",
        "scope": "CANDIDATE_ONLY_NONPUBLISHING",
        "pgMajor": pg, "version": rights["version"],
        "originalZipSha256": rights["expectedZipSha256"],
        "binaryMembers": len(rows), "namedLegalDocuments": len(rights["licenseNoticeFiles"]),
        "parsedPeMembers": len(rows) - len(not_parsed),
        "notParsedPeMembers": sorted(not_parsed),
        "missingNamedNoticeAtOwnBinary": sorted(
            r["path"] for r in rows if not r["candidateDocuments"]),
        "staticReachableMissingNamedNoticeConsumers": missing,
        "ambiguousBundledImportNames": [
            {"name": name, "consumers": sorted(paths), "resolvedOnWindows": False}
            for name, paths in sorted(ambiguous.items())
        ],
        "notBundledImportNames": [
            {"name": name, "consumers": sorted(paths), "resolvedOnWindows": False}
            for name, paths in sorted(externals.items())
        ],
        "perBinaryGraph": output,
        "staticNameGraphIsRealWindowsLoaderEvidence": False,
        "allThirdPartyLicenseAndNoticeObligationsVerified": False,
        "optionalDynamicLoadLibraryDependenciesVerified": False,
        "historicalGroongaInputSha256Authenticated": False,
        "signedProducerSourceToBinaryAttestationVerified": False,
        "independentOwnerSignedGetAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", required=True, type=int, choices=tuple(PINS))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pgroonga-rights-deps-") as directory:
        archive = Path(directory) / original_name(args.pg)
        download_original(args.pg, archive)
        rights = audit_members(archive, args.pg)
        imports = inspect_archive(archive, args.pg)
        report = graph(rights, imports, strict=True)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    print("TRANSITIVE_STATIC_NAME_GRAPH=OBSERVED ACTUAL_DLL_RESOLUTION=UNVERIFIED "
          "COMPONENT_RIGHTS=DENY PRODUCER_ATTESTATION=DENY OWNER=DENY "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
