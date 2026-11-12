#!/usr/bin/env python3
"""Review observed Windows PostgreSQL modules against exact TimescaleDB PE imports.

Read-only receipt join. Module enumeration is an observation of sampled processes,
not a proof of Windows DLL search order, API-set forwarding, every dynamic load,
license closure, producer attestation, admission, or public access.
"""
import argparse
import json
from pathlib import Path, PureWindowsPath
import re

HEX = re.compile(r"[0-9a-f]{64}\Z")
PG = ("16", "17", "18")
VERSIONS = ("2.31.0", "2.32.0")

def dll_names(version):
    if version not in VERSIONS:
        raise ValueError("Unreviewed TimescaleDB release version")
    return frozenset((
        "timescaledb.dll", f"timescaledb-{version}.dll",
        f"timescaledb-tsl-{version}.dll",
    ))

DLLS = dll_names("2.31.0")  # Preserve the reviewed historical test contract.



def strict_load(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("Invalid bounded receipt input")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("Duplicate receipt key")
            result[k] = v
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def join_receipts(static, runtime, pg, version="2.31.0"):
    expected_dlls = dll_names(version)
    if pg not in PG or type(static) is not dict or type(runtime) is not dict:
        raise ValueError("Unsupported PG or invalid receipts")
    if (static.get("schemaVersion") != "pgextwin-issue112-timescaledb-pe-imports-deny-only/v1"
            or static.get("state") != "CANDIDATE_ONLY_NONPUBLISHING"
            or static.get("pgMajor") != pg or static.get("allImportTablesParsed") is not True
            or static.get("publicGetAuthorized") is not False
            or static.get("publisherAuthorized") is not False):
        raise ValueError("Original exact PE audit has not passed its deny-only gates")
    if version == "2.32.0":
        # Bind the live sample to the separate 2.32.0 independent original
        # ZIP ledger before checking any module paths. Never reuse 2.31.0.
        from issue112_timescaledb_pe_imports import latest_original_pin
        pin = latest_original_pin(pg)
        if (static.get("releaseTag") != version or
                static.get("assetId") != pin["assetId"] or
                static.get("originalBytes") != pin["size"] or
                static.get("originalSha256") != pin["sha256"]):
            raise ValueError("Live 2.32.0 import receipt is not exact original")
    elif static.get("releaseTag") not in (None, "2.31.0"):
        raise ValueError("Historical import receipt version mismatch")
    if (version == "2.32.0" and runtime.get("releaseVersion") != version):
        raise ValueError("Runtime sample belongs to wrong release version")
    if (version == "2.31.0" and runtime.get("releaseVersion") not in (None, version)):
        raise ValueError("Historical runtime sample version mismatch")
    originals = static.get("dllImportReceipts")
    if type(originals) is not list or len(originals) != 3:
        raise ValueError("Invalid original DLL count")
    expected = {}
    imported = {}
    for row in originals:
        if type(row) is not dict or row.get("analysis") != "AMD64_PE32_PLUS_IMPORT_TABLES_PARSED":
            raise ValueError("Unparsed original member")
        name = PureWindowsPath(row.get("path", "")).name.casefold()
        digest = row.get("sha256")
        if (name not in expected_dlls or name in expected or
                type(digest) is not str or not HEX.fullmatch(digest) or
                type(row.get("nonbundledNameImports")) is not list):
            raise ValueError("Invalid exact original DLL identity")
        expected[name] = {"path": row["path"], "sha256": digest}
        for dep in row["nonbundledNameImports"]:
            if (type(dep) is not str or not dep or dep != dep.casefold()
                    or "/" in dep or "\\" in dep):
                raise ValueError("Invalid nonbundled imported name")
            imported.setdefault(dep, set()).add(row["path"])
    if set(expected) != expected_dlls:
        raise ValueError("Missing original DLL")
    triage = static.get("unbundledImportTriage")
    if (type(triage) is not list or
            set(x.get("name") for x in triage if type(x) is dict) != set(imported) or
            len(triage) != len(imported)):
        raise ValueError("Static import triage does not match per-DLL receipts")
    for row in triage:
        if (row.get("referencedBy") != sorted(imported[row["name"]]) or
                row.get("resolvedOnExactTargetWindows") is not False):
            raise ValueError("Unfounded original dependency-resolution claim")
    if (runtime.get("pgMajor") != pg or
            type(runtime.get("sampledProcessCount")) is not int or
            runtime["sampledProcessCount"] < 1):
        raise ValueError("No matched PostgreSQL process was sampled")
    modules = runtime.get("modules")
    if type(modules) is not list or len(modules) > 1000:
        raise ValueError("Unbounded Windows module evidence")
    seen = {}
    for module in modules:
        if type(module) is not dict or set(module) != {
            "path", "name", "sha256", "authenticodeStatus"}:
            raise ValueError("Unknown Windows module receipt")
        path = module["path"]
        name = module["name"]
        digest = module["sha256"]
        if (type(path) is not str or not 3 <= len(path) <= 512 or
                type(name) is not str or name != PureWindowsPath(path).name.casefold() or
                type(digest) is not str or not HEX.fullmatch(digest) or
                type(module["authenticodeStatus"]) is not str):
            raise ValueError("Invalid Windows module path/hash/signature observation")
        identity = path.casefold()
        if identity in seen and seen[identity] != module:
            raise ValueError("Conflicting Windows module receipt")
        seen[identity] = module
    by_name = {}
    for row in seen.values():
        by_name.setdefault(row["name"], []).append(row)
    loaded = []
    for name in sorted(expected_dlls):
        members = sorted(by_name.get(name, []), key=lambda r: r["path"].casefold())
        loaded.append({
            "name": name,
            "originalZipMemberSha256": expected[name]["sha256"],
            "sampledPaths": members,
            "atLeastOneLoadedFileMatchesOriginalSha256": any(
                m["sha256"] == expected[name]["sha256"] for m in members),
        })
    if not any(x["atLeastOneLoadedFileMatchesOriginalSha256"] for x in loaded):
        raise ValueError("No exact original TimescaleDB DLL observed in live PostgreSQL")
    providers = []
    for name in sorted(imported):
        providers.append({
            "importName": name,
            "referencedBy": sorted(imported[name]),
            "observedLoadedPaths": sorted(by_name.get(name, []),
                                          key=lambda r: r["path"].casefold()),
            "observedAsLoadedModule": name in by_name,
            "allEffectiveLoaderPathsProven": False,
        })
    return {
        "schemaVersion": "pgextwin-issue112-timescaledb-windows-loaded-module-evidence/v1",
        "scope": "CANDIDATE_ONLY_NONPUBLISHING",
        "pgMajor": pg, "releaseTag": version,
        "originalZipSha256": static.get("originalSha256"),
        "sampledPostgresProcessCount": runtime["sampledProcessCount"],
        "timescaledbLoadedDlls": loaded, "nonbundledImports": providers,
        "observationLimit": "SAMPLED_POSTGRES_PROCESSES_NOT_COMPLETE_LOADER_CLOSURE",
        "apiSetForwardingVerified": False, "unobservedDynamicLoadCoverageVerified": False,
        "allDependenciesResolvedVerified": False,
        "licenseAndThirdPartyNoticesVerified": False,
        "producerBuildToAssetSignatureVerified": False,
        "newSourceSpecificOwnerSignedAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=PG, required=True)
    parser.add_argument("--version", choices=VERSIONS, default="2.31.0")
    parser.add_argument("--imports", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()
    report = join_receipts(strict_load(args.imports), strict_load(args.runtime), args.pg, version=args.version)
    print(json.dumps(report, sort_keys=True))
    print("TIMESCALEDB_LIVE_MODULE_OBSERVATION=PASS VERSION=" + args.version + " PG=" + args.pg +
          " FULL_DEPENDENCY_CLOSURE=UNVERIFIED PUBLIC_GET=DENY"
          " MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
