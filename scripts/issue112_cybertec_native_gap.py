#!/usr/bin/env python3
"""Offline Cybertec index versus native Catalog gap classifier; NEVER an admission."""
import argparse
import json
from pathlib import Path
import re

MAJORS = frozenset(("14", "15", "16", "17", "18"))
NAME = re.compile(r"[a-z][a-z0-9_]{1,40}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
DENIALS = ("originalBytesVerified", "originalSha256Verified", "upstreamVersionVerified",
           "communityPostgresqlAbiVerified", "producerProvenanceVerified",
           "licenseNoticeClosureVerified", "independentSignedAdmission",
           "publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized",
           "releaseAuthorized")
TRAILER = ("CYBERTEC_METADATA_ONLY=YES PACKAGE_COMPATIBILITY=UNVERIFIED "
           "LATEST=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def bounded_file(path, limit):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Missing, linked, empty or oversized input")
    return path.read_text("utf-8")


def load_index(path):
    content = bounded_file(Path(path), MAX_REPORT_BYTES)
    # Accept only the original index script's JSON line plus its exact denial trailer.
    lines = content.splitlines()
    if len(lines) == 2 and lines[1] == TRAILER:
        content = lines[0]
    elif len(lines) != 1:
        raise ValueError("Unexpected index output envelope")
    return json.loads(content, object_pairs_hook=unique)


def catalog_coverage(catalog_root, names):
    root = Path(catalog_root) / "extensions"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Missing native Catalog directory")
    coverage = {}
    for name in names:
        if not NAME.fullmatch(name):
            raise ValueError("Invalid extension identifier")
        path = root / (name + ".json")
        if not path.exists() and not path.is_symlink():
            continue
        document = json.loads(bounded_file(path, MAX_MANIFEST_BYTES), object_pairs_hook=unique)
        if (type(document) is not dict or document.get("schemaVersion") != 2 or
                document.get("name") != name or not isinstance(document.get("postgresql"), dict) or
                not isinstance(document.get("latest"), dict) or
                not document["latest"].get("releaseTag")):
            raise ValueError("Contradictory native Catalog declaration for " + name)
        majors = []
        for major in sorted(MAJORS):
            item = document["postgresql"].get(major)
            if (isinstance(item, dict) and item.get("available") is True and
                    isinstance(item.get("sha256"), str) and SHA.fullmatch(item["sha256"]) and
                    isinstance(item.get("asset"), str) and item["asset"].endswith(".zip")):
                majors.append(major)
        coverage[name] = majors
    return coverage


def classify(report, catalog_root):
    if type(report) is not dict or report.get("schemaVersion") != "pgextwin-issue112-cybertec-windows-index/v1":
        raise ValueError("Unrecognized Cybertec index schema")
    if (report.get("trust") != "UNTRUSTED_DIRECTORY_METADATA_ONLY" or
            report.get("providerPackaging") != "CYBERTEC_PGEE_COMMUNITY_PG_COMPATIBILITY_UNVERIFIED" or
            report.get("latestVersionResolution") != "NOT_VERIFIED"):
        raise ValueError("Source trust escalation")
    for flag in ("sourceArchiveDownloaded", "binaryArchiveDownloaded", "publicGetAuthorized",
                 "mirrorAuthorized", "publisherAuthorized", "releaseAuthorized"):
        if report.get(flag) is not False:
            raise ValueError("Unauthorized source/publication claim")
    observed = report.get("pgMajorsObserved")
    if (type(observed) is not list or not observed or len(set(observed)) != len(observed) or
            any(type(m) is not str or m not in MAJORS for m in observed)):
        raise ValueError("Invalid observed PG majors")
    candidates = report.get("candidates")
    if (type(candidates) is not list or not candidates or len(candidates) > 500 or
            report.get("zipCandidates") != len(candidates)):
        raise ValueError("Invalid or unbounded candidate list")
    names = {}
    unique_assets = set()
    for row in candidates:
        if type(row) is not dict or any(row.get(flag) is not False for flag in DENIALS):
            raise ValueError("Candidate trust escalation")
        name, pg, filename = row.get("extension"), row.get("pgMajor"), row.get("fileName")
        if (type(name) is not str or not NAME.fullmatch(name) or pg not in observed or
                type(filename) is not str or len(filename) > 200 or
                not filename.startswith(f"{name}-{pg}") or not filename.endswith(".zip")):
            raise ValueError("Invalid candidate identity")
        ident = (pg, filename)
        if ident in unique_assets:
            raise ValueError("Duplicate candidate ZIP")
        unique_assets.add(ident)
        names.setdefault(name, set()).add(pg)
    if (report.get("extensionNamesObserved") != len(names) or
            report.get("completeObservedFiveMajorNames") != sorted(
                name for name, majors in names.items() if MAJORS <= majors)):
        raise ValueError("Contradictory reported coverage")
    native = catalog_coverage(catalog_root, sorted(names))
    new = sorted(set(names) - set(native))
    return {
        "schemaVersion": "pgextwin-issue112-cybertec-native-gap/v1",
        "comparison": "CANDIDATE_METADATA_VS_NATIVE_CATALOG_DECLARATION_ONLY",
        "providerPackaging": "CYBERTEC_PGEE_COMMUNITY_PG_COMPATIBILITY_UNVERIFIED",
        "indexCandidateZipCount": len(candidates),
        "indexExtensionNameCount": len(names),
        "catalogNativeOverlappingNames": sorted(native),
        "catalogNativeOverlappingMajorDeclarations": native,
        "notInNativeCatalogNames": new,
        "notInNativeCatalogFiveMajorObservedNames": sorted(
            n for n in new if MAJORS <= names[n]),
        "unverifiedProviderVersions": True,
        "windowsCompatibilityVerified": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "publisherAuthorized": False, "releaseAuthorized": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--index", type=Path, required=True, help="Existing Cybertec index JSON or exact two-line CLI output")
    p.add_argument("--catalog", type=Path, default=Path(__file__).resolve().parents[1])
    args = p.parse_args()
    print(json.dumps(classify(load_index(args.index), args.catalog), sort_keys=True))
    print("CYBERTEC=METADATA_ONLY NATIVE=CATALOG_DECLARATION_ONLY PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
