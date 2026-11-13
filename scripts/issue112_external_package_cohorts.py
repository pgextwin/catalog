#!/usr/bin/env python3
"""Package-centric external review batches: latest observed / exact version.

Never an authorization feed, issuer request, public GET, mirror or release.
One physical original (e.g. an OSGeo bundle) is planned only once per PG major,
even when several extension components select it.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

from issue112_external_batch_plan import Denied, SUPPORTED
from issue112_latest_external_review import DENY, ROOT, make_plan, version_key

SCHEMA = "pgextwin-issue112-external-original-cohorts/v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FORMAT = frozenset(("zip", "7z", "exe"))
MAX_ROWS = 5000


def require(ok, reason):
    if not ok:
        raise Denied("external original cohorts DENY: " + reason)


def validate_row(row):
    require(type(row) is dict and
            type(row.get("packageIdentity")) is str and
            0 < len(row["packageIdentity"]) <= 350 and
            type(row.get("extension")) is str and
            type(row.get("source")) is str and
            type(row.get("provider")) is str and
            type(row.get("pgMajor")) is str and
            row["pgMajor"] in SUPPORTED and
            type(row.get("assetName")) is str and
            re.fullmatch(r"[A-Za-z0-9_.+-]{1,220}", row["assetName"]) is not None and
            row.get("format") in FORMAT and
            type(row.get("versionMeaning")) is str and
            all(row.get(flag) is False for flag in DENY),
            "malformed or authority-bearing review row")
    blockers = row.get("blockers")
    require(type(blockers) is list and len(blockers) > 0 and
            all(type(b) is str and 0 < len(b) <= 120 for b in blockers),
            "missing bounded admission blockers")
    size, digest = row.get("originalBytes"), row.get("originalSha256")
    require((size is None and digest is None) or
            (type(size) is int and 0 < size <= 2_000_000_000 and
             type(digest) is str and SHA256.fullmatch(digest) is not None),
            "mismatched original SHA256/byte receipts")
    identity = row["packageIdentity"]
    bundle = row["versionMeaning"] == "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION"
    if bundle:
        require(row["source"] == "OSGEO_REHASHED_ORIGINAL_ONLY" and
                row["format"] == "zip" and size is not None and
                version_key(row.get("version")) is not None,
                "unverified shared bundle metadata")
    return bundle


def build(root=ROOT, pg="all", extension=None, version=None, source="all",
          max_batch=12, cybertec_index=None, packaging_label=None,
          single_bundle=False, latest_per_pg=False):
    require(type(max_batch) is int and 1 <= max_batch <= 20,
            "batch size must be between 1 and 20")
    require(type(single_bundle) is bool and
            (not single_bundle or
             (pg == "all" and version is None and source in ("all", "osgeo"))),
            "--single-bundle requires --pg all, OSGeo source and no exact --version")
    require(type(latest_per_pg) is bool and
            (not latest_per_pg or version is None),
            "--latest-per-pg cannot accompany exact --version")
    # The existing selector validates every upstream registry and signed-denial
    # field BEFORE filtering. Do not reproduce or weaken that validation here.
    review = make_plan(root, pg=pg, extension=extension, version=version,
                       source=source, cybertec_index=cybertec_index,
                       packaging_label=packaging_label)
    require(review.get("schemaVersion") ==
            "pgextwin-issue112-latest-external-review/v1" and
            review.get("trust") == "CANDIDATE_REVIEW_ONLY_NEVER_AUTHORIZATION" and
            review.get("admittedAssets") == 0 and
            all(review.get(flag) is False for flag in DENY),
            "underlying review is not deny-only")
    rows = review.get("selected")
    require(type(rows) is list and len(rows) <= MAX_ROWS and
            review.get("selectedReviewRows") == len(rows),
            "invalid or unbounded selected inventory")

    # Validate the entire underlying selected inventory BEFORE narrowing to
    # the newest observed version across PG majors. In particular, a poisoned
    # older row must not be hidden by the latest-only preference.
    require(all(type(r) is dict and type(r.get("packageIdentity")) is str
                for r in rows) and
            len({r["packageIdentity"] for r in rows}) ==
            review.get("uniqueOriginalPackages") and
            set(r["packageIdentity"] for r in rows) ==
            set(review.get("uniqueOriginalPackageIdentities", [])),
            "underlying review identity set mismatch")
    # Both selectors must not mask an invalid row from the full inventory.
    for row in rows:
        validate_row(row)
    chosen_bundle = None
    if single_bundle:
        bundled = [r for r in rows if
                   r["versionMeaning"] == "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION"]
        require(bool(bundled), "no observed OSGeo bundle to choose")
        chosen_bundle = max(
            bundled, key=lambda r: (version_key(r["version"]),
                                    int(r["pgMajor"]), r["packageIdentity"]))
        rows = [r for r in rows
                if r["versionMeaning"] != "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION"
                or r["packageIdentity"] == chosen_bundle["packageIdentity"]]
    older_omitted = 0
    if version is None and not latest_per_pg:
        highest = {}
        for r in rows:
            # Bundle releases are intentionally chosen per available PG
            # original, not by comparing pgRouting component versions.
            if r.get("versionMeaning") == "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION":
                continue
            key = version_key(r.get("version"))
            if key is not None:
                name = r.get("extension")
                if name not in highest or key > highest[name]:
                    highest[name] = key
        kept = [
            r for r in rows
            if r.get("versionMeaning") == "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION"
            or version_key(r.get("version")) is None
            or version_key(r.get("version")) == highest.get(r.get("extension"))
        ]
        older_omitted = len(rows) - len(kept)
        rows = kept

    packages = {}
    for row in rows:
        bundle = validate_row(row)
        blockers = row["blockers"]
        size, digest = row.get("originalBytes"), row.get("originalSha256")
        identity = row["packageIdentity"]
        descriptor = (row["source"], row["provider"], row["pgMajor"],
                      row["assetName"], row["format"], row.get("version"),
                      row["versionMeaning"], size, digest, bundle)
        item = packages.get(identity)
        if item is None:
            item = {"packageIdentity": identity, "source": row["source"],
                    "provider": row["provider"], "pgMajor": row["pgMajor"],
                    "assetName": row["assetName"], "format": row["format"],
                    "observedVersion": row.get("version"),
                    "versionMeaning": row["versionMeaning"],
                    "sharedBundle": bundle, "originalBytes": size,
                    "originalSha256": digest, "extensions": [],
                    "blockers": set(), "_descriptor": descriptor}
            packages[identity] = item
        else:
            require(item["_descriptor"] == descriptor,
                    "one package identity has contradictory byte/version/PG metadata")
        require(row["extension"] not in item["extensions"],
                "duplicate extension component in original package")
        item["extensions"].append(row["extension"])
        item["blockers"].update(blockers)

    require(set(packages) == {r["packageIdentity"] for r in rows},
            "deduplication contradicts selected original identities")
    ordered = []
    for item in sorted(packages.values(),
                       key=lambda x: (int(x["pgMajor"]), x["source"],
                                      x["assetName"], x["packageIdentity"])):
        item.pop("_descriptor")
        item["extensions"].sort()
        item["blockers"] = sorted(item["blockers"])
        item["reviewOnly"] = True
        item.update(DENY)
        ordered.append(item)

    # Physical packages, not logical extensions, determine bounded cohorts.
    # A failed or held package cannot cause silent source substitution.
    groups = defaultdict(list)
    for item in ordered:
        groups[item["pgMajor"]].append(item)
    batches = []
    for major, items in sorted(groups.items(), key=lambda pair: int(pair[0])):
        for offset in range(0, len(items), max_batch):
            batches.append({
                "batchId": f"review-{len(batches) + 1:03d}",
                "pgMajor": major, "packages": items[offset:offset + max_batch],
                "reviewOnly": True, "downloadAuthorized": False,
                "publisherAuthorized": False, "mirrorAuthorized": False,
            })
    coverage_sets = defaultdict(set)
    for row in rows:
        coverage_sets[row["extension"]].add(row["pgMajor"])
    coverage = {name: sorted(majors, key=int)
                for name, majors in sorted(coverage_sets.items())}
    missing = {name: sorted(set(SUPPORTED) - set(majors), key=int)
               for name, majors in sorted(coverage.items())}
    return {
        "schemaVersion": SCHEMA,
        "trust": "UNTRUSTED_CANDIDATES_NEVER_SIGNED_ADMISSION",
        "selectionRule": ("EXACT_OBSERVED_VERSION" if version is not None else
                          "LATEST_OBSERVED_PER_EXTENSION_AND_PG" if latest_per_pg else
                          "GLOBAL_HIGHEST_OBSERVED_STABLE_EXCEPT_BUNDLES"),
        "latestUpstreamVerified": False,
        "pgSelection": pg, "sourceSelection": source,
        "extensionSelection": extension, "exactVersionSelection": version,
        "singleLatestBundleRequested": single_bundle,
        "latestPerPgMajorRequested": latest_per_pg,
        "singleBundleOriginalIdentity": (
            chosen_bundle["packageIdentity"] if chosen_bundle is not None else None),
        "singleBundleMajorIsNotCrossMajorCompatibility": single_bundle,
        "observedMajorCoverageNotSupportClaim": coverage,
        "unobservedMajorsNotSupportVerdict": missing,
        "selectedReviewRows": len(rows), "olderObservedRowsOmitted": older_omitted,
        "uniqueOriginalPackages": len(ordered),
        "reviewBatchCount": len(batches), "maxBatch": max_batch,
        "batches": batches, "admittedAssets": 0,
        "networkRequests": 0, "userDownloadAvailable": False,
        **DENY,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT)
    parser.add_argument("--pg", default="all",
                        choices=("all", *sorted(SUPPORTED)))
    parser.add_argument("--extension")
    parser.add_argument("--version")
    parser.add_argument("--source", default="all",
                        choices=("all", "github", "osgeo", "pgroonga",
                                 "http", "timescaledb", "cybertec"))
    parser.add_argument("--cybertec-index", type=Path)
    parser.add_argument("--packaging-label")
    parser.add_argument("--max-batch", type=int, default=12)
    parser.add_argument("--single-bundle", action="store_true",
                        help="Review the newest observed OSGeo bundle only; "
                             "does not imply cross-PG ABI compatibility")
    parser.add_argument("--latest-per-pg", action="store_true",
                        help="Retain newest observed binary for EACH PG major; "
                             "not a support or admission claim")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build(args.catalog, args.pg, args.extension, args.version,
                   args.source, args.max_batch, args.cybertec_index,
                   args.packaging_label, args.single_bundle,
                    args.latest_per_pg)
    require(not args.output.exists() and not args.output.is_symlink(),
            "output must be create-only")
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2,
                                      ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"ORIGINAL_REVIEW_PACKAGES={report['uniqueOriginalPackages']} "
          f"BATCHES={report['reviewBatchCount']} ADMITTED=0 "
          "PUBLIC_GET=DENY MIRROR=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
