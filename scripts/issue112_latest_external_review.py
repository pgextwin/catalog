#!/usr/bin/env python3
"""Fail-closed, offline latest-observed external review plan; never a download feed.

Reuses the existing validated GitHub discovery review and independently
rehashed OSGeo original pins. Does not fetch, sign, install or publish assets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from issue112_external_batch_plan import build as github_review, Denied, SUPPORTED
from issue112_osgeo_winnie_version_receipt import ORIGINALS

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "pgextwin-issue112-latest-external-review/v1"
NAME = re.compile(r"[a-z][a-z0-9_]{1,40}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")
# Official PostGIS Windows bundles also contain the listed installable
# PostGIS subextensions (see the upstream Enabling PostGIS instructions).
# These are *review candidates*, not independently verified/authorized
# components. One original ZIP per PG major; never manufacture new assets.
# Filename versions refer ONLY to the PostGIS BUNDLE, not individual modules.
BUNDLE_COMPONENTS = (
    "postgis",
    "pgrouting",
    "postgis_raster",
    "postgis_sfcgal",
    "postgis_topology",
    "address_standardizer",
    "postgis_tiger_geocoder",
)
DENY = dict(downloadAuthorized=False, mirrorAuthorized=False,
            redistributionAuthorized=False, publisherAuthorized=False,
            releaseAuthorized=False, independentSignedAdmission=False)


def require(ok, reason):
    if not ok:
        raise Denied("latest external review DENY: " + reason)


def version_key(value):
    """Numeric, stable-only ordering: 1.10 > 1.9; reject pre-releases."""
    if type(value) is not str or VERSION.fullmatch(value) is None:
        return None
    numbers = tuple(int(part) for part in value.split("."))
    if any(num > 999999 for num in numbers):
        return None
    return numbers + (0,) * (4 - len(numbers))


def make_plan(root=ROOT, pg="all", extension=None, version=None, source="all"):
    require(pg == "all" or pg in SUPPORTED, "unsupported PG major")
    require(source in ("all", "github", "osgeo"), "unsupported source type")
    require(extension is None or
            (type(extension) is str and NAME.fullmatch(extension) is not None),
            "unsafe extension filter")
    require(version is None or
            (extension is not None and type(version) is str and
             VERSION.fullmatch(version) is not None),
            "exact --version requires a safe --extension")
    # Always validate the COMPLETE GitHub candidate registry before filtering.
    # Source, PG and version selectors must never hide a poisoned unselected row.
    baseline = github_review(root)
    rows = []
    if source in ("all", "github"):
        for batch in baseline["batches"]:
            for candidate in batch["records"]:
                major = candidate["pgMajor"]
                if major not in SUPPORTED:
                    continue
                rows.append({
                    "source": "GITHUB_DISCOVERY_ONLY",
                    "extension": candidate["extension"], "pgMajor": major,
                    "version": candidate["version"],
                    "versionMeaning": "UPSTREAM_VERSION_OBSERVED",
                    "provider": candidate["provider"],
                    "releaseTag": candidate["releaseTag"],
                    "assetName": candidate["assetName"],
                    "format": candidate["format"],
                    "packageIdentity": "github:" + candidate["provider"].lower() +
                                       ":" + str(candidate["releaseId"]) + ":" +
                                       str(candidate["assetId"]),
                    "originalBytes": candidate["originalBytes"],
                    "originalSha256": candidate["originalSha256"],
                    "blockers": candidate["blockers"],
                    **DENY,
                })
    if source in ("all", "osgeo"):
        # ORIGINALS is an independently SHA256-rehashed, immutable 5-major
        # set. No inference of currently upstream-latest or signer identity.
        for major, (bundle_version, size, sha) in sorted(ORIGINALS.items()):
            require(major in SUPPORTED and version_key(bundle_version) is not None and
                    type(size) is int and size > 0 and
                    type(sha) is str and re.fullmatch(r"[0-9a-f]{64}", sha),
                    "malformed previously observed OSGeo pin")
            filename = f"postgis-bundle-pg{major}-{bundle_version}x64.zip"
            identity = f"osgeo:pg{major}:{bundle_version}:{sha}"
            for component in BUNDLE_COMPONENTS:
                rows.append({
                    "source": "OSGEO_REHASHED_ORIGINAL_ONLY",
                    "extension": component, "pgMajor": major,
                    "version": bundle_version,
                    "versionMeaning": "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION",
                    "provider": "OSGeo/PostGIS Windows Winnie",
                    "releaseTag": None,
                    "assetName": filename, "format": "zip",
                    "packageIdentity": identity,
                    "originalBytes": size, "originalSha256": sha,
                    "blockers": [
                        "PRODUCER_SOURCE_TO_BINARY_ATTESTATION_MISSING",
                        "ALL_COMPONENT_LICENSE_NOTICE_CLOSURE_MISSING",
                        "RUNTIME_DEPENDENCY_CLOSURE_MISSING",
                        "INDEPENDENT_SIGNED_SOURCE_AUTHORIZATION_REQUIRED",
                    ],
                    **DENY,
                })
    # Do not equate 'highest in a bounded inventory' to upstream's latest.
    # Crucially, keep ALL same-version variants for manual source review.
    groups = {}
    for row in rows:
        key = version_key(row["version"])
        if key is None:
            continue
        if pg != "all" and row["pgMajor"] != pg:
            continue
        if extension is not None and row["extension"] != extension:
            continue
        if version is not None and row["version"] != version:
            continue
        group = (row["extension"], row["pgMajor"])
        prior = groups.get(group)
        if prior is None or key > prior[0]:
            groups[group] = (key, [row])
        elif key == prior[0]:
            prior[1].append(row)

    selected = []
    for group in sorted(groups, key=lambda item: (item[0], int(item[1]))):
        selected.extend(sorted(groups[group][1], key=lambda x: (
            x["source"], x["provider"], x["assetName"], x["packageIdentity"])))
    # Every listed component of a PG major shares ONE OSGeo ZIP identity.
    # Keep each component's review row, count the ZIP once. Review dedup
    # never permits any download or claims individual component runtime proof.
    packages = sorted(set(item["packageIdentity"] for item in selected))
    coverage = {}
    for item in selected:
        coverage.setdefault(item["extension"], []).append(item["pgMajor"])
    coverage = {name: sorted(set(majors), key=int)
                for name, majors in sorted(coverage.items())}
    require(all(all(item.get(flag) is False for flag in DENY) for item in selected),
            "permission escalation")
    return {
        "schemaVersion": SCHEMA,
        "trust": "CANDIDATE_REVIEW_ONLY_NEVER_AUTHORIZATION",
        "selectionRule": "HIGHEST_STABLE_VERSION_OBSERVED_PER_EXTENSION_AND_PG",
        "latestUpstreamVerified": False,
        "sourceSelection": source, "pgSelection": pg,
        "extensionSelection": extension, "exactVersionSelection": version,
        "githubDiscoveryCandidatesChecked": baseline["totalCandidateAssets"],
        "selectedReviewRows": len(selected),
        "uniqueOriginalPackages": len(packages),
        "uniqueOriginalPackageIdentities": packages,
        "observedMajorCoverageNotSupportClaim": coverage,
        "selected": selected,
        "admittedAssets": 0,
        **DENY,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT)
    parser.add_argument("--pg", default="all", choices=("all", *sorted(SUPPORTED)))
    parser.add_argument("--extension")
    parser.add_argument("--version")
    parser.add_argument("--source", default="all",
                        choices=("all", "github", "osgeo"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = make_plan(args.catalog, args.pg, args.extension,
                       args.version, args.source)
    require(not args.output.exists() and not args.output.is_symlink(),
            "output must be create-only")
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(f"LATEST_OBSERVED_REVIEW={result['selectedReviewRows']} "
          f"UNIQUE_ORIGINALS={result['uniqueOriginalPackages']} "
          "AUTHORIZED=0 PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
