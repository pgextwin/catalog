#!/usr/bin/env python3
"""Read-only exact GitHub provider Release identity comparison for #112.

This is a structural verifier for metadata obtained separately from authenticated
GitHub GET. The caller MUST authenticate that GET; JSON passed to this module
is not proof of origin. In particular, a match is NEVER source-specific
Publisher authorization, a valid Sigstore verification, or a download permit.
"""
import re

from external_admission_preflight import ROOT
from external_signed_asset_pin import build_candidate

SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compare_exact_source(row, repository, release):
    """Check one reviewed PG18 source against externally fetched GitHub API data."""
    require(isinstance(row, dict) and isinstance(repository, dict)
            and isinstance(release, dict), "Malformed source/API metadata")
    name = row["sourceRepo"]
    tag = row["releaseTag"]
    require(repository.get("full_name") == name
            and type(repository.get("id")) is int
            and repository["id"] == row["repositoryId"]
            and repository.get("html_url") == "https://github.com/" + name,
            "Wrong provider repository identity")
    require(type(release.get("id")) is int
            and release["id"] == row["releaseId"]
            and release.get("tag_name") == tag
            and release.get("draft") is False
            and release.get("prerelease") is False
            and release.get("html_url") ==
                f"https://github.com/{name}/releases/tag/{tag}",
            "Wrong, draft or prerelease provider Release")

    assets = release.get("assets")
    require(isinstance(assets, list) and 1 <= len(assets) <= 100,
            "Missing or oversized Release asset inventory")
    ids, names, found = set(), set(), None
    for asset in assets:
        require(isinstance(asset, dict) and type(asset.get("id")) is int
                and asset["id"] > 0
                and isinstance(asset.get("name"), str) and asset["name"]
                and asset["id"] not in ids and asset["name"] not in names,
                "Duplicate or invalid provider Release asset identity")
        ids.add(asset["id"])
        names.add(asset["name"])
        if asset["id"] == row["assetId"] or asset["name"] == row["assetName"]:
            require(asset["id"] == row["assetId"]
                    and asset["name"] == row["assetName"],
                    "Provider Release asset ID/name substitution")
            require(found is None, "Duplicate pinned original asset")
            found = asset
    require(found is not None, "Original provider asset disappeared")
    require(type(found.get("size")) is int
            and found["size"] == row["originalBytes"]
            and found.get("state") == "uploaded"
            and isinstance(row.get("originalSha256"), str)
            and SHA256.fullmatch(row["originalSha256"]) is not None
            and found.get("digest") == "sha256:" + row["originalSha256"]
            and found.get("browser_download_url") == row["originalProviderUrl"],
            "Provider asset changed size/hash/URL/upload state")

    # Source specificity: this comparison cannot upgrade a signed candidate
    # or override its deny-only permissions.
    require(row.get("sourceGroup") == "external"
            and row.get("pgMajor") == "18"
            and row.get("sourcePublisherAuthorized") is False
            and row.get("downloadAuthorized") is False
            and row.get("mirrorAuthorized") is False,
            "Untrusted external record attempted permission elevation")
    return {
        "sourceRepo": name,
        "releaseId": row["releaseId"],
        "assetId": row["assetId"],
        "originalSha256": row["originalSha256"],
        "scope": "EXACT_GITHUB_RELEASE_METADATA_MATCH_ONLY",
        "sourcePublisherAuthorized": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
    }


def compare_publisher_intake(root=ROOT, commit=None, snapshots=None):
    """Bind the two reviewed candidates to supplied API snapshots; still DENY."""
    candidate = build_candidate(root, commit)
    require(candidate["originalProviderAssets"] == 2
            and candidate["discoveryCandidates"] == 203
            and candidate["downloadDeniedCandidates"] == 203
            and all(candidate[field] is False for field in (
                "originalBinarySignatureVerified", "publicationAuthorized",
                "sourcePublisherAuthorized", "downloadAuthorized",
                "mirrorAuthorized", "redistributionAuthorized", "installAuthorized")),
            "Candidate attempted trust elevation")
    rows = candidate["records"]
    require(isinstance(snapshots, dict)
            and set(snapshots) == {row["sourceRepo"] for row in rows},
            "Incomplete or expanded source-specific API snapshot")
    results = []
    for row in rows:
        snapshot = snapshots[row["sourceRepo"]]
        require(isinstance(snapshot, dict)
                and set(snapshot) == {"repository", "release"},
                "Malformed source-specific API snapshot")
        results.append(compare_exact_source(row, snapshot["repository"],
                                            snapshot["release"]))
    return {
        "schemaVersion": "pgextwin-external-source-publisher-readiness/v1",
        "catalogCommit": commit,
        "metadataIdentityMatched": len(results),
        "discoveryCandidates": 203,
        "downloadDeniedCandidates": 203,
        "status": "METADATA_MATCH_ONLY_FORMAL_AUTHORIZATION_REQUIRED",
        "requiredIndependentGates": [
            "authenticated_github_rest_get_of_source_repo_release_and_asset",
            "original_main_signed_pin_and_independent_sigstore_byte_verification",
            "dedicated_protected_publisher_environment",
            "publisher_app_identity_and_minimum_permission_policy",
            "source_specific_direct_link_rights_and_visible_notice_policy",
            "actual_original_asset_byte_sha256_and_target_abi_verification",
            "formal_source_specific_publisher_acceptance",
        ],
        "publicationAuthorized": False,
        "sourcePublisherAuthorized": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "installAuthorized": False,
        "records": results,
    }
