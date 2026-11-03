#!/usr/bin/env python3
"""Fail-closed external source-kind Publisher policy; NO publishing authority.

Unlike native OWNER_ISSUE_COMMENT_MAIN_SIGNING, this source kind MUST NOT
inherit the central 'publisher' Environment or its App. Only independently
verified GitHub administrator state, exact original-main signatures, and an
explicit future reviewed protected policy change could enable direct links.
This module intentionally has no issuing or publication path.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from external_admission_preflight import ROOT
from external_direct_link_review import (
    EXACT_ASSETS, REVIEW, strict_read, validate_review,
)

POLICY = "config/issue112-external-publisher-policy.json"
SCHEMA = "pgextwin-external-direct-provider-publisher-policy/v1"
SOURCE_KIND = "EXTERNAL_GITHUB_RELEASE_ASSET"
ENVIRONMENT = "external-direct-provider-publisher"
ROOT_KEYS = {
    "schemaVersion", "sourceKind", "mode", "publisherEnvironment",
    "publisherAppId", "publisherInstallationId",
    "protectedEnvironmentVerified", "leastPrivilegeAppVerified",
    "originalMainIndependentSigstoreVerified",
    "formalSourceSpecificAuthorization", "approvedOperation",
    "mirrorAuthorized", "redistributionAuthorized", "records",
}
ROW_KEYS = {
    "sourceRepo", "releaseId", "assetId", "referenceReviewOnly",
    "noticeRequirement", "dependencyTreatment",
    "sourcePublisherAuthorized", "downloadAuthorized", "mirrorAuthorized",
}
REQUIREMENTS = {
    "andreiramani/pgvector_pgsql_windows": (
        "SHOW_UNOFFICIAL_COMMUNITY_STATUS_AND_UPSTREAM_LICENSE",
        "NO_THIRD_PARTY_DEPENDENCY_REDISTRIBUTION",
    ),
    "laurenz/oracle_fdw": (
        "SHOW_ORIGINAL_LICENSE_AND_SEPARATE_ORACLE_CLIENT_LICENSE",
        "ORACLE_CLIENT_END_USER_OBTAINED_NEVER_REDISTRIBUTED",
    ),
}


def require(condition, reason):
    if not condition:
        raise ValueError("External formal Publisher DENY: " + reason)


def inspect_policy(root=ROOT, policy=None, review=None):
    """Validate exact review + policy; always return NONAUTHORIZING receipt."""
    root = Path(root)
    doc = strict_read(root / POLICY) if policy is None else policy
    source_review = strict_read(root / REVIEW) if review is None else review
    require(validate_review(root, source_review) == {
        "referenceLinksReviewed": 2, "signedExternalCatalogPins": 0,
        "downloadAuthorized": False, "mirrorAuthorized": False,
        "scope": "CANDIDATE_ONLY",
    }, "untrusted source evidence")
    require(type(doc) is dict and set(doc) == ROOT_KEYS, "missing or unknown policy keys")
    for k, expected in (
        ("schemaVersion", SCHEMA),
        ("sourceKind", SOURCE_KIND),
        ("mode", "DENY_PENDING_GITHUB_ADMIN_EVIDENCE"),
        ("publisherEnvironment", ENVIRONMENT),
        ("publisherAppId", None),
        ("publisherInstallationId", None),
        ("protectedEnvironmentVerified", False),
        ("leastPrivilegeAppVerified", False),
        ("originalMainIndependentSigstoreVerified", False),
        ("formalSourceSpecificAuthorization", False),
        ("approvedOperation", "NONE"),
        ("mirrorAuthorized", False),
        ("redistributionAuthorized", False),
    ):
        require(type(doc[k]) is type(expected) and doc[k] == expected,
                "unexpected or elevated boundary field: " + k)
    rows = doc["records"]
    require(type(rows) is list and len(rows) == 2, "unknown or absent source policy")
    reviewed = {
        (r["sourceRepo"], r["releaseId"], r["assetId"]): r
        for r in source_review["records"]
    }
    require(len(reviewed) == 2, "duplicated review identity")
    seen = set()
    for row in rows:
        require(type(row) is dict and set(row) == ROW_KEYS,
                "unexpected source-specific operation keys")
        key = (row.get("sourceRepo"), row.get("releaseId"), row.get("assetId"))
        require(key in EXACT_ASSETS and key in reviewed and key not in seen,
                "repeated, unknown or switched provider asset")
        seen.add(key)
        source = reviewed[key]
        name = source["sourceRepo"]
        notice, dependency = REQUIREMENTS[name]
        require(row["referenceReviewOnly"] is True
                and row["noticeRequirement"] == notice
                and row["dependencyTreatment"] == dependency
                and row["sourcePublisherAuthorized"] is False
                and row["downloadAuthorized"] is False
                and row["mirrorAuthorized"] is False,
                "source rights/NOTICE or permission unexpectedly elevated")
        require(source["referenceLinkReviewed"] is True
                and source["downloadAuthorized"] is False
                and source["mirrorAuthorized"] is False
                and source["mirrorRightsReviewed"] is False
                and type(source["noticeTreatment"]) is str
                and len(source["noticeTreatment"]) >= 100,
                "original review is not a distribution license")
    require(seen == set(EXACT_ASSETS), "provider scope differs from reviewed pilot")
    raw = (root / POLICY).read_bytes()
    return {
        "schemaVersion": SCHEMA,
        "sourceKind": SOURCE_KIND,
        "publisherEnvironment": ENVIRONMENT,
        "policySha256": hashlib.sha256(raw).hexdigest(),
        "formalAdmissionReady": False,
        "sourcePublisherAuthorized": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "status": "SOURCE_POLICY_REVIEW_ONLY_PUBLISH_DENY",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(inspect_policy(), sort_keys=True))
