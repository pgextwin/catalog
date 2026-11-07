#!/usr/bin/env python3
"""Read-only source-specific ORIGINAL_PROVIDER_GET_ONLY intake (Issue #112).

This validates proposed pins and evidence shapes, not owner approval, signed
Catalog admission, download permission, asset provenance or legal rights.
The authenticated GitHub GET and independent binary hash are external gates.
Do not consume this module's output as an authorization in the CLI/Publisher.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from external_admission_preflight import ROOT
from external_direct_link_review import EXACT_ASSETS, strict_read
from external_provider_release_identity import compare_exact_source

INTAKE = "config/issue112-pg-trickle-direct-get-intake-v1.json"
SCHEMA = "pgextwin-external-direct-get-intake/v1"
ROW_KEYS = {
    "sourceGroup", "providerType", "extension", "pgMajor",
    "targetEnvironment", "upstreamVersion", "sourceRepo", "repositoryId",
    "releaseId", "releaseTag", "assetId", "assetName", "originalProviderUrl",
    "originalBytes", "originalSha256", "licenseSpdx", "licenseUrl",
    "noticeTreatment", "dependencyTreatment", "runtimeEvidence",
    "sourcePublisherAuthorized", "downloadAuthorized", "mirrorAuthorized",
}
ROOT_KEYS = {
    "schemaVersion", "sourceKind", "intendedOperation", "reviewStatus",
    "authorizationIssuer", "independentSignedAdmission", "publicationAuthorized",
    "downloadAuthorized", "mirrorAuthorized", "redistributionAuthorized",
    "records",
}
RUNTIME_KEYS = {"repository", "runId", "runAttempt", "event",
                "headSha", "conclusion", "scope"}
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
EXTENSION = re.compile(r"[a-z][a-z0-9_]*\Z")
SAFE = re.compile(r"[A-Za-z0-9_.-]+\Z")


def require(ok, message):
    if not ok:
        raise ValueError("External direct GET intake DENY: " + message)


def validate_intake(doc):
    require(type(doc) is dict and set(doc) == ROOT_KEYS, "root shape")
    expected = {
        "schemaVersion": SCHEMA,
        "sourceKind": "EXTERNAL_GITHUB_RELEASE_ASSET",
        "intendedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
        "reviewStatus": "CANDIDATE_ONLY",
        "authorizationIssuer": "NONE",
        "independentSignedAdmission": False,
        "publicationAuthorized": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "redistributionAuthorized": False,
    }
    for key, value in expected.items():
        require(type(doc[key]) is type(value) and doc[key] == value,
                "unauthorized trust or operation: " + key)
    rows = doc["records"]
    require(type(rows) is list and 1 <= len(rows) <= 20, "invalid intake size")
    identities, filenames = set(), set()
    for row in rows:
        require(type(row) is dict and set(row) == ROW_KEYS, "source pin shape")
        for key in ("repositoryId", "releaseId", "assetId", "originalBytes"):
            require(type(row[key]) is int and row[key] > 0,
                    "invalid source numeric identity: " + key)
        for key in ("sourcePublisherAuthorized", "downloadAuthorized", "mirrorAuthorized"):
            require(row[key] is False, "unsigned permission: " + key)
        name = row["sourceRepo"]
        asset = row["assetName"]
        tag = row["releaseTag"]
        major = row["pgMajor"]
        require(type(name) is str and REPO.fullmatch(name) is not None
                and not name.lower().startswith("pgextwin/"),
                "unsafe or native source identity")
        require((name, row["releaseId"], row["assetId"]) not in EXACT_ASSETS,
                "held initial providers cannot be promoted by new intake")
        require(type(asset) is str and SAFE.fullmatch(asset) is not None
                and asset.lower().endswith(".zip")
                and type(tag) is str and SAFE.fullmatch(tag) is not None,
                "unsafe original ZIP or tag")
        require(type(row["sourceGroup"]) is str and row["sourceGroup"] == "external"
                and row["providerType"] in ("upstream-official", "community")
                and type(row["extension"]) is str
                and EXTENSION.fullmatch(row["extension"]) is not None
                and type(major) is str and major in ("14", "15", "16", "17", "18")
                and type(row["upstreamVersion"]) is str
                and 1 <= len(row["upstreamVersion"]) <= 64,
                "invalid source/target environment")
        require(type(row["targetEnvironment"]) is str
                and "Windows x64" in row["targetEnvironment"]
                and "PostgreSQL " + major in row["targetEnvironment"],
                "ambiguous PostgreSQL/Windows ABI target")
        require(type(row["originalSha256"]) is str
                and SHA64.fullmatch(row["originalSha256"]) is not None
                and row["originalBytes"] <= 64 * 1024 * 1024,
                "missing or oversized original byte pin")
        url = "https://github.com/" + name + "/releases/download/" + tag + "/" + asset
        require(row["originalProviderUrl"] == url, "forged provider URL")
        require(type(row["licenseSpdx"]) is str
                and len(row["licenseSpdx"]) >= 3
                and type(row["licenseUrl"]) is str
                and row["licenseUrl"].startswith("https://github.com/" + name + "/blob/")
                and row["licenseUrl"].endswith("/LICENSE")
                and type(row["noticeTreatment"]) is str
                and len(row["noticeTreatment"]) >= 60
                and type(row["dependencyTreatment"]) is str
                and len(row["dependencyTreatment"]) >= 60,
                "missing license/NOTICE/dependency review")
        runtime = row["runtimeEvidence"]
        require(type(runtime) is dict and set(runtime) == RUNTIME_KEYS,
                "invalid runtime evidence")
        require(runtime["repository"] == "pgextwin/catalog"
                and type(runtime["runId"]) is int and runtime["runId"] > 0
                and type(runtime["runAttempt"]) is int and runtime["runAttempt"] == 1
                and runtime["event"] == "push" and runtime["conclusion"] == "success"
                and type(runtime["headSha"]) is str
                and SHA40.fullmatch(runtime["headSha"]) is not None
                and type(runtime["scope"]) is str
                and "Windows" in runtime["scope"]
                and "PG" + major in runtime["scope"],
                "invalid claimed original Windows run")
        identity = (name.lower(), row["releaseId"], row["assetId"])
        dest = (row["extension"], major, asset.lower())
        require(identity not in identities and dest not in filenames,
                "duplicate provider identity or destination")
        identities.add(identity)
        filenames.add(dest)
    return rows


def inspect_intake(root=ROOT, document=None, snapshots=None):
    """Check locally declared candidate. API snapshots are caller-authenticated.

    Synthetic metadata comparison DOES NOT authenticate the snapshot or issue
    a permission; even an exact match always produces a denial receipt.
    """
    root = Path(root)
    doc = strict_read(root / INTAKE) if document is None else document
    rows = validate_intake(doc)
    matched = 0
    if snapshots is not None:
        require(type(snapshots) is dict and set(snapshots) ==
                {row["sourceRepo"] for row in rows}, "incomplete provider snapshots")
        for row in rows:
            item = snapshots[row["sourceRepo"]]
            require(type(item) is dict and set(item) == {"repository", "release"},
                    "invalid provider snapshot structure")
            proof = compare_exact_source(row, item["repository"], item["release"])
            require(proof["downloadAuthorized"] is False
                    and proof["mirrorAuthorized"] is False,
                    "provider metadata attempted trust elevation")
            matched += 1
    raw = (root / INTAKE).read_bytes() if document is None else None
    return {
        "schemaVersion": SCHEMA,
        "intendedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
        "sourceSpecificCandidates": len(rows),
        "metadataMatchesWithoutAuthenticatingSnapshots": matched,
        "intakeSha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
        "approvalIssuer": "NONE",
        "independentSigstoreAuthorizedPin": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "state": "CANDIDATE_ONLY_PUBLISH_DENY",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(inspect_intake(), sort_keys=True))
