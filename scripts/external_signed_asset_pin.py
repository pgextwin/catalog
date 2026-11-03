#!/usr/bin/env python3
"""Nonpublishing, source-aware exact external Catalog pin candidates for #112.

Only the protected-main GitHub Actions workflow may attest the output.
Neither this script nor a valid Sigstore attestation authorizes download,
mirroring, installation, or a source-specific Publisher operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from external_admission_preflight import ROOT
from external_direct_link_review import REVIEW, strict_read, validate_review
from external_formal_publisher_policy import inspect_policy

SHA40 = re.compile(r"[0-9a-f]{40}\Z")


def build_candidate(root=ROOT, commit=None, review=None):
    root = Path(root)
    if not isinstance(commit, str) or not SHA40.fullmatch(commit):
        raise ValueError("Exact 40-byte protected Catalog commit required")
    raw = (root / REVIEW).read_bytes()
    doc = strict_read(root / REVIEW) if review is None else review
    result = validate_review(root, doc)
    if (result != {
        "referenceLinksReviewed": 2, "signedExternalCatalogPins": 0,
        "downloadAuthorized": False, "mirrorAuthorized": False,
        "scope": "CANDIDATE_ONLY",
    }):
        raise ValueError("Unexpected pre-signature source review")
    if doc["evidenceCatalogCommit"] != "30929a791f7926c078034cc891a99244bffa9e4d":
        raise ValueError("Reviewed Catalog evidence lineage changed")
    # Bind the candidate to the protected, deny-only source-kind policy.
    # This is NOT permission to use the inherited native Publisher App/Environment.
    source_policy = inspect_policy(root, review=doc)
    records = []
    for row in sorted(doc["records"], key=lambda x: (
            x["sourceRepo"], x["releaseId"], x["assetId"])):
        records.append({
            "sourceGroup": "external",
            "extension": row["extension"],
            "upstreamVersion": row["upstreamVersion"],
            "pgMajor": row["pgMajor"],
            "targetEnvironment": row["targetEnvironment"],
            "providerType": row["providerType"],
            "sourceRepo": row["sourceRepo"],
            "repositoryId": row["repositoryId"],
            "releaseId": row["releaseId"],
            "releaseTag": row["releaseTag"],
            "assetId": row["assetId"],
            "assetName": row["assetName"],
            "originalProviderUrl": row["originalProviderUrl"],
            "originalBytes": row["originalBytes"],
            "originalSha256": row["originalSha256"],
            "licenseUrl": row["packageLicenseUrl"],
            "dependencyInformationUrl": row["dependencyInformationUrl"],
            "dependencyLicenseUrl": row["dependencyLicenseUrl"],
            "noticeTreatment": row["noticeTreatment"],
            "providerStatusNotice": row["providerStatusNotice"],
            "runtimeEvidence": row["runtimeEvidence"],
            "runtimeScope": row["runtimeScope"],
            "referenceLinkReviewed": True,
            "originalBinarySignatureVerified": False,
            "sourcePublisherAuthorized": False,
            "downloadAuthorized": False,
            "mirrorAuthorized": False,
        })
    if len(records) != 2:
        raise ValueError("Only two original-provider PG18 pilots permitted")
    return {
        "schemaVersion": "pgextwin-external-catalog-asset-pin-candidate/v1",
        "repository": "pgextwin/catalog",
        "catalogCommit": commit,
        "reviewEvidenceCommit": doc["evidenceCatalogCommit"],
        "reviewEvidenceSha256": hashlib.sha256(raw).hexdigest(),
        "source": "PROTECTED_CATALOG_MAIN_REVIEW",
        "purpose": "SOURCE_AWARE_EXACT_ORIGINAL_ASSET_PIN_NONPUBLISHING",
        "originalProviderAssets": len(records),
        "discoveryCandidates": 203,
        "downloadDeniedCandidates": 203,
        "originalBinarySignatureVerified": False,
        "publicationAuthorized": False,
        "sourcePublisherAuthorized": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "installAuthorized": False,
        "sourceSpecificPublisherPolicy": source_policy,
        "records": records,
    }


def canonical_bytes(data):
    return (json.dumps(data, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = canonical_bytes(build_candidate(args.catalog, args.commit))
    # Create-only. Never overwrite or upload to a public Release.
    with args.output.open("xb") as file:
        file.write(data)
    print(f"EXTERNAL_PIN_CANDIDATE_BYTES={len(data)} "
          f"SHA256={hashlib.sha256(data).hexdigest()} "
          "SIGNED=false DOWNLOAD_DENY=203 MIRROR_DENY=203 PUBLISH_DENY")


if __name__ == "__main__":
    main()
