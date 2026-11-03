#!/usr/bin/env python3
"""Issue #112 external Windows evidence preflight; metadata/read-only only.

The output is a *gap report*, never a downloadable pin, approval, signed
manifest, license opinion or cryptographic verification. The existing
Publisher and signed Catalog feed remain the only formal delivery paths.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REGISTRIES = (
    "external/windows-candidates-v1.json",
    "external/windows-candidates-portalcorp-v1.json",
)
PILOT = "evidence/issue112-external-original-byte-pilot-20261103.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def identity(obj):
    return (obj["sourceRepo"], obj["releaseId"], obj["assetId"])


def load_candidates(root=ROOT):
    output, ids = [], set()
    for name in REGISTRIES:
        registry = read_json(root / name)
        if (registry.get("schemaVersion") != "pgextwin-windows-source-candidates/v1"
                or registry.get("trust") != "UNVERIFIED_METADATA_ONLY"
                or registry.get("publicationAuthorized") is not False
                or registry.get("redistributionAuthorized") is not False):
            raise ValueError("Local discovery registry attempted trust elevation")
        for c in registry["candidates"]:
            key = identity(c)
            if key in ids:
                raise ValueError("Cross-registry duplicate asset identity")
            ids.add(key)
            if (c["sourceGroup"] != "external" or c["buildMethod"] != "external"
                    or c["verificationState"] != "metadata-only"
                    or c["downloadAuthorized"] is not False
                    or c["redistributionAuthorization"] != "not-authorized"
                    or c["originalSha256"] is not None
                    or c["rightsReviewed"] is not False
                    or c["provenanceVerified"] is not False
                    or c["compatibilityVerified"] is not False
                    or c["dependenciesVerified"] is not False):
                raise ValueError("Untrusted candidate cannot authorize download")
            output.append(c)
    return output


def pilot_index(pilot, candidates):
    if (pilot.get("schemaVersion") != "pgextwin-external-windows-byte-pilot/v1"
            or pilot.get("runId") != 41638680503 or pilot.get("runAttempt") != 1
            or not SHA40.fullmatch(pilot.get("sourceHead", ""))
            or any(pilot.get(k) is not False for k in (
                "signatureVerified", "provenanceVerified", "abiApproved",
                "licenseApproved", "downloadAuthorized", "mirrorAuthorized"))):
        raise ValueError("Unreviewed byte pilot trust envelope")
    by_id = {identity(c): c for c in candidates}
    index = {}
    for item in pilot["results"]:
        key = (item["provider"], item["releaseId"], item["assetId"])
        if key in index or key not in by_id:
            raise ValueError("Duplicate or out-of-scope original-byte pilot")
        c = by_id[key]
        if (c["extension"] != item["extension"]
                or c["upstreamVersion"] != item["upstreamVersion"]
                or c["pgMajor"] != item["pgMajor"]
                or not isinstance(item["bytes"], int) or item["bytes"] < 1
                or not isinstance(item["zipMembers"], int) or item["zipMembers"] < 1
                or not SHA256.fullmatch(item["sha256"])
                or item["result"] != "ORIGINAL_ZIP_SHA256_AND_CRC_PASS"):
            raise ValueError("Byte-pilot result mismatch with asset identity")
        api_digest = c["apiDigest"]
        if api_digest is not None and api_digest != "sha256:" + item["sha256"]:
            raise ValueError("Original bytes contradict GitHub API digest")
        index[key] = item["sha256"]
    return index


def preflight(candidates, pilot):
    pinned = pilot_index(pilot, candidates)
    evidence = []
    gaps = Counter()
    for c in sorted(candidates, key=identity):
        proof = pinned.get(identity(c))
        missing = []
        # Each provider's publication practices inform acceptable evidence.
        # Mandatory checks concern the *usable binary*, not whether the
        # upstream community produces pgextwin's own supply-chain artifacts.
        if proof is None:
            missing.append("independent_original_zip_byte_hash")
        # The metadata-only registry never establishes a reviewed provider
        # identity. Authenticated release/asset IDs plus verified original bytes
        # and a documented provider risk review MAY be sufficient; an upstream
        # Sigstore signature or build attestation is not universally mandatory.
        if not c["provenanceVerified"]:
            missing.append("reviewed_provider_release_origin")
        if not c["rightsReviewed"]:
            missing.append("license_and_applicable_notices_for_intended_use")
        if not c["compatibilityVerified"]:
            missing.append("exact_pg_distribution_arch_and_abi_runtime")
        if not c["dependenciesVerified"]:
            missing.append("runtime_dependency_closure")
        # These are pgextwin's OWN consumer trust/authorization gates, not
        # artifacts the external provider is required to manufacture.
        missing.extend(("authenticated_signed_catalog_pin",
                        "formal_pgextwin_download_authorization"))
        optional = []
        if not isinstance(c["sourceCommitSha"], str) or not SHA40.fullmatch(c["sourceCommitSha"]):
            optional.append("upstream_source_commit_if_available")
        # Never infer the presence or absence of an upstream signature/SBOM
        # from the untrusted discovery registry; assess these per provider.
        gaps.update(missing)
        evidence.append({
            "sourceRepo": c["sourceRepo"],
            "releaseId": c["releaseId"], "assetId": c["assetId"],
            "extension": c["extension"],
            "version": c["upstreamVersion"], "pgMajor": c["pgMajor"],
            "assetName": c["assetName"],
            "providerType": c["providerType"],
            "reportedOriginalBytePilotSha256": proof,
            "bytePilotScope": "BYTE_INTEGRITY_ONLY" if proof else "NO_ORIGINAL_BYTE_PROOF",
            "downloadAuthorized": False, "mirrorAuthorized": False,
            "missingGates": missing,
            "optionalProviderEvidenceToConsider": optional,
        })
    if not evidence:
        raise ValueError("Empty external registry is not accepted")
    return {
        "schemaVersion": "pgextwin-external-admission-preflight/v1",
        "trust": "UNTRUSTED_METADATA_EVIDENCE_ONLY",
        "publicationAuthorized": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "candidates": len(evidence),
        "bytePilotsLinked": len(pinned),
        "blockedCandidates": len(evidence),
        "providerEvidencePolicy": "PROPORTIONATE_NOT_PGEXTWIN_ARTIFACT_PARITY",
        "upstreamArtifactsNotUniversallyRequired": [
            "upstream_sigstore_attestation", "upstream_spdx_sbom",
            "upstream_grype_report", "upstream_reproducible_build_proof",
        ],
        "missingGatesCount": dict(sorted(gaps.items())),
        "records": evidence,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = preflight(load_candidates(), read_json(ROOT / PILOT))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "candidates": report["candidates"],
        "bytePilotsLinked": report["bytePilotsLinked"],
        "blockedCandidates": report["blockedCandidates"],
        "missingGatesCount": report["missingGatesCount"],
        "downloadAuthorized": False, "mirrorAuthorized": False
    }, sort_keys=True))


if __name__ == "__main__":
    main()
