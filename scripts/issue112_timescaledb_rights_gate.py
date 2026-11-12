#!/usr/bin/env python3
"""Fail-closed, offline TimescaleDB rights/provenance intake contract.

This only checks the immutable *description* of reviewed candidate evidence.
It never fetches assets, signs, approves a provider or publishes a ZIP.
A PASS here is categorically NOT a publication authorization.
"""
import argparse
from datetime import datetime
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = "external/timescaledb-rights-provenance-intake-v1.json"
BASELINE_PATH = "external/timescaledb-release-watch-baseline-v1.json"
SCHEMA = "pgextwin-issue112-timescaledb-rights-provenance/v1"
DOCS = {
    "LICENSE": "6b7980745c9892ba0d79368acab331dea2246ac2",
    "LICENSE-APACHE": "f433b1a53f5b830a205fd2df78e2b34974656c7b",
    "NOTICE": "a47a53c48d921bef9023e41e8def002d45465a7d",
    "tsl/LICENSE-TIMESCALE": "e92b2d902723571c921cfe59b841e6d7ab40f30d",
}
OPEN_GATES = {
    "exactBinaryComponentToLicenseMapping",
    "bundledLicenseNoticeCompleteness",
    "runtimeAndBundledDependencyClosure",
    "upstreamReleaseSourceToBinaryProvenance",
    "producerAuthorizationForPgextwinDelivery",
}
PERMISSION_KEYS = {"publicGet", "mirror", "release", "publish"}


def strict_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise ValueError("Missing, symlinked or oversized intake")
    def reject_duplicates(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError("Duplicate JSON key: " + k)
            obj[k] = v
        return obj
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def validate(ledger, baseline):
    if type(ledger) is not dict or set(ledger) != {
        "schemaVersion", "scope", "upstream", "sourceLicenseScopes",
        "licenseReview", "windowsAssets", "evidence", "permissions",
        "originalZipInventory", "releasePipelineObservation",
    }:
        raise ValueError("Unknown TimescaleDB rights-intake schema")
    if (ledger["schemaVersion"] != SCHEMA or
        ledger["scope"] != "CANDIDATE_ONLY_NONPUBLISHING"):
        raise ValueError("Unexpected rights-intake scope")
    up = ledger["upstream"]
    if (type(up) is not dict or set(up) != {"repository", "tag", "releaseId", "documents"} or
        up["repository"] != "timescale/timescaledb" or
        up["tag"] != "2.31.0" or up["releaseId"] != 418582851 or
        up["documents"] != DOCS):
        raise ValueError("Upstream tag, release, or source-license documents drifted")
    if ledger["sourceLicenseScopes"] != [
        {"pathScope": "outside tsl/",
         "licenseObservation": "Apache-2.0-or-compatible-unless-file-says-otherwise",
         "binaryAttribution": "UNVERIFIED"},
        {"pathScope": "tsl/",
         "licenseObservation": "Timescale-License-unless-file-says-otherwise",
         "binaryAttribution": "UNVERIFIED"},
    ]:
        raise ValueError("Incorrect source-vs-binary rights attribution")
    legal = ledger["licenseReview"]
    if (type(legal) is not dict or set(legal) != {
        "timescaleClauses", "unmodifiedStandaloneDistributionMayBePermitted",
        "specificUseAndTermsCleared", "allThirdPartyNoticesCleared",
    } or legal["timescaleClauses"] != ["2.1(c)", "2.2"] or
        legal["unmodifiedStandaloneDistributionMayBePermitted"] is not True or
        legal["specificUseAndTermsCleared"] is not False or
        legal["allThirdPartyNoticesCleared"] is not False):
        raise ValueError("Unsubstantiated Timescale License clearance")
    if (type(baseline) is not dict or
        baseline.get("sourceRepo") != "timescale/timescaledb" or
        baseline.get("releaseTag") != "2.31.0" or
        baseline.get("releaseId") != 418582851 or
        any(baseline.get(k) is not False for k in (
            "downloadAuthorized", "publicationAuthorized", "redistributionAuthorized"))):
        raise ValueError("Existing strict source baseline is not DENY")
    assets, expected = ledger["windowsAssets"], baseline.get("records")
    if (type(assets) is not list or type(expected) is not list or len(assets) != 3 or len(expected) != 3):
        raise ValueError("Expected exactly three original Windows ZIPs")
    for major, row, prev in zip(("16", "17", "18"), assets, expected):
        if type(row) is not dict or set(row) != {
            "pgMajor", "assetId", "assetName", "originalSha256", "originalBytes",
        } or type(prev) is not dict:
            raise ValueError("Unexpected Windows original asset entry")
        if (row["pgMajor"] != major or prev.get("pgMajor") != major or
            row["assetId"] != prev.get("assetId") or
            row["assetName"] != prev.get("assetName") or
            row["originalSha256"] != prev.get("apiSha256") or
            row["originalBytes"] != prev.get("apiBytes") or
            not isinstance(row["originalSha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", row["originalSha256"])):
            raise ValueError("Original Windows ZIP pins deviate from prior baseline")

    # Public upstream release metadata establishes asset identity and timing,
    # NOT the delegated (mutable @main) producer build or signed digest provenance.
    pipeline = ledger["releasePipelineObservation"]
    expected_pipeline = {
    "tagCommitSha": "4fa2a7c6b579171a1a8966fd87a0d4189ebab43b",
    "releaseWorkflowGitBlob": "f9cab87e5116a23f0b116690b8b3598e8c598a71",
    "delegatedBuildWorkflow": "timescale/release-build-scripts/.github/workflows/timescaledb-windows.yml@main",
    "delegatedBuildWorkflowRefPinned": False,
    "delegatedBuildWorkflowSourceRetrieved": False,
    "releasePublishedAt": "2026-10-20T16:06:02Z",
    "assetCreatedAtUtc": {
        "16": "2026-10-20T16:02:37Z",
        "17": "2026-10-20T16:05:28Z",
        "18": "2026-10-20T16:03:22Z"
    },
    "postPublishWindowsQa": {
        "runId": 39454913531,
        "event": "workflow_dispatch",
        "headSha": "4fa2a7c6b579171a1a8966fd87a0d4189ebab43b",
        "startedAt": "2026-10-20T16:09:19Z",
        "conclusion": "success",
        "producerRunEvidence": False
    },
    "exactProducerRunToZipShaBindingVerified": False
}
    if pipeline != expected_pipeline:
        raise ValueError("Upstream release / QA observation drift or forged producer proof")
    if not (max(datetime.fromisoformat(t.replace("Z", "+00:00"))
                for t in pipeline["assetCreatedAtUtc"].values())
            < datetime.fromisoformat(pipeline["releasePublishedAt"].replace("Z", "+00:00"))
            < datetime.fromisoformat(pipeline["postPublishWindowsQa"]["startedAt"].replace("Z", "+00:00"))):
        raise ValueError("Post-release QA cannot precede release assets")

    # Observed in a genuine prior successful CI Run; existing immutable log,
    # not a new retrieval or a producer/source-to-binary attestation.
    inventory = ledger["originalZipInventory"]
    if type(inventory) is not dict or set(inventory) != {
        "source", "runId", "sourceRef", "observationLimit", "rows",
        "licenseNoticeBundlingVerified", "producerBuildFlagsVerified",
    } or inventory["source"] != "EXISTING_GENUINE_ORIGINAL_REHASH_CI_LOGS_ONLY" or (
        inventory["runId"] != 43116446694 or
        inventory["sourceRef"] != "pgextwin/catalog" or
        inventory["observationLimit"] !=
            "ZIP_METADATA_FILENAME_REGEX_ONLY_NOT_SETUP_EXE_EMBEDDED_CONTENT" or
        inventory["licenseNoticeBundlingVerified"] is not False or
        inventory["producerBuildFlagsVerified"] is not False
    ):
        raise ValueError("Unverified archived original ZIP component inventory")
    expected_inventory = [
        ("16", 130845554299, 33783221),
        ("17", 130845554217, 33783221),
        ("18", 130845553821, 33785269),
    ]
    if type(inventory["rows"]) is not list or len(inventory["rows"]) != 3:
        raise ValueError("Incomplete genuine source ZIP inventories")
    for observed, (major, job, expanded_bytes) in zip(
            inventory["rows"], expected_inventory):
        if (type(observed) is not dict or set(observed) != {
            "pgMajor", "jobId", "members", "dllMembers",
            "declaredUncompressedBytes", "potentialNoticePaths",
        } or observed["pgMajor"] != major or observed["jobId"] != job or
            observed["members"] != 77 or observed["dllMembers"] != 3 or
            observed["declaredUncompressedBytes"] != expanded_bytes or
            observed["potentialNoticePaths"] != []):
            raise ValueError("Original CI ZIP metadata/notice-path receipt drift")
    # No filename match does not prove no notices embedded in setup.exe or
    # documents under unrelated filenames, and NEVER grants rights clearance.
    evidence = ledger["evidence"]
    if (type(evidence) is not dict or set(evidence) !=
        OPEN_GATES | {"originalZipIndependentRehash", "windowsPostgresqlSqlPg16Pg17Pg18",
                      "newSourceSpecificOwnerSignedAdmission"} or
        any(evidence[key] != "UNVERIFIED" for key in OPEN_GATES) or
        evidence["originalZipIndependentRehash"] != "PASS" or
        evidence["windowsPostgresqlSqlPg16Pg17Pg18"] != "PASS" or
        evidence["newSourceSpecificOwnerSignedAdmission"] != "MISSING"):
        raise ValueError("Incomplete legal/provenance gates are not approved")
    permissions = ledger["permissions"]
    if (type(permissions) is not dict or set(permissions) != PERMISSION_KEYS or
        any(value is not False for value in permissions.values())):
        raise ValueError("Candidate-only origin must remain publication DENY")
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=ROOT)
    opts = p.parse_args()
    validate(strict_json(opts.root / LEDGER_PATH),
             strict_json(opts.root / BASELINE_PATH))
    print("TIMESCALEDB_RIGHTS_INTAKE=PASS CANDIDATE_ONLY "
          "LEGAL_AND_PROVENANCE=UNVERIFIED PUBLIC_GET=DENY "
          "MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
