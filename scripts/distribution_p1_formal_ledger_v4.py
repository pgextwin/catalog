#!/usr/bin/env python3
"""Issue #112: immutable v4 genuine historical formal intake RECORD checker.

This verifies a sealed, independently corroborated admission record, NOT a
fixture Sigstore check. The actual two signed predicates were checked by
protected-main Run 38984927984; their original row receipts are archived as
85 diagnostic JSON items bound to a SHA256-pinned GitHub Actions Artifact.
The action artifact is NEVER substituted for GitHub Release original bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_formal_ledger_v3 import validate as previous_validate

ROOT = Path(__file__).resolve().parents[1]
V4 = ROOT / "evidence/p1/formal-acceptance-20261017-v4.json"
V3 = ROOT / "evidence/p1/formal-acceptance-20261017-v3.json"
PINS = ROOT / "config/issue112-p1-historical-source-pins-20261017.json"
FLEET = ROOT / "config/issue112-p1-fleet-pins-20261017.json"

V4_GIT_BLOB = "ef8f4ec0214631523b449c7539329eb636f6d730"
V3_GIT_BLOB = "d26b3db5ce497200cfaadf793851653c7c582df6"
PINS_GIT_BLOB = "c04a8c34688265cfd598fe99c399aa032321ed61"
AUDIT_COMMIT = "2330d9027f33c7ab3317e382539725feda285a1e"
AUDIT_ARTIFACT_SHA = "071cf1c7d41338382546ba61ad6cbc63ac58af4285dcf7bad2fcebc044bb897c"
AUDIT_SUMMARY_SHA = "4025b7c773e194b42f4b3b65fb8b2d0ebf5c54810c8b7abbb1707c5e57fe0abe"
ROOT_SHA = "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"
GH_SHA = "7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b"
SHA64 = re.compile(r"[a-f0-9]{64}\Z")


def git_blob(data: bytes) -> str:
    require(type(data) is bytes and len(data) <= 1024 * 1024,
            "oversized immutable admission record")
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii")
                        + b"\x00" + data).hexdigest()


def validate(raw: bytes, previous: bytes, pins_raw: bytes, fleet_raw: bytes) -> dict:
    require(git_blob(raw) == V4_GIT_BLOB
            and git_blob(previous) == V3_GIT_BLOB
            and git_blob(pins_raw) == PINS_GIT_BLOB,
            "v4/v3/immutable historical evidence Git Blob changed")
    previous_validate(previous)
    d, v3, pins, fleet = (strict_json(x) for x in
                          (raw, previous, pins_raw, fleet_raw))
    require(type(d) is dict and type(v3) is dict and type(pins) is dict
            and type(fleet) is dict, "record must be a JSON object")
    require(set(d) == {
        "schema", "createdAt", "previousLedgerPath", "previousLedgerGitBlob",
        "previousFormalAccepted", "historicalSourceAccepted",
        "historicalSourceTotal", "catalogImmutableCommit",
        "originalHistoricalProfileGitBlob", "audit", "newAcceptedRows",
        "newAcceptedCount", "formalP1Accepted", "formalP1Total",
        "remainingDenied", "plpgsqlCheckFailedOriginalRunUnwaived",
        "orafceMixedAttemptPG14to17Denied", "fleetComplete", "p1", "p2",
        "publicationAuthorized", "distributionAuthorized",
        "formalDistribution", "historicalSourceAcceptedRows", "note",
    }, "unexpected formal v4 record keys")
    for key, value in (
        ("schema", "pgextwin-p1-formal-acceptance/v4"),
        ("createdAt", "2026-10-17"),
        ("previousLedgerPath", "evidence/p1/formal-acceptance-20261017-v3.json"),
        ("previousLedgerGitBlob", V3_GIT_BLOB),
        ("previousFormalAccepted", 6),
        ("catalogImmutableCommit", fleet["catalogCommitSha"]),
        ("originalHistoricalProfileGitBlob", PINS_GIT_BLOB),
        ("newAcceptedCount", 55),
        ("formalP1Accepted", 61),
        ("formalP1Total", 70),
        ("remainingDenied", 9),
        ("historicalSourceAccepted", 0),
        ("historicalSourceTotal", 40),
        ("plpgsqlCheckFailedOriginalRunUnwaived", True),
        ("orafceMixedAttemptPG14to17Denied", True),
        ("fleetComplete", False), ("p1", "BLOCKED"), ("p2", "NO-GO"),
        ("publicationAuthorized", False), ("distributionAuthorized", False),
        ("formalDistribution", "DENY"),
    ):
        require(type(d.get(key)) is type(value) and d[key] == value,
                "false v4 formal source/Run/acceptance/publication gate: " + key)
    require(v3["formalP1Accepted"] == 6 and
            len(v3["acceptedRows"]) == 6 and
            d["historicalSourceAcceptedRows"] == v3["historicalSourceAcceptedRows"] == [] and
            type(d["note"]) is str and "Work個別監査不要" in d["note"],
            "v3 sealed history or source ledger modified")

    proof = d["audit"]
    require(type(proof) is dict and
            set(proof) == {
                "runId", "runUrl", "trustedMainVerifierCommit",
                "diagnosticArtifactId", "diagnosticArtifactSha256",
                "summaryJsonSha256", "releaseFullOriginalByteReceipts",
                "allOriginalAssetsRehashed", "allPgZipCrcVerified",
                "allSpdxGrypeStructured", "genuineTufAndDualSigstorePerNewRow",
                "verificationExecutableSha256", "trustedRootSha256",
                "bundleAndOriginalJobDetailsInIndividuallyHashedRowReceipts",
                "actionsArtifactIsNotOriginalReleaseBytes",
            } and
            proof["runId"] == 38984927984 and
            proof["runUrl"] ==
                "https://github.com/pgextwin/catalog/actions/runs/38984927984" and
            proof["trustedMainVerifierCommit"] == AUDIT_COMMIT and
            proof["diagnosticArtifactId"] == 12082613192 and
            proof["diagnosticArtifactSha256"] == AUDIT_ARTIFACT_SHA and
            proof["summaryJsonSha256"] == AUDIT_SUMMARY_SHA and
            proof["releaseFullOriginalByteReceipts"] == 14 and
            proof["verificationExecutableSha256"] == GH_SHA and
            proof["trustedRootSha256"] == ROOT_SHA and
            all(type(proof[k]) is bool and proof[k] is True for k in (
                "allOriginalAssetsRehashed", "allPgZipCrcVerified",
                "allSpdxGrypeStructured", "genuineTufAndDualSigstorePerNewRow",
                "bundleAndOriginalJobDetailsInIndividuallyHashedRowReceipts",
                "actionsArtifactIsNotOriginalReleaseBytes")),
            "genuine trusted-main run and original-Asset trust boundary changed")

    rows = d["newAcceptedRows"]
    require(type(rows) is list and len(rows) == 55,
            "incorrect 55 individual verified row receipts")
    historic = pins["items"]
    require(type(historic) is list and len(historic) == 12
            and len({x["name"] for x in historic}) == 12,
            "original historical profile incomplete")
    p_by_name = {x["name"]: x for x in historic}
    expected = {(x["name"], major) for x in historic
                for major in (14, 15, 16, 17, 18)}
    expected -= {("pg_bigm", 14)}
    expected -= {("orafce", major) for major in (14, 15, 16, 17)}
    require(len(expected) == 55, "historical lane overlap")
    old_keys = {(x["extension"], x["pgMajor"]) for x in v3["acceptedRows"]}
    require(expected.isdisjoint(old_keys), "v3 admitted row recounted")
    seen = set()
    for row in rows:
        require(type(row) is dict and set(row) == {
            "extension", "pgMajor", "repositoryId", "releaseId",
            "assetId", "assetName", "packagingSha", "runId",
            "runAttempt", "signerSha", "buildJobId", "publicationJobId",
            "rowReceiptSha256", "profile", "workIndividualAuditRequired",
        }, "row evidence missing or schema drift")
        name, major = row["extension"], row["pgMajor"]
        require(type(major) is int and (name, major) in expected
                and (name, major) not in seen, "forged, denied or duplicate row")
        seen.add((name, major))
        p = p_by_name[name]
        asset = row["assetName"]
        require(type(asset) is str
                and asset.endswith(f"-pg{major}-windows-x64.zip")
                and fleet["assetIds"][name].get(asset) == row["assetId"]
                and type(row["assetId"]) is int and row["assetId"] > 0
                and row["repositoryId"] == p["repositoryId"]
                and row["releaseId"] == p["releaseId"]
                and row["packagingSha"] == p["packagingSha"]
                and row["runId"] == p["runId"]
                and row["runAttempt"] == p["runAttempt"]
                and row["signerSha"] == p["signerSha"]
                and row["buildJobId"] == p["pgBuildJobIds"][str(major)]
                and row["publicationJobId"] == p["publishJobId"]
                and row["profile"] == "historical/windows.yml/push/v1"
                and row["workIndividualAuditRequired"] is False
                and type(row["rowReceiptSha256"]) is str
                and SHA64.fullmatch(row["rowReceiptSha256"]),
                "unverified original historical Release/Run/asset/job/receipt pin")
    require(seen == expected, "historical verified row missing")
    return {"decision": "V4_FORMAL_RECORD_INTEGRITY_VALID_NOT_A_CRYPTO_TEST",
            "accepted": 61, "addedGenuineRows": 55, "remainingDenied": 9,
            "historicalSourceAccepted": 0, "publicationAuthorized": False,
            "distributionAuthorized": False}


def main():
    try:
        result = validate(V4.read_bytes(), V3.read_bytes(), PINS.read_bytes(),
                          FLEET.read_bytes())
    except (Denied, OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        print(json.dumps({"decision": "DENY",
                          "reason": str(exc)[:240],
                          "publicationAuthorized": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
