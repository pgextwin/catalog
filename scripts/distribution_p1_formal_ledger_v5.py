#!/usr/bin/env python3
"""Issue 112 v5 immutable cross-attempt formal admission RECORD checker.

Never impersonate independent gh/TUF/Sigstore. Provenance is the original
protected-main read-only Run 38993139365, the SHA-pinned 85-file diagnostic
artifact and the exact four sha256-pinned genuine row receipts.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_formal_ledger_v4 import (
    validate as validate_v4, git_blob, V4, V3, PINS, FLEET, V4_GIT_BLOB
)
from distribution_p1_orafce_cross_attempt import (
    OBSERVED, OBSERVED_BLOB, PUB, PUBLISH_BLOB
)

ROOT = Path(__file__).resolve().parents[1]
V5 = ROOT / "evidence/p1/formal-acceptance-20261017-v5.json"
V5_GIT_BLOB = "d82e3f375b1e0836d52b7f6a8942497cedc9881b"
EXPECTED_AUDIT = json.loads("{\"runId\":38993139365,\"runUrl\":\"https://github.com/pgextwin/catalog/actions/runs/38993139365\",\"trustedMainVerifierCommit\":\"92d711c5c9d45b3cb39d6fa5b6de9742197cbae8\",\"runConclusion\":\"failure\",\"actualBatchExitCode\":2,\"diagnosticArtifactId\":12085967964,\"diagnosticArtifactSha256\":\"bb05e70aa7aab687be4f562aa6a867a7f5cc6d1d3f26ad7f57ded1abc505cbce\",\"summaryJsonSha256\":\"8ce904315db8ed8a16d9ea1cc56fddf3c8a05e652ff6be3b67ee47fa24698b1f\",\"orafceReleaseReceiptSha256\":\"172f63f5045f7e350aac3d82b33ed00dd82faf6581fb3c4afc361047ce60ea0f\",\"receiptJsonCount\":85,\"releaseFullOriginalByteReceipts\":14,\"all224AssetsRehashed\":true,\"all70PgZipCrcVerified\":true,\"all70SpdxGrypeStructured\":true,\"batchAlreadyAccepted\":6,\"batchPassCandidates\":59,\"batchDenied\":5,\"batchBlocked\":0,\"orafceGenuineTufAndDualSigstorePerRow\":true,\"originalReleaseAssetsNotReplacedWithActionsArtifact\":true,\"officialGhSha256\":\"7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b\",\"trustedRootSha256\":\"65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c\",\"crossAttemptObservationGitBlob\":\"1a2a3a17799aa72f31cede7150f2cfa1afe43956\",\"originalPublisherLogGitBlob\":\"591f05c75cf0a5aacbedcc2cd339822080e4ad5f\"}")
EXPECTED_ROWS = json.loads("[{\"extension\":\"orafce\",\"pgMajor\":14,\"repositoryId\":1413246504,\"releaseId\":409043426,\"assetId\":628346166,\"assetName\":\"orafce-VERSION_4_16_13-pg14-windows-x64.zip\",\"originalZipSha256\":\"1b49956b4f7b8e3b4f5264344bc0db38928559453ca67ccc184b7cfad9575039\",\"packagingSha\":\"9f10b9039abe8c909df1ed17133481f4d64da1e4\",\"signerSha\":\"43993b864e59bd35870e15c410ac13c85def8531\",\"runId\":38062983035,\"originalBuildAttempt\":1,\"originalRunAttempt1Conclusion\":\"failure\",\"originalBuildJobId\":114244899868,\"finalPublicationAttempt\":2,\"finalRunAttempt2Conclusion\":\"success\",\"finalPublishJobId\":114251123808,\"originalArtifactTransferSha256\":\"ce1b4f6a68ae2ec1438ab91323344afc8d293e56af2c5788fec11cab9104117f\",\"bundleSha256\":\"dab9d6b772ba2791e0737cb93f93bb82354ec83b30dd4dae751730476fdb3d11\",\"rowReceiptSha256\":\"5a53a6c560d16c0e2978f271b9a20aaaef021a922b310f4c0d1a8c47c66ba057\",\"profile\":\"strict-orafce-cross-attempt/v1\",\"workIndividualAuditRequired\":false},{\"extension\":\"orafce\",\"pgMajor\":15,\"repositoryId\":1413246504,\"releaseId\":409043426,\"assetId\":628346162,\"assetName\":\"orafce-VERSION_4_16_13-pg15-windows-x64.zip\",\"originalZipSha256\":\"1b945cf443cf70ab2b0353895613e3a3ee97ed23e37e0144cc113939c292b74a\",\"packagingSha\":\"9f10b9039abe8c909df1ed17133481f4d64da1e4\",\"signerSha\":\"43993b864e59bd35870e15c410ac13c85def8531\",\"runId\":38062983035,\"originalBuildAttempt\":1,\"originalRunAttempt1Conclusion\":\"failure\",\"originalBuildJobId\":114244899833,\"finalPublicationAttempt\":2,\"finalRunAttempt2Conclusion\":\"success\",\"finalPublishJobId\":114251123808,\"originalArtifactTransferSha256\":\"aea77542a92ac91a0a47c271c806aca97a925aa23a1985668df12514b15951c6\",\"bundleSha256\":\"09e46073e0aee745ac3e686cbabed72e9bbbd3fda8176460ff15cd34b28093c1\",\"rowReceiptSha256\":\"49720bc32b4e8a77315ac37fe97f259832061a8f83a2c2bb4de3387b81629a23\",\"profile\":\"strict-orafce-cross-attempt/v1\",\"workIndividualAuditRequired\":false},{\"extension\":\"orafce\",\"pgMajor\":16,\"repositoryId\":1413246504,\"releaseId\":409043426,\"assetId\":628346163,\"assetName\":\"orafce-VERSION_4_16_13-pg16-windows-x64.zip\",\"originalZipSha256\":\"a8b6f29b2fd5b7ad2598e74eb952c88e19549742e8c8361d57fdc00e877367e5\",\"packagingSha\":\"9f10b9039abe8c909df1ed17133481f4d64da1e4\",\"signerSha\":\"43993b864e59bd35870e15c410ac13c85def8531\",\"runId\":38062983035,\"originalBuildAttempt\":1,\"originalRunAttempt1Conclusion\":\"failure\",\"originalBuildJobId\":114244899844,\"finalPublicationAttempt\":2,\"finalRunAttempt2Conclusion\":\"success\",\"finalPublishJobId\":114251123808,\"originalArtifactTransferSha256\":\"f88447c5e9ed157792017c514b810aa1f07d8682dac0561dc46b6979429f1755\",\"bundleSha256\":\"4e48309a31c773b17f813948c99f8aae693a994445af783ad7b7b082d5615e7a\",\"rowReceiptSha256\":\"849033dc389adce997c3338abaa4d3ba4b470bdc88be13107319867f907828c8\",\"profile\":\"strict-orafce-cross-attempt/v1\",\"workIndividualAuditRequired\":false},{\"extension\":\"orafce\",\"pgMajor\":17,\"repositoryId\":1413246504,\"releaseId\":409043426,\"assetId\":628346158,\"assetName\":\"orafce-VERSION_4_16_13-pg17-windows-x64.zip\",\"originalZipSha256\":\"d16077ef8df2a3770bd36cb4ce1eb2bb884f11c6a70adca623583680bd5474aa\",\"packagingSha\":\"9f10b9039abe8c909df1ed17133481f4d64da1e4\",\"signerSha\":\"43993b864e59bd35870e15c410ac13c85def8531\",\"runId\":38062983035,\"originalBuildAttempt\":1,\"originalRunAttempt1Conclusion\":\"failure\",\"originalBuildJobId\":114244899848,\"finalPublicationAttempt\":2,\"finalRunAttempt2Conclusion\":\"success\",\"finalPublishJobId\":114251123808,\"originalArtifactTransferSha256\":\"f1e1930c7c7c0eb4e961ec75d9af124234e1c28922f63ac4956494b4ed9ae8f6\",\"bundleSha256\":\"c81cbd9fb91a158df2613e4ff65c23156828f0e326e12f2266b8bd82ff302700\",\"rowReceiptSha256\":\"18d021ec64d00e52e583deb10a3197172420db5aa9690a34685e181397edabcf\",\"profile\":\"strict-orafce-cross-attempt/v1\",\"workIndividualAuditRequired\":false}]")


def validate(raw: bytes, previous: bytes, pins: bytes, fleet: bytes) -> dict:
    require(git_blob(raw) == V5_GIT_BLOB and
            git_blob(previous) == V4_GIT_BLOB,
            "v5/v4 sealed ledger Git Blob differs")
    # Includes the full v3/v2 immutable validation chain and all 55 v4 rows.
    validate_v4(previous, V3.read_bytes(), pins, fleet)
    d, prior = strict_json(raw), strict_json(previous)
    require(type(d) is dict and set(d) == {
        "schema", "createdAt", "previousLedgerPath", "previousLedgerGitBlob",
        "previousFormalAccepted", "catalogImmutableCommit", "audit",
        "newAcceptedRows", "newAcceptedCount", "formalP1Accepted",
        "formalP1Total", "remainingDenied", "historicalSourceAccepted",
        "historicalSourceTotal", "plpgsqlCheckFailedOriginalRunUnwaived",
        "orafceOriginalAttempt1RunIsFailure",
        "orafceOriginalAttempt2PublishSuccess", "fleetComplete", "p1",
        "p2", "publicationAuthorized", "distributionAuthorized",
        "formalDistribution", "historicalSourceAcceptedRows", "note",
    }, "unexpected v5 keys / non-object formal record")
    expected = {
        "schema": "pgextwin-p1-formal-acceptance/v5",
        "createdAt": "2026-10-17",
        "previousLedgerPath": "evidence/p1/formal-acceptance-20261017-v4.json",
        "previousLedgerGitBlob": V4_GIT_BLOB,
        "previousFormalAccepted": 61,
        "catalogImmutableCommit": "e372e2c6a95adcf8227ea82d6253df3792b6f029",
        "newAcceptedCount": 4,
        "formalP1Accepted": 65,
        "formalP1Total": 70,
        "remainingDenied": 5,
        "historicalSourceAccepted": 0,
        "historicalSourceTotal": 40,
        "plpgsqlCheckFailedOriginalRunUnwaived": True,
        "orafceOriginalAttempt1RunIsFailure": True,
        "orafceOriginalAttempt2PublishSuccess": True,
        "fleetComplete": False, "p1": "BLOCKED", "p2": "NO-GO",
        "publicationAuthorized": False,
        "distributionAuthorized": False,
        "formalDistribution": "DENY",
        "historicalSourceAcceptedRows": [],
    }
    for key, value in expected.items():
        require(type(d[key]) is type(value) and d[key] == value,
                "false v5 admission/publication/source/attempt gate: " + key)
    require(d["audit"] == EXPECTED_AUDIT
            and d["newAcceptedRows"] == EXPECTED_ROWS,
            "v5 actual original audit/receipt or row evidence differs")
    require(type(d["note"]) is str and "Work個別監査不要" in d["note"],
            "Work exception substituted for actual verification")
    require(prior["formalP1Accepted"] == 61 and
            len(prior["newAcceptedRows"]) == 55,
            "previous formally admitted rows changed")
    existing = {(r["extension"], r["pgMajor"]) for r in
                strict_json(V3.read_bytes())["acceptedRows"] +
                prior["newAcceptedRows"]}
    require(len(existing) == 61, "v2/v3/v4 accepted rows overlap")

    require(git_blob(OBSERVED.read_bytes()) == OBSERVED_BLOB and
            git_blob(PUB.read_bytes()) == PUBLISH_BLOB,
            "original orafce publication/observation evidence unpinned")
    observed = strict_json(OBSERVED.read_bytes())
    publisher = strict_json(PUB.read_bytes())
    require(observed["runId"] == 38062983035
            and observed["attempt1"] == {
                "conclusion": "failure", "failedBuildMajor": 18,
                "publishSucceeded": False
            }
            and observed["attempt2"]["conclusion"] == "success"
            and observed["attempt2"]["publisherJobId"] == 114251123808
            and observed["publisherLogGitBlob"] == PUBLISH_BLOB
            and publisher["runId"] == observed["runId"]
            and publisher["runAttempt"] == 2
            and publisher["publishJobId"] == 114251123808,
            "orafce source original failed Run or successful publish altered")
    by_major = {r["pgMajor"]: r for r in observed["rows"]}
    require(set(by_major) == {14, 15, 16, 17}
            and len(observed["rows"]) == 4,
            "original strict cross-attempt PG scope differs")
    seen = set()
    for row in d["newAcceptedRows"]:
        key = (row["extension"], row["pgMajor"])
        pg = row["pgMajor"]
        require(type(pg) is int and key == ("orafce", pg)
                and pg in by_major and key not in existing and key not in seen,
                "duplicate / plpgsql_check / PG18 / unverified v5 row")
        seen.add(key)
        orig = by_major[pg]
        require(row["assetName"] == orig["originalZipName"]
                and row["assetId"] == orig["originalZipAssetId"]
                and row["originalZipSha256"] == orig["originalZipSha256"]
                and row["originalArtifactTransferSha256"] ==
                    orig["uploadedArtifactArchiveSha256"] ==
                    orig["publisherDownloadedArtifactSha256"]
                and row["originalBuildJobId"] == orig["buildJobId"]
                and row["originalBuildAttempt"] == orig["buildAttempt"] == 1
                and row["originalRunAttempt1Conclusion"] == "failure"
                and row["finalPublicationAttempt"] == 2
                and row["finalRunAttempt2Conclusion"] == "success"
                and row["finalPublishJobId"] == 114251123808
                and row["runId"] == 38062983035
                and row["packagingSha"] == observed["packagingSha"]
                and row["repositoryId"] == observed["repositoryId"]
                and row["releaseId"] == observed["releaseId"]
                and row["signerSha"] ==
                    "43993b864e59bd35870e15c410ac13c85def8531"
                and row["profile"] == "strict-orafce-cross-attempt/v1"
                and row["workIndividualAuditRequired"] is False,
                "original signed ZIP / upload transport / publication continuity denied")
    require(seen == {("orafce", pg) for pg in (14, 15, 16, 17)},
            "missing genuine new row")
    return {"decision": "V5_FORMAL_RECORD_INTEGRITY_VALID_NOT_A_CRYPTO_TEST",
            "accepted": 65, "addedGenuineRows": 4, "remainingDenied": 5,
            "historicalSourceAccepted": 0, "publicationAuthorized": False,
            "distributionAuthorized": False}


def main():
    try:
        result = validate(V5.read_bytes(), V4.read_bytes(),
                          PINS.read_bytes(), FLEET.read_bytes())
    except (Denied, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({"decision": "DENY", "reason": str(exc)[:240],
                          "publicationAuthorized": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
