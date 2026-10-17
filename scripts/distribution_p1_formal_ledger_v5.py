#!/usr/bin/env python3
"""Issue #112 immutable v5 formal intake RECORD verifier, never Sigstore substitute.

Actual cryptography ran in protected-main Run 38993139365, four original
orafce build attempt-1 rows verified with exact successful attempt-2 final
publication. The audit Run globally failed due to five other DENY rows.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_formal_ledger_v4 import (
    validate as validate_v4, git_blob, V4, V3, PINS, FLEET, V4_GIT_BLOB,
)
from distribution_p1_orafce_cross_attempt import (
    OBSERVED, OBSERVED_BLOB, PUB, PUBLISH_BLOB,
)

ROOT = Path(__file__).resolve().parents[1]
V5 = ROOT / "evidence/p1/formal-acceptance-20261017-v5.json"
V5_GIT_BLOB = "ed0c8b252c8123c4ef7a073965af332424d6a3e5"
ROW_PINS = {
  14: ("5a53a6c560d16c0e2978f271b9a20aaaef021a922b310f4c0d1a8c47c66ba057",
       "dab9d6b772ba2791e0737cb93f93bb82354ec83b30dd4dae751730476fdb3d11"),
  15: ("49720bc32b4e8a77315ac37fe97f259832061a8f83a2c2bb4de3387b81629a23",
       "09e46073e0aee745ac3e686cbabed72e9bbbd3fda8176460ff15cd34b28093c1"),
  16: ("849033dc389adce997c3338abaa4d3ba4b470bdc88be13107319867f907828c8",
       "4e48309a31c773b17f813948c99f8aae693a994445af783ad7b7b082d5615e7a"),
  17: ("18d021ec64d00e52e583deb10a3197172420db5aa9690a34685e181397edabcf",
       "c81cbd9fb91a158df2613e4ff65c23156828f0e326e12f2266b8bd82ff302700"),
}
ROW_FIELDS = {
    "extension","pgMajor","repositoryId","releaseId","assetId","assetName",
    "runId","buildAttempt","finalPublicationAttempt","publishJobId",
    "packagingSha","signerSha","releaseIdentitySha256","buildJobId",
    "zipSha256","artifactArchiveSha256","bundleSha256","rowReceiptSha256",
    "verificationOrigin","verificationProfile","originalBuildAttempt1RunConclusion",
    "originalBuildJobConclusion","finalPublicationAttempt2RunConclusion",
    "originalPublicationJobConclusion","integrityVerified","signatureVerified",
    "workIndividualAuditRequired",
}
AUDIT = {
  "runId":38993139365,
  "runUrl":"https://github.com/pgextwin/catalog/actions/runs/38993139365",
  "trustedMainVerifierCommit":"92d711c5c9d45b3cb39d6fa5b6de9742197cbae8",
  "artifactId":12085967964,
  "artifactSha256":"bb05e70aa7aab687be4f562aa6a867a7f5cc6d1d3f26ad7f57ded1abc505cbce",
  "summarySha256":"8ce904315db8ed8a16d9ea1cc56fddf3c8a05e652ff6be3b67ee47fa24698b1f",
  "orafceCommonReceiptSha256":"172f63f5045f7e350aac3d82b33ed00dd82faf6581fb3c4afc361047ce60ea0f",
  "originalPublicationLogBlob":"591f05c75cf0a5aacbedcc2cd339822080e4ad5f",
  "originalArtifactObservationBlob":"1a2a3a17799aa72f31cede7150f2cfa1afe43956",
  "officialGhSha256":"7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b",
  "trustedRootSha256":"65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c",
  "fourGenuineDualSigstoreProofs":True,
  "releaseOriginalAllAssetsAndCrc":True,
  "artifactIsDiagnosticOnly":True,
  "actualFleetRunFailedBecauseOtherFiveRemainDenied":True,
}


def validate(raw, previous, prev_v3, original_pins, fleet_raw):
    require(git_blob(raw) == V5_GIT_BLOB,
            "v5 formal record original Git Blob SHA changed")
    validate_v4(previous, prev_v3, original_pins, fleet_raw)
    require(git_blob(previous) == V4_GIT_BLOB,
            "sealed formal v4 acceptance cannot be changed")
    old, pins, fleet = (strict_json(previous), strict_json(original_pins),
                        strict_json(fleet_raw))
    doc = strict_json(raw)
    require(type(doc) is dict and set(doc) == {
        "schema","createdAt","previousLedgerPath","previousLedgerGitBlob",
        "catalogImmutableCommit","audit","previousAccepted","newAcceptedCount",
        "newAcceptedRows","formalP1Accepted","formalP1Total","remainingDenied",
        "historicalSourceAccepted","historicalSourceTotal",
        "historicalSourceAcceptedRows","failedPlpgsqlCheckPromotionRunUnwaived",
        "originalOrafceAttempt1FailureNotReclassified",
        "fleetComplete","p1","p2","publicationAuthorized",
        "distributionAuthorized","formalDistribution","note"},
        "unrecognized v5 formal acceptance fields")
    require(doc["schema"] == "pgextwin-p1-formal-acceptance/v5"
            and doc["createdAt"] == "2026-10-17"
            and doc["previousLedgerPath"] ==
                "evidence/p1/formal-acceptance-20261017-v4.json"
            and doc["previousLedgerGitBlob"] == V4_GIT_BLOB
            and doc["catalogImmutableCommit"] ==
                "e372e2c6a95adcf8227ea82d6253df3792b6f029"
            and doc["audit"] == AUDIT,
            "v5 original receipt/Run/GitHub trust evidence changed")
    require(git_blob(OBSERVED.read_bytes()) == OBSERVED_BLOB
            and git_blob(PUB.read_bytes()) == PUBLISH_BLOB,
            "original four PG proof input/archive substitution")
    observed = strict_json(OBSERVED.read_bytes())
    original = {x["pgMajor"]: x for x in observed["rows"]}
    pin = next(x for x in pins["items"] if x["name"] == "orafce")
    new = doc["newAcceptedRows"]
    require(type(new) is list and len(new) == 4
            and [x["pgMajor"] for x in new] == [14,15,16,17],
            "4 exact PG identity order or count changed")
    seen={(r["extension"],r["pgMajor"]) for r in old["newAcceptedRows"]}
    for r in new:
        require(type(r) is dict and set(r) == ROW_FIELDS,
                "incomplete or synthetic accepted cross-attempt row")
        pg = r["pgMajor"]
        orig=original[pg]
        receipt_sha,bundle_sha=ROW_PINS[pg]
        require((r["extension"],pg) not in seen,
                "cross-attempt formal accepted row double-counted")
        seen.add((r["extension"],pg))
        require(r["extension"] == "orafce"
                and r["repositoryId"] == pin["repositoryId"] == 1413246504
                and r["releaseId"] == pin["releaseId"] == 409043426
                and r["assetId"] == orig["originalZipAssetId"]
                and r["assetId"] == fleet["assetIds"]["orafce"][r["assetName"]]
                and r["assetName"] == orig["originalZipName"]
                and r["zipSha256"] == orig["originalZipSha256"]
                and r["artifactArchiveSha256"] ==
                   orig["uploadedArtifactArchiveSha256"]
                and r["packagingSha"] == pin["packagingSha"]
                and r["signerSha"] == pin["signerSha"]
                and r["runId"] == pin["runId"] == 38062983035
                and r["buildJobId"] == orig["buildJobId"]
                and r["buildAttempt"] == 1
                and r["finalPublicationAttempt"] == pin["runAttempt"] == 2
                and r["publishJobId"] == pin["publishJobId"] == 114251123808
                and r["releaseIdentitySha256"] ==
                   "c84db3083873cc5a830e37b5bbec978531e52dd295965a99c1cd4e85626659e0"
                and r["rowReceiptSha256"] == receipt_sha
                and r["bundleSha256"] == bundle_sha
                and r["verificationProfile"] == "strict-orafce-cross-attempt/v1"
                and r["verificationOrigin"] ==
                    "protected-main-original-release-and-real-Sigstore"
                and r["originalBuildAttempt1RunConclusion"] == "failure"
                and r["originalBuildJobConclusion"] == "success"
                and r["finalPublicationAttempt2RunConclusion"] == "success"
                and r["originalPublicationJobConclusion"] == "success"
                and r["integrityVerified"] is True
                and r["signatureVerified"] is True
                and r["workIndividualAuditRequired"] is False,
                "unproven original orafce PG/Run/Job/zip/dual-Sigstore admission")
    for k,value in (("previousAccepted",61), ("newAcceptedCount",4),
                    ("formalP1Accepted",65),("formalP1Total",70),
                    ("remainingDenied",5),("historicalSourceAccepted",0),
                    ("historicalSourceTotal",40),("fleetComplete",False),
                    ("p1","BLOCKED"),("p2","NO-GO"),
                    ("publicationAuthorized",False),("distributionAuthorized",False),
                    ("formalDistribution","DENY"),
                    ("failedPlpgsqlCheckPromotionRunUnwaived",True),
                    ("originalOrafceAttempt1FailureNotReclassified",True)):
        require(type(doc[k]) is type(value) and doc[k] == value,
                "wrong cross-attempt formal P1/source/publication count or gate: " + k)
    require(doc["historicalSourceAcceptedRows"] == [] and
            doc["historicalSourceAcceptedRows"] ==
               old["historicalSourceAcceptedRows"],
            "unproven new historical source acceptance")
    require(type(doc["note"]) is str and "failed" in doc["note"],
            "original failed Run cannot be silently waived")
    return {"decision":"V5_FORMAL_RECORD_VALID_NOT_SIGSTORE_TEST",
            "formalP1Accepted":65,"newRows":4,"remainingDenied":5,
            "historicalSourceAccepted":0, "publicationAuthorized":False,
            "distributionAuthorized":False}


def main():
    try:
        print(json.dumps(validate(V5.read_bytes(),V4.read_bytes(),V3.read_bytes(),
                                  PINS.read_bytes(),FLEET.read_bytes()),
                         sort_keys=True))
        return 0
    except (Denied,OSError,ValueError,KeyError,TypeError,AttributeError) as exc:
        print(json.dumps({"decision":"DENY", "reason":str(exc)[:240],
                          "publicationAuthorized":False}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
