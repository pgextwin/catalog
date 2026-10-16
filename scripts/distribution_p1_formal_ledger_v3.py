#!/usr/bin/env python3
"""Issue #112: read-only v3 acceptance ledger integrity, NOT Sigstore verifier.

Formal admission was based on actual protected-main original-Release and
Sigstore execution, not on this standalone fixture validator. This script
checks immutable identities and ledger monotonicity only. It NEVER replaces
the archived genuine Run or performs synthetic signature verification.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_formal_ledger_v2 import validate as validate_previous, BASELINE

ROOT = Path(__file__).resolve().parents[1]
PREVIOUS = ROOT / "evidence/p1/formal-acceptance-20261017-v2.json"
LEDGER = ROOT / "evidence/p1/formal-acceptance-20261017-v3.json"
RUN_SHA = "0ac13f66b76c230ec68944aa96572486545cf5bb"
SOURCE_SHA = "1198ff30137ee3fd01a9e168647a7167324bb713"
SIGNER_SHA = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
ORIGINAL_RELEASE_ID = 410447206
ROOT_SHA = "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"
GH_SHA = "7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b"
OUTER_SHA = "59e2ab4338ba0c75a3b9406b6288dd7e2b58ae777be1bb0c1899c738d59aea5d"
COMMON_SHA = "44d091a754e10049a280247bf5c1be1028e7e27286fdf82b19147ee3e5fe11f2"
SUM_SHA = "1ba85e6b0ba251f7db48fdc4e4447599ca9ac47f22212afa0337bc66abafed2a"
IDENTITY_SHA = "7c2e3d0bb122e14997444ce6c95e67969cbd6fb1c378ea850bcc379f1cfa6a88"
PINS = {
    14: (633345001, 114748851610,
         "08d96ced687258193b0725767056467b17c3e7f7f2a750c76f44379d0ada42a6",
         "6e4f549c4c43e1695ea400bd045d412b4bec54e13b8be1dd6bdd257d0e7a26b0",
         "56d79eb13bb91f42a424633fcc29f743ad7f82e824f7c211526a508de3a3d82a"),
    15: (633345012, 114748851643,
         "7e01b94c13ba7dc931738753c24fc6a390903d9bbfee0adfa5dd9ed46d49bdd5",
         "fb11e93550a6e413dab55d9688fb64017e0a0ca63bdd4e009d125176b00548f2",
         "68068ef2495cafd9118ed7ebe0c1459ef80bd4981bb2539e4e462dfac57e9808"),
    16: (633345023, 114748851645,
         "8bf4bf45cd4b6b6e98ab528e1aaf6807782bdf6afa0fac06bc8c86246490a714",
         "3d13ec8d8797f5808d896f5b28b0a8a069fa4e183d57acb5b84bd98ca4409545",
         "b6dd726d61d53b6718e32a9903d4f3a454649ce98756a8cf3e18df72d2a6e1e8"),
    17: (633345034, 114748851652,
         "3a6185dff62119a181236e711a816da09c2844daa1844767578ecd95b938e622",
         "933de356db8b40faccdcef183863a6e2b6a8864a4353ffc311db65e644259515",
         "1eb9de209a24306a2bbf313a8d82aeebc9b74232135a3ed6994810e153229b46"),
    18: (633345056, 114748851641,
         "a8d4d19dfba11859823469ecab4ba53c89e7a24caff99a15b652eda475164fff",
         "bd06bc2755c6ef7ebbde4ddcb04cf5e908c7a01ed8336dd869a4ea77cb6afc56",
         "6c78567d8334b3a9588e90afb3c073e92450a958776ba3d39dd38866e96c7fb1"),
}

def validate(raw, previous_raw):
    require(type(raw) is bytes and 0 < len(raw) <= 32768,
            "invalid v3 formal record byte size")
    previous = strict_json(previous_raw)
    validate_previous(previous_raw)  # Do not modify or backdate sealed 1/70.
    d = strict_json(raw)
    require(type(d) is dict and set(d) == {
        "schema", "createdAt", "previousLedger", "previousLedgerSource",
        "catalogEvidenceCommit", "acceptedRows", "historicalSourceAcceptedRows",
        "formalP1Accepted", "formalP1Total", "historicalSourceAccepted",
        "historicalSourceTotal", "unacceptedRows", "p1", "p2", "fleetComplete",
        "publicationAuthorized", "distributionAuthorized", "formalDistribution", "note"},
        "unexpected v3 ledger keys")
    require(d["schema"] == "pgextwin-p1-formal-acceptance/v3"
            and d["createdAt"] == "2026-10-17"
            and d["previousLedger"] == "evidence/p1/formal-acceptance-20261017-v2.json"
            and d["previousLedgerSource"] == previous["priorAdmissionSource"]
            and d["catalogEvidenceCommit"] ==
                "e372e2c6a95adcf8227ea82d6253df3792b6f029",
            "v3 references do not match immutable prior acceptance")
    rows = d["acceptedRows"]
    require(type(rows) is list and len(rows) == 6
            and rows[0] == BASELINE and type(rows[0]) is dict,
            "original historical PG14 baseline altered or extra admitted rows")
    keys = set()
    for r, major in zip(rows[1:], sorted(PINS)):
        require(type(r) is dict and
                set(r) == {"extension", "pgMajor", "repositoryId", "releaseId",
                           "releaseTag", "packagingSha", "runId", "runAttempt",
                           "publisherJobId", "signerSha", "trustedRootSha256",
                           "officialGhSha256", "releaseIdentitySha256", "assetId",
                           "assetName", "originalZipSha256", "buildJobId",
                           "bundleSha256", "rowReceiptSha256", "verificationOrigin",
                           "profile", "integrityVerified", "signatureVerified",
                           "sourceVerified", "runAndJobsVerified",
                           "workIndividualAuditRequired", "evidence"},
                "unexpected/missing accepted row evidence fields")
        asset_id, build_job, receipt_sha, original_sha, bundle_sha = PINS[major]
        require(r["extension"] == "wal2json"
                and type(r["pgMajor"]) is int and r["pgMajor"] == major
                and r["repositoryId"] == 1412861698
                and r["releaseId"] == ORIGINAL_RELEASE_ID
                and r["releaseTag"] == "v2.7-windows.1"
                and r["packagingSha"] == SOURCE_SHA
                and r["runId"] == 38230537748 and r["runAttempt"] == 1
                and r["publisherJobId"] == 114753316427
                and r["signerSha"] == SIGNER_SHA
                and r["trustedRootSha256"] == ROOT_SHA
                and r["officialGhSha256"] == GH_SHA
                and r["releaseIdentitySha256"] == IDENTITY_SHA
                and r["assetId"] == asset_id
                and r["assetName"] ==
                    f"wal2json-wal2json_2_7-pg{major}-windows-x64.zip"
                and r["originalZipSha256"] == original_sha
                and r["buildJobId"] == build_job
                and r["rowReceiptSha256"] == receipt_sha
                and r["bundleSha256"] == bundle_sha
                and r["profile"] == "main/promote.yml/workflow_dispatch"
                and r["verificationOrigin"] == "genuine-trusted-main",
                "unproven/mismatched v3 formal row identity")
        require(all(type(r[k]) is bool and r[k] is True for k in (
                    "integrityVerified", "signatureVerified",
                    "sourceVerified", "runAndJobsVerified"))
                and r["workIndividualAuditRequired"] is False,
                "unauthenticated v3 row status")
        e = r["evidence"]
        require(type(e) is dict and
                set(e) == {
                    "auditRunUrl", "auditRunId", "auditMainCommit", "artifactId",
                    "artifactSha256", "commonReceiptSha256", "summaryReceiptSha256",
                    "fullReleaseAssetsRehashed", "allPgZipCrcVerified",
                    "allSpdxGrypeInspected", "checksPerformedWithRealGhAndTuf",
                    "originalReleaseAssetsAreNotActionsArtifacts",
                    "originalReleaseUrl"},
                "unrecognized provenance references")
        require(e["auditRunId"] == 38979537796
                and e["auditRunUrl"] ==
                    "https://github.com/pgextwin/catalog/actions/runs/38979537796"
                and e["auditMainCommit"] == RUN_SHA
                and e["artifactId"] == 12080557446
                and e["artifactSha256"] == OUTER_SHA
                and e["commonReceiptSha256"] == COMMON_SHA
                and e["summaryReceiptSha256"] == SUM_SHA
                and e["originalReleaseUrl"] ==
                    "https://github.com/pgextwin/wal2json/releases/tag/v2.7-windows.1"
                and all(type(e[k]) is bool and e[k] is True for k in
                        ("fullReleaseAssetsRehashed", "allPgZipCrcVerified",
                         "allSpdxGrypeInspected", "checksPerformedWithRealGhAndTuf",
                         "originalReleaseAssetsAreNotActionsArtifacts")),
                "original verification Run/proof linkage changed")
        key = (r["extension"], major, r["repositoryId"], r["releaseId"], asset_id)
        require(key not in keys, "same row double-counted")
        keys.add(key)
    require(type(d["historicalSourceAcceptedRows"]) is list and
            d["historicalSourceAcceptedRows"] ==
                previous["historicalSourceAcceptedRows"] == [],
            "unauthenticated historical source admission")
    for k, expected in (
            ("formalP1Accepted", 6), ("formalP1Total", 70),
            ("historicalSourceAccepted", 0), ("historicalSourceTotal", 40),
            ("unacceptedRows", 64), ("p1", "BLOCKED"), ("p2", "NO-GO"),
            ("fleetComplete", False), ("publicationAuthorized", False),
            ("distributionAuthorized", False), ("formalDistribution", "DENY")):
        require(type(d[k]) is type(expected) and d[k] == expected,
                "false admission/source/publication gate: " + k)
    require(type(d["note"]) is str and "Actions" in d["note"],
            "missing original-asset trust separation")
    return {"decision": "V3_RECORD_INTEGRITY_VALID_NOT_A_CRYPTO_TEST",
            "accepted": len(rows), "historicalSourceAccepted": 0,
            "publicationAuthorized": False, "distributionAuthorized": False}


def main():
    try:
        result = validate(LEDGER.read_bytes(), PREVIOUS.read_bytes())
    except (Denied, OSError, TypeError, KeyError, ValueError) as exc:
        print(json.dumps({"decision": "DENY", "reason": str(exc)[:160],
                          "publicationAuthorized": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
