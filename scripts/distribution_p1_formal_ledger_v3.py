#!/usr/bin/env python3
"""Read-only, exact evidence-pinned Issue #112 formal v3 acceptance contract.

Reconciles the five real protected-main gh Sigstore PASS rows with immutable
original Release IDs and the previously sealed PG14 baseline. Does NOT itself
generate cryptographic proof; never upgrades test fixtures or diagnostic-only
Actions artifacts into verified original Release bytes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

from distribution_manifest_v1 import Denied, require, strict_json
from distribution_p1_formal_ledger_v2 import BASELINE, LEDGER as PRIOR_LEDGER, validate as validate_prior

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "evidence/p1/formal-acceptance-20261017-v3.json"
PRIOR_BLOB = "4d31331bd22b2b14e09e19ca20682a82092b7194"
RUN = {
    "repository": "pgextwin/catalog", "runId": 38979537796, "runAttempt": 1,
    "headSha": "0ac13f66b76c230ec68944aa96572486545cf5bb",
    "path": ".github/workflows/issue112-p1-fleet-readonly.yml",
    "event": "push", "runConclusion": "failure",
    "failureExplanation": "Expected fail-closed fleet exit 2 for 64 unaccepted rows; independently successful wal2json PG14-18 rows have genuine dual Sigstore PASS",
    "artifactId": 12080557446,
    "diagnosticZipSha256": "59e2ab4338ba0c75a3b9406b6288dd7e2b58ae777be1bb0c1899c738d59aea5d",
    "originalReleaseReceiptSha256": "44d091a754e10049a280247bf5c1be1028e7e27286fdf82b19147ee3e5fe11f2",
    "summaryReceiptSha256": "1ba85e6b0ba251f7db48fdc4e4447599ca9ac47f22212afa0337bc66abafed2a",
    "officialGhBinarySha256": "7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b",
    "publisherOriginalRunId": 38230537748, "publisherOriginalRunAttempt": 1,
    "publisherConclusion": "success", "publicationJobId": 114753316427,
    "originalReleaseUrl": "https://github.com/pgextwin/wal2json/releases/tag/v2.7-windows.1",
}
ROWS = (
    (14, 633345001, "6e4f549c4c43e1695ea400bd045d412b4bec54e13b8be1dd6bdd257d0e7a26b0", 114748851610,
     "56d79eb13bb91f42a424633fcc29f743ad7f82e824f7c211526a508de3a3d82a", "08d96ced687258193b0725767056467b17c3e7f7f2a750c76f44379d0ada42a6"),
    (15, 633345012, "fb11e93550a6e413dab55d9688fb64017e0a0ca63bdd4e009d125176b00548f2", 114748851643,
     "68068ef2495cafd9118ed7ebe0c1459ef80bd4981bb2539e4e462dfac57e9808", "7e01b94c13ba7dc931738753c24fc6a390903d9bbfee0adfa5dd9ed46d49bdd5"),
    (16, 633345023, "3d13ec8d8797f5808d896f5b28b0a8a069fa4e183d57acb5b84bd98ca4409545", 114748851645,
     "b6dd726d61d53b6718e32a9903d4f3a454649ce98756a8cf3e18df72d2a6e1e8", "8bf4bf45cd4b6b6e98ab528e1aaf6807782bdf6afa0fac06bc8c86246490a714"),
    (17, 633345034, "933de356db8b40faccdcef183863a6e2b6a8864a4353ffc311db65e644259515", 114748851652,
     "1eb9de209a24306a2bbf313a8d82aeebc9b74232135a3ed6994810e153229b46", "3a6185dff62119a181236e711a816da09c2844daa1844767578ecd95b938e622"),
    (18, 633345056, "bd06bc2755c6ef7ebbde4ddcb04cf5e908c7a01ed8336dd869a4ea77cb6afc56", 114748851641,
     "6c78567d8334b3a9588e90afb3c073e92450a958776ba3d39dd38866e96c7fb1", "a8d4d19dfba11859823469ecab4ba53c89e7a24caff99a15b652eda475164fff"),
)


def expected_rows():
    return [{
        "extension": "wal2json", "pgMajor": major, "repositoryId": 1412861698,
        "releaseId": 410447206, "assetId": asset, "zipSha256": digest,
        "profile": "main-promotion/v1", "runId": 38230537748, "runAttempt": 1,
        "buildJobId": job, "publicationJobId": 114753316427,
        "signerSha": "5756b3c5136a8bf4db710016cfe97555f0a71c6d",
        "sourceSha": "1198ff30137ee3fd01a9e168647a7167324bb713",
        "trustedRootSha256": "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c",
        "slsaAndSpdxBundleSha256": bundle, "rowReceiptSha256": receipt,
        "integrityVerified": True, "signatureVerified": True,
        "observation": "Work個別監査不要：自動実検査済み",
    } for major, asset, digest, job, bundle, receipt in ROWS]


def git_blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def validate(data, prior_bytes):
    validate_prior(prior_bytes)
    require(git_blob_sha(prior_bytes) == PRIOR_BLOB, "prior formal admission ledger bytes changed")
    require(type(data) is bytes and 0 < len(data) <= 32768, "missing/oversized v3")
    d = strict_json(data)
    require(type(d) is dict and set(d) == {
        "schema", "createdAt", "supersedes", "supersedesGitBlobSha",
        "acceptanceSource", "verifiedCatalogCommit", "genuineRunner",
        "acceptedRows", "historicalSourceAcceptedRows", "formalP1Accepted",
        "formalP1Total", "historicalSourceAccepted", "historicalSourceTotal",
        "p1", "p2", "fleetComplete", "publicationAuthorized",
        "distributionAuthorized", "note",
    }, "unknown formal v3 fields")
    require(d["schema"] == "pgextwin-p1-formal-acceptance/v3"
            and d["createdAt"] == "2026-10-17"
            and d["supersedes"] == "evidence/p1/formal-acceptance-20261017-v2.json"
            and d["supersedesGitBlobSha"] == PRIOR_BLOB
            and d["acceptanceSource"] == "https://github.com/pgextwin/build/issues/112#issuecomment-6220371461"
            and d["verifiedCatalogCommit"] == "e372e2c6a95adcf8227ea82d6253df3792b6f029",
            "v3 original code/ledger source replaced")
    require(type(d["genuineRunner"]) is dict and d["genuineRunner"] == RUN,
            "genuine original run/real gh/artifact SHA or status substituted")
    expected = [BASELINE] + expected_rows()
    require(type(d["acceptedRows"]) is list and d["acceptedRows"] == expected
            and all(type(row) is dict for row in d["acceptedRows"]),
            "duplicated/unsupported/wrong-profile accepted row")
    require(len({(x["extension"], x["pgMajor"]) for x in expected}) == 6,
            "formal accepted row identity collision")
    require(type(d["historicalSourceAcceptedRows"]) is list
            and d["historicalSourceAcceptedRows"] == [],
            "historical source admission has no independent proof")
    for key, value in (("formalP1Accepted", 6), ("formalP1Total", 70),
                       ("historicalSourceAccepted", 0), ("historicalSourceTotal", 40),
                       ("fleetComplete", False), ("p1", "BLOCKED"),
                       ("p2", "NO-GO"), ("publicationAuthorized", False),
                       ("distributionAuthorized", False)):
        require(type(d[key]) is type(value) and d[key] == value,
                "unsafe formal v3 status/counter: " + key)
    require(type(d["note"]) is str and
            "plpgsql_check Run 38128142145 attempt 1" in d["note"],
            "original failed Promotion waiver")
    return {
        "schema": "pgextwin-p1-ledger-validation/v3", "decision": "FORMAL_ROWS_RECONCILED",
        "formallyAccepted": 6, "total": 70,
        "historicalSourceAccepted": 0, "historicalSourceTotal": 40,
        "fleetComplete": False, "p1": "BLOCKED", "p2": "NO-GO",
        "publicationAuthorized": False, "distributionAuthorized": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ledger", type=Path, default=LEDGER)
    p.add_argument("--prior", type=Path, default=PRIOR_LEDGER)
    args = p.parse_args(argv)
    try:
        print(json.dumps(validate(args.ledger.read_bytes(), args.prior.read_bytes()),
                         sort_keys=True))
        return 0
    except (Denied, OSError, KeyError, ValueError, TypeError) as exc:
        print(json.dumps({"decision": "DENY", "publicationAuthorized": False,
                          "distributionAuthorized": False,
                          "reason": str(exc)[:240]}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
