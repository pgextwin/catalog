#!/usr/bin/env python3
"""Issue #112 historical P1 evidence intake. Nonpublishing; NEVER a Sigstore verifier.

A byte-matched Work receipt is an evidence reference, not a formal P1 acceptance.
No external API, GitHub writes, signature verification, or privileged action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
LEDGER = REPO / "evidence/p1/pg_bigm-pg14-intake-ledger.json"
RECEIPT = REPO / "evidence/p1/pg_bigm-pg14-work-receipt-20261016.json"
RECEIPT_SHA = "010dbff810264bf46e8d0b62e88f787d72756ced7d5dba7118359161404dd294"
ARCHIVE_SHA = "4e126798ea4fa84b50c441143ff3294d675831843c3b2bb3e57ff8a2f30e9ba3"
ARCHIVE_SIZE = 533654

ROW = {
    "extension": "pg_bigm",
    "pgMajor": 14,
    "catalogSnapshot": "2e850bb5e5a3441edaa887fa5f7c378d22aea4c6",
    "repoId": 1405047175,
    "releaseId": 408449466,
    "zipAssetId": 626562095,
    "zipSha256": "3cd9f0facca96f185a406e795fd28a75acea60bb45ac531c9e06fcbc32e2277d",
    "runId": 38007421492,
    "runAttempt": 1,
    "historicalEvent": "push",
    "packagingSha": "cfbb52f8caf41b2c393a1a34f6011157979af2bb",
    "upstreamSha": "735dceba0ecdd8ac1aaaaa207226a7102b6bbd71",
}
EVIDENCE = {
    "source": "Work GET-only; real verifier exit 0 reported on 2026-10-16",
    "issueComment": "https://github.com/pgextwin/build/issues/112#issuecomment-6215234245",
    "verifierCommit": "40dcac693773c710d2b65fa5fe797bfca17ffb82",
    "receiptFile": "evidence/p1/pg_bigm-pg14-work-receipt-20261016.json",
    "receiptSha256": RECEIPT_SHA,
    "archiveName": "pgextwin-issue112-pgbigm-pg14-reaudit-evidence-20261016.tar.gz",
    "archiveSha256": ARCHIVE_SHA,
    "archiveSize": ARCHIVE_SIZE,
}
STATES = {
    "workReportedTechnicalPass": True,
    "rehashAssets": 4,
    "releaseAssetCount": 16,
    "releaseAllAssetsRehashed": False,
    "historicalSourceFormallyAccepted": False,
    "formalP1RowAccepted": False,
    "fleetComplete": False,
    "publicationAuthorized": False,
    "distributionAuthorized": False,
}
RECEIPT_FIELDS = {
    "profile": "historical-pg_bigm-pg14/1",
    "catalogCommit": ROW["catalogSnapshot"],
    "repoId": ROW["repoId"],
    "releaseId": ROW["releaseId"],
    "assetId": ROW["zipAssetId"],
    "assetSha256": ROW["zipSha256"],
    "runId": ROW["runId"],
    "attempt": ROW["runAttempt"],
    "packagingSha": ROW["packagingSha"],
    "upstreamCommit": ROW["upstreamSha"],
    "signerSha": "8246f4d3415a48b1ad4af13f421277057886b58f",
    "originalRootSha256": "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c",
    "rowEvidenceComplete": True,
    "signatureVerified": True,
    "integrityVerified": True,
    "all16AssetsRehashed": False,
    "fleetComplete": False,
    "publicationAuthorized": False,
    "distributionAuthorized": False,
}


class Denied(ValueError):
    pass


def require(test, message):
    if not test:
        raise Denied(message)


def strict_json(data):
    def no_dupes(pairs):
        d = {}
        for key, value in pairs:
            require(key not in d, "duplicate JSON key")
            d[key] = value
        return d

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_dupes,
                          parse_constant=lambda _: (_ for _ in ()).throw(Denied("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Denied("invalid JSON") from exc


def exact(actual, expected, label):
    require(type(actual) is dict and set(actual) == set(expected), label + ": missing/extra keys")
    require(all(type(actual[key]) is type(value) and actual[key] == value
                for key, value in expected.items()), label + ": changed pin or status")


def read_local(path, limit):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
            "missing, linked or oversized local evidence")
    return path.read_bytes()


def reconcile(ledger_bytes, receipt_bytes, archive_bytes=None):
    require(len(ledger_bytes) <= 16384 and len(receipt_bytes) <= 16384, "oversized JSON")
    ledger = strict_json(ledger_bytes)
    require(type(ledger) is dict and set(ledger) == {"schema", "row", "evidence", "states"}
            and ledger["schema"] == "pgextwin-p1-historical-evidence-intake/v1",
            "wrong ledger schema or unknown status")
    exact(ledger["row"], ROW, "row")
    exact(ledger["evidence"], EVIDENCE, "evidence")
    exact(ledger["states"], STATES, "states")
    require(hashlib.sha256(receipt_bytes).hexdigest() == RECEIPT_SHA,
            "receipt byte SHA256 is not independently pinned")
    receipt = strict_json(receipt_bytes)
    require(type(receipt) is dict and set(RECEIPT_FIELDS).issubset(receipt),
            "receipt incomplete")
    for key, expected in RECEIPT_FIELDS.items():
        require(type(receipt[key]) is type(expected) and receipt[key] == expected,
                "receipt identity or status mismatch: " + key)
    require(type(receipt.get("verifiedBundleSha256")) is dict
            and set(receipt["verifiedBundleSha256"]) ==
            {"https://slsa.dev/provenance/v1", "https://spdx.dev/Document/v2.3"},
            "receipt must reference both predicates")
    archive_matched = False
    if archive_bytes is not None:
        require(len(archive_bytes) == ARCHIVE_SIZE
                and hashlib.sha256(archive_bytes).hexdigest() == ARCHIVE_SHA,
                "archive byte SHA256/size mismatch")
        archive_matched = True

    return {
        "schema": "pgextwin-p1-evidence-intake-result/v1",
        "extension": "pg_bigm", "pgMajor": 14,
        "evidenceOrigin": "Work-reported; NOT cryptographically reverified here",
        "receiptSha256Matched": True,
        "archiveSha256Matched": archive_matched,
        "workReportedTechnicalPass": True,
        "releaseAssetBytesIndependentlyRehashedByWork": 4,
        "releaseAssetTotal": 16,
        "formalP1RowsAccepted": 0, "formalP1RowsExpected": 70,
        "historicalSourceAccepted": 0, "historicalSourceExpected": 40,
        "p1": "BLOCKED", "p2": "NO-GO", "publicationAuthorized": False,
        "distributionAuthorized": False,
        "missing": ["original other 12/16 Release Asset payload rehash",
                    "explicit narrowly accepted historical P1 run/profile exception",
                    "independent reconciliation of full original proofs before formal admission"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=LEDGER)
    parser.add_argument("--receipt", type=Path, default=RECEIPT)
    parser.add_argument("--archive", type=Path, help="optional original archive bytes; no extraction")
    args = parser.parse_args(argv)
    try:
        archive = read_local(args.archive, 1024 * 1024) if args.archive else None
        result = reconcile(read_local(args.ledger, 16384),
                           read_local(args.receipt, 16384), archive)
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 0
    except (Denied, OSError) as exc:
        print(json.dumps({"decision": "DENY", "p1": "BLOCKED",
                          "formalP1RowsAccepted": 0,
                          "publicationAuthorized": False,
                          "distributionAuthorized": False,
                          "reason": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
