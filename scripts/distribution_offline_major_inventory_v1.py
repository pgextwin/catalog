#!/usr/bin/env python3
"""Nonpublishing Issue #112 P0: fail-closed 14 x PG-major inventory.

Inputs are pinned Catalog index and the immutable formal acceptance ledger chain.
This is a RECORD integrity check, never an independent cryptographic verifier.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import subprocess

from distribution_manifest_v1 import Denied, require, strict_json, canonical
from distribution_p1_formal_ledger_v5 import validate as validate_v5, V5, V4, PINS, FLEET
from verified_release_record import ALLOWED

ROOT = Path(__file__).resolve().parents[1]
CATALOG_COMMIT = "ebe65013b35c18f0d545b9d350ab63f7968fb92c"
MAJORS = (14, 15, 16, 17, 18)
DENIED = "plpgsql_check"


def read_pinned_index():
    # This v1 ledger intentionally describes its sealed historical source,
    # never today's growing distribution Catalog. Missing local Git history
    # remains a denial; do not fetch or silently substitute the live index.
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", CATALOG_COMMIT + ":index.json"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0, "pinned historical Catalog index unavailable")
    return result.stdout


def build(index_blob: bytes, v5_blob: bytes, v4_blob: bytes,
          pins_blob: bytes, fleet_blob: bytes, *, catalog_commit: str):
    require(catalog_commit == CATALOG_COMMIT, "Catalog source commit changed; re-audit required")
    index = strict_json(index_blob)
    require(type(index) is dict and index.get("schemaVersion") == 2
            and index.get("extensions") == sorted(ALLOWED)
            and len(index["extensions"]) == 14, "not the exact 14-extension Catalog")
    verdict = validate_v5(v5_blob, v4_blob, pins_blob, fleet_blob)
    require(verdict["accepted"] == 65 and verdict["remainingDenied"] == 5
            and verdict["publicationAuthorized"] is False
            and verdict["distributionAuthorized"] is False,
            "formal P1 ledger no longer matches 65/70 DENY")
    rows = []
    for name in index["extensions"]:
        for major in MAJORS:
            denied = name == DENIED
            rows.append({"extension": name, "pgMajor": str(major),
                         "formalP1": "DENY" if denied else "ACCEPTED_RECORD_ONLY",
                         "sourceCryptographicallyVerifiedHere": False,
                         "distributionAuthorized": False})
    require(len(rows) == 70 and sum(r["formalP1"] == "DENY" for r in rows) == 5,
            "incomplete inventory")
    return {"schemaVersion": "pgextwin-offline-major-inventory/v1",
            "catalogCommitSha": catalog_commit,
            "formalLedger": "evidence/p1/formal-acceptance-20261017-v5.json",
            "acceptedRecordRows": 65, "deniedRows": 5,
            "historicalSourceAcceptedFromExistingLedger": 40,
            "scope": "GET_ONLY_RECORD_PROJECTION_NOT_CRYPTO_VERIFICATION",
            "archiveGenerationAuthorized": False,
            "publicationAuthorized": False, "distributionAuthorized": False,
            "majors": [{"pgMajor": str(pg),
                        "proposedLocalZipName": f"pgextwin-offline-pg{pg}-windows-x64.zip",
                        "complete": False, "distributionAuthorized": False}
                       for pg in MAJORS],
            "rows": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog-commit", default=CATALOG_COMMIT)
    args = parser.parse_args()
    try:
        result = build(read_pinned_index(), V5.read_bytes(),
                       V4.read_bytes(), PINS.read_bytes(), FLEET.read_bytes(),
                       catalog_commit=args.catalog_commit)
    except (Denied, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({"decision": "DENY", "reason": str(exc)[:240],
                          "distributionAuthorized": False}))
        return 2
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
