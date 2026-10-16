#!/usr/bin/env python3
"""Issue #112 formal baseline ledger v2; historical receipts remain immutable.

Read-only invariant checker. New actual admissions MUST be written into a new
ledger version after independent original-byte/Sigstore/Run verification, not
by making this CLI accept a synthetic PASS_CANDIDATE or an Actions Artifact.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from distribution_manifest_v1 import Denied, require, strict_json

FORMAL_SOURCE = "https://github.com/pgextwin/build/issues/112#issuecomment-6220371461"
BASELINE = {
    "extension": "pg_bigm",
    "pgMajor": 14,
    "repositoryId": 1405047175,
    "releaseId": 408449466,
    "assetId": 626562095,
    "profile": "historical-pg_bigm-pg14/1",
    "sealSource": FORMAL_SOURCE,
    "verifierCommit": "e372e2c6a95adcf8227ea82d6253df3792b6f029",
}
LEDGER = (Path(__file__).resolve().parents[1] /
          "evidence/p1/formal-acceptance-20261017-v2.json")


def validate(raw):
    require(type(raw) is bytes and 0 < len(raw) < 65536, "missing/oversized ledger")
    doc = strict_json(raw)
    require(type(doc) is dict and set(doc) == {
        "schema", "createdAt", "catalogBaselineCommit", "priorAdmissionSource",
        "acceptedRows", "historicalSourceAcceptedRows", "formalP1Accepted",
        "formalP1Total", "historicalSourceAccepted", "historicalSourceTotal",
        "fleetComplete", "p1", "p2", "publicationAuthorized",
        "distributionAuthorized", "nextUnadmittedMustProvide"},
        "unexpected formal ledger fields")
    require(doc["schema"] == "pgextwin-p1-formal-acceptance/v2"
            and doc["createdAt"] == "2026-10-17"
            and doc["catalogBaselineCommit"] ==
                "fca5900e41d1727d3a03f63e4eead90cf58db372"
            and doc["priorAdmissionSource"] == FORMAL_SOURCE,
            "wrong baseline source/version")
    accepted = doc["acceptedRows"]
    require(type(accepted) is list and len(accepted) == 1
            and type(accepted[0]) is dict and accepted[0] == BASELINE,
            "formal PG14 identity changed or unverified new rows added")
    require(type(doc["historicalSourceAcceptedRows"]) is list and
            doc["historicalSourceAcceptedRows"] == [],
            "unverified historical source admitted")
    for key, expected in (("formalP1Accepted", 1), ("formalP1Total", 70),
                          ("historicalSourceAccepted", 0),
                          ("historicalSourceTotal", 40),
                          ("fleetComplete", False), ("p1", "BLOCKED"),
                          ("p2", "NO-GO"), ("publicationAuthorized", False),
                          ("distributionAuthorized", False)):
        require(type(doc[key]) is type(expected) and doc[key] == expected,
                "unsafe/counter status change: " + key)
    require(type(doc["nextUnadmittedMustProvide"]) is str and
            "Sigstore" in doc["nextUnadmittedMustProvide"],
            "missing subsequent admission trust contract")
    return {
        "schema": "pgextwin-p1-ledger-validation/v2",
        "formalP1Accepted": 1, "formalP1Total": 70,
        "historicalSourceAccepted": 0, "historicalSourceTotal": 40,
        "p1": "BLOCKED", "publicationAuthorized": False,
        "distributionAuthorized": False, "decision": "READONLY_BASELINE_VALID",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=LEDGER)
    args = parser.parse_args(argv)
    try:
        result = validate(args.ledger.read_bytes())
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Denied, OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"decision": "DENY", "formalNewAdmissions": 0,
                          "publicationAuthorized": False,
                          "distributionAuthorized": False,
                          "reason": str(exc)[:240]}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
