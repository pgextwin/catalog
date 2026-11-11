#!/usr/bin/env python3
"""Fail-closed, offline TimescaleDB rights/provenance intake contract.

This only checks the immutable *description* of reviewed candidate evidence.
It never fetches assets, signs, approves a provider or publishes a ZIP.
A PASS here is categorically NOT a publication authorization.
"""
import argparse
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
